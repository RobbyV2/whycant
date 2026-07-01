//! Target identity resolution. Defaults to the invoking real user
//! (SUDO_UID/GID/USER before getuid) so sudo does not silently pass DAC checks,
//! and resolves `--user` to a uid, primary gid, and full supplementary group
//! set via getgrouplist. Every layer evaluates against this, not the process.

use crate::report;
use anyhow::{Result, anyhow};
use std::ffi::OsStr;
use uzers::{
    get_current_gid, get_current_uid, get_effective_uid, get_group_by_gid, get_user_by_name,
    get_user_by_uid, get_user_groups,
};

pub struct Identity {
    pub uid: u32,
    pub primary_gid: u32,
    pub groups: Vec<u32>,
    pub name: Option<String>,
    pub is_self: bool,
}

fn env_u32(key: &str) -> Option<u32> {
    std::env::var(key).ok().and_then(|s| s.parse().ok())
}

fn groups_for(name: Option<&str>, primary_gid: u32) -> Vec<u32> {
    let mut groups = match name.and_then(|n| get_user_groups(OsStr::new(n), primary_gid)) {
        Some(gs) => gs.iter().map(|g| g.gid()).collect(),
        None => Vec::new(),
    };
    if !groups.contains(&primary_gid) {
        groups.push(primary_gid);
    }
    groups
}

fn build_identity(uid: u32, primary_gid: Option<u32>, name: Option<String>) -> Result<Identity> {
    let entry = get_user_by_uid(uid);
    let name = name.or_else(|| {
        entry
            .as_ref()
            .and_then(|u| u.name().to_str().map(str::to_owned))
    });
    let primary_gid = primary_gid
        .or_else(|| entry.as_ref().map(|u| u.primary_group_id()))
        .ok_or_else(|| anyhow!("cannot determine primary gid for uid {uid}"))?;
    let groups = groups_for(name.as_deref(), primary_gid);
    Ok(Identity {
        uid,
        primary_gid,
        groups,
        name,
        is_self: uid == get_effective_uid(),
    })
}

fn real_identity() -> Result<Identity> {
    match env_u32("SUDO_UID") {
        Some(uid) => build_identity(uid, env_u32("SUDO_GID"), std::env::var("SUDO_USER").ok()),
        None => build_identity(get_current_uid(), Some(get_current_gid()), None),
    }
}

pub fn resolve_target(user: Option<&str>) -> Result<Identity> {
    match user {
        None => real_identity(),
        Some(spec) => {
            let entry = match spec.parse::<u32>() {
                Ok(uid) => get_user_by_uid(uid),
                Err(_) => get_user_by_name(spec),
            }
            .ok_or_else(|| anyhow!("unknown user: {spec}"))?;
            build_identity(
                entry.uid(),
                Some(entry.primary_group_id()),
                entry.name().to_str().map(str::to_owned),
            )
        }
    }
}

pub fn running_as() -> sudo::RunningAs {
    sudo::check()
}

fn report_running_as(ra: &sudo::RunningAs) -> report::RunningAs {
    match ra {
        sudo::RunningAs::Root => report::RunningAs::Root,
        sudo::RunningAs::User => report::RunningAs::User,
        sudo::RunningAs::Suid => report::RunningAs::SudoElevated,
    }
}

fn lsm_active() -> bool {
    [
        "/sys/fs/selinux",
        "/sys/kernel/security/apparmor",
        "/sys/fs/smackfs",
        "/sys/kernel/security/tomoyo",
    ]
    .iter()
    .any(|p| std::path::Path::new(p).exists())
}

pub fn banner_text(id: &Identity, ra: &sudo::RunningAs) -> String {
    let head = format!(
        "running as {} (uid {})",
        id.name.as_deref().unwrap_or("?"),
        id.uid
    );
    let note = match ra {
        sudo::RunningAs::Root | sudo::RunningAs::Suid => Some("full audit-log access"),
        sudo::RunningAs::User if lsm_active() => Some("MAC denial confirmation needs sudo"),
        sudo::RunningAs::User => None,
    };
    match note {
        Some(n) => format!("{head}; {n}"),
        None => head,
    }
}

pub fn to_report(id: &Identity) -> report::IdentityReport {
    let ra = running_as();
    let group_names = id
        .groups
        .iter()
        .filter_map(|&g| get_group_by_gid(g).and_then(|gr| gr.name().to_str().map(str::to_owned)))
        .collect();
    report::IdentityReport {
        target_uid: id.uid,
        target_user: id.name.clone(),
        primary_gid: id.primary_gid,
        groups: id.groups.clone(),
        group_names,
        running_as: report_running_as(&ra),
        privilege_note: banner_text(id, &ra),
        target_is_self: id.is_self,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn current_user_has_primary_group() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe { std::env::remove_var("SUDO_UID") };
        unsafe { std::env::remove_var("SUDO_GID") };
        unsafe { std::env::remove_var("SUDO_USER") };
        let id = resolve_target(None).unwrap();
        assert!(!id.groups.is_empty());
        assert!(id.groups.contains(&id.primary_gid));
    }

    fn ident() -> Identity {
        Identity {
            uid: 1000,
            primary_gid: 1000,
            groups: vec![1000],
            name: Some("alice".into()),
            is_self: true,
        }
    }

    #[test]
    fn root_banner_notes_audit_access() {
        let b = banner_text(&ident(), &sudo::RunningAs::Root);
        assert!(b.contains("full audit-log access"));
    }

    #[test]
    fn user_mac_clause_tracks_lsm_presence() {
        let b = banner_text(&ident(), &sudo::RunningAs::User);
        assert!(b.starts_with("running as alice (uid 1000)"));
        assert_eq!(
            b.contains("MAC denial confirmation needs sudo"),
            lsm_active()
        );
    }

    #[test]
    fn sudo_env_overrides_current_uid() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var("SUDO_UID", "0") };
        unsafe { std::env::set_var("SUDO_GID", "0") };
        unsafe { std::env::set_var("SUDO_USER", "root") };
        let id = resolve_target(None);
        unsafe { std::env::remove_var("SUDO_UID") };
        unsafe { std::env::remove_var("SUDO_GID") };
        unsafe { std::env::remove_var("SUDO_USER") };
        let id = id.unwrap();
        assert_eq!(id.uid, 0);
        assert_eq!(id.primary_gid, 0);
        assert_eq!(id.name.as_deref(), Some("root"));
    }
}
