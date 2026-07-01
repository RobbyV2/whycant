use crate::engine::{Layer, LayerResult, LayerStatus};
use crate::identity::Identity;
use crate::op::{GateTarget, Op, gating_node};
use crate::report::{Certainty, Evidence, EvidenceSource, Fix, FixAction, LayerId, Risk};
use std::fs::{self, Metadata};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use uzers::{get_group_by_gid, get_user_by_uid};

pub struct DacLayer;

impl Layer for DacLayer {
    fn name(&self) -> &str {
        "dac"
    }
    fn order(&self) -> u8 {
        3
    }
    fn id(&self) -> LayerId {
        LayerId::Dac
    }
    fn check(&self, id: &Identity, path: &Path, op: Op) -> LayerResult {
        match gating_node(op, path) {
            GateTarget::Node(p) => check_node(id, p, op),
            GateTarget::Parent { of, sticky_matters } => check_parent(id, of, op, sticky_matters),
        }
    }
}

fn check_node(id: &Identity, p: &Path, op: Op) -> LayerResult {
    let meta = match fs::metadata(p) {
        Ok(m) => m,
        Err(_) => return LayerResult::skip(),
    };
    let ev = vec![ls_evidence(p, &meta)];
    if granted(id, &meta, op) {
        return LayerResult {
            status: LayerStatus::Pass,
            certainty: Certainty::Proven,
            evidence: ev,
            fixes: Vec::new(),
            detail: suid_note(&meta),
        };
    }
    let who = who(id);
    let class = class_of(id, &meta);
    let detail = format!(
        "DAC denies {} for {}: mode {:04o}, {who} class {class} lacks {}",
        op_word(op),
        who,
        meta.mode() & 0o7777,
        op_letter(op)
    );
    LayerResult::block(Certainty::Proven, detail, ev, grant_fixes(id, &meta, p, op))
}

fn check_parent(id: &Identity, of: &Path, op: Op, sticky_matters: bool) -> LayerResult {
    let parent = parent_of(of);
    let meta = match fs::metadata(&parent) {
        Ok(m) => m,
        Err(_) => return LayerResult::skip(),
    };
    let ev = vec![ls_evidence(&parent, &meta)];
    let who = who(id);
    let (w, x) = dir_wx(id, &meta);
    if !(w && x) {
        let missing = match (w, x) {
            (false, false) => "w and x",
            (false, true) => "w",
            _ => "x",
        };
        let detail = format!(
            "DAC denies {} for {who}: parent {} mode {:04o} lacks {missing}",
            op_word(op),
            parent.display(),
            meta.mode() & 0o7777
        );
        return LayerResult::block(
            Certainty::Proven,
            detail,
            ev,
            grant_fixes(id, &meta, &parent, op),
        );
    }
    if sticky_matters && meta.mode() & 0o1000 != 0 && id.uid != 0 && id.uid != meta.uid() {
        let owns_file = fs::metadata(of).map(|m| m.uid() == id.uid).unwrap_or(false);
        if !owns_file {
            let detail = format!(
                "sticky parent {} (mode {:04o}): {who} owns neither",
                parent.display(),
                meta.mode() & 0o7777
            );
            return LayerResult::block(Certainty::Proven, detail, ev, vec![chown_fix(id, of)]);
        }
    }
    LayerResult::pass(ev)
}

fn granted(id: &Identity, meta: &Metadata, op: Op) -> bool {
    let m = meta.mode();
    if id.uid == 0 {
        return match op {
            Op::Read | Op::Write | Op::Delete | Op::Create => true,
            Op::Exec => m & 0o111 != 0,
            Op::Traverse => meta.is_dir() || m & 0o111 != 0,
        };
    }
    let bits = class_bits(id, meta);
    match op {
        Op::Read => bits & 0o4 != 0,
        Op::Write => bits & 0o2 != 0,
        Op::Exec | Op::Traverse => bits & 0o1 != 0,
        Op::Delete | Op::Create => bits & 0o2 != 0 && bits & 0o1 != 0,
    }
}

fn dir_wx(id: &Identity, meta: &Metadata) -> (bool, bool) {
    if id.uid == 0 {
        return (true, true);
    }
    let b = class_bits(id, meta);
    (b & 0o2 != 0, b & 0o1 != 0)
}

fn class_bits(id: &Identity, meta: &Metadata) -> u32 {
    let m = meta.mode();
    if id.uid == meta.uid() {
        (m >> 6) & 0o7
    } else if in_group(id, meta.gid()) {
        (m >> 3) & 0o7
    } else {
        m & 0o7
    }
}

fn in_group(id: &Identity, gid: u32) -> bool {
    id.primary_gid == gid || id.groups.contains(&gid)
}

fn class_of(id: &Identity, meta: &Metadata) -> &'static str {
    if id.uid == meta.uid() {
        "owner"
    } else if in_group(id, meta.gid()) {
        "group"
    } else {
        "other"
    }
}

fn grant_fixes(id: &Identity, meta: &Metadata, p: &Path, op: Op) -> Vec<Fix> {
    let who = who(id);
    let perm = op_letter(op);
    let pstr = p.to_string_lossy().into_owned();
    let needs_root = id.uid != meta.uid();
    vec![
        Fix {
            action: FixAction::Run {
                argv: vec![
                    "setfacl".into(),
                    "-m".into(),
                    format!("u:{who}:{perm}"),
                    pstr.clone(),
                ],
            },
            needs_root,
            description: format!("grant {who} {perm} on {pstr} via a named-user ACL entry"),
            risk: Risk::Low,
            rationale: "named-user entry only".into(),
        },
        Fix {
            action: FixAction::Run {
                argv: vec!["chmod".into(), format!("o+{perm}"), pstr.clone()],
            },
            needs_root,
            description: format!("grant {perm} to the other class on {pstr}"),
            risk: Risk::Medium,
            rationale: "all users; prefer setfacl".into(),
        },
    ]
}

fn chown_fix(id: &Identity, file: &Path) -> Fix {
    let fstr = file.to_string_lossy().into_owned();
    Fix {
        action: FixAction::Run {
            argv: vec!["chown".into(), id.uid.to_string(), fstr.clone()],
        },
        needs_root: true,
        description: format!("chown {fstr} to uid {}", id.uid),
        risk: Risk::Medium,
        rationale: "transfer ownership".into(),
    }
}

fn suid_note(meta: &Metadata) -> String {
    let m = meta.mode();
    let mut n = String::new();
    if m & 0o4000 != 0 {
        n.push_str(&format!("setuid bit set; exec runs as uid {}", meta.uid()));
    }
    if m & 0o2000 != 0 {
        if !n.is_empty() {
            n.push_str("; ");
        }
        n.push_str(&format!("setgid bit set; exec runs as gid {}", meta.gid()));
    }
    n
}

fn ls_evidence(p: &Path, meta: &Metadata) -> Evidence {
    Evidence {
        source: EvidenceSource::LsLd,
        raw: ls_line(p, meta),
        path: Some(p.to_path_buf()),
    }
}

fn ls_line(p: &Path, meta: &Metadata) -> String {
    let m = meta.mode();
    let typ = if meta.is_dir() { 'd' } else { '-' };
    let owner = rwx(m, 6, m & 0o4000 != 0, 's', 'S');
    let group = rwx(m, 3, m & 0o2000 != 0, 's', 'S');
    let other = rwx(m, 0, m & 0o1000 != 0, 't', 'T');
    let un = get_user_by_uid(meta.uid())
        .and_then(|u| u.name().to_str().map(str::to_owned))
        .unwrap_or_else(|| meta.uid().to_string());
    let gn = get_group_by_gid(meta.gid())
        .and_then(|g| g.name().to_str().map(str::to_owned))
        .unwrap_or_else(|| meta.gid().to_string());
    format!(
        "{typ}{owner}{group}{other} {} {un} {gn} {} {}",
        meta.nlink(),
        meta.size(),
        p.display()
    )
}

fn rwx(m: u32, shift: u32, special: bool, set: char, unset: char) -> String {
    let b = (m >> shift) & 0o7;
    let r = if b & 0o4 != 0 { 'r' } else { '-' };
    let w = if b & 0o2 != 0 { 'w' } else { '-' };
    let x = match (b & 0o1 != 0, special) {
        (true, true) => set,
        (false, true) => unset,
        (true, false) => 'x',
        (false, false) => '-',
    };
    format!("{r}{w}{x}")
}

fn parent_of(p: &Path) -> PathBuf {
    match p.parent() {
        Some(par) if !par.as_os_str().is_empty() => par.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

fn who(id: &Identity) -> String {
    id.name.clone().unwrap_or_else(|| id.uid.to_string())
}

fn op_word(op: Op) -> &'static str {
    match op {
        Op::Read => "read",
        Op::Write => "write",
        Op::Exec => "exec",
        Op::Traverse => "traverse",
        Op::Delete => "delete",
        Op::Create => "create",
    }
}

fn op_letter(op: Op) -> &'static str {
    match op {
        Op::Read => "r",
        Op::Write => "w",
        Op::Exec | Op::Traverse => "x",
        Op::Delete | Op::Create => "wx",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct Tmp(PathBuf);
    impl Tmp {
        fn new() -> Self {
            static C: AtomicU32 = AtomicU32::new(0);
            let n = C.fetch_add(1, Ordering::Relaxed);
            let p = std::env::temp_dir().join(format!("whycant-dac-{}-{}", std::process::id(), n));
            fs::create_dir_all(&p).unwrap();
            Tmp(p)
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn ident(uid: u32, gid: u32, groups: Vec<u32>) -> Identity {
        Identity {
            uid,
            primary_gid: gid,
            groups,
            name: Some("t".into()),
            is_self: false,
        }
    }

    fn chmod(p: &Path, mode: u32) {
        fs::set_permissions(p, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn owner_reads_other_blocked_0600() {
        let t = Tmp::new();
        let f = t.0.join("secret");
        fs::write(&f, b"x").unwrap();
        chmod(&f, 0o600);
        let m = fs::metadata(&f).unwrap();

        let owner = ident(m.uid(), m.gid(), vec![m.gid()]);
        assert!(matches!(
            check_node(&owner, &f, Op::Read).status,
            LayerStatus::Pass
        ));

        let other = ident(m.uid() + 4242, m.gid() + 4242, vec![]);
        let r = check_node(&other, &f, Op::Read);
        assert!(matches!(r.status, LayerStatus::Block));
        assert!(r.certainty == Certainty::Proven);
        assert!(
            r.fixes
                .iter()
                .any(|f| f.argv().first().map(String::as_str) == Some("setfacl"))
        );
    }

    #[test]
    fn dir_0755_traversable_by_other() {
        let t = Tmp::new();
        let d = t.0.join("pub");
        fs::create_dir(&d).unwrap();
        chmod(&d, 0o755);
        let other = ident(99999, 99999, vec![]);
        assert!(matches!(
            check_node(&other, &d, Op::Traverse).status,
            LayerStatus::Pass
        ));
    }

    #[test]
    fn owner_of_0555_dir_denied_create() {
        if rustix::process::geteuid().is_root() {
            return;
        }
        let t = Tmp::new();
        let d = t.0.join("ro");
        fs::create_dir(&d).unwrap();
        chmod(&d, 0o555);
        let m = fs::metadata(&d).unwrap();
        let owner = ident(m.uid(), m.gid(), vec![m.gid()]);
        let r = check_parent(&owner, &d.join("child"), Op::Create, false);
        assert!(matches!(r.status, LayerStatus::Block));
        assert!(r.certainty == Certainty::Proven);
    }

    #[test]
    fn owner_of_0444_file_denied_write() {
        if rustix::process::geteuid().is_root() {
            return;
        }
        let t = Tmp::new();
        let f = t.0.join("readonly");
        fs::write(&f, b"x").unwrap();
        chmod(&f, 0o444);
        let m = fs::metadata(&f).unwrap();
        let owner = ident(m.uid(), m.gid(), vec![m.gid()]);
        let r = check_node(&owner, &f, Op::Write);
        assert!(matches!(r.status, LayerStatus::Block));
        assert!(r.certainty == Certainty::Proven);
    }

    #[test]
    fn owner_of_0555_dir_denied_delete() {
        if rustix::process::geteuid().is_root() {
            return;
        }
        let t = Tmp::new();
        let d = t.0.join("ro");
        fs::create_dir(&d).unwrap();
        let f = d.join("note");
        fs::write(&f, b"x").unwrap();
        chmod(&d, 0o555);
        let m = fs::metadata(&d).unwrap();
        let owner = ident(m.uid(), m.gid(), vec![m.gid()]);
        let r = check_parent(&owner, &f, Op::Delete, true);
        assert!(matches!(r.status, LayerStatus::Block));
        assert!(r.certainty == Certainty::Proven);
    }

    #[test]
    fn sticky_delete_non_owner_blocked_owner_allowed() {
        let t = Tmp::new();
        let d = t.0.join("shared");
        fs::create_dir(&d).unwrap();
        chmod(&d, 0o1777);
        let f = d.join("note");
        fs::write(&f, b"x").unwrap();
        chmod(&f, 0o644);
        let m = fs::metadata(&f).unwrap();

        let stranger = ident(m.uid() + 8888, m.gid() + 8888, vec![]);
        let r = check_parent(&stranger, &f, Op::Delete, true);
        assert!(matches!(r.status, LayerStatus::Block));
        assert!(r.certainty == Certainty::Proven);

        let owner = ident(m.uid(), m.gid(), vec![m.gid()]);
        assert!(matches!(
            check_parent(&owner, &f, Op::Delete, true).status,
            LayerStatus::Pass
        ));
    }
}
