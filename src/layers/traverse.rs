use crate::engine::{Layer, LayerResult};
use crate::identity::Identity;
use crate::op::Op;
use crate::report::{Certainty, Evidence, EvidenceSource, Fix, FixAction, LayerId, Risk};
use std::fs::Metadata;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use uzers::{get_group_by_gid, get_user_by_uid};

pub struct TraverseLayer;

enum Class {
    Owner,
    Group,
    Other,
}

fn class_of(id: &Identity, meta: &Metadata) -> Class {
    match () {
        _ if id.uid == meta.uid() => Class::Owner,
        _ if meta.gid() == id.primary_gid || id.groups.contains(&meta.gid()) => Class::Group,
        _ => Class::Other,
    }
}

fn has_search(id: &Identity, meta: &Metadata) -> bool {
    let mode = meta.mode();
    match class_of(id, meta) {
        Class::Owner => mode & 0o100 != 0,
        Class::Group => mode & 0o010 != 0,
        Class::Other => mode & 0o001 != 0,
    }
}

fn perm_string(mode: u32, is_dir: bool) -> String {
    let bit = |m: u32, c: char| if mode & m != 0 { c } else { '-' };
    let sp = |set: u32, x: u32, lo: char, up: char| match (mode & set != 0, mode & x != 0) {
        (true, true) => lo,
        (true, false) => up,
        (false, true) => 'x',
        (false, false) => '-',
    };
    let mut s = String::with_capacity(10);
    s.push(if is_dir { 'd' } else { '-' });
    s.push(bit(0o400, 'r'));
    s.push(bit(0o200, 'w'));
    s.push(sp(0o4000, 0o100, 's', 'S'));
    s.push(bit(0o040, 'r'));
    s.push(bit(0o020, 'w'));
    s.push(sp(0o2000, 0o010, 's', 'S'));
    s.push(bit(0o004, 'r'));
    s.push(bit(0o002, 'w'));
    s.push(sp(0o1000, 0o001, 't', 'T'));
    s
}

fn ls_ld(path: &Path, meta: &Metadata) -> String {
    let owner = get_user_by_uid(meta.uid())
        .and_then(|u| u.name().to_str().map(str::to_owned))
        .unwrap_or_else(|| meta.uid().to_string());
    let group = get_group_by_gid(meta.gid())
        .and_then(|g| g.name().to_str().map(str::to_owned))
        .unwrap_or_else(|| meta.gid().to_string());
    format!(
        "{} {} {} {} {} {}",
        perm_string(meta.mode(), meta.is_dir()),
        meta.nlink(),
        owner,
        group,
        meta.len(),
        path.display()
    )
}

fn subject(id: &Identity) -> String {
    id.name.clone().unwrap_or_else(|| format!("uid {}", id.uid))
}

fn build_fix(id: &Identity, dir: &Path, meta: &Metadata) -> (Fix, String) {
    let (sym, who) = match class_of(id, meta) {
        Class::Owner => ("u+x", "owner"),
        Class::Group => ("g+x", "group"),
        Class::Other => ("o+x", "others"),
    };
    let euid = rustix::process::geteuid();
    let needs_root = !euid.is_root() && euid.as_raw() != meta.uid();
    let target = dir.display().to_string();
    let detail = format!(
        "{} not traversable by {}; missing {} execute bit",
        target,
        subject(id),
        who
    );
    let fix = Fix {
        action: FixAction::Run {
            argv: vec!["chmod".into(), sym.into(), target.clone()],
        },
        needs_root,
        description: format!("grant search (execute) on {target}"),
        risk: Risk::Low,
        rationale: format!("add {who} search bit"),
    };
    (fix, detail)
}

fn evaluate(id: &Identity, path: &Path) -> LayerResult {
    let abs = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    let parent = match abs.parent() {
        Some(p) => p.to_path_buf(),
        None => return LayerResult::pass(Vec::new()),
    };
    let mut chain = Vec::new();
    for dir in parent.ancestors().collect::<Vec<_>>().into_iter().rev() {
        let meta = match std::fs::metadata(dir) {
            Ok(m) => m,
            Err(_) => return LayerResult::skip(),
        };
        chain.push(Evidence {
            source: EvidenceSource::LsLd,
            raw: ls_ld(dir, &meta),
            path: Some(dir.to_path_buf()),
        });
        if id.uid == 0 || has_search(id, &meta) {
            continue;
        }
        let (fix, detail) = build_fix(id, dir, &meta);
        return LayerResult::block(Certainty::Proven, detail, chain, vec![fix]);
    }
    LayerResult::pass(chain)
}

impl Layer for TraverseLayer {
    fn name(&self) -> &str {
        "traverse"
    }
    fn order(&self) -> u8 {
        2
    }
    fn id(&self) -> LayerId {
        LayerId::Traverse
    }
    fn check(&self, id: &Identity, path: &Path, _op: Op) -> LayerResult {
        evaluate(id, path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::LayerStatus;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    fn mk(mode: u32, p: &Path) {
        fs::set_permissions(p, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn middle_ancestor_is_the_blocker() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = std::env::temp_dir().join(format!("whycant_tv_{}_{nanos}", std::process::id()));
        let a = base.join("a");
        let b = a.join("b");
        let c = b.join("c");
        fs::create_dir_all(&c).unwrap();
        mk(0o755, &base);
        mk(0o755, &a);
        mk(0o000, &b);

        let owner = uzers::get_effective_uid();
        let id = Identity {
            uid: owner,
            primary_gid: uzers::get_current_gid(),
            groups: vec![uzers::get_current_gid()],
            name: Some("tester".into()),
            is_self: false,
        };

        let r = evaluate(&id, &c);
        if owner != 0 {
            assert!(matches!(r.status, LayerStatus::Block));
            assert!(r.certainty == Certainty::Proven);

            let blocker = r.evidence.last().unwrap();
            assert_eq!(blocker.path.as_deref(), Some(b.as_path()));
            assert!(r.detail.contains(&b.display().to_string()));

            assert!(r
                .evidence
                .iter()
                .any(|e| e.path.as_deref() == Some(a.as_path())));
            assert!(r
                .evidence
                .iter()
                .all(|e| e.path.as_deref() != Some(c.as_path())));

            let fix = &r.fixes[0];
            let FixAction::Run { argv } = &fix.action else {
                panic!("expected run fix");
            };
            assert_eq!(argv.last().unwrap(), &b.display().to_string());
            assert!(argv.iter().any(|s| s == "u+x"));
            assert!(
                !fix.needs_root,
                "current user owns the dir; no sudo to chmod"
            );
        }

        mk(0o755, &b);
        let _ = fs::remove_dir_all(&base);
    }
}
