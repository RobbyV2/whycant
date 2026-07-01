use crate::engine::{Layer, LayerResult};
use crate::identity::Identity;
use crate::op::Op;
use crate::report::LayerId;
use std::path::Path;

pub struct AclLayer;

impl Layer for AclLayer {
    fn name(&self) -> &str {
        "acl"
    }
    fn order(&self) -> u8 {
        4
    }
    fn id(&self) -> LayerId {
        LayerId::Acl
    }
    fn check(&self, id: &Identity, path: &Path, op: Op) -> LayerResult {
        #[cfg(all(feature = "acl", any(target_os = "linux", target_os = "freebsd")))]
        {
            posix::check(id, path, op)
        }
        #[cfg(not(all(feature = "acl", any(target_os = "linux", target_os = "freebsd"))))]
        {
            let _ = (id, path, op);
            LayerResult::skip()
        }
    }
}

#[cfg(all(feature = "acl", any(target_os = "linux", target_os = "freebsd")))]
mod posix {
    use crate::engine::LayerResult;
    use crate::identity::Identity;
    use crate::op::{gating_node, GateTarget, Op};
    use crate::report::{Certainty, Evidence, EvidenceSource, Fix, FixAction, Risk};
    use exacl::{getfacl, AclEntry, AclEntryKind, Perm};
    use std::fs;
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};
    use uzers::{get_group_by_name, get_user_by_name};

    pub struct Denial {
        line: String,
        raw: Perm,
        eff: Perm,
        mask: Option<Perm>,
        class: &'static str,
    }

    pub fn check(id: &Identity, path: &Path, op: Op) -> LayerResult {
        let target = match gating_node(op, path) {
            GateTarget::Node(p) => p.to_path_buf(),
            GateTarget::Parent { of, .. } => parent_of(of),
        };
        let meta = match fs::metadata(&target) {
            Ok(m) => m,
            Err(_) => return LayerResult::skip(),
        };
        let entries = match getfacl(&target, None) {
            Ok(e) => e,
            Err(_) => return LayerResult::skip(),
        };
        if !extended(&entries) {
            return LayerResult::skip();
        }
        let need = op_perms(op);
        match evaluate(&entries, meta.uid(), meta.gid(), id, need) {
            None => LayerResult::pass(dump(&entries, &target)),
            Some(d) => block(id, op, &target, meta.uid(), d),
        }
    }

    fn evaluate(
        entries: &[AclEntry],
        owner_uid: u32,
        owning_gid: u32,
        id: &Identity,
        need: Perm,
    ) -> Option<Denial> {
        let mask = entries
            .iter()
            .find(|e| matches!(e.kind, AclEntryKind::Mask))
            .map(|e| e.perms);
        if id.uid == owner_uid {
            return None;
        }
        if let Some(e) = entries.iter().find(|e| {
            matches!(e.kind, AclEntryKind::User) && !e.name.is_empty() && user_matches(&e.name, id)
        }) {
            return decide(e, mask, "named user", need);
        }
        let matched: Vec<&AclEntry> = entries
            .iter()
            .filter(|e| group_matches(e, owning_gid, id))
            .collect();
        match matched.iter().any(|e| clip(e.perms, mask).contains(need)) {
            true => None,
            false => match matched.iter().max_by_key(|e| clip(e.perms, mask).bits()) {
                Some(best) => decide(best, mask, "group", need),
                None => None,
            },
        }
    }

    fn decide(e: &AclEntry, mask: Option<Perm>, class: &'static str, need: Perm) -> Option<Denial> {
        let masked = !matches!(class, "owner" | "other");
        let eff = match masked {
            true => clip(e.perms, mask),
            false => e.perms,
        };
        match eff.contains(need) {
            true => None,
            false => Some(Denial {
                line: acl_line(e),
                raw: e.perms,
                eff,
                mask: masked.then_some(mask).flatten(),
                class,
            }),
        }
    }

    fn group_matches(e: &AclEntry, owning_gid: u32, id: &Identity) -> bool {
        match e.kind {
            AclEntryKind::Group if e.name.is_empty() => in_gid(id, owning_gid),
            AclEntryKind::Group => group_gid(&e.name).map(|g| in_gid(id, g)).unwrap_or(false),
            _ => false,
        }
    }

    fn block(id: &Identity, op: Op, target: &Path, owner_uid: u32, d: Denial) -> LayerResult {
        let who = who(id);
        let entry_line = match d.eff != d.raw {
            true => format!("{}\t#effective:{}", d.line, perm_str(d.eff)),
            false => d.line.clone(),
        };
        let mut ev = vec![Evidence {
            source: EvidenceSource::Getfacl,
            raw: entry_line,
            path: Some(target.to_path_buf()),
        }];
        let mask_str = match d.mask {
            Some(m) => {
                let line = format!("mask::{}", perm_str(m));
                ev.push(Evidence {
                    source: EvidenceSource::Getfacl,
                    raw: line.clone(),
                    path: Some(target.to_path_buf()),
                });
                format!("mask {}", perm_str(m))
            }
            None => "no mask".into(),
        };
        let detail = format!(
            "ACL denies {} for {who}: POSIX.1e {} entry {} grants {} under {mask_str}",
            op_word(op),
            d.class,
            d.line,
            perm_str(d.eff)
        );
        let fixes = vec![grant_fix(id, op, target, owner_uid)];
        LayerResult::block(Certainty::Proven, detail, ev, fixes)
    }

    fn grant_fix(id: &Identity, op: Op, target: &Path, owner_uid: u32) -> Fix {
        let who = who(id);
        let perm = op_letters(op);
        let pstr = target.to_string_lossy().into_owned();
        Fix {
            action: FixAction::Run {
                argv: vec![
                    "setfacl".into(),
                    "-m".into(),
                    format!("u:{who}:{perm}"),
                    pstr.clone(),
                ],
            },
            needs_root: id.uid != owner_uid,
            description: format!("grant {who} {perm} on {pstr} via a named-user ACL entry"),
            risk: Risk::Low,
            rationale: "named-user entry only".into(),
        }
    }

    fn dump(entries: &[AclEntry], target: &Path) -> Vec<Evidence> {
        entries
            .iter()
            .map(|e| Evidence {
                source: EvidenceSource::Getfacl,
                raw: acl_line(e),
                path: Some(target.to_path_buf()),
            })
            .collect()
    }

    fn extended(entries: &[AclEntry]) -> bool {
        entries.iter().any(|e| match e.kind {
            AclEntryKind::Mask => true,
            AclEntryKind::User | AclEntryKind::Group => !e.name.is_empty(),
            _ => false,
        })
    }

    fn acl_line(e: &AclEntry) -> String {
        let (tag, name) = match e.kind {
            AclEntryKind::User => ("user", e.name.as_str()),
            AclEntryKind::Group => ("group", e.name.as_str()),
            AclEntryKind::Mask => ("mask", ""),
            _ => ("other", ""),
        };
        format!("{tag}:{name}:{}", perm_str(e.perms))
    }

    fn perm_str(p: Perm) -> String {
        let bit = |b: Perm, c: char| match p.contains(b) {
            true => c,
            false => '-',
        };
        format!(
            "{}{}{}",
            bit(Perm::READ, 'r'),
            bit(Perm::WRITE, 'w'),
            bit(Perm::EXECUTE, 'x')
        )
    }

    fn clip(p: Perm, mask: Option<Perm>) -> Perm {
        match mask {
            Some(m) => p & m,
            None => p,
        }
    }

    fn in_gid(id: &Identity, gid: u32) -> bool {
        id.primary_gid == gid || id.groups.contains(&gid)
    }

    fn user_matches(name: &str, id: &Identity) -> bool {
        match name.parse::<u32>() {
            Ok(uid) => uid == id.uid,
            Err(_) => {
                id.name.as_deref() == Some(name)
                    || get_user_by_name(name)
                        .map(|u| u.uid() == id.uid)
                        .unwrap_or(false)
            }
        }
    }

    fn group_gid(name: &str) -> Option<u32> {
        match name.parse::<u32>() {
            Ok(g) => Some(g),
            Err(_) => get_group_by_name(name).map(|g| g.gid()),
        }
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

    fn op_perms(op: Op) -> Perm {
        match op {
            Op::Read => Perm::READ,
            Op::Write => Perm::WRITE,
            Op::Exec | Op::Traverse => Perm::EXECUTE,
            Op::Delete | Op::Create => Perm::WRITE | Perm::EXECUTE,
        }
    }

    fn op_letters(op: Op) -> &'static str {
        match op {
            Op::Read => "r",
            Op::Write => "w",
            Op::Exec | Op::Traverse => "x",
            Op::Delete | Op::Create => "wx",
        }
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

    #[cfg(test)]
    mod tests {
        use super::*;
        use exacl::Flag;
        use std::sync::atomic::{AtomicU32, Ordering};

        fn ident(uid: u32, gid: u32, groups: Vec<u32>) -> Identity {
            Identity {
                uid,
                primary_gid: gid,
                groups,
                name: None,
                is_self: false,
            }
        }

        fn entry(kind: AclEntryKind, name: &str, perms: Perm) -> AclEntry {
            AclEntry {
                kind,
                name: name.into(),
                perms,
                flags: Flag::empty(),
                allow: true,
            }
        }

        fn base_with_named_user(user_perms: Perm, mask: Perm) -> Vec<AclEntry> {
            vec![
                entry(
                    AclEntryKind::User,
                    "",
                    Perm::READ | Perm::WRITE | Perm::EXECUTE,
                ),
                entry(AclEntryKind::User, "99991", user_perms),
                entry(AclEntryKind::Group, "", Perm::READ),
                entry(AclEntryKind::Mask, "", mask),
                entry(AclEntryKind::Other, "", Perm::READ),
            ]
        }

        #[test]
        fn named_user_clipped_by_mask_is_fingered() {
            let acl = base_with_named_user(Perm::READ | Perm::EXECUTE, Perm::READ);
            let id = ident(99991, 5000, vec![5000]);
            let d = evaluate(&acl, 1000, 1000, &id, Perm::EXECUTE).expect("must deny");
            assert_eq!(d.line, "user:99991:r-x");
            assert!(d.eff == Perm::READ);
            assert!(d.mask == Some(Perm::READ));
            assert_eq!(d.class, "named user");
        }

        #[test]
        fn named_user_within_mask_passes() {
            let acl = base_with_named_user(Perm::READ | Perm::EXECUTE, Perm::READ | Perm::EXECUTE);
            let id = ident(99991, 5000, vec![5000]);
            assert!(evaluate(&acl, 1000, 1000, &id, Perm::EXECUTE).is_none());
        }

        #[test]
        fn owning_group_masked_denial() {
            let acl = vec![
                entry(
                    AclEntryKind::User,
                    "",
                    Perm::READ | Perm::WRITE | Perm::EXECUTE,
                ),
                entry(AclEntryKind::Group, "", Perm::READ | Perm::WRITE),
                entry(AclEntryKind::Mask, "", Perm::READ),
                entry(AclEntryKind::Other, "", Perm::READ),
            ];
            let id = ident(4242, 7777, vec![7777]);
            let d = evaluate(&acl, 1000, 7777, &id, Perm::WRITE).expect("must deny");
            assert_eq!(d.line, "group::rw-");
            assert!(d.eff == Perm::READ);
            assert_eq!(d.class, "group");
        }

        #[test]
        fn owner_defers_to_dac() {
            let acl = base_with_named_user(Perm::READ, Perm::READ);
            let id = ident(1000, 1000, vec![1000]);
            assert!(evaluate(&acl, 1000, 1000, &id, Perm::WRITE).is_none());
        }

        #[test]
        fn named_group_union_grants_when_one_matches() {
            let acl = vec![
                entry(
                    AclEntryKind::User,
                    "",
                    Perm::READ | Perm::WRITE | Perm::EXECUTE,
                ),
                entry(AclEntryKind::Group, "", Perm::READ),
                entry(AclEntryKind::Group, "6001", Perm::READ | Perm::WRITE),
                entry(
                    AclEntryKind::Mask,
                    "",
                    Perm::READ | Perm::WRITE | Perm::EXECUTE,
                ),
                entry(AclEntryKind::Other, "", Perm::empty()),
            ];
            let id = ident(4242, 5000, vec![5000, 6001]);
            assert!(evaluate(&acl, 1000, 9999, &id, Perm::WRITE).is_none());
        }

        struct Tmp(PathBuf);
        impl Drop for Tmp {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        fn tmpdir() -> Tmp {
            static C: AtomicU32 = AtomicU32::new(0);
            let n = C.fetch_add(1, Ordering::Relaxed);
            let p = std::env::temp_dir().join(format!("whycant-acl-{}-{}", std::process::id(), n));
            fs::create_dir_all(&p).unwrap();
            Tmp(p)
        }

        #[test]
        fn real_acl_fingers_named_user_if_supported() {
            let t = tmpdir();
            let f = t.0.join("guarded");
            fs::write(&f, b"x").unwrap();
            let m = fs::metadata(&f).unwrap();
            let acl = vec![
                entry(AclEntryKind::User, "", Perm::READ | Perm::WRITE),
                entry(AclEntryKind::User, "99991", Perm::READ),
                entry(AclEntryKind::Group, "", Perm::READ),
                entry(AclEntryKind::Mask, "", Perm::READ),
                entry(AclEntryKind::Other, "", Perm::READ),
            ];
            if exacl::setfacl(&[&f], &acl, None).is_err() {
                return;
            }
            let id = ident(99991, m.gid() + 4242, vec![m.gid() + 4242]);
            let r = check(&id, &f, Op::Write);
            assert!(matches!(r.status, crate::engine::LayerStatus::Block));
            assert!(r.certainty == Certainty::Proven);
            assert!(r.evidence.iter().any(|e| e.raw.contains("user:99991")));
            assert!(r
                .fixes
                .iter()
                .any(|fx| fx.argv().first().map(String::as_str) == Some("setfacl")));
        }
    }
}
