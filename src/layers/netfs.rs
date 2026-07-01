use crate::engine::{Layer, LayerResult};
use crate::identity::Identity;
use crate::op::Op;
use crate::report::{Evidence, EvidenceSource, Fix, FixAction, LayerId, Risk};
use std::path::Path;

pub struct NetfsLayer;

enum NetKind {
    Nfs,
    Cifs,
    Other(&'static str),
}

fn classify(fstype: &str) -> Option<NetKind> {
    match fstype {
        "nfs" | "nfs4" => Some(NetKind::Nfs),
        "cifs" | "smb3" | "smb" => Some(NetKind::Cifs),
        "fuse.sshfs" => Some(NetKind::Other("fuse.sshfs")),
        "afs" => Some(NetKind::Other("afs")),
        _ => None,
    }
}

fn is_write(op: Op) -> bool {
    matches!(op, Op::Write | Op::Delete | Op::Create)
}

fn under(target: &str, mp: &str) -> bool {
    mp == "/" || target == mp || target.starts_with(&format!("{mp}/"))
}

struct MountInfo<'a> {
    source: &'a str,
    mp: &'a str,
    fstype: &'a str,
    opts: &'a str,
}

fn parse_mount(line: &str) -> Option<MountInfo<'_>> {
    let mut f = line.split_whitespace();
    let source = f.next()?;
    let mp = f.next()?;
    let fstype = f.next()?;
    let opts = f.next()?;
    Some(MountInfo {
        source,
        mp,
        fstype,
        opts,
    })
}

fn mount_for<'a>(target: &str, mounts: &'a str) -> Option<MountInfo<'a>> {
    mounts
        .lines()
        .filter_map(parse_mount)
        .filter(|m| under(target, m.mp))
        .max_by_key(|m| m.mp.len())
}

fn has_flag(opts: &str, flag: &str) -> bool {
    opts.split(',').any(|o| o == flag)
}

fn forced_creds(opts: &str) -> Vec<&str> {
    let keys = ["uid=", "gid=", "file_mode=", "dir_mode="];
    opts.split(',')
        .filter(|o| keys.iter().any(|k| o.starts_with(k)))
        .collect()
}

fn advice(text: impl Into<String>) -> Fix {
    Fix {
        action: FixAction::Advice { text: text.into() },
        needs_root: false,
        description: "server-side check".into(),
        risk: Risk::Low,
        rationale:
            "server arbitrates access"
                .into(),
    }
}

struct Suspect {
    detail: String,
    ev: String,
    fixes: Vec<Fix>,
}

fn analyze(m: &MountInfo, target_root: bool, euid_root: bool, op: Op) -> Option<Suspect> {
    let ev = format!("{} on {} type {} ({})", m.source, m.mp, m.fstype, m.opts);
    let write = is_write(op);
    match classify(m.fstype)? {
        NetKind::Nfs => {
            let mut notes = vec![format!(
                "{} is an {} mount; NFS authorizes by numeric uid",
                m.mp, m.fstype
            )];
            let mut fixes = vec![advice(
                "confirm the uid maps server-side (idmapd/NFSv4)",
            )];
            if write && (target_root || euid_root) {
                notes.push("root, so root_squash may reject this write".into());
                fixes.push(advice(
                    "check root_squash in /etc/exports",
                ));
            }
            if write && has_flag(m.opts, "ro") {
                notes.push(
                    "ro mount; export may be read-only".into(),
                );
                fixes.push(advice(
                    "verify export is rw in /etc/exports",
                ));
            }
            Some(Suspect {
                detail: notes.join("; "),
                ev,
                fixes,
            })
        }
        NetKind::Cifs => {
            let creds = forced_creds(m.opts);
            let cred_str = match creds.is_empty() {
                true => String::from("mount credentials"),
                false => creds.join(","),
            };
            Some(Suspect {
                detail: format!(
                    "{} is a {} mount; mount credentials ({}) govern access",
                    m.mp, m.fstype, cred_str
                ),
                ev,
                fixes: vec![
                    advice("verify share ACL on the server"),
                    advice("remount with correct credentials"),
                ],
            })
        }
        NetKind::Other(name) => Some(Suspect {
            detail: format!(
                "{} is a {} network mount; remote host arbitrates access",
                m.mp, name
            ),
            ev,
            fixes: vec![advice("confirm remote permissions on the server")],
        }),
    }
}

impl Layer for NetfsLayer {
    fn name(&self) -> &str {
        "netfs"
    }
    fn order(&self) -> u8 {
        10
    }
    fn id(&self) -> LayerId {
        LayerId::NetworkFs
    }
    fn check(&self, id: &Identity, path: &Path, op: Op) -> LayerResult {
        let abs = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
        let mounts = match std::fs::read_to_string("/proc/mounts") {
            Ok(s) => s,
            Err(_) => return LayerResult::skip(),
        };
        let target = abs.to_string_lossy();
        let Some(m) = mount_for(&target, &mounts) else {
            return LayerResult::skip();
        };
        let euid_root = uzers::get_effective_uid() == 0;
        match analyze(&m, id.uid == 0, euid_root, op) {
            None => LayerResult::skip(),
            Some(s) => LayerResult::suspect(
                s.detail,
                vec![Evidence {
                    source: EvidenceSource::MountOpts,
                    raw: s.ev,
                    path: Some(abs.to_path_buf()),
                }],
                s.fixes,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mi<'a>(fstype: &'a str, opts: &'a str) -> MountInfo<'a> {
        MountInfo {
            source: "s:/e",
            mp: "/mnt",
            fstype,
            opts,
        }
    }

    #[test]
    fn parses_mount_line() {
        let m = parse_mount("server:/export /mnt/nfs nfs4 rw,relatime,vers=4.2 0 0").unwrap();
        assert_eq!(m.source, "server:/export");
        assert_eq!(m.mp, "/mnt/nfs");
        assert_eq!(m.fstype, "nfs4");
        assert_eq!(m.opts, "rw,relatime,vers=4.2");
    }

    #[test]
    fn nfs_root_write_is_root_squash() {
        let m = mi("nfs", "rw");
        let s = analyze(&m, true, false, Op::Write).unwrap();
        assert!(s.detail.contains("root_squash"));
    }

    #[test]
    fn nfs_ro_option_notes_export() {
        let m = mi("nfs", "ro,relatime");
        let s = analyze(&m, false, false, Op::Write).unwrap();
        assert!(s.detail.contains("read-only"));
    }

    #[test]
    fn cifs_uid_is_credential_suspect() {
        let m = mi("cifs", "rw,uid=1000,gid=1000,file_mode=0755");
        let s = analyze(&m, false, false, Op::Read).unwrap();
        assert!(s.detail.contains("credentials"));
        assert!(s.ev.contains("uid=1000"));
    }

    #[test]
    fn ext4_is_skipped() {
        let m = mi("ext4", "rw");
        assert!(analyze(&m, true, true, Op::Write).is_none());
    }
}
