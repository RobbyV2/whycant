use crate::engine::{Layer, LayerResult};
use crate::identity::Identity;
use crate::op::Op;
use crate::report::{Evidence, EvidenceSource, LayerId};
use std::path::Path;

pub struct NetfsLayer;

fn is_write(op: Op) -> bool {
    matches!(op, Op::Write | Op::Delete | Op::Create)
}

fn under(target: &str, mp: &str) -> bool {
    mp == "/" || target == mp || target.starts_with(&format!("{mp}/"))
}

fn mount_for<'a>(target: &str, mounts: &'a str) -> Option<(&'a str, &'a str)> {
    mounts
        .lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            let _dev = f.next()?;
            let mp = f.next()?;
            let fstype = f.next()?;
            under(target, mp).then_some((mp, fstype))
        })
        .max_by_key(|(mp, _)| mp.len())
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
        let Some((mp, fstype)) = mount_for(&target, &mounts) else {
            return LayerResult::skip();
        };
        let net = matches!(fstype, "nfs" | "nfs4" | "cifs" | "smb3");
        match net && id.uid == 0 && is_write(op) {
            false => LayerResult::skip(),
            true => LayerResult::suspect(
                format!(
                    "{mp} is a {fstype} mount; root_squash may remap uid 0 to nobody on the server, so a root write can be denied server-side in a way not visible from the client"
                ),
                vec![Evidence {
                    source: EvidenceSource::MountOpts,
                    raw: format!("{mp} type {fstype}"),
                    path: Some(abs.to_path_buf()),
                }],
                Vec::new(),
            ),
        }
    }
}
