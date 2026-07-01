use crate::engine::{Layer, LayerResult};
use crate::identity::Identity;
use crate::op::Op;
use crate::report::LayerId;
use std::path::Path;

pub struct CapsLayer;

impl Layer for CapsLayer {
    fn name(&self) -> &str {
        "caps"
    }
    fn order(&self) -> u8 {
        7
    }
    fn id(&self) -> LayerId {
        LayerId::Capabilities
    }
    fn check(&self, id: &Identity, path: &Path, op: Op) -> LayerResult {
        #[cfg(target_os = "linux")]
        {
            return linux_check(id, path, op);
        }
        #[allow(unreachable_code)]
        {
            let _ = (id, path, op);
            LayerResult::skip()
        }
    }
}

#[cfg(target_os = "linux")]
use crate::engine::LayerStatus;
#[cfg(target_os = "linux")]
use crate::report::{Certainty, Evidence, EvidenceSource};
#[cfg(target_os = "linux")]
use caps::{CapSet, Capability};

#[cfg(target_os = "linux")]
fn linux_check(id: &Identity, path: &Path, op: Op) -> LayerResult {
    let mut evidence = Vec::new();
    let mut notes = Vec::new();

    if id.is_self {
        if let Ok(effective) = caps::read(None, CapSet::Effective) {
            let mut held: Vec<Capability> = effective
                .into_iter()
                .filter(|c| dac_bypass_note(*c).is_some())
                .collect();
            held.sort_by_key(Capability::index);
            for cap in held {
                let desc = dac_bypass_note(cap).unwrap_or("");
                evidence.push(Evidence {
                    source: EvidenceSource::Capability,
                    raw: format!("{cap} (effective): {desc}"),
                    path: None,
                });
                notes.push(format!("holds {}", cap.to_string().to_lowercase()));
            }
        }
    }

    if matches!(op, Op::Exec) {
        if let Some(fc) = read_file_caps(path) {
            evidence.push(getcap_line(&fc, path));
            let names = cap_names(fc.permitted);
            if !names.is_empty() {
                notes.push(format!("file caps {}", names.join(",")));
            }
        }
    }

    let detail = match (notes.is_empty(), id.is_self) {
        (false, true) => format!(
            "{} bypasses DAC for {}; annotation only",
            notes.join("; "),
            op_word(op)
        ),
        (false, false) => format!("{} on target; annotation only", notes.join("; ")),
        (true, _) => format!("no capability affects {} of the target", op_word(op)),
    };

    info(evidence, detail)
}

#[cfg(target_os = "linux")]
fn info(evidence: Vec<Evidence>, detail: String) -> LayerResult {
    LayerResult {
        status: LayerStatus::Skip,
        certainty: Certainty::Proven,
        evidence,
        fixes: Vec::new(),
        detail,
    }
}

#[cfg(target_os = "linux")]
fn dac_bypass_note(cap: Capability) -> Option<&'static str> {
    match cap {
        Capability::CAP_DAC_OVERRIDE => Some("bypasses r/w/x checks"),
        Capability::CAP_DAC_READ_SEARCH => Some("bypasses read/traverse checks"),
        Capability::CAP_FOWNER => Some("bypasses owner checks (sticky delete, mode)"),
        _ => None,
    }
}

#[cfg(target_os = "linux")]
struct FileCaps {
    permitted: u64,
    inheritable: u64,
    effective: bool,
}

#[cfg(target_os = "linux")]
const VFS_CAP_REVISION_MASK: u32 = 0xFF00_0000;
#[cfg(target_os = "linux")]
const VFS_CAP_FLAGS_EFFECTIVE: u32 = 0x0000_0001;
#[cfg(target_os = "linux")]
const VFS_CAP_REVISION_1: u32 = 0x0100_0000;
#[cfg(target_os = "linux")]
const VFS_CAP_REVISION_2: u32 = 0x0200_0000;
#[cfg(target_os = "linux")]
const VFS_CAP_REVISION_3: u32 = 0x0300_0000;

#[cfg(target_os = "linux")]
fn decode_vfs_caps(blob: &[u8]) -> Option<FileCaps> {
    let le = |o: usize| {
        blob.get(o..o + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    let magic = le(0)?;
    let effective = magic & VFS_CAP_FLAGS_EFFECTIVE != 0;
    let (permitted, inheritable) = match magic & VFS_CAP_REVISION_MASK {
        VFS_CAP_REVISION_1 => (u64::from(le(4)?), u64::from(le(8)?)),
        VFS_CAP_REVISION_2 | VFS_CAP_REVISION_3 => (
            u64::from(le(4)?) | (u64::from(le(12)?) << 32),
            u64::from(le(8)?) | (u64::from(le(16)?) << 32),
        ),
        _ => return None,
    };
    Some(FileCaps {
        permitted,
        inheritable,
        effective,
    })
}

#[cfg(target_os = "linux")]
fn read_file_caps(path: &Path) -> Option<FileCaps> {
    let blob = xattr::get(path, "security.capability").ok()??;
    decode_vfs_caps(&blob)
}

#[cfg(target_os = "linux")]
fn sorted_caps() -> Vec<Capability> {
    let mut all: Vec<Capability> = caps::all().into_iter().collect();
    all.sort_by_key(Capability::index);
    all
}

#[cfg(target_os = "linux")]
fn cap_names(mask: u64) -> Vec<String> {
    sorted_caps()
        .into_iter()
        .filter(|c| mask & c.bitmask() != 0)
        .map(|c| c.to_string().to_lowercase())
        .collect()
}

#[cfg(target_os = "linux")]
fn getcap_line(fc: &FileCaps, path: &Path) -> Evidence {
    let mut groups: Vec<(String, Vec<String>)> = Vec::new();
    for cap in sorted_caps() {
        let bm = cap.bitmask();
        let p = fc.permitted & bm != 0;
        let i = fc.inheritable & bm != 0;
        if !p && !i {
            continue;
        }
        let mut flags = String::new();
        if fc.effective && p {
            flags.push('e');
        }
        if i {
            flags.push('i');
        }
        if p {
            flags.push('p');
        }
        let name = cap.to_string().to_lowercase();
        match groups.iter_mut().find(|(f, _)| *f == flags) {
            Some((_, names)) => names.push(name),
            None => groups.push((flags, vec![name])),
        }
    }
    let rendered: Vec<String> = groups
        .into_iter()
        .map(|(flags, names)| format!("{}={}", names.join(","), flags))
        .collect();
    Evidence {
        source: EvidenceSource::FileCap,
        raw: format!("{} {}", path.display(), rendered.join(" ")),
        path: Some(path.to_path_buf()),
    }
}

#[cfg(target_os = "linux")]
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

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    fn ident(is_self: bool) -> Identity {
        Identity {
            uid: 4242,
            primary_gid: 4242,
            groups: vec![4242],
            name: Some("t".into()),
            is_self,
        }
    }

    fn rev2_blob(permitted_low: u32, effective: bool) -> Vec<u8> {
        let magic = VFS_CAP_REVISION_2
            | if effective {
                VFS_CAP_FLAGS_EFFECTIVE
            } else {
                0
            };
        let mut b = Vec::new();
        for word in [magic, permitted_low, 0, 0, 0] {
            b.extend_from_slice(&word.to_le_bytes());
        }
        b
    }

    #[test]
    fn dac_override_recognized_as_bypass() {
        assert!(dac_bypass_note(Capability::CAP_DAC_OVERRIDE).is_some());
        assert!(dac_bypass_note(Capability::CAP_DAC_READ_SEARCH).is_some());
        assert!(dac_bypass_note(Capability::CAP_FOWNER).is_some());
        assert!(dac_bypass_note(Capability::CAP_NET_BIND_SERVICE).is_none());
    }

    #[test]
    fn decode_names_file_capability() {
        let bit = Capability::CAP_NET_BIND_SERVICE.bitmask() as u32;
        let fc = decode_vfs_caps(&rev2_blob(bit, true)).unwrap();
        assert!(fc.effective);
        assert!(fc.permitted & Capability::CAP_NET_BIND_SERVICE.bitmask() != 0);
        assert_eq!(cap_names(fc.permitted), vec!["cap_net_bind_service"]);
        let ev = getcap_line(&fc, Path::new("/usr/bin/x"));
        assert!(ev.raw.contains("cap_net_bind_service=ep"));
    }

    #[test]
    fn short_or_unknown_blob_decodes_to_none() {
        assert!(decode_vfs_caps(&[]).is_none());
        assert!(decode_vfs_caps(&[0, 0, 0]).is_none());
        assert!(decode_vfs_caps(&0u32.to_le_bytes()).is_none());
    }

    #[test]
    fn skip_with_note_when_no_capability_present() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("plain");
        std::fs::write(&f, b"x").unwrap();
        let r = CapsLayer.check(&ident(false), &f, Op::Read);
        assert!(matches!(r.status, LayerStatus::Skip));
        assert!(r.evidence.is_empty());
        assert!(!r.detail.is_empty());
    }
}
