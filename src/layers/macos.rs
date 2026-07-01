use crate::engine::{Layer, LayerResult};
use crate::identity::Identity;
use crate::op::Op;
use crate::report::LayerId;
use std::path::Path;

pub struct MacosLayer;

impl Layer for MacosLayer {
    fn name(&self) -> &str {
        "macos"
    }
    fn order(&self) -> u8 {
        9
    }
    fn id(&self) -> LayerId {
        LayerId::MacosSip
    }
    fn check(&self, id: &Identity, path: &Path, op: Op) -> LayerResult {
        let _ = (id, path, op);
        #[cfg(target_os = "macos")]
        {
            return read_and_classify(path, op);
        }
        #[allow(unreachable_code)]
        LayerResult::skip()
    }
}

#[cfg(target_os = "macos")]
fn read_and_classify(path: &Path, op: Op) -> LayerResult {
    let flags = stat_flags(path).unwrap_or(0);
    let quarantine = read_quarantine(path);
    let home = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_default();
    pure::classify(flags, quarantine.as_deref(), path, &home, op)
}

#[cfg(target_os = "macos")]
fn stat_flags(path: &Path) -> Option<u32> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let c = CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    match unsafe { libc::stat(c.as_ptr(), &mut st) } {
        0 => Some(st.st_flags as u32),
        _ => None,
    }
}

#[cfg(target_os = "macos")]
fn read_quarantine(path: &Path) -> Option<String> {
    xattr::get(path, pure::QUARANTINE_XATTR)
        .ok()
        .flatten()
        .map(|b| String::from_utf8_lossy(&b).into_owned())
}

#[cfg(any(target_os = "macos", test))]
mod pure {
    use crate::engine::LayerResult;
    use crate::op::Op;
    use crate::report::{Certainty, Evidence, EvidenceSource, Fix, FixAction, Risk};
    use std::path::Path;

    pub const SF_RESTRICTED: u32 = 0x0008_0000;
    pub const QUARANTINE_XATTR: &str = "com.apple.quarantine";

    pub const TCC_LOCATIONS: &[&str] = &[
        "Library/Mail",
        "Library/Messages",
        "Library/Application Support/com.apple.TCC",
        "Library/Safari",
        "Library/Cookies",
        "Library/HomeKit",
        "Pictures/Photos Library.photoslibrary",
    ];

    pub fn sip_restricted(flags: u32, op: Op) -> bool {
        matches!(op, Op::Write | Op::Delete | Op::Create) && flags & SF_RESTRICTED != 0
    }

    pub fn quarantine_blocks_exec(present: bool, op: Op) -> bool {
        present && op == Op::Exec
    }

    pub fn is_tcc_protected(path: &Path, home: &Path) -> Option<&'static str> {
        TCC_LOCATIONS
            .iter()
            .copied()
            .find(|rel| path.starts_with(home.join(rel)))
    }

    pub fn classify(
        flags: u32,
        quarantine: Option<&str>,
        path: &Path,
        home: &Path,
        op: Op,
    ) -> LayerResult {
        if sip_restricted(flags, op) {
            return sip_block(path, op);
        }
        if quarantine_blocks_exec(quarantine.is_some(), op) {
            return quarantine_suspect(path, quarantine.unwrap_or_default());
        }
        match is_tcc_protected(path, home) {
            Some(loc) => tcc_suspect(path, loc),
            None => LayerResult::skip(),
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

    fn sip_block(path: &Path, op: Op) -> LayerResult {
        let detail = format!(
            "SIP restricts {} on {}: SF_RESTRICTED set",
            op_word(op),
            path.display()
        );
        let evidence = Evidence {
            source: EvidenceSource::Statflags,
            raw: format!("restricted {}", path.display()),
            path: Some(path.to_path_buf()),
        };
        LayerResult::block(Certainty::Proven, detail, vec![evidence], vec![sip_fix()])
    }

    fn sip_fix() -> Fix {
        Fix {
            action: FixAction::Advice {
                text: "SIP-protected; disable SIP from recovery".into(),
            },
            needs_root: false,
            description: "SIP guards this path".into(),
            risk: Risk::High,
            rationale: "csrutil disable from recovery".into(),
        }
    }

    fn quarantine_suspect(path: &Path, value: &str) -> LayerResult {
        let detail = format!(
            "Gatekeeper may block first run of {}: com.apple.quarantine set",
            path.display()
        );
        let evidence = Evidence {
            source: EvidenceSource::Xattr,
            raw: format!("{QUARANTINE_XATTR}={value} {}", path.display()),
            path: Some(path.to_path_buf()),
        };
        LayerResult::suspect(detail, vec![evidence], vec![quarantine_fix(path)])
    }

    fn quarantine_fix(path: &Path) -> Fix {
        Fix {
            action: FixAction::Advice {
                text: format!(
                    "xattr -d com.apple.quarantine {} or approve in System Settings > Privacy & Security",
                    path.display()
                ),
            },
            needs_root: false,
            description: "clear the Gatekeeper quarantine attribute".into(),
            risk: Risk::Low,
            rationale: "skips Gatekeeper first-run check".into(),
        }
    }

    fn tcc_suspect(path: &Path, loc: &str) -> LayerResult {
        let detail = "TCC-protected; terminal may lack Full Disk Access".to_string();
        let evidence = Evidence {
            source: EvidenceSource::Xattr,
            raw: format!("{} under TCC-protected location ~/{loc}", path.display()),
            path: Some(path.to_path_buf()),
        };
        LayerResult::suspect(detail, vec![evidence], vec![tcc_fix()])
    }

    fn tcc_fix() -> Fix {
        Fix {
            action: FixAction::Advice {
                text: "grant your terminal Full Disk Access in System Settings > Privacy & Security > Full Disk Access, then retry".into(),
            },
            needs_root: false,
            description: "grant Full Disk Access to the terminal".into(),
            risk: Risk::Medium,
            rationale: "grant Full Disk Access".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::pure::*;
    use crate::engine::LayerStatus;
    use crate::op::Op;
    use crate::report::{Certainty, FixAction};
    use std::path::{Path, PathBuf};

    fn home() -> PathBuf {
        PathBuf::from("/Users/tester")
    }

    #[test]
    fn sip_restricted_blocks_write_delete_create() {
        for op in [Op::Write, Op::Delete, Op::Create] {
            assert!(sip_restricted(SF_RESTRICTED, op));
        }
    }

    #[test]
    fn sip_ignores_read_exec_traverse() {
        for op in [Op::Read, Op::Exec, Op::Traverse] {
            assert!(!sip_restricted(SF_RESTRICTED, op));
        }
    }

    #[test]
    fn sip_absent_never_blocks() {
        for op in [Op::Write, Op::Delete, Op::Create] {
            assert!(!sip_restricted(0, op));
        }
    }

    #[test]
    fn sip_write_is_a_proven_block_with_advice() {
        let r = classify(
            SF_RESTRICTED,
            None,
            Path::new("/System/x"),
            &home(),
            Op::Write,
        );
        assert!(matches!(r.status, LayerStatus::Block));
        assert!(matches!(r.certainty, Certainty::Proven));
        assert!(matches!(r.fixes[0].action, FixAction::Advice { .. }));
        assert!(!r.fixes[0].needs_root);
    }

    #[test]
    fn quarantine_exec_is_a_suspect_note() {
        let r = classify(
            0,
            Some("0081;deadbeef;Safari;"),
            Path::new("/Users/tester/Downloads/tool"),
            &home(),
            Op::Exec,
        );
        assert!(matches!(r.status, LayerStatus::Suspect));
        assert!(matches!(r.certainty, Certainty::Suspected));
    }

    #[test]
    fn quarantine_only_relevant_to_exec() {
        for op in [Op::Read, Op::Write, Op::Delete, Op::Create, Op::Traverse] {
            assert!(!quarantine_blocks_exec(true, op));
        }
        assert!(quarantine_blocks_exec(true, Op::Exec));
        assert!(!quarantine_blocks_exec(false, Op::Exec));
    }

    #[test]
    fn tcc_location_matches_mail_and_reports_suspect() {
        let p = home().join("Library/Mail/V10/box.mbox");
        assert!(is_tcc_protected(&p, &home()).is_some());
        let r = classify(0, None, &p, &home(), Op::Read);
        assert!(matches!(r.status, LayerStatus::Suspect));
        assert!(matches!(r.certainty, Certainty::Suspected));
    }

    #[test]
    fn tcc_covers_tcc_db_with_spaced_path() {
        let p = home().join("Library/Application Support/com.apple.TCC/TCC.db");
        assert!(is_tcc_protected(&p, &home()).is_some());
    }

    #[test]
    fn ordinary_tmp_path_is_not_tcc() {
        assert!(is_tcc_protected(Path::new("/tmp/scratch"), &home()).is_none());
        let r = classify(0, None, Path::new("/tmp/scratch"), &home(), Op::Read);
        assert!(matches!(r.status, LayerStatus::Skip));
    }
}
