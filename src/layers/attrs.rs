use crate::engine::{Layer, LayerResult};
use crate::identity::Identity;
use crate::op::Op;
use crate::report::{Certainty, Evidence, EvidenceSource, Fix, FixAction, LayerId, Risk};
use std::path::{Path, PathBuf};

pub struct AttrLayer;

impl Layer for AttrLayer {
    fn name(&self) -> &str {
        "attrs"
    }
    fn order(&self) -> u8 {
        5
    }
    fn id(&self) -> LayerId {
        LayerId::Attrs
    }
    fn check(&self, _id: &Identity, path: &Path, op: Op) -> LayerResult {
        candidates(op, path)
            .into_iter()
            .find_map(|node| check_node(&node, op))
            .unwrap_or_else(LayerResult::skip)
    }
}

#[derive(Clone, Copy)]
enum Reason {
    Immutable,
    Append,
}

fn classify(immutable: bool, append: bool, op: Op) -> Option<Reason> {
    if !matches!(op, Op::Write | Op::Delete | Op::Create) {
        return None;
    }
    match (immutable, append) {
        (true, _) => Some(Reason::Immutable),
        (false, true) if matches!(op, Op::Write | Op::Delete) => Some(Reason::Append),
        _ => None,
    }
}

fn candidates(op: Op, path: &Path) -> Vec<PathBuf> {
    match op {
        Op::Write => vec![path.to_path_buf()],
        Op::Create => vec![parent_of(path)],
        Op::Delete => vec![path.to_path_buf(), parent_of(path)],
        _ => Vec::new(),
    }
}

fn parent_of(p: &Path) -> PathBuf {
    match p.parent() {
        Some(par) if !par.as_os_str().is_empty() => par.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

#[cfg(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "macos"
))]
fn block_result(path: &Path, op: Op, reason: Reason, evidence: Evidence) -> LayerResult {
    let (letter, word) = match reason {
        Reason::Immutable => ('i', "immutable"),
        Reason::Append => ('a', "append-only"),
    };
    let detail = format!(
        "attrs deny {} on {}: {letter} ({word}) attribute set",
        op_word(op),
        path.display()
    );
    LayerResult::block(
        Certainty::Proven,
        detail,
        vec![evidence],
        vec![fix(path, reason)],
    )
}

#[cfg(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "macos"
))]
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

#[cfg(target_os = "linux")]
fn check_node(path: &Path, op: Op) -> Option<LayerResult> {
    use rustix::fs::{ioctl_getflags, open, IFlags, Mode, OFlags};
    let fd = open(
        path,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .ok()?;
    let flags = ioctl_getflags(&fd).ok()?;
    let reason = classify(
        flags.contains(IFlags::IMMUTABLE),
        flags.contains(IFlags::APPEND),
        op,
    )?;
    Some(block_result(
        path,
        op,
        reason,
        lsattr_line(flags.bits(), path),
    ))
}

#[cfg(target_os = "linux")]
fn lsattr_line(raw: u32, path: &Path) -> Evidence {
    const TABLE: &[(u32, char)] = &[
        (0x0000_0001, 's'),
        (0x0000_0002, 'u'),
        (0x0000_0008, 'S'),
        (0x0001_0000, 'D'),
        (0x0000_0010, 'i'),
        (0x0000_0020, 'a'),
        (0x0000_0040, 'd'),
        (0x0000_0080, 'A'),
        (0x0000_0004, 'c'),
        (0x0000_0800, 'E'),
        (0x0000_4000, 'j'),
        (0x0000_1000, 'I'),
        (0x0000_8000, 't'),
        (0x0002_0000, 'T'),
        (0x0008_0000, 'e'),
        (0x0080_0000, 'C'),
        (0x1000_0000, 'N'),
        (0x2000_0000, 'P'),
    ];
    let field: String = TABLE
        .iter()
        .map(|&(mask, c)| if raw & mask != 0 { c } else { '-' })
        .collect();
    Evidence {
        source: EvidenceSource::Lsattr,
        raw: format!("{field} {}", path.display()),
        path: Some(path.to_path_buf()),
    }
}

#[cfg(target_os = "linux")]
fn fix(path: &Path, reason: Reason) -> Fix {
    let (flag, word) = match reason {
        Reason::Immutable => ("-i", "immutable"),
        Reason::Append => ("-a", "append-only"),
    };
    let p = path.to_string_lossy().into_owned();
    Fix {
        action: FixAction::Run {
            argv: vec!["chattr".into(), flag.into(), p.clone()],
        },
        needs_root: true,
        description: format!("clear the {word} attribute on {p}"),
        risk: Risk::Medium,
        rationale: "clears the blocking attribute".into(),
    }
}

#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "macos"
))]
#[allow(clippy::unnecessary_cast)]
fn check_node(path: &Path, op: Op) -> Option<LayerResult> {
    let flags = stat_flags(path)?;
    let immutable = flags & (libc::UF_IMMUTABLE as u32 | libc::SF_IMMUTABLE as u32) != 0;
    let append = flags & (libc::UF_APPEND as u32 | libc::SF_APPEND as u32) != 0;
    let reason = classify(immutable, append, op)?;
    Some(block_result(path, op, reason, chflags_line(flags, path)))
}

#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "macos"
))]
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

#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "macos"
))]
#[allow(clippy::unnecessary_cast)]
fn chflags_line(flags: u32, path: &Path) -> Evidence {
    const TABLE: &[(u32, &str)] = &[
        (libc::UF_IMMUTABLE as u32, "uchg"),
        (libc::SF_IMMUTABLE as u32, "schg"),
        (libc::UF_APPEND as u32, "uappnd"),
        (libc::SF_APPEND as u32, "sappnd"),
    ];
    let set: Vec<&str> = TABLE
        .iter()
        .filter(|&&(mask, _)| flags & mask != 0)
        .map(|&(_, name)| name)
        .collect();
    let list = match set.is_empty() {
        true => "-".to_string(),
        false => set.join(","),
    };
    Evidence {
        source: EvidenceSource::Statflags,
        raw: format!("{list} {}", path.display()),
        path: Some(path.to_path_buf()),
    }
}

#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "macos"
))]
fn fix(path: &Path, reason: Reason) -> Fix {
    let (flag, word) = match reason {
        Reason::Immutable => ("nouchg", "immutable"),
        Reason::Append => ("nouappnd", "append-only"),
    };
    let p = path.to_string_lossy().into_owned();
    Fix {
        action: FixAction::Run {
            argv: vec!["chflags".into(), flag.into(), p.clone()],
        },
        needs_root: true,
        description: format!("clear the {word} attribute on {p}"),
        risk: Risk::Medium,
        rationale: "clears the blocking flag".into(),
    }
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "macos"
)))]
fn check_node(_path: &Path, _op: Op) -> Option<LayerResult> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    use crate::engine::LayerStatus;

    #[test]
    fn immutable_blocks_structural_ops() {
        for op in [Op::Write, Op::Delete, Op::Create] {
            assert!(matches!(classify(true, false, op), Some(Reason::Immutable)));
        }
    }

    #[test]
    fn append_blocks_write_and_delete_not_create() {
        assert!(matches!(
            classify(false, true, Op::Write),
            Some(Reason::Append)
        ));
        assert!(matches!(
            classify(false, true, Op::Delete),
            Some(Reason::Append)
        ));
        assert!(classify(false, true, Op::Create).is_none());
    }

    #[test]
    fn no_flags_never_blocks() {
        for op in [Op::Write, Op::Delete, Op::Create] {
            assert!(classify(false, false, op).is_none());
        }
    }

    #[test]
    fn read_exec_traverse_never_block() {
        for op in [Op::Read, Op::Exec, Op::Traverse] {
            assert!(classify(true, true, op).is_none());
        }
    }

    #[cfg(target_os = "linux")]
    fn ident() -> Identity {
        Identity {
            uid: 0,
            primary_gid: 0,
            groups: vec![0],
            name: Some("root".into()),
            is_self: true,
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn immutable_roundtrip_root() {
        use rustix::fs::{ioctl_getflags, ioctl_setflags, open, IFlags, Mode, OFlags};
        if !rustix::process::geteuid().is_root() {
            eprintln!("attrs: skipping immutable round-trip; needs root");
            return;
        }
        let dir = std::env::temp_dir().join(format!("whycant-attrs-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("locked");
        std::fs::write(&f, b"x").unwrap();

        let set = |on: bool| {
            let fd = open(&f, OFlags::RDONLY, Mode::empty()).unwrap();
            let mut fl = ioctl_getflags(&fd).unwrap();
            fl.set(IFlags::IMMUTABLE, on);
            ioctl_setflags(&fd, fl).unwrap();
        };

        set(true);
        let r = AttrLayer.check(&ident(), &f, Op::Write);
        set(false);
        std::fs::remove_dir_all(&dir).unwrap();

        assert!(matches!(r.status, LayerStatus::Block));
        assert!(r.certainty == Certainty::Proven);
        assert!(r
            .fixes
            .iter()
            .any(|x| x.argv().first().map(String::as_str) == Some("chattr")));
    }
}
