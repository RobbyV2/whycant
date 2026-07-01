use crate::engine::{Layer, LayerResult, LayerStatus};
use crate::identity::Identity;
use crate::op::Op;
use crate::report::{Certainty, Evidence, EvidenceSource, Fix, FixAction, LayerId, Risk};
use rustix::fs::{StatVfsMountFlags, statvfs};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

pub struct MountLayer;

impl Layer for MountLayer {
    fn name(&self) -> &str {
        "mount"
    }
    fn order(&self) -> u8 {
        6
    }
    fn id(&self) -> LayerId {
        LayerId::Mount
    }
    fn check(&self, _id: &Identity, path: &Path, op: Op) -> LayerResult {
        match read_mount(path) {
            Ok(info) => evaluate(&info, path, op),
            Err(e) => LayerResult {
                status: LayerStatus::Error,
                certainty: Certainty::Proven,
                evidence: Vec::new(),
                fixes: Vec::new(),
                detail: format!("statvfs failed: {e}"),
            },
        }
    }
}

struct MountInfo {
    ro: bool,
    noexec: bool,
    nosuid: bool,
    nodev: bool,
    mountpoint: String,
    source: Option<String>,
    fstype: Option<String>,
    options: Option<String>,
}

impl MountInfo {
    fn opts_string(&self) -> String {
        match &self.options {
            Some(o) => o.clone(),
            None => {
                let mut parts = vec![match self.ro {
                    true => "ro",
                    false => "rw",
                }];
                if self.noexec {
                    parts.push("noexec");
                }
                if self.nosuid {
                    parts.push("nosuid");
                }
                if self.nodev {
                    parts.push("nodev");
                }
                parts.join(",")
            }
        }
    }
    fn evidence(&self) -> Evidence {
        let raw = format!(
            "{} on {} type {} ({})",
            self.source.as_deref().unwrap_or("?"),
            self.mountpoint,
            self.fstype.as_deref().unwrap_or("?"),
            self.opts_string()
        );
        Evidence {
            source: match self.options.is_some() {
                true => EvidenceSource::MountOpts,
                false => EvidenceSource::Statvfs,
            },
            raw,
            path: Some(PathBuf::from(&self.mountpoint)),
        }
    }
}

fn read_mount(path: &Path) -> Result<MountInfo, rustix::io::Errno> {
    let f = statvfs(path)?.f_flag;
    let mountpoint = find_mount_point(path);
    let (noexec, nodev) = {
        #[cfg(target_os = "linux")]
        {
            (
                f.contains(StatVfsMountFlags::NOEXEC),
                f.contains(StatVfsMountFlags::NODEV),
            )
        }
        #[cfg(not(target_os = "linux"))]
        {
            (false, false)
        }
    };
    let mut info = MountInfo {
        ro: f.contains(StatVfsMountFlags::RDONLY),
        noexec,
        nosuid: f.contains(StatVfsMountFlags::NOSUID),
        nodev,
        mountpoint: mountpoint.to_string_lossy().into_owned(),
        source: None,
        fstype: None,
        options: None,
    };
    #[cfg(target_os = "linux")]
    enrich_linux(&mountpoint, &mut info);
    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    enrich_bsd(path, &mut info);
    Ok(info)
}

fn find_mount_point(path: &Path) -> PathBuf {
    let abs = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let dev_of = |p: &Path| std::fs::metadata(p).ok().map(|m| m.dev());
    let target = dev_of(&abs);
    let mut cur: &Path = &abs;
    while let Some(parent) = cur.parent() {
        if dev_of(parent) != target {
            break;
        }
        cur = parent;
    }
    cur.to_path_buf()
}

fn evaluate(info: &MountInfo, _path: &Path, op: Op) -> LayerResult {
    let ev = info.evidence();
    match op {
        Op::Write | Op::Delete | Op::Create if info.ro => LayerResult::block(
            Certainty::Proven,
            format!(
                "{} mounted read-only; {} refused",
                info.mountpoint,
                op_word(op)
            ),
            vec![ev],
            vec![remount_fix(&info.mountpoint, "rw")],
        ),
        Op::Exec if info.noexec => LayerResult::block(
            Certainty::Proven,
            format!("{} mounted noexec; exec refused", info.mountpoint),
            vec![ev],
            vec![relocate_advice(), remount_fix(&info.mountpoint, "exec")],
        ),
        _ => LayerResult::skip(),
    }
}

fn op_word(op: Op) -> &'static str {
    match op {
        Op::Read => "read",
        Op::Write => "write",
        Op::Exec => "execute",
        Op::Traverse => "traverse",
        Op::Delete => "delete",
        Op::Create => "create",
    }
}

fn remount_fix(mnt: &str, flag: &str) -> Fix {
    Fix {
        action: FixAction::Run {
            argv: vec![
                "mount".into(),
                "-o".into(),
                format!("remount,{flag}"),
                mnt.into(),
            ],
        },
        needs_root: true,
        description: format!("remount {mnt} with {flag}"),
        risk: Risk::High,
        rationale: "remounts the filesystem".into(),
    }
}

fn relocate_advice() -> Fix {
    Fix {
        action: FixAction::Advice {
            text: "run from a filesystem without noexec".into(),
        },
        needs_root: false,
        description: "run from an exec-mounted filesystem".into(),
        risk: Risk::Low,
        rationale: "avoids weakening the mount".into(),
    }
}

#[cfg(target_os = "linux")]
fn enrich_linux(mountpoint: &Path, info: &mut MountInfo) {
    let data = match std::fs::read_to_string("/proc/self/mountinfo") {
        Ok(d) => d,
        Err(_) => return,
    };
    let mp = mountpoint.to_string_lossy();
    for line in data.lines() {
        let sep = match line.find(" - ") {
            Some(i) => i,
            None => continue,
        };
        let (left, right) = line.split_at(sep);
        let lf: Vec<&str> = left.split_whitespace().collect();
        let (point, opts) = match (lf.get(4), lf.get(5)) {
            (Some(&p), Some(&o)) => (p, o),
            _ => continue,
        };
        if unescape(point) != mp {
            continue;
        }
        let rf: Vec<&str> = right[3..].split_whitespace().collect();
        info.options = Some(opts.to_string());
        info.fstype = rf.first().map(|s| s.to_string());
        info.source = rf.get(1).map(|s| s.to_string());
    }
}

#[cfg(target_os = "linux")]
fn unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\'
            && i + 3 < b.len()
            && let Ok(v) = u8::from_str_radix(&s[i + 1..i + 4], 8)
        {
            out.push(v);
            i += 4;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
fn enrich_bsd(path: &Path, info: &mut MountInfo) {
    use std::os::unix::ffi::OsStrExt;
    let c = match std::ffi::CString::new(path.as_os_str().as_bytes()) {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut buf: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c.as_ptr(), &mut buf) } != 0 {
        return;
    }
    let read = |arr: &[libc::c_char]| {
        unsafe { std::ffi::CStr::from_ptr(arr.as_ptr()) }
            .to_string_lossy()
            .into_owned()
    };
    info.fstype = Some(read(&buf.f_fstypename));
    info.source = Some(read(&buf.f_mntfromname));
    info.mountpoint = read(&buf.f_mntonname);
    let flags = buf.f_flags as u64;
    info.ro = flags & libc::MNT_RDONLY as u64 != 0;
    info.noexec = flags & libc::MNT_NOEXEC as u64 != 0;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mi(ro: bool, noexec: bool) -> MountInfo {
        MountInfo {
            ro,
            noexec,
            nosuid: false,
            nodev: false,
            mountpoint: "/mnt".into(),
            source: Some("/dev/sdz".into()),
            fstype: Some("ext4".into()),
            options: None,
        }
    }

    fn ident() -> Identity {
        Identity {
            uid: 0,
            primary_gid: 0,
            groups: Vec::new(),
            name: None,
            is_self: false,
        }
    }

    #[test]
    fn ro_blocks_mutating_ops() {
        for op in [Op::Write, Op::Delete, Op::Create] {
            let r = evaluate(&mi(true, false), Path::new("/mnt/f"), op);
            assert!(matches!(r.status, LayerStatus::Block));
            assert!(matches!(r.certainty, Certainty::Proven));
            assert_eq!(r.fixes.len(), 1);
            assert!(r.fixes[0].needs_root);
            assert!(matches!(r.fixes[0].risk, Risk::High));
        }
    }

    #[test]
    fn ro_leaves_read_and_exec_alone() {
        for op in [Op::Read, Op::Exec, Op::Traverse] {
            let r = evaluate(&mi(true, false), Path::new("/mnt/f"), op);
            assert!(matches!(r.status, LayerStatus::Skip));
        }
    }

    #[test]
    fn noexec_blocks_exec_only() {
        let blk = evaluate(&mi(false, true), Path::new("/mnt/x"), Op::Exec);
        assert!(matches!(blk.status, LayerStatus::Block));
        assert_eq!(blk.fixes.len(), 2);
        assert!(matches!(blk.fixes[0].action, FixAction::Advice { .. }));
        assert!(matches!(blk.fixes[0].risk, Risk::Low));
        assert!(!blk.fixes[0].needs_root);
        assert!(matches!(blk.fixes[1].action, FixAction::Run { .. }));
        assert!(matches!(blk.fixes[1].risk, Risk::High));
        for op in [Op::Read, Op::Write, Op::Create, Op::Delete, Op::Traverse] {
            let r = evaluate(&mi(false, true), Path::new("/mnt/x"), op);
            assert!(matches!(r.status, LayerStatus::Skip));
        }
    }

    #[test]
    fn clean_mount_skips_everything() {
        for op in [
            Op::Read,
            Op::Write,
            Op::Exec,
            Op::Delete,
            Op::Create,
            Op::Traverse,
        ] {
            let r = evaluate(&mi(false, false), Path::new("/mnt/f"), op);
            assert!(matches!(r.status, LayerStatus::Skip));
        }
    }

    #[test]
    fn statvfs_root_read_is_sane() {
        let r = MountLayer.check(&ident(), Path::new("/"), Op::Read);
        assert!(matches!(r.status, LayerStatus::Skip | LayerStatus::Block));
    }
}
