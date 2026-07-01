use crate::engine::{Layer, LayerResult, LayerStatus};
use crate::identity::Identity;
use crate::op::Op;
use crate::report::{Certainty, Evidence, EvidenceSource, LayerId};
use std::fs::{self, Metadata};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

pub struct ExistenceLayer;

impl Layer for ExistenceLayer {
    fn name(&self) -> &str {
        "existence"
    }
    fn order(&self) -> u8 {
        1
    }
    fn id(&self) -> LayerId {
        LayerId::Existence
    }
    fn check(&self, _id: &Identity, path: &Path, op: Op) -> LayerResult {
        match op {
            Op::Create => check_create(path),
            _ => match fs::symlink_metadata(path) {
                Ok(meta) if meta.file_type().is_symlink() => resolve_symlink(path, &meta),
                Ok(meta) => LayerResult::pass(vec![lstat_ev(path, &meta)]),
                Err(e) => classify(path, &e),
            },
        }
    }
}

fn parent_of(p: &Path) -> PathBuf {
    match p.parent() {
        Some(par) if !par.as_os_str().is_empty() => par.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

fn check_create(path: &Path) -> LayerResult {
    let parent = parent_of(path);
    let meta = match fs::metadata(&parent) {
        Ok(m) => m,
        Err(e) => return classify_parent(&parent, &e),
    };
    if !meta.is_dir() {
        let raw = ev(
            format!("stat {}: not a directory", parent.display()),
            &parent,
        );
        return err(
            format!("create parent {} is not a directory", parent.display()),
            vec![raw],
        );
    }
    let parent_ev = lstat_ev(&parent, &meta);
    match fs::symlink_metadata(path) {
        Ok(tmeta) => LayerResult {
            status: LayerStatus::Pass,
            certainty: Certainty::Proven,
            evidence: vec![parent_ev, lstat_ev(path, &tmeta)],
            fixes: Vec::new(),
            detail: format!(
                "{} already exists; create would fail EEXIST",
                path.display()
            ),
        },
        Err(_) => LayerResult::pass(vec![parent_ev]),
    }
}

fn classify_parent(parent: &Path, e: &std::io::Error) -> LayerResult {
    let raw = ev(format!("stat {}: {}", parent.display(), e), parent);
    match e.raw_os_error() {
        Some(libc::EACCES) => LayerResult::skip(),
        Some(libc::ENOENT) => err(
            format!("parent directory does not exist: {}", parent.display()),
            vec![raw],
        ),
        Some(libc::ENOTDIR) => err(
            format!(
                "a path component of {} is not a directory",
                parent.display()
            ),
            vec![raw],
        ),
        _ => err(
            format!("cannot stat parent {}: {e}", parent.display()),
            vec![raw],
        ),
    }
}

fn ev(raw: String, path: &Path) -> Evidence {
    Evidence {
        source: EvidenceSource::LsLd,
        raw,
        path: Some(path.to_path_buf()),
    }
}

fn lstat_ev(path: &Path, meta: &Metadata) -> Evidence {
    ev(format!("{} {}", perm_string(meta), path.display()), path)
}

fn err(detail: impl Into<String>, evidence: Vec<Evidence>) -> LayerResult {
    LayerResult {
        status: LayerStatus::Error,
        certainty: Certainty::Proven,
        evidence,
        fixes: Vec::new(),
        detail: detail.into(),
    }
}

fn resolve_symlink(path: &Path, lmeta: &Metadata) -> LayerResult {
    let link_line = match fs::read_link(path) {
        Ok(t) => format!(
            "{} {} -> {}",
            perm_string(lmeta),
            path.display(),
            t.display()
        ),
        Err(_) => format!("{} {}", perm_string(lmeta), path.display()),
    };
    let link_ev = ev(link_line, path);
    match fs::metadata(path) {
        Ok(tmeta) => LayerResult::pass(vec![link_ev, lstat_ev(path, &tmeta)]),
        Err(e) => match e.raw_os_error() {
            Some(libc::EACCES) => LayerResult::skip(),
            Some(libc::ELOOP) => err(
                format!("symlink loop resolving {}", path.display()),
                vec![link_ev],
            ),
            Some(libc::ENOENT) | Some(libc::ENOTDIR) => err(
                format!("broken symlink: {} target does not exist", path.display()),
                vec![link_ev],
            ),
            _ => err(format!("symlink target unresolvable: {e}"), vec![link_ev]),
        },
    }
}

fn classify(path: &Path, e: &std::io::Error) -> LayerResult {
    let raw = ev(format!("lstat {}: {}", path.display(), e), path);
    match e.raw_os_error() {
        Some(libc::EACCES) => LayerResult::skip(),
        Some(libc::ENOENT) => err(
            format!("target does not exist: {}", path.display()),
            vec![raw],
        ),
        Some(libc::ENOTDIR) => err(
            format!("a path component of {} is not a directory", path.display()),
            vec![raw],
        ),
        _ => err(format!("cannot stat {}: {e}", path.display()), vec![raw]),
    }
}

fn perm_string(meta: &Metadata) -> String {
    let m = meta.mode();
    let ftype = match m & 0o170000 {
        0o040000 => 'd',
        0o120000 => 'l',
        0o100000 => '-',
        0o060000 => 'b',
        0o020000 => 'c',
        0o010000 => 'p',
        0o140000 => 's',
        _ => '?',
    };
    let bit = |mask: u32, ch: char| if m & mask != 0 { ch } else { '-' };
    let mut s = String::with_capacity(10);
    s.push(ftype);
    for (r, w, x) in [
        (0o400, 0o200, 0o100),
        (0o040, 0o020, 0o010),
        (0o004, 0o002, 0o001),
    ] {
        s.push(bit(r, 'r'));
        s.push(bit(w, 'w'));
        s.push(bit(x, 'x'));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct Tmp(PathBuf);

    impl Tmp {
        fn new() -> Self {
            let mut p = std::env::temp_dir();
            let n = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            p.push(format!("whycant-existence-{}-{n}", std::process::id()));
            fs::create_dir_all(&p).unwrap();
            Tmp(p)
        }
        fn at(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
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

    fn run(path: &Path) -> LayerResult {
        ExistenceLayer.check(&ident(), path, Op::Read)
    }

    #[test]
    fn existing_file_passes() {
        let t = Tmp::new();
        let f = t.at("real");
        fs::write(&f, b"x").unwrap();
        let r = run(&f);
        assert!(r.status == LayerStatus::Pass);
        assert!(!r.evidence.is_empty());
    }

    #[test]
    fn missing_is_error() {
        let t = Tmp::new();
        let r = run(&t.at("nope"));
        assert!(r.status == LayerStatus::Error);
        assert!(r.detail.contains("does not exist"));
    }

    #[test]
    fn broken_symlink_is_error() {
        let t = Tmp::new();
        let link = t.at("dangling");
        symlink(t.at("absent"), &link).unwrap();
        let r = run(&link);
        assert!(r.status == LayerStatus::Error);
        assert!(r.detail.contains("broken symlink"));
        assert!(r.evidence.iter().any(|e| e.raw.contains("->")));
    }

    #[test]
    fn symlink_to_existing_passes() {
        let t = Tmp::new();
        let target = t.at("target");
        fs::write(&target, b"x").unwrap();
        let link = t.at("good");
        symlink(&target, &link).unwrap();
        let r = run(&link);
        assert!(r.status == LayerStatus::Pass);
    }

    #[test]
    fn create_missing_target_passes_on_dir_parent() {
        let t = Tmp::new();
        let r = ExistenceLayer.check(&ident(), &t.at("newfile"), Op::Create);
        assert!(r.status == LayerStatus::Pass);
        assert!(r.detail.is_empty());
    }

    #[test]
    fn create_existing_target_is_informational() {
        let t = Tmp::new();
        let f = t.at("here");
        fs::write(&f, b"x").unwrap();
        let r = ExistenceLayer.check(&ident(), &f, Op::Create);
        assert!(r.status == LayerStatus::Pass);
        assert!(r.detail.contains("EEXIST"));
    }

    #[test]
    fn create_missing_parent_is_error() {
        let t = Tmp::new();
        let deep = t.at("absent").join("child");
        let r = ExistenceLayer.check(&ident(), &deep, Op::Create);
        assert!(r.status == LayerStatus::Error);
        assert!(r.detail.contains("parent"));
    }

    #[test]
    fn create_parent_not_dir_is_error() {
        let t = Tmp::new();
        let file = t.at("afile");
        fs::write(&file, b"x").unwrap();
        let under = file.join("child");
        let r = ExistenceLayer.check(&ident(), &under, Op::Create);
        assert!(r.status == LayerStatus::Error);
    }

    #[test]
    fn delete_missing_target_still_errors() {
        let t = Tmp::new();
        let r = ExistenceLayer.check(&ident(), &t.at("gone"), Op::Delete);
        assert!(r.status == LayerStatus::Error);
        assert!(r.detail.contains("does not exist"));
    }

    #[test]
    fn symlink_loop_is_error() {
        let t = Tmp::new();
        let a = t.at("a");
        let b = t.at("b");
        symlink(&b, &a).unwrap();
        symlink(&a, &b).unwrap();
        let r = run(&a);
        assert!(r.status == LayerStatus::Error);
        assert!(r.detail.contains("loop"));
    }
}
