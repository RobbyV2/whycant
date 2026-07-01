use crate::op::{gating_node, GateTarget, Op};
use crate::report::CrossCheck;
use rustix::fs::{accessat, Access, AtFlags, CWD};
use rustix::io::Errno;
use std::path::Path;

pub struct KernelCheck {
    pub r: bool,
    pub w: bool,
    pub x: bool,
}

pub struct KernelAnswer {
    pub allowed: bool,
    pub errno: Option<Errno>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Concord {
    Agree,
    Disagree,
}

fn op_access(op: Op) -> Access {
    match op {
        Op::Read => Access::READ_OK,
        Op::Write => Access::WRITE_OK,
        Op::Exec | Op::Traverse => Access::EXEC_OK,
        Op::Delete | Op::Create => Access::WRITE_OK | Access::EXEC_OK,
    }
}

fn gate_path(op: Op, path: &Path) -> &Path {
    match gating_node(op, path) {
        GateTarget::Node(p) => p,
        GateTarget::Parent {
            of,
            sticky_matters: _,
        } => match of.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        },
    }
}

pub fn accessat_answer(path: &Path, access: Access) -> KernelAnswer {
    match accessat(CWD, path, access, AtFlags::EACCESS) {
        Ok(()) => KernelAnswer {
            allowed: true,
            errno: None,
        },
        Err(e) => KernelAnswer {
            allowed: false,
            errno: Some(e),
        },
    }
}

fn kernel_check(path: &Path) -> KernelCheck {
    let probe = |a| accessat(CWD, path, a, AtFlags::EACCESS).is_ok();
    KernelCheck {
        r: probe(Access::READ_OK),
        w: probe(Access::WRITE_OK),
        x: probe(Access::EXEC_OK),
    }
}

pub fn compare(answer: &KernelAnswer, model_allows: bool) -> Concord {
    match answer.allowed == model_allows {
        true => Concord::Agree,
        false => Concord::Disagree,
    }
}

fn disagree_message(answer: &KernelAnswer) -> String {
    let base = "model and kernel disagree";
    match answer.errno {
        Some(e) => format!("{base} (kernel errno {})", e.raw_os_error()),
        None => base.to_string(),
    }
}

pub fn cross_check(path: &Path, op: Op, model_allows: bool) -> CrossCheck {
    let gate = gate_path(op, path);
    let answer = accessat_answer(gate, op_access(op));
    let rwx = kernel_check(gate);
    let agree = compare(&answer, model_allows) == Concord::Agree;
    let message = match agree {
        true => None,
        false => Some(disagree_message(&answer)),
    };
    CrossCheck {
        available: true,
        kernel_allows: Some(answer.allowed),
        model_allows,
        agree,
        kernel_rwx: Some([rwx.r, rwx.w, rwx.x]),
        message,
    }
}

pub fn unavailable(uid: u32, model_allows: bool) -> CrossCheck {
    CrossCheck {
        available: false,
        kernel_allows: None,
        model_allows,
        agree: true,
        kernel_rwx: None,
        message: Some(format!(
            "symbolic only for uid {uid}; no kernel cross-check"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    fn is_root() -> bool {
        rustix::process::getuid().as_raw() == 0
    }

    fn scratch(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("whycant_{tag}_{}", std::process::id()))
    }

    #[test]
    fn readable_path_reports_true() {
        let p = scratch("rt");
        fs::write(&p, b"x").unwrap();
        let a = accessat_answer(&p, Access::READ_OK);
        fs::remove_file(&p).ok();
        assert!(a.allowed);
        assert!(a.errno.is_none());
    }

    #[test]
    fn zero_mode_not_readable() {
        if is_root() {
            return;
        }
        let p = scratch("zm");
        fs::write(&p, b"x").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o000)).unwrap();
        let a = accessat_answer(&p, Access::READ_OK);
        fs::remove_file(&p).ok();
        assert!(!a.allowed);
        assert!(a.errno.is_some());
    }

    #[test]
    fn blocked_meets_kernel_allowed_disagrees() {
        let ans = KernelAnswer {
            allowed: true,
            errno: None,
        };
        assert_eq!(compare(&ans, false), Concord::Disagree);
    }
}
