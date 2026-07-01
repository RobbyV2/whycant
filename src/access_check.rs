use crate::op::Op;
use crate::report::CrossCheck;
use rustix::fs::{accessat, Access, AtFlags, CWD};
use std::path::Path;

pub struct KernelCheck {
    pub r: bool,
    pub w: bool,
    pub x: bool,
}

pub fn kernel_check(path: &Path) -> KernelCheck {
    let probe = |a| accessat(CWD, path, a, AtFlags::EACCESS).is_ok();
    KernelCheck {
        r: probe(Access::READ_OK),
        w: probe(Access::WRITE_OK),
        x: probe(Access::EXEC_OK),
    }
}

pub fn cross_check(path: &Path, op: Op, model_allows: bool) -> CrossCheck {
    let k = kernel_check(path);
    let kernel_allows = match op {
        Op::Read => k.r,
        Op::Write | Op::Delete | Op::Create => k.w,
        Op::Exec | Op::Traverse => k.x,
    };
    let agree = kernel_allows == model_allows;
    let message = match agree {
        true => None,
        false => Some(
            "model and kernel disagree"
                .to_string(),
        ),
    };
    CrossCheck {
        kernel_allows,
        model_allows,
        agree,
        message,
    }
}
