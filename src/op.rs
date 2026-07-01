//! Operation model. The [`Op`] a layer evaluates, the [`OpArg`] CLI keyword,
//! the parent-directory redirection for delete/create, and op inference from a
//! bare path or a wrapped command.

use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::fs::Metadata;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// The filesystem operation being explained. `Delete` and `Create` gate on the
/// parent directory, not the target's own mode.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    Read,
    Write,
    Exec,
    Traverse,
    Delete,
    Create,
}

/// CLI keyword form of an op; `Cd` is an alias of `Traverse`.
#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OpArg {
    Read,
    Write,
    Exec,
    Traverse,
    Cd,
    Delete,
    Create,
}

impl OpArg {
    pub fn parse_keyword(s: &str) -> Option<Self> {
        <Self as ValueEnum>::from_str(s, true).ok()
    }
}

impl From<OpArg> for Op {
    fn from(a: OpArg) -> Self {
        match a {
            OpArg::Read => Op::Read,
            OpArg::Write => Op::Write,
            OpArg::Exec => Op::Exec,
            OpArg::Traverse | OpArg::Cd => Op::Traverse,
            OpArg::Delete => Op::Delete,
            OpArg::Create => Op::Create,
        }
    }
}

pub enum GateTarget<'a> {
    Node(&'a Path),
    Parent { of: &'a Path, sticky_matters: bool },
}

pub fn gating_node(op: Op, target: &Path) -> GateTarget<'_> {
    match op {
        Op::Delete | Op::Create => GateTarget::Parent {
            of: target,
            sticky_matters: op == Op::Delete,
        },
        _ => GateTarget::Node(target),
    }
}

pub fn infer_bare(meta: &Metadata, _path: &Path) -> Op {
    match () {
        _ if meta.is_dir() => Op::Traverse,
        _ if meta.permissions().mode() & 0o111 != 0 => Op::Exec,
        _ => Op::Read,
    }
}

pub fn infer_cmd(argv: &[OsString]) -> Option<(Op, PathBuf)> {
    let prog = argv.first()?.to_str()?;
    let op = match prog {
        "cat" | "less" | "head" | "tail" | "more" => Op::Read,
        "tee" | "truncate" => Op::Write,
        "rm" | "unlink" => Op::Delete,
        "touch" | "mkdir" | "install" => Op::Create,
        "cd" | "pushd" => Op::Traverse,
        _ => Op::Exec,
    };
    let path = match op {
        Op::Exec => PathBuf::from(prog),
        _ => PathBuf::from(argv.get(1)?),
    };
    Some((op, path))
}
