mod access_check;
mod cli;
mod config;
mod engine;
mod fix;
mod identity;
mod layers;
mod op;
mod render;
mod report;
mod term;

use anyhow::{Result, anyhow};
use clap::Parser;
use cli::{Action, Cli, Format};
use op::{Op, OpArg};
use report::Verdict;
use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use term::TermCtx;

enum AppError {
    Usage(String),
    Internal(anyhow::Error),
}

impl From<anyhow::Error> for AppError {
    fn from(e: anyhow::Error) -> Self {
        Self::Internal(e)
    }
}

fn main() {
    let code = match real_main() {
        Ok(c) => c,
        Err(AppError::Usage(m)) => {
            eprintln!("whycant: {m}");
            64
        }
        Err(AppError::Internal(e)) => {
            eprintln!("whycant: {e:#}");
            70
        }
    };
    std::process::exit(code);
}

fn real_main() -> Result<i32, AppError> {
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            let code = if e.use_stderr() { 64 } else { 0 };
            e.print().ok();
            return Ok(code);
        }
    };
    if let Some(shell) = cli.completions {
        cli::print_completions(shell)?;
        return Ok(0);
    }
    if cli.man {
        cli::print_manpage()?;
        return Ok(0);
    }

    let settings = config::load()?;
    let resolved = cli.resolve(&settings);
    let term = TermCtx::detect(resolved.color, resolved.ascii);
    let id = identity::resolve_target(cli.user.as_deref())
        .map_err(|e| AppError::Usage(e.to_string()))?;
    let (op, path) = dispatch(&cli).map_err(|e| AppError::Usage(e.to_string()))?;

    let tty = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    let interactive = resolved.interactive.unwrap_or(tty);
    let action = cli
        .action(interactive)
        .map_err(|e| AppError::Usage(e.to_string()))?;

    let chain = engine::default_chain();
    let mut report = engine::run(&chain, &id, &path, op, resolved.all);
    if !resolved.print_fixes {
        report.fixes.clear();
    }

    let machine = matches!(resolved.format, Format::Json | Format::Toml);
    if !machine && !resolved.quiet {
        term.banner(&report.identity.privilege_note);
    }
    for w in &report.warnings {
        let _ = writeln!(term.err(), "whycant: {w}");
    }

    let out = render::render(&report, resolved.format, &term, resolved.all)?;
    writeln!(term.out(), "{out}").map_err(anyhow::Error::from)?;

    let blocked = report.verdict == Verdict::Blocked;
    match action {
        Action::PrintOnly => {}
        Action::ApplyFirst => fix::auto_apply(&report, &chain, &id, &path, op, &term)?,
        Action::Prompt if blocked && !report.fixes.is_empty() => {
            fix::interactive(&report, &chain, &id, &path, op, &term)?
        }
        Action::Prompt => {}
    }
    Ok(report::exit_code(&report))
}

fn dispatch(cli: &Cli) -> Result<(Op, PathBuf)> {
    if !cli.cmd.is_empty() {
        return op::infer_cmd(&cli.cmd).ok_or_else(|| anyhow!("cannot infer op from command"));
    }
    match (&cli.op, &cli.path) {
        (Some(tok), Some(p)) => match OpArg::parse_keyword(tok) {
            Some(oparg) => Ok((oparg.into(), p.clone())),
            None => Err(anyhow!("unknown op '{tok}'; usage: whycant <op> <path>")),
        },
        (Some(tok), None) => match OpArg::parse_keyword(tok) {
            Some(_) => Err(anyhow!("usage: whycant <op> <path>")),
            None => {
                let p = PathBuf::from(tok);
                let op = match std::fs::symlink_metadata(&p) {
                    Ok(meta) => op::infer_bare(&meta, &p),
                    Err(_) => Op::Read,
                };
                Ok((op, p))
            }
        },
        _ => Err(anyhow!("usage: whycant <op> <path>")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::fs::Permissions;
    use std::os::unix::fs::PermissionsExt;

    fn cli(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).unwrap()
    }

    #[test]
    fn bare_dir_infers_traverse() {
        let d = tempfile::tempdir().unwrap();
        let (op, path) =
            dispatch(&cli(&["whycant", "--json", d.path().to_str().unwrap()])).unwrap();
        assert_eq!(op, Op::Traverse);
        assert_eq!(path, d.path());
    }

    #[test]
    fn bare_regular_file_infers_read() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("plain");
        std::fs::write(&f, "x").unwrap();
        std::fs::set_permissions(&f, Permissions::from_mode(0o644)).unwrap();
        let (op, path) = dispatch(&cli(&["whycant", "--json", f.to_str().unwrap()])).unwrap();
        assert_eq!(op, Op::Read);
        assert_eq!(path, f);
    }

    #[test]
    fn bare_exec_file_infers_exec() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("prog");
        std::fs::write(&f, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&f, Permissions::from_mode(0o755)).unwrap();
        let (op, _) = dispatch(&cli(&["whycant", "--json", f.to_str().unwrap()])).unwrap();
        assert_eq!(op, Op::Exec);
    }

    #[test]
    fn explicit_read_stays_read() {
        let (op, path) = dispatch(&cli(&["whycant", "read", "/etc/hostname"])).unwrap();
        assert_eq!(op, Op::Read);
        assert_eq!(path, PathBuf::from("/etc/hostname"));
    }

    #[test]
    fn lone_invalid_token_is_path() {
        let (op, path) = dispatch(&cli(&["whycant", "not-an-op-zzz"])).unwrap();
        assert_eq!(op, Op::Read);
        assert_eq!(path, PathBuf::from("not-an-op-zzz"));
    }

    #[test]
    fn lone_op_keyword_errors() {
        assert!(dispatch(&cli(&["whycant", "read"])).is_err());
    }
}
