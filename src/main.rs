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

use anyhow::{anyhow, Result};
use clap::Parser;
use cli::{Cli, Format};
use op::Op;
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
    cli.action(interactive)
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
    Ok(report::exit_code(&report))
}

fn dispatch(cli: &Cli) -> Result<(Op, PathBuf)> {
    if !cli.cmd.is_empty() {
        return op::infer_cmd(&cli.cmd).ok_or_else(|| anyhow!("cannot infer op from command"));
    }
    match (cli.op, &cli.path) {
        (Some(oparg), Some(p)) => Ok((oparg.into(), p.clone())),
        (None, Some(p)) => {
            let op = match std::fs::symlink_metadata(p) {
                Ok(meta) => op::infer_bare(&meta, p),
                Err(_) => Op::Read,
            };
            Ok((op, p.clone()))
        }
        _ => Err(anyhow!("usage: whycant <op> <path>")),
    }
}
