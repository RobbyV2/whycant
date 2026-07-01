pub use crate::report::{Fix, FixAction};

use crate::engine::{self, Layer};
use crate::identity::Identity;
use crate::op::Op;
use crate::report::{LayerId, Report, Verdict};
use crate::term::TermCtx;
use anyhow::{Result, anyhow};
use inquire::{Confirm, Select};
use std::fmt;
use std::io::Write;
use std::process::{Command, Stdio};

impl Fix {
    pub fn display(&self) -> String {
        match &self.action {
            FixAction::Run { argv } => {
                let cmd = quote_argv(argv);
                match self.needs_root {
                    true => format!("sudo {cmd}"),
                    false => cmd,
                }
            }
            FixAction::Advice { text } => text.clone(),
        }
    }

    fn is_run(&self) -> bool {
        matches!(self.action, FixAction::Run { .. })
    }

    #[cfg(test)]
    pub fn argv(&self) -> &[String] {
        match &self.action {
            FixAction::Run { argv } => argv,
            FixAction::Advice { .. } => &[],
        }
    }
}

fn quote_argv(argv: &[String]) -> String {
    argv.iter()
        .map(|a| shell_quote(a))
        .collect::<Vec<_>>()
        .join(" ")
}

fn shell_quote(s: &str) -> String {
    match s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "-_./:=,".contains(c))
    {
        true => s.to_string(),
        false => format!("'{}'", s.replace('\'', "'\\''")),
    }
}

pub fn ordered(fixes: &[Fix]) -> Vec<&Fix> {
    let mut v: Vec<&Fix> = fixes.iter().collect();
    v.sort_by_key(|f| (f.needs_root, f.risk.rank()));
    v
}

fn is_root() -> bool {
    rustix::process::geteuid().is_root()
}

fn command_argv(argv: &[String], needs_root: bool, is_root: bool) -> Vec<String> {
    match needs_root && !is_root {
        true => std::iter::once("sudo".to_string())
            .chain(argv.iter().cloned())
            .collect(),
        false => argv.to_vec(),
    }
}

fn spawn_argv(full: &[String]) -> Result<bool> {
    let (prog, args) = full.split_first().ok_or_else(|| anyhow!("empty command"))?;
    Ok(Command::new(prog).args(args).status()?.success())
}

pub fn execute(fix: &Fix, is_root: bool) -> Result<Option<bool>> {
    match &fix.action {
        FixAction::Advice { .. } => Ok(None),
        FixAction::Run { argv } => Ok(Some(spawn_argv(&command_argv(
            argv,
            fix.needs_root,
            is_root,
        ))?)),
    }
}

pub enum Recheck {
    Cleared,
    Blocked {
        layer: Option<LayerId>,
        culprit: Option<String>,
    },
}

pub fn recheck(chain: &[Box<dyn Layer>], id: &Identity, path: &std::path::Path, op: Op) -> Recheck {
    let fresh = engine::run(chain, id, path, op, false);
    match fresh.verdict {
        Verdict::Allowed => Recheck::Cleared,
        _ => Recheck::Blocked {
            layer: fresh.blocking_layer,
            culprit: fresh.culprit,
        },
    }
}

fn print_recheck(
    term: &TermCtx,
    chain: &[Box<dyn Layer>],
    id: &Identity,
    path: &std::path::Path,
    op: Op,
) -> Result<()> {
    match recheck(chain, id, path, op) {
        Recheck::Cleared => writeln!(term.out(), "recheck: block cleared; {op:?} now allowed")?,
        Recheck::Blocked { layer, culprit } => {
            let l = layer.map_or_else(|| "unknown".to_string(), |l| format!("{l:?}"));
            writeln!(
                term.out(),
                "recheck: still blocked at {l}: {}",
                culprit.unwrap_or_default()
            )?;
        }
    }
    Ok(())
}

fn copy_to_clipboard(text: &str) -> Result<bool> {
    let tools: [(&str, &[&str]); 3] = [
        ("wl-copy", &[]),
        ("xclip", &["-selection", "clipboard"]),
        ("pbcopy", &[]),
    ];
    for (prog, args) in tools {
        let child = Command::new(prog)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        let mut child = match child {
            Ok(c) => c,
            Err(_) => continue,
        };
        if let Some(mut si) = child.stdin.take() {
            si.write_all(text.as_bytes())?;
        }
        child.wait()?;
        return Ok(true);
    }
    Ok(false)
}

enum Choice<'a> {
    Fix(&'a Fix),
    Explain,
    Copy,
    ShowAll,
    Cancel,
}

impl fmt::Display for Choice<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Choice::Fix(fix) => {
                let tail = match fix.is_run() {
                    true => String::new(),
                    false => " (advice, not runnable)".into(),
                };
                write!(
                    f,
                    "{} [risk: {}]{}  {}",
                    fix.description,
                    fix.risk.word(),
                    tail,
                    fix.display()
                )
            }
            Choice::Explain => write!(f, "explain this fix"),
            Choice::Copy => write!(f, "copy command to clipboard"),
            Choice::ShowAll => write!(f, "show full audit (--all)"),
            Choice::Cancel => write!(f, "cancel"),
        }
    }
}

fn pick_fix<'a>(prompt: &str, order: &[&'a Fix], run_only: bool) -> Option<&'a Fix> {
    let items: Vec<Choice<'a>> = order
        .iter()
        .copied()
        .filter(|f| !run_only || f.is_run())
        .map(Choice::Fix)
        .collect();
    if items.is_empty() {
        return None;
    }
    match Select::new(prompt, items).prompt() {
        Ok(Choice::Fix(f)) => Some(f),
        _ => None,
    }
}

fn explain(term: &TermCtx, report: &Report, fix: &Fix) -> Result<()> {
    writeln!(term.out(), "{}", fix.description)?;
    writeln!(term.out(), "rationale: {}", fix.rationale)?;
    if let Some(bl) = report.blocking_layer {
        for lr in report.layer_results.iter().filter(|r| r.layer == bl) {
            for ev in &lr.evidence {
                writeln!(term.out(), "evidence: {}", ev.raw)?;
            }
        }
    }
    Ok(())
}

fn apply_run(
    term: &TermCtx,
    fix: &Fix,
    argv: &[String],
    chain: &[Box<dyn Layer>],
    id: &Identity,
    path: &std::path::Path,
    op: Op,
) -> Result<()> {
    let full = command_argv(argv, fix.needs_root, is_root());
    let shown = quote_argv(&full);
    let go = Confirm::new(&format!("Run `{shown}`?"))
        .with_default(false)
        .prompt()
        .unwrap_or(false);
    if !go {
        return Ok(());
    }
    match spawn_argv(&full)? {
        true => print_recheck(term, chain, id, path, op)?,
        false => writeln!(term.err(), "whycant: fix command exited non-zero")?,
    }
    Ok(())
}

pub fn interactive(
    report: &Report,
    chain: &[Box<dyn Layer>],
    id: &Identity,
    path: &std::path::Path,
    op: Op,
    term: &TermCtx,
) -> Result<()> {
    let order = ordered(&report.fixes);
    loop {
        let mut items: Vec<Choice> = order.iter().copied().map(Choice::Fix).collect();
        items.extend([
            Choice::Explain,
            Choice::Copy,
            Choice::ShowAll,
            Choice::Cancel,
        ]);
        let sel = match Select::new("Select a fix:", items).prompt() {
            Ok(c) => c,
            Err(_) => return Ok(()),
        };
        match sel {
            Choice::Fix(fix) => {
                match &fix.action {
                    FixAction::Run { argv } => apply_run(term, fix, argv, chain, id, path, op)?,
                    FixAction::Advice { text } => {
                        writeln!(term.out(), "advice (not executable): {text}")?
                    }
                }
                return Ok(());
            }
            Choice::Explain => {
                if let Some(f) = pick_fix("Explain which fix?", &order, false) {
                    explain(term, report, f)?;
                }
            }
            Choice::Copy => {
                if let Some(f) = pick_fix("Copy which command?", &order, true) {
                    let cmd = f.display();
                    match copy_to_clipboard(&cmd)? {
                        true => writeln!(term.err(), "copied to clipboard")?,
                        false => writeln!(
                            term.err(),
                            "no clipboard tool (wl-copy/xclip/pbcopy); copy manually: {cmd}"
                        )?,
                    }
                }
            }
            Choice::ShowAll => {
                let full = engine::run(chain, id, path, op, true);
                let out = crate::render::human::render_human(&full, term, true);
                writeln!(term.out(), "{out}")?;
            }
            Choice::Cancel => return Ok(()),
        }
    }
}

pub fn auto_apply(
    report: &Report,
    chain: &[Box<dyn Layer>],
    id: &Identity,
    path: &std::path::Path,
    op: Op,
    term: &TermCtx,
) -> Result<()> {
    let fix = match ordered(&report.fixes).into_iter().next() {
        Some(f) => f,
        None => return Ok(()),
    };
    if !fix.is_run() {
        writeln!(
            term.err(),
            "whycant: top fix is advice-only; nothing auto-applied"
        )?;
        return Ok(());
    }
    let is_root = is_root();
    writeln!(term.err(), "whycant: applying {}", fix.display())?;
    match execute(fix, is_root)? {
        Some(true) => print_recheck(term, chain, id, path, op)?,
        Some(false) => writeln!(term.err(), "whycant: fix command exited non-zero")?,
        None => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::Risk;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    fn run_fix(desc: &str, needs_root: bool, risk: Risk) -> Fix {
        Fix {
            action: FixAction::Run {
                argv: vec!["chmod".into(), "o+x".into(), "/p".into()],
            },
            needs_root,
            description: desc.into(),
            risk,
            rationale: String::new(),
        }
    }

    fn advice_fix() -> Fix {
        Fix {
            action: FixAction::Advice {
                text: "confirm from the audit log".into(),
            },
            needs_root: true,
            description: "manual".into(),
            risk: Risk::High,
            rationale: String::new(),
        }
    }

    fn advice_fix_low() -> Fix {
        Fix {
            action: FixAction::Advice {
                text: "run it from an exec-mounted filesystem".into(),
            },
            needs_root: false,
            description: "relocate".into(),
            risk: Risk::Low,
            rationale: String::new(),
        }
    }

    #[test]
    fn ordering_is_least_privilege_first_and_stable() {
        let fixes = vec![
            run_fix("A", false, Risk::Medium),
            run_fix("B", false, Risk::Low),
            run_fix("C", true, Risk::Low),
            run_fix("D", false, Risk::Low),
        ];
        let got: Vec<&str> = ordered(&fixes)
            .iter()
            .map(|f| f.description.as_str())
            .collect();
        assert_eq!(got, ["B", "D", "A", "C"]);
    }

    #[test]
    fn sudo_elevation_builds_argv_with_no_shell() {
        let argv = vec!["chmod".to_string(), "o+x".into(), "/p".into()];
        assert_eq!(
            command_argv(&argv, true, false),
            ["sudo", "chmod", "o+x", "/p"]
        );
        assert_eq!(command_argv(&argv, true, true), ["chmod", "o+x", "/p"]);
        assert_eq!(command_argv(&argv, false, false), ["chmod", "o+x", "/p"]);
    }

    #[test]
    fn advice_top_fix_blocks_auto_apply_escalation() {
        assert!(matches!(execute(&advice_fix(), false), Ok(None)));
        let advice_over_run = vec![run_fix("remount", true, Risk::High), advice_fix_low()];
        let top = ordered(&advice_over_run).into_iter().next().unwrap();
        assert!(!top.is_run(), "safe advice outranks the high-risk sudo fix");
    }

    fn tree() -> (PathBuf, PathBuf) {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = std::env::temp_dir().join(format!("whycant_fx_{}_{nanos}", std::process::id()));
        let c = base.join("a").join("b").join("c");
        fs::create_dir_all(&c).unwrap();
        for d in [&base, &base.join("a"), &c] {
            fs::set_permissions(d, fs::Permissions::from_mode(0o755)).unwrap();
        }
        fs::set_permissions(base.join("a").join("b"), fs::Permissions::from_mode(0o644)).unwrap();
        (base, c)
    }

    fn owner_id() -> Identity {
        Identity {
            uid: uzers::get_effective_uid(),
            primary_gid: uzers::get_current_gid(),
            groups: vec![uzers::get_current_gid()],
            name: Some("me".into()),
            is_self: false,
        }
    }

    #[test]
    fn recheck_reports_cleared_and_not_cleared() {
        let (base, c) = tree();
        let b = base.join("a").join("b");
        fs::set_permissions(&b, fs::Permissions::from_mode(0o000)).unwrap();
        let chain = engine::default_chain();
        let id = owner_id();

        if uzers::get_effective_uid() != 0 {
            let before = engine::run(&chain, &id, &c, Op::Traverse, false);
            assert_eq!(before.blocking_layer, Some(LayerId::Traverse));
            assert!(matches!(
                recheck(&chain, &id, &c, Op::Traverse),
                Recheck::Blocked {
                    layer: Some(LayerId::Traverse),
                    ..
                }
            ));
        }

        fs::set_permissions(&b, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            recheck(&chain, &id, &c, Op::Traverse),
            Recheck::Cleared
        ));

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn owned_dir_fix_needs_no_root() {
        let (base, c) = tree();
        let b = base.join("a").join("b");
        fs::set_permissions(&b, fs::Permissions::from_mode(0o600)).unwrap();
        let owner = uzers::get_effective_uid();
        let id = Identity {
            uid: owner,
            primary_gid: uzers::get_current_gid(),
            groups: vec![uzers::get_current_gid()],
            name: Some("me".into()),
            is_self: false,
        };
        let rep = engine::run(&engine::default_chain(), &id, &c, Op::Traverse, false);
        if owner != 0 {
            let fix = ordered(&rep.fixes)
                .into_iter()
                .find(|f| f.is_run())
                .expect("a runnable fix");
            assert!(!fix.needs_root, "owner-fix should not need root");
            assert_eq!(command_argv(fix.argv(), fix.needs_root, false), fix.argv());
        }
        let _: &Path = &c;
        let _ = fs::remove_dir_all(&base);
    }
}
