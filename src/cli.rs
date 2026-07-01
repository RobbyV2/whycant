use crate::config::{Settings, Tristate};
use crate::op::OpArg;
use clap::{CommandFactory, Parser, ValueEnum};
use clap_complete::{Shell, generate};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;

const VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (",
    env!("WHYCANT_GIT_HASH"),
    ")"
);

#[derive(Parser)]
#[command(
    name = "whycant",
    version = VERSION,
    about = "Explain, with evidence, why a filesystem operation is denied."
)]
pub struct Cli {
    #[arg(value_enum, value_name = "OP")]
    pub op: Option<OpArg>,
    #[arg(value_name = "PATH")]
    pub path: Option<PathBuf>,
    #[arg(last = true, value_name = "CMD")]
    pub cmd: Vec<OsString>,
    #[arg(long, value_name = "USER")]
    pub user: Option<String>,
    #[arg(long)]
    pub trace: bool,
    #[arg(short = 'i', long = "interactive", overrides_with = "no_interactive")]
    pub interactive: bool,
    #[arg(short = 'I', long = "no-interactive")]
    pub no_interactive: bool,
    #[arg(short = 'v', long = "all")]
    pub all: bool,
    #[arg(short = 'q', long)]
    pub quiet: bool,
    #[arg(long, conflicts_with_all = ["toml", "format"])]
    pub json: bool,
    #[arg(long, conflicts_with_all = ["json", "format"])]
    pub toml: bool,
    #[arg(long, value_enum, value_name = "FMT")]
    pub format: Option<Format>,
    #[arg(long, value_enum, value_name = "WHEN", default_value = "auto")]
    pub color: ColorMode,
    #[arg(short = 'a', long)]
    pub ascii: bool,
    #[arg(long)]
    pub apply: bool,
    #[arg(long)]
    pub yes: bool,
    #[arg(long, value_enum, value_name = "SHELL", hide = true)]
    pub completions: Option<Shell>,
    #[arg(long = "man", hide = true)]
    pub man: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ColorMode {
    Auto,
    Always,
    Never,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    Human,
    Json,
    Toml,
    Plain,
}

pub struct Resolved {
    pub color: ColorMode,
    pub format: Format,
    pub ascii: bool,
    pub all: bool,
    pub quiet: bool,
    pub print_fixes: bool,
    pub interactive: Option<bool>,
}

pub enum Action {
    Prompt,
    PrintOnly,
    ApplyFirst,
}

impl Cli {
    pub fn resolve(&self, cfg: &Settings) -> Resolved {
        let explicit = match (self.json, self.toml, self.format) {
            (true, _, _) => Some(Format::Json),
            (_, true, _) => Some(Format::Toml),
            (_, _, f @ Some(_)) => f,
            _ => None,
        };
        let format = explicit
            .or(cfg.format)
            .unwrap_or_else(|| match is_ci() && !force_color() {
                true => Format::Plain,
                false => Format::Human,
            });
        let color = match self.color {
            ColorMode::Auto => cfg.color.unwrap_or(ColorMode::Auto),
            c => c,
        };
        let interactive = match (self.interactive, self.no_interactive) {
            (true, _) => Some(true),
            (_, true) => Some(false),
            _ => match cfg.interactive {
                Some(Tristate::On) => Some(true),
                Some(Tristate::Off) => Some(false),
                Some(Tristate::Auto) | None => None,
            },
        };
        Resolved {
            color,
            format,
            ascii: self.ascii || cfg.ascii.unwrap_or(false),
            all: self.all || cfg.all.unwrap_or(false),
            quiet: self.quiet,
            print_fixes: cfg.print_fixes.unwrap_or(true),
            interactive,
        }
    }

    pub fn action(&self, interactive: bool) -> anyhow::Result<Action> {
        match (interactive, self.apply, self.yes) {
            (true, _, _) => Ok(Action::Prompt),
            (false, false, _) => Ok(Action::PrintOnly),
            (false, true, true) => Ok(Action::ApplyFirst),
            (false, true, false) => Err(anyhow::anyhow!(
                "--apply needs --yes to run non-interactively"
            )),
        }
    }
}

fn env_present(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|v| !v.is_empty())
}

fn env_truthy(name: &str) -> bool {
    matches!(std::env::var(name), Ok(v) if !v.is_empty() && v != "0" && v != "false")
}

fn is_ci() -> bool {
    ["CI", "GITHUB_ACTIONS", "GITLAB_CI"]
        .iter()
        .any(|k| env_present(k))
}

fn force_color() -> bool {
    env_truthy("CLICOLOR_FORCE") || env_truthy("FORCE_COLOR")
}

const EXIT_STATUS_ROFF: &str = "\
.SH \"EXIT STATUS\"
.TP
.B 0
Allowed; nothing denies the operation.
.TP
.B 1
Blocked (proven).
.TP
.B 2
Blocked but indeterminate; needs elevated privilege to decide.
.TP
.B 3
Target error: ENOENT, not a regular file, or broken symlink.
.TP
.B 64
Usage error.
";

pub fn render_completions(shell: Shell) -> Vec<u8> {
    let mut cmd = Cli::command();
    let name = cmd.get_name().to_string();
    let mut buf = Vec::new();
    generate(shell, &mut cmd, name, &mut buf);
    buf
}

pub fn render_manpage() -> anyhow::Result<Vec<u8>> {
    let man = clap_mangen::Man::new(Cli::command());
    let mut buf = Vec::new();
    man.render_title(&mut buf)?;
    man.render_name_section(&mut buf)?;
    man.render_synopsis_section(&mut buf)?;
    man.render_description_section(&mut buf)?;
    man.render_options_section(&mut buf)?;
    buf.extend_from_slice(EXIT_STATUS_ROFF.as_bytes());
    man.render_version_section(&mut buf)?;
    Ok(buf)
}

pub fn print_completions(shell: Shell) -> anyhow::Result<()> {
    std::io::stdout().write_all(&render_completions(shell))?;
    Ok(())
}

pub fn print_manpage() -> anyhow::Result<()> {
    std::io::stdout().write_all(&render_manpage()?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).unwrap()
    }

    fn settings() -> Settings {
        Settings::default()
    }

    #[test]
    fn explicit_op_path() {
        let c = parse(&["whycant", "read", "/etc/shadow"]);
        assert!(matches!(c.op, Some(OpArg::Read)));
        assert_eq!(c.path.as_deref(), Some(Path::new("/etc/shadow")));
        assert!(c.cmd.is_empty());
    }

    #[test]
    fn cmd_form() {
        let c = parse(&["whycant", "--", "rm", "-rf", "/etc"]);
        assert!(c.op.is_none() && c.path.is_none());
        assert_eq!(c.cmd, ["rm", "-rf", "/etc"]);
    }

    #[test]
    fn cd_alias_parses() {
        let c = parse(&["whycant", "cd", "/srv"]);
        assert!(matches!(c.op, Some(OpArg::Cd)));
    }

    #[test]
    fn flag_beats_config_format() {
        let mut cfg = settings();
        cfg.format = Some(Format::Toml);
        assert!(matches!(
            parse(&["whycant", "--json", "read", "/p"])
                .resolve(&cfg)
                .format,
            Format::Json
        ));
    }

    #[test]
    fn config_format_used_without_flag() {
        let mut cfg = settings();
        cfg.format = Some(Format::Toml);
        assert!(matches!(
            parse(&["whycant", "read", "/p"]).resolve(&cfg).format,
            Format::Toml
        ));
    }

    #[test]
    fn flag_beats_config_color() {
        let mut cfg = settings();
        cfg.color = Some(ColorMode::Never);
        let r = parse(&["whycant", "--color", "always", "read", "/p"]).resolve(&cfg);
        assert!(matches!(r.color, ColorMode::Always));
    }

    #[test]
    fn config_color_used_when_auto() {
        let mut cfg = settings();
        cfg.color = Some(ColorMode::Never);
        let r = parse(&["whycant", "read", "/p"]).resolve(&cfg);
        assert!(matches!(r.color, ColorMode::Never));
    }

    #[test]
    fn all_from_config_or_flag() {
        let mut cfg = settings();
        cfg.all = Some(true);
        assert!(parse(&["whycant", "read", "/p"]).resolve(&cfg).all);
        assert!(
            parse(&["whycant", "-v", "read", "/p"])
                .resolve(&settings())
                .all
        );
    }

    #[test]
    fn interactive_precedence() {
        let mut cfg = settings();
        cfg.interactive = Some(Tristate::Off);
        assert_eq!(
            parse(&["whycant", "-i", "read", "/p"])
                .resolve(&cfg)
                .interactive,
            Some(true)
        );
        cfg.interactive = Some(Tristate::On);
        assert_eq!(
            parse(&["whycant", "read", "/p"]).resolve(&cfg).interactive,
            Some(true)
        );
        cfg.interactive = Some(Tristate::Auto);
        assert_eq!(
            parse(&["whycant", "read", "/p"]).resolve(&cfg).interactive,
            None
        );
    }

    #[test]
    fn completions_carry_binary_name() {
        let out = String::from_utf8(render_completions(Shell::Bash)).unwrap();
        assert!(!out.is_empty());
        assert!(out.contains("whycant"));
    }

    #[test]
    fn manpage_lists_exit_codes() {
        let out = String::from_utf8(render_manpage().unwrap()).unwrap();
        assert!(!out.is_empty());
        assert!(out.contains("EXIT STATUS"));
        for code in ["0", "1", "2", "3", "64"] {
            assert!(out.contains(code), "missing exit code {code}");
        }
    }

    #[test]
    fn apply_needs_yes_non_interactive() {
        assert!(
            parse(&["whycant", "--apply", "read", "/p"])
                .action(false)
                .is_err()
        );
        assert!(matches!(
            parse(&["whycant", "--apply", "read", "/p"]).action(true),
            Ok(Action::Prompt)
        ));
        assert!(matches!(
            parse(&["whycant", "--apply", "--yes", "read", "/p"]).action(false),
            Ok(Action::ApplyFirst)
        ));
        assert!(matches!(
            parse(&["whycant", "read", "/p"]).action(false),
            Ok(Action::PrintOnly)
        ));
    }
}
