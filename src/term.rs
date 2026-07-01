//! Terminal capability and policy. Owns color and hyperlink resolution, glyph
//! set, width, and signal-safe teardown; no other module reads terminal env
//! vars, calls `isatty`, or emits an escape directly.

use crate::cli::ColorMode;
use std::borrow::Cow;
use std::io::{IsTerminal, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ColorDepth {
    None,
    Ansi16,
    Ansi256,
    TrueColor,
}

#[derive(Clone, Copy)]
pub enum GlyphSet {
    Unicode,
    Ascii,
}

#[derive(Clone, Copy)]
pub enum Stream {
    Out,
    Err,
}

#[derive(Clone, Copy)]
pub enum Glyph {
    Deny,
    Pass,
    Arrow,
}

pub struct TermCtx {
    pub color: ColorDepth,
    pub glyphs: GlyphSet,
    pub hyperlinks: bool,
    pub width: usize,
}

static OUT_ON: AtomicBool = AtomicBool::new(true);
static ERR_ON: AtomicBool = AtomicBool::new(true);
static HYPERLINKS: AtomicBool = AtomicBool::new(false);
static DIRTY: AtomicBool = AtomicBool::new(false);
static INSTALLED: AtomicBool = AtomicBool::new(false);

fn env_str(k: &str) -> String {
    std::env::var(k).unwrap_or_default()
}

fn env_nonempty(k: &str) -> bool {
    std::env::var(k).map(|v| !v.is_empty()).unwrap_or(false)
}

fn env_truthy(k: &str) -> bool {
    matches!(std::env::var(k), Ok(v) if !v.is_empty() && v != "0" && v != "false")
}

fn is_ci() -> bool {
    ["CI", "GITHUB_ACTIONS", "GITLAB_CI"]
        .iter()
        .any(|k| env_nonempty(k))
}

fn is_c_locale() -> bool {
    ["LC_ALL", "LC_CTYPE", "LANG"]
        .iter()
        .any(|k| matches!(std::env::var(k).as_deref(), Ok("") | Ok("C") | Ok("POSIX")))
}

struct ColorEnv {
    no_color: bool,
    force: bool,
    clicolor_zero: bool,
    dumb: bool,
    truecolor: bool,
    term256: bool,
}

impl ColorEnv {
    fn detect() -> Self {
        let term = env_str("TERM");
        let colorterm = env_str("COLORTERM");
        Self {
            no_color: env_nonempty("NO_COLOR"),
            force: env_truthy("CLICOLOR_FORCE") || env_truthy("FORCE_COLOR"),
            clicolor_zero: env_str("CLICOLOR") == "0",
            dumb: term == "dumb",
            truecolor: colorterm.contains("truecolor") || colorterm.contains("24bit"),
            term256: term.contains("256color"),
        }
    }
}

fn color_on(mode: ColorMode, ascii: bool, env: &ColorEnv, tty: bool) -> bool {
    if ascii {
        return false;
    }
    match mode {
        ColorMode::Never => false,
        ColorMode::Always => true,
        ColorMode::Auto => {
            if env.no_color {
                return false;
            }
            if env.force {
                return true;
            }
            if env.clicolor_zero {
                return false;
            }
            tty
        }
    }
}

fn depth_of(on: bool, env: &ColorEnv) -> ColorDepth {
    match () {
        _ if !on || env.dumb => ColorDepth::None,
        _ if env.truecolor => ColorDepth::TrueColor,
        _ if env.term256 => ColorDepth::Ansi256,
        _ => ColorDepth::Ansi16,
    }
}

extern "C" fn on_signal(sig: libc::c_int) {
    if DIRTY.load(Ordering::Relaxed) {
        const RESET: &[u8] = b"\x1b]8;;\x1b\\\x1b[0m";
        unsafe {
            if OUT_ON.load(Ordering::Relaxed) || HYPERLINKS.load(Ordering::Relaxed) {
                libc::write(1, RESET.as_ptr() as *const libc::c_void, RESET.len());
            }
            if ERR_ON.load(Ordering::Relaxed) {
                libc::write(2, RESET.as_ptr() as *const libc::c_void, RESET.len());
            }
            libc::signal(sig, libc::SIG_DFL);
            libc::raise(sig);
        }
    } else {
        unsafe {
            libc::signal(sig, libc::SIG_DFL);
            libc::raise(sig);
        }
    }
}

fn install_signals() {
    if INSTALLED.swap(true, Ordering::SeqCst) {
        return;
    }
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_signal as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
    }
}

fn file_uri(p: &Path) -> Option<String> {
    let abs = match p.is_absolute() {
        true => p.to_path_buf(),
        false => p.canonicalize().ok()?,
    };
    let mut enc = String::new();
    for &b in abs.as_os_str().as_bytes() {
        let keep = (0x20..=0x7e).contains(&b) && !matches!(b, b' ' | b'%' | b'?' | b'#');
        match keep {
            true => enc.push(b as char),
            false => enc.push_str(&format!("%{b:02X}")),
        }
    }
    Some(format!("file://{enc}"))
}

fn wrap_osc8(uri: &str, text: &str) -> String {
    format!("\x1b]8;;{uri}\x1b\\{text}\x1b]8;;\x1b\\")
}

fn hyperlink_core<'a>(enabled: bool, abspath: &Path, text: &'a str) -> Cow<'a, str> {
    if !enabled {
        return Cow::Borrowed(text);
    }
    match file_uri(abspath) {
        Some(uri) if uri.len() <= 2000 => Cow::Owned(wrap_osc8(&uri, text)),
        _ => Cow::Borrowed(text),
    }
}

fn truncate_middle(full: &str, base: &str, max: usize, ell: &str) -> String {
    if full.chars().count() <= max {
        return full.to_string();
    }
    let bw = base.chars().count();
    let ew = ell.chars().count();
    if bw + ew >= max {
        return format!("{ell}{base}");
    }
    let head: String = full.chars().take(max - bw - ew).collect();
    format!("{head}{ell}{base}")
}

impl TermCtx {
    pub fn detect(color: ColorMode, ascii: bool) -> Self {
        let env = ColorEnv::detect();
        let out_tty = std::io::stdout().is_terminal();
        let err_tty = std::io::stderr().is_terminal();
        let out_on = color_on(color, ascii, &env, out_tty);
        let err_on = color_on(color, ascii, &env, err_tty);
        let depth = depth_of(out_on || err_on, &env);
        OUT_ON.store(out_on && depth != ColorDepth::None, Ordering::Relaxed);
        ERR_ON.store(err_on && depth != ColorDepth::None, Ordering::Relaxed);
        let hyper = out_tty
            && !is_ci()
            && !ascii
            && depth != ColorDepth::None
            && supports_hyperlinks::on(supports_hyperlinks::Stream::Stdout);
        HYPERLINKS.store(hyper, Ordering::Relaxed);
        install_signals();
        let glyphs = match ascii || env.dumb || is_c_locale() {
            true => GlyphSet::Ascii,
            false => GlyphSet::Unicode,
        };
        let width = terminal_size::terminal_size()
            .map(|(w, _)| w.0 as usize)
            .or_else(|| std::env::var("COLUMNS").ok().and_then(|c| c.parse().ok()))
            .unwrap_or(80);
        Self {
            color: depth,
            glyphs,
            hyperlinks: hyper,
            width,
        }
    }

    pub fn out(&self) -> anstream::AutoStream<std::io::Stdout> {
        anstream::AutoStream::new(std::io::stdout(), self.choice(Stream::Out))
    }

    pub fn err(&self) -> anstream::AutoStream<std::io::Stderr> {
        anstream::AutoStream::new(std::io::stderr(), self.choice(Stream::Err))
    }

    fn choice(&self, s: Stream) -> anstream::ColorChoice {
        match self.colored(s) {
            true => anstream::ColorChoice::Always,
            false => anstream::ColorChoice::Never,
        }
    }

    pub fn colored(&self, s: Stream) -> bool {
        if self.color == ColorDepth::None {
            return false;
        }
        match s {
            Stream::Out => OUT_ON.load(Ordering::Relaxed),
            Stream::Err => ERR_ON.load(Ordering::Relaxed),
        }
    }

    pub fn mark_dirty(&self) {
        DIRTY.store(true, Ordering::Relaxed);
    }

    pub fn glyph(&self, g: Glyph) -> &'static str {
        match (self.glyphs, g) {
            (GlyphSet::Unicode, Glyph::Deny) => "\u{2717}",
            (GlyphSet::Unicode, Glyph::Pass) => "\u{2713}",
            (GlyphSet::Unicode, Glyph::Arrow) => "\u{2192}",
            (GlyphSet::Ascii, Glyph::Deny) => "x",
            (GlyphSet::Ascii, Glyph::Pass) => "ok",
            (GlyphSet::Ascii, Glyph::Arrow) => "->",
        }
    }

    pub fn style_rgb(&self, r: u8, g: u8, b: u8) -> anstyle::Style {
        match self.quantize(r, g, b) {
            Some(c) => anstyle::Style::new().fg_color(Some(c)),
            None => anstyle::Style::new(),
        }
    }

    fn quantize(&self, r: u8, g: u8, b: u8) -> Option<anstyle::Color> {
        use anstyle::AnsiColor::{
            Black, Blue, BrightBlack, BrightBlue, BrightCyan, BrightGreen, BrightMagenta,
            BrightRed, BrightWhite, BrightYellow, Cyan, Green, Magenta, Red, White, Yellow,
        };
        match self.color {
            ColorDepth::None => None,
            ColorDepth::TrueColor => Some(anstyle::Color::Rgb(anstyle::RgbColor(r, g, b))),
            ColorDepth::Ansi256 => {
                let q = |v: u8| (v as u16 * 5 / 255) as u8;
                Some(anstyle::Color::Ansi256(anstyle::Ansi256Color(
                    16 + 36 * q(r) + 6 * q(g) + q(b),
                )))
            }
            ColorDepth::Ansi16 => {
                let hi = |v: u8| (v > 0x60) as usize;
                let idx = hi(r) | hi(g) << 1 | hi(b) << 2;
                let bright = r.max(g).max(b) > 0xaa;
                let dim = [Black, Red, Green, Yellow, Blue, Magenta, Cyan, White];
                let brt = [
                    BrightBlack,
                    BrightRed,
                    BrightGreen,
                    BrightYellow,
                    BrightBlue,
                    BrightMagenta,
                    BrightCyan,
                    BrightWhite,
                ];
                let c = match bright {
                    true => brt[idx],
                    false => dim[idx],
                };
                Some(anstyle::Color::Ansi(c))
            }
        }
    }

    pub fn hyperlink<'a>(&self, abspath: &Path, text: &'a str) -> Cow<'a, str> {
        let out = hyperlink_core(self.hyperlinks, abspath, text);
        if matches!(out, Cow::Owned(_)) {
            self.mark_dirty();
        }
        out
    }

    pub fn truncate_path(&self, p: &Path, max: usize) -> String {
        let full = p.display().to_string();
        let base = p
            .file_name()
            .map(|b| b.to_string_lossy().into_owned())
            .unwrap_or_default();
        let ell = match self.glyphs {
            GlyphSet::Unicode => "\u{2026}",
            GlyphSet::Ascii => "...",
        };
        truncate_middle(&full, &base, max, ell)
    }

    pub fn banner(&self, line: &str) {
        let _ = writeln!(self.err(), "whycant: {line}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn env(
        dumb: bool,
        truecolor: bool,
        term256: bool,
        no_color: bool,
        force: bool,
        cz: bool,
    ) -> ColorEnv {
        ColorEnv {
            no_color,
            force,
            clicolor_zero: cz,
            dumb,
            truecolor,
            term256,
        }
    }

    fn resolve(mode: ColorMode, ascii: bool, e: &ColorEnv, tty: bool) -> ColorDepth {
        depth_of(color_on(mode, ascii, e, tty), e)
    }

    #[test]
    fn never_is_off() {
        let e = env(false, true, false, false, true, false);
        assert_eq!(resolve(ColorMode::Never, false, &e, true), ColorDepth::None);
    }

    #[test]
    fn always_beats_pipe_and_no_color() {
        let e = env(false, false, false, true, false, false);
        assert_eq!(
            resolve(ColorMode::Always, false, &e, false),
            ColorDepth::Ansi16
        );
    }

    #[test]
    fn ascii_forces_off() {
        let e = env(false, true, false, false, false, false);
        assert_eq!(resolve(ColorMode::Always, true, &e, true), ColorDepth::None);
    }

    #[test]
    fn no_color_beats_force() {
        let e = env(false, false, false, true, true, false);
        assert_eq!(resolve(ColorMode::Auto, false, &e, true), ColorDepth::None);
    }

    #[test]
    fn force_beats_pipe() {
        let e = env(false, false, false, false, true, false);
        assert_eq!(
            resolve(ColorMode::Auto, false, &e, false),
            ColorDepth::Ansi16
        );
    }

    #[test]
    fn clicolor_zero_off_on_tty() {
        let e = env(false, false, false, false, false, true);
        assert_eq!(resolve(ColorMode::Auto, false, &e, true), ColorDepth::None);
    }

    #[test]
    fn auto_tty_tiers() {
        let tc = env(false, true, false, false, false, false);
        assert_eq!(
            resolve(ColorMode::Auto, false, &tc, true),
            ColorDepth::TrueColor
        );
        let c256 = env(false, false, true, false, false, false);
        assert_eq!(
            resolve(ColorMode::Auto, false, &c256, true),
            ColorDepth::Ansi256
        );
        let c16 = env(false, false, false, false, false, false);
        assert_eq!(
            resolve(ColorMode::Auto, false, &c16, true),
            ColorDepth::Ansi16
        );
    }

    #[test]
    fn auto_pipe_off() {
        let e = env(false, true, false, false, false, false);
        assert_eq!(resolve(ColorMode::Auto, false, &e, false), ColorDepth::None);
    }

    #[test]
    fn dumb_forces_none_even_with_force() {
        let e = env(true, true, true, false, true, false);
        assert_eq!(
            resolve(ColorMode::Always, false, &e, true),
            ColorDepth::None
        );
    }

    #[test]
    fn hyperlink_emits_only_when_enabled() {
        let p = Path::new("/tmp/some file.txt");
        let on = hyperlink_core(true, p, "label");
        assert!(on.contains("\x1b]8;;file:///tmp/some%20file.txt"));
        assert!(on.ends_with("\x1b]8;;\x1b\\"));
        assert!(on.contains("label"));
        let off = hyperlink_core(false, p, "label");
        assert_eq!(off, Cow::Borrowed("label"));
    }

    #[test]
    fn truncate_keeps_basename_and_elides_middle() {
        let full = "/home/alice/deeply/nested/dir/secret.txt";
        let out = truncate_middle(full, "secret.txt", 20, "\u{2026}");
        assert!(out.contains("secret.txt"), "basename kept: {out}");
        assert!(out.contains('\u{2026}'), "ellipsis present: {out}");
        assert!(out.chars().count() <= 20, "within width: {out}");
        assert!(out.starts_with('/'), "head retained: {out}");
    }

    #[test]
    fn truncate_never_drops_basename() {
        let out = truncate_middle("/a/verylongbasename.txt", "verylongbasename.txt", 8, "...");
        assert!(out.ends_with("verylongbasename.txt"));
    }

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn env_reader_picks_up_no_color() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var("NO_COLOR", "1") };
        assert!(ColorEnv::detect().no_color);
        unsafe { std::env::remove_var("NO_COLOR") };
        assert!(!ColorEnv::detect().no_color);
    }
}
