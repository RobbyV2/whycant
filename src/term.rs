use crate::cli::ColorMode;
use std::borrow::Cow;
use std::io::{IsTerminal, Write};
use std::path::Path;

#[derive(Clone, Copy, PartialEq, Eq)]
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
    pub width: usize,
}

fn is_dumb() -> bool {
    std::env::var("TERM").map(|t| t == "dumb").unwrap_or(false)
}

fn is_c_locale() -> bool {
    ["LC_ALL", "LC_CTYPE", "LANG"]
        .iter()
        .any(|k| matches!(std::env::var(k).as_deref(), Ok("") | Ok("C") | Ok("POSIX")))
}

fn resolve_on(mode: ColorMode, tty: bool) -> bool {
    match mode {
        ColorMode::Never => false,
        ColorMode::Always => true,
        ColorMode::Auto => {
            if anstyle_query::no_color() {
                return false;
            }
            if anstyle_query::clicolor_force() {
                return true;
            }
            tty
        }
    }
}

fn detect_depth() -> ColorDepth {
    if is_dumb() {
        return ColorDepth::None;
    }
    let colorterm = std::env::var("COLORTERM").unwrap_or_default();
    if colorterm.contains("truecolor") || colorterm.contains("24bit") {
        return ColorDepth::TrueColor;
    }
    match std::env::var("TERM")
        .unwrap_or_default()
        .contains("256color")
    {
        true => ColorDepth::Ansi256,
        false => ColorDepth::Ansi16,
    }
}

impl TermCtx {
    pub fn detect(color: ColorMode, ascii: bool) -> Self {
        let depth = match resolve_on(color, std::io::stdout().is_terminal()) {
            true => detect_depth(),
            false => ColorDepth::None,
        };
        let glyphs = match ascii || is_dumb() || is_c_locale() {
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

    pub fn colored(&self, _s: Stream) -> bool {
        self.color != ColorDepth::None
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
        anstyle::Style::new().fg_color(Some(anstyle::Color::Rgb(anstyle::RgbColor(r, g, b))))
    }

    pub fn hyperlink<'a>(&self, _abspath: &Path, text: &'a str) -> Cow<'a, str> {
        Cow::Borrowed(text)
    }

    pub fn truncate_path(&self, p: &Path, _max: usize) -> String {
        p.display().to_string()
    }

    pub fn banner(&self, line: &str) {
        let _ = writeln!(self.err(), "whycant: {line}");
    }
}
