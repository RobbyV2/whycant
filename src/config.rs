use crate::cli::{ColorMode, Format};
use anyhow::Result;
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Clone, Copy)]
pub enum Tristate {
    On,
    Off,
    Auto,
}

impl<'de> Deserialize<'de> for Tristate {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = Tristate;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("0|1|on|off|auto")
            }
            fn visit_bool<E>(self, v: bool) -> Result<Tristate, E> {
                Ok(if v { Tristate::On } else { Tristate::Off })
            }
            fn visit_i64<E>(self, v: i64) -> Result<Tristate, E> {
                Ok(if v != 0 { Tristate::On } else { Tristate::Off })
            }
            fn visit_u64<E>(self, v: u64) -> Result<Tristate, E> {
                Ok(if v != 0 { Tristate::On } else { Tristate::Off })
            }
            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Tristate, E> {
                match s.to_ascii_lowercase().as_str() {
                    "on" | "1" | "true" | "yes" => Ok(Tristate::On),
                    "off" | "0" | "false" | "no" => Ok(Tristate::Off),
                    "auto" => Ok(Tristate::Auto),
                    o => Err(E::custom(format!("invalid interactive value: {o}"))),
                }
            }
        }
        d.deserialize_any(V)
    }
}

#[derive(Deserialize, Default)]
pub struct Settings {
    pub color: Option<ColorMode>,
    pub format: Option<Format>,
    pub interactive: Option<Tristate>,
    pub print_fixes: Option<bool>,
    pub ascii: Option<bool>,
    pub all: Option<bool>,
}

fn config_dir() -> Option<PathBuf> {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
}

pub fn load() -> Result<Settings> {
    let mut b = ::config::Config::builder();
    if let Some(dir) = config_dir() {
        let path = dir.join("whycant").join("config.toml");
        b = b.add_source(
            ::config::File::from(path)
                .format(::config::FileFormat::Toml)
                .required(false),
        );
    }
    b = b.add_source(::config::Environment::with_prefix("WHYCANT").try_parsing(true));
    Ok(b.build()?.try_deserialize()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::ColorMode;
    use std::io::Write;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn temp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "whycant-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(d.join("whycant")).unwrap();
        d
    }

    #[test]
    fn env_beats_file_and_underscore_key() {
        let _g = ENV_LOCK.lock().unwrap();
        let dir = temp_dir("layer");
        let mut f = std::fs::File::create(dir.join("whycant").join("config.toml")).unwrap();
        writeln!(f, "color = \"always\"\nprint_fixes = false\n").unwrap();
        std::env::set_var("XDG_CONFIG_HOME", &dir);
        std::env::set_var("WHYCANT_COLOR", "never");
        std::env::set_var("WHYCANT_PRINT_FIXES", "true");
        std::env::set_var("WHYCANT_INTERACTIVE", "1");
        let s = load().unwrap();
        std::env::remove_var("WHYCANT_COLOR");
        std::env::remove_var("WHYCANT_PRINT_FIXES");
        std::env::remove_var("WHYCANT_INTERACTIVE");
        std::env::remove_var("XDG_CONFIG_HOME");
        std::fs::remove_dir_all(&dir).ok();
        assert!(matches!(s.color, Some(ColorMode::Never)));
        assert_eq!(s.print_fixes, Some(true));
        assert!(matches!(s.interactive, Some(Tristate::On)));
    }

    #[test]
    fn missing_file_is_defaults() {
        let _g = ENV_LOCK.lock().unwrap();
        let dir = temp_dir("empty");
        std::env::set_var("XDG_CONFIG_HOME", &dir);
        let s = load().unwrap();
        std::env::remove_var("XDG_CONFIG_HOME");
        std::fs::remove_dir_all(&dir).ok();
        assert!(s.color.is_none() && s.format.is_none() && s.interactive.is_none());
    }
}
