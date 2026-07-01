pub use crate::report::Fix;

impl Fix {
    pub fn display(&self) -> String {
        let cmd = self
            .argv
            .iter()
            .map(|a| shell_quote(a))
            .collect::<Vec<_>>()
            .join(" ");
        match self.needs_root {
            true => format!("sudo {cmd}"),
            false => cmd,
        }
    }
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
