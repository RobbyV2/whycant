pub mod human;
pub mod machine;

use crate::cli::Format;
use crate::report::Report;
use crate::term::TermCtx;
use anyhow::Result;

pub fn render(report: &Report, format: Format, term: &TermCtx, verbose: bool) -> Result<String> {
    match format {
        Format::Human => Ok(human::render_human(report, term, verbose)),
        Format::Json => machine::render_json(report),
        Format::Toml => machine::render_toml(report),
        Format::Plain => Ok(machine::render_plain(report)),
    }
}
