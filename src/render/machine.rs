use crate::report::{Report, Risk};
use anyhow::Result;

pub fn render_json(report: &Report) -> Result<String> {
    Ok(serde_json::to_string_pretty(report)?)
}

pub fn render_toml(report: &Report) -> Result<String> {
    Ok(toml::to_string_pretty(report)?)
}

fn risk_word(r: Risk) -> &'static str {
    match r {
        Risk::Low => "low",
        Risk::Medium => "medium",
        Risk::High => "high",
    }
}

pub fn render_plain(report: &Report) -> String {
    let op = format!("{:?}", report.op).to_lowercase();
    let mut lines = vec![format!(
        "{} {} {} {}",
        report.verdict.glyph(),
        report.verdict.word(),
        op,
        report.path.display()
    )];
    if let Some(c) = &report.culprit {
        lines.push(format!("culprit: {c}"));
    }
    for f in &report.fixes {
        lines.push(format!(
            "fix: {}  [risk: {}]",
            f.display(),
            risk_word(f.risk)
        ));
    }
    for w in &report.warnings {
        lines.push(format!("warning: {w}"));
    }
    lines.join("\n")
}
