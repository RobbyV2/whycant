use crate::report::{
    CrossCheck, Evidence, EvidenceSource, Fix, Mark, PathComponent, Report, Risk, Verdict,
};
use crate::term::{Glyph, GlyphSet, Stream, TermCtx};
use anstyle::Style;
use std::path::Path;

pub fn render_human(report: &Report, term: &TermCtx, verbose: bool) -> String {
    let mut lines: Vec<String> = Vec::new();
    lines.push(verdict_line(report, term));
    push_zone(&mut lines, chain_lines(report, term, verbose));
    push_zone(&mut lines, evidence_lines(report, term));
    push_zone(&mut lines, crosscheck_lines(report, term));
    push_zone(&mut lines, fix_lines(report, term));
    lines.join("\n")
}

fn push_zone(lines: &mut Vec<String>, zone: Vec<String>) {
    if !zone.is_empty() {
        lines.push(String::new());
        lines.extend(zone);
    }
}

fn paint(term: &TermCtx, style: Style, s: &str) -> String {
    match term.colored(Stream::Out) {
        true => format!("{}{}{}", style.render(), s, style.render_reset()),
        false => s.to_string(),
    }
}

fn verdict_style(term: &TermCtx, v: Verdict) -> Style {
    let (r, g, b) = match v {
        Verdict::Allowed => (0x2e, 0xcc, 0x71),
        Verdict::Blocked => (0xe7, 0x4c, 0x3c),
        Verdict::Indeterminate => (0xf1, 0xc4, 0x0f),
        Verdict::TargetError => (0xe6, 0x7e, 0x22),
    };
    term.style_rgb(r, g, b).bold()
}

fn verdict_glyph(term: &TermCtx, v: Verdict) -> &'static str {
    match v {
        Verdict::Allowed => term.glyph(Glyph::Pass),
        Verdict::Blocked => term.glyph(Glyph::Deny),
        Verdict::Indeterminate => "?",
        Verdict::TargetError => match term.glyphs {
            GlyphSet::Unicode => "\u{26a0}",
            GlyphSet::Ascii => "!",
        },
    }
}

fn render_path(term: &TermCtx, p: &Path, max: usize) -> String {
    let text = term.truncate_path(p, max);
    term.hyperlink(p, &text).into_owned()
}

fn verdict_line(report: &Report, term: &TermCtx) -> String {
    let v = report.verdict;
    let head = paint(
        term,
        verdict_style(term, v),
        &format!("{} {}", verdict_glyph(term, v), v.word()),
    );
    let op = format!("{:?}", report.op).to_lowercase();
    let path = render_path(term, &report.path, term.width);
    let mut line = format!("{head}  {op} {path}");
    if let Some(c) = &report.culprit {
        line.push_str(&format!("   {c}"));
    }
    line
}

fn mark_glyph(term: &TermCtx, m: Mark) -> &'static str {
    match m {
        Mark::Pass => term.glyph(Glyph::Pass),
        Mark::Block => term.glyph(Glyph::Deny),
        Mark::NotReached => match term.glyphs {
            GlyphSet::Unicode => "\u{00b7}",
            GlyphSet::Ascii => ".",
        },
    }
}

fn mark_style(term: &TermCtx, m: Mark) -> Style {
    let (r, g, b) = match m {
        Mark::Pass => (0x2e, 0xcc, 0x71),
        Mark::Block => (0xe7, 0x4c, 0x3c),
        Mark::NotReached => (0x88, 0x88, 0x88),
    };
    term.style_rgb(r, g, b)
}

fn component_detail(c: &PathComponent) -> String {
    match c.mark {
        Mark::NotReached => c.note.clone().unwrap_or_else(|| "not reached".into()),
        _ => {
            let mut parts: Vec<&str> = Vec::new();
            if let Some(ev) = &c.evidence {
                parts.push(ev.raw.as_str());
            }
            if let Some(n) = &c.note {
                parts.push(n.as_str());
            }
            parts.join("   ")
        }
    }
}

fn chain_lines(report: &Report, term: &TermCtx, verbose: bool) -> Vec<String> {
    let has_block = report
        .evidence_chain
        .iter()
        .any(|c| matches!(c.mark, Mark::Block));
    let visible: Vec<&PathComponent> = report
        .evidence_chain
        .iter()
        .filter(|c| verbose || !(has_block && matches!(c.mark, Mark::Pass)))
        .collect();
    if visible.is_empty() {
        return Vec::new();
    }
    let width = visible
        .iter()
        .map(|c| c.name.chars().count())
        .max()
        .unwrap_or(0)
        .min(40);
    visible
        .iter()
        .map(|c| {
            let mark = paint(term, mark_style(term, c.mark), mark_glyph(term, c.mark));
            let need = match c.mark {
                Mark::NotReached => "",
                _ => c.need.as_str(),
            };
            format!(
                "  {:<width$}  {} {}  {}",
                c.name,
                mark,
                need,
                component_detail(c)
            )
            .trim_end()
            .to_string()
        })
        .collect()
}

fn source_label(s: EvidenceSource) -> &'static str {
    match s {
        EvidenceSource::LsLd => "ls -ld",
        EvidenceSource::Getfacl => "getfacl",
        EvidenceSource::Lsattr => "lsattr",
        EvidenceSource::MountOpts => "mount",
        EvidenceSource::SelinuxLabel => "selinux",
        EvidenceSource::ApparmorStatus => "apparmor",
        EvidenceSource::AuditAvc => "audit",
        EvidenceSource::Statvfs => "statvfs",
        EvidenceSource::Capability => "getcap",
        EvidenceSource::Xattr => "xattr",
        EvidenceSource::Statflags => "stat",
    }
}

fn evidence_line(term: &TermCtx, ev: &Evidence) -> String {
    let tag = paint(
        term,
        term.style_rgb(0x88, 0x88, 0x88),
        source_label(ev.source),
    );
    format!("  {tag}  {}", ev.raw)
}

fn evidence_lines(report: &Report, term: &TermCtx) -> Vec<String> {
    let Some(id) = report.blocking_layer else {
        return Vec::new();
    };
    let Some(lr) = report.layer_results.iter().find(|r| r.layer == id) else {
        return Vec::new();
    };
    if lr.evidence.is_empty() {
        return Vec::new();
    }
    let mut out = vec![paint(term, term.style_rgb(0x88, 0x88, 0x88), &lr.summary)];
    out.extend(lr.evidence.iter().map(|ev| evidence_line(term, ev)));
    out
}

fn crosscheck_lines(report: &Report, term: &TermCtx) -> Vec<String> {
    let Some(cc) = &report.cross_check else {
        return Vec::new();
    };
    let msg = cc.message.clone().unwrap_or_else(|| default_crosscheck(cc));
    let style = match cc.agree {
        true => term.style_rgb(0x88, 0x88, 0x88),
        false => term.style_rgb(0xf1, 0xc4, 0x0f).bold(),
    };
    vec![paint(term, style, &format!("cross-check: {msg}"))]
}

fn default_crosscheck(cc: &CrossCheck) -> String {
    match cc.agree {
        true => "model and kernel concur".into(),
        false => "model and kernel disagree".into(),
    }
}

fn risk_word(r: Risk) -> &'static str {
    match r {
        Risk::Low => "low",
        Risk::Medium => "medium",
        Risk::High => "high",
    }
}

fn risk_style(term: &TermCtx, r: Risk) -> Style {
    let (rr, g, b) = match r {
        Risk::Low => (0x2e, 0xcc, 0x71),
        Risk::Medium => (0xf1, 0xc4, 0x0f),
        Risk::High => (0xe7, 0x4c, 0x3c),
    };
    term.style_rgb(rr, g, b)
}

fn fix_lines(report: &Report, term: &TermCtx) -> Vec<String> {
    if report.fixes.is_empty() {
        return Vec::new();
    }
    let arrow = term.glyph(Glyph::Arrow);
    report
        .fixes
        .iter()
        .flat_map(|f: &Fix| {
            let tag = paint(
                term,
                risk_style(term, f.risk),
                &format!("[risk: {}]", risk_word(f.risk)),
            );
            [
                format!("  {arrow} {}   {tag}", f.display()),
                format!("      {}", f.rationale),
            ]
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::op::Op;
    use crate::report::{
        Certainty, IdentityReport, LayerId, LayerResult, LayerStatus, NodeKind, RunningAs,
    };
    use crate::term::{ColorDepth, GlyphSet};

    fn plain_term() -> TermCtx {
        TermCtx {
            color: ColorDepth::None,
            glyphs: GlyphSet::Unicode,
            width: 80,
        }
    }

    fn blocked_traverse() -> Report {
        Report {
            schema_version: 1,
            tool: "whycant".into(),
            identity: IdentityReport {
                target_uid: 33,
                target_user: Some("www-data".into()),
                primary_gid: 33,
                groups: vec![33],
                group_names: vec!["www-data".into()],
                running_as: RunningAs::User,
                privilege_note: String::new(),
                target_is_self: false,
            },
            op: Op::Traverse,
            path: "/home/alice/secret.txt".into(),
            resolved_path: None,
            verdict: Verdict::Blocked,
            certainty: Certainty::Proven,
            culprit: Some("/home/alice not traversable by www-data".into()),
            blocking_layer: Some(LayerId::Traverse),
            evidence_chain: vec![
                PathComponent {
                    name: "/".into(),
                    kind: NodeKind::Dir,
                    mark: Mark::Pass,
                    need: "x".into(),
                    evidence: None,
                    note: None,
                    layer: Some(LayerId::Traverse),
                },
                PathComponent {
                    name: "home".into(),
                    kind: NodeKind::Dir,
                    mark: Mark::Pass,
                    need: "x".into(),
                    evidence: None,
                    note: None,
                    layer: Some(LayerId::Traverse),
                },
                PathComponent {
                    name: "alice".into(),
                    kind: NodeKind::Dir,
                    mark: Mark::Block,
                    need: "x".into(),
                    evidence: Some(Evidence {
                        source: EvidenceSource::LsLd,
                        raw: "drwx------ root root /home/alice".into(),
                        path: None,
                    }),
                    note: Some("www-data lacks traverse".into()),
                    layer: Some(LayerId::Traverse),
                },
                PathComponent {
                    name: "secret.txt".into(),
                    kind: NodeKind::File,
                    mark: Mark::NotReached,
                    need: "r".into(),
                    evidence: None,
                    note: None,
                    layer: None,
                },
            ],
            layer_results: vec![LayerResult {
                layer: LayerId::Traverse,
                status: LayerStatus::Block,
                certainty: Certainty::Proven,
                summary: "traverse denied at /home/alice".into(),
                evidence: vec![Evidence {
                    source: EvidenceSource::LsLd,
                    raw: "drwx------ 3 root root 4096 /home/alice".into(),
                    path: None,
                }],
            }],
            fixes: vec![Fix {
                argv: vec!["chmod".into(), "o+x".into(), "/home/alice".into()],
                needs_root: true,
                description: "grant traverse on the blocking directory".into(),
                risk: Risk::Low,
                rationale: "others need +x to descend into /home/alice".into(),
            }],
            cross_check: None,
            warnings: vec![],
        }
    }

    #[test]
    fn blocked_traverse_renders_verdict_and_fix() {
        let out = render_human(&blocked_traverse(), &plain_term(), false);
        assert!(out.contains("\u{2717} BLOCKED"), "verdict line: {out}");
        assert!(
            out.contains("chmod") && out.contains("o+x"),
            "fix present: {out}"
        );
        assert!(!out.contains('\u{1b}'), "no ansi under plain: {out}");
        assert!(out.contains("not reached"), "downstream marked: {out}");
    }
}
