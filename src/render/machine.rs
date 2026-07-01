use crate::render::human::{render_report, Layout};
use crate::report::Report;
use crate::term::{ColorDepth, GlyphSet, TermCtx};
use anyhow::Result;

pub fn render_json(report: &Report) -> Result<String> {
    Ok(serde_json::to_string_pretty(report)?)
}

pub fn render_toml(report: &Report) -> Result<String> {
    Ok(toml::to_string_pretty(report)?)
}

pub fn render_plain(report: &Report, term: &TermCtx) -> String {
    let plain = TermCtx {
        color: ColorDepth::None,
        glyphs: GlyphSet::Ascii,
        width: term.width,
    };
    render_report(report, &plain, true, Layout::Plain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::op::Op;
    use crate::report::{
        Certainty, CrossCheck, Evidence, EvidenceSource, Fix, IdentityReport, LayerId, LayerResult,
        LayerStatus, Mark, NodeKind, PathComponent, Risk, RunningAs, Verdict,
    };

    fn plain_term() -> TermCtx {
        TermCtx {
            color: ColorDepth::None,
            glyphs: GlyphSet::Ascii,
            width: 80,
        }
    }

    fn sample() -> Report {
        Report {
            schema_version: 1,
            tool: "whycant".into(),
            identity: IdentityReport {
                target_uid: 1000,
                target_user: Some("alice".into()),
                primary_gid: 1000,
                groups: vec![1000, 27],
                group_names: vec!["alice".into(), "sudo".into()],
                running_as: RunningAs::User,
                privilege_note: "running as alice (uid 1000)".into(),
                target_is_self: true,
            },
            op: Op::Read,
            path: "/srv/secret/report.txt".into(),
            resolved_path: None,
            verdict: Verdict::Blocked,
            certainty: Certainty::Proven,
            culprit: Some("DAC denies read for alice: mode 0600".into()),
            blocking_layer: Some(LayerId::Dac),
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
                    name: "srv".into(),
                    kind: NodeKind::Dir,
                    mark: Mark::Pass,
                    need: "x".into(),
                    evidence: None,
                    note: None,
                    layer: Some(LayerId::Traverse),
                },
                PathComponent {
                    name: "secret".into(),
                    kind: NodeKind::Dir,
                    mark: Mark::Pass,
                    need: "x".into(),
                    evidence: None,
                    note: None,
                    layer: Some(LayerId::Traverse),
                },
                PathComponent {
                    name: "report.txt".into(),
                    kind: NodeKind::File,
                    mark: Mark::Block,
                    need: "r".into(),
                    evidence: None,
                    note: Some("class other lacks r".into()),
                    layer: Some(LayerId::Dac),
                },
            ],
            layer_results: vec![LayerResult {
                layer: LayerId::Dac,
                status: LayerStatus::Block,
                certainty: Certainty::Proven,
                summary: "DAC denies read".into(),
                evidence: vec![Evidence {
                    source: EvidenceSource::LsLd,
                    raw: "-rw------- 1 root root 1240 /srv/secret/report.txt".into(),
                    path: Some("/srv/secret/report.txt".into()),
                }],
            }],
            fixes: vec![Fix {
                argv: vec![
                    "setfacl".into(),
                    "-m".into(),
                    "u:alice:r".into(),
                    "/srv/secret/report.txt".into(),
                ],
                needs_root: true,
                description: "grant alice r via named-user ACL".into(),
                risk: Risk::Low,
                rationale: "owner, group, other unchanged".into(),
            }],
            cross_check: Some(CrossCheck {
                available: true,
                kernel_allows: Some(false),
                model_allows: false,
                agree: true,
                kernel_rwx: Some([false, false, false]),
                message: None,
            }),
            warnings: vec!["audit log unreadable, re-run with sudo".into()],
        }
    }

    #[test]
    fn json_toml_describe_identical_data() {
        let r = sample();
        let j = render_json(&r).unwrap();
        let t = render_toml(&r).unwrap();
        let from_json: Report = serde_json::from_str(&j).unwrap();
        let from_toml: Report = toml::from_str(&t).unwrap();
        assert_eq!(j, serde_json::to_string_pretty(&from_json).unwrap());
        assert_eq!(j, serde_json::to_string_pretty(&from_toml).unwrap());
    }

    #[test]
    fn schema_version_in_both_formats() {
        let r = sample();
        assert!(render_json(&r).unwrap().contains("\"schema_version\": 1"));
        assert!(render_toml(&r).unwrap().contains("schema_version = 1"));
    }

    #[test]
    fn toml_file_round_trip() {
        let r = sample();
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("report.toml");
        std::fs::write(&p, render_toml(&r).unwrap()).unwrap();
        let back: Report = toml::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        assert_eq!(
            render_json(&r).unwrap(),
            render_json(&back).unwrap(),
            "toml file round-trips to identical json"
        );
    }

    #[test]
    fn plain_is_greppable_and_bare() {
        let out = render_plain(&sample(), &plain_term());
        assert!(!out.contains('\u{1b}'), "no ansi: {out}");
        assert!(out.is_ascii(), "no unicode glyphs: {out}");
        assert!(!out.contains("\n\n"), "no blank separators: {out}");
        let first = out.lines().next().unwrap();
        assert!(
            first.starts_with("verdict blocked read /srv/secret/report.txt"),
            "{first}"
        );
        assert!(out.lines().any(|l| l.starts_with("culprit ")));
        assert!(out.lines().any(|l| l.starts_with("chain ")));
        assert!(out.lines().any(|l| l.starts_with("evidence dac ls_ld ")));
        assert!(out.lines().any(|l| l.starts_with("crosscheck agree ")));
        assert!(out.lines().any(|l| l.starts_with("fix low ")));
        assert!(out.lines().any(|l| l.starts_with("fix-note ")));
        for l in out.lines() {
            assert!(!l.starts_with(' '), "fixed leading token, no indent: {l}");
        }
    }

    #[test]
    fn plain_snapshot() {
        insta::assert_snapshot!(render_plain(&sample(), &plain_term()));
    }
}
