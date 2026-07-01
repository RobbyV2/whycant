use whycant::op::Op;
use whycant::render::human::render_human;
use whycant::render::machine::{render_json, render_plain, render_toml};
use whycant::report::*;
use whycant::term::{ColorDepth, GlyphSet, TermCtx};

fn term(color: ColorDepth, glyphs: GlyphSet) -> TermCtx {
    ctx(color, glyphs, false)
}

fn ctx(color: ColorDepth, glyphs: GlyphSet, hyperlinks: bool) -> TermCtx {
    TermCtx {
        color,
        glyphs,
        hyperlinks,
        width: 80,
    }
}

fn perms() -> [(&'static str, TermCtx); 5] {
    [
        ("nocolor", ctx(ColorDepth::None, GlyphSet::Unicode, false)),
        (
            "color",
            ctx(ColorDepth::TrueColor, GlyphSet::Unicode, false),
        ),
        (
            "hyperlink",
            ctx(ColorDepth::TrueColor, GlyphSet::Unicode, true),
        ),
        ("dumb", ctx(ColorDepth::None, GlyphSet::Ascii, false)),
        ("piped", ctx(ColorDepth::None, GlyphSet::Unicode, false)),
    ]
}

fn ev(source: EvidenceSource, raw: &str, path: Option<&str>) -> Evidence {
    Evidence {
        source,
        raw: raw.into(),
        path: path.map(Into::into),
    }
}

fn comp(
    name: &str,
    kind: NodeKind,
    mark: Mark,
    need: &str,
    evidence: Option<Evidence>,
    note: Option<&str>,
    layer: Option<LayerId>,
) -> PathComponent {
    PathComponent {
        name: name.into(),
        kind,
        mark,
        need: need.into(),
        evidence,
        note: note.map(Into::into),
        layer,
    }
}

fn ident(
    uid: u32,
    user: &str,
    gid: u32,
    groups: Vec<u32>,
    names: &[&str],
    is_self: bool,
) -> IdentityReport {
    IdentityReport {
        target_uid: uid,
        target_user: Some(user.into()),
        primary_gid: gid,
        groups,
        group_names: names.iter().map(|s| (*s).into()).collect(),
        running_as: RunningAs::User,
        privilege_note: format!(
            "running as {user} (uid {uid}); MAC denial confirmation needs sudo"
        ),
        target_is_self: is_self,
    }
}

fn lr(layer: LayerId, status: LayerStatus, summary: &str, evidence: Vec<Evidence>) -> LayerResult {
    LayerResult {
        layer,
        status,
        certainty: Certainty::Proven,
        summary: summary.into(),
        evidence,
    }
}

fn fix(argv: &[&str], root: bool, desc: &str, risk: Risk, rationale: &str) -> Fix {
    Fix {
        action: FixAction::Run {
            argv: argv.iter().map(|s| (*s).into()).collect(),
        },
        needs_root: root,
        description: desc.into(),
        risk,
        rationale: rationale.into(),
    }
}

fn blocked_traverse() -> Report {
    Report {
        schema_version: 1,
        tool: "whycant".into(),
        identity: ident(1000, "alice", 1000, vec![1000], &["alice"], false),
        op: Op::Traverse,
        path: "/srv/data/report.txt".into(),
        resolved_path: None,
        verdict: Verdict::Blocked,
        certainty: Certainty::Proven,
        culprit: Some("/srv/data not traversable by alice".into()),
        blocking_layer: Some(LayerId::Traverse),
        evidence_chain: vec![
            comp(
                "/",
                NodeKind::Dir,
                Mark::Pass,
                "x",
                None,
                None,
                Some(LayerId::Traverse),
            ),
            comp(
                "srv",
                NodeKind::Dir,
                Mark::Pass,
                "x",
                None,
                None,
                Some(LayerId::Traverse),
            ),
            comp(
                "data",
                NodeKind::Dir,
                Mark::Block,
                "x",
                Some(ev(
                    EvidenceSource::LsLd,
                    "drwxr-x--- 4 root staff 4096 /srv/data",
                    Some("/srv/data"),
                )),
                Some("others lack x; alice is not owner or in group staff"),
                Some(LayerId::Traverse),
            ),
            comp(
                "report.txt",
                NodeKind::File,
                Mark::NotReached,
                "r",
                None,
                None,
                None,
            ),
        ],
        layer_results: vec![lr(
            LayerId::Traverse,
            LayerStatus::Block,
            "traverse denied at /srv/data",
            vec![ev(
                EvidenceSource::LsLd,
                "drwxr-x--- 4 root staff 4096 /srv/data",
                Some("/srv/data"),
            )],
        )],
        fixes: vec![fix(
            &["chmod", "o+x", "/srv/data"],
            true,
            "grant others traverse on the blocking directory",
            Risk::Low,
            "others need +x to descend into /srv/data toward report.txt",
        )],
        cross_check: None,
        warnings: vec![],
    }
}

fn acl_denied() -> Report {
    Report {
        schema_version: 1,
        tool: "whycant".into(),
        identity: ident(33, "www-data", 33, vec![33], &["www-data"], false),
        op: Op::Read,
        path: "/srv/share/config.yaml".into(),
        resolved_path: None,
        verdict: Verdict::Blocked,
        certainty: Certainty::Proven,
        culprit: Some("ACL mask clips www-data to no access on config.yaml".into()),
        blocking_layer: Some(LayerId::Acl),
        evidence_chain: vec![
            comp(
                "/",
                NodeKind::Dir,
                Mark::Pass,
                "x",
                None,
                None,
                Some(LayerId::Traverse),
            ),
            comp(
                "srv",
                NodeKind::Dir,
                Mark::Pass,
                "x",
                None,
                None,
                Some(LayerId::Traverse),
            ),
            comp(
                "share",
                NodeKind::Dir,
                Mark::Pass,
                "x",
                None,
                None,
                Some(LayerId::Traverse),
            ),
            comp(
                "config.yaml",
                NodeKind::File,
                Mark::Block,
                "r",
                Some(ev(
                    EvidenceSource::Getfacl,
                    "user:www-data:r--  #effective:---",
                    Some("/srv/share/config.yaml"),
                )),
                Some("mask::--- clips the named-user entry to no effective access"),
                Some(LayerId::Acl),
            ),
        ],
        layer_results: vec![lr(
            LayerId::Acl,
            LayerStatus::Block,
            "ACL denies read: named-user entry masked to none",
            vec![
                ev(
                    EvidenceSource::Getfacl,
                    "user:www-data:r--  #effective:---",
                    Some("/srv/share/config.yaml"),
                ),
                ev(
                    EvidenceSource::Getfacl,
                    "mask::---",
                    Some("/srv/share/config.yaml"),
                ),
            ],
        )],
        fixes: vec![fix(
            &["setfacl", "-m", "m::rx", "/srv/share/config.yaml"],
            true,
            "extend the ACL mask so the existing named-user entry takes effect",
            Risk::Low,
            "u:www-data:r-- is already present; only the mask is clipping it",
        )],
        cross_check: None,
        warnings: vec![
            "check for a default ACL on the parent that could re-clip after edits".into(),
        ],
    }
}

fn allowed_concur() -> Report {
    Report {
        schema_version: 1,
        tool: "whycant".into(),
        identity: ident(1000, "alice", 1000, vec![1000, 4], &["alice", "adm"], true),
        op: Op::Read,
        path: "/home/alice/notes.txt".into(),
        resolved_path: None,
        verdict: Verdict::Allowed,
        certainty: Certainty::Proven,
        culprit: None,
        blocking_layer: None,
        evidence_chain: vec![
            comp(
                "/",
                NodeKind::Dir,
                Mark::Pass,
                "x",
                None,
                None,
                Some(LayerId::Traverse),
            ),
            comp(
                "home",
                NodeKind::Dir,
                Mark::Pass,
                "x",
                None,
                None,
                Some(LayerId::Traverse),
            ),
            comp(
                "alice",
                NodeKind::Dir,
                Mark::Pass,
                "x",
                None,
                None,
                Some(LayerId::Traverse),
            ),
            comp(
                "notes.txt",
                NodeKind::File,
                Mark::Pass,
                "r",
                Some(ev(
                    EvidenceSource::LsLd,
                    "-rw-r--r-- 1 alice alice 220 /home/alice/notes.txt",
                    Some("/home/alice/notes.txt"),
                )),
                None,
                Some(LayerId::Dac),
            ),
        ],
        layer_results: vec![
            lr(
                LayerId::Traverse,
                LayerStatus::Pass,
                "all ancestors traversable by alice",
                vec![],
            ),
            lr(
                LayerId::Dac,
                LayerStatus::Pass,
                "DAC allows read: mode 0644, world-readable",
                vec![ev(
                    EvidenceSource::LsLd,
                    "-rw-r--r-- 1 alice alice 220 /home/alice/notes.txt",
                    Some("/home/alice/notes.txt"),
                )],
            ),
        ],
        fixes: vec![],
        cross_check: Some(CrossCheck {
            available: true,
            kernel_allows: Some(true),
            model_allows: true,
            agree: true,
            kernel_rwx: Some([true, false, false]),
            message: None,
        }),
        warnings: vec![],
    }
}

fn target_error() -> Report {
    Report {
        schema_version: 1,
        tool: "whycant".into(),
        identity: ident(1000, "alice", 1000, vec![1000], &["alice"], false),
        op: Op::Read,
        path: "/srv/data/missing.txt".into(),
        resolved_path: None,
        verdict: Verdict::TargetError,
        certainty: Certainty::Proven,
        culprit: Some("/srv/data/missing.txt does not exist (ENOENT)".into()),
        blocking_layer: Some(LayerId::Existence),
        evidence_chain: vec![
            comp(
                "/",
                NodeKind::Dir,
                Mark::Pass,
                "x",
                None,
                None,
                Some(LayerId::Traverse),
            ),
            comp(
                "srv",
                NodeKind::Dir,
                Mark::Pass,
                "x",
                None,
                None,
                Some(LayerId::Traverse),
            ),
            comp(
                "data",
                NodeKind::Dir,
                Mark::Pass,
                "x",
                None,
                None,
                Some(LayerId::Traverse),
            ),
            comp(
                "missing.txt",
                NodeKind::Missing,
                Mark::Block,
                "r",
                None,
                Some("no such file or directory"),
                Some(LayerId::Existence),
            ),
        ],
        layer_results: vec![lr(
            LayerId::Existence,
            LayerStatus::Block,
            "target does not exist: ENOENT",
            vec![ev(
                EvidenceSource::LsLd,
                "stat: cannot stat '/srv/data/missing.txt': No such file or directory",
                Some("/srv/data/missing.txt"),
            )],
        )],
        fixes: vec![],
        cross_check: None,
        warnings: vec![],
    }
}

fn render_and_snap(prefix: &str, r: &Report) {
    for (pname, t) in perms() {
        insta::assert_snapshot!(
            format!("{prefix}__human__{pname}"),
            render_human(r, &t, true)
        );
    }
    let plain = render_plain(r, &term(ColorDepth::None, GlyphSet::Unicode));
    let json = render_json(r).unwrap();
    let toml = render_toml(r).unwrap();
    assert!(
        json.contains("\"schema_version\": 1"),
        "json carries schema_version"
    );
    assert!(
        toml.contains("schema_version = 1"),
        "toml carries schema_version"
    );
    assert!(
        !plain.contains('\u{1b}'),
        "plain has no ansi escapes: {plain}"
    );
    assert!(plain.is_ascii(), "plain is ascii only: {plain}");
    insta::assert_snapshot!(format!("{prefix}__plain"), plain);
    insta::assert_snapshot!(format!("{prefix}__json"), json);
    insta::assert_snapshot!(format!("{prefix}__toml"), toml);
}

#[test]
fn fixture_blocked_traverse() {
    let r = blocked_traverse();
    render_and_snap("blocked_traverse", &r);
    let unicode = render_human(&r, &term(ColorDepth::None, GlyphSet::Unicode), true);
    assert!(
        unicode.contains('\u{2717}') && unicode.contains("BLOCKED"),
        "unicode culprit mark: {unicode}"
    );
    assert!(
        unicode.contains("chmod") && unicode.contains("o+x"),
        "fix shown: {unicode}"
    );
    let dumb = render_human(&r, &term(ColorDepth::None, GlyphSet::Ascii), true);
    assert!(dumb.contains("x BLOCKED"), "ascii culprit mark: {dumb}");
    assert!(dumb.is_ascii(), "dumb output ascii only: {dumb}");
    let plain = render_plain(&r, &term(ColorDepth::None, GlyphSet::Unicode));
    assert!(
        plain.contains("culprit /srv/data not traversable by alice"),
        "plain culprit: {plain}"
    );
    assert!(
        plain.contains("fix low run sudo chmod 'o+x' /srv/data"),
        "plain fix: {plain}"
    );
}

#[test]
fn fixture_acl_denied() {
    let r = acl_denied();
    render_and_snap("acl_denied", &r);
    let unicode = render_human(&r, &term(ColorDepth::None, GlyphSet::Unicode), true);
    assert!(
        unicode.contains('\u{2717}') && unicode.contains("BLOCKED"),
        "unicode culprit mark: {unicode}"
    );
    assert!(
        unicode.contains("setfacl") && unicode.contains("mask"),
        "fix shown: {unicode}"
    );
    let dumb = render_human(&r, &term(ColorDepth::None, GlyphSet::Ascii), true);
    assert!(dumb.contains("x BLOCKED"), "ascii culprit mark: {dumb}");
    let plain = render_plain(&r, &term(ColorDepth::None, GlyphSet::Ascii));
    assert!(
        plain.contains("fix low run sudo setfacl -m m::rx /srv/share/config.yaml"),
        "plain fix: {plain}"
    );
    assert!(
        plain.contains("evidence acl getfacl "),
        "plain evidence: {plain}"
    );
}

#[test]
fn fixture_allowed_concur() {
    let r = allowed_concur();
    render_and_snap("allowed_concur", &r);
    let unicode = render_human(&r, &term(ColorDepth::None, GlyphSet::Unicode), true);
    assert!(
        unicode.contains('\u{2713}') && unicode.contains("ALLOWED"),
        "allowed mark: {unicode}"
    );
    assert!(
        unicode.contains("model and kernel concur"),
        "crosscheck concur: {unicode}"
    );
    let plain = render_plain(&r, &term(ColorDepth::None, GlyphSet::Unicode));
    assert!(
        plain.starts_with("verdict allowed read /home/alice/notes.txt"),
        "plain verdict: {plain}"
    );
    assert!(
        plain.contains("crosscheck agree "),
        "plain crosscheck: {plain}"
    );
    assert!(!plain.contains("fix "), "allowed has no fix: {plain}");
}

#[test]
fn fixture_target_error() {
    let r = target_error();
    render_and_snap("target_error", &r);
    let unicode = render_human(&r, &term(ColorDepth::None, GlyphSet::Unicode), true);
    assert!(
        unicode.contains('\u{26a0}') && unicode.contains("TARGET ERROR"),
        "target error mark: {unicode}"
    );
    let dumb = render_human(&r, &term(ColorDepth::None, GlyphSet::Ascii), true);
    assert!(
        dumb.contains("! TARGET ERROR"),
        "ascii target error mark: {dumb}"
    );
    let plain = render_plain(&r, &term(ColorDepth::None, GlyphSet::Unicode));
    assert!(
        plain.starts_with("verdict target_error read /srv/data/missing.txt"),
        "plain verdict: {plain}"
    );
    assert!(
        plain.contains("culprit /srv/data/missing.txt does not exist"),
        "plain culprit: {plain}"
    );
    assert!(!plain.contains("fix "), "target error has no fix: {plain}");
}
