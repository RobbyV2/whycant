#![cfg(feature = "root-tests")]

use std::path::Path;
use std::process::Command;
use whycant::engine::{Layer, LayerStatus};
use whycant::identity::Identity;
use whycant::layers::{AttrLayer, DacLayer};
use whycant::op::Op;
use whycant::report::{Certainty, FixAction};

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn skip(name: &str) -> bool {
    match is_root() {
        true => false,
        false => {
            eprintln!("root_integration::{name}: skipping; needs root");
            true
        }
    }
}

fn run(cmd: &str, args: &[&str]) {
    let ok = Command::new(cmd)
        .args(args)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(ok, "{cmd} {args:?} failed");
}

fn ident(uid: u32, gid: u32) -> Identity {
    Identity {
        uid,
        primary_gid: gid,
        groups: vec![gid],
        name: None,
        is_self: false,
    }
}

fn s(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

#[test]
fn immutable_reports_proven_block() {
    if skip("immutable_reports_proven_block") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("locked");
    std::fs::write(&f, b"x").unwrap();
    run("chattr", &["+i", &s(&f)]);
    let r = AttrLayer.check(&ident(0, 0), &f, Op::Write);
    run("chattr", &["-i", &s(&f)]);
    assert!(matches!(r.status, LayerStatus::Block));
    assert!(r.certainty == Certainty::Proven);
    assert!(r.fixes.iter().any(|x| match &x.action {
        FixAction::Run { argv } => argv.first().map(String::as_str) == Some("chattr"),
        FixAction::Advice { text: _ } => false,
    }));
}

#[cfg(feature = "acl")]
#[test]
fn acl_named_user_denial_is_fingered() {
    use whycant::layers::AclLayer;
    if skip("acl_named_user_denial_is_fingered") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("guarded");
    std::fs::write(&f, b"x").unwrap();
    if Command::new("setfacl")
        .args(["-m", "u:12345:r", &s(&f)])
        .status()
        .map(|st| st.success())
        .unwrap_or(false)
    {
        let r = AclLayer.check(&ident(12345, 65534), &f, Op::Write);
        assert!(matches!(r.status, LayerStatus::Block));
        assert!(r.certainty == Certainty::Proven);
        assert!(r.evidence.iter().any(|e| e.raw.contains("user:12345")));
    } else {
        eprintln!("acl_named_user_denial_is_fingered: setfacl unavailable; skipping");
    }
}

#[test]
fn dac_ownership_denies_foreign_user() {
    if skip("dac_ownership_denies_foreign_user") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("owned");
    std::fs::write(&f, b"x").unwrap();
    run("chmod", &["0600", &s(&f)]);
    run("chown", &["12345:12345", &s(&f)]);
    let r = DacLayer.check(&ident(65534, 65534), &f, Op::Read);
    assert!(matches!(r.status, LayerStatus::Block));
    assert!(r.certainty == Certainty::Proven);
}
