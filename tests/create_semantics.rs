use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use whycant::engine::{self, default_chain};
use whycant::identity::Identity;
use whycant::op::Op;
use whycant::report::{LayerId, Verdict, exit_code};

fn owner_of(p: &Path) -> Identity {
    let m = fs::metadata(p).unwrap();
    Identity {
        uid: m.uid(),
        primary_gid: m.gid(),
        groups: vec![m.gid()],
        name: None,
        is_self: false,
    }
}

#[test]
fn create_in_writable_owned_dir_is_allowed() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("newfile");
    let chain = default_chain();
    let rep = engine::run(&chain, &owner_of(dir.path()), &target, Op::Create, false);
    assert!(
        matches!(rep.verdict, Verdict::Allowed),
        "expected allowed, culprit {:?}",
        rep.culprit
    );
    assert_eq!(exit_code(&rep), 0);
}

#[test]
fn create_lacking_parent_write_is_dac_block() {
    if rustix::process::geteuid().is_root() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let parent = dir.path().join("box");
    fs::create_dir(&parent).unwrap();
    let target = parent.join("newfile");
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o555)).unwrap();
    let chain = default_chain();
    let rep = engine::run(&chain, &owner_of(dir.path()), &target, Op::Create, false);
    assert!(
        matches!(rep.verdict, Verdict::Blocked),
        "culprit {:?}",
        rep.culprit
    );
    assert_eq!(rep.blocking_layer, Some(LayerId::Dac));
}

#[test]
fn create_missing_parent_is_target_error() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("absent").join("child");
    let chain = default_chain();
    let rep = engine::run(&chain, &owner_of(dir.path()), &target, Op::Create, false);
    assert!(matches!(rep.verdict, Verdict::TargetError));
    assert_eq!(exit_code(&rep), 3);
}

#[test]
fn delete_missing_target_is_target_error() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("gone");
    let chain = default_chain();
    let rep = engine::run(&chain, &owner_of(dir.path()), &target, Op::Delete, false);
    assert!(matches!(rep.verdict, Verdict::TargetError));
    assert_eq!(exit_code(&rep), 3);
}
