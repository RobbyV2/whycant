//! Serializable report model. One [`Report`] drives every output format, so
//! JSON, TOML, plain, and human renderings cannot drift. Also holds the
//! verdict, certainty, layer, evidence, and fix types, and the exit-code map.

use crate::op::Op;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Full diagnosis of one operation: verdict, per-layer results, evidence chain,
/// and ordered fixes. Serializes identically across formats.
#[derive(Serialize, Deserialize)]
pub struct Report {
    pub schema_version: u32,
    pub tool: String,
    pub identity: IdentityReport,
    pub op: Op,
    pub path: PathBuf,
    pub resolved_path: Option<PathBuf>,
    pub verdict: Verdict,
    pub certainty: Certainty,
    pub culprit: Option<String>,
    pub blocking_layer: Option<LayerId>,
    pub evidence_chain: Vec<PathComponent>,
    pub layer_results: Vec<LayerResult>,
    pub fixes: Vec<Fix>,
    pub cross_check: Option<CrossCheck>,
    pub warnings: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct IdentityReport {
    pub target_uid: u32,
    pub target_user: Option<String>,
    pub primary_gid: u32,
    pub groups: Vec<u32>,
    pub group_names: Vec<String>,
    pub running_as: RunningAs,
    pub privilege_note: String,
    pub target_is_self: bool,
}

#[derive(Serialize, Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum RunningAs {
    Root,
    User,
    SudoElevated,
}

/// Final outcome of the chain for the requested op.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// No layer blocks the op.
    Allowed,
    /// A layer denies the op.
    Blocked,
    /// A denial is suspected but cannot be confirmed unprivileged.
    Indeterminate,
    /// The target itself is unresolvable (ENOENT, not a file, broken symlink).
    TargetError,
}

impl Verdict {
    pub fn word(self) -> &'static str {
        match self {
            Self::Allowed => "ALLOWED",
            Self::Blocked => "BLOCKED",
            Self::Indeterminate => "INDETERMINATE",
            Self::TargetError => "TARGET ERROR",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Certainty {
    Proven,
    Suspected,
    Indeterminate,
}

/// Stable identifier for each of the eleven layers, in chain order.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum LayerId {
    /// Symlink resolution; ENOENT versus EACCES-masked-ENOENT; broken links.
    Existence,
    /// Per-ancestor traverse (`x`) for the identity.
    Traverse,
    /// Owner/group/other mode bits, sticky, setuid/setgid.
    Dac,
    /// POSIX or NFSv4 access-control list evaluation.
    Acl,
    /// Immutable and append-only file attributes.
    Attrs,
    /// Read-only and noexec mount flags.
    Mount,
    /// Process and file capabilities.
    Capabilities,
    /// SELinux, AppArmor, SMACK/TOMOYO mandatory access control.
    Mac,
    /// macOS SIP, quarantine, read-only system volume, TCC.
    MacosSip,
    /// NFS/CIFS root_squash, ro-export, uid mismatch; always suspected.
    NetworkFs,
    /// Container and user-namespace context (uid_map, dropped caps, seccomp).
    Container,
}

#[derive(Serialize, Deserialize)]
pub struct PathComponent {
    pub name: String,
    pub kind: NodeKind,
    pub mark: Mark,
    pub need: String,
    pub evidence: Option<Evidence>,
    pub note: Option<String>,
    pub layer: Option<LayerId>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Dir,
    File,
    Symlink { target: PathBuf },
    Missing,
}

#[derive(Serialize, Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum Mark {
    Pass,
    Block,
    NotReached,
}

#[derive(Serialize, Deserialize)]
pub struct LayerResult {
    pub layer: LayerId,
    pub status: LayerStatus,
    pub certainty: Certainty,
    pub summary: String,
    pub evidence: Vec<Evidence>,
}

/// Serialized per-layer status. The internal [`crate::engine::LayerStatus`]
/// `Error` maps to `Unknown` here.
#[derive(Serialize, Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum LayerStatus {
    /// Layer applies and permits the op.
    Pass,
    /// Layer denies the op.
    Block,
    /// Denial inferred without conclusive evidence.
    Suspect,
    /// Layer inapplicable on this platform or path.
    Skip,
    /// Layer could not decide unprivileged; drives `Indeterminate`.
    Unknown,
}

/// One raw line of proof behind a verdict, quoted verbatim so the user can
/// eyeball-verify it (an `ls -ld` line, a `getfacl` entry, mount options).
#[derive(Serialize, Deserialize, Clone)]
pub struct Evidence {
    pub source: EvidenceSource,
    pub raw: String,
    pub path: Option<PathBuf>,
}

#[derive(Serialize, Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    LsLd,
    Getfacl,
    Lsattr,
    MountOpts,
    SelinuxLabel,
    ApparmorStatus,
    MacStatus,
    AuditAvc,
    Statvfs,
    Capability,
    FileCap,
    Namespace,
    Xattr,
    Statflags,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FixAction {
    Run { argv: Vec<String> },
    Advice { text: String },
}

/// A least-privilege remedy for one blocking layer. Either a runnable argv or
/// non-executable advice, tagged with privilege, risk, and rationale.
#[derive(Serialize, Deserialize, Clone)]
pub struct Fix {
    pub action: FixAction,
    pub needs_root: bool,
    pub description: String,
    pub risk: Risk,
    pub rationale: String,
}

#[derive(Serialize, Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum Risk {
    Low,
    Medium,
    High,
}

impl Risk {
    pub fn word(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
    pub fn rank(self) -> u8 {
        match self {
            Self::Low => 0,
            Self::Medium => 1,
            Self::High => 2,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CrossCheck {
    pub available: bool,
    pub kernel_allows: Option<bool>,
    pub model_allows: bool,
    pub agree: bool,
    pub kernel_rwx: Option<[bool; 3]>,
    pub message: Option<String>,
}

/// Map a report to its process exit code: 0 allowed, 1 blocked and proven,
/// 2 blocked but indeterminate, 3 target error.
pub fn exit_code(report: &Report) -> i32 {
    match (report.verdict, report.certainty) {
        (Verdict::Allowed, _) => 0,
        (Verdict::Blocked, Certainty::Proven) => 1,
        (Verdict::Blocked, _) => 2,
        (Verdict::Indeterminate, _) => 2,
        (Verdict::TargetError, _) => 3,
    }
}
