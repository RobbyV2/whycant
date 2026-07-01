use crate::op::Op;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

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

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Allowed,
    Blocked,
    Indeterminate,
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

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum LayerId {
    Existence,
    Traverse,
    Dac,
    Acl,
    Attrs,
    Mount,
    Capabilities,
    Mac,
    MacosSip,
    NetworkFs,
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

#[derive(Serialize, Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum LayerStatus {
    Pass,
    Block,
    Suspect,
    Skip,
    Unknown,
}

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
    AuditAvc,
    Statvfs,
    Capability,
    Xattr,
    Statflags,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FixAction {
    Run { argv: Vec<String> },
    Advice { text: String },
}

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

pub fn exit_code(report: &Report) -> i32 {
    match (report.verdict, report.certainty) {
        (Verdict::Allowed, _) => 0,
        (Verdict::Blocked, Certainty::Proven) => 1,
        (Verdict::Blocked, _) => 2,
        (Verdict::Indeterminate, _) => 2,
        (Verdict::TargetError, _) => 3,
    }
}
