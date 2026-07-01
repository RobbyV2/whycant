use crate::identity::Identity;
use crate::layers::*;
use crate::op::Op;
use crate::report::{self, Certainty, Evidence, Fix, IdentityReport, LayerId, Report, Verdict};
use std::path::Path;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LayerStatus {
    Pass,
    Block,
    Skip,
    Error,
}

pub struct LayerResult {
    pub status: LayerStatus,
    pub certainty: Certainty,
    pub evidence: Vec<Evidence>,
    pub fixes: Vec<Fix>,
    pub detail: String,
}

impl LayerResult {
    pub fn skip() -> Self {
        Self {
            status: LayerStatus::Skip,
            certainty: Certainty::Proven,
            evidence: Vec::new(),
            fixes: Vec::new(),
            detail: String::new(),
        }
    }
    pub fn pass(evidence: Vec<Evidence>) -> Self {
        Self {
            status: LayerStatus::Pass,
            certainty: Certainty::Proven,
            evidence,
            fixes: Vec::new(),
            detail: String::new(),
        }
    }
    pub fn block(
        certainty: Certainty,
        detail: impl Into<String>,
        evidence: Vec<Evidence>,
        fixes: Vec<Fix>,
    ) -> Self {
        Self {
            status: LayerStatus::Block,
            certainty,
            evidence,
            fixes,
            detail: detail.into(),
        }
    }
}

pub trait Layer: Sync {
    fn name(&self) -> &str;
    fn order(&self) -> u8;
    fn id(&self) -> LayerId;
    fn check(&self, target: &Identity, path: &Path, op: Op) -> LayerResult;
}

pub fn default_chain() -> Vec<Box<dyn Layer>> {
    vec![
        Box::new(ExistenceLayer),
        Box::new(TraverseLayer),
        Box::new(DacLayer),
        Box::new(AclLayer),
        Box::new(AttrLayer),
        Box::new(MountLayer),
        Box::new(CapsLayer),
        Box::new(MacLayer),
        Box::new(MacosLayer),
        Box::new(NetfsLayer),
        Box::new(ContainerLayer),
    ]
}

fn to_report_result(layer: LayerId, r: &LayerResult) -> report::LayerResult {
    let status = match r.status {
        LayerStatus::Pass => report::LayerStatus::Pass,
        LayerStatus::Block => report::LayerStatus::Block,
        LayerStatus::Skip => report::LayerStatus::Skip,
        LayerStatus::Error => report::LayerStatus::Unknown,
    };
    report::LayerResult {
        layer,
        status,
        certainty: r.certainty,
        summary: r.detail.clone(),
        evidence: r.evidence.clone(),
    }
}

fn base_report(op: Op, path: &Path, identity: IdentityReport) -> Report {
    Report {
        schema_version: 1,
        tool: "whycant".into(),
        identity,
        op,
        path: path.to_path_buf(),
        resolved_path: None,
        verdict: Verdict::Allowed,
        certainty: Certainty::Proven,
        culprit: None,
        blocking_layer: None,
        evidence_chain: Vec::new(),
        layer_results: Vec::new(),
        fixes: Vec::new(),
        cross_check: None,
        warnings: Vec::new(),
    }
}

pub fn run(chain: &[Box<dyn Layer>], id: &Identity, path: &Path, op: Op, all: bool) -> Report {
    let mut results = Vec::new();
    let mut warnings = Vec::new();
    let mut blocking: Option<(LayerId, Certainty, String, Vec<Fix>)> = None;

    for layer in chain {
        let r = layer.check(id, path, op);
        let lid = layer.id();
        match (r.status, layer.order()) {
            (LayerStatus::Error, 1) => {
                let mut rep = base_report(op, path, crate::identity::to_report(id));
                rep.verdict = Verdict::TargetError;
                rep.certainty = Certainty::Indeterminate;
                rep.culprit = Some(r.detail.clone());
                rep.blocking_layer = Some(lid);
                rep.layer_results.push(to_report_result(lid, &r));
                return rep;
            }
            (LayerStatus::Error, _) => {
                warnings.push(format!("{}: {}", layer.name(), r.detail));
            }
            (LayerStatus::Block, _) if blocking.is_none() => {
                blocking = Some((lid, r.certainty, r.detail.clone(), r.fixes.clone()));
            }
            _ => {}
        }
        let stop = r.status == LayerStatus::Block && r.certainty == Certainty::Proven && !all;
        results.push(to_report_result(lid, &r));
        if stop {
            break;
        }
    }

    let mut rep = base_report(op, path, crate::identity::to_report(id));
    rep.layer_results = results;
    rep.warnings = warnings;
    if let Some((lid, cert, detail, fixes)) = &blocking {
        rep.verdict = Verdict::Blocked;
        rep.certainty = *cert;
        rep.culprit = Some(detail.clone());
        rep.blocking_layer = Some(*lid);
        rep.fixes = fixes.clone();
    }

    let model_allows = rep.verdict == Verdict::Allowed;
    rep.cross_check = id
        .is_self
        .then(|| crate::access_check::cross_check(path, op, model_allows));
    rep
}
