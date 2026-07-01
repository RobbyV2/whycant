//! Ordered layer chain runner. Threads one `(identity, path, op)` through every
//! [`Layer`] in fixed order, short-circuits reporting at the first proven block,
//! folds per-layer certainty into a final verdict, and assembles the [`Report`].

use crate::identity::Identity;
use crate::layers::*;
use crate::op::Op;
use crate::report::{
    self, Certainty, Evidence, Fix, IdentityReport, LayerId, Mark, NodeKind, PathComponent, Report,
    Verdict,
};
use std::path::Path;

/// Per-layer outcome the runner acts on.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LayerStatus {
    /// Layer applies and permits the op; the walk continues.
    Pass,
    /// Layer denies the op; the reported verdict when earliest and proven.
    Block,
    /// Denial inferred without conclusive evidence; carries `Suspected`.
    Suspect,
    /// Layer inapplicable on this platform or path; ignored for the verdict.
    Skip,
    /// Layer-local read failure; recorded, and on layer 1 aborts to a target error.
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
    pub fn suspect(detail: impl Into<String>, evidence: Vec<Evidence>, fixes: Vec<Fix>) -> Self {
        Self {
            status: LayerStatus::Suspect,
            certainty: Certainty::Suspected,
            evidence,
            fixes,
            detail: detail.into(),
        }
    }
}

/// One access-control layer. Reads real filesystem state and evaluates it
/// against a target identity for one op.
pub trait Layer: Sync {
    /// Short human name used in output and warnings.
    fn name(&self) -> &str;
    /// Fixed position in the chain, 1 through 11.
    fn order(&self) -> u8;
    /// Serializable identifier of this layer.
    fn id(&self) -> LayerId;
    /// Evaluate `op` on `path` for `target`, returning the layer's result.
    fn check(&self, target: &Identity, path: &Path, op: Op) -> LayerResult;
}

/// Build the eleven-layer chain in fixed order.
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
        LayerStatus::Suspect => report::LayerStatus::Suspect,
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

struct Culprit {
    lid: LayerId,
    certainty: Certainty,
    detail: String,
    fixes: Vec<Fix>,
}

pub fn run(chain: &[Box<dyn Layer>], id: &Identity, path: &Path, op: Op, all: bool) -> Report {
    let mut results = Vec::new();
    let mut warnings = Vec::new();
    let mut proven: Option<Culprit> = None;
    let mut suspected: Option<Culprit> = None;
    let mut saw_suspect = false;

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
            (LayerStatus::Block, _) => {
                let slot = match r.certainty {
                    Certainty::Proven => &mut proven,
                    _ => &mut suspected,
                };
                if slot.is_none() {
                    *slot = Some(Culprit {
                        lid,
                        certainty: r.certainty,
                        detail: r.detail.clone(),
                        fixes: r.fixes.clone(),
                    });
                }
            }
            (LayerStatus::Suspect, _) => saw_suspect = true,
            _ => {}
        }
        let stop =
            matches!(r.status, LayerStatus::Block) && r.certainty == Certainty::Proven && !all;
        results.push(to_report_result(lid, &r));
        if stop {
            break;
        }
    }

    let mut rep = base_report(op, path, crate::identity::to_report(id));
    rep.layer_results = results;
    rep.warnings = warnings;
    match proven.or(suspected) {
        Some(c) => {
            rep.verdict = Verdict::Blocked;
            rep.certainty = c.certainty;
            rep.culprit = Some(c.detail);
            rep.blocking_layer = Some(c.lid);
            rep.fixes = c.fixes;
        }
        None if saw_suspect => {
            rep.verdict = Verdict::Indeterminate;
            rep.certainty = Certainty::Suspected;
        }
        None => {}
    }

    rep.evidence_chain = build_chain(id, path, op, &rep);

    let model_allows = rep.verdict == Verdict::Allowed;
    rep.cross_check = Some(match id.is_self {
        true => crate::access_check::cross_check(path, op, model_allows),
        false => crate::access_check::unavailable(id.uid, model_allows),
    });
    rep
}

fn build_chain(id: &Identity, path: &Path, op: Op, rep: &Report) -> Vec<PathComponent> {
    let subject = id.name.clone().unwrap_or_else(|| format!("uid {}", id.uid));
    let blocked_in_traverse = rep.blocking_layer == Some(LayerId::Traverse);
    let mut chain = Vec::new();
    if let Some(tr) = rep
        .layer_results
        .iter()
        .find(|r| r.layer == LayerId::Traverse)
    {
        let n = tr.evidence.len();
        for (i, ev) in tr.evidence.iter().enumerate() {
            let is_blocker = blocked_in_traverse
                && i + 1 == n
                && matches!(tr.status, report::LayerStatus::Block);
            chain.push(PathComponent {
                name: ev.path.as_deref().map(component_name).unwrap_or_default(),
                kind: NodeKind::Dir,
                mark: match is_blocker {
                    true => Mark::Block,
                    false => Mark::Pass,
                },
                need: "x".into(),
                evidence: Some(ev.clone()),
                note: is_blocker.then(|| format!("{subject} lacks traverse")),
                layer: Some(LayerId::Traverse),
            });
        }
    }
    let terminal_mark = match (blocked_in_traverse, rep.verdict) {
        (true, _) => Mark::NotReached,
        (_, Verdict::Blocked) => Mark::Block,
        _ => Mark::Pass,
    };
    let (note, layer) = match terminal_mark {
        Mark::Block => (rep.culprit.clone(), rep.blocking_layer),
        _ => (None, None),
    };
    chain.push(PathComponent {
        name: component_name(path),
        kind: terminal_kind(path),
        mark: terminal_mark,
        need: op_need(op).into(),
        evidence: None,
        note,
        layer,
    });
    chain
}

fn component_name(p: &Path) -> String {
    p.file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| p.display().to_string())
}

fn terminal_kind(p: &Path) -> NodeKind {
    match std::fs::symlink_metadata(p) {
        Err(_) => NodeKind::Missing,
        Ok(m) if m.file_type().is_symlink() => NodeKind::Symlink {
            target: std::fs::read_link(p).unwrap_or_default(),
        },
        Ok(m) if m.is_dir() => NodeKind::Dir,
        Ok(_) => NodeKind::File,
    }
}

fn op_need(op: Op) -> &'static str {
    match op {
        Op::Read => "r",
        Op::Write => "w",
        Op::Exec | Op::Traverse => "x",
        Op::Delete | Op::Create => "wx",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::exit_code;
    use std::path::PathBuf;

    enum Kind {
        Pass,
        ProvenBlock,
        Suspect,
    }

    struct Mock(LayerId, u8, Kind);

    impl Layer for Mock {
        fn name(&self) -> &str {
            "mock"
        }
        fn order(&self) -> u8 {
            self.1
        }
        fn id(&self) -> LayerId {
            self.0
        }
        fn check(&self, _id: &Identity, _p: &Path, _op: Op) -> LayerResult {
            match self.2 {
                Kind::Pass => LayerResult::pass(Vec::new()),
                Kind::ProvenBlock => {
                    LayerResult::block(Certainty::Proven, "blk", Vec::new(), Vec::new())
                }
                Kind::Suspect => LayerResult::suspect("susp", Vec::new(), Vec::new()),
            }
        }
    }

    fn ident() -> Identity {
        Identity {
            uid: 4242,
            primary_gid: 4242,
            groups: vec![4242],
            name: Some("t".into()),
            is_self: false,
        }
    }

    fn run_chain(kinds: Vec<(LayerId, u8, Kind)>) -> Report {
        let chain: Vec<Box<dyn Layer>> = kinds
            .into_iter()
            .map(|(id, ord, k)| Box::new(Mock(id, ord, k)) as Box<dyn Layer>)
            .collect();
        run(&chain, &ident(), &PathBuf::from("/"), Op::Read, false)
    }

    #[test]
    fn suspect_alone_is_indeterminate() {
        let rep = run_chain(vec![
            (LayerId::Dac, 3, Kind::Pass),
            (LayerId::Mac, 8, Kind::Suspect),
        ]);
        assert!(matches!(rep.verdict, Verdict::Indeterminate));
        assert!(rep.certainty == Certainty::Suspected);
        assert_eq!(exit_code(&rep), 2);
    }

    #[test]
    fn proven_block_precedes_suspect() {
        let rep = run_chain(vec![
            (LayerId::Mac, 8, Kind::Suspect),
            (LayerId::Dac, 3, Kind::ProvenBlock),
        ]);
        assert!(matches!(rep.verdict, Verdict::Blocked));
        assert!(rep.certainty == Certainty::Proven);
        assert_eq!(rep.blocking_layer, Some(LayerId::Dac));
        assert_eq!(exit_code(&rep), 1);
    }

    #[test]
    fn all_pass_is_allowed() {
        let rep = run_chain(vec![(LayerId::Dac, 3, Kind::Pass)]);
        assert!(matches!(rep.verdict, Verdict::Allowed));
        assert_eq!(exit_code(&rep), 0);
    }
}
