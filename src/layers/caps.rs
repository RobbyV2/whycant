use crate::engine::{Layer, LayerResult};
use crate::identity::Identity;
use crate::op::Op;
use crate::report::LayerId;
use std::path::Path;

pub struct CapsLayer;

impl Layer for CapsLayer {
    fn name(&self) -> &str {
        "caps"
    }
    fn order(&self) -> u8 {
        7
    }
    fn id(&self) -> LayerId {
        LayerId::Capabilities
    }
    fn check(&self, _id: &Identity, _path: &Path, _op: Op) -> LayerResult {
        LayerResult::skip()
    }
}
