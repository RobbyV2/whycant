use crate::engine::{Layer, LayerResult};
use crate::identity::Identity;
use crate::op::Op;
use crate::report::LayerId;
use std::path::Path;

pub struct MacLayer;

impl Layer for MacLayer {
    fn name(&self) -> &str {
        "mac"
    }
    fn order(&self) -> u8 {
        8
    }
    fn id(&self) -> LayerId {
        LayerId::Mac
    }
    fn check(&self, _id: &Identity, _path: &Path, _op: Op) -> LayerResult {
        LayerResult::skip()
    }
}
