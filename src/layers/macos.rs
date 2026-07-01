use crate::engine::{Layer, LayerResult};
use crate::identity::Identity;
use crate::op::Op;
use crate::report::LayerId;
use std::path::Path;

pub struct MacosLayer;

impl Layer for MacosLayer {
    fn name(&self) -> &str {
        "macos"
    }
    fn order(&self) -> u8 {
        9
    }
    fn id(&self) -> LayerId {
        LayerId::MacosSip
    }
    fn check(&self, _id: &Identity, _path: &Path, _op: Op) -> LayerResult {
        LayerResult::skip()
    }
}
