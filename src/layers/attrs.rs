use crate::engine::{Layer, LayerResult};
use crate::identity::Identity;
use crate::op::Op;
use crate::report::LayerId;
use std::path::Path;

pub struct AttrLayer;

impl Layer for AttrLayer {
    fn name(&self) -> &str {
        "attrs"
    }
    fn order(&self) -> u8 {
        5
    }
    fn id(&self) -> LayerId {
        LayerId::Attrs
    }
    fn check(&self, _id: &Identity, _path: &Path, _op: Op) -> LayerResult {
        LayerResult::skip()
    }
}
