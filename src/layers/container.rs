use crate::engine::{Layer, LayerResult};
use crate::identity::Identity;
use crate::op::Op;
use crate::report::LayerId;
use std::path::Path;

pub struct ContainerLayer;

impl Layer for ContainerLayer {
    fn name(&self) -> &str {
        "container"
    }
    fn order(&self) -> u8 {
        11
    }
    fn id(&self) -> LayerId {
        LayerId::Container
    }
    fn check(&self, _id: &Identity, _path: &Path, _op: Op) -> LayerResult {
        LayerResult::skip()
    }
}
