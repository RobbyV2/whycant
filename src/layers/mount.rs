use crate::engine::{Layer, LayerResult};
use crate::identity::Identity;
use crate::op::Op;
use crate::report::LayerId;
use std::path::Path;

pub struct MountLayer;

impl Layer for MountLayer {
    fn name(&self) -> &str {
        "mount"
    }
    fn order(&self) -> u8 {
        6
    }
    fn id(&self) -> LayerId {
        LayerId::Mount
    }
    fn check(&self, _id: &Identity, _path: &Path, _op: Op) -> LayerResult {
        LayerResult::skip()
    }
}
