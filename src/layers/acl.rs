use crate::engine::{Layer, LayerResult};
use crate::identity::Identity;
use crate::op::Op;
use crate::report::LayerId;
use std::path::Path;

pub struct AclLayer;

impl Layer for AclLayer {
    fn name(&self) -> &str {
        "acl"
    }
    fn order(&self) -> u8 {
        4
    }
    fn id(&self) -> LayerId {
        LayerId::Acl
    }
    fn check(&self, _id: &Identity, _path: &Path, _op: Op) -> LayerResult {
        LayerResult::skip()
    }
}
