use crate::engine::{Layer, LayerResult};
use crate::identity::Identity;
use crate::op::Op;
use crate::report::LayerId;
use std::path::Path;

pub struct NetfsLayer;

impl Layer for NetfsLayer {
    fn name(&self) -> &str {
        "netfs"
    }
    fn order(&self) -> u8 {
        10
    }
    fn id(&self) -> LayerId {
        LayerId::NetworkFs
    }
    fn check(&self, _id: &Identity, _path: &Path, _op: Op) -> LayerResult {
        LayerResult::skip()
    }
}
