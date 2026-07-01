//! The eleven access-control layers. Each is a struct implementing
//! [`crate::engine::Layer`]; platform-specific mechanisms live inside each
//! layer's check and fall through to a Skip where inapplicable.

mod acl;
mod attrs;
mod caps;
mod container;
mod dac;
mod existence;
mod mac;
mod macos;
mod mount;
mod netfs;
mod traverse;

pub use acl::AclLayer;
pub use attrs::AttrLayer;
pub use caps::CapsLayer;
pub use container::ContainerLayer;
pub use dac::DacLayer;
pub use existence::ExistenceLayer;
pub use mac::MacLayer;
pub use macos::MacosLayer;
pub use mount::MountLayer;
pub use netfs::NetfsLayer;
pub use traverse::TraverseLayer;
