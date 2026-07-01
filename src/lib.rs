//! whycant walks each access-control layer a Unix kernel consults to explain,
//! with evidence, why a filesystem operation is denied for a chosen identity.
//! It reports the first real blocker and prints the exact least-privilege fix,
//! collapsing a manual runbook (`id`, `ls -l`, `namei -l`, `getfacl`, `lsattr`,
//! `mount`, label and audit inspection) into one command. Each layer is
//! evaluated symbolically against a target identity (uid, primary gid, full
//! supplementary group set), not through `access(2)`, which answers only for
//! the current euid.
//!
//! # Layered model
//!
//! Access is a fixed chain of eleven layers run in order: existence, traverse,
//! DAC, ACL, attributes, mount flags, capabilities, MAC/LSM, macOS SIP,
//! network filesystem, and container/userns. Each [`engine::Layer`] reads real
//! filesystem state and evaluates it against a target [`identity::Identity`]
//! for one [`op::Op`]. Portability lives inside each layer's check; an
//! inapplicable platform returns a Skip, so the chain shape, output, and
//! exit-code mapping are identical on every OS.
//!
//! # Verdict and certainty
//!
//! Each layer returns a [`engine::LayerStatus`]: `Pass`, `Block`, `Suspect`,
//! `Skip`, or `Error`. The runner folds these into a [`report::Verdict`]
//! (`Allowed`, `Blocked`, `Indeterminate`, `TargetError`) carrying a
//! [`report::Certainty`] (`Proven` or `Suspected`). Anything computable
//! unprivileged is `Proven`; a denial provable only from the audit log or a
//! server that cannot be inspected stays `Suspected`. The earliest proven
//! block wins; absent that, the earliest suspected block; absent that, a lone
//! suspect yields `Indeterminate`; otherwise `Allowed`.
//!
//! # Exit codes
//!
//! | Code | Meaning |
//! |------|---------|
//! | 0 | allowed, no blocker |
//! | 1 | blocked, cause proven |
//! | 2 | blocked but indeterminate; needs privilege to confirm |
//! | 3 | target error (ENOENT, not a file, broken symlink) |
//! | 64 | usage error |
//! | 70 | internal error, panics only |
//!
//! Codes 0 through 3 follow the verdict and certainty via [`report::exit_code`].
//!
//! # CLI usage
//!
//! ```console
//! $ whycant read /home/alice/secret.txt
//! ✗ BLOCKED  read /home/alice/secret.txt   /home/alice not traversable by bob
//!
//! $ whycant --user www-data exec /usr/local/bin/app
//! $ whycant -- cat /etc/shadow
//! $ whycant --json traverse /srv/data
//! ```
//!
//! # Stability
//!
//! whycant is CLI-first; this library backs the binary and its tests, and the
//! 0.x library API is not yet semver-stable.

pub mod access_check;
pub mod cli;
pub mod config;
pub mod engine;
pub mod fix;
pub mod identity;
pub mod layers;
pub mod op;
pub mod render;
pub mod report;
pub mod term;
