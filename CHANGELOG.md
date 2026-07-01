# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0]

### Added

- Access-control evaluation across eleven layers, checked in kernel-consult order:
  existence, ancestor traverse (`+x`), DAC mode/owner bits, POSIX/NFSv4 ACL, file
  attributes (immutable/append), mount flags (`ro`/`noexec`), Linux capabilities,
  MAC/LSM (SELinux, AppArmor, SMACK/TOMOYO), macOS SIP/quarantine/TCC, network
  filesystem root_squash/ro-export/uid-mismatch, and container/user-namespace.
- Evaluation against a chosen target identity (uid, primary gid, full supplementary
  group set) rather than the current euid.
- Verdict and certainty model: the first denying layer is named with its raw evidence
  line; anything computable unprivileged is proven, a denial provable only from the
  audit log is suspected until confirmed with elevated privilege.
- Output formats: `human` glyph verdict with vertical evidence chain, `plain` ASCII
  columns for `grep`/`awk`, `json` and `toml` single-`Report` encodings.
- Exit codes: `0` allowed, `1` blocked and proven, `2` blocked but indeterminate,
  `3` target error, `64` usage error.
- Least-privilege fix suggestions with a risk annotation; optional apply.
- Shell completions (`--completions <shell>`) and man page generation (`--man`).
- Platform support for Linux, macOS, and FreeBSD; inapplicable layers report `skip`
  so the chain and exit-code mapping stay identical across platforms.

[0.1.0]: https://crates.io/crates/whycant
