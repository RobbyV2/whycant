# whycant

Explain, with evidence, why a filesystem operation is denied for a chosen identity.

## What it does

Walks every access-control layer a Unix kernel consults, in order, and evaluates each
against a target identity (uid, primary gid, full supplementary group set) rather than
the current euid:

- ancestor traverse (`+x`)
- DAC mode/owner
- POSIX/NFSv4 ACL
- immutable and append attrs
- mount flags (`ro`/`noexec`)
- Linux MAC/LSM (SELinux, AppArmor, SMACK/TOMOYO)
- capabilities
- network-FS (NFS/CIFS root_squash, ro-export, uid mismatch)
- container/userns
- macOS SIP, quarantine, TCC

Names what first denies the operation, shows the raw evidence line behind the verdict, and prints the
exact least-privilege fix. Anything computable unprivileged is proven; a MAC denial
provable only from the audit log is suspected until confirmed with `sudo`.

## Install

```sh
cargo install whycant
```

From source:

```sh
# Linux needs libacl for the ACL layer
sudo apt-get install -y libacl1-dev
cargo build --release
# ACL layer is optional; build without exacl/libacl:
cargo build --release --no-default-features
```

Man page:

```sh
whycant --man > whycant.1
sudo cp whycant.1 /usr/local/share/man/man1/whycant.1
man whycant
```

## Usage

```sh
whycant read /srv/data/report.txt          # explicit op + path
whycant /srv/data                          # bare path, op inferred (dir -> traverse)
whycant --user www-data read /srv/share/x  # evaluate on behalf of another user
whycant -- cat /etc/shadow                 # wrap a command, infer op + target
whycant --json read /srv/data/report.txt   # machine output on stdout
whycant -v write /home/alice/secret.txt    # --all: every layer, including pass/skip
```

## Sample output

```
✗ BLOCKED  traverse /srv/data/report.txt   /srv/data not traversable by alice

  /           ✓ x
  srv         ✓ x
  data        ✗ x  drwxr-x--- 4 root staff 4096 /srv/data   others lack x; alice not in group staff
  report.txt  ·   not reached

traverse denied at /srv/data
  ls -ld  drwxr-x--- 4 root staff 4096 /srv/data

  → sudo chmod 'o+x' /srv/data   [risk: low]
      others need +x to descend into /srv/data toward report.txt
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | allowed; nothing denies the operation |
| 1 | blocked, cause proven |
| 2 | blocked but indeterminate; needs privilege to confirm |
| 3 | target error (ENOENT, not a regular file, broken symlink) |
| 64 | usage error |

## Output formats

- `human` (default) glyph verdict, vertical evidence chain, raw lines, fixes; banner on stderr.
- `plain` (`--format plain`) ASCII marks, stable columns, one record per line for `grep`/`awk`.
- `json` (`--json`) one `Report` on stdout, no banner, identity/privilege folded in.
- `toml` (`--toml`) same `Report`, TOML encoding.

## Platform matrix

| Layer | Linux | FreeBSD | macOS |
|---|---|---|---|
| existence, traverse, DAC | yes | yes | yes |
| ACL | POSIX (exacl) | NFSv4/POSIX | NFSv4 |
| attrs | `FS_IOC_GETFLAGS` | `st_flags` | `st_flags` |
| mount | `statvfs` + `/proc/mounts` | `statfs` MNT_* | `statfs` + ro system volume |
| capabilities | yes | skip | skip |
| MAC/LSM | SELinux, AppArmor, SMACK/TOMOYO | mac(4) presence | skip |
| macOS SIP/quarantine/TCC | skip | skip | yes |
| network-FS | yes | yes | yes |
| container/userns | yes | skip | skip |

Inapplicable layers report `skip` so the chain and exit-code mapping stay identical across platforms.
