use crate::engine::{Layer, LayerResult, LayerStatus};
use crate::identity::Identity;
use crate::op::Op;
use crate::report::{Certainty, Evidence, EvidenceSource, Fix, FixAction, LayerId, Risk};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

const FULL_CAPS: u64 = 0x0000_01ff_ffff_ffff;

pub struct ContainerLayer;

struct MapEntry {
    inside: u32,
    outside: u32,
    len: u32,
}

fn parse_uid_map(s: &str) -> Vec<MapEntry> {
    s.lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            let inside = f.next()?.parse().ok()?;
            let outside = f.next()?.parse().ok()?;
            let len = f.next()?.parse().ok()?;
            Some(MapEntry {
                inside,
                outside,
                len,
            })
        })
        .collect()
}

fn is_host_map(m: &[MapEntry]) -> bool {
    matches!(m, [e] if e.inside == 0 && e.outside == 0 && e.len == u32::MAX)
}

fn maps_inside(m: &[MapEntry], uid: u32) -> bool {
    m.iter().any(|e| {
        let lo = e.inside as u64;
        (uid as u64) >= lo && (uid as u64) < lo + e.len as u64
    })
}

fn mapped_range(m: &[MapEntry]) -> String {
    match m.first() {
        Some(e) => format!("{}..{}", e.inside, e.inside as u64 + e.len as u64),
        None => "none".into(),
    }
}

fn status_field<'a>(status: &'a str, key: &str) -> Option<&'a str> {
    status
        .lines()
        .find_map(|l| l.strip_prefix(key).map(str::trim))
}

fn parse_cap_bnd(status: &str) -> Option<u64> {
    status_field(status, "CapBnd:").and_then(|v| u64::from_str_radix(v, 16).ok())
}

fn parse_seccomp(status: &str) -> u32 {
    status_field(status, "Seccomp:")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

fn caps_reduced(capbnd: u64) -> bool {
    capbnd != FULL_CAPS && capbnd & !FULL_CAPS == 0
}

fn container_marker() -> Option<String> {
    match () {
        _ if Path::new("/.dockerenv").exists() => Some("/.dockerenv present".into()),
        _ if Path::new("/run/.containerenv").exists() => Some("/run/.containerenv present".into()),
        _ => match std::env::var("container") {
            Ok(v) if !v.is_empty() => Some(format!("container={v}")),
            _ => None,
        },
    }
}

fn overflow_uid() -> u32 {
    std::fs::read_to_string("/proc/sys/kernel/overflowuid")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(65534)
}

fn cap_ev(raw: String) -> Evidence {
    Evidence {
        source: EvidenceSource::Capability,
        raw,
        path: None,
    }
}

fn env_evidence(
    map: &[MapEntry],
    capbnd: Option<u64>,
    reduced: bool,
    seccomp: u32,
    marker: &Option<String>,
) -> Vec<Evidence> {
    let mut ev = Vec::new();
    if !map.is_empty() && !is_host_map(map) {
        let raw = map
            .iter()
            .map(|e| format!("{} {} {}", e.inside, e.outside, e.len))
            .collect::<Vec<_>>()
            .join(" | ");
        ev.push(cap_ev(format!("/proc/self/uid_map: {raw}")));
    }
    if reduced {
        ev.push(cap_ev(format!("CapBnd: {:016x}", capbnd.unwrap_or(0))));
    }
    if seccomp > 0 {
        ev.push(cap_ev(format!("Seccomp: {seccomp} (filter)")));
    }
    if let Some(m) = marker {
        ev.push(cap_ev(m.clone()));
    }
    ev
}

fn env_summary(userns: bool, range: &str, reduced: bool, filtering: bool, marker: bool) -> String {
    let mut parts = Vec::new();
    if userns {
        parts.push(format!(
            "user namespace; uids outside {range} appear as nobody"
        ));
    }
    if reduced {
        parts.push("reduced capability bounding set".into());
    }
    if filtering {
        parts.push("seccomp filtering active".into());
    }
    if marker && !userns {
        parts.push("container markers present".into());
    }
    parts.join("; ")
}

fn check_container(path: &Path) -> LayerResult {
    let uid_map = match std::fs::read_to_string("/proc/self/uid_map") {
        Ok(s) => s,
        Err(_) => return LayerResult::skip(),
    };
    let map = parse_uid_map(&uid_map);
    let userns = !map.is_empty() && !is_host_map(&map);
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let capbnd = parse_cap_bnd(&status);
    let reduced = capbnd.is_some_and(caps_reduced);
    let seccomp = parse_seccomp(&status);
    let filtering = seccomp > 0;
    let marker = container_marker();
    let range = mapped_range(&map);

    let overflow = overflow_uid();
    let owner = std::fs::metadata(path).ok().map(|m| m.uid());
    let unmapped = owner.filter(|&o| userns && (o == overflow || !maps_inside(&map, o)));

    match unmapped {
        Some(o) => {
            let mut ev = env_evidence(&map, capbnd, reduced, seccomp, &marker);
            ev.push(Evidence {
                source: EvidenceSource::LsLd,
                raw: format!("owner uid {o} (shown as nobody {overflow})"),
                path: Some(path.to_path_buf()),
            });
            let fix = Fix {
                action: FixAction::Advice {
                    text: format!(
                        "owning uid outside {range}; extend subuid map or chown into {range}"
                    ),
                },
                needs_root: true,
                description: "resolve the user-namespace uid mapping".into(),
                risk: Risk::Medium,
                rationale:
                    "uid unmapped in namespace"
                        .into(),
            };
            LayerResult::suspect(
                format!(
                    "uid {o} unmapped in namespace, appears as nobody ({overflow})"
                ),
                ev,
                vec![fix],
            )
        }
        None => {
            let containerized = marker.is_some() || (userns && (reduced || filtering));
            match containerized {
                false => LayerResult::skip(),
                true => LayerResult {
                    status: LayerStatus::Skip,
                    certainty: Certainty::Proven,
                    evidence: env_evidence(&map, capbnd, reduced, seccomp, &marker),
                    fixes: Vec::new(),
                    detail: env_summary(userns, &range, reduced, filtering, marker.is_some()),
                },
            }
        }
    }
}

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
    fn check(&self, _id: &Identity, path: &Path, _op: Op) -> LayerResult {
        check_container(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_map_is_not_userns() {
        let m = parse_uid_map("         0          0 4294967295\n");
        assert_eq!(m.len(), 1);
        assert!(is_host_map(&m));
    }

    #[test]
    fn offset_map_is_userns_with_gaps() {
        let m = parse_uid_map("0 100000 65536\n");
        assert!(!is_host_map(&m));
        assert!(maps_inside(&m, 0));
        assert!(maps_inside(&m, 65535));
        assert!(!maps_inside(&m, 65536));
        assert!(!maps_inside(&m, 200000));
        assert_eq!(mapped_range(&m), "0..65536");
    }

    #[test]
    fn multiline_map_covers_each_range() {
        let m = parse_uid_map("0 1000 1\n1 100000 65536\n");
        assert!(maps_inside(&m, 0));
        assert!(maps_inside(&m, 1));
        assert!(maps_inside(&m, 65536));
        assert!(!maps_inside(&m, 65537));
    }

    #[test]
    fn cap_bnd_full_vs_reduced() {
        assert!(!caps_reduced(
            parse_cap_bnd("CapBnd:\t000001ffffffffff").unwrap()
        ));
        assert!(caps_reduced(
            parse_cap_bnd("CapBnd:\t00000000a80425fb").unwrap()
        ));
        assert!(!caps_reduced(0xffff_ffff_ffff_ffff));
    }

    #[test]
    fn seccomp_mode_parses() {
        assert_eq!(parse_seccomp("Seccomp:\t0\nSeccomp_filters:\t0"), 0);
        assert_eq!(parse_seccomp("Seccomp:\t2"), 2);
        assert_eq!(parse_seccomp("Name:\tx"), 0);
    }
}
