#![cfg_attr(not(target_os = "linux"), allow(dead_code))]
use crate::engine::{Layer, LayerResult};
use crate::identity::Identity;
use crate::op::Op;
use crate::report::{Fix, FixAction, LayerId, Risk};
use std::path::Path;

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
use crate::engine::LayerStatus;
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
use crate::report::{Certainty, Evidence, EvidenceSource};

pub struct MacLayer;

impl Layer for MacLayer {
    fn name(&self) -> &str {
        "mac"
    }
    fn order(&self) -> u8 {
        8
    }
    fn id(&self) -> LayerId {
        LayerId::Mac
    }
    fn check(&self, id: &Identity, path: &Path, op: Op) -> LayerResult {
        let _ = (&id, &path, &op);
        #[cfg(target_os = "linux")]
        {
            return linux::check(id, path, op);
        }
        #[cfg(target_os = "freebsd")]
        {
            return check_freebsd();
        }
        #[allow(unreachable_code)]
        LayerResult::skip()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SeMode {
    Enforcing,
    Permissive,
}

fn parse_enforce(s: &str) -> Option<SeMode> {
    match s.trim() {
        "1" => Some(SeMode::Enforcing),
        "0" => Some(SeMode::Permissive),
        _ => None,
    }
}

fn clean_label(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw)
        .trim_end_matches('\0')
        .trim()
        .to_string()
}

fn selinux_type(ctx: &str) -> Option<&str> {
    ctx.split(':').nth(2)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum AaMode {
    Enforce,
    Complain,
    Unconfined,
}

#[derive(Clone, PartialEq, Eq, Debug)]
struct AaProfile {
    name: String,
    mode: AaMode,
}

fn parse_aa_current(s: &str) -> AaProfile {
    let s = s.trim();
    match s.rsplit_once(" (") {
        Some((name, rest)) => {
            let mode = match rest.trim_end_matches(')') {
                "enforce" => AaMode::Enforce,
                "complain" => AaMode::Complain,
                _ => AaMode::Unconfined,
            };
            AaProfile {
                name: name.trim().to_string(),
                mode,
            }
        }
        None => AaProfile {
            name: s.to_string(),
            mode: AaMode::Unconfined,
        },
    }
}

fn scan_denials(text: &str, tokens: &[String]) -> Option<String> {
    text.lines()
        .rev()
        .find(|l| {
            let denial = (l.contains("avc:") && l.contains("denied"))
                || (l.contains("apparmor=") && l.contains("DENIED"));
            denial
                && tokens
                    .iter()
                    .any(|t| !t.is_empty() && l.contains(t.as_str()))
        })
        .map(|l| l.trim().to_string())
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum MacKind {
    Selinux,
    Apparmor,
}

fn implicated(se_enforcing_labeled: bool, aa_enforce: bool) -> Option<MacKind> {
    match (se_enforcing_labeled, aa_enforce) {
        (true, _) => Some(MacKind::Selinux),
        (false, true) => Some(MacKind::Apparmor),
        (false, false) => None,
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum MacVerdict {
    Proven,
    Suspected(MacKind),
    Skip,
}

fn decide(has_denial: bool, implicated: Option<MacKind>) -> MacVerdict {
    match (has_denial, implicated) {
        (true, _) => MacVerdict::Proven,
        (false, Some(k)) => MacVerdict::Suspected(k),
        (false, None) => MacVerdict::Skip,
    }
}

fn op_word(op: Op) -> &'static str {
    match op {
        Op::Read => "read",
        Op::Write => "write",
        Op::Exec => "exec",
        Op::Traverse => "traverse",
        Op::Delete => "delete",
        Op::Create => "create",
    }
}

fn advice(text: String) -> Fix {
    Fix {
        action: FixAction::Advice { text },
        needs_root: true,
        description: "confirm and adjust MAC policy".into(),
        risk: Risk::Medium,
        rationale: "confirm from the audit trail".into(),
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::process::Command;

    const SELINUX_ENFORCE: &str = "/sys/fs/selinux/enforce";
    const APPARMOR_DIR: &str = "/sys/kernel/security/apparmor";
    const SMACK_DIR: &str = "/sys/fs/smackfs";
    const TOMOYO_DIR: &str = "/sys/kernel/security/tomoyo";

    struct SeState {
        enforcing: bool,
        file_label: Option<String>,
        domain: Option<String>,
    }

    fn read_selinux(path: &Path) -> Option<SeState> {
        let raw = std::fs::read_to_string(SELINUX_ENFORCE).ok()?;
        let enforcing = matches!(parse_enforce(&raw), Some(SeMode::Enforcing));
        let file_label = xattr::get(path, "security.selinux")
            .ok()
            .flatten()
            .map(|b| clean_label(&b))
            .filter(|s| !s.is_empty());
        let domain = std::fs::read_to_string("/proc/self/attr/current")
            .ok()
            .map(|s| clean_label(s.as_bytes()))
            .filter(|s| !s.is_empty());
        Some(SeState {
            enforcing,
            file_label,
            domain,
        })
    }

    fn read_apparmor() -> Option<AaProfile> {
        if !Path::new(APPARMOR_DIR).exists() {
            return None;
        }
        let raw = std::fs::read_to_string("/proc/self/attr/apparmor/current")
            .or_else(|_| std::fs::read_to_string("/proc/self/attr/current"))
            .ok()?;
        Some(parse_aa_current(&raw))
    }

    fn audit_sources() -> Vec<(String, String)> {
        if let Ok(t) = std::fs::read_to_string("/var/log/audit/audit.log") {
            return vec![("/var/log/audit/audit.log".into(), t)];
        }
        let cmds: [(&str, &[&str]); 2] = [
            ("journalctl", &["-k", "--no-pager", "-o", "cat"]),
            ("dmesg", &[]),
        ];
        let mut out = Vec::new();
        for (prog, args) in cmds {
            match Command::new(prog).args(args).output() {
                Ok(o) if o.status.success() => {
                    out.push((
                        prog.to_string(),
                        String::from_utf8_lossy(&o.stdout).into_owned(),
                    ));
                }
                _ => {}
            }
        }
        out
    }

    fn ev(source: EvidenceSource, raw: String, path: Option<&Path>) -> Evidence {
        Evidence {
            source,
            raw,
            path: path.map(Path::to_path_buf),
        }
    }

    fn aa_word(m: AaMode) -> &'static str {
        match m {
            AaMode::Enforce => "enforce",
            AaMode::Complain => "complain",
            AaMode::Unconfined => "unconfined",
        }
    }

    fn skip_note(evidence: Vec<Evidence>, detail: String) -> LayerResult {
        LayerResult {
            status: LayerStatus::Skip,
            certainty: Certainty::Proven,
            evidence,
            fixes: Vec::new(),
            detail,
        }
    }

    fn presence_notes(se: &Option<SeState>, smack: bool, tomoyo: bool) -> Vec<String> {
        let mut n = Vec::new();
        if let Some(s) = se {
            if !s.enforcing {
                n.push("SELinux permissive; logs, no deny".into());
            }
        }
        if smack {
            n.push("SMACK present; not evaluated per-file".into());
        }
        if tomoyo {
            n.push("TOMOYO present; not evaluated per-file".into());
        }
        n
    }

    fn proven_fix(se: &Option<SeState>, aa: &Option<AaProfile>, op: Op) -> Fix {
        let text = match se.as_ref().and_then(|s| s.file_label.as_deref()) {
            Some(label) => {
                let t = selinux_type(label).unwrap_or(label);
                format!(
                    "SELinux type {t} denies {}; `sudo ausearch -m avc -ts recent`, adjust with `chcon`/`semanage fcontext`",
                    op_word(op)
                )
            }
            None => match aa.as_ref().filter(|a| a.mode != AaMode::Unconfined) {
                Some(a) => format!("profile {} enforce; `sudo aa-status`", a.name),
                None => "`sudo ausearch -m avc -ts recent`; adjust MAC policy".to_string(),
            },
        };
        advice(text)
    }

    fn suspect_detail(
        kind: MacKind,
        se: &Option<SeState>,
        aa: &Option<AaProfile>,
        id: &Identity,
        path: &Path,
        op: Op,
    ) -> String {
        match kind {
            MacKind::Selinux => {
                let label = se
                    .as_ref()
                    .and_then(|s| s.file_label.as_deref())
                    .unwrap_or("?");
                let dom = se.as_ref().and_then(|s| s.domain.as_deref()).unwrap_or("?");
                format!(
                    "SELinux enforcing; label {label} may not permit domain {dom} for {} on {}; uid {} needs sudo",
                    op_word(op),
                    path.display(),
                    id.uid
                )
            }
            MacKind::Apparmor => {
                let name = aa.as_ref().map(|a| a.name.as_str()).unwrap_or("?");
                format!(
                    "AppArmor profile {name} enforce may deny {} on {}; uid {} needs sudo",
                    op_word(op),
                    path.display(),
                    id.uid
                )
            }
        }
    }

    fn suspect_fix(kind: MacKind) -> Fix {
        let text = match kind {
            MacKind::Selinux => {
                "`sudo ausearch -m avc -ts recent`; adjust with `chcon`/`semanage fcontext`"
            }
            MacKind::Apparmor => {
                "`sudo journalctl -k | grep DENIED` or `sudo aa-status`; adjust profile"
            }
        };
        advice(text.to_string())
    }

    pub fn check(id: &Identity, path: &Path, op: Op) -> LayerResult {
        let se = read_selinux(path);
        let aa = read_apparmor();
        let smack = Path::new(SMACK_DIR).exists();
        let tomoyo = Path::new(TOMOYO_DIR).exists();

        if se.is_none() && aa.is_none() && !smack && !tomoyo {
            return LayerResult::skip();
        }

        let mut evidence = Vec::new();
        let mut tokens = vec![path.to_string_lossy().into_owned()];
        if let Some(b) = path.file_name() {
            tokens.push(b.to_string_lossy().into_owned());
        }

        if let Some(s) = &se {
            if let Some(fl) = &s.file_label {
                evidence.push(ev(
                    EvidenceSource::SelinuxLabel,
                    format!("{fl} {}", path.display()),
                    Some(path),
                ));
                if let Some(t) = selinux_type(fl) {
                    tokens.push(t.to_string());
                }
            }
            if let Some(d) = &s.domain {
                evidence.push(ev(
                    EvidenceSource::SelinuxLabel,
                    format!("process domain {d}"),
                    None,
                ));
                if let Some(t) = selinux_type(d) {
                    tokens.push(t.to_string());
                }
            }
        }
        if let Some(a) = &aa {
            if a.mode != AaMode::Unconfined {
                evidence.push(ev(
                    EvidenceSource::ApparmorStatus,
                    format!("{} ({})", a.name, aa_word(a.mode)),
                    None,
                ));
                tokens.push(a.name.clone());
            }
        }

        let denial = audit_sources()
            .into_iter()
            .find_map(|(src, text)| scan_denials(&text, &tokens).map(|l| (src, l)));

        let se_impl = se
            .as_ref()
            .is_some_and(|s| s.enforcing && s.file_label.is_some());
        let aa_impl = matches!(aa.as_ref().map(|a| a.mode), Some(AaMode::Enforce));
        let imp = implicated(se_impl, aa_impl);

        match decide(denial.is_some(), imp) {
            MacVerdict::Proven => match denial {
                Some((src, line)) => {
                    let mut ev_all = evidence;
                    ev_all.push(ev(
                        EvidenceSource::AuditAvc,
                        format!("{src}: {line}"),
                        Some(path),
                    ));
                    let detail = format!(
                        "MAC denies {} on {}: denial in {src}",
                        op_word(op),
                        path.display()
                    );
                    LayerResult::block(
                        Certainty::Proven,
                        detail,
                        ev_all,
                        vec![proven_fix(&se, &aa, op)],
                    )
                }
                None => LayerResult::skip(),
            },
            MacVerdict::Suspected(kind) => {
                let detail = suspect_detail(kind, &se, &aa, id, path, op);
                LayerResult::suspect(detail, evidence, vec![suspect_fix(kind)])
            }
            MacVerdict::Skip => {
                let mut ev_all = evidence;
                for note in presence_notes(&se, smack, tomoyo) {
                    ev_all.push(ev(EvidenceSource::MacStatus, note, None));
                }
                skip_note(ev_all, "MAC present; no denial signal".into())
            }
        }
    }
}

#[cfg(target_os = "freebsd")]
fn check_freebsd() -> LayerResult {
    use std::ffi::CString;
    let present = CString::new("security.mac.version").is_ok_and(|name| {
        let mut len: libc::size_t = 0;
        unsafe {
            libc::sysctlbyname(
                name.as_ptr(),
                std::ptr::null_mut(),
                &mut len,
                std::ptr::null_mut(),
                0,
            ) == 0
        }
    });
    match present {
        true => LayerResult {
            status: LayerStatus::Skip,
            certainty: Certainty::Proven,
            evidence: vec![Evidence {
                source: EvidenceSource::MacStatus,
                raw: "mac(4) framework present; no per-file evaluation".into(),
                path: None,
            }],
            fixes: Vec::new(),
            detail: "MAC framework present; not evaluated per-file".into(),
        },
        false => LayerResult::skip(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforce_parses_zero_and_one() {
        assert_eq!(parse_enforce("1\n"), Some(SeMode::Enforcing));
        assert_eq!(parse_enforce("0"), Some(SeMode::Permissive));
        assert_eq!(parse_enforce("x"), None);
    }

    #[test]
    fn apparmor_confined_enforce_classified() {
        let p = parse_aa_current("/usr/bin/man (enforce)\n");
        assert_eq!(p.mode, AaMode::Enforce);
        assert_eq!(p.name, "/usr/bin/man");
        assert_eq!(
            parse_aa_current("firefox (complain)").mode,
            AaMode::Complain
        );
        assert_eq!(parse_aa_current("unconfined").mode, AaMode::Unconfined);
    }

    #[test]
    fn selinux_xattr_label_and_type() {
        let label = clean_label(b"system_u:object_r:etc_t:s0\0");
        assert_eq!(label, "system_u:object_r:etc_t:s0");
        assert_eq!(selinux_type(&label), Some("etc_t"));
    }

    #[test]
    fn denial_line_matches_path_or_program_only() {
        let avc = "type=AVC msg=audit(1): avc:  denied  { read } for pid=1 comm=\"cat\" name=\"secret.txt\" scontext=a tcontext=b\nunrelated";
        let toks = vec!["/home/a/secret.txt".to_string(), "secret.txt".to_string()];
        assert!(scan_denials(avc, &toks).is_some());
        let aa = "audit: type=1400 apparmor=\"DENIED\" operation=\"open\" profile=\"/usr/bin/foo\" name=\"/etc/shadow\"";
        assert!(scan_denials(aa, &["/usr/bin/foo".to_string()]).is_some());
        assert!(scan_denials("nothing relevant", &toks).is_none());
        assert!(scan_denials("avc:  denied  { read }", &toks).is_none());
    }

    #[test]
    fn decision_doctrine_proven_suspected_skip() {
        assert_eq!(decide(true, None), MacVerdict::Proven);
        assert_eq!(
            decide(false, Some(MacKind::Selinux)),
            MacVerdict::Suspected(MacKind::Selinux)
        );
        assert_eq!(decide(false, None), MacVerdict::Skip);
        assert_eq!(implicated(true, false), Some(MacKind::Selinux));
        assert_eq!(implicated(false, true), Some(MacKind::Apparmor));
        assert_eq!(implicated(false, false), None);
    }
}
