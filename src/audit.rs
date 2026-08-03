use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

use crate::config::Config;
use crate::feeds::{self, FeedState};
use crate::gate::Verdict;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Finding {
    pub severity: String,
    pub message: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Report {
    pub scanned_installed: usize,
    pub foreign_installed: Vec<String>,
    pub infected: Vec<Verdict>,
    pub processes: Vec<Finding>,
    pub persistence: Vec<Finding>,
}

fn cmd_stdout(prog: &str, args: &[&str]) -> String {
    match Command::new(prog).args(args).output() {
        Ok(o) => String::from_utf8_lossy(&o.stdout).into_owned(),
        Err(e) => format!("<{} no disponible: {}>", prog, e),
    }
}

fn pacman_all_installed() -> Vec<String> {
    cmd_stdout("pacman", &["-Qq"])
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect()
}

fn pacman_owns(path: &str) -> bool {
    match Command::new("pacman").args(["-Qo", path]).output() {
        Ok(o) => o.status.success(),
        Err(_) => false,
    }
}

fn pacman_foreign() -> Vec<String> {
    cmd_stdout("pacman", &["-Qm"])
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect()
}

fn is_kernel_thread(cmd: &str, cmdline: &[u8], ppid: u32) -> bool {
    cmdline.is_empty() && ppid == 2 && cmd.starts_with('[') && cmd.ends_with(']')
}

pub fn run(cfg: &Config) -> Report {
    let state: FeedState =
        feeds::refresh(cfg, false).unwrap_or(FeedState { updated_at: 0, packages: HashMap::new() });

    let mut infected: Vec<Verdict> = Vec::new();
    let installed = pacman_all_installed();
    for name in &installed {
        let (bad, reasons) = feeds::feed_verdict(&state, name);
        if bad {
            infected.push(Verdict {
                name: name.clone(),
                malicious: true,
                reasons,
            });
        }
    }
    let foreign = pacman_foreign();

    let processes = scan_processes(cfg);
    let persistence = scan_persistence(cfg);

    Report {
        scanned_installed: installed.len(),
        foreign_installed: foreign,
        infected,
        processes,
        persistence,
    }
}

// ---------- procesos ----------

const SUSPICIOUS_DIRS: &[&str] = &["/tmp/", "/dev/shm/", "/var/tmp/", "/run/user/"];

fn short(cmd: &str, n: usize) -> String {
    if cmd.len() <= n {
        cmd.to_string()
    } else {
        format!("{}…", &cmd[..n])
    }
}

fn in_suspicious_dir(p: &str) -> Option<&'static str> {
    SUSPICIOUS_DIRS.iter().find(|d| p.starts_with(**d)).copied()
}

fn not_pacman_owned_path(p: &str) -> bool {
    !(p.starts_with("/usr")
        || p.starts_with("/bin")
        || p.starts_with("/sbin")
        || p.starts_with("/lib")
        || p.starts_with("/proc")
        || p.starts_with("/app/")
        || p.starts_with("/snap/"))
}

fn scan_processes(cfg: &Config) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut ownership: HashMap<String, bool> = HashMap::new();
    let mut ownership_checks = 0usize;
    let mut reported_exe: std::collections::HashSet<String> = std::collections::HashSet::new();

    let proc_root = Path::new("/proc");
    let Ok(entries) = std::fs::read_dir(proc_root) else {
        findings.push(Finding {
            severity: "warn".into(),
            message: "no se pudo leer /proc".into(),
        });
        return findings;
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_string_lossy().parse::<u32>().ok() else {
            continue;
        };
        let cmdline_path = PathBuf::from(format!("/proc/{}/cmdline", pid));
        let cmdline_bytes = std::fs::read(&cmdline_path).unwrap_or_default();
        let cmdline = cmdline_bytes
            .split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect::<Vec<_>>()
            .join(" ");

        let status = std::fs::read_to_string(format!("/proc/{}/status", pid)).unwrap_or_default();
        let ppid = status
            .lines()
            .find_map(|l| l.strip_prefix("PPid:"))
            .and_then(|v| v.trim().parse::<u32>().ok())
            .unwrap_or(0);
        let comm = status
            .lines()
            .find_map(|l| l.strip_prefix("Name:"))
            .map(|v| v.trim().to_string())
            .unwrap_or_default();

        if is_kernel_thread(&comm, &cmdline_bytes, ppid) {
            continue;
        }
        if cmdline.contains("aur-guard") {
            continue;
        }

        let exe = std::fs::read_link(format!("/proc/{}/exe", pid)).ok();

        if let Some(exe) = &exe {
            let es = exe.to_string_lossy().to_string();
            if let Some(d) = in_suspicious_dir(&es) {
                findings.push(Finding {
                    severity: "crit".into(),
                    message: format!(
                        "proceso {} [{}] con binario en {}: {}",
                        pid,
                        comm,
                        d,
                        short(&cmdline, 120)
                    ),
                });
            }
            if ownership_checks < 80 && not_pacman_owned_path(&es) {
                let owned = *ownership.entry(es.clone()).or_insert_with(|| {
                    ownership_checks += 1;
                    pacman_owns(&es)
                });
                if !owned && reported_exe.insert(es.clone()) {
                    findings.push(Finding {
                        severity: "warn".into(),
                        message: format!(
                            "proceso {} [{}] con binario sin paquete: {} ({})",
                            pid,
                            comm,
                            es,
                            short(&cmdline, 100)
                        ),
                    });
                }
            }
        } else if let Some(d) = in_suspicious_dir(&cmdline) {
            findings.push(Finding {
                severity: "info".into(),
                message: format!(
                    "proceso {} [{}] en ruta sospechosa {}: {}",
                    pid,
                    comm,
                    d,
                    short(&cmdline, 120)
                ),
            });
        }
    }

    // puertos escuchando
    let pid_re = regex::Regex::new(r#"pid=(\d+)"#).unwrap();
    for (opt, proto) in [("-tlnp", "TCP"), ("-ulnp", "UDP")] {
        let out = cmd_stdout("ss", &[opt]);
        if out.starts_with("<ss") {
            continue;
        }
        let mut seen = std::collections::HashSet::new();
        for line in out.lines() {
            for cap in pid_re.captures_iter(line) {
                let pid = cap[1].to_string();
                if !seen.insert(pid.clone()) {
                    continue;
                }
                if let Ok(exe) = std::fs::read_link(format!("/proc/{}/exe", pid)) {
                    let es = exe.to_string_lossy().to_string();
                    if let Some(d) = in_suspicious_dir(&es) {
                        findings.push(Finding {
                            severity: "crit".into(),
                            message: format!("puerto {} escuchando desde {} (pid {}): {}", proto, d, pid, es),
                        });
                    }
                }
            }
        }
    }
    let _ = cfg;
    findings
}

// ---------- persistencia ----------

fn recent_secs(cfg: &Config) -> u64 {
    cfg.recent_days.saturating_mul(86400)
}

fn mtime_recent(path: &Path, recent: u64) -> bool {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        .map(|d| d.as_secs() <= recent)
        .unwrap_or(false)
}

fn scan_persistence(cfg: &Config) -> Vec<Finding> {
    let mut findings = Vec::new();
    let recent = recent_secs(cfg);

    for dir in ["/etc/systemd/system"] {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for e in entries.flatten() {
                let p = e.path();
                let name = e.file_name().to_string_lossy().to_string();
                if !name.ends_with(".service") && !name.ends_with(".timer") && !name.ends_with(".socket") {
                    continue;
                }
                if mtime_recent(&p, recent) {
                    findings.push(Finding {
                        severity: "warn".into(),
                        message: format!("unit systemd modificada recientemente: {} ({})", dir, name),
                    });
                }
            }
        }
    }

    if let Some(home) = dirs::home_dir() {
        let udir = home.join(".config").join("systemd").join("user");
        if let Ok(entries) = std::fs::read_dir(&udir) {
            for e in entries.flatten() {
                let p = e.path();
                let name = e.file_name().to_string_lossy().to_string();
                if !name.ends_with(".service") && !name.ends_with(".timer") {
                    continue;
                }
                if mtime_recent(&p, recent) {
                    findings.push(Finding {
                        severity: "warn".into(),
                        message: format!("unit systemd de usuario modificada recientemente: {}", name),
                    });
                }
            }
        }

        // autostart
        let autostart = home.join(".config").join("autostart");
        if let Ok(entries) = std::fs::read_dir(&autostart) {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if name.ends_with(".desktop") {
                    findings.push(Finding {
                        severity: "info".into(),
                        message: format!("entrada de autostart presente: {}", name),
                    });
                }
            }
        }

        // authorized_keys
        let ak = home.join(".ssh").join("authorized_keys");
        if ak.exists() {
            let count = std::fs::read_to_string(&ak)
                .map(|t| t.lines().filter(|l| !l.trim().is_empty()).count())
                .unwrap_or(0);
            let rec = if mtime_recent(&ak, recent) { " (modificado recientemente)" } else { "" };
            findings.push(Finding {
                severity: if count > 0 { "warn".into() } else { "info".into() },
                message: format!("authorized_keys con {} claves{}", count, rec),
            });
        }

        // shell rc recientes
        for rc in [".bashrc", ".zshrc", ".profile", ".bash_profile"] {
            let p = home.join(rc);
            if p.exists() && mtime_recent(&p, recent) {
                findings.push(Finding {
                    severity: "info".into(),
                    message: format!("{} modificado recientemente", rc),
                });
            }
        }
    }

    // cron
    for p in ["/etc/crontab", "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"] {
        let path = Path::new(p);
        if path.is_file() {
            if mtime_recent(path, recent) {
                findings.push(Finding {
                    severity: "warn".into(),
                    message: format!("{} modificado recientemente", p),
                });
            }
        } else if path.is_dir() {
            if let Ok(entries) = std::fs::read_dir(path) {
                for e in entries.flatten() {
                    let ep = e.path();
                    if mtime_recent(&ep, recent) {
                        findings.push(Finding {
                            severity: "warn".into(),
                            message: format!("{} modificado recientemente", ep.display()),
                        });
                    }
                }
            }
        }
    }

    if Path::new("/etc/rc.local").exists() {
        findings.push(Finding {
            severity: "info".into(),
            message: "/etc/rc.local existe".into(),
        });
    }

    let iptables = cmd_stdout("iptables", &["-L", "-n"]);
    if iptables.starts_with("<iptables") {
        findings.push(Finding {
            severity: "info".into(),
            message: "iptables no disponible o requiere permisos".into(),
        });
    } else {
        let n = iptables.lines().filter(|l| l.contains("ACCEPT") || l.contains("DROP") || l.contains("REJECT")).count();
        if n > 0 {
            findings.push(Finding {
                severity: "info".into(),
                message: format!("{} reglas activas en iptables", n),
            });
        }
    }

    findings
}
