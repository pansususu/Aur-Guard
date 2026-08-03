use anyhow::Result;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::audit;
use crate::config::{socket_path, state_dir, Config};
use crate::feeds;

pub const GRACE_NS: i64 = 3_000_000_000; // inactividad antes de morir
pub const MAX_LIFETIME: Duration = Duration::from_secs(300);

#[derive(Clone, serde::Serialize, serde::Deserialize, Debug)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    Ping,
    CheckFeeds,
    CheckPackages { names: Vec<String> },
    GateCheck { name: String, dir: Option<String> },
    ScanHost,
    Shutdown,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    Pong { version: String },
    FeedsResult { new_malware: Vec<String>, total: usize, error: Option<String> },
    CheckResult { verdicts: Vec<crate::gate::Verdict> },
    GateResult { verdict: crate::gate::Verdict },
    ScanResult { report: audit::Report },
    ShuttingDown,
    Error { message: String },
}

fn pidfile() -> PathBuf {
    state_dir().join("daemon.pid")
}

pub fn daemon_pid() -> Option<u32> {
    fs::read_to_string(pidfile())
        .ok()
        .and_then(|t| t.trim().parse::<u32>().ok())
}

fn now_nanos() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

fn dispatch(cfg: &Config, req: Request) -> Response {
    match req {
        Request::Ping => Response::Pong {
            version: env!("CARGO_PKG_VERSION").to_string(),
        },
        Request::CheckFeeds => match feeds::refresh(cfg, true) {
            Ok(state) => {
                let set = feeds::malware_set(&state);
                let baseline = feeds::load_baseline();
                let had_baseline = feeds::has_baseline();
                let mut new: Vec<String> = set.difference(&baseline).cloned().collect();
                new.sort();
                if !new.is_empty() {
                    for n in &new {
                        let reasons = state
                            .packages
                            .get(n)
                            .map(|r| r.join(", "))
                            .unwrap_or_default();
                        let installed = feeds::is_installed(n);
                        if had_baseline {
                            // Cambio nuevo en el feed: alertar siempre.
                            let extra = if installed {
                                " — ¡INSTALADO EN TU SISTEMA!"
                            } else {
                                ""
                            };
                            crate::alerts::notify(
                                cfg,
                                &format!("AUR: paquete marcado como malware{}", extra),
                                &format!("{} [{}]", n, reasons),
                            );
                        } else if installed {
                            // Sincronizacion inicial: solo alertar lo instalado.
                            crate::alerts::notify(
                                cfg,
                                "AUR: paquete instalado y marcado como malware",
                                &format!("{} [{}]", n, reasons),
                            );
                        }
                    }
                    let _ = feeds::save_baseline(&set);
                } else if !had_baseline {
                    let _ = feeds::save_baseline(&set);
                }
                Response::FeedsResult {
                    new_malware: new,
                    total: set.len(),
                    error: None,
                }
            }
            Err(e) => Response::FeedsResult {
                new_malware: Vec::new(),
                total: 0,
                error: Some(e.to_string()),
            },
        },
        Request::CheckPackages { names } => {
            let verdicts = names
                .iter()
                .map(|n| crate::gate::check(cfg, n, None))
                .collect();
            Response::CheckResult { verdicts }
        }
        Request::GateCheck { name, dir } => Response::GateResult {
            verdict: crate::gate::check(cfg, &name, dir.as_deref()),
        },
        Request::ScanHost => Response::ScanResult {
            report: audit::run(cfg),
        },
        Request::Shutdown => Response::ShuttingDown,
    }
}

fn handle_conn(mut stream: UnixStream, cfg: Config) {
    let mut reader = BufReader::new(stream.try_clone().expect("clonar stream"));
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let req: Request = match serde_json::from_str(trimmed) {
            Ok(r) => r,
            Err(e) => {
                let resp = Response::Error { message: e.to_string() };
                let _ = writeln!(stream, "{}", serde_json::to_string(&resp).unwrap());
                let _ = stream.flush();
                continue;
            }
        };
        let resp = dispatch(&cfg, req.clone());
        let _ = writeln!(stream, "{}", serde_json::to_string(&resp).unwrap());
        let _ = stream.flush();
        if let Request::Shutdown = req {
            break;
        }
    }
}

pub fn run(cfg: Config) -> Result<()> {
    let sock = socket_path();
    let _ = fs::remove_file(&sock);
    if let Some(parent) = sock.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::create_dir_all(state_dir())?;
    fs::write(pidfile(), format!("{}\n", std::process::id()))?;

    let listener = UnixListener::bind(&sock)?;
    listener.set_nonblocking(true)?;
    eprintln!("aur-guard daemon listo en {}", sock.display());

    let terminate = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGTERM, terminate.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGINT, terminate.clone())?;

    let active = Arc::new(AtomicUsize::new(0));
    let last_activity = Arc::new(AtomicI64::new(now_nanos()));

    let term = terminate.clone();
    let act = active.clone();
    let la = last_activity.clone();
    let cfg_thread = cfg.clone();
    let accept_thread = std::thread::spawn(move || {
        let listener = listener;
        while !term.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => {
                    la.store(now_nanos(), Ordering::Relaxed);
                    act.fetch_add(1, Ordering::Relaxed);
                    let cfg = cfg_thread.clone();
                    let act = act.clone();
                    std::thread::spawn(move || {
                        handle_conn(stream, cfg);
                        act.fetch_sub(1, Ordering::Relaxed);
                    });
                }
                Err(_) => std::thread::sleep(Duration::from_millis(50)),
            }
        }
    });

    let start = Instant::now();
    loop {
        if terminate.load(Ordering::Relaxed) {
            break;
        }
        if active.load(Ordering::Relaxed) == 0
            && now_nanos() - last_activity.load(Ordering::Relaxed) >= GRACE_NS
        {
            break;
        }
        if start.elapsed() > MAX_LIFETIME {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    terminate.store(true, Ordering::Relaxed);
    let _ = accept_thread.join();
    let _ = fs::remove_file(&sock);
    let _ = fs::remove_file(pidfile());
    eprintln!("aur-guard daemon terminado");
    Ok(())
}
