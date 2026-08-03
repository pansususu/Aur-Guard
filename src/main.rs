mod alerts;
mod audit;
mod config;
mod daemon;
mod feeds;
mod gate;
mod paru;
mod shell;

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::process::{Child, Stdio};
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use clap::{Parser, Subcommand};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;

use crate::config::{socket_path, Config};
use crate::daemon::{Request, Response};

#[derive(Parser)]
#[command(name = "aur-guard", version, about = "Monitor de malware AUR + auditoria de host (daemon efimero + gancho paru)")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Instala el gancho de paru y revisa paquetes contra el feed antes de instalar
    Install {
        /// Paquetes a comprobar contra el feed (opcional)
        packages: Vec<String>,
    },
    /// Despierta el daemon solo para refrescar el repositorio, registrar cambios y avisar
    Check,
    /// Despierta el daemon para escanear el sistema (paquetes infectados, procesos, persistencia)
    Scan,
    /// Gancho interno llamado por paru (PreBuildCommand) antes de cada build
    #[command(hide = true)]
    Gate,
    /// Estado del daemon
    Status,
    /// Detiene el daemon
    Stop,
    /// Instala en .bashrc/.zshrc una funcion `paru` que comprueba malware ANTES de instalar
    ShellHook,
    /// Daemon efimero (uso interno)
    #[command(hide = true)]
    Daemon,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Daemon => {
            let cfg = Config::load()?;
            daemon::run(cfg)
        }
        Command::Install { packages } => cmd_install(packages),
        Command::Check => cmd_check(),
        Command::Scan => cmd_scan(),
        Command::Gate => cmd_gate(),
        Command::Status => cmd_status(),
        Command::Stop => cmd_stop(),
        Command::ShellHook => cmd_shell_hook(),
    }
}

// ---------- daemon lifecycle ----------

fn send_request(req: &Request) -> Result<Response> {
    let sock = socket_path();
    let mut stream = UnixStream::connect(&sock)
        .map_err(|e| anyhow!("no hay daemon escuchando en {}: {}", sock.display(), e))?;
    stream.set_read_timeout(Some(Duration::from_secs(120)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    writeln!(stream, "{}", serde_json::to_string(req)?)?;
    stream.flush()?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let resp: Response =
        serde_json::from_str(line.trim()).map_err(|e| anyhow!("respuesta invalida: {}", e))?;
    Ok(resp)
}

fn ping() -> bool {
    matches!(
        send_request(&Request::Ping),
        Ok(Response::Pong { .. })
    )
}

fn spawn_daemon() -> Result<Child> {
    let exe = std::env::current_exe()?;
    let child = std::process::Command::new(exe)
        .arg("daemon")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    Ok(child)
}

/// Asegura un daemon escuchando. Devuelve el Child si lo lanzo este proceso.
fn ensure_daemon() -> Result<Option<Child>> {
    if ping() {
        return Ok(None);
    }
    let mut child = spawn_daemon()?;
    for _ in 0..60 {
        if ping() {
            return Ok(Some(child));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = child.kill();
    bail!("no se pudo arrancar el daemon")
}

/// Mata el daemon (SIGTERM -> SIGKILL) y espera a que muera.
fn shutdown_daemon(child: Option<Child>) {
    if let Some(pid) = crate::daemon::daemon_pid() {
        let _ = kill(Pid::from_raw(pid as i32), Signal::SIGTERM);
        for _ in 0..40 {
            if crate::daemon::daemon_pid().is_none() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        if crate::daemon::daemon_pid().is_some() {
            let _ = kill(Pid::from_raw(pid as i32), Signal::SIGKILL);
        }
    }
    if let Some(mut c) = child {
        let _ = c.wait();
    }
}

fn with_daemon<T>(f: impl FnOnce(&Config) -> Result<T>) -> Result<T> {
    let cfg = Config::load()?;
    let child = ensure_daemon()?;
    let r = f(&cfg);
    shutdown_daemon(child);
    r
}

// ---------- comandos ----------

fn cmd_install(packages: Vec<String>) -> Result<()> {
    let hook_msg = match paru::ensure_hook() {
        Ok(m) => m,
        Err(e) => e.to_string(),
    };
    println!("[install] {}", hook_msg);

    if packages.is_empty() {
        println!("[install] no se pasaron paquetes; solo se dejo listo el gancho de paru.");
        return Ok(());
    }

    with_daemon(|_cfg| {
        let resp = send_request(&Request::CheckPackages { names: packages })?;
        match resp {
            Response::CheckResult { verdicts } => {
                let mut any_bad = false;
                for v in &verdicts {
                    if v.malicious {
                        any_bad = true;
                        println!(
                            "[INSTALAR BLOQUEADO] {} -> COMPROMETIDO [{}]",
                            v.name,
                            v.reasons.join(", ")
                        );
                    } else {
                        println!("[ok] {} -> sin coincidencias de malware", v.name);
                    }
                }
                if any_bad {
                    bail!("paquetes comprometidos; abortando instalacion");
                }
                Ok(())
            }
            other => Err(anyhow!("respuesta inesperada: {:?}", other)),
        }
    })
}

fn cmd_check() -> Result<()> {
    with_daemon(|_cfg| {
        let resp = send_request(&Request::CheckFeeds)?;
        match resp {
            Response::FeedsResult {
                new_malware,
                total,
                error,
            } => {
                if let Some(e) = error {
                    eprintln!("[check] error refrescando feeds: {}", e);
                }
                println!("[check] feed actualizado: {} paquetes en la lista de malware.", total);
                if new_malware.is_empty() {
                    println!("[check] sin cambios nuevos.");
                } else {
                    println!("[check] paquetes NUEVOS marcados como malware:");
                    for n in &new_malware {
                        println!("  - {}", n);
                    }
                }
                Ok(())
            }
            other => Err(anyhow!("respuesta inesperada: {:?}", other)),
        }
    })
}

fn cmd_scan() -> Result<()> {
    with_daemon(|_cfg| {
        let resp = send_request(&Request::ScanHost)?;
        match resp {
            Response::ScanResult { report } => {
                print_report(&report);
                Ok(())
            }
            other => Err(anyhow!("respuesta inesperada: {:?}", other)),
        }
    })
}

fn pkgbase_from_env_or_cwd() -> Option<String> {
    if let Ok(v) = std::env::var("PKGBASE") {
        if !v.trim().is_empty() {
            return Some(v.trim().to_string());
        }
    }
    let text = std::fs::read_to_string("PKGBUILD").ok()?;
    let re = regex::Regex::new(r"(?m)^\s*(pkgbase|pkgname)\s*=\s*([^#\s]+)").ok()?;
    let mut first_name: Option<String> = None;
    for cap in re.captures_iter(&text) {
        let key = &cap[1];
        let raw = &cap[2];
        let val = raw
            .trim_matches('"')
            .trim_matches('\'')
            .to_string();
        if key == "pkgbase" {
            return Some(val);
        }
        if first_name.is_none() {
            first_name = Some(val);
        }
    }
    first_name
}

fn cmd_gate() -> Result<()> {
    let name = pkgbase_from_env_or_cwd()
        .ok_or_else(|| anyhow!("no se pudo determinar el nombre del paquete"))?;
    let dir = std::env::current_dir()
        .ok()
        .map(|p| p.to_string_lossy().to_string());
    println!("[aur-guard gate] comprobando '{}'...", name);

    let verdict = with_daemon(|_cfg| {
        let resp = send_request(&Request::GateCheck {
            name: name.clone(),
            dir,
        })?;
        match resp {
            Response::GateResult { verdict } => Ok(verdict),
            other => Err(anyhow!("respuesta inesperada: {:?}", other)),
        }
    })?;

    if verdict.malicious {
        println!(
            "[BLOQUEADO] '{}' es malware: [{}]",
            name,
            verdict.reasons.join(", ")
        );
        eprintln!(
            "aur-guard: BLOQUEADO '{}' — {}",
            name,
            verdict.reasons.join(", ")
        );
        std::process::exit(1);
    }
    println!("[ok] '{}' sin coincidencias de malware.", name);
    Ok(())
}

fn cmd_status() -> Result<()> {
    if ping() {
        println!("daemon activo (pid {})", crate::daemon::daemon_pid().unwrap_or(0));
    } else {
        println!("daemon no activo");
    }
    Ok(())
}

fn cmd_stop() -> Result<()> {
    if !ping() {
        println!("daemon no activo");
        return Ok(());
    }
    shutdown_daemon(None);
    println!("daemon detenido");
    Ok(())
}

fn cmd_shell_hook() -> Result<()> {
    println!("{}", shell::install_hook()?);
    Ok(())
}

fn print_report(r: &audit::Report) {
    println!("== ESCANEO DEL SISTEMA ==");
    println!(
        "[+] {} paquetes instalados revisados ({} de AUR)",
        r.scanned_installed,
        r.foreign_installed.len()
    );

    println!("\n== PAQUETES INFECTADOS INSTALADOS ==");
    if r.infected.is_empty() {
        println!("  sin coincidencias");
    } else {
        for v in &r.infected {
            println!("  [CRIT] {} [{}]", v.name, v.reasons.join(", "));
        }
    }

    println!("\n== PROCESOS SOSPECHOSOS ==");
    if r.processes.is_empty() {
        println!("  sin anomalias");
    } else {
        for f in &r.processes {
            println!("  [{}] {}", f.severity.to_uppercase(), f.message);
        }
    }

    println!("\n== PERSISTENCIA / AUTORUN ==");
    if r.persistence.is_empty() {
        println!("  sin anomalias");
    } else {
        for f in &r.persistence {
            println!("  [{}] {}", f.severity.to_uppercase(), f.message);
        }
    }
    println!();
}
