use std::fs;
use std::process::Command;

use crate::config::{now_epoch, state_dir, Config};

fn log_line(level: &str, msg: &str) {
    let dir = state_dir();
    let _ = fs::create_dir_all(&dir);
    let path = dir.join("aur-guard.log");
    let ts = now_epoch();
    let _ = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .and_then(|mut f| {
            use std::io::Write;
            f.write_fmt(format_args!("[{}][{}] {}\n", ts, level, msg))
        });
}

pub fn notify(cfg: &Config, title: &str, body: &str) {
    log_line("ALERTA", &format!("{} — {}", title, body));
    if cfg.log {
        eprintln!("aur-guard: {} — {}", title, body);
    }
    if cfg.notify {
        let _ = Command::new("notify-send")
            .args([
                "--app-name=aur-guard",
                "--urgency=critical",
                "--expire-time=60000",
                title,
                body,
            ])
            .spawn();
    }
}
