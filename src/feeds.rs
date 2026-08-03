use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::sync::OnceLock;
use tokio::runtime::Runtime;

use crate::config::{now_epoch, state_dir, Config, FeedConfig};

fn rt() -> &'static Runtime {
    static RT: OnceLock<Runtime> = OnceLock::new();
    RT.get_or_init(|| Runtime::new().expect("no se pudo crear el runtime tokio"))
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct FeedState {
    pub updated_at: i64,
    pub packages: HashMap<String, Vec<String>>,
}

#[derive(serde::Deserialize)]
struct CampaignIndex {
    campaigns: Vec<Campaign>,
}

#[derive(serde::Deserialize)]
struct Campaign {
    #[serde(rename = "id")]
    id: String,
    #[serde(rename = "type")]
    type_: String,
    #[serde(default)]
    lists: Vec<String>,
    #[serde(default)]
    refresh_url: Option<String>,
}

fn state_file() -> std::path::PathBuf {
    state_dir().join("feeds").join("current.json")
}

fn baseline_file() -> std::path::PathBuf {
    state_dir().join("feed_baseline.json")
}

// (el bloqueo se ejecuta dentro de rt().block_on)
fn http_get(client: &reqwest::Client, url: &str) -> Result<String> {
    rt().block_on(http_get_fut(client, url))
}

fn http_get_fut(client: &reqwest::Client, url: &str) -> impl std::future::Future<Output = Result<String>> {
    let client = client.clone();
    let url = url.to_string();
    async move {
        let resp = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            client.get(&url).send(),
        )
        .await
        .map_err(|_| anyhow::anyhow!("timeout {}", url))??;
        let t = tokio::time::timeout(std::time::Duration::from_secs(30), resp.text())
            .await
            .map_err(|_| anyhow::anyhow!("timeout lectura {}", url))??;
        Ok::<String, anyhow::Error>(t)
    }
}

pub fn parse_list(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with('`'))
        .map(|l| l.split_whitespace().next().unwrap_or("").to_string())
        .filter(|l| valid_name(l))
        .collect()
}

/// Solo nombres de paquete validos (sin ruido de markdown ni basura).
pub fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.chars().all(|c| c.is_ascii_alphanumeric() || "@._+:-".contains(c))
        && s.chars().next().map(|c| c.is_ascii_alphanumeric()).unwrap_or(false)
}

fn refresh_lenucksi(client: &reqwest::Client, f: &FeedConfig, map: &mut HashMap<String, Vec<String>>) -> Result<()> {
    let base = f.base_url.as_deref().unwrap_or_default().trim_end_matches('/');
    let index_url = format!("{}/data/campaigns.json", base);
    let index_text = http_get(client, &index_url)?;
    let index: CampaignIndex = serde_json::from_str(&index_text)?;
    for camp in index.campaigns {
        if camp.type_ != "aur" {
            continue;
        }
        for list in camp.lists {
            let url = format!("{}/{}", base, list.trim_start_matches('/'));
            if let Ok(txt) = http_get(client, &url) {
                for name in parse_list(&txt) {
                    map.entry(name).or_default().push(camp.id.clone());
                }
            }
        }
        if let Some(ru) = &camp.refresh_url {
            if let Ok(txt) = http_get(client, ru) {
                for name in parse_list(&txt) {
                    map.entry(name).or_default().push(camp.id.clone());
                }
            }
        }
    }
    Ok(())
}

fn refresh_plain(client: &reqwest::Client, f: &FeedConfig, map: &mut HashMap<String, Vec<String>>) -> Result<()> {
    let url = f.url.as_deref().unwrap_or_default();
    let txt = http_get(client, url)?;
    for name in parse_list(&txt) {
        map.entry(name).or_default().push(f.name.clone());
    }
    Ok(())
}

pub fn load_cached() -> Option<FeedState> {
    fs::read_to_string(state_file())
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
}

/// Refresca los feeds (o devuelve la cache si esta fresca y no se fuerza).
pub fn refresh(cfg: &Config, force: bool) -> Result<FeedState> {
    if !force {
        if let Some(s) = load_cached() {
            let age = now_epoch() - s.updated_at;
            if age < cfg.cache_ttl_secs as i64 {
                return Ok(s);
            }
        }
    }

    let client = reqwest::Client::builder().build()?;
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    for f in &cfg.feeds {
        if !f.enabled.unwrap_or(true) {
            continue;
        }
        let r = match f.kind.as_str() {
            "lenucksi" => refresh_lenucksi(&client, f, &mut map),
            "plain" => refresh_plain(&client, f, &mut map),
            other => Err(anyhow::anyhow!("tipo de feed desconocido: {}", other)),
        };
        if let Err(e) = r {
            eprintln!("aur-guard: feed '{}' fallo: {}", f.name, e);
        }
    }

    for reasons in map.values_mut() {
        reasons.sort();
        reasons.dedup();
    }
    let state = FeedState {
        updated_at: now_epoch(),
        packages: map,
    };
    if let Some(parent) = state_file().parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(state_file(), serde_json::to_string_pretty(&state)?)?;
    Ok(state)
}

pub fn malware_set(state: &FeedState) -> HashSet<String> {
    state.packages.keys().cloned().collect()
}

pub fn normalize(name: &str) -> Vec<String> {
    let mut out = vec![name.to_string()];
    for suffix in ["-git", "-bin", "-svn", "-hg", "-bzr", "-cvs", "-dev"] {
        if let Some(stripped) = name.strip_suffix(suffix) {
            out.push(stripped.to_string());
        }
    }
    out
}

/// Veredicto de un paquete frente al feed: devuelve (infectado, campañas).
pub fn feed_verdict(state: &FeedState, name: &str) -> (bool, Vec<String>) {
    for n in normalize(name) {
        if let Some(reasons) = state.packages.get(&n) {
            return (true, reasons.clone());
        }
    }
    (false, Vec::new())
}

// ------- baseline / alertas de cambios -------

pub fn load_baseline() -> HashSet<String> {
    fs::read_to_string(baseline_file())
        .ok()
        .and_then(|t| serde_json::from_str::<Vec<String>>(&t).ok())
        .map(|v| v.into_iter().filter(|n| valid_name(n)).collect())
        .unwrap_or_default()
}

pub fn has_baseline() -> bool {
    baseline_file().exists()
}

pub fn save_baseline(set: &HashSet<String>) -> Result<()> {
    let mut v: Vec<String> = set.iter().cloned().collect();
    v.sort();
    if let Some(parent) = baseline_file().parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(baseline_file(), serde_json::to_string(&v)?)?;
    Ok(())
}

/// Comprueba si un paquete concreto esta instalado.
pub fn is_installed(name: &str) -> bool {
    std::process::Command::new("pacman")
        .args(["-Q", name])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}