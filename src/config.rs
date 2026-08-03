use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub fn config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("aur-guard")
}

pub fn state_dir() -> PathBuf {
    dirs::state_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("aur-guard")
}

pub fn config_file() -> PathBuf {
    config_dir().join("config.toml")
}

pub fn socket_path() -> PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(state_dir)
        .join("aur-guard.sock")
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub cache_ttl_secs: u64,
    pub recent_days: u64,
    pub notify: bool,
    pub log: bool,
    pub feeds: Vec<FeedConfig>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeedConfig {
    pub name: String,
    pub kind: String,
    #[serde(default)]
    pub base_url: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

const DEFAULT_CONFIG: &str = r##"# Configuracion de aur-guard
# TTL de la cache de feeds en segundos (3600 = 1 hora).
cache_ttl_secs = 3600
# Dias hacia atras para considerar una unit/cron/rc como "modificada recientemente".
recent_days = 30
# Enviar alertas con notify-send.
notify = true
# Escribir alertas en stderr (journald lo captura).
log = true

# Feeds de paquetes AUR considerados malware. Se pueden anadir mas listas
# con kind = "plain" y una URL a un archivo de texto (un paquete por linea,
# comentarios con #).
[[feeds]]
name = "aur-malware-check"
kind = "lenucksi"
base_url = "https://raw.githubusercontent.com/lenucksi/aur-malware-check/master"
enabled = true
"##;

impl Config {
    pub fn load() -> Result<Self> {
        let path = config_file();
        if !path.exists() {
            std::fs::create_dir_all(config_dir())?;
            std::fs::write(&path, DEFAULT_CONFIG)?;
        }
        let text = std::fs::read_to_string(&path)?;
        toml::from_str(&text).map_err(|e| anyhow!("config invalida {}: {}", path.display(), e))
    }
}

pub fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
