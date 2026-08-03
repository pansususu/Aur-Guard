use anyhow::Result;
use std::fs;
use std::path::PathBuf;

const MARK: &str = "#### aur-guard: paru wrapper (comprobacion de malware antes de instalar) ####";

const SNIPPET: &str = r#"paru() {
  if [[ "$1" == "-S" ]]; then
    local _pkgs=() _a
    for _a in "${@:2}"; do
      [[ "$_a" == -* || -z "$_a" ]] && continue
      _pkgs+=("$_a")
    done
    if (( ${#_pkgs[@]} )); then
      aur-guard install "${_pkgs[@]}" || {
        echo "aur-guard: instalacion bloqueada (paquete comprometido)." >&2
        return 1
      }
    fi
  fi
  command paru "$@"
}
"#;

fn rc_path() -> PathBuf {
    let shell = std::env::var("SHELL").unwrap_or_default();
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
    if shell.contains("zsh") {
        home.join(".zshrc")
    } else {
        home.join(".bashrc")
    }
}

pub fn install_hook() -> Result<String> {
    let path = rc_path();
    let existing = fs::read_to_string(&path).unwrap_or_default();
    if existing.contains(MARK) {
        return Ok(format!("el gancho de shell ya esta instalado en {}", path.display()));
    }
    let mut content = existing;
    if !content.ends_with('\n') {
        content.push('\n');
    }
    content.push_str(MARK);
    content.push('\n');
    content.push_str(SNIPPET);
    content.push('\n');
    fs::write(&path, content)?;
    Ok(format!(
        "gancho de shell instalado en {}. Abre una terminal nueva para que aplique.",
        path.display()
    ))
}