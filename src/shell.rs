use anyhow::Result;
use std::fs;
use std::path::{Path, PathBuf};

const MARK: &str = "#### aur-guard: paru wrapper (comprobacion de malware antes de instalar) ####";

const FISH_MARK: &str = "# aur-guard: paru wrapper (comprobacion de malware antes de instalar)";

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

const FISH_SNIPPET: &str = r#"function paru --wraps paru
  if test "$argv[1]" = "-S"
    set -l pkgs
    for a in $argv[2..-1]
      if test -z "$a"; or string match -q -- '-*' "$a"
        continue
      end
      set -a pkgs "$a"
    end
    if test (count $pkgs) -gt 0
      aur-guard install $pkgs; or begin
        echo "aur-guard: instalacion bloqueada (paquete comprometido)." >&2
        return 1
      end
    end
  end
  command paru $argv
end
"#;

fn rc_path() -> PathBuf {
    let shell = std::env::var("SHELL").unwrap_or_default();
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
    if shell.contains("fish") {
        home.join(".config").join("fish").join("config.fish")
    } else if shell.contains("zsh") {
        home.join(".zshrc")
    } else {
        home.join(".bashrc")
    }
}

fn hook_for(path: &Path) -> (&'static str, &'static str) {
    if path.ends_with("config.fish") {
        (FISH_MARK, FISH_SNIPPET)
    } else {
        (MARK, SNIPPET)
    }
}

pub fn install_hook() -> Result<String> {
    let path = rc_path();
    let (mark, snippet) = hook_for(&path);
    let existing = fs::read_to_string(&path).unwrap_or_default();
    if existing.contains(mark) {
        return Ok(format!("el gancho de shell ya esta instalado en {}", path.display()));
    }
    let mut content = existing;
    if !content.ends_with('\n') {
        content.push('\n');
    }
    content.push_str(mark);
    content.push('\n');
    content.push_str(snippet);
    content.push('\n');
    fs::write(&path, content)?;
    Ok(format!(
        "gancho de shell instalado en {}. Abre una terminal nueva para que aplique.",
        path.display()
    ))
}