use anyhow::{anyhow, Result};
use std::fs;
use std::path::PathBuf;

const HOOK_LINE: &str = "PreBuildCommand = aur-guard gate";

pub fn paru_conf() -> PathBuf {
    let dir = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(dirs::config_dir)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    dir.join("paru").join("paru.conf")
}

fn line_is_ours(line: &str) -> bool {
    let t = line.trim();
    t == HOOK_LINE || (t.starts_with("PreBuildCommand") && t.contains("aur-guard gate"))
}

fn has_conflicting_prebuild(lines: &[String]) -> Option<String> {
    lines.iter().find_map(|l| {
        let t = l.trim();
        if t.starts_with("PreBuildCommand") && !t.contains("aur-guard gate") {
            Some(t.to_string())
        } else {
            None
        }
    })
}

fn insert_under_bin(lines: Vec<String>) -> Vec<String> {
    // 1) si el gancho ya vive bajo [bin], no tocar
    let bin_idx = lines.iter().position(|l| l.trim() == "[bin]");
    if let Some(idx) = bin_idx {
        if lines[idx + 1..].iter().any(|l| line_is_ours(l)) {
            return lines;
        }
        let mut out = Vec::with_capacity(lines.len() + 1);
        for (i, l) in lines.iter().enumerate() {
            out.push(l.clone());
            if i == idx {
                out.push(HOOK_LINE.to_string());
            }
        }
        out.push(String::new());
        return out;
    }

    // 2) no hay [bin]: anadir la seccion al final
    let mut out = lines;
    out.push(String::new());
    out.push("[bin]".to_string());
    out.push(HOOK_LINE.to_string());
    out
}

/// Asegura el gancho `PreBuildCommand` bajo la seccion [bin] de paru (idempotente).
pub fn ensure_hook() -> Result<String> {
    let path = paru_conf();
    let parent = path.parent().unwrap();
    fs::create_dir_all(parent)?;

    let text = if path.exists() {
        fs::read_to_string(&path)?
    } else {
        String::new()
    };
    let lines: Vec<String> = text.lines().map(String::from).collect();

    if let Some(conflict) = has_conflicting_prebuild(&lines) {
        return Err(anyhow!(
            "paru.conf ya tiene un PreBuildCommand distinto ({}); no se modifica. Ajustalo a: {}",
            conflict,
            HOOK_LINE
        ));
    }

    let already = lines.iter().any(|l| l.trim() == "[bin]")
        && lines
            .iter()
            .enumerate()
            .any(|(i, l)| l.trim() == "[bin]" && lines[i + 1..].iter().any(|x| line_is_ours(x)));

    let new_lines = insert_under_bin(lines);
    let content = new_lines.join("\n") + "\n";
    if !already {
        fs::write(&path, content)?;
    }
    Ok(if already {
        "gancho paru ya instalado".into()
    } else {
        format!("gancho paru instalado en {}", path.display())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_is_ours_accepts_hook_variants() {
        assert!(line_is_ours(HOOK_LINE));
        assert!(line_is_ours("  PreBuildCommand = aur-guard gate  "));
        assert!(line_is_ours("PreBuildCommand   aur-guard gate"));
    }

    #[test]
    fn line_is_ours_rejects_others() {
        assert!(!line_is_ours("PreBuildCommand = something else"));
        assert!(!line_is_ours("# comentario"));
        assert!(!line_is_ours(""));
    }

    #[test]
    fn has_conflicting_prebuild_finds_conflict() {
        let lines = vec!["[bin]".to_string(), "PreBuildCommand = other".to_string()];
        assert_eq!(
            has_conflicting_prebuild(&lines),
            Some("PreBuildCommand = other".to_string())
        );
    }

    #[test]
    fn has_conflicting_prebuild_none_when_ok() {
        let lines = vec!["[bin]".to_string(), HOOK_LINE.to_string()];
        assert_eq!(has_conflicting_prebuild(&lines), None);
    }

    #[test]
    fn insert_under_bin_after_existing_section() {
        let out = insert_under_bin(vec!["[bin]".to_string(), "MakepkgArgs".to_string()]);
        assert_eq!(out, vec![
            "[bin]".to_string(),
            HOOK_LINE.to_string(),
            "MakepkgArgs".to_string(),
            String::new(),
        ]);
    }

    #[test]
    fn insert_under_bin_no_section_appends() {
        let out = insert_under_bin(vec!["A".to_string()]);
        assert_eq!(out, vec![
            "A".to_string(),
            String::new(),
            "[bin]".to_string(),
            HOOK_LINE.to_string(),
        ]);
    }

    #[test]
    fn insert_under_bin_idempotent() {
        let lines = vec!["[bin]".to_string(), HOOK_LINE.to_string()];
        assert_eq!(insert_under_bin(lines), vec!["[bin]".to_string(), HOOK_LINE.to_string()]);
    }
}
