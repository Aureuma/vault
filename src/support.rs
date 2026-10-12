//! Local replacements for the three couplings this code had to the `si` crates
//! before extraction. Each is a faithful reimplementation, not a behaviour change:
//!
//! - `git_repo_root_from` was `si_config::runtime::git_repo_root_from`
//! - `OutputFormat` and `show_vault_trust_lookup` were `si-cli`'s (main.rs)
//! - `default_home_dir` was `si-cli`'s private helper
use std::fmt;
use std::fs;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::ValueEnum;
use serde::Serialize;

use crate::trust::TrustStore;

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
}

impl fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Text => "text",
            Self::Json => "json",
        };
        f.write_str(value)
    }
}

pub fn default_home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| PathBuf::from("/"))
}

/// Absolutize without touching the filesystem (mirrors si-config's path_absolutize).
fn path_absolutize(path: &Path) -> PathBuf {
    let mut base = if path.is_absolute() {
        PathBuf::new()
    } else {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"))
    };
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                base.pop();
            }
            other => base.push(other.as_os_str()),
        }
    }
    base
}

fn resolve_directory_path(path: &Path, label: &str) -> Result<PathBuf> {
    if path.as_os_str().is_empty() {
        bail!("{label}: empty path");
    }
    let abs = path
        .canonicalize()
        .or_else(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                Ok(path_absolutize(path))
            } else {
                Err(err)
            }
        })
        .with_context(|| format!("{label}: resolve {}", path.display()))?;
    Ok(abs)
}

fn is_git_repo_dir(dir: &Path) -> bool {
    dir.join(".git").exists()
}

/// Walk up from `start` until a directory containing `.git` is found.
pub fn git_repo_root_from(start: &Path) -> Result<PathBuf> {
    let start = resolve_directory_path(start, "git repo root")?;
    let mut current = start.clone();
    loop {
        if is_git_repo_dir(&current) {
            return Ok(current);
        }
        let Some(parent) = current.parent() else {
            break;
        };
        if parent == current {
            break;
        }
        current = parent.to_path_buf();
    }
    bail!("git repo root: none found from {}", start.display())
}

/// Kept for API compatibility with the pre-extraction helper set.
pub fn has_direct_git_children(dir: &Path) -> bool {
    let Ok(entries) = fs::read_dir(dir) else {
        return false;
    };
    entries
        .filter_map(|entry| entry.ok())
        .any(|entry| is_git_repo_dir(&entry.path()))
}

fn render_text_value(value: &str) -> String {
    if value.trim().is_empty() {
        "-".to_owned()
    } else {
        value.trim().to_owned()
    }
}

fn render_option_text_value(value: Option<&str>) -> String {
    match value {
        Some(inner) => render_text_value(inner),
        None => "-".to_owned(),
    }
}

#[derive(Debug, Serialize)]
struct TrustLookupView {
    found: bool,
    matches: bool,
    repo_root: String,
    file: String,
    expected_fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    stored_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    trusted_at: Option<String>,
}

/// JSON field names are held byte-compatible with the pre-extraction output
/// (`found`/`matches`/`stored_fingerprint`/`trusted_at`) so existing
/// `vault trust lookup --format json` consumers keep working.
pub fn show_trust_lookup(
    path: PathBuf,
    repo_root: &str,
    file: &str,
    fingerprint: &str,
    format: OutputFormat,
) -> Result<()> {
    let store = TrustStore::load(path)?;
    let entry = store.find(repo_root, file);
    let view = TrustLookupView {
        found: entry.is_some(),
        matches: entry
            .map(|entry| entry.fingerprint.trim() == fingerprint.trim())
            .unwrap_or(false),
        repo_root: repo_root.trim().to_owned(),
        file: file.trim().to_owned(),
        expected_fingerprint: fingerprint.trim().to_owned(),
        stored_fingerprint: entry.map(|entry| entry.fingerprint.clone()),
        trusted_at: entry.and_then(|entry| {
            if entry.trusted_at.trim().is_empty() {
                None
            } else {
                Some(entry.trusted_at.clone())
            }
        }),
    };

    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&view)?),
        OutputFormat::Text => {
            println!("found={}", view.found);
            println!("matches={}", view.matches);
            println!("repo_root={}", render_text_value(&view.repo_root));
            println!("file={}", render_text_value(&view.file));
            println!(
                "expected_fingerprint={}",
                render_text_value(&view.expected_fingerprint)
            );
            println!(
                "stored_fingerprint={}",
                render_option_text_value(view.stored_fingerprint.as_deref())
            );
            println!(
                "trusted_at={}",
                render_option_text_value(view.trusted_at.as_deref())
            );
        }
    }

    Ok(())
}
