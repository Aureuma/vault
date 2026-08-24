use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use tempfile::NamedTempFile;
use thiserror::Error;

pub const TRUST_SCHEMA_VERSION: i32 = 3;

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustStore {
    pub schema_version: i32,
    #[serde(default)]
    pub entries: Vec<TrustEntry>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustEntry {
    pub repo_root: String,
    pub file: String,
    pub fingerprint: String,
    #[serde(default)]
    pub trusted_at: String,
}

#[derive(Debug, Error)]
pub enum TrustStoreError {
    #[error("trust path required")]
    MissingPath,
    #[error("create trust directory: {0}")]
    CreateDirectory(#[source] std::io::Error),
    #[error("stat trust file: {0}")]
    Stat(#[source] std::io::Error),
    #[error("read trust file: {0}")]
    Read(#[source] std::io::Error),
    #[error("parse trust file: {0}")]
    Parse(#[source] serde_json::Error),
    #[error("serialize trust file: {0}")]
    Serialize(#[source] serde_json::Error),
    #[error("create temp trust file: {0}")]
    CreateTemp(#[source] std::io::Error),
    #[error("write temp trust file: {0}")]
    WriteTemp(#[source] std::io::Error),
    #[error("persist temp trust file: {0}")]
    Persist(#[source] std::io::Error),
    #[error("set trust file permissions: {0}")]
    SetPermissions(#[source] std::io::Error),
    #[error("trust file must be a regular file")]
    NotRegularFile,
}

impl TrustStore {
    pub fn empty() -> Self {
        Self { schema_version: TRUST_SCHEMA_VERSION, entries: Vec::new() }
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, TrustStoreError> {
        let path = clean_path(path.as_ref())?;
        match fs::metadata(path) {
            Ok(metadata) => {
                if !metadata.is_file() {
                    return Err(TrustStoreError::NotRegularFile);
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::empty());
            }
            Err(err) => return Err(TrustStoreError::Stat(err)),
        }
        let raw = fs::read(path).map_err(TrustStoreError::Read)?;
        let mut store: TrustStore = serde_json::from_slice(&raw).map_err(TrustStoreError::Parse)?;
        if store.schema_version < TRUST_SCHEMA_VERSION {
            store.schema_version = TRUST_SCHEMA_VERSION;
        }
        store.entries = store.entries.into_iter().map(|entry| entry.normalized()).collect();
        Ok(store)
    }

    pub fn find(&self, repo_root: &str, file: &str) -> Option<&TrustEntry> {
        let repo_root = clean_key_path(repo_root);
        let file = clean_key_path(file);
        self.entries.iter().find(|entry| {
            clean_key_path(&entry.repo_root) == repo_root && clean_key_path(&entry.file) == file
        })
    }

    pub fn upsert(&mut self, entry: TrustEntry) {
        let mut entry = entry.normalized();
        if entry.trusted_at.is_empty() {
            entry.trusted_at = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true);
        }
        if let Some(existing) = self.entries.iter_mut().find(|existing| {
            clean_key_path(&existing.repo_root) == entry.repo_root
                && clean_key_path(&existing.file) == entry.file
        }) {
            *existing = entry;
            return;
        }
        self.entries.push(entry);
    }

    pub fn delete(&mut self, repo_root: &str, file: &str) -> bool {
        let repo_root = clean_key_path(repo_root);
        let file = clean_key_path(file);
        let original_len = self.entries.len();
        self.entries.retain(|entry| {
            clean_key_path(&entry.repo_root) != repo_root || clean_key_path(&entry.file) != file
        });
        self.entries.len() != original_len
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), TrustStoreError> {
        let path = clean_path(path.as_ref())?;
        let dir = path.parent().ok_or(TrustStoreError::MissingPath)?;
        fs::create_dir_all(dir).map_err(TrustStoreError::CreateDirectory)?;
        let payload = Self {
            schema_version: self.schema_version.max(TRUST_SCHEMA_VERSION),
            entries: self.entries.iter().map(TrustEntry::normalized).collect(),
        };
        let mut raw = serde_json::to_vec_pretty(&payload).map_err(TrustStoreError::Serialize)?;
        raw.push(b'\n');
        let mut tmp = NamedTempFile::new_in(dir).map_err(TrustStoreError::CreateTemp)?;
        set_file_mode(tmp.path(), 0o600).map_err(TrustStoreError::SetPermissions)?;
        use std::io::Write as _;
        tmp.write_all(&raw).map_err(TrustStoreError::WriteTemp)?;
        tmp.flush().map_err(TrustStoreError::WriteTemp)?;
        tmp.persist(path).map_err(|err| TrustStoreError::Persist(err.error))?;
        set_file_mode(path, 0o600).map_err(TrustStoreError::SetPermissions)?;
        Ok(())
    }
}

impl TrustEntry {
    pub fn normalized(&self) -> Self {
        Self {
            repo_root: clean_key_path(&self.repo_root),
            file: clean_key_path(&self.file),
            fingerprint: self.fingerprint.trim().to_owned(),
            trusted_at: self.trusted_at.trim().to_owned(),
        }
    }
}

fn clean_path(path: &Path) -> Result<&Path, TrustStoreError> {
    if path.as_os_str().is_empty() {
        return Err(TrustStoreError::MissingPath);
    }
    Ok(path)
}

fn clean_key_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let input = Path::new(trimmed);
    let mut normalized = PathBuf::new();
    for component in input.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(Path::new("/")),
            Component::CurDir => {}
            Component::ParentDir => {
                let _ = normalized.pop();
            }
            Component::Normal(part) => normalized.push(part),
        }
    }
    if normalized.as_os_str().is_empty() && input.is_absolute() {
        "/".to_owned()
    } else {
        normalized.display().to_string()
    }
}

fn set_file_mode(path: &Path, mode: u32) -> Result<(), std::io::Error> {
    #[cfg(unix)]
    {
        fs::set_permissions(path, PermissionsExt::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{TRUST_SCHEMA_VERSION, TrustEntry, TrustStore};
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    #[test]
    fn trust_store_round_trip_matches_go_behavior() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("trust.json");
        let mut store = TrustStore::empty();
        store.upsert(TrustEntry {
            repo_root: "/repo".to_owned(),
            file: "/repo/.env".to_owned(),
            fingerprint: "deadbeef".to_owned(),
            trusted_at: String::new(),
        });

        store.save(&path).expect("save trust store");

        let loaded = TrustStore::load(&path).expect("load trust store");
        let entry = loaded.find("/repo", "/repo/.env").expect("entry");
        assert_eq!(entry.fingerprint, "deadbeef");
        assert!(!entry.trusted_at.is_empty());
        #[cfg(unix)]
        {
            let mode = fs::metadata(&path).expect("stat trust store").permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn trust_store_load_defaults_when_file_is_missing() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("missing.json");

        let loaded = TrustStore::load(&path).expect("load missing trust store");

        assert_eq!(loaded.schema_version, TRUST_SCHEMA_VERSION);
        assert!(loaded.entries.is_empty());
    }

    #[test]
    fn trust_store_upsert_and_delete_normalize_paths() {
        let mut store = TrustStore::empty();
        store.upsert(TrustEntry {
            repo_root: " /repo/../repo ".to_owned(),
            file: " /repo/.env ".to_owned(),
            fingerprint: "deadbeef".to_owned(),
            trusted_at: String::new(),
        });

        let entry = store.find("/repo", "/repo/.env").expect("normalized entry");
        assert_eq!(entry.repo_root, "/repo");

        assert!(store.delete("/repo", "/repo/.env"));
        assert!(store.find("/repo", "/repo/.env").is_none());
    }
}
