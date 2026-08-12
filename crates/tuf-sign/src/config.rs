//! Per-signer configuration.
//!
//! Lives at `.tuf-ci.toml` in the repository root: it is about one person's clone, not
//! about the repository, so the first time it is written the tool also adds it to
//! `.git/info/exclude`. That keeps it out of commits without needing an entry in a
//! `.gitignore` that everybody shares.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// The configuration file's name, relative to the repository root.
pub const CONFIG_FILE: &str = ".tuf-ci.toml";

/// One signer's settings for one clone.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    /// Who this signer is.
    pub user: User,
    /// Which remotes to read from and write to.
    #[serde(default)]
    pub git: GitRemotes,
    /// Which YubiKey to use, when more than one is ever plugged in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub yubikey: Option<Yubikey>,
}

/// Who the signer is.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    /// The signer's GitHub handle, always `@`-prefixed and lower-cased.
    pub name: String,
}

/// Which remotes the signing tool talks to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct GitRemotes {
    /// The remote holding the TUF repository.
    pub pull_remote: String,
    /// Where to push signatures. A fork, for signers without write access.
    pub push_remote: String,
}

impl Default for GitRemotes {
    fn default() -> Self {
        GitRemotes {
            pull_remote: "origin".into(),
            push_remote: "origin".into(),
        }
    }
}

/// Which YubiKey to sign with.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Yubikey {
    /// The serial number, for signers who keep more than one plugged in.
    pub serial: u32,
}

impl Config {
    /// The configuration file's path within `root`.
    pub fn path(root: &Path) -> PathBuf {
        root.join(CONFIG_FILE)
    }

    /// Read the configuration, or `None` if it has not been written yet.
    pub fn load(root: &Path) -> Result<Option<Self>> {
        let path = Self::path(root);
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err).with_context(|| format!("reading {}", path.display())),
        };
        let config: Config = toml::from_str(&text)
            .with_context(|| format!("{} is not valid configuration", path.display()))?;
        config.validate()?;
        Ok(Some(config))
    }

    /// Write the configuration, and keep it out of git.
    pub fn save(&self, root: &Path) -> Result<()> {
        self.validate()?;
        let path = Self::path(root);
        let text = toml::to_string_pretty(self).context("could not encode the configuration")?;
        std::fs::write(&path, text).with_context(|| format!("writing {}", path.display()))?;
        exclude_from_git(root)?;
        Ok(())
    }

    fn validate(&self) -> Result<()> {
        if !self.user.name.starts_with('@') || self.user.name.len() < 2 {
            bail!(
                "user name {:?} should be a GitHub handle such as \"@octocat\"",
                self.user.name
            );
        }
        Ok(())
    }

    /// Whether signatures are pushed somewhere other than where they are read from, which
    /// is how a signer without write access to the repository contributes.
    pub fn signs_via_fork(&self) -> bool {
        self.git.push_remote != self.git.pull_remote
    }
}

/// Normalise a handle the way it is written into metadata: `@`-prefixed and lower-case.
///
/// Metadata records the handle, and the tool matches on it to decide whose signature is
/// wanted, so `Alice`, `alice` and `@alice` all have to name the same person.
pub fn normalize_handle(raw: &str) -> String {
    let trimmed = raw.trim().trim_start_matches('@').to_lowercase();
    format!("@{trimmed}")
}

/// Add the configuration file to this clone's private exclude list.
fn exclude_from_git(root: &Path) -> Result<()> {
    let exclude = root.join(".git").join("info").join("exclude");
    // A worktree's `.git` is a file, not a directory; in that case there is nothing local
    // to write to and the caller is not the place the config lives anyway.
    if !exclude.parent().is_some_and(Path::is_dir) {
        return Ok(());
    }

    let existing = std::fs::read_to_string(&exclude).unwrap_or_default();
    if existing.lines().any(|line| line.trim() == CONFIG_FILE) {
        return Ok(());
    }

    let mut updated = existing;
    if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push_str(&format!(
        "\n# Personal tuf-sign settings; not shared with the repository.\n{CONFIG_FILE}\n"
    ));
    std::fs::write(&exclude, updated).with_context(|| format!("writing {}", exclude.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles_are_normalised_to_one_spelling() {
        assert_eq!(normalize_handle("Alice"), "@alice");
        assert_eq!(normalize_handle("@Alice"), "@alice");
        assert_eq!(normalize_handle("  @alice  "), "@alice");
        assert_eq!(normalize_handle("@@alice"), "@alice");
    }

    #[test]
    fn configuration_round_trips() {
        let config = Config {
            user: User {
                name: "@arlosi".into(),
            },
            git: GitRemotes {
                pull_remote: "upstream".into(),
                push_remote: "origin".into(),
            },
            yubikey: Some(Yubikey { serial: 12345678 }),
        };
        let text = toml::to_string_pretty(&config).unwrap();
        assert_eq!(toml::from_str::<Config>(&text).unwrap(), config);
        assert!(config.signs_via_fork());
    }

    #[test]
    fn remotes_default_to_origin() {
        let config: Config = toml::from_str("[user]\nname = \"@arlosi\"\n").unwrap();
        assert_eq!(config.git.pull_remote, "origin");
        assert_eq!(config.git.push_remote, "origin");
        assert!(!config.signs_via_fork());
    }

    #[test]
    fn a_bare_username_is_rejected_rather_than_silently_mismatched() {
        let config: Config = toml::from_str("[user]\nname = \"arlosi\"\n").unwrap();
        assert!(config.validate().is_err());
    }
}
