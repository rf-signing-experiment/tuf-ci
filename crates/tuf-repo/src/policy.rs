//! What this project adds to TUF, and where it is kept.
//!
//! TUF says who may sign a role and how many of them are needed. It says nothing about who
//! holds a key, where an automated signer reaches one, or how long a role's word should be
//! good for — all of which a repository administered through pull requests has to record
//! somewhere.
//!
//! It goes in one object at the root of each metadata document:
//!
//! ```json
//! {
//!   "_type": "root",
//!   "keys":  { "…": { "keytype": "ecdsa", … } },
//!   "roles": { "root": { "keyids": ["…"], "threshold": 1 } },
//!   "x-tuf-ci": {
//!     "signers": { "bd828d85…": "@arlosi" },
//!     "online":  { "6d1392ab…": "gcpkms:projects/…" },
//!     "periods": { "root": { "expiry-days": 365, "signing-days": 60 } }
//!   }
//! }
//! ```
//!
//! One block, at the top level, and never nested inside a key or a role. That is not a
//! stylistic choice: `additional_fields` on the four metadata types is the only place the
//! `tuf` crate preserves what it does not understand. A field written inside a key or a
//! role object is silently dropped the first time any tool round-trips the document, which
//! would lose the ownership record without anything failing.
//!
//! Keeping it inside the payload rather than in a file beside it also keeps it signed: how
//! long a role's metadata stays valid is part of what the delegating role's signers attest
//! to, and an unsigned file would let anyone with write access change it.

use std::collections::{BTreeMap, HashMap};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use tuf::crypto::KeyId;
use tuf::metadata::MetadataPath;

use crate::error::{Error, Result};

/// A role's name.
///
/// TUF calls this a metadata path, because it is also where the role's document lives.
/// This project only ever uses it as a name, so it is aliased to say so — and constructed
/// through [`role_name`], which is stricter than [`MetadataPath::new`] about separators.
pub type RoleName = MetadataPath;

/// The key this project's data is filed under in a metadata document's extra fields.
pub const POLICY_FIELD: &str = "x-tuf-ci";

// ---------------------------------------------------------------------------
// Role names
// ---------------------------------------------------------------------------

/// Parse a role name.
///
/// Stricter than [`MetadataPath::new`], which permits `a/b`: a role name is also a single
/// path component under `metadata/` and a single directory under `targets/`, so one
/// containing a separator would name files this repository could not read back.
pub fn role_name(name: &str) -> Result<MetadataPath> {
    if name.is_empty() {
        return Err(Error::invalid("role name is empty"));
    }
    if name.contains(['/', '\\']) || name == "." || name == ".." {
        return Err(Error::invalid(format!("invalid role name {name:?}")));
    }
    MetadataPath::new(name.to_owned()).map_err(|err| Error::invalid(err.to_string()))
}

/// Whether `role` is signed by an automated key rather than by people.
///
/// Online roles are re-signed on every publish, so they never take part in a signing event
/// and a change to one inside an event is an error.
pub fn is_online(role: &MetadataPath) -> bool {
    matches!(role.as_str(), "snapshot" | "timestamp")
}

/// Whether `role` is one of the four the root role delegates to directly.
pub fn is_top_level(role: &MetadataPath) -> bool {
    matches!(role.as_str(), "root" | "targets" | "snapshot" | "timestamp")
}

/// Whether `role` is a targets role: anything but `root`, `snapshot` and `timestamp`.
pub fn is_targets(role: &MetadataPath) -> bool {
    !is_online(role) && role.as_str() != "root"
}

// ---------------------------------------------------------------------------
// Periods
// ---------------------------------------------------------------------------

/// How long a role's metadata is valid, and how long before expiry it should be re-signed.
///
/// Both periods live on the delegating role rather than on the delegate's own metadata, so
/// that one document says everything about a delegation: who may sign it, how many of them
/// are needed, and for how long the result is good.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Periods {
    /// Days from signing until the metadata expires.
    #[serde(rename = "expiry-days")]
    pub expiry_days: u32,
    /// Days before expiry at which a new signing event should start.
    #[serde(rename = "signing-days")]
    pub signing_days: u32,
}

impl Periods {
    /// The expiry timestamp for metadata signed at `now`.
    ///
    /// Truncated to the second, because that is the precision the metadata format records
    /// and a value that does not survive its own round trip breaks equality comparisons.
    pub fn expires_at(&self, now: DateTime<Utc>) -> DateTime<Utc> {
        let expires = now + Duration::days(i64::from(self.expiry_days));
        expires - Duration::nanoseconds(i64::from(expires.timestamp_subsec_nanos()))
    }

    /// Reject periods that leave no time to gather signatures.
    pub fn validate(&self, role: &MetadataPath) -> Result<()> {
        if self.expiry_days == 0 {
            return Err(Error::invalid(format!(
                "{role} would expire the moment it was signed"
            )));
        }
        if self.signing_days == 0 {
            return Err(Error::invalid(format!(
                "{role} leaves no time to re-sign before it expires"
            )));
        }
        if self.signing_days >= self.expiry_days {
            return Err(Error::invalid(format!(
                "{role} starts re-signing after {} days but expires after {}, so a signing \
                 event would never close",
                self.signing_days, self.expiry_days
            )));
        }
        Ok(())
    }
}

/// The periods a role gets when nothing has configured it yet.
pub const DEFAULT_PERIODS: Periods = Periods {
    expiry_days: 365,
    signing_days: 60,
};

// ---------------------------------------------------------------------------
// The policy block
// ---------------------------------------------------------------------------

/// This project's additions to a metadata document.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    /// Who holds each offline key, as an `@`-prefixed GitHub handle.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub signers: BTreeMap<KeyId, String>,
    /// Where an automated signer can reach each online key, e.g. a cloud KMS URI.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub online: BTreeMap<KeyId, String>,
    /// Validity and re-signing periods, keyed by the role they apply to.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub periods: BTreeMap<String, Periods>,
}

impl Policy {
    /// Read the policy out of a document's extra fields.
    ///
    /// A document with no block at all is not an error: it is what any TUF metadata written
    /// by something other than this tool looks like, and it reads as a repository nobody
    /// has recorded anything about yet.
    pub fn read(extra: &HashMap<String, serde_json::Value>) -> Result<Self> {
        match extra.get(POLICY_FIELD) {
            None => Ok(Policy::default()),
            Some(value) => serde_json::from_value(value.clone())
                .map_err(|err| Error::invalid(format!("{POLICY_FIELD}: {err}"))),
        }
    }

    /// Write the policy into a document's extra fields, removing it when it says nothing.
    pub fn write(&self, extra: &mut HashMap<String, serde_json::Value>) -> Result<()> {
        if *self == Policy::default() {
            extra.remove(POLICY_FIELD);
            return Ok(());
        }
        extra.insert(POLICY_FIELD.to_owned(), serde_json::to_value(self)?);
        Ok(())
    }

    /// Who or what signs with `key_id`: an `@handle`, an online signer's URI, or neither.
    ///
    /// Used wherever a signer has to be named to a person.
    pub fn signer_name(&self, key_id: &KeyId) -> String {
        self.signers
            .get(key_id)
            .or_else(|| self.online.get(key_id))
            .cloned()
            .unwrap_or_else(|| format!("<unattributed key {}>", crate::crypto::abbreviated(key_id)))
    }

    /// The periods configured for `role`, or the defaults.
    pub fn periods(&self, role: &MetadataPath) -> Periods {
        self.periods
            .get(role.as_str())
            .copied()
            .unwrap_or(DEFAULT_PERIODS)
    }

    /// Set the periods for `role`.
    pub fn set_periods(&mut self, role: &MetadataPath, periods: Periods) {
        self.periods.insert(role.as_str().to_owned(), periods);
    }

    /// Forget everything recorded about keys no longer present in `keys`.
    pub fn retain_keys<'a>(&mut self, keys: impl Iterator<Item = &'a KeyId>) {
        let live: std::collections::BTreeSet<&KeyId> = keys.collect();
        self.signers.retain(|key_id, _| live.contains(key_id));
        self.online.retain(|key_id, _| live.contains(key_id));
    }
}

// ---------------------------------------------------------------------------
// Role configuration
// ---------------------------------------------------------------------------

/// Who may sign a role, how many of them are needed, and for how long the result is good.
///
/// This is what a person asks for. It becomes metadata only once every signer named here
/// has contributed a key; until then it waits in the signing event's state file, because
/// metadata naming a threshold it has no keys to meet is not valid metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleConfig {
    /// The signers, as `@handle`s.
    pub signers: Vec<String>,
    /// How many of them must sign.
    pub threshold: u32,
    /// Validity and re-signing periods.
    pub periods: Periods,
}

impl RoleConfig {
    /// Reject a configuration that could never be satisfied.
    pub fn validate(&self, role: &MetadataPath) -> Result<()> {
        if self.signers.is_empty() {
            return Err(Error::invalid(format!(
                "{role} must have at least one signer"
            )));
        }
        let unique: std::collections::BTreeSet<&String> = self.signers.iter().collect();
        if unique.len() != self.signers.len() {
            return Err(Error::invalid(format!("{role} lists a signer twice")));
        }
        if self.threshold < 1 {
            return Err(Error::invalid(format!(
                "{role} threshold must be at least 1"
            )));
        }
        if self.threshold as usize > self.signers.len() {
            return Err(Error::invalid(format!(
                "{role} needs {} signatures but has only {} signers",
                self.threshold,
                self.signers.len()
            )));
        }
        self.periods.validate(role)
    }
}

// ---------------------------------------------------------------------------
// Delegation paths
// ---------------------------------------------------------------------------

/// How many directory levels below its own directory a delegated role owns.
///
/// `targets/<role>/a/b/c/d/file` is owned by `<role>`; a fifth level is not.
pub const MAX_DELEGATION_DEPTH: usize = 4;

/// The artifact path patterns for a role that owns `targets/<role>/` and
/// [`MAX_DELEGATION_DEPTH`] levels below it.
pub fn default_paths(role: &MetadataPath) -> Vec<String> {
    let mut pattern = format!("{role}/*");
    let mut paths = Vec::with_capacity(MAX_DELEGATION_DEPTH);
    for _ in 0..MAX_DELEGATION_DEPTH {
        paths.push(pattern.clone());
        pattern.push_str("/*");
    }
    paths
}

/// Whether `path` matches a delegation path pattern.
///
/// `*` matches within one path component and never across a `/`, so `crates/*` covers
/// `crates/serde` but not `crates/se/rde`. That is why [`default_paths`] lists one pattern
/// per directory level rather than a single recursive one: the depth a role owns is
/// explicit in its metadata rather than implied by the matcher.
pub fn path_matches(pattern: &str, path: &str) -> bool {
    let mut pattern_parts = pattern.split('/');
    let mut path_parts = path.split('/');
    loop {
        match (pattern_parts.next(), path_parts.next()) {
            (None, None) => return true,
            (Some(pattern), Some(part)) if component_matches(pattern, part) => {}
            _ => return false,
        }
    }
}

/// Whether one path component matches one pattern component, where `*` matches any run of
/// characters that is not a separator.
fn component_matches(pattern: &str, component: &str) -> bool {
    let sections: Vec<&str> = pattern.split('*').collect();
    let Some((last, leading)) = sections.split_last() else {
        return pattern == component;
    };
    if leading.is_empty() {
        return pattern == component;
    }

    let mut rest = component;
    let Some(first) = leading.first() else {
        return false;
    };
    if !rest.starts_with(first) {
        return false;
    }
    rest = &rest[first.len()..];

    for section in &leading[1..] {
        match rest.find(section) {
            Some(index) => rest = &rest[index + section.len()..],
            None => return false,
        }
    }

    rest.len() >= last.len() && rest.ends_with(last)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_names_reject_path_traversal() {
        assert!(role_name("..").is_err());
        assert!(role_name("a/b").is_err());
        assert!(role_name("").is_err());
        assert_eq!(role_name("crates").unwrap().as_str(), "crates");
    }

    #[test]
    fn role_classification() {
        assert!(is_online(&MetadataPath::snapshot()));
        assert!(is_online(&MetadataPath::timestamp()));
        assert!(!is_online(&MetadataPath::root()));
        assert!(is_targets(&MetadataPath::targets()));
        assert!(is_targets(&role_name("crates").unwrap()));
        assert!(!is_targets(&MetadataPath::root()));
        assert!(!is_top_level(&role_name("crates").unwrap()));
    }

    #[test]
    fn the_policy_block_round_trips_through_extra_fields() {
        let mut policy = Policy::default();
        policy
            .signers
            .insert("abc123".parse().unwrap(), "@arlosi".into());
        policy.set_periods(&MetadataPath::root(), DEFAULT_PERIODS);

        let mut extra = HashMap::new();
        policy.write(&mut extra).unwrap();
        assert_eq!(Policy::read(&extra).unwrap(), policy);
    }

    #[test]
    fn an_empty_policy_writes_no_field_at_all() {
        // Otherwise every document this tool touches would grow an empty object, which is
        // noise in a diff a human has to read before signing.
        let mut extra = HashMap::new();
        extra.insert(POLICY_FIELD.to_owned(), serde_json::json!({"signers": {}}));
        Policy::default().write(&mut extra).unwrap();
        assert!(!extra.contains_key(POLICY_FIELD));
    }

    #[test]
    fn metadata_written_by_another_tool_reads_as_an_empty_policy() {
        assert_eq!(Policy::read(&HashMap::new()).unwrap(), Policy::default());
    }

    #[test]
    fn default_paths_cover_the_documented_depth() {
        assert_eq!(
            default_paths(&role_name("crates").unwrap()),
            ["crates/*", "crates/*/*", "crates/*/*/*", "crates/*/*/*/*"],
        );
    }

    #[test]
    fn wildcards_do_not_cross_directory_separators() {
        assert!(path_matches("crates/*", "crates/serde"));
        assert!(!path_matches("crates/*", "crates/se/rde"));
        assert!(path_matches("crates/*/*", "crates/se/rde"));
        assert!(!path_matches("crates/*", "other/serde"));
    }

    #[test]
    fn wildcards_match_within_a_component() {
        assert!(path_matches("*.txt", "notes.txt"));
        assert!(path_matches("v*-final", "v2-final"));
        assert!(!path_matches("*.txt", "notes.md"));
        assert!(path_matches("*", "anything"));
    }

    #[test]
    fn periods_reject_configurations_that_cannot_be_signed() {
        let role = MetadataPath::root();
        assert!(DEFAULT_PERIODS.validate(&role).is_ok());
        assert!(
            Periods {
                expiry_days: 0,
                signing_days: 0
            }
            .validate(&role)
            .is_err()
        );
        assert!(
            Periods {
                expiry_days: 30,
                signing_days: 30
            }
            .validate(&role)
            .is_err()
        );
    }

    #[test]
    fn an_expiry_survives_its_own_round_trip() {
        // The metadata format records seconds. An expiry carrying nanoseconds would not
        // equal itself once written and read back, which is how a role starts looking
        // changed when nothing changed it.
        let now = Utc::now();
        let expires = DEFAULT_PERIODS.expires_at(now);
        assert_eq!(expires.timestamp_subsec_nanos(), 0);
    }
}
