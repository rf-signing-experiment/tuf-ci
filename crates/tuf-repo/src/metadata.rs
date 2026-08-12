//! The TUF metadata model.
//!
//! Every struct here carries an [`Extra`] map of fields it did not recognise, and writes
//! them back out untouched. That matters in a repository where several people run several
//! versions of the tool: a signer on an older release must not silently delete a field a
//! newer release wrote, because doing so would invalidate everyone else's signatures.
//!
//! Fields this project defines are named rather than left in `Extra`, and all use the
//! `x-tuf-ci-` prefix that the TUF spec reserves for implementation extensions.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Duration, Utc};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::crypto::{self, KeyId};
use crate::error::{Error, Result};

/// The TUF specification version this crate writes.
pub const SPEC_VERSION: &str = "1.0.31";

/// Fields of a metadata object that this version of the crate does not know about.
///
/// They are preserved verbatim across a load/store cycle.
pub type Extra = BTreeMap<String, Value>;

// ---------------------------------------------------------------------------
// Role names
// ---------------------------------------------------------------------------

/// The name of a role: one of the four top-level roles, or a delegated targets role.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RoleName(String);

impl RoleName {
    /// The top-level `root` role.
    pub fn root() -> Self {
        RoleName("root".into())
    }

    /// The top-level `targets` role.
    pub fn targets() -> Self {
        RoleName("targets".into())
    }

    /// The top-level `snapshot` role.
    pub fn snapshot() -> Self {
        RoleName("snapshot".into())
    }

    /// The top-level `timestamp` role.
    pub fn timestamp() -> Self {
        RoleName("timestamp".into())
    }

    /// The name as it appears in metadata and as the metadata file's stem.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this role is signed by an automated key rather than by people.
    ///
    /// Online roles are re-signed on every publish, so they never take part in a signing
    /// event and a change to one inside an event is an error.
    pub fn is_online(&self) -> bool {
        matches!(self.0.as_str(), "snapshot" | "timestamp")
    }

    /// Whether this role is one of the four the root role delegates to directly.
    pub fn is_top_level(&self) -> bool {
        matches!(
            self.0.as_str(),
            "root" | "targets" | "snapshot" | "timestamp"
        )
    }

    /// Whether this is a targets role, i.e. anything but `root`, `snapshot` and
    /// `timestamp`.
    pub fn is_targets(&self) -> bool {
        !self.is_online() && self.0 != "root"
    }
}

impl FromStr for RoleName {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        if s.is_empty() {
            return Err(Error::invalid("role name is empty"));
        }
        // The name becomes a path component under `metadata/` and `targets/`.
        if s.contains(['/', '\\']) || s == "." || s == ".." {
            return Err(Error::invalid(format!("invalid role name {s:?}")));
        }
        Ok(RoleName(s.to_owned()))
    }
}

impl fmt::Display for RoleName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for RoleName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

/// A public key, as it appears in a delegating role's key set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Key {
    /// The key algorithm family, e.g. `ecdsa`.
    pub keytype: String,
    /// The signature scheme, e.g. `ecdsa-sha2-nistp256`.
    pub scheme: String,
    /// The key material.
    pub keyval: KeyVal,
    /// The person who holds this key, as an `@`-prefixed GitHub handle.
    ///
    /// Absent for online keys, which have an [`online_uri`](Self::online_uri) instead.
    #[serde(
        rename = "x-tuf-ci-owner",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub owner: Option<String>,
    /// Where an automated signer can reach this key, e.g. a cloud KMS URI.
    #[serde(
        rename = "x-tuf-ci-online-uri",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub online_uri: Option<String>,
    /// Fields this version of the crate does not recognise.
    #[serde(flatten)]
    pub extra: Extra,
}

/// The `keyval` of a [`Key`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyVal {
    /// A PEM-encoded `SubjectPublicKeyInfo`, as POUF-2 requires of every key type.
    pub public: String,
    /// Fields this version of the crate does not recognise.
    #[serde(flatten)]
    pub extra: Extra,
}

impl Key {
    /// Build an offline signer's key from a PEM `SubjectPublicKeyInfo`.
    ///
    /// Returns the key alongside the [`KeyId`] it will be filed under.
    pub fn from_pem(pem: &str, owner: &str) -> Result<(KeyId, Key)> {
        let key_id = KeyId::for_pem(pem)?;
        let key = Key {
            keytype: crypto::KEYTYPE_ECDSA.into(),
            scheme: crypto::ECDSA_SHA2_NISTP256.into(),
            keyval: KeyVal {
                public: pem.to_owned(),
                extra: Extra::new(),
            },
            owner: Some(owner.to_owned()),
            online_uri: None,
            extra: Extra::new(),
        };
        Ok((key_id, key))
    }

    /// Build an automated signer's key from a PEM `SubjectPublicKeyInfo` and the URI an
    /// automated signer can reach the private half at.
    pub fn online(pem: &str, uri: &str) -> Result<(KeyId, Key)> {
        let (key_id, mut key) = Key::from_pem(pem, "")?;
        key.owner = None;
        key.online_uri = Some(uri.to_owned());
        Ok((key_id, key))
    }

    /// Who or what signs with this key: an `@handle`, or an online signer's URI.
    ///
    /// Used wherever a signer has to be named to a human.
    pub fn signer_name(&self) -> &str {
        self.owner
            .as_deref()
            .or(self.online_uri.as_deref())
            .unwrap_or("<unattributed key>")
    }

    /// Verify `signature` over `message` with this key.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        crypto::verify(&self.scheme, &self.keyval.public, message, signature)
    }
}

// ---------------------------------------------------------------------------
// Role definitions
// ---------------------------------------------------------------------------

/// How long a role's metadata is valid, and how long before expiry it should be re-signed.
///
/// Both periods live on the delegating role rather than on the delegate's own metadata, so
/// that one document says everything about a delegation: who may sign it, how many of them
/// are needed, and for how long the result is good.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Periods {
    /// Days from signing until the metadata expires.
    pub expiry_days: u32,
    /// Days before expiry at which a new signing event should start.
    pub signing_days: u32,
}

impl Periods {
    /// The expiry timestamp for metadata signed at `now`.
    pub fn expires_at(&self, now: DateTime<Utc>) -> DateTime<Utc> {
        now + Duration::days(i64::from(self.expiry_days))
    }

    /// Whether metadata expiring at `expires` has entered its signing period by `now`.
    pub fn in_signing_period(&self, expires: DateTime<Utc>, now: DateTime<Utc>) -> bool {
        now >= expires - Duration::days(i64::from(self.signing_days))
    }

    /// Reject periods that would leave no time to sign, or no validity after signing.
    pub fn validate(&self, role: &RoleName) -> Result<()> {
        if self.signing_days < 1 {
            return Err(Error::invalid(format!(
                "{role} has a signing period of {} days, which leaves no time to sign",
                self.signing_days
            )));
        }
        if self.expiry_days <= self.signing_days {
            return Err(Error::invalid(format!(
                "{role} expires after {} days but starts signing {} days before that",
                self.expiry_days, self.signing_days
            )));
        }
        Ok(())
    }
}

/// A top-level role as defined in [`Root::roles`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Role {
    /// The keys permitted to sign this role.
    pub keyids: Vec<KeyId>,
    /// How many distinct keys from `keyids` must sign.
    pub threshold: u32,
    /// Days from signing until this role's metadata expires.
    #[serde(rename = "x-tuf-ci-expiry-days")]
    pub expiry_days: u32,
    /// Days before expiry at which a new signing event should start.
    #[serde(rename = "x-tuf-ci-signing-days")]
    pub signing_days: u32,
    /// Fields this version of the crate does not recognise.
    #[serde(flatten)]
    pub extra: Extra,
}

/// A targets role delegated by another targets role.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegatedRole {
    /// The role's name, which is also its metadata filename and its artifact directory.
    pub name: RoleName,
    /// The keys permitted to sign this role.
    pub keyids: Vec<KeyId>,
    /// How many distinct keys from `keyids` must sign.
    pub threshold: u32,
    /// Artifact path patterns this role is responsible for.
    pub paths: Vec<String>,
    /// Whether a match here ends the delegation search.
    pub terminating: bool,
    /// Days from signing until this role's metadata expires.
    #[serde(rename = "x-tuf-ci-expiry-days")]
    pub expiry_days: u32,
    /// Days before expiry at which a new signing event should start.
    #[serde(rename = "x-tuf-ci-signing-days")]
    pub signing_days: u32,
    /// Fields this version of the crate does not recognise.
    #[serde(flatten)]
    pub extra: Extra,
}

/// How many directory levels below its own directory a delegated role owns.
///
/// `targets/<role>/a/b/c/d/file` is owned by `<role>`; a fifth level is not.
pub const MAX_DELEGATION_DEPTH: usize = 4;

/// The artifact path patterns for a role that owns `targets/<role>/` and
/// [`MAX_DELEGATION_DEPTH`] levels below it.
pub fn default_paths(role: &RoleName) -> Vec<String> {
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
/// characters within the component.
fn component_matches(pattern: &str, component: &str) -> bool {
    let mut sections = pattern.split('*');
    let first = sections.next().expect("split yields at least one section");
    let Some(mut rest) = component.strip_prefix(first) else {
        return false;
    };

    let sections: Vec<&str> = sections.collect();
    let Some((last, middle)) = sections.split_last() else {
        // No wildcard at all: the prefix had to be the whole component.
        return rest.is_empty();
    };

    for section in middle {
        match rest.find(section) {
            Some(at) => rest = &rest[at + section.len()..],
            None => return false,
        }
    }

    // The trailing section must reach the end without re-consuming what came before it.
    rest.len() >= last.len() && rest.ends_with(last)
}

/// What a delegating role says about one of its delegates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoleSpec<'a> {
    /// The keys permitted to sign the delegate.
    pub keyids: &'a [KeyId],
    /// How many distinct keys must sign.
    pub threshold: u32,
    /// Validity and re-signing periods.
    pub periods: Periods,
}

impl Role {
    fn spec(&self) -> RoleSpec<'_> {
        RoleSpec {
            keyids: &self.keyids,
            threshold: self.threshold,
            periods: Periods {
                expiry_days: self.expiry_days,
                signing_days: self.signing_days,
            },
        }
    }
}

impl DelegatedRole {
    fn spec(&self) -> RoleSpec<'_> {
        RoleSpec {
            keyids: &self.keyids,
            threshold: self.threshold,
            periods: Periods {
                expiry_days: self.expiry_days,
                signing_days: self.signing_days,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Payloads
// ---------------------------------------------------------------------------

/// The behaviour common to the four kinds of metadata payload.
pub trait Payload: Serialize + DeserializeOwned + Clone + PartialEq + fmt::Debug {
    /// The value of the payload's `_type` field.
    const TYPE: &'static str;

    /// The metadata version.
    fn version(&self) -> u64;
    /// Set the metadata version.
    fn set_version(&mut self, version: u64);
    /// When this metadata stops being valid.
    fn expires(&self) -> DateTime<Utc>;
    /// Set when this metadata stops being valid.
    fn set_expires(&mut self, expires: DateTime<Utc>);
    /// The `_type` field as parsed, for checking it against [`Payload::TYPE`].
    fn declared_type(&self) -> &str;

    /// Check that the payload declares the type it was parsed as.
    fn check_type(&self) -> Result<()> {
        if self.declared_type() != Self::TYPE {
            return Err(Error::invalid(format!(
                "expected {:?} metadata but the payload says {:?}",
                Self::TYPE,
                self.declared_type()
            )));
        }
        Ok(())
    }
}

macro_rules! impl_payload {
    ($ty:ty, $name:literal) => {
        impl Payload for $ty {
            const TYPE: &'static str = $name;

            fn version(&self) -> u64 {
                self.version
            }
            fn set_version(&mut self, version: u64) {
                self.version = version;
            }
            fn expires(&self) -> DateTime<Utc> {
                self.expires
            }
            fn set_expires(&mut self, expires: DateTime<Utc>) {
                self.expires = expires;
            }
            fn declared_type(&self) -> &str {
                &self.typ
            }
        }
    };
}

/// The root role: the trust anchor, listing the keys of all four top-level roles.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Root {
    /// Always `"root"`.
    #[serde(rename = "_type")]
    pub typ: String,
    /// The TUF specification version this metadata conforms to.
    pub spec_version: String,
    /// The metadata version, which increases by exactly one per published root.
    pub version: u64,
    /// When this metadata stops being valid.
    #[serde(with = "crate::ser::datetime")]
    pub expires: DateTime<Utc>,
    /// Whether published metadata and artifacts are version- and hash-prefixed.
    pub consistent_snapshot: bool,
    /// Every key referenced by [`roles`](Self::roles).
    pub keys: BTreeMap<KeyId, Key>,
    /// The four top-level roles.
    pub roles: BTreeMap<RoleName, Role>,
    /// Fields this version of the crate does not recognise.
    #[serde(flatten)]
    pub extra: Extra,
}

impl_payload!(Root, "root");

impl Root {
    /// An empty root delegating to the four top-level roles, but to no keys yet.
    ///
    /// Version zero and an immediate expiry are placeholders: both are set properly when
    /// the metadata is first written, from the known-good version and the configured
    /// periods.
    pub fn empty(now: DateTime<Utc>, periods: Periods) -> Self {
        let role = || Role {
            keyids: Vec::new(),
            threshold: 1,
            expiry_days: periods.expiry_days,
            signing_days: periods.signing_days,
            extra: Extra::new(),
        };
        Root {
            typ: Self::TYPE.into(),
            spec_version: SPEC_VERSION.into(),
            version: 0,
            expires: now,
            consistent_snapshot: true,
            keys: BTreeMap::new(),
            roles: BTreeMap::from([
                (RoleName::root(), role()),
                (RoleName::targets(), role()),
                (RoleName::snapshot(), role()),
                (RoleName::timestamp(), role()),
            ]),
            extra: Extra::new(),
        }
    }

    /// Add `key` to the key set and permit it to sign `role`.
    pub fn authorize(&mut self, role: &RoleName, key_id: KeyId, key: Key) -> Result<()> {
        let entry = self
            .roles
            .get_mut(role)
            .ok_or_else(|| Error::NoSuchRole(role.to_string()))?;
        if !entry.keyids.contains(&key_id) {
            entry.keyids.push(key_id.clone());
            entry.keyids.sort();
        }
        self.keys.insert(key_id, key);
        Ok(())
    }

    /// Stop `key_id` from signing `role`, and drop the key if nothing else uses it.
    pub fn revoke(&mut self, role: &RoleName, key_id: &KeyId) {
        if let Some(entry) = self.roles.get_mut(role) {
            entry.keyids.retain(|id| id != key_id);
        }
        self.collect_unused_keys();
    }

    /// Drop keys no role refers to any more.
    pub fn collect_unused_keys(&mut self) {
        let in_use: std::collections::BTreeSet<&KeyId> =
            self.roles.values().flat_map(|role| &role.keyids).collect();
        let unused: Vec<KeyId> = self
            .keys
            .keys()
            .filter(|key_id| !in_use.contains(key_id))
            .cloned()
            .collect();
        for key_id in unused {
            self.keys.remove(&key_id);
        }
    }
}

/// A targets role: the artifacts it vouches for, and the roles it delegates to.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Targets {
    /// Always `"targets"`, for the top-level role and every delegate alike.
    #[serde(rename = "_type")]
    pub typ: String,
    /// The TUF specification version this metadata conforms to.
    pub spec_version: String,
    /// The metadata version.
    pub version: u64,
    /// When this metadata stops being valid.
    #[serde(with = "crate::ser::datetime")]
    pub expires: DateTime<Utc>,
    /// The artifacts this role vouches for, keyed by path relative to `targets/`.
    pub targets: BTreeMap<String, TargetFile>,
    /// The roles this one delegates to. Absent when it delegates to none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegations: Option<Delegations>,
    /// Fields this version of the crate does not recognise.
    #[serde(flatten)]
    pub extra: Extra,
}

impl_payload!(Targets, "targets");

impl Targets {
    /// An empty targets role, vouching for nothing and delegating to nobody.
    pub fn empty(now: DateTime<Utc>) -> Self {
        Targets {
            typ: Self::TYPE.into(),
            spec_version: SPEC_VERSION.into(),
            version: 0,
            expires: now,
            targets: BTreeMap::new(),
            delegations: None,
            extra: Extra::new(),
        }
    }

    /// The delegation to `role`, if there is one.
    pub fn delegation(&self, role: &RoleName) -> Option<&DelegatedRole> {
        self.delegations
            .as_ref()?
            .roles
            .iter()
            .find(|delegated| &delegated.name == role)
    }

    /// The delegation to `role`, creating it with default paths if it is new.
    pub fn delegation_mut(&mut self, role: &RoleName, periods: Periods) -> &mut DelegatedRole {
        let delegations = self.delegations.get_or_insert_with(|| Delegations {
            keys: BTreeMap::new(),
            roles: Vec::new(),
            extra: Extra::new(),
        });

        if let Some(index) = delegations
            .roles
            .iter()
            .position(|delegated| &delegated.name == role)
        {
            return &mut delegations.roles[index];
        }

        delegations.roles.push(DelegatedRole {
            name: role.clone(),
            keyids: Vec::new(),
            threshold: 1,
            paths: default_paths(role),
            terminating: true,
            expiry_days: periods.expiry_days,
            signing_days: periods.signing_days,
            extra: Extra::new(),
        });
        // Keep delegations ordered by name so that adding one produces a diff showing
        // only that delegation, whatever order events happen to be merged in.
        delegations.roles.sort_by(|a, b| a.name.cmp(&b.name));
        delegations
            .roles
            .iter_mut()
            .find(|delegated| &delegated.name == role)
            .expect("just inserted")
    }

    /// Add `key` to the delegation key set and permit it to sign `role`.
    pub fn authorize(
        &mut self,
        role: &RoleName,
        key_id: KeyId,
        key: Key,
        periods: Periods,
    ) -> Result<()> {
        let delegated = self.delegation_mut(role, periods);
        if !delegated.keyids.contains(&key_id) {
            delegated.keyids.push(key_id.clone());
            delegated.keyids.sort();
        }
        self.delegations
            .as_mut()
            .expect("delegation_mut created it")
            .keys
            .insert(key_id, key);
        Ok(())
    }

    /// Stop `key_id` from signing `role`, and drop the key if nothing else uses it.
    pub fn revoke(&mut self, role: &RoleName, key_id: &KeyId) {
        let Some(delegations) = self.delegations.as_mut() else {
            return;
        };
        if let Some(delegated) = delegations
            .roles
            .iter_mut()
            .find(|delegated| &delegated.name == role)
        {
            delegated.keyids.retain(|id| id != key_id);
        }
        collect_unused_delegation_keys(delegations);
    }

    /// Remove the delegation to `role` entirely.
    ///
    /// Returns whether there was one to remove.
    pub fn remove_delegation(&mut self, role: &RoleName) -> bool {
        let Some(delegations) = self.delegations.as_mut() else {
            return false;
        };
        let before = delegations.roles.len();
        delegations
            .roles
            .retain(|delegated| &delegated.name != role);
        if delegations.roles.len() == before {
            return false;
        }
        collect_unused_delegation_keys(delegations);
        // An empty delegations object says the same thing as no delegations object, so
        // write the simpler of the two.
        if delegations.roles.is_empty() && delegations.keys.is_empty() {
            self.delegations = None;
        }
        true
    }
}

fn collect_unused_delegation_keys(delegations: &mut Delegations) {
    let in_use: std::collections::BTreeSet<&KeyId> = delegations
        .roles
        .iter()
        .flat_map(|role| &role.keyids)
        .collect();
    let unused: Vec<KeyId> = delegations
        .keys
        .keys()
        .filter(|key_id| !in_use.contains(key_id))
        .cloned()
        .collect();
    for key_id in unused {
        delegations.keys.remove(&key_id);
    }
}

/// The delegations of a [`Targets`] role.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delegations {
    /// Every key referenced by [`roles`](Self::roles).
    pub keys: BTreeMap<KeyId, Key>,
    /// The delegated roles, in the order they are searched.
    pub roles: Vec<DelegatedRole>,
    /// Fields this version of the crate does not recognise.
    #[serde(flatten)]
    pub extra: Extra,
}

/// One artifact vouched for by a targets role.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetFile {
    /// The artifact's size in bytes.
    pub length: u64,
    /// Digests of the artifact, keyed by algorithm name.
    pub hashes: BTreeMap<String, String>,
    /// Application-defined data attached to the artifact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom: Option<Value>,
    /// Fields this version of the crate does not recognise.
    #[serde(flatten)]
    pub extra: Extra,
}

impl TargetFile {
    /// Describe the artifact held in `bytes`.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        TargetFile {
            length: bytes.len() as u64,
            hashes: BTreeMap::from([("sha256".to_owned(), crypto::sha256_hex(bytes))]),
            custom: None,
            extra: Extra::new(),
        }
    }
}

/// The snapshot role: the version of every targets metadata file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    /// Always `"snapshot"`.
    #[serde(rename = "_type")]
    pub typ: String,
    /// The TUF specification version this metadata conforms to.
    pub spec_version: String,
    /// The metadata version.
    pub version: u64,
    /// When this metadata stops being valid.
    #[serde(with = "crate::ser::datetime")]
    pub expires: DateTime<Utc>,
    /// Every targets metadata file, keyed by filename.
    pub meta: BTreeMap<String, MetaFile>,
    /// Fields this version of the crate does not recognise.
    #[serde(flatten)]
    pub extra: Extra,
}

impl_payload!(Snapshot, "snapshot");

/// The timestamp role: the version of the current snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Timestamp {
    /// Always `"timestamp"`.
    #[serde(rename = "_type")]
    pub typ: String,
    /// The TUF specification version this metadata conforms to.
    pub spec_version: String,
    /// The metadata version.
    pub version: u64,
    /// When this metadata stops being valid.
    #[serde(with = "crate::ser::datetime")]
    pub expires: DateTime<Utc>,
    /// The current snapshot, under the key `snapshot.json`.
    pub meta: BTreeMap<String, MetaFile>,
    /// Fields this version of the crate does not recognise.
    #[serde(flatten)]
    pub extra: Extra,
}

impl_payload!(Timestamp, "timestamp");

/// A reference from one metadata file to another.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetaFile {
    /// The referenced metadata's version.
    pub version: u64,
    /// The referenced file's size in bytes, when recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length: Option<u64>,
    /// Digests of the referenced file, when recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hashes: Option<BTreeMap<String, String>>,
    /// Fields this version of the crate does not recognise.
    #[serde(flatten)]
    pub extra: Extra,
}

// ---------------------------------------------------------------------------
// Delegators
// ---------------------------------------------------------------------------

/// A role that defines the keys and threshold of other roles.
///
/// `root` delegates to the four top-level roles; a targets role delegates to the roles in
/// its `delegations`. Both answer the same two questions, so the signing-event logic can
/// treat them alike.
#[derive(Clone, Debug, PartialEq)]
pub enum Delegator {
    /// The root role, delegating to the top-level roles.
    Root(Root),
    /// A targets role, delegating to the roles named in its delegations.
    Targets(Targets),
}

impl Delegator {
    /// What this role says about its delegate `role`, if it delegates to it at all.
    pub fn role_spec(&self, role: &RoleName) -> Option<RoleSpec<'_>> {
        match self {
            Delegator::Root(root) => root.roles.get(role).map(Role::spec),
            Delegator::Targets(targets) => targets
                .delegations
                .as_ref()?
                .roles
                .iter()
                .find(|delegated| &delegated.name == role)
                .map(DelegatedRole::spec),
        }
    }

    /// Look up one of this role's keys.
    pub fn key(&self, key_id: &KeyId) -> Option<&Key> {
        match self {
            Delegator::Root(root) => root.keys.get(key_id),
            Delegator::Targets(targets) => targets.delegations.as_ref()?.keys.get(key_id),
        }
    }

    /// The keys permitted to sign `role`, in the order the delegation lists them.
    ///
    /// Key ids naming a key this delegator does not hold are skipped; such a delegation is
    /// unsatisfiable, which [`crate::event`] reports separately rather than by panicking
    /// here.
    pub fn keys_for(&self, role: &RoleName) -> Vec<(KeyId, &Key)> {
        let Some(spec) = self.role_spec(role) else {
            return Vec::new();
        };
        spec.keyids
            .iter()
            .filter_map(|key_id| self.key(key_id).map(|key| (key_id.clone(), key)))
            .collect()
    }

    /// The names of every role this one delegates to.
    pub fn delegated_roles(&self) -> Vec<RoleName> {
        match self {
            Delegator::Root(root) => root.roles.keys().cloned().collect(),
            Delegator::Targets(targets) => targets
                .delegations
                .as_ref()
                .map(|delegations| {
                    delegations
                        .roles
                        .iter()
                        .map(|role| role.name.clone())
                        .collect()
                })
                .unwrap_or_default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_names_reject_path_traversal() {
        assert!("..".parse::<RoleName>().is_err());
        assert!("a/b".parse::<RoleName>().is_err());
        assert!("".parse::<RoleName>().is_err());
        assert_eq!("crates".parse::<RoleName>().unwrap().as_str(), "crates");
    }

    #[test]
    fn role_name_classification() {
        assert!(RoleName::snapshot().is_online());
        assert!(RoleName::timestamp().is_online());
        assert!(!RoleName::root().is_online());
        assert!(RoleName::targets().is_targets());
        assert!("crates".parse::<RoleName>().unwrap().is_targets());
        assert!(!RoleName::root().is_targets());
        assert!(!"crates".parse::<RoleName>().unwrap().is_top_level());
    }

    #[test]
    fn default_paths_cover_the_documented_depth() {
        let role = "crates".parse::<RoleName>().unwrap();
        assert_eq!(
            default_paths(&role),
            ["crates/*", "crates/*/*", "crates/*/*/*", "crates/*/*/*/*"],
        );
    }

    #[test]
    fn periods_reject_configurations_that_cannot_be_signed() {
        let role = RoleName::root();
        assert!(
            Periods {
                expiry_days: 365,
                signing_days: 60
            }
            .validate(&role)
            .is_ok()
        );
        // No time to sign at all.
        assert!(
            Periods {
                expiry_days: 365,
                signing_days: 0
            }
            .validate(&role)
            .is_err()
        );
        // Signing starts before the previous version was even issued.
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
    fn wildcards_do_not_cross_directory_separators() {
        assert!(path_matches("crates/*", "crates/serde"));
        assert!(!path_matches("crates/*", "crates/se/rde"));
        assert!(path_matches("crates/*/*", "crates/se/rde"));
        assert!(!path_matches("crates/*", "crates"));
        assert!(!path_matches("crates/*", "other/serde"));
        // The top-level targets role owns only direct children.
        assert!(path_matches("*", "file.txt"));
        assert!(!path_matches("*", "dir/file.txt"));
    }

    #[test]
    fn wildcards_match_within_a_component() {
        assert!(path_matches("crates/se*", "crates/serde"));
        assert!(path_matches("crates/*rde", "crates/serde"));
        assert!(path_matches("crates/s*d*", "crates/serde"));
        assert!(!path_matches("crates/se*", "crates/tokio"));
        // A literal pattern still has to match in full.
        assert!(path_matches("crates/serde", "crates/serde"));
        assert!(!path_matches("crates/serd", "crates/serde"));
    }

    #[test]
    fn revoking_the_last_use_of_a_key_drops_it() {
        let periods = Periods {
            expiry_days: 365,
            signing_days: 60,
        };
        let mut root = Root::empty(Utc::now(), periods);
        let key_id = KeyId::from_str("abc").unwrap();
        let key = Key {
            keytype: "ecdsa".into(),
            scheme: "ecdsa-sha2-nistp256".into(),
            keyval: KeyVal {
                public: "pem".into(),
                extra: Extra::new(),
            },
            owner: Some("@arlosi".into()),
            online_uri: None,
            extra: Extra::new(),
        };

        root.authorize(&RoleName::root(), key_id.clone(), key.clone())
            .unwrap();
        root.authorize(&RoleName::targets(), key_id.clone(), key)
            .unwrap();
        assert_eq!(root.keys.len(), 1);

        // Still used by targets, so the key stays.
        root.revoke(&RoleName::root(), &key_id);
        assert_eq!(root.keys.len(), 1);

        root.revoke(&RoleName::targets(), &key_id);
        assert!(root.keys.is_empty());
    }

    #[test]
    fn removing_the_only_delegation_removes_the_delegations_object() {
        let periods = Periods {
            expiry_days: 365,
            signing_days: 60,
        };
        let role: RoleName = "crates".parse().unwrap();
        let mut targets = Targets::empty(Utc::now());
        targets.delegation_mut(&role, periods);
        assert!(targets.delegations.is_some());

        assert!(targets.remove_delegation(&role));
        assert!(targets.delegations.is_none());
        assert!(!targets.remove_delegation(&role));
    }

    #[test]
    fn unknown_fields_survive_a_round_trip() {
        let json = serde_json::json!({
            "keytype": "ecdsa",
            "scheme": "ecdsa-sha2-nistp256",
            "keyval": { "public": "pem", "x-future-field": 1 },
            "x-tuf-ci-owner": "@arlosi",
            "x-invented-later": { "nested": true },
        });
        let key: Key = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(key.owner.as_deref(), Some("@arlosi"));
        assert!(key.extra.contains_key("x-invented-later"));
        assert!(key.keyval.extra.contains_key("x-future-field"));
        assert_eq!(serde_json::to_value(&key).unwrap(), json);
    }
}
