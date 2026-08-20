//! Reading and writing a repository's files.
//!
//! Everything the state machine needs is behind [`Source`], which has two implementations:
//! [`FsSource`] reads the working tree, and [`GitSource`] reads a commit without checking
//! it out. That second one is why computing a signing event's status costs nothing: the
//! "known good" state a signing event is compared against is read straight out of the
//! merge-base commit, rather than by cloning the repository into a temporary directory.
//!
//! # Documents on disk
//!
//! A role is two files. `metadata/root.json` holds the payload — the exact bytes the
//! signatures cover — and `metadata/root.sig.json` holds the signatures. Keeping them
//! apart is what makes a signing event reviewable: adding a signature produces a diff
//! that touches four lines of one file, and a metadata change reads as JSON rather than
//! as a base64 blob.
//!
//! The two are one DSSE envelope, assembled at publish time by concatenation
//! ([`Signed::envelope`]) and never by re-serializing the payload. POUF-2 signs the
//! payload's exact bytes, so those bytes are frozen the moment they are authored: any
//! reformat, however harmless it looks, invalidates every signature already collected.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tuf::crypto::{KeyId, PublicKey, Signature, SignatureValue};
use tuf::metadata::{
    Delegation, Delegations, Metadata, MetadataPath, RoleDefinition, RootMetadata,
    SnapshotMetadata, TargetDescription, TargetPath, TargetsMetadata, TimestampMetadata,
};
use tuf::pouf::{Pouf, Pouf2};

use crate::error::{Error, Result};
use crate::policy::{self, Periods, Policy};
use crate::ser;

/// The directory holding metadata, relative to the repository root.
pub const METADATA_DIR: &str = "metadata";

/// The directory holding artifacts, relative to the repository root.
pub const TARGETS_DIR: &str = "targets";

/// The directory holding every published version of the root role.
pub const ROOT_HISTORY_DIR: &str = "metadata/root_history";

/// The file recording a signing event's open invitations and pending configuration.
pub const EVENT_STATE_PATH: &str = "metadata/.signing-event.json";

/// The path of a role's payload file.
pub fn payload_path(role: &MetadataPath) -> String {
    format!("{METADATA_DIR}/{role}.json")
}

/// The path of a role's signature file.
pub fn signature_path(role: &MetadataPath) -> String {
    format!("{METADATA_DIR}/{role}.sig.json")
}

/// The path of an archived root version's payload file.
pub fn root_history_payload_path(version: u32) -> String {
    format!("{ROOT_HISTORY_DIR}/{version}.root.json")
}

/// The path of an archived root version's signature file.
pub fn root_history_signature_path(version: u32) -> String {
    format!("{ROOT_HISTORY_DIR}/{version}.root.sig.json")
}

// ---------------------------------------------------------------------------
// Sources
// ---------------------------------------------------------------------------

/// Somewhere repository files can be read from.
pub trait Source {
    /// Read a file by its path relative to the repository root.
    ///
    /// Returns `Ok(None)` when the file does not exist, which for most of this crate is an
    /// ordinary answer rather than a failure: a role that has never been created and a
    /// role that has been deleted both read as absent.
    fn read(&self, path: &str) -> Result<Option<Vec<u8>>>;

    /// List every file at or below `dir`, as paths relative to the repository root.
    ///
    /// A missing directory lists as empty.
    fn list(&self, dir: &str) -> Result<Vec<String>>;
}

/// Reads a working tree.
#[derive(Clone, Debug)]
pub struct FsSource {
    root: PathBuf,
}

impl FsSource {
    /// Read the working tree rooted at `root`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        FsSource { root: root.into() }
    }

    /// The repository root this source reads.
    pub fn root(&self) -> &Path {
        &self.root
    }
}

impl Source for FsSource {
    fn read(&self, path: &str) -> Result<Option<Vec<u8>>> {
        match std::fs::read(self.root.join(path)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(Error::io(format!("reading {path}"), err)),
        }
    }

    fn list(&self, dir: &str) -> Result<Vec<String>> {
        let mut found = Vec::new();
        let mut pending = vec![dir.to_owned()];

        while let Some(relative) = pending.pop() {
            let entries = match std::fs::read_dir(self.root.join(&relative)) {
                Ok(entries) => entries,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                Err(err) => return Err(Error::io(format!("listing {relative}"), err)),
            };

            for entry in entries {
                let entry = entry.map_err(|err| Error::io(format!("listing {relative}"), err))?;
                let name = entry.file_name().to_string_lossy().into_owned();
                let path = format!("{relative}/{name}");
                let file_type = entry
                    .file_type()
                    .map_err(|err| Error::io(format!("inspecting {path}"), err))?;
                if file_type.is_dir() {
                    pending.push(path);
                } else {
                    found.push(path);
                }
            }
        }

        found.sort();
        Ok(found)
    }
}

/// Reads a git commit without checking it out.
#[derive(Clone, Debug)]
pub struct GitSource {
    repo: PathBuf,
    rev: String,
}

impl GitSource {
    /// Read the tree of `rev` in the git repository at `repo`.
    pub fn new(repo: impl Into<PathBuf>, rev: impl Into<String>) -> Self {
        GitSource {
            repo: repo.into(),
            rev: rev.into(),
        }
    }

    fn git(&self, args: &[&str]) -> Result<std::process::Output> {
        Command::new("git")
            .arg("-C")
            .arg(&self.repo)
            .args(args)
            .output()
            .map_err(|err| Error::io(format!("running git {}", args.join(" ")), err))
    }
}

impl Source for GitSource {
    fn read(&self, path: &str) -> Result<Option<Vec<u8>>> {
        let spec = format!("{}:{path}", self.rev);
        let output = self.git(&["show", &spec])?;
        if output.status.success() {
            return Ok(Some(output.stdout));
        }

        // git does not distinguish "no such path in this tree" from other failures by exit
        // code, so fall back to asking whether the path exists at all.
        let exists = self.git(&["cat-file", "-e", &spec])?.status.success();
        if exists {
            Err(Error::io(
                format!(
                    "reading {path} at {}: {}",
                    self.rev,
                    String::from_utf8_lossy(&output.stderr).trim()
                ),
                std::io::Error::other("git show failed"),
            ))
        } else {
            Ok(None)
        }
    }

    fn list(&self, dir: &str) -> Result<Vec<String>> {
        let output = self.git(&["ls-tree", "-r", "--name-only", "-z", &self.rev, "--", dir])?;
        if !output.status.success() {
            // An absent directory is not an error, and neither is a revision with no tree
            // at all, which is how the very first signing event in a repository looks.
            return Ok(Vec::new());
        }
        let mut found: Vec<String> = output
            .stdout
            .split(|byte| *byte == 0)
            .filter(|entry| !entry.is_empty())
            .map(|entry| String::from_utf8_lossy(entry).into_owned())
            .collect();
        found.sort();
        Ok(found)
    }
}

/// A source that holds no files, standing in for the state before a repository exists.
#[derive(Clone, Copy, Debug, Default)]
pub struct EmptySource;

impl Source for EmptySource {
    fn read(&self, _path: &str) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }

    fn list(&self, _dir: &str) -> Result<Vec<String>> {
        Ok(Vec::new())
    }
}

// ---------------------------------------------------------------------------
// Signed documents
// ---------------------------------------------------------------------------

/// A metadata payload together with the signatures over it.
///
/// The bytes the payload was read from are kept alongside the parsed value, and signatures
/// are always checked against *those* bytes. A payload is never re-serialized in order to
/// verify it, so no drift in how JSON is written can turn a valid repository invalid.
#[derive(Clone, Debug)]
pub struct Signed<M> {
    raw: Vec<u8>,
    payload: M,
    policy: Policy,
    signatures: Vec<Signature>,
}

/// The on-disk shape of a `<role>.sig.json`.
///
/// An object rather than a bare array, so the same key names the signatures here and in a
/// published envelope, and so the file can gain a field later without changing shape.
#[derive(Default, Serialize, Deserialize)]
struct SignatureFile {
    #[serde(default)]
    signatures: Vec<SignatureEntry>,
}

/// One signature, as the sidecar records it.
///
/// Deliberately not `tuf::crypto::Signature`'s own encoding, which is hex because that is
/// what POUF-1's canonical JSON calls for. A DSSE envelope writes base64, and the sidecar
/// is half of an envelope: a signature has to read identically in both files, or a
/// reviewer comparing them sees two different strings for one signature.
#[derive(Serialize, Deserialize)]
struct SignatureEntry {
    keyid: String,
    sig: String,
}

impl SignatureEntry {
    fn of(signature: &Signature) -> Self {
        SignatureEntry {
            keyid: signature.key_id().to_string(),
            sig: dsse::SignatureBytes::from_bytes(signature.value().as_bytes()).to_base64(),
        }
    }

    fn parse(self) -> Result<Signature> {
        let key_id = self.keyid.parse().map_err(Error::invalid)?;
        let bytes = dsse::SignatureBytes::from_base64(&self.sig)
            .map_err(|err| Error::encoding(format!("signature by {}: {err}", self.keyid)))?;
        Ok(Signature::new(
            key_id,
            SignatureValue::new(bytes.into_bytes()),
        ))
    }
}

impl<M: Metadata + ExtraFields + Clone> Signed<M> {
    /// Author a new, unsigned document.
    ///
    /// This is the only place payload bytes are produced. They are pretty-printed once,
    /// here, and frozen: everything downstream reads [`raw`](Self::raw).
    pub fn new(payload: M) -> Result<Self> {
        let raw = ser::author(&payload)?;
        Self::parse(raw, Vec::new())
    }

    /// Parse a payload file and its signature file.
    pub fn parse(raw: Vec<u8>, signatures: Vec<Signature>) -> Result<Self> {
        let data = <Pouf2 as Pouf>::RawData::from_slice(raw.clone());
        let payload = M::from_raw_data::<Pouf2>(&data).map_err(Error::invalid)?;
        let policy = Policy::read(payload.additional_fields_map())?;
        Ok(Signed {
            raw,
            payload,
            policy,
            signatures,
        })
    }

    /// The parsed payload.
    pub fn payload(&self) -> &M {
        &self.payload
    }

    /// This project's additions to the payload.
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// The exact bytes of the payload file.
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// The signatures gathered so far.
    pub fn signatures(&self) -> &[Signature] {
        &self.signatures
    }

    /// The bytes of this document's `.sig.json` file.
    pub fn signature_file(&self) -> Result<Vec<u8>> {
        ser::to_bytes(&SignatureFile {
            signatures: self.signatures.iter().map(SignatureEntry::of).collect(),
        })
    }

    /// The bytes a signature over this payload is computed over.
    pub fn signing_input(&self) -> Vec<u8> {
        dsse::pae(tuf::pouf::PAYLOAD_TYPE, &self.raw)
    }

    /// The published form: payload and signatures in one DSSE envelope.
    ///
    /// Assembled from the stored bytes, never from a fresh serialization of the payload.
    pub fn envelope(&self) -> Result<Vec<u8>> {
        let data = <Pouf2 as Pouf>::RawData::from_slice(self.raw.clone());
        Pouf2::serialize_signed(&self.signatures, &data).map_err(Error::encoding)
    }

    /// Replace the payload, discarding every signature.
    ///
    /// The signatures are dropped rather than kept because they were made over the old
    /// bytes: keeping them would leave a document whose signatures verify against
    /// something other than what it now says.
    pub fn set_payload(&mut self, payload: M) -> Result<()> {
        *self = Signed::new(payload)?;
        Ok(())
    }

    /// Record a signature over the current payload bytes, replacing any by the same key.
    ///
    /// Entries are kept sorted by key id: two signers signing concurrently then produce the
    /// same file whichever order the commits land in, which keeps merge conflicts to the
    /// genuine ones.
    pub fn add_signature(&mut self, signature: Signature) {
        self.signatures
            .retain(|existing| existing.key_id() != signature.key_id());
        self.signatures.push(signature);
        self.signatures.sort_by(|a, b| a.key_id().cmp(b.key_id()));
    }

    /// Sign the current payload bytes with `signer`.
    pub fn sign_with(&mut self, signer: &mut dyn crate::signer::Signer) -> Result<()> {
        let message = self.signing_input();
        let bytes = signer.sign(&message)?;
        let key_id = signer.key_id().clone();

        // Check our own work before storing it: a signing device that returns a signature
        // over the wrong bytes, or with the wrong key, should be caught here rather than
        // by CI after the signer has gone home.
        signer
            .public_key()
            .verify_bytes(&message, &bytes)
            .map_err(|_| Error::BadSignature(key_id.clone()))?;

        self.add_signature(Signature::new(key_id, SignatureValue::new(bytes)));
        Ok(())
    }

    /// Check this document's signatures against what `delegator` says about `role`.
    ///
    /// Deliberately not [`tuf::verify::verify_signatures`], which stops counting the moment
    /// the threshold is met and logs bad signatures rather than returning them. A pull
    /// request has to say which named person has signed and which has not, and to tell
    /// "has not signed" apart from "signed, but the signature does not verify".
    pub fn tally(&self, delegator: &Delegator<'_>, role: &MetadataPath) -> Tally {
        let Some(spec) = delegator.role_spec(role) else {
            return Tally::empty(role.clone());
        };
        let message = self.signing_input();
        let mut tally = Tally {
            role: role.clone(),
            threshold: spec.threshold,
            signed: Vec::new(),
            missing: Vec::new(),
            invalid: Vec::new(),
        };

        for key_id in &spec.keyids {
            let Some(key) = delegator.key(key_id) else {
                // A delegation naming a key the delegator does not hold can never be
                // satisfied. Report it as an unusable signer rather than ignoring it.
                tally.invalid.push(SignerRef {
                    key_id: key_id.clone(),
                    name: format!("<unknown key {}>", crate::crypto::abbreviated(key_id)),
                });
                continue;
            };
            let who = SignerRef {
                key_id: key_id.clone(),
                name: delegator.signer_name(key_id),
            };
            match self
                .signatures
                .iter()
                .find(|signature| signature.key_id() == key_id)
            {
                None => tally.missing.push(who),
                Some(signature) => match key.verify_bytes(&message, signature.value().as_bytes()) {
                    Ok(()) => tally.signed.push(who),
                    Err(_) => tally.invalid.push(who),
                },
            }
        }

        tally
    }
}

impl<M: PartialEq> PartialEq for Signed<M> {
    fn eq(&self, other: &Self) -> bool {
        self.raw == other.raw && self.signatures == other.signatures
    }
}

impl Signed<RootMetadata> {
    /// This root seen as the role that delegates to the four top-level roles.
    pub fn delegator(&self) -> Delegator<'_> {
        Delegator::Root {
            root: &self.payload,
            policy: &self.policy,
        }
    }
}

impl Signed<TargetsMetadata> {
    /// This targets role seen as the role that delegates to the roles it names.
    pub fn delegator(&self) -> Delegator<'_> {
        Delegator::Targets {
            targets: &self.payload,
            policy: &self.policy,
        }
    }
}

/// Reaching a metadata document's extra fields without knowing which kind it is.
pub trait ExtraFields {
    /// The fields this crate's model does not name, including the policy block.
    fn additional_fields_map(&self) -> &HashMap<String, serde_json::Value>;
}

macro_rules! impl_extra_fields {
    ($($ty:ty),*) => {
        $(impl ExtraFields for $ty {
            fn additional_fields_map(&self) -> &HashMap<String, serde_json::Value> {
                self.additional_fields()
            }
        })*
    };
}
impl_extra_fields!(
    RootMetadata,
    TargetsMetadata,
    SnapshotMetadata,
    TimestampMetadata
);

// ---------------------------------------------------------------------------
// Taking a document apart to change it
// ---------------------------------------------------------------------------
//
// `tuf`'s metadata types are immutable by construction, which is right for a document that
// has been signed and wrong for one being drafted. These are the seam: take a document
// apart, change a field, put it back together. They exist only for the duration of an
// edit — every field is `tuf`'s own type, and nothing here is a parallel model.

/// The pieces of a [`RootMetadata`].
#[derive(Clone, Debug)]
pub struct RootParts {
    /// The metadata version.
    pub version: u32,
    /// When this metadata stops being valid.
    pub expires: DateTime<Utc>,
    /// Whether published metadata is version- and hash-prefixed.
    pub consistent_snapshot: bool,
    /// Every key referenced by [`roles`](Self::roles).
    pub keys: HashMap<KeyId, PublicKey>,
    /// The four top-level roles.
    pub roles: BTreeMap<String, RoleParts>,
    /// This project's additions.
    pub policy: Policy,
    /// Fields nothing here names.
    pub extra: HashMap<String, serde_json::Value>,
}

/// Who may sign one role, and how many of them are needed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RoleParts {
    /// The keys permitted to sign.
    pub keyids: BTreeSet<KeyId>,
    /// How many distinct keys must sign.
    pub threshold: u32,
}

impl RootParts {
    /// Take `root` apart.
    pub fn of(root: &RootMetadata, policy: &Policy) -> Self {
        RootParts {
            version: root.version(),
            expires: *root.expires(),
            consistent_snapshot: root.consistent_snapshot(),
            keys: root.keys().clone(),
            roles: BTreeMap::from([
                ("root".to_owned(), role_parts(root.root())),
                ("snapshot".to_owned(), role_parts(root.snapshot())),
                ("targets".to_owned(), role_parts(root.targets())),
                ("timestamp".to_owned(), role_parts(root.timestamp())),
            ]),
            policy: policy.clone(),
            extra: root.additional_fields().clone(),
        }
    }

    /// An empty root delegating to the four top-level roles, but to no keys yet.
    pub fn empty(now: DateTime<Utc>, periods: Periods) -> Self {
        let mut policy = Policy::default();
        let mut roles = BTreeMap::new();
        for name in ["root", "snapshot", "targets", "timestamp"] {
            roles.insert(
                name.to_owned(),
                RoleParts {
                    keyids: BTreeSet::new(),
                    threshold: 1,
                },
            );
            policy.periods.insert(name.to_owned(), periods);
        }
        RootParts {
            version: 1,
            expires: periods.expires_at(now),
            consistent_snapshot: true,
            keys: HashMap::new(),
            roles,
            policy,
            extra: HashMap::new(),
        }
    }

    /// The entry for `role`, which must be one of the four top-level roles.
    pub fn role_mut(&mut self, role: &MetadataPath) -> Result<&mut RoleParts> {
        self.roles
            .get_mut(role.as_str())
            .ok_or_else(|| Error::NoSuchRole(role.to_string()))
    }

    /// Put the document back together.
    ///
    /// Drops keys no role refers to any more, and the policy recorded about them: a key
    /// left behind after the last role that could use it stopped naming it reads as a key
    /// the repository still trusts.
    pub fn build(mut self) -> Result<RootMetadata> {
        let in_use: BTreeSet<&KeyId> = self.roles.values().flat_map(|r| &r.keyids).collect();
        let live: Vec<KeyId> = in_use.iter().map(|id| (*id).clone()).collect();
        self.keys.retain(|key_id, _| in_use.contains(key_id));
        self.policy.retain_keys(live.iter());
        self.policy.write(&mut self.extra)?;

        RootMetadata::new(
            self.version,
            self.expires,
            self.consistent_snapshot,
            self.keys.clone(),
            role_definition(&self.roles, "root")?,
            role_definition(&self.roles, "snapshot")?,
            role_definition(&self.roles, "targets")?,
            role_definition(&self.roles, "timestamp")?,
            self.extra.clone(),
        )
        .map_err(Error::invalid)
    }
}

/// Take one role definition apart, whichever role it happens to describe.
fn role_parts<M: Metadata>(definition: &RoleDefinition<M>) -> RoleParts {
    RoleParts {
        keyids: definition.key_ids().iter().cloned().collect(),
        threshold: definition.threshold(),
    }
}

/// Put one role definition back together.
fn role_definition<M: Metadata>(
    roles: &BTreeMap<String, RoleParts>,
    name: &str,
) -> Result<RoleDefinition<M>> {
    let parts = roles
        .get(name)
        .ok_or_else(|| Error::NoSuchRole(name.to_owned()))?;
    RoleDefinition::new(parts.threshold, parts.keyids.iter().cloned().collect())
        .map_err(Error::invalid)
}

/// The pieces of a [`TargetsMetadata`].
#[derive(Clone, Debug)]
pub struct TargetsParts {
    /// The metadata version.
    pub version: u32,
    /// When this metadata stops being valid.
    pub expires: DateTime<Utc>,
    /// The artifacts this role vouches for.
    pub targets: HashMap<TargetPath, TargetDescription>,
    /// Every key referenced by [`roles`](Self::roles).
    pub keys: HashMap<KeyId, PublicKey>,
    /// The roles this one delegates to, in the order they are searched.
    pub roles: Vec<DelegationParts>,
    /// This project's additions.
    pub policy: Policy,
    /// Fields nothing here names.
    pub extra: HashMap<String, serde_json::Value>,
}

/// The pieces of one [`Delegation`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DelegationParts {
    /// The delegated role's name.
    pub name: MetadataPath,
    /// The keys permitted to sign it.
    pub keyids: BTreeSet<KeyId>,
    /// How many distinct keys must sign.
    pub threshold: u32,
    /// Artifact path patterns the role is responsible for.
    pub paths: BTreeSet<String>,
    /// Whether a match here ends the delegation search.
    pub terminating: bool,
}

impl TargetsParts {
    /// Take `targets` apart.
    pub fn of(targets: &TargetsMetadata, policy: &Policy) -> Self {
        TargetsParts {
            version: targets.version(),
            expires: *targets.expires(),
            targets: targets.targets().clone(),
            keys: targets.delegations().keys().clone(),
            roles: targets
                .delegations()
                .roles()
                .iter()
                .map(|delegation| DelegationParts {
                    name: delegation.name().clone(),
                    keyids: delegation.key_ids().iter().cloned().collect(),
                    threshold: delegation.threshold(),
                    paths: delegation
                        .paths()
                        .iter()
                        .map(|path| path.to_string())
                        .collect(),
                    terminating: delegation.terminating(),
                })
                .collect(),
            policy: policy.clone(),
            extra: targets.additional_fields().clone(),
        }
    }

    /// An empty targets role, vouching for nothing and delegating to nobody.
    pub fn empty(now: DateTime<Utc>, periods: Periods) -> Self {
        TargetsParts {
            version: 1,
            expires: periods.expires_at(now),
            targets: HashMap::new(),
            keys: HashMap::new(),
            roles: Vec::new(),
            policy: Policy::default(),
            extra: HashMap::new(),
        }
    }

    /// The delegation to `role`, creating it with default paths if it is new.
    pub fn delegation_mut(&mut self, role: &MetadataPath) -> &mut DelegationParts {
        if let Some(index) = self.roles.iter().position(|d| &d.name == role) {
            return &mut self.roles[index];
        }
        self.roles.push(DelegationParts {
            name: role.clone(),
            keyids: BTreeSet::new(),
            threshold: 1,
            paths: policy::default_paths(role).into_iter().collect(),
            terminating: true,
        });
        // Ordered by name so that adding one produces a diff showing only that delegation,
        // whatever order events happen to be merged in.
        self.roles.sort_by(|a, b| a.name.cmp(&b.name));
        self.roles
            .iter_mut()
            .find(|d| &d.name == role)
            .expect("just inserted")
    }

    /// Remove the delegation to `role`. Returns whether there was one.
    pub fn remove_delegation(&mut self, role: &MetadataPath) -> bool {
        let before = self.roles.len();
        self.roles.retain(|d| &d.name != role);
        self.policy.periods.remove(role.as_str());
        before != self.roles.len()
    }

    /// Put the document back together.
    pub fn build(mut self) -> Result<TargetsMetadata> {
        let in_use: BTreeSet<&KeyId> = self.roles.iter().flat_map(|r| &r.keyids).collect();
        let live: Vec<KeyId> = in_use.iter().map(|id| (*id).clone()).collect();
        self.keys.retain(|key_id, _| in_use.contains(key_id));
        self.policy.retain_keys(live.iter());
        self.policy.write(&mut self.extra)?;

        let mut roles = Vec::with_capacity(self.roles.len());
        for parts in &self.roles {
            let paths: HashSet<TargetPath> = parts
                .paths
                .iter()
                .map(|path| TargetPath::new(path.clone()).map_err(Error::invalid))
                .collect::<Result<_>>()?;
            roles.push(
                Delegation::new(
                    parts.name.clone(),
                    parts.terminating,
                    parts.threshold,
                    parts.keyids.iter().cloned().collect(),
                    paths,
                )
                .map_err(Error::invalid)?,
            );
        }

        let delegations = Delegations::new(self.keys.clone(), roles).map_err(Error::invalid)?;
        TargetsMetadata::new(
            self.version,
            self.expires,
            self.targets.clone(),
            delegations,
            self.extra.clone(),
        )
        .map_err(Error::invalid)
    }
}

// ---------------------------------------------------------------------------
// Delegators
// ---------------------------------------------------------------------------

/// A role that defines the keys and threshold of other roles.
///
/// `root` delegates to the four top-level roles; a targets role delegates to the roles in
/// its `delegations`. Both answer the same two questions, so the signing-event logic can
/// treat them alike.
#[derive(Clone, Copy, Debug)]
pub enum Delegator<'a> {
    /// The root role, delegating to the top-level roles.
    Root {
        /// The root payload.
        root: &'a RootMetadata,
        /// Its policy block.
        policy: &'a Policy,
    },
    /// A targets role, delegating to the roles named in its delegations.
    Targets {
        /// The targets payload.
        targets: &'a TargetsMetadata,
        /// Its policy block.
        policy: &'a Policy,
    },
}

/// What a delegator says about one of its delegates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoleSpec {
    /// The keys permitted to sign, ordered so reports are stable.
    pub keyids: Vec<KeyId>,
    /// How many distinct keys must sign.
    pub threshold: u32,
    /// Validity and re-signing periods.
    pub periods: Periods,
}

impl<'a> Delegator<'a> {
    /// This delegator's policy block.
    pub fn policy(&self) -> &'a Policy {
        match self {
            Delegator::Root { policy, .. } | Delegator::Targets { policy, .. } => policy,
        }
    }

    /// What this role says about its delegate `role`, if it delegates to it at all.
    pub fn role_spec(&self, role: &MetadataPath) -> Option<RoleSpec> {
        let (keyids, threshold) = match self {
            Delegator::Root { root, .. } => {
                let definition = match role.as_str() {
                    "root" => root.root(),
                    "snapshot" => return spec_of(root.snapshot(), role, self.policy()),
                    "targets" => return spec_of(root.targets(), role, self.policy()),
                    "timestamp" => return spec_of(root.timestamp(), role, self.policy()),
                    _ => return None,
                };
                (definition.key_ids().clone(), definition.threshold())
            }
            Delegator::Targets { targets, .. } => {
                let delegation = targets
                    .delegations()
                    .roles()
                    .iter()
                    .find(|delegation| delegation.name() == role)?;
                (delegation.key_ids().clone(), delegation.threshold())
            }
        };
        let mut keyids: Vec<KeyId> = keyids.into_iter().collect();
        keyids.sort();
        Some(RoleSpec {
            keyids,
            threshold,
            periods: self.policy().periods(role),
        })
    }

    /// Whether an automated key signs `role`, rather than people.
    ///
    /// Read out of this document's own key records: a key is online because the repository
    /// records a signing URI for it, so the same rule answers for `snapshot` and for a
    /// delegated role handed to automation. Nothing here looks at what the role is called.
    ///
    /// A role with no keys is not online, and neither is one whose keys are only partly
    /// online — that is a misconfiguration rather than a third kind of role, and
    /// [`crate::event`] reports it as one.
    pub fn is_online(&self, role: &MetadataPath) -> bool {
        match self.role_spec(role) {
            Some(spec) if !spec.keyids.is_empty() => spec
                .keyids
                .iter()
                .all(|key_id| self.policy().is_online_key(key_id)),
            _ => false,
        }
    }

    /// Look up one of this role's keys.
    pub fn key(&self, key_id: &KeyId) -> Option<&'a PublicKey> {
        match self {
            Delegator::Root { root, .. } => root.keys().get(key_id),
            Delegator::Targets { targets, .. } => targets.delegations().keys().get(key_id),
        }
    }

    /// Every key this role holds.
    pub fn keys(&self) -> &'a HashMap<KeyId, PublicKey> {
        match self {
            Delegator::Root { root, .. } => root.keys(),
            Delegator::Targets { targets, .. } => targets.delegations().keys(),
        }
    }

    /// Who or what signs with `key_id`, named the way a person would recognise it.
    pub fn signer_name(&self, key_id: &KeyId) -> String {
        self.policy().signer_name(key_id)
    }

    /// The keys permitted to sign `role`, in the order the delegation lists them.
    ///
    /// Key ids naming a key this delegator does not hold are skipped; such a delegation is
    /// unsatisfiable, which [`crate::event`] reports separately rather than by panicking.
    pub fn keys_for(&self, role: &MetadataPath) -> Vec<(KeyId, &'a PublicKey)> {
        let Some(spec) = self.role_spec(role) else {
            return Vec::new();
        };
        spec.keyids
            .into_iter()
            .filter_map(|key_id| self.key(&key_id).map(|key| (key_id, key)))
            .collect()
    }

    /// The names of every role this one delegates to.
    pub fn delegated_roles(&self) -> Vec<MetadataPath> {
        match self {
            Delegator::Root { .. } => vec![
                MetadataPath::root(),
                MetadataPath::snapshot(),
                MetadataPath::targets(),
                MetadataPath::timestamp(),
            ],
            Delegator::Targets { targets, .. } => targets
                .delegations()
                .roles()
                .iter()
                .map(|delegation| delegation.name().clone())
                .collect(),
        }
    }

    /// The artifact path patterns `role` is responsible for.
    pub fn paths_for(&self, role: &MetadataPath) -> Vec<String> {
        match self {
            Delegator::Root { .. } => Vec::new(),
            Delegator::Targets { targets, .. } => targets
                .delegations()
                .roles()
                .iter()
                .find(|delegation| delegation.name() == role)
                .map(|delegation| delegation.paths().iter().map(|p| p.to_string()).collect())
                .unwrap_or_default(),
        }
    }
}

fn spec_of<M>(
    definition: &RoleDefinition<M>,
    role: &MetadataPath,
    policy: &Policy,
) -> Option<RoleSpec>
where
    M: Metadata,
{
    let mut keyids: Vec<KeyId> = definition.key_ids().iter().cloned().collect();
    keyids.sort();
    Some(RoleSpec {
        keyids,
        threshold: definition.threshold(),
        periods: policy.periods(role),
    })
}

// ---------------------------------------------------------------------------
// Signature tallies
// ---------------------------------------------------------------------------

/// One key, named the way a person would recognise it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignerRef {
    /// The key.
    pub key_id: KeyId,
    /// Who holds it.
    pub name: String,
}

/// How a role's signatures stand against its threshold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tally {
    /// The role the signatures are for.
    pub role: MetadataPath,
    /// How many valid signatures are required.
    pub threshold: u32,
    /// Keys that have signed the current payload.
    pub signed: Vec<SignerRef>,
    /// Keys that have not signed yet.
    pub missing: Vec<SignerRef>,
    /// Keys whose signature is present but does not verify, or that cannot be used.
    pub invalid: Vec<SignerRef>,
}

impl Tally {
    /// A tally with nobody permitted to sign, which can never be satisfied.
    pub fn empty(role: MetadataPath) -> Self {
        Tally {
            role,
            // An unreachable threshold: nobody is permitted to sign this role, so no
            // number of signatures makes it valid.
            threshold: 1,
            signed: Vec::new(),
            missing: Vec::new(),
            invalid: Vec::new(),
        }
    }

    /// Whether enough valid signatures have been gathered.
    pub fn is_met(&self) -> bool {
        self.signed.len() as u32 >= self.threshold
    }

    /// How many more signatures are needed, or zero if the threshold is met.
    pub fn outstanding(&self) -> u32 {
        self.threshold.saturating_sub(self.signed.len() as u32)
    }
}

// ---------------------------------------------------------------------------
// Signing event state
// ---------------------------------------------------------------------------

/// The unsigned state of a signing event: what is intended but not yet in the metadata.
///
/// Two things live here rather than in the metadata, for the same reason. A signer who has
/// been invited has no key in the repository yet, and a role whose threshold is being
/// raised cannot have that threshold written until the keys to meet it exist — TUF
/// metadata naming a threshold it has no keys for is not valid metadata, and every tool
/// that reads it, including this one, is entitled to reject it.
///
/// So intent is recorded here and materialised into the metadata the moment it can be
/// satisfied. The file is deleted when the event closes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventState {
    /// Roles each invited signer has yet to accept, keyed by `@handle`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub invites: BTreeMap<String, Vec<MetadataPath>>,
    /// Role configurations that cannot be written until every signer has a key.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub pending: BTreeMap<String, crate::policy::RoleConfig>,
}

impl EventState {
    /// An event with nothing outstanding.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether there is nothing outstanding, so the file can be removed.
    pub fn is_empty(&self) -> bool {
        self.invites.is_empty() && self.pending.is_empty()
    }

    /// The roles `user` has been invited to.
    pub fn for_user(&self, user: &str) -> &[MetadataPath] {
        self.invites
            .get(user)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    /// Everyone invited to `role`.
    pub fn for_role(&self, role: &MetadataPath) -> Vec<&str> {
        let mut users: Vec<&str> = self
            .invites
            .iter()
            .filter(|(_, roles)| roles.contains(role))
            .map(|(user, _)| user.as_str())
            .collect();
        users.sort_unstable();
        users
    }

    /// Invite `user` to sign `role`.
    pub fn add(&mut self, user: &str, role: &MetadataPath) {
        let roles = self.invites.entry(user.to_owned()).or_default();
        if !roles.contains(role) {
            roles.push(role.clone());
            roles.sort();
        }
    }

    /// Withdraw one invitation, dropping the signer once nothing is outstanding.
    pub fn remove(&mut self, user: &str, role: &MetadataPath) {
        if let Some(roles) = self.invites.get_mut(user) {
            roles.retain(|open| open != role);
            if roles.is_empty() {
                self.invites.remove(user);
            }
        }
    }

    /// Withdraw every invitation to `role`.
    pub fn remove_role(&mut self, role: &MetadataPath) {
        for roles in self.invites.values_mut() {
            roles.retain(|open| open != role);
        }
        self.invites.retain(|_, roles| !roles.is_empty());
        self.pending.remove(role.as_str());
    }

    /// The configuration `role` is waiting to have written, if any.
    pub fn pending_for(&self, role: &MetadataPath) -> Option<&crate::policy::RoleConfig> {
        self.pending.get(role.as_str())
    }
}

// ---------------------------------------------------------------------------
// Repository state
// ---------------------------------------------------------------------------

/// Every metadata document in a repository at one point in time.
#[derive(Debug, Default)]
pub struct RepoState {
    /// The root role, absent before the repository has been created.
    pub root: Option<Signed<RootMetadata>>,
    /// The top-level targets role and every delegated targets role.
    pub targets: BTreeMap<MetadataPath, Signed<TargetsMetadata>>,
    /// The snapshot role, which only online signing produces.
    pub snapshot: Option<Signed<SnapshotMetadata>>,
    /// The timestamp role, which only online signing produces.
    pub timestamp: Option<Signed<TimestampMetadata>>,
    /// Invitations and pending configuration, if this state is mid-signing-event.
    pub event: EventState,
}

impl RepoState {
    /// Read every role from `source`.
    pub fn load(source: &dyn Source) -> Result<Self> {
        let mut state = RepoState::default();

        for path in source.list(METADATA_DIR)? {
            let Some(role) = role_of_metadata_path(&path) else {
                continue;
            };
            let Some(raw) = source.read(&path)? else {
                continue;
            };
            let signatures = read_signatures(source, &signature_path(&role))?;

            if role == MetadataPath::root() {
                state.root = Some(Signed::parse(raw, signatures)?);
            } else if role == MetadataPath::snapshot() {
                state.snapshot = Some(Signed::parse(raw, signatures)?);
            } else if role == MetadataPath::timestamp() {
                state.timestamp = Some(Signed::parse(raw, signatures)?);
            } else {
                state.targets.insert(role, Signed::parse(raw, signatures)?);
            }
        }

        if let Some(raw) = source.read(EVENT_STATE_PATH)? {
            state.event = serde_json::from_slice(&raw)?;
        }

        Ok(state)
    }

    /// Whether the repository exists at all.
    pub fn is_initialized(&self) -> bool {
        self.root.is_some()
    }

    /// The root role, or an error naming what is missing.
    pub fn root(&self) -> Result<&Signed<RootMetadata>> {
        self.root
            .as_ref()
            .ok_or_else(|| Error::invalid("this repository has no root metadata yet"))
    }

    /// The role that defines the keys and threshold of `role`.
    ///
    /// Top-level roles are delegated by root; everything else by the top-level targets role.
    pub fn delegator_of(&self, role: &MetadataPath) -> Result<Delegator<'_>> {
        if policy::is_top_level(role) {
            Ok(self.root()?.delegator())
        } else {
            self.targets
                .get(&MetadataPath::targets())
                .map(Signed::<TargetsMetadata>::delegator)
                .ok_or_else(|| Error::NoSuchRole(MetadataPath::targets().to_string()))
        }
    }

    /// `role` seen as a delegator of other roles, if it is one.
    pub fn delegator_view(&self, role: &MetadataPath) -> Option<Delegator<'_>> {
        if *role == MetadataPath::root() {
            return self.root.as_ref().map(Signed::<RootMetadata>::delegator);
        }
        self.targets
            .get(role)
            .map(Signed::<TargetsMetadata>::delegator)
    }

    /// Every role present, ordered `root`, `targets`, then delegates alphabetically.
    ///
    /// The order matters wherever roles are reported or processed in turn: a delegating
    /// role has to be dealt with before the roles it delegates to.
    pub fn role_names(&self) -> Vec<MetadataPath> {
        let mut names = Vec::new();
        if self.root.is_some() {
            names.push(MetadataPath::root());
        }
        if self.targets.contains_key(&MetadataPath::targets()) {
            names.push(MetadataPath::targets());
        }
        names.extend(
            self.targets
                .keys()
                .filter(|role| **role != MetadataPath::targets())
                .cloned(),
        );
        names
    }

    /// The exact payload bytes of `role`, if it is present.
    pub fn raw_payload(&self, role: &MetadataPath) -> Option<&[u8]> {
        if *role == MetadataPath::root() {
            return self.root.as_ref().map(Signed::raw);
        }
        if *role == MetadataPath::snapshot() {
            return self.snapshot.as_ref().map(Signed::raw);
        }
        if *role == MetadataPath::timestamp() {
            return self.timestamp.as_ref().map(Signed::raw);
        }
        self.targets.get(role).map(Signed::raw)
    }

    /// The version of `role`, or zero if it does not exist here.
    ///
    /// Zero for an absent role is what makes "one more than the known-good version" the
    /// right rule for a role being created for the first time as well as for one being
    /// changed.
    pub fn version_of(&self, role: &MetadataPath) -> u32 {
        if *role == MetadataPath::root() {
            return self.root.as_ref().map_or(0, |r| r.payload().version());
        }
        self.targets.get(role).map_or(0, |t| t.payload().version())
    }
}

/// The role a metadata path belongs to, or `None` if it is not a role payload.
///
/// Signature files, the event state file and archived roots all read as `None`.
fn role_of_metadata_path(path: &str) -> Option<MetadataPath> {
    let name = path.strip_prefix(METADATA_DIR)?.strip_prefix('/')?;
    // Anything in a subdirectory is history, not current state.
    if name.contains('/') {
        return None;
    }
    let stem = name.strip_suffix(".json")?;
    if stem.ends_with(".sig") || stem.starts_with('.') {
        return None;
    }
    policy::role_name(stem).ok()
}

fn read_signatures(source: &dyn Source, path: &str) -> Result<Vec<Signature>> {
    match source.read(path)? {
        Some(raw) => serde_json::from_slice::<SignatureFile>(&raw)?
            .signatures
            .into_iter()
            .map(SignatureEntry::parse)
            .collect(),
        None => Ok(Vec::new()),
    }
}

/// Read a payload file and the signature file beside it, if the payload is there.
///
/// Both paths are given rather than derived from a role, because the same document is
/// filed under two different names: `metadata/root.json` while it is current, and
/// `metadata/root_history/3.root.json` for good.
pub fn read_signed<M: Metadata + ExtraFields + Clone>(
    source: &dyn Source,
    payload: &str,
    signatures: &str,
) -> Result<Option<Signed<M>>> {
    let Some(raw) = source.read(payload)? else {
        return Ok(None);
    };
    Ok(Some(Signed::parse(
        raw,
        read_signatures(source, signatures)?,
    )?))
}

/// Every archived root version, by version number.
///
/// A client that has not looked since root version 2 reaches version 5 by verifying 3,
/// then 4, then 5, each against the one before it. So publishing a repository means
/// publishing every root that has ever been signed, not only the current one.
pub fn read_root_history(source: &dyn Source) -> Result<BTreeMap<u32, Signed<RootMetadata>>> {
    let mut history = BTreeMap::new();

    for path in source.list(ROOT_HISTORY_DIR)? {
        let Some(version) = root_history_version(&path) else {
            continue;
        };
        let Some(signed) =
            read_signed::<RootMetadata>(source, &path, &root_history_signature_path(version))?
        else {
            continue;
        };
        if signed.payload().version() != version {
            return Err(Error::invalid(format!(
                "{path} holds root version {}",
                signed.payload().version()
            )));
        }
        history.insert(version, signed);
    }

    Ok(history)
}

/// The root version an archived payload path names, or `None` if it names something else.
fn root_history_version(path: &str) -> Option<u32> {
    path.strip_prefix(ROOT_HISTORY_DIR)?
        .strip_prefix('/')?
        .strip_suffix(".root.json")?
        .parse()
        .ok()
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

/// Writes a repository's files into a working tree.
#[derive(Clone, Debug)]
pub struct Writer {
    root: PathBuf,
}

impl Writer {
    /// Write into the working tree rooted at `root`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Writer { root: root.into() }
    }

    /// Write a role's payload and signature files.
    pub fn write_role<M: Metadata + ExtraFields + Clone>(
        &self,
        role: &MetadataPath,
        signed: &Signed<M>,
    ) -> Result<()> {
        self.write(&payload_path(role), signed.raw())?;
        self.write(&signature_path(role), &signed.signature_file()?)
    }

    /// Archive a root version under `root_history/`, so that a client trusting an old root
    /// can walk forward to the current one.
    pub fn archive_root(&self, signed: &Signed<RootMetadata>) -> Result<()> {
        let version = signed.payload().version();
        self.write(&root_history_payload_path(version), signed.raw())?;
        self.write(
            &root_history_signature_path(version),
            &signed.signature_file()?,
        )
    }

    /// Write the signing event state, removing the file when nothing is outstanding.
    ///
    /// Returns whether the path is worth staging: writing it obviously is, and so is
    /// removing one that existed, but a file that was never there and still is not would
    /// make `git add` fail on a path it has never heard of.
    pub fn write_event_state(&self, state: &EventState) -> Result<bool> {
        if !state.is_empty() {
            self.write(EVENT_STATE_PATH, &ser::to_bytes(state)?)?;
            return Ok(true);
        }
        self.remove(EVENT_STATE_PATH)
    }

    /// Delete a role's payload and signature files.
    ///
    /// Returns whether anything was actually there to delete.
    pub fn remove_role(&self, role: &MetadataPath) -> Result<bool> {
        let mut removed = false;
        for path in [payload_path(role), signature_path(role)] {
            removed |= self.remove(&path)?;
        }
        Ok(removed)
    }

    /// Remove a file, reporting whether it was there.
    fn remove(&self, path: &str) -> Result<bool> {
        match std::fs::remove_file(self.root.join(path)) {
            Ok(()) => Ok(true),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(err) => Err(Error::io(format!("removing {path}"), err)),
        }
    }

    fn write(&self, path: &str, bytes: &[u8]) -> Result<()> {
        let full = self.root.join(path);
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|err| Error::io(format!("creating {}", parent.display()), err))?;
        }
        std::fs::write(&full, bytes).map_err(|err| Error::io(format!("writing {path}"), err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_paths_are_classified() {
        let role = |p| role_of_metadata_path(p).map(|r| r.to_string());
        assert_eq!(role("metadata/root.json").as_deref(), Some("root"));
        assert_eq!(role("metadata/crates.json").as_deref(), Some("crates"));
        assert_eq!(role("metadata/root.sig.json"), None);
        assert_eq!(role("metadata/.signing-event.json"), None);
        assert_eq!(role("metadata/root_history/1.root.json"), None);
        assert_eq!(role("metadata/README.md"), None);
        assert_eq!(role("targets/root.json"), None);
    }

    #[test]
    fn archived_root_paths_name_their_version() {
        assert_eq!(
            root_history_version("metadata/root_history/1.root.json"),
            Some(1)
        );
        assert_eq!(
            root_history_version("metadata/root_history/12.root.json"),
            Some(12)
        );
        // The signature file sits beside the payload and is read through it, not listed.
        assert_eq!(
            root_history_version("metadata/root_history/1.root.sig.json"),
            None
        );
        assert_eq!(root_history_version("metadata/root.json"), None);
        assert_eq!(
            root_history_version("metadata/root_history/README.md"),
            None
        );
    }

    #[test]
    fn event_state_round_trips_through_its_file() {
        let mut state = EventState::new();
        state.add("@arlosi", &MetadataPath::root());
        state.add("@arlosi", &MetadataPath::targets());
        state.add("@other", &MetadataPath::root());

        let bytes = ser::to_bytes(&state).unwrap();
        let parsed: EventState = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed, state);

        assert_eq!(parsed.for_user("@arlosi").len(), 2);
        assert_eq!(
            parsed.for_role(&MetadataPath::root()),
            ["@arlosi", "@other"]
        );
        assert!(parsed.for_user("@nobody").is_empty());
    }

    #[test]
    fn accepting_the_last_invitation_empties_the_state() {
        let mut state = EventState::new();
        state.add("@arlosi", &MetadataPath::root());
        state.remove("@arlosi", &MetadataPath::root());
        assert!(state.is_empty());
    }

    #[test]
    fn removing_a_role_withdraws_every_invitation_to_it() {
        let crates = policy::role_name("crates").unwrap();
        let mut state = EventState::new();
        state.add("@arlosi", &crates);
        state.add("@other", &crates);
        state.add("@other", &MetadataPath::root());
        state.remove_role(&crates);
        assert_eq!(state.for_role(&crates), Vec::<&str>::new());
        assert_eq!(state.for_user("@other"), [MetadataPath::root()]);
        assert!(state.for_user("@arlosi").is_empty());
    }

    #[test]
    fn the_signature_file_format_is_fixed() {
        // A real key id and signature, in the layout this crate writes. Nothing verifies
        // against these bytes — signatures cover the payload file — but a change in field
        // order, indentation or base64 dialect would rewrite every signature file in a
        // repository, and these diffs are what reviewers read.
        const FILE: &str = r#"{
  "signatures": [
    {
      "keyid": "bd828d85ebaa1d4a1e59773e5056d384b87f98db8604b77f76af056d36b8e6f9",
      "sig": "MEUCIQDh632FEh1JHYqSMGJgdH/djiDyv31xT1bYgPyPBsF0IwIgXas0UGf023NZKEgyy3y4JPVhzq8Ed0x/yeraHtnV3FU="
    }
  ]
}
"#;

        let parsed: SignatureFile = serde_json::from_slice(FILE.as_bytes()).unwrap();
        assert_eq!(ser::to_bytes(&parsed).unwrap(), FILE.as_bytes());
    }
}
