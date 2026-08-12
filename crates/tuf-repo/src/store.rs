//! Reading and writing a repository's files.
//!
//! Everything the state machine needs is behind [`Source`], which has two implementations:
//! [`FsSource`] reads the working tree, and [`GitSource`] reads a commit without checking
//! it out. That second one is why computing a signing event's status costs nothing: the
//! "known good" state a signing event is compared against is read straight out of the
//! merge-base commit, rather than by cloning the repository into a temporary directory as
//! the Python implementation does on every invocation.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

use crate::envelope::{self, Signatures};
use crate::error::{Error, Result};
use crate::metadata::{Delegator, Payload, RoleName, Root, Snapshot, Targets, Timestamp};
use crate::ser;

/// The directory holding metadata, relative to the repository root.
pub const METADATA_DIR: &str = "metadata";

/// The directory holding artifacts, relative to the repository root.
pub const TARGETS_DIR: &str = "targets";

/// The directory holding every published version of the root role.
pub const ROOT_HISTORY_DIR: &str = "metadata/root_history";

/// The file recording a signing event's open invitations.
pub const EVENT_STATE_PATH: &str = "metadata/.signing-event.json";

/// The path of a role's payload file.
pub fn payload_path(role: &RoleName) -> String {
    format!("{METADATA_DIR}/{role}.json")
}

/// The path of a role's signature file.
pub fn signature_path(role: &RoleName) -> String {
    format!("{METADATA_DIR}/{role}.sig.json")
}

/// The path of an archived root version's payload file.
pub fn root_history_payload_path(version: u64) -> String {
    format!("{ROOT_HISTORY_DIR}/{version}.root.json")
}

/// The path of an archived root version's signature file.
pub fn root_history_signature_path(version: u64) -> String {
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
// Signed metadata
// ---------------------------------------------------------------------------

/// A metadata payload together with the signatures over it.
///
/// The bytes the payload was read from are kept alongside the parsed value, and signatures
/// are always checked against *those* bytes. A payload is therefore never re-serialized in
/// order to verify it, so no amount of drift in how this crate writes JSON can turn a
/// valid repository into an invalid one.
#[derive(Clone, Debug, PartialEq)]
pub struct Signed<P> {
    raw: Vec<u8>,
    payload: P,
    signatures: Signatures,
}

impl<P: Payload> Signed<P> {
    /// Serialize `payload` into a new, unsigned document.
    pub fn new(payload: P) -> Result<Self> {
        Ok(Signed {
            raw: ser::to_bytes(&payload)?,
            payload,
            signatures: Signatures::new(),
        })
    }

    /// Parse a payload file and its signature file.
    pub fn parse(raw: Vec<u8>, signatures: Signatures) -> Result<Self> {
        let payload: P = serde_json::from_slice(&raw)?;
        payload.check_type()?;
        Ok(Signed {
            raw,
            payload,
            signatures,
        })
    }

    /// The parsed payload.
    pub fn payload(&self) -> &P {
        &self.payload
    }

    /// The exact bytes of the payload file.
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// The signatures gathered so far.
    pub fn signatures(&self) -> &Signatures {
        &self.signatures
    }

    /// The bytes that a signature over this payload is computed over.
    pub fn signing_input(&self) -> Vec<u8> {
        envelope::signing_input(&self.raw)
    }

    /// Replace the payload, discarding every signature.
    ///
    /// The signatures are dropped rather than kept because they were made over the old
    /// bytes: keeping them would leave a document whose signatures verify against
    /// something other than what it now says.
    pub fn set_payload(&mut self, payload: P) -> Result<()> {
        self.raw = ser::to_bytes(&payload)?;
        self.payload = payload;
        self.signatures.clear();
        Ok(())
    }

    /// Edit the payload in place, discarding every signature if it changed.
    ///
    /// Returns whether the payload ended up different. An edit that changes nothing leaves
    /// existing signatures alone, so re-running a tool is not a way to lose signatures.
    pub fn edit(&mut self, edit: impl FnOnce(&mut P)) -> Result<bool> {
        let mut payload = self.payload.clone();
        edit(&mut payload);
        if payload == self.payload {
            return Ok(false);
        }
        self.set_payload(payload)?;
        Ok(true)
    }

    /// Record a signature over the current payload bytes.
    pub fn add_signature(&mut self, key_id: crate::crypto::KeyId, signature: &[u8]) {
        self.signatures
            .insert(envelope::Signature::new(key_id, signature));
    }

    /// Sign the current payload bytes with `signer`.
    pub fn sign_with(&mut self, signer: &mut dyn crate::signer::Signer) -> Result<()> {
        let signature = signer.sign(&self.signing_input())?;
        let key_id = signer.key_id().clone();

        // Check our own work before storing it: a signing device that returns a signature
        // over the wrong bytes, or with the wrong key, should be caught here rather than
        // by CI after the signer has gone home.
        crate::crypto::verify(
            crate::crypto::ECDSA_SHA2_NISTP256,
            signer.public_key_pem(),
            &self.signing_input(),
            &signature,
        )
        .map_err(|_| Error::BadSignature(key_id.clone()))?;

        self.add_signature(key_id, &signature);
        Ok(())
    }

    /// Check this document's signatures against what `delegator` says about `role`.
    pub fn tally(&self, delegator: &Delegator, role: &RoleName) -> Tally {
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

        for key_id in spec.keyids {
            let Some(key) = delegator.key(key_id) else {
                // A delegation naming a key the delegator does not hold can never be
                // satisfied. Report it as an unusable signer rather than ignoring it.
                tally.invalid.push(SignerRef {
                    key_id: key_id.clone(),
                    name: format!("<unknown key {}>", key_id.abbreviated()),
                });
                continue;
            };
            let who = SignerRef {
                key_id: key_id.clone(),
                name: key.signer_name().to_owned(),
            };
            match self.signatures.get(key_id) {
                None => tally.missing.push(who),
                Some(signature) => match signature
                    .decode()
                    .and_then(|bytes| key.verify(&message, &bytes))
                {
                    Ok(()) => tally.signed.push(who),
                    Err(_) => tally.invalid.push(who),
                },
            }
        }

        tally
    }

    /// Consume this document, returning its payload.
    pub fn into_payload(self) -> P {
        self.payload
    }
}

impl Signed<Root> {
    /// This root as a delegator of the top-level roles.
    pub fn delegator(&self) -> Delegator {
        Delegator::Root(self.payload.clone())
    }
}

impl Signed<Targets> {
    /// This targets role as a delegator of the roles it delegates to.
    pub fn delegator(&self) -> Delegator {
        Delegator::Targets(self.payload.clone())
    }
}

/// A key, named the way a person would recognise it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignerRef {
    /// The key's id.
    pub key_id: crate::crypto::KeyId,
    /// The signer's `@handle`, or an online signer's URI.
    pub name: String,
}

/// How a role's signatures stand against its threshold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tally {
    /// The role the signatures are for.
    pub role: RoleName,
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
    ///
    /// This is what a role nothing delegates to looks like, and what a role reports while
    /// its delegating metadata is missing.
    pub fn empty(role: RoleName) -> Self {
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

/// The contents of `metadata/.signing-event.json`.
///
/// An invitation records that somebody has been added as a signer of a role but has not
/// yet contributed a key. The file exists only while an event has open invitations; the
/// last accepted invitation removes it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invites {
    /// Roles each invited signer has yet to accept, keyed by `@handle`.
    #[serde(default)]
    pub invites: BTreeMap<String, Vec<RoleName>>,
}

impl Invites {
    /// No open invitations.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether there are no open invitations at all.
    pub fn is_empty(&self) -> bool {
        self.invites.is_empty()
    }

    /// The roles `user` has been invited to.
    pub fn for_user(&self, user: &str) -> &[RoleName] {
        self.invites.get(user).map_or(&[], Vec::as_slice)
    }

    /// The users invited to `role`.
    pub fn for_role(&self, role: &RoleName) -> Vec<&str> {
        self.invites
            .iter()
            .filter(|(_, roles)| roles.contains(role))
            .map(|(user, _)| user.as_str())
            .collect()
    }

    /// Invite `user` to sign `role`.
    pub fn add(&mut self, user: &str, role: &RoleName) {
        let roles = self.invites.entry(user.to_owned()).or_default();
        if !roles.contains(role) {
            roles.push(role.clone());
            roles.sort();
        }
    }

    /// Withdraw `user`'s invitation to `role`.
    pub fn remove(&mut self, user: &str, role: &RoleName) {
        if let Some(roles) = self.invites.get_mut(user) {
            roles.retain(|invited| invited != role);
            if roles.is_empty() {
                self.invites.remove(user);
            }
        }
    }

    /// Withdraw every invitation to `role`, whoever holds it.
    pub fn remove_role(&mut self, role: &RoleName) {
        for roles in self.invites.values_mut() {
            roles.retain(|invited| invited != role);
        }
        self.invites.retain(|_, roles| !roles.is_empty());
    }
}

// ---------------------------------------------------------------------------
// Loading a whole repository
// ---------------------------------------------------------------------------

/// Every role in a repository at one point in time.
#[derive(Clone, Debug, Default)]
pub struct RepoState {
    /// The root role, absent before the repository has been created.
    pub root: Option<Signed<Root>>,
    /// The top-level targets role and every delegated targets role.
    pub targets: BTreeMap<RoleName, Signed<Targets>>,
    /// The snapshot role, which only online signing produces.
    pub snapshot: Option<Signed<Snapshot>>,
    /// The timestamp role, which only online signing produces.
    pub timestamp: Option<Signed<Timestamp>>,
    /// Open invitations, if this state is mid-signing-event.
    pub invites: Invites,
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
            let signatures = read_signatures(source, &role)?;

            if role == RoleName::root() {
                state.root = Some(Signed::parse(raw, signatures)?);
            } else if role == RoleName::snapshot() {
                state.snapshot = Some(Signed::parse(raw, signatures)?);
            } else if role == RoleName::timestamp() {
                state.timestamp = Some(Signed::parse(raw, signatures)?);
            } else {
                state.targets.insert(role, Signed::parse(raw, signatures)?);
            }
        }

        if let Some(raw) = source.read(EVENT_STATE_PATH)? {
            state.invites = serde_json::from_slice(&raw)?;
        }

        Ok(state)
    }

    /// Whether the repository exists at all.
    pub fn is_initialized(&self) -> bool {
        self.root.is_some()
    }

    /// The root role, or an error naming what is missing.
    pub fn root(&self) -> Result<&Signed<Root>> {
        self.root
            .as_ref()
            .ok_or_else(|| Error::invalid("this repository has no root metadata yet"))
    }

    /// The role that defines the keys and threshold of `role`.
    ///
    /// Top-level roles are delegated by root; everything else by the top-level targets
    /// role.
    pub fn delegator_of(&self, role: &RoleName) -> Result<Delegator> {
        if role.is_top_level() {
            Ok(self.root()?.delegator())
        } else {
            self.targets
                .get(&RoleName::targets())
                .map(Signed::<Targets>::delegator)
                .ok_or_else(|| Error::NoSuchRole(RoleName::targets().to_string()))
        }
    }

    /// Every role present, ordered `root`, `targets`, then delegates alphabetically.
    ///
    /// The order matters wherever roles are reported or processed in turn: a delegating
    /// role has to be dealt with before the roles it delegates to.
    pub fn role_names(&self) -> Vec<RoleName> {
        let mut names = Vec::new();
        if self.root.is_some() {
            names.push(RoleName::root());
        }
        if self.targets.contains_key(&RoleName::targets()) {
            names.push(RoleName::targets());
        }
        names.extend(
            self.targets
                .keys()
                .filter(|role| **role != RoleName::targets())
                .cloned(),
        );
        names
    }

    /// The version of `role`, or zero if it does not exist here.
    ///
    /// Zero for an absent role is what makes "one more than the known-good version" the
    /// right rule for a role being created for the first time as well as for one being
    /// changed.
    pub fn version_of(&self, role: &RoleName) -> u64 {
        if *role == RoleName::root() {
            return self.root.as_ref().map_or(0, |r| r.payload().version);
        }
        self.targets.get(role).map_or(0, |t| t.payload().version)
    }
}

/// The role a metadata path belongs to, or `None` if it is not a role payload.
///
/// Signature files, the event state file and archived roots all read as `None`.
fn role_of_metadata_path(path: &str) -> Option<RoleName> {
    let name = path.strip_prefix(METADATA_DIR)?.strip_prefix('/')?;
    // Anything in a subdirectory is history, not current state.
    if name.contains('/') {
        return None;
    }
    let stem = name.strip_suffix(".json")?;
    if stem.ends_with(".sig") || stem.starts_with('.') {
        return None;
    }
    stem.parse().ok()
}

fn read_signatures(source: &dyn Source, role: &RoleName) -> Result<Signatures> {
    match source.read(&signature_path(role))? {
        Some(raw) => Ok(serde_json::from_slice(&raw)?),
        None => Ok(Signatures::new()),
    }
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
    ///
    /// Writing root also archives that version under `root_history/`, so that a client
    /// that trusts an old root can walk forward to the current one.
    pub fn write_role<P: Payload>(&self, role: &RoleName, signed: &Signed<P>) -> Result<()> {
        self.write(&payload_path(role), signed.raw())?;
        self.write(&signature_path(role), &ser::to_bytes(signed.signatures())?)?;

        if *role == RoleName::root() {
            let version = signed.payload().version();
            self.write(&root_history_payload_path(version), signed.raw())?;
            self.write(
                &root_history_signature_path(version),
                &ser::to_bytes(signed.signatures())?,
            )?;
        }
        Ok(())
    }

    /// Write the signing event state, removing the file when no invitations are open.
    ///
    /// Returns whether the path is worth staging: writing it obviously is, and so is
    /// removing one that existed, but a file that was never there and still is not would
    /// make `git add` fail on a path it has never heard of.
    pub fn write_invites(&self, invites: &Invites) -> Result<bool> {
        if !invites.is_empty() {
            self.write(EVENT_STATE_PATH, &ser::to_bytes(invites)?)?;
            return Ok(true);
        }
        self.remove(EVENT_STATE_PATH)
    }

    /// Delete a role's payload and signature files.
    ///
    /// Returns whether anything was actually there to delete.
    pub fn remove_role(&self, role: &RoleName) -> Result<bool> {
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
    fn invites_round_trip_through_their_file() {
        let mut invites = Invites::new();
        invites.add("@arlosi", &RoleName::root());
        invites.add("@arlosi", &RoleName::targets());
        invites.add("@other", &RoleName::root());

        let bytes = ser::to_bytes(&invites).unwrap();
        let parsed: Invites = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed, invites);

        assert_eq!(parsed.for_user("@arlosi").len(), 2);
        assert_eq!(parsed.for_role(&RoleName::root()), ["@arlosi", "@other"]);
        assert!(parsed.for_user("@nobody").is_empty());
    }

    #[test]
    fn accepting_the_last_invitation_empties_the_state() {
        let mut invites = Invites::new();
        invites.add("@arlosi", &RoleName::root());
        invites.remove("@arlosi", &RoleName::root());
        assert!(invites.is_empty());
    }

    #[test]
    fn removing_a_role_withdraws_every_invitation_to_it() {
        let mut invites = Invites::new();
        invites.add("@a", &RoleName::root());
        invites.add("@b", &RoleName::root());
        invites.add("@b", &RoleName::targets());
        invites.remove_role(&RoleName::root());
        assert_eq!(invites.for_user("@b"), [RoleName::targets()]);
        assert!(invites.for_user("@a").is_empty());
    }
}
