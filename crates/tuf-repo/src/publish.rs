//! Turning a signed repository into the files a TUF client fetches.
//!
//! A signing event leaves the repository in a form built for review: each role is a
//! payload file and a signature file, side by side in git, so a diff says what changed.
//! A client wants neither of those. It wants one DSSE envelope per role, named by version,
//! reachable over HTTP:
//!
//! ```text
//! metadata/1.root.json      metadata/root.json        the same document, two names
//! metadata/3.targets.json   metadata/9.snapshot.json
//! metadata/timestamp.json
//! targets/crates/<sha256>.serde-1.0.0.crate
//! ```
//!
//! Publishing is the translation, and nothing more. It signs nothing, mints nothing and
//! dates nothing: every byte it writes is either a document already signed in git or a
//! copy of an artifact those documents describe. That is what lets somebody who holds no
//! keys at all check the published repository — run this against the same commit and the
//! files come out identical, byte for byte. It also means `snapshot` and `timestamp` must
//! already be committed; they are the online key's work, and publishing cannot stand in
//! for it.
//!
//! # What is checked first
//!
//! Before a single file is written, the whole repository is replayed through
//! [`tuf::database::Database`] — the same code a client runs. The root chain is walked
//! from the oldest archived version forward, then timestamp, snapshot, targets and each
//! delegated role in turn, each verified against the one that vouches for it. Artifacts
//! are then checked against the descriptions in that verified metadata as they are read.
//! A repository that would not satisfy a client does not get published.
//!
//! # Uploading, and uploading again
//!
//! Every name here except `metadata/root.json` and `metadata/timestamp.json` pins its own
//! contents: a version number for metadata, a hash for artifacts. Those files are written
//! once and never rewritten, which is what makes republishing cheap — a [`Sink`] is asked
//! whether it already holds a file, and only the ones it does not are transferred.
//!
//! It is also what makes an interrupted publish harmless. Files go out in dependency
//! order — artifacts, then the metadata describing them, then `snapshot`, and
//! `timestamp` last — so at every moment the live `timestamp.json` names a snapshot whose
//! roles and artifacts are all already there. A publish that dies halfway leaves the
//! previous repository intact and adds some files nothing points at yet.
//!
//! Nothing is ever deleted. An old `4.snapshot.json` costs a few kilobytes and is the
//! difference between a client mid-update carrying on and a client failing.
//!
//! For an object store this is one `ListObjectsV2` to learn what is already there, a `PUT`
//! per missing file in the order [`Plan::entries`] gives them, and no delete pass. See
//! [`Sink`].

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tuf::crypto::HashAlgorithm;
use tuf::database::Database;
use tuf::metadata::{
    Metadata, MetadataPath, MetadataVersion, RawSignedMetadata, RootMetadata, TargetPath,
};
use tuf::pouf::Pouf2;

use crate::crypto;
use crate::error::{Error, Result};
use crate::store::{self, ExtraFields, RepoState, Signed, Source};

/// The directory published metadata is served from.
pub const METADATA_PREFIX: &str = "metadata";

/// The directory published artifacts are served from.
pub const TARGETS_PREFIX: &str = "targets";

// ---------------------------------------------------------------------------
// What gets published
// ---------------------------------------------------------------------------

/// One file in a published repository.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Where the file is served from, relative to the repository's base URL.
    pub path: String,
    /// Hex SHA-256 of the file's contents.
    pub digest: String,
    /// The file's length in bytes.
    pub size: u64,
    /// Whether the name pins the contents.
    ///
    /// True for everything addressed by a version number or a hash, which is everything
    /// but `root.json` and `timestamp.json`. A [`Sink`] that finds an immutable file
    /// already in place can skip it without looking at what is in it.
    pub immutable: bool,
    origin: Origin,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Origin {
    /// A DSSE envelope, assembled in memory.
    Envelope(Vec<u8>),
    /// An artifact, read from the repository at this path when it is needed.
    Artifact(String),
}

/// Everything a repository publishes, in the order it must be written.
#[derive(Clone, Debug)]
pub struct Plan {
    entries: Vec<Entry>,
}

/// What a publish did.
#[derive(Clone, Debug, Default)]
pub struct Report {
    /// The files transferred.
    pub written: Vec<String>,
    /// The files the sink already held.
    pub unchanged: Vec<String>,
    /// How many bytes were transferred.
    pub bytes: u64,
}

impl Report {
    /// Whether anything was actually written.
    pub fn changed(&self) -> bool {
        !self.written.is_empty()
    }
}

/// A published repository's files and their digests.
///
/// The thing to compare when checking that what is live is what the signed metadata says
/// it should be: build the same commit, and the two manifests match.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Every published file, ordered by path.
    pub files: Vec<ManifestEntry>,
}

/// One line of a [`Manifest`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEntry {
    /// Where the file is served from.
    pub path: String,
    /// Hex SHA-256 of its contents.
    pub sha256: String,
    /// Its length in bytes.
    pub size: u64,
}

impl Plan {
    /// Work out what `source` publishes, verifying it as a client would.
    ///
    /// `as_of` is the moment expiry is judged against. It is a parameter rather than
    /// "now" so that reproducing an older publish does not fail on metadata that has since
    /// expired.
    pub fn build(source: &dyn Source, as_of: DateTime<Utc>) -> Result<Self> {
        let state = RepoState::load(source)?;
        let history = store::read_root_history(source)?;
        let chain = root_chain(&state, &history)?;
        let database = verify(&state, &chain, as_of)?;

        let root = state.root()?;
        let snapshot = online_role(state.snapshot.as_ref(), "snapshot")?;
        let timestamp = online_role(state.timestamp.as_ref(), "timestamp")?;
        let consistent = root.payload().consistent_snapshot();
        let named = |version: u32| {
            if consistent {
                MetadataVersion::Number(version)
            } else {
                MetadataVersion::None
            }
        };

        let mut entries = Vec::new();

        // Artifacts first. Nothing published later can be read by a client until the
        // files it describes are in place, and a publish that fails on a missing artifact
        // should fail before it has changed anything a client can see.
        for path in target_paths(&database) {
            let description = database
                .target_description_with_start_time(&as_of, &path)
                .map_err(|err| Error::invalid(format!("{path}: {err}")))?;
            let hash = description
                .hashes()
                .get(&HashAlgorithm::Sha256)
                .ok_or_else(|| Error::invalid(format!("{path} is described without a sha256")))?;
            let published = if consistent {
                path.with_hash_prefix(hash).map_err(Error::invalid)?
            } else {
                path.clone()
            };

            entries.push(Entry {
                path: format!("{TARGETS_PREFIX}/{published}"),
                digest: hash.to_string(),
                size: description.length(),
                immutable: consistent,
                origin: Origin::Artifact(format!("{}/{path}", store::TARGETS_DIR)),
            });
        }

        // Then the roles that describe them, each before whatever vouches for it:
        // delegated roles, the top-level targets role, root, snapshot, and timestamp last.
        for (role, signed) in &state.targets {
            if *role != MetadataPath::targets() {
                entries.push(metadata_entry(
                    role,
                    named(signed.payload().version()),
                    signed,
                )?);
            }
        }
        let targets = state
            .targets
            .get(&MetadataPath::targets())
            .ok_or_else(|| Error::invalid("this repository has no targets metadata"))?;
        entries.push(metadata_entry(
            &MetadataPath::targets(),
            named(targets.payload().version()),
            targets,
        )?);

        for (version, signed) in &chain {
            // Root is versioned whatever `consistent_snapshot` says: walking the chain one
            // version at a time is how a client learns to trust the current root at all.
            entries.push(metadata_entry(
                &MetadataPath::root(),
                MetadataVersion::Number(*version),
                *signed,
            )?);
        }
        entries.push(metadata_entry(
            &MetadataPath::root(),
            MetadataVersion::None,
            root,
        )?);

        entries.push(metadata_entry(
            &MetadataPath::snapshot(),
            named(snapshot.payload().version()),
            snapshot,
        )?);
        entries.push(metadata_entry(
            &MetadataPath::timestamp(),
            MetadataVersion::None,
            timestamp,
        )?);

        Ok(Plan { entries })
    }

    /// Every file this publishes, in the order it must be written.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// The published files and their digests, ordered by path.
    pub fn manifest(&self) -> Manifest {
        let mut files: Vec<ManifestEntry> = self
            .entries
            .iter()
            .map(|entry| ManifestEntry {
                path: entry.path.clone(),
                sha256: entry.digest.clone(),
                size: entry.size,
            })
            .collect();
        files.sort_by(|a, b| a.path.cmp(&b.path));
        Manifest { files }
    }

    /// Write everything `sink` does not already hold, reading artifacts from `source`.
    pub fn write(&self, source: &dyn Source, sink: &mut dyn Sink) -> Result<Report> {
        let mut report = Report::default();

        for entry in &self.entries {
            if sink.has(entry)? {
                report.unchanged.push(entry.path.clone());
                continue;
            }
            let bytes = self.contents(entry, source)?;
            sink.put(entry, &bytes)?;
            report.bytes += bytes.len() as u64;
            report.written.push(entry.path.clone());
        }

        Ok(report)
    }

    fn contents<'a>(&'a self, entry: &'a Entry, source: &dyn Source) -> Result<Cow<'a, [u8]>> {
        let path = match &entry.origin {
            Origin::Envelope(bytes) => return Ok(Cow::Borrowed(bytes)),
            Origin::Artifact(path) => path,
        };

        let bytes = source.read(path)?.ok_or_else(|| {
            Error::invalid(format!(
                "{path} is described by targets metadata but is not in the repository"
            ))
        })?;

        // The metadata is signed and the file beside it is not, so the two can disagree —
        // an artifact edited after it was signed for, say. Publishing it anyway would put
        // a file live that every client rejects, under a name that says it is something
        // else.
        if bytes.len() as u64 != entry.size || hex::encode(crypto::sha256(&bytes)) != entry.digest {
            return Err(Error::invalid(format!(
                "{path} is not the file the signed targets metadata describes"
            )));
        }

        Ok(Cow::Owned(bytes))
    }
}

// ---------------------------------------------------------------------------
// Where it goes
// ---------------------------------------------------------------------------

/// Somewhere a published repository is written.
///
/// Two methods, because a publish is mostly a question of what can be skipped. An
/// implementation backed by an object store answers [`has`](Sink::has) from one bucket
/// listing: for an immutable entry the name alone settles it, and for the two mutable ones
/// — `root.json` and `timestamp.json` — it should say `false` and let them be rewritten.
pub trait Sink {
    /// Store `bytes` at `entry.path`.
    fn put(&mut self, entry: &Entry, bytes: &[u8]) -> Result<()>;

    /// Whether this sink already holds `entry` exactly.
    ///
    /// Answering `false` is always safe; it costs a transfer.
    fn has(&mut self, entry: &Entry) -> Result<bool> {
        let _ = entry;
        Ok(false)
    }
}

/// Writes a published repository into a directory.
#[derive(Clone, Debug)]
pub struct FsSink {
    root: PathBuf,
}

impl FsSink {
    /// Publish into the directory at `root`, creating it as needed.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        FsSink { root: root.into() }
    }

    /// The directory being published into.
    pub fn root(&self) -> &Path {
        &self.root
    }
}

impl Sink for FsSink {
    fn put(&mut self, entry: &Entry, bytes: &[u8]) -> Result<()> {
        let full = self.root.join(&entry.path);
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|err| Error::io(format!("creating {}", parent.display()), err))?;
        }
        std::fs::write(&full, bytes)
            .map_err(|err| Error::io(format!("writing {}", entry.path), err))
    }

    fn has(&mut self, entry: &Entry) -> Result<bool> {
        // A local directory can afford to check the contents rather than trust the name,
        // and doing so is the point of publishing locally: an auditor rebuilding a live
        // repository wants every file compared, not the immutable ones assumed.
        match std::fs::read(self.root.join(&entry.path)) {
            Ok(bytes) => Ok(bytes.len() as u64 == entry.size
                && hex::encode(crypto::sha256(&bytes)) == entry.digest),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(err) => Err(Error::io(format!("reading {}", entry.path), err)),
        }
    }
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// Every root version this repository publishes, current one included.
fn root_chain<'a>(
    state: &'a RepoState,
    history: &'a BTreeMap<u32, Signed<RootMetadata>>,
) -> Result<BTreeMap<u32, &'a Signed<RootMetadata>>> {
    let root = state.root()?;
    let current = root.payload().version();

    let mut chain: BTreeMap<u32, &Signed<RootMetadata>> = history
        .iter()
        .map(|(version, signed)| (*version, signed))
        .collect();

    if let Some(newer) = chain.keys().rev().find(|version| **version > current) {
        return Err(Error::invalid(format!(
            "{} is archived, but metadata/root.json is version {current}",
            store::root_history_payload_path(*newer)
        )));
    }

    if let Some(archived) = chain.insert(current, root)
        && archived != root
    {
        return Err(Error::invalid(format!(
            "{} does not match metadata/root.json",
            store::root_history_payload_path(current)
        )));
    }

    Ok(chain)
}

/// Replay the repository the way a client would, and hand back what it came to trust.
fn verify(
    state: &RepoState,
    chain: &BTreeMap<u32, &Signed<RootMetadata>>,
    as_of: DateTime<Utc>,
) -> Result<Database<Pouf2>> {
    let versions: Vec<u32> = chain.keys().copied().collect();
    let (first, last) = match (versions.first(), versions.last()) {
        (Some(first), Some(last)) => (*first, *last),
        _ => return Err(Error::invalid("this repository has no root metadata")),
    };
    if versions.len() as u32 != last - first + 1 {
        return Err(Error::invalid(
            "metadata/root_history is missing a version, so the root chain cannot be walked",
        ));
    }

    // The oldest root we hold is the trust anchor, since there is nothing left to check it
    // against. Every version after it is verified against its predecessor and itself.
    let mut database = Database::from_trusted_root(&raw(chain[&first])?)
        .map_err(|err| Error::invalid(format!("root version {first} is not usable: {err}")))?;
    for version in first + 1..=last {
        database
            .update_root(&raw(chain[&version])?)
            .map_err(|err| Error::invalid(format!("root version {version}: {err}")))?;
    }

    let snapshot = online_role(state.snapshot.as_ref(), "snapshot")?;
    let timestamp = online_role(state.timestamp.as_ref(), "timestamp")?;
    database
        .update_timestamp(&as_of, &raw(timestamp)?)
        .map_err(|err| expiry_hint("timestamp", err))?;
    database
        .update_snapshot(&as_of, &raw(snapshot)?)
        .map_err(|err| expiry_hint("snapshot", err))?;

    let targets = state
        .targets
        .get(&MetadataPath::targets())
        .ok_or_else(|| Error::invalid("this repository has no targets metadata"))?;
    database
        .update_targets(&as_of, &raw(targets)?)
        .map_err(|err| expiry_hint("targets", err))?;

    // A delegated role may not delegate further, so every one of them hangs off the
    // top-level targets role and can be loaded in one pass.
    for (role, signed) in &state.targets {
        if *role == MetadataPath::targets() {
            continue;
        }
        database
            .update_delegated_targets(&as_of, &MetadataPath::targets(), role, &raw(signed)?)
            .map_err(|err| expiry_hint(role.as_str(), err))?;
    }

    Ok(database)
}

/// A role that only online signing produces, or an error saying who has to produce it.
fn online_role<'a, M>(signed: Option<&'a Signed<M>>, role: &str) -> Result<&'a Signed<M>> {
    signed.ok_or_else(|| {
        Error::invalid(format!(
            "there is no {role} metadata to publish. {role} is signed by the online key when a \
             signing event merges, and a client cannot use a repository without it"
        ))
    })
}

fn expiry_hint(role: &str, err: tuf::Error) -> Error {
    let hint = match err {
        tuf::Error::ExpiredMetadata { .. } => {
            ". Pass the time the repository was published to reproduce an older publish"
        }
        _ => "",
    };
    Error::invalid(format!("{role} metadata does not verify: {err}{hint}"))
}

/// Every artifact path the verified metadata describes.
fn target_paths(database: &Database<Pouf2>) -> BTreeSet<TargetPath> {
    let mut paths = BTreeSet::new();
    if let Some(targets) = database.trusted_targets() {
        paths.extend(targets.targets().keys().cloned());
    }
    for delegated in database.trusted_delegations().values() {
        paths.extend(delegated.targets().keys().cloned());
    }
    paths
}

fn raw<M: Metadata + ExtraFields + Clone>(
    signed: &Signed<M>,
) -> Result<RawSignedMetadata<Pouf2, M>> {
    Ok(RawSignedMetadata::new(signed.envelope()?))
}

fn metadata_entry<M: Metadata + ExtraFields + Clone>(
    role: &MetadataPath,
    version: MetadataVersion,
    signed: &Signed<M>,
) -> Result<Entry> {
    let bytes = signed.envelope()?;
    Ok(Entry {
        path: format!(
            "{METADATA_PREFIX}/{}",
            role.components::<Pouf2>(version).join("/")
        ),
        digest: hex::encode(crypto::sha256(&bytes)),
        size: bytes.len() as u64,
        immutable: matches!(version, MetadataVersion::Number(_)),
        origin: Origin::Envelope(bytes),
    })
}
