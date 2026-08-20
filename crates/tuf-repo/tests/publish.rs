//! Publishing: from the pair of files a signing event leaves in git to the files a client
//! fetches.
//!
//! The test that matters here is the last step of every case: take what was published and
//! walk it the way a client does — trust the oldest root, follow the chain forward, then
//! timestamp, snapshot, targets, the delegated role, and finally the artifact itself. If
//! that walk succeeds against the published bytes, the repository is live.

use std::collections::BTreeMap;
use std::path::Path;

use chrono::{DateTime, Duration, TimeZone, Utc};
use tuf::crypto::HashAlgorithm;
use tuf::database::Database;
use tuf::metadata::{
    Metadata, MetadataDescription, MetadataPath, MetadataVersion, RawSignedMetadata, RootMetadata,
    SnapshotMetadata, SnapshotMetadataBuilder, TargetPath, TargetsMetadata, TimestampMetadata,
    TimestampMetadataBuilder,
};
use tuf::pouf::Pouf2;

use tuf_repo::crypto::PublicKey;
use tuf_repo::event::{RoleConfig, SigningEvent};
use tuf_repo::policy::{self, Periods, RoleName};
use tuf_repo::publish::{FsSink, Plan, Sink};
use tuf_repo::signer::Signer as _;
use tuf_repo::store::{self, ExtraFields, RepoState, Signed, Source, Writer};
use tuf_repo::testing::MemorySigner;

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// A repository held in memory, standing in for a branch.
#[derive(Clone, Debug, Default)]
struct Files(BTreeMap<String, Vec<u8>>);

impl Source for Files {
    fn read(&self, path: &str) -> tuf_repo::Result<Option<Vec<u8>>> {
        Ok(self.0.get(path).cloned())
    }

    fn list(&self, dir: &str) -> tuf_repo::Result<Vec<String>> {
        let prefix = format!("{dir}/");
        Ok(self
            .0
            .keys()
            .filter(|path| path.starts_with(&prefix))
            .cloned()
            .collect())
    }
}

struct Repo {
    main: Files,
    dir: tempfile::TempDir,
}

impl Repo {
    fn new() -> Self {
        Repo {
            main: Files::default(),
            dir: tempfile::tempdir().expect("temp dir"),
        }
    }

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 12, 12, 0, 0).unwrap()
    }

    fn event_with(&self, files: &Files) -> SigningEvent {
        let known_good = RepoState::load(&self.main).expect("main loads");
        let mut merged = self.main.clone();
        merged.0.extend(files.0.clone());
        let current = RepoState::load(&merged).expect("event branch loads");
        SigningEvent::from_states(known_good, current).at(Self::now())
    }

    /// Merge an event, as a push to `main` would.
    fn merge(&mut self, event: &SigningEvent) {
        let writer = Writer::new(self.dir.path());
        for path in event.persist(&writer).expect("event persists") {
            if let Ok(bytes) = std::fs::read(self.dir.path().join(&path)) {
                self.main.0.insert(path, bytes);
            }
        }
        if event.event_state().is_empty() {
            self.main.0.remove("metadata/.signing-event.json");
        }
    }
}

fn periods() -> Periods {
    Periods {
        expiry_days: 365,
        signing_days: 60,
    }
}

fn config(signers: &[&str], threshold: u32) -> RoleConfig {
    RoleConfig {
        signers: signers.iter().map(|s| (*s).to_owned()).collect(),
        threshold,
        periods: periods(),
    }
}

fn key_of(owner: &str) -> PublicKey {
    MemorySigner::for_owner(owner).public_key().clone()
}

const ONLINE_URI: &str = "gcpkms:projects/example/locations/global/keyRings/tuf/cryptoKeys/online";

/// A repository with a `crates` delegation and one artifact in each targets role, signed
/// and merged, but not yet published.
fn repository() -> Repo {
    let mut repo = Repo::new();
    let crates: RoleName = policy::role_name("crates").unwrap();

    let mut event = repo.event_with(&Files::default());
    event
        .initialize(periods(), key_of("@alice"), "@alice")
        .unwrap();
    for role in [RoleName::snapshot(), RoleName::timestamp()] {
        event
            .configure_online_role(&role, key_of("online"), ONLINE_URI, periods())
            .unwrap();
    }
    event
        .configure_role(&crates, &config(&["@alice"], 1))
        .unwrap();
    event
        .accept_invite(&crates, "@alice", key_of("@alice"))
        .unwrap();

    let mut alice = MemorySigner::for_owner("@alice");
    for role in [RoleName::root(), RoleName::targets(), crates.clone()] {
        event.sign(&role, &mut alice).unwrap();
    }
    assert!(event.status().is_mergeable(), "{:#?}", event.status());
    repo.merge(&event);

    add_artifacts(
        &mut repo,
        &[
            ("notice.txt", b"read me".to_vec()),
            ("crates/serde-1.0.0.crate", b"not really a crate".to_vec()),
        ],
    );
    online_sign(&mut repo);
    repo
}

/// Commit artifacts, rebuild the targets metadata over them, sign, and merge.
fn add_artifacts(repo: &mut Repo, artifacts: &[(&str, Vec<u8>)]) {
    let mut files = Files::default();
    for (path, contents) in artifacts {
        files.0.insert(format!("targets/{path}"), contents.clone());
    }

    let mut event = repo.event_with(&files);
    let mut all = repo.main.clone();
    all.0.extend(files.0.clone());
    let updated = event.update_targets(&all).unwrap();
    assert!(!updated.is_empty(), "the artifacts changed no role");

    let mut alice = MemorySigner::for_owner("@alice");
    for role in &updated {
        event.sign(role, &mut alice).unwrap();
    }
    assert!(event.status().is_mergeable(), "{:#?}", event.status());
    repo.merge(&event);
    repo.main.0.extend(files.0);
}

/// What the online key does when an event merges.
///
/// Both descriptions cover the published *envelope*, not the payload file, because that is
/// what a client downloads and hashes. Nothing else here would notice if they did not, but
/// a client would refuse the repository.
fn online_sign(repo: &mut Repo) {
    let state = RepoState::load(&repo.main).unwrap();
    let mut online = MemorySigner::for_owner("online");
    let now = Repo::now();

    let mut builder = SnapshotMetadataBuilder::new()
        .version(
            state
                .snapshot
                .as_ref()
                .map_or(1, |s| s.payload().version() + 1),
        )
        .expires(now + Duration::days(7));
    for (role, signed) in &state.targets {
        builder = builder.insert_metadata_description(
            role.clone(),
            describe(&signed.envelope().unwrap(), signed.payload().version()),
        );
    }
    let mut snapshot = Signed::new(builder.build().unwrap()).unwrap();
    snapshot.sign_with(&mut online).unwrap();

    let timestamp = TimestampMetadataBuilder::from_metadata_description(describe(
        &snapshot.envelope().unwrap(),
        snapshot.payload().version(),
    ))
    .version(
        state
            .timestamp
            .as_ref()
            .map_or(1, |t| t.payload().version() + 1),
    )
    .expires(now + Duration::days(1))
    .build()
    .unwrap();
    let mut timestamp = Signed::new(timestamp).unwrap();
    timestamp.sign_with(&mut online).unwrap();

    put(&mut repo.main, &MetadataPath::snapshot(), &snapshot);
    put(&mut repo.main, &MetadataPath::timestamp(), &timestamp);
}

fn describe<M: Metadata>(envelope: &[u8], version: u32) -> MetadataDescription<M> {
    MetadataDescription::from_slice(envelope, version, &[HashAlgorithm::Sha256]).unwrap()
}

fn put<M: Metadata + ExtraFields + Clone>(
    files: &mut Files,
    role: &MetadataPath,
    signed: &Signed<M>,
) {
    files
        .0
        .insert(store::payload_path(role), signed.raw().to_vec());
    files.0.insert(
        store::signature_path(role),
        signed.signature_file().unwrap(),
    );
}

/// Publish `repo` into a fresh directory and hand back where it went.
fn publish(repo: &Repo) -> (tempfile::TempDir, tuf_repo::publish::Report) {
    let out = tempfile::tempdir().expect("temp dir");
    let plan = Plan::build(&repo.main, Repo::now()).expect("plan");
    let mut sink = FsSink::new(out.path());
    let report = plan.write(&repo.main, &mut sink).expect("write");
    (out, report)
}

// ---------------------------------------------------------------------------
// A client, walking what was published
// ---------------------------------------------------------------------------

/// Read a published metadata file the way a client fetches it.
fn fetch<M: Metadata>(
    dir: &Path,
    role: &MetadataPath,
    version: MetadataVersion,
) -> RawSignedMetadata<Pouf2, M> {
    let path = dir
        .join("metadata")
        .join(role.components::<Pouf2>(version).join("/"));
    let bytes = std::fs::read(&path).unwrap_or_else(|err| panic!("{}: {err}", path.display()));
    RawSignedMetadata::new(bytes)
}

/// Walk a published repository from its oldest root to its artifacts, as a client does.
fn walk(dir: &Path) -> Database<Pouf2> {
    let mut version = 1;
    let mut database = Database::from_trusted_root(&fetch::<RootMetadata>(
        dir,
        &MetadataPath::root(),
        MetadataVersion::Number(version),
    ))
    .expect("the first root is usable");

    // Forward through every published root, stopping where the chain stops.
    loop {
        version += 1;
        let path = dir.join(format!("metadata/{version}.root.json"));
        if !path.exists() {
            break;
        }
        database
            .update_root(&RawSignedMetadata::<Pouf2, RootMetadata>::new(
                std::fs::read(&path).unwrap(),
            ))
            .unwrap_or_else(|err| panic!("root version {version}: {err}"));
    }

    let now = Repo::now();
    database
        .update_timestamp(
            &now,
            &fetch::<TimestampMetadata>(dir, &MetadataPath::timestamp(), MetadataVersion::None),
        )
        .expect("timestamp verifies");

    let snapshot_version = database.trusted_timestamp().unwrap().snapshot().version();
    database
        .update_snapshot(
            &now,
            &fetch::<SnapshotMetadata>(
                dir,
                &MetadataPath::snapshot(),
                MetadataVersion::Number(snapshot_version),
            ),
        )
        .expect("snapshot verifies");

    let described: Vec<(MetadataPath, u32)> = database
        .trusted_snapshot()
        .unwrap()
        .meta()
        .iter()
        .map(|(role, description)| (role.clone(), description.version()))
        .collect();

    for (role, version) in &described {
        if *role != MetadataPath::targets() {
            continue;
        }
        database
            .update_targets(
                &now,
                &fetch::<TargetsMetadata>(dir, role, MetadataVersion::Number(*version)),
            )
            .expect("targets verifies");
    }
    for (role, version) in &described {
        if *role == MetadataPath::targets() {
            continue;
        }
        database
            .update_delegated_targets(
                &now,
                &MetadataPath::targets(),
                role,
                &fetch::<TargetsMetadata>(dir, role, MetadataVersion::Number(*version)),
            )
            .unwrap_or_else(|err| panic!("{role} verifies: {err}"));
    }

    database
}

/// Fetch an artifact the way a client does: look it up in the verified metadata, take the
/// hash it names, and read the file that hash points at.
fn fetch_target(dir: &Path, database: &Database<Pouf2>, path: &str) -> Vec<u8> {
    let target = TargetPath::new(path).unwrap();
    let description = database
        .target_description_with_start_time(&Repo::now(), &target)
        .unwrap_or_else(|err| panic!("{path} is described: {err}"));
    let hash = description.hashes().get(&HashAlgorithm::Sha256).unwrap();
    let published = target.with_hash_prefix(hash).unwrap();

    let bytes = std::fs::read(dir.join("targets").join(published.to_string()))
        .unwrap_or_else(|err| panic!("{path}: {err}"));
    assert_eq!(bytes.len() as u64, description.length());
    bytes
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn a_published_repository_is_one_a_client_can_walk() {
    let repo = repository();
    let (out, report) = publish(&repo);

    assert!(report.changed());
    assert!(report.unchanged.is_empty(), "{:#?}", report.unchanged);

    let database = walk(out.path());
    assert_eq!(
        fetch_target(out.path(), &database, "notice.txt"),
        b"read me"
    );
    assert_eq!(
        fetch_target(out.path(), &database, "crates/serde-1.0.0.crate"),
        b"not really a crate"
    );
}

#[test]
fn published_metadata_is_the_envelope_the_two_files_make_together() {
    let repo = repository();
    let (out, _) = publish(&repo);

    let envelope: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.path().join("metadata/1.root.json")).unwrap())
            .unwrap();

    // POUF-2: the payload is carried base64-encoded, with its type beside it, and the
    // signatures that were in `root.sig.json` alongside.
    assert_eq!(envelope["payloadType"], "application/vnd.tuf+json");
    assert_eq!(envelope["signatures"].as_array().unwrap().len(), 1);

    // The payload inside is the bytes of `metadata/root.json`, unchanged. Anything else
    // would mean the signatures were made over something other than what is published.
    use base64::Engine as _;
    let payload = base64::engine::general_purpose::STANDARD
        .decode(envelope["payload"].as_str().unwrap())
        .unwrap();
    assert_eq!(payload, *repo.main.0.get("metadata/root.json").unwrap());

    // The unversioned name serves the same document, for a client with nowhere to start.
    assert_eq!(
        std::fs::read(out.path().join("metadata/root.json")).unwrap(),
        std::fs::read(out.path().join("metadata/1.root.json")).unwrap()
    );
}

#[test]
fn republishing_an_unchanged_repository_transfers_nothing() {
    let repo = repository();
    let (out, first) = publish(&repo);

    let plan = Plan::build(&repo.main, Repo::now()).unwrap();
    let mut sink = FsSink::new(out.path());
    let second = plan.write(&repo.main, &mut sink).unwrap();

    assert!(!second.changed(), "{:#?}", second.written);
    assert_eq!(second.unchanged.len(), first.written.len());
    assert_eq!(second.bytes, 0);
}

#[test]
fn a_new_version_republishes_only_what_it_changed() {
    let mut repo = repository();
    let (out, first) = publish(&repo);

    // A second artifact: targets gains a version, snapshot and timestamp are reissued, and
    // everything already published keeps the name it had.
    add_artifacts(&mut repo, &[("changelog.txt", b"and another".to_vec())]);
    online_sign(&mut repo);

    let plan = Plan::build(&repo.main, Repo::now()).unwrap();
    let mut sink = FsSink::new(out.path());
    let second = plan.write(&repo.main, &mut sink).unwrap();

    assert_eq!(
        second.written,
        [
            "targets/db45b4f2c65403f04cff6b8d1b13cd40d54b1deb13eba59f419931675fe9e9b0.changelog.txt",
            "metadata/3.targets.json",
            "metadata/2.snapshot.json",
            "metadata/timestamp.json",
        ],
        "only the new artifact, the roles that changed, and the two mutable names"
    );
    assert!(first.written.len() > second.written.len());

    // And the result is still walkable, which is the point of republishing in that order.
    let database = walk(out.path());
    assert_eq!(
        fetch_target(out.path(), &database, "notice.txt"),
        b"read me"
    );
    assert_eq!(
        fetch_target(out.path(), &database, "changelog.txt"),
        b"and another"
    );
}

#[test]
fn an_artifact_that_does_not_match_its_metadata_is_not_published() {
    let mut repo = repository();
    repo.main
        .0
        .insert("targets/notice.txt".into(), b"tampered with".to_vec());

    let plan = Plan::build(&repo.main, Repo::now()).expect("the metadata itself is fine");
    let out = tempfile::tempdir().unwrap();
    let mut sink = FsSink::new(out.path());
    let err = plan.write(&repo.main, &mut sink).unwrap_err().to_string();

    assert!(
        err.contains("targets/notice.txt") && err.contains("describes"),
        "{err}"
    );
}

#[test]
fn a_repository_without_online_metadata_cannot_be_published() {
    let mut repo = repository();
    repo.main.0.remove("metadata/timestamp.json");
    repo.main.0.remove("metadata/timestamp.sig.json");

    let err = Plan::build(&repo.main, Repo::now())
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("no timestamp metadata") && err.contains("online key"),
        "{err}"
    );
}

#[test]
fn a_root_that_does_not_match_its_archived_copy_is_not_published() {
    let mut repo = repository();

    // Corrupt the archive rather than the live file, so the failure is the disagreement
    // itself and not unparseable metadata.
    let archived = repo
        .main
        .0
        .get("metadata/root_history/1.root.json")
        .unwrap()
        .clone();
    let mut edited = String::from_utf8(archived).unwrap();
    edited = edited.replace("\"version\": 1", "\"version\":  1");
    repo.main
        .0
        .insert("metadata/root_history/1.root.json".into(), edited.into());

    let err = Plan::build(&repo.main, Repo::now())
        .unwrap_err()
        .to_string();
    assert!(err.contains("does not match metadata/root.json"), "{err}");
}

#[test]
fn the_manifest_lists_every_published_file_by_digest() {
    let repo = repository();
    let (out, _) = publish(&repo);
    let manifest = Plan::build(&repo.main, Repo::now()).unwrap().manifest();

    let mut paths: Vec<&str> = manifest.files.iter().map(|f| f.path.as_str()).collect();
    let sorted = {
        let mut copy = paths.clone();
        copy.sort_unstable();
        copy
    };
    assert_eq!(paths, sorted, "the manifest is ordered by path");
    paths.dedup();
    assert_eq!(
        paths.len(),
        manifest.files.len(),
        "no path is published twice"
    );

    // Every line describes a file that is there, with the digest it claims.
    for file in &manifest.files {
        let bytes = std::fs::read(out.path().join(&file.path))
            .unwrap_or_else(|err| panic!("{}: {err}", file.path));
        assert_eq!(bytes.len() as u64, file.size, "{}", file.path);
        assert_eq!(
            hex::encode(tuf_repo::crypto::sha256(&bytes)),
            file.sha256,
            "{}",
            file.path
        );
    }
}

#[test]
fn a_sink_that_holds_nothing_is_asked_for_everything() {
    // The default `has` says no, so a sink can be a bare `put`. Publishing then transfers
    // the whole repository, which is what a first publish to an empty bucket is.
    #[derive(Default)]
    struct Bare(Vec<String>);
    impl Sink for Bare {
        fn put(&mut self, entry: &tuf_repo::publish::Entry, bytes: &[u8]) -> tuf_repo::Result<()> {
            assert_eq!(bytes.len() as u64, entry.size);
            self.0.push(entry.path.clone());
            Ok(())
        }
    }

    let repo = repository();
    let plan = Plan::build(&repo.main, Repo::now()).unwrap();
    let mut sink = Bare::default();
    let report = plan.write(&repo.main, &mut sink).unwrap();

    assert_eq!(sink.0, report.written);
    assert!(report.unchanged.is_empty());

    // Timestamp last: everything it names is already in place by the time it lands.
    assert_eq!(sink.0.last().unwrap(), "metadata/timestamp.json");
}
