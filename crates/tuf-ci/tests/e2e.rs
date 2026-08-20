//! End-to-end: a real git repository, the real `tuf-ci` binary, and metadata signed the
//! way `tuf-sign` signs it.
//!
//! `tuf-sign` itself cannot be driven from a test, because it wants a YubiKey. What it does
//! to the repository, though, is entirely [`tuf_repo`] calls, so the test makes those calls
//! with a software key and runs the actual CI binary against the result. That covers the
//! parts a unit test cannot: git discovery, merge-base resolution, the commits the tool
//! makes, and its exit codes.

use std::path::Path;
use std::process::{Command, Output};

use chrono::{Duration, TimeZone, Utc};
use tuf::crypto::HashAlgorithm;
use tuf::metadata::{
    Metadata, MetadataDescription, MetadataPath, SnapshotMetadataBuilder, TimestampMetadataBuilder,
};
use tuf_repo::crypto::PublicKey;
use tuf_repo::event::{RoleConfig, SigningEvent};
use tuf_repo::policy::{self, Periods, RoleName};
use tuf_repo::signer::Signer as _;
use tuf_repo::store::{
    self, EmptySource, ExtraFields, FsSource, GitSource, RepoState, Signed, Writer,
};
use tuf_repo::testing::MemorySigner;

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

struct Repo {
    dir: tempfile::TempDir,
}

impl Repo {
    /// A git repository with one commit on `main`.
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let repo = Repo { dir };
        repo.git(&["init", "--quiet", "--initial-branch=main"]);
        repo.git(&["config", "user.name", "Test"]);
        repo.git(&["config", "user.email", "test@example.com"]);
        repo.git(&["config", "commit.gpgsign", "false"]);
        std::fs::write(repo.path().join("README.md"), "test repository\n").unwrap();
        repo.git(&["add", "README.md"]);
        repo.commit("Initial commit");
        repo
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn git(&self, args: &[&str]) -> String {
        let output = Command::new("git")
            .arg("-C")
            .arg(self.path())
            .args(args)
            .output()
            .expect("git runs");
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    }

    fn commit(&self, message: &str) {
        self.git(&["commit", "--quiet", "--message", message]);
    }

    fn write(&self, path: &str, contents: &[u8]) {
        let full = self.path().join(path);
        std::fs::create_dir_all(full.parent().unwrap()).unwrap();
        std::fs::write(full, contents).unwrap();
    }

    /// Run the real CI binary against this repository.
    fn tuf_ci(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_tuf-ci"))
            .arg("--repo")
            .arg(self.path())
            .args(args)
            // The branch would otherwise be read from the environment of whatever CI is
            // running this test suite.
            .env(
                "GITHUB_REF_NAME",
                self.git(&["rev-parse", "--abbrev-ref", "HEAD"]),
            )
            .env_remove("GITHUB_TOKEN")
            .env_remove("GITHUB_REPOSITORY")
            .output()
            .expect("tuf-ci runs")
    }

    /// Open a signing event against the merge base with `main`, as the tools do.
    fn event(&self) -> SigningEvent {
        let head = self.git(&["rev-parse", "HEAD"]);
        let base = Command::new("git")
            .arg("-C")
            .arg(self.path())
            .args(["merge-base", "main", &head])
            .output()
            .expect("git runs");

        let known_good = if base.status.success() {
            let base = String::from_utf8_lossy(&base.stdout).trim().to_owned();
            RepoState::load(&GitSource::new(self.path(), base)).unwrap()
        } else {
            RepoState::load(&EmptySource).unwrap()
        };
        let current = RepoState::load(&FsSource::new(self.path())).unwrap();

        SigningEvent::from_states(known_good, current)
            .at(Utc.with_ymd_and_hms(2026, 8, 12, 12, 0, 0).unwrap())
    }

    /// Write an event's changes out and commit them, as `tuf-sign` would.
    fn persist(&self, event: &SigningEvent, message: &str) {
        let paths = event.persist(&Writer::new(self.path())).unwrap();
        let mut args = vec!["add", "--"];
        args.extend(paths.iter().map(String::as_str));
        self.git(&args);
        self.commit(message);
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

fn online_key() -> PublicKey {
    MemorySigner::for_owner("online").public_key().clone()
}

/// Where CI would reach the online key.
const ONLINE_URI: &str = "gcpkms:projects/example/keys/online";

/// Create, sign and merge a repository's first metadata version.
fn bootstrap(repo: &Repo, signers: &[&str], threshold: u32) {
    let creator = signers.first().expect("at least one signer");
    let mut event = repo.event();
    event
        .initialize(
            periods(),
            MemorySigner::for_owner(creator).public_key().clone(),
            creator,
        )
        .expect("initialize");
    event
        .configure_online(online_key(), ONLINE_URI, periods(), periods())
        .expect("configure online roles");
    event
        .configure_role(&RoleName::root(), &config(signers, threshold))
        .expect("configure root");
    event
        .configure_role(&RoleName::targets(), &config(signers, threshold))
        .expect("configure targets");

    for name in signers {
        let key = MemorySigner::for_owner(name).public_key().clone();
        for role in [RoleName::root(), RoleName::targets()] {
            if event.event_state().for_user(name).contains(&role) {
                event
                    .accept_invite(&role, name, key.clone())
                    .expect("accept invite");
            }
        }
    }

    for name in signers {
        let mut signer = MemorySigner::for_owner(name);
        event
            .sign(&RoleName::root(), &mut signer)
            .expect("sign root");
        event
            .sign(&RoleName::targets(), &mut signer)
            .expect("sign targets");
    }

    assert!(
        event.status().is_mergeable(),
        "bootstrap should be mergeable: {:#?}",
        event.status()
    );
    repo.persist(&event, "Create root and targets metadata");
}

/// Describe a published envelope, which is what a client downloads and hashes — not the
/// payload file beside it.
fn describe<M: Metadata>(bytes: &[u8], version: u32) -> MetadataDescription<M> {
    MetadataDescription::from_slice(bytes, version, &[HashAlgorithm::Sha256]).unwrap()
}

/// Sign snapshot and timestamp with the online key, and commit them.
///
/// This is the step that runs when a signing event merges. It is not `tuf-ci`'s job yet,
/// so the test does it directly; publishing needs it done because a client cannot use a
/// repository without those two roles.
fn online_sign(repo: &Repo) {
    let state = RepoState::load(&FsSource::new(repo.path())).unwrap();
    let mut online = MemorySigner::for_owner("online");
    let now = Utc.with_ymd_and_hms(2026, 8, 12, 12, 0, 0).unwrap();

    let mut builder = SnapshotMetadataBuilder::new()
        .version(1)
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
    .version(1)
    .expires(now + Duration::days(1))
    .build()
    .unwrap();
    let mut timestamp = Signed::new(timestamp).unwrap();
    timestamp.sign_with(&mut online).unwrap();

    write_role(repo, &MetadataPath::snapshot(), &snapshot);
    write_role(repo, &MetadataPath::timestamp(), &timestamp);
    repo.git(&["add", "metadata"]);
    repo.commit("Sign snapshot and timestamp");
}

fn write_role<M: Metadata + ExtraFields + Clone>(
    repo: &Repo,
    role: &MetadataPath,
    signed: &Signed<M>,
) {
    repo.write(&store::payload_path(role), signed.raw());
    repo.write(
        &store::signature_path(role),
        &signed.signature_file().unwrap(),
    );
}

/// Every file in a published tree, by path, with its sha256.
fn published(dir: &Path) -> std::collections::BTreeMap<String, String> {
    let mut found = std::collections::BTreeMap::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(next) = pending.pop() {
        for entry in std::fs::read_dir(&next).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                pending.push(entry.path());
                continue;
            }
            let relative = entry
                .path()
                .strip_prefix(dir)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            let bytes = std::fs::read(entry.path()).unwrap();
            found.insert(relative, hex::encode(tuf_repo::crypto::sha256(&bytes)));
        }
    }
    found
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn combined(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn committing_an_artifact_produces_metadata_that_needs_signing() {
    let repo = Repo::new();
    bootstrap(&repo, &["@alice"], 1);

    repo.git(&["switch", "--quiet", "--create", "sign/add-notes"]);
    repo.write("targets/notes.txt", b"release notes\n");
    repo.git(&["add", "targets/notes.txt"]);
    repo.commit("Add release notes");

    // CI turns the artifact into metadata.
    let update = repo.tuf_ci(&["update-targets"]);
    assert_eq!(
        update.status.code(),
        Some(0),
        "update-targets should report a change: {}",
        combined(&update)
    );
    assert!(
        combined(&update).contains("targets"),
        "{}",
        combined(&update)
    );
    assert_eq!(
        repo.git(&["log", "-1", "--pretty=%s"]),
        "Update targets metadata for targets"
    );

    // The new metadata is unsigned, so the event cannot be merged.
    let status = repo.tuf_ci(&["status"]);
    assert_eq!(
        status.status.code(),
        Some(1),
        "unsigned metadata should not be mergeable: {}",
        combined(&status)
    );
    let report = stdout(&status);
    assert!(report.contains("Waiting on 1 more signature."), "{report}");
    assert!(report.contains("1 artifact added"), "{report}");
    assert!(report.contains("`@alice`"), "{report}");

    // Running it again finds nothing further to do.
    let again = repo.tuf_ci(&["update-targets"]);
    assert_eq!(again.status.code(), Some(1), "{}", combined(&again));

    // Alice signs, and now it can be merged.
    let mut event = repo.event();
    let mut alice = MemorySigner::for_owner("@alice");
    event.sign(&RoleName::targets(), &mut alice).unwrap();
    repo.persist(&event, "Sign targets as @alice");

    let status = repo.tuf_ci(&["status"]);
    assert_eq!(
        status.status.code(),
        Some(0),
        "signed metadata should be mergeable: {}",
        combined(&status)
    );
    assert!(
        stdout(&status).contains("can be reviewed"),
        "{}",
        stdout(&status)
    );
}

#[test]
fn a_threshold_is_reported_as_it_fills_up() {
    let repo = Repo::new();
    bootstrap(&repo, &["@alice", "@bob"], 2);

    repo.git(&["switch", "--quiet", "--create", "sign/add-notes"]);
    repo.write("targets/notes.txt", b"release notes\n");
    repo.git(&["add", "targets/notes.txt"]);
    repo.commit("Add release notes");
    assert_eq!(repo.tuf_ci(&["update-targets"]).status.code(), Some(0));

    let json = repo.tuf_ci(&["status", "--format", "json"]);
    let report: serde_json::Value = serde_json::from_str(&stdout(&json)).unwrap();
    assert_eq!(report["mergeable"], false);
    assert_eq!(report["outstanding_signatures"], 2);

    let mut event = repo.event();
    let mut alice = MemorySigner::for_owner("@alice");
    event.sign(&RoleName::targets(), &mut alice).unwrap();
    repo.persist(&event, "Sign targets as @alice");

    let json = repo.tuf_ci(&["status", "--format", "json"]);
    let report: serde_json::Value = serde_json::from_str(&stdout(&json)).unwrap();
    assert_eq!(report["mergeable"], false);
    assert_eq!(report["outstanding_signatures"], 1);
    assert_eq!(report["roles"][0]["waiting_on"][0], "@bob");
    assert_eq!(report["roles"][0]["signed"][0], "@alice");

    let mut event = repo.event();
    let mut bob = MemorySigner::for_owner("@bob");
    event.sign(&RoleName::targets(), &mut bob).unwrap();
    repo.persist(&event, "Sign targets as @bob");

    let json = repo.tuf_ci(&["status", "--format", "json"]);
    let report: serde_json::Value = serde_json::from_str(&stdout(&json)).unwrap();
    assert_eq!(report["mergeable"], true);
    assert_eq!(report["outstanding_signatures"], 0);
}

#[test]
fn an_invitation_holds_the_event_open_until_the_key_arrives() {
    let repo = Repo::new();
    bootstrap(&repo, &["@alice"], 1);

    repo.git(&["switch", "--quiet", "--create", "sign/add-bob"]);
    let mut event = repo.event();
    event
        .configure_role(&RoleName::targets(), &config(&["@alice", "@bob"], 2))
        .unwrap();
    repo.persist(&event, "Invite @bob to sign targets");

    let json = repo.tuf_ci(&["status", "--format", "json"]);
    let report: serde_json::Value = serde_json::from_str(&stdout(&json)).unwrap();
    assert_eq!(report["mergeable"], false);
    assert_eq!(report["invitations"][0]["user"], "@bob");
    assert_eq!(report["invitations"][0]["role"], "targets");

    let markdown = stdout(&repo.tuf_ci(&["status"]));
    assert!(markdown.contains("has been invited to sign"), "{markdown}");
    assert!(markdown.contains("tuf-sign sign/add-bob"), "{markdown}");

    // Bob accepts and everyone signs the resulting root.
    let mut event = repo.event();
    let bob_key = MemorySigner::for_owner("@bob").public_key().clone();
    event
        .accept_invite(&RoleName::targets(), "@bob", bob_key)
        .unwrap();
    let mut alice = MemorySigner::for_owner("@alice");
    event.sign(&RoleName::root(), &mut alice).unwrap();
    repo.persist(&event, "Add @bob key to targets and sign root");

    let json = repo.tuf_ci(&["status", "--format", "json"]);
    let report: serde_json::Value = serde_json::from_str(&stdout(&json)).unwrap();
    assert_eq!(report["mergeable"], true, "{report:#}");
    assert!(report["invitations"].as_array().unwrap().is_empty());
}

#[test]
fn a_delegated_role_owns_its_own_directory() {
    let repo = Repo::new();
    bootstrap(&repo, &["@alice"], 1);

    let crates: RoleName = policy::role_name("crates").unwrap();

    repo.git(&["switch", "--quiet", "--create", "sign/add-crates"]);
    let mut event = repo.event();
    event
        .configure_role(&crates, &config(&["@alice"], 1))
        .unwrap();
    let alice_key = MemorySigner::for_owner("@alice").public_key().clone();
    event.accept_invite(&crates, "@alice", alice_key).unwrap();
    let mut alice = MemorySigner::for_owner("@alice");
    event.sign(&RoleName::targets(), &mut alice).unwrap();
    event.sign(&crates, &mut alice).unwrap();
    repo.persist(&event, "Delegate crates to @alice");

    assert_eq!(repo.tuf_ci(&["status"]).status.code(), Some(0));
    repo.git(&["switch", "--quiet", "main"]);
    repo.git(&["merge", "--quiet", "--ff-only", "sign/add-crates"]);

    // Artifacts land in the role that owns their directory.
    repo.git(&["switch", "--quiet", "--create", "sign/publish"]);
    repo.write("targets/crates/serde", b"crate bytes\n");
    repo.write("targets/top-level.txt", b"owned by targets\n");
    repo.git(&["add", "targets"]);
    repo.commit("Add artifacts");
    assert_eq!(repo.tuf_ci(&["update-targets"]).status.code(), Some(0));

    let json = repo.tuf_ci(&["status", "--format", "json"]);
    let report: serde_json::Value = serde_json::from_str(&stdout(&json)).unwrap();
    let roles = report["roles"].as_array().unwrap();
    let by_name = |name: &str| {
        roles
            .iter()
            .find(|role| role["role"] == name)
            .unwrap_or_else(|| panic!("no status for {name}: {report:#}"))
    };
    assert_eq!(
        by_name("crates")["artifact_changes"][0]["path"],
        "crates/serde"
    );
    assert_eq!(
        by_name("targets")["artifact_changes"][0]["path"],
        "top-level.txt"
    );
    assert_eq!(
        by_name("crates")["artifact_changes"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn a_branch_with_no_metadata_changes_reports_nothing_to_do() {
    let repo = Repo::new();
    bootstrap(&repo, &["@alice"], 1);

    repo.git(&["switch", "--quiet", "--create", "sign/nothing"]);
    repo.write("NOTES.md", b"unrelated change\n");
    repo.git(&["add", "NOTES.md"]);
    repo.commit("Unrelated change");

    let update = repo.tuf_ci(&["update-targets"]);
    assert_eq!(update.status.code(), Some(1), "{}", combined(&update));

    let status = repo.tuf_ci(&["status"]);
    assert_eq!(status.status.code(), Some(1));
    assert!(
        stdout(&status).contains("changes no metadata yet"),
        "{}",
        stdout(&status)
    );
}

#[test]
fn tampering_with_a_signature_is_caught() {
    let repo = Repo::new();
    bootstrap(&repo, &["@alice"], 1);

    repo.git(&["switch", "--quiet", "--create", "sign/add-notes"]);
    repo.write("targets/notes.txt", b"release notes\n");
    repo.git(&["add", "targets/notes.txt"]);
    repo.commit("Add release notes");
    repo.tuf_ci(&["update-targets"]);

    let mut event = repo.event();
    let mut alice = MemorySigner::for_owner("@alice");
    event.sign(&RoleName::targets(), &mut alice).unwrap();
    repo.persist(&event, "Sign targets as @alice");
    assert_eq!(repo.tuf_ci(&["status"]).status.code(), Some(0));

    // Change the artifact without re-signing. The metadata still says the old digest, so
    // the payload is unchanged and the signature still verifies — but CI rebuilds the
    // metadata from the artifact and the signature then no longer applies.
    repo.write("targets/notes.txt", b"different bytes\n");
    repo.git(&["add", "targets/notes.txt"]);
    repo.commit("Change the artifact behind the signature");

    assert_eq!(
        repo.tuf_ci(&["update-targets"]).status.code(),
        Some(0),
        "the metadata should be rebuilt to match the new artifact"
    );
    let status = repo.tuf_ci(&["status"]);
    assert_eq!(
        status.status.code(),
        Some(1),
        "changing an artifact must invalidate the signature over its metadata: {}",
        stdout(&status)
    );
    assert!(stdout(&status).contains("Waiting on 1 more signature."));
}

#[test]
fn publishing_turns_the_signed_pairs_into_a_repository_a_client_can_fetch() {
    let repo = Repo::new();
    bootstrap(&repo, &["@alice"], 1);

    // An artifact with bytes git must not touch: a NUL, and a line ending that a
    // text-mode checkout would rewrite.
    let artifact: &[u8] = b"binary\r\n\x00bytes\n";
    repo.git(&["switch", "--quiet", "--create", "sign/add-artifact"]);
    repo.write("targets/payload.bin", artifact);
    repo.git(&["add", "targets"]);
    repo.commit("Add an artifact");
    assert_eq!(repo.tuf_ci(&["update-targets"]).status.code(), Some(0));

    let mut event = repo.event();
    let mut alice = MemorySigner::for_owner("@alice");
    event.sign(&RoleName::targets(), &mut alice).unwrap();
    repo.persist(&event, "Sign targets");
    repo.git(&["switch", "--quiet", "main"]);
    repo.git(&["merge", "--quiet", "--ff-only", "sign/add-artifact"]);
    online_sign(&repo);

    // A first publish writes everything and says so. `--as-of` is what an auditor
    // reproducing an old publish passes, and what this test needs, since the harness
    // signs at a fixed date and a timestamp is good for a day.
    let out = repo.path().join("dist");
    let published_at = "2026-08-12T12:00:00Z";
    let first = repo.tuf_ci(&[
        "publish",
        "--out",
        out.to_str().unwrap(),
        "--as-of",
        published_at,
    ]);
    assert_eq!(first.status.code(), Some(0), "{}", combined(&first));

    let files = published(&out);
    assert!(files.contains_key("metadata/timestamp.json"), "{files:#?}");
    assert!(files.contains_key("metadata/1.root.json"), "{files:#?}");
    assert!(files.contains_key("metadata/root.json"), "{files:#?}");

    // The artifact is served under its own hash, byte for byte.
    let digest = hex::encode(tuf_repo::crypto::sha256(artifact));
    let published_artifact = out.join(format!("targets/{digest}.payload.bin"));
    assert_eq!(std::fs::read(&published_artifact).unwrap(), artifact);

    // Publishing again has nothing to do, and says so with exit 1 so a workflow can skip
    // the upload.
    let second = repo.tuf_ci(&[
        "publish",
        "--out",
        out.to_str().unwrap(),
        "--as-of",
        published_at,
    ]);
    assert_eq!(second.status.code(), Some(1), "{}", combined(&second));
    assert!(combined(&second).contains("0 of"), "{}", combined(&second));

    // The auditor's path: publish the same commit again, from git rather than from the
    // working tree, into an empty directory. Every file comes out identical.
    let audit = repo.path().join("audit");
    let output = repo.tuf_ci(&[
        "publish",
        "--rev",
        "main",
        "--out",
        audit.to_str().unwrap(),
        "--manifest",
        "-",
        "--as-of",
        published_at,
    ]);
    assert_eq!(output.status.code(), Some(0), "{}", combined(&output));
    assert_eq!(published(&audit), files);

    // And the manifest it printed describes exactly those files.
    let manifest: serde_json::Value = serde_json::from_str(&stdout(&output)).unwrap();
    let listed: std::collections::BTreeMap<String, String> = manifest["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|file| {
            (
                file["path"].as_str().unwrap().to_owned(),
                file["sha256"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    assert_eq!(listed, files);
}

#[test]
fn a_repository_missing_its_online_roles_will_not_publish() {
    let repo = Repo::new();
    bootstrap(&repo, &["@alice"], 1);

    let out = repo.path().join("dist");
    let output = repo.tuf_ci(&["publish", "--out", out.to_str().unwrap()]);

    // Exit 2 is "this did not work", as distinct from 1, which means "nothing to do".
    assert_eq!(output.status.code(), Some(2), "{}", combined(&output));
    assert!(
        combined(&output).contains("online key"),
        "{}",
        combined(&output)
    );
    assert!(!out.exists(), "nothing should have been written");
}
