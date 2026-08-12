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

use chrono::{TimeZone, Utc};
use tuf_repo::event::{RoleConfig, SigningEvent};
use tuf_repo::metadata::{Key, Periods, RoleName};
use tuf_repo::signer::Signer as _;
use tuf_repo::store::{EmptySource, FsSource, GitSource, RepoState, Writer};
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

fn online_key() -> Key {
    let signer = MemorySigner::for_owner("online");
    Key::online(
        signer.public_key_pem(),
        "gcpkms:projects/example/keys/online",
    )
    .expect("online key")
    .1
}

/// Create, sign and merge a repository's first metadata version.
fn bootstrap(repo: &Repo, signers: &[&str], threshold: u32) {
    let mut event = repo.event();
    event.initialize(periods()).unwrap();
    event
        .configure_role(&RoleName::root(), &config(signers, threshold))
        .unwrap();
    event
        .configure_role(&RoleName::targets(), &config(signers, threshold))
        .unwrap();
    event
        .configure_online(online_key(), periods(), periods())
        .unwrap();

    for name in signers {
        let key = MemorySigner::for_owner(name).public_key().1;
        event
            .accept_invite(&RoleName::root(), name, key.clone())
            .unwrap();
        event
            .accept_invite(&RoleName::targets(), name, key)
            .unwrap();
    }
    for name in signers {
        let mut signer = MemorySigner::for_owner(name);
        event.sign(&RoleName::root(), &mut signer).unwrap();
        event.sign(&RoleName::targets(), &mut signer).unwrap();
    }
    assert!(event.status().is_mergeable(), "{:#?}", event.status());

    repo.persist(&event, "Create root and targets metadata");
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
    let bob_key = MemorySigner::for_owner("@bob").public_key().1;
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

    let crates: RoleName = "crates".parse().unwrap();

    repo.git(&["switch", "--quiet", "--create", "sign/add-crates"]);
    let mut event = repo.event();
    event
        .configure_role(&crates, &config(&["@alice"], 1))
        .unwrap();
    let alice_key = MemorySigner::for_owner("@alice").public_key().1;
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
