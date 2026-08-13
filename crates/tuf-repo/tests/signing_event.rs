//! Signing-event behaviour, driven the way the two binaries drive it.
//!
//! Each test runs a whole event: branch from a known-good state, make changes, gather
//! signatures, and merge. That is deliberately coarser than unit-testing each method,
//! because the bugs worth catching here are the ones where two steps disagree — a version
//! bumped twice, a signature silently dropped, a role reported complete by one code path
//! and incomplete by another.

use std::collections::BTreeMap;

use chrono::{DateTime, TimeZone, Utc};
use tuf_repo::event::{ArtifactChange, RoleConfig, SigningEvent};
use tuf_repo::metadata::{Key, Periods, RoleName};
use tuf_repo::signer::Signer as _;
use tuf_repo::store::{RepoState, Source, Writer};
use tuf_repo::testing::MemorySigner;

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// A repository held in memory, standing in for a working tree.
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

/// A repository, and the signing event currently open against it.
struct Repo {
    /// The state of the main branch.
    main: Files,
    /// Where an event's output is written, standing in for the working tree.
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

    /// Open a signing event branching from the main branch.
    fn event(&self) -> SigningEvent {
        let known_good = RepoState::load(&self.main).expect("main branch loads");
        let current = RepoState::load(&self.main).expect("main branch loads");
        SigningEvent::from_states(known_good, current).at(Self::now())
    }

    /// Open a signing event that already has `files` staged on its branch.
    fn event_with(&self, files: &Files) -> SigningEvent {
        let known_good = RepoState::load(&self.main).expect("main branch loads");
        let mut merged = self.main.clone();
        merged.0.extend(files.0.clone());
        let current = RepoState::load(&merged).expect("event branch loads");
        SigningEvent::from_states(known_good, current).at(Self::now())
    }

    /// Write out an event's changes and return them, as a push to the event branch would.
    fn persist(&self, event: &SigningEvent) -> Files {
        let writer = Writer::new(self.dir.path());
        let paths = event.persist(&writer).expect("event persists");
        let mut files = Files::default();
        for path in paths {
            if let Ok(bytes) = std::fs::read(self.dir.path().join(&path)) {
                files.0.insert(path, bytes);
            }
        }
        files
    }

    /// Merge an event into the main branch.
    fn merge(&mut self, event: &SigningEvent) {
        let files = self.persist(event);
        self.main.0.extend(files.0);
        // Merging closes the event, so its state file goes with it.
        if event.invites().is_empty() {
            self.main.0.remove("metadata/.signing-event.json");
        }
    }

    /// Put an artifact on the event branch.
    fn add_artifact(&self, files: &mut Files, path: &str, contents: &[u8]) {
        let _ = self;
        files.0.insert(format!("targets/{path}"), contents.to_vec());
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
    let (_, key) = Key::online(
        signer.public_key_pem(),
        "gcpkms:projects/example/locations/global/keyRings/tuf/cryptoKeys/online",
    )
    .expect("online key");
    key
}

/// Take a repository from nothing to a signed, merged first version.
fn bootstrap(repo: &mut Repo, signers: &[&str], threshold: u32) {
    let mut event = repo.event();
    event.initialize(periods()).expect("initialize");
    event
        .configure_role(&RoleName::root(), &config(signers, threshold))
        .expect("configure root");
    event
        .configure_role(&RoleName::targets(), &config(signers, threshold))
        .expect("configure targets");
    event
        .configure_online(online_key(), periods(), periods())
        .expect("configure online roles");

    for name in signers {
        let signer = MemorySigner::for_owner(name);
        let (_, key) = signer.public_key();
        event
            .accept_invite(&RoleName::root(), name, key.clone())
            .expect("accept root invite");
        event
            .accept_invite(&RoleName::targets(), name, key)
            .expect("accept targets invite");
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
    repo.merge(&event);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn a_new_repository_needs_an_invitation_accepted_before_it_can_be_signed() {
    let mut repo = Repo::new();
    let mut event = repo.event();

    event.initialize(periods()).unwrap();
    event
        .configure_role(&RoleName::root(), &config(&["@alice"], 1))
        .unwrap();
    event
        .configure_role(&RoleName::targets(), &config(&["@alice"], 1))
        .unwrap();
    event
        .configure_online(online_key(), periods(), periods())
        .unwrap();

    // Alice has been named as a signer but has contributed no key, so there is nothing
    // worth signing yet: the key set is still going to change.
    let tasks = event.tasks_for("@alice");
    assert_eq!(tasks.accept, [RoleName::root(), RoleName::targets()]);
    assert!(tasks.sign.is_empty());
    assert!(!event.status().is_mergeable());

    let alice = MemorySigner::for_owner("@alice");
    let (_, key) = alice.public_key();
    event
        .accept_invite(&RoleName::root(), "@alice", key.clone())
        .unwrap();
    event
        .accept_invite(&RoleName::targets(), "@alice", key)
        .unwrap();

    let tasks = event.tasks_for("@alice");
    assert!(tasks.accept.is_empty());
    assert_eq!(tasks.sign, [RoleName::root(), RoleName::targets()]);

    let mut alice = MemorySigner::for_owner("@alice");
    event.sign(&RoleName::root(), &mut alice).unwrap();
    event.sign(&RoleName::targets(), &mut alice).unwrap();

    let status = event.status();
    assert!(status.is_mergeable(), "{status:#?}");
    assert_eq!(status.outstanding(), 0);
    assert_eq!(status.roles.len(), 2);
    for role in &status.roles {
        assert_eq!(role.version, 1, "{} should be version 1", role.role);
    }

    repo.merge(&event);
}

#[test]
fn an_uninvited_signer_cannot_add_a_signature() {
    let mut repo = Repo::new();
    bootstrap(&mut repo, &["@alice"], 1);

    let mut event = repo.event();
    event
        .configure_role(&RoleName::targets(), &config(&["@alice"], 1))
        .unwrap();

    let mut mallory = MemorySigner::for_owner("@mallory");
    let err = event
        .sign(&RoleName::targets(), &mut mallory)
        .expect_err("mallory holds no key for targets");
    assert!(err.to_string().contains("not permitted to sign"), "{err}");
}

#[test]
fn a_threshold_of_two_reports_progress_and_blocks_until_both_have_signed() {
    let mut repo = Repo::new();
    bootstrap(&mut repo, &["@alice", "@bob"], 2);

    // Change something so there is a signing event at all.
    let mut files = Files::default();
    repo.add_artifact(&mut files, "notes.txt", b"first");
    let mut event = repo.event_with(&files);
    let mut artifacts = repo.main.clone();
    artifacts.0.extend(files.0.clone());
    let updated = event.update_targets(&artifacts).unwrap();
    assert_eq!(updated, [RoleName::targets()]);

    let status = event.role_status(&RoleName::targets());
    assert_eq!(status.tally.threshold, 2);
    assert_eq!(status.outstanding(), 2);
    assert_eq!(status.waiting_on(), ["@alice", "@bob"]);

    let mut alice = MemorySigner::for_owner("@alice");
    event.sign(&RoleName::targets(), &mut alice).unwrap();

    let status = event.role_status(&RoleName::targets());
    assert_eq!(status.outstanding(), 1);
    assert_eq!(status.waiting_on(), ["@bob"]);
    assert!(!event.status().is_mergeable());

    let mut bob = MemorySigner::for_owner("@bob");
    event.sign(&RoleName::targets(), &mut bob).unwrap();
    assert!(event.status().is_mergeable(), "{:#?}", event.status());
}

#[test]
fn adding_a_root_signer_needs_the_consent_of_the_signer_being_joined() {
    let mut repo = Repo::new();
    bootstrap(&mut repo, &["@alice"], 1);

    let mut event = repo.event();
    event
        .configure_role(&RoleName::root(), &config(&["@alice", "@bob"], 2))
        .unwrap();

    let bob = MemorySigner::for_owner("@bob");
    let (_, bob_key) = bob.public_key();
    event
        .accept_invite(&RoleName::root(), "@bob", bob_key)
        .unwrap();

    // The new root must satisfy both the incoming threshold of two and the outgoing
    // threshold of one, so Bob signing alone is not enough.
    let mut bob = MemorySigner::for_owner("@bob");
    event.sign(&RoleName::root(), &mut bob).unwrap();
    let status = event.role_status(&RoleName::root());
    assert_eq!(status.tally.signed.len(), 1);
    assert_eq!(
        status
            .previous_tally
            .as_ref()
            .expect("root has a previous tally")
            .signed
            .len(),
        0,
        "bob is not a signer of the outgoing root"
    );
    assert!(!status.is_complete());

    let mut alice = MemorySigner::for_owner("@alice");
    event.sign(&RoleName::root(), &mut alice).unwrap();
    assert!(event.status().is_mergeable(), "{:#?}", event.status());
}

#[test]
fn removing_a_signer_still_requires_that_signer_to_agree() {
    let mut repo = Repo::new();
    bootstrap(&mut repo, &["@alice", "@bob"], 1);

    let mut event = repo.event();
    event
        .configure_role(&RoleName::root(), &config(&["@alice"], 1))
        .unwrap();

    // Bob's key is gone from the new root, but the outgoing root still lists him, so his
    // signature is one of the two that could satisfy the previous threshold.
    let status = event.role_status(&RoleName::root());
    assert_eq!(
        status
            .tally
            .missing
            .iter()
            .map(|s| &s.name)
            .collect::<Vec<_>>(),
        ["@alice"]
    );
    let previous = status.previous_tally.expect("root has a previous tally");
    let mut names: Vec<&str> = previous.missing.iter().map(|s| s.name.as_str()).collect();
    names.sort_unstable();
    assert_eq!(names, ["@alice", "@bob"]);

    // Alice is in both key sets, so her single signature satisfies both thresholds.
    let mut alice = MemorySigner::for_owner("@alice");
    event.sign(&RoleName::root(), &mut alice).unwrap();
    assert!(event.status().is_mergeable(), "{:#?}", event.status());
}

#[test]
fn several_changes_in_one_event_still_produce_one_new_version() {
    let mut repo = Repo::new();
    bootstrap(&mut repo, &["@alice"], 1);
    assert_eq!(repo.event().current().version_of(&RoleName::root()), 1);

    let mut event = repo.event();
    event
        .configure_role(&RoleName::root(), &config(&["@alice"], 1))
        .unwrap();
    event
        .configure_online(online_key(), periods(), periods())
        .unwrap();
    event
        .configure_role(
            &RoleName::root(),
            &RoleConfig {
                signers: vec!["@alice".into()],
                threshold: 1,
                periods: Periods {
                    expiry_days: 200,
                    signing_days: 30,
                },
            },
        )
        .unwrap();

    assert_eq!(
        event.current().version_of(&RoleName::root()),
        2,
        "three edits in one event should still be version 2"
    );
}

#[test]
fn an_edit_that_changes_nothing_does_not_discard_signatures() {
    let mut repo = Repo::new();
    bootstrap(&mut repo, &["@alice"], 1);

    let mut event = repo.event();
    event
        .configure_role(&RoleName::targets(), &config(&["@alice", "@bob"], 1))
        .unwrap();
    let bob = MemorySigner::for_owner("@bob");
    let (_, bob_key) = bob.public_key();
    event
        .accept_invite(&RoleName::targets(), "@bob", bob_key)
        .unwrap();
    let mut alice = MemorySigner::for_owner("@alice");
    event.sign(&RoleName::root(), &mut alice).unwrap();
    assert_eq!(event.role_status(&RoleName::root()).tally.signed.len(), 1);

    // Re-running the same configuration is a no-op, and must not cost Alice her signature.
    let changed = event
        .configure_role(&RoleName::targets(), &config(&["@alice", "@bob"], 1))
        .unwrap();
    assert!(!changed);
    assert_eq!(
        event.role_status(&RoleName::root()).tally.signed.len(),
        1,
        "a no-op edit discarded a signature"
    );
}

#[test]
fn changing_a_payload_discards_the_signatures_over_the_old_bytes() {
    let mut repo = Repo::new();
    bootstrap(&mut repo, &["@alice"], 1);

    let mut event = repo.event();
    event
        .configure_role(&RoleName::targets(), &config(&["@alice"], 1))
        .unwrap();
    let mut alice = MemorySigner::for_owner("@alice");
    event.sign(&RoleName::root(), &mut alice).unwrap();
    assert_eq!(event.role_status(&RoleName::root()).tally.signed.len(), 1);

    // The periods for `targets` live in root, so changing them rewrites root.
    event
        .configure_role(
            &RoleName::targets(),
            &RoleConfig {
                signers: vec!["@alice".into()],
                threshold: 1,
                periods: Periods {
                    expiry_days: 200,
                    signing_days: 30,
                },
            },
        )
        .unwrap();
    assert_eq!(
        event.role_status(&RoleName::root()).tally.signed.len(),
        0,
        "root changed, so the signature over the old root must be gone"
    );
}

#[test]
fn inviting_a_signer_does_not_by_itself_invalidate_signatures() {
    // An invitation is unsigned bookkeeping: it records that somebody has been asked for a
    // key, and it changes no metadata until they provide one. Signatures gathered before
    // the invitation are still signatures over the current bytes, and discarding them
    // would mean nobody could ever sign a role while an invitation was outstanding.
    let mut repo = Repo::new();
    bootstrap(&mut repo, &["@alice"], 1);

    let mut event = repo.event();
    event
        .configure_role(&RoleName::targets(), &config(&["@alice", "@bob"], 1))
        .unwrap();
    let mut alice = MemorySigner::for_owner("@alice");
    event.sign(&RoleName::root(), &mut alice).unwrap();
    assert_eq!(event.role_status(&RoleName::root()).tally.signed.len(), 1);

    // But root is still not signable while the invitation is open, because accepting it
    // will change root.
    assert!(
        !event.blocking_invites(&RoleName::root()).is_empty(),
        "an invitation to targets blocks root, which holds the targets keys"
    );
    assert!(!event.status().is_mergeable());

    // Accepting does change root, and does cost Alice her signature.
    let bob_key = MemorySigner::for_owner("@bob").public_key().1;
    event
        .accept_invite(&RoleName::targets(), "@bob", bob_key)
        .unwrap();
    assert_eq!(event.role_status(&RoleName::root()).tally.signed.len(), 0);
}

#[test]
fn artifacts_are_assigned_to_the_role_that_owns_their_directory() {
    let mut repo = Repo::new();
    bootstrap(&mut repo, &["@alice"], 1);

    let crates: RoleName = "crates".parse().unwrap();

    // Delegate `crates` to Alice.
    let mut event = repo.event();
    event
        .configure_role(&crates, &config(&["@alice"], 1))
        .unwrap();
    let alice_key = MemorySigner::for_owner("@alice").public_key().1;
    event.accept_invite(&crates, "@alice", alice_key).unwrap();
    let mut alice = MemorySigner::for_owner("@alice");
    event.sign(&RoleName::targets(), &mut alice).unwrap();
    event.sign(&crates, &mut alice).unwrap();
    assert!(event.status().is_mergeable(), "{:#?}", event.status());
    repo.merge(&event);

    // Now add artifacts in three places and see where they land.
    let mut files = Files::default();
    repo.add_artifact(&mut files, "top-level.txt", b"owned by targets");
    repo.add_artifact(&mut files, "crates/serde", b"owned by crates");
    repo.add_artifact(&mut files, "crates/a/b/c/d/deep", b"too deep for crates");

    let mut event = repo.event_with(&files);
    let mut artifacts = repo.main.clone();
    artifacts.0.extend(files.0.clone());
    let mut updated = event.update_targets(&artifacts).unwrap();
    updated.sort();
    assert_eq!(updated, [crates.clone(), RoleName::targets()]);

    assert_eq!(
        event.artifact_changes(&RoleName::targets()),
        [ArtifactChange::Added("top-level.txt".into())],
        "the top-level role owns only files directly in targets/"
    );
    assert_eq!(
        event.artifact_changes(&crates),
        [ArtifactChange::Added("crates/serde".into())],
        "a fifth directory level is beyond the delegated paths"
    );
}

#[test]
fn housekeeping_dotfiles_are_not_signed_as_artifacts() {
    let mut repo = Repo::new();
    bootstrap(&mut repo, &["@alice"], 1);

    let crates: RoleName = "crates".parse().unwrap();
    let mut event = repo.event();
    event
        .configure_role(&crates, &config(&["@alice"], 1))
        .unwrap();
    let alice_key = MemorySigner::for_owner("@alice").public_key().1;
    event.accept_invite(&crates, "@alice", alice_key).unwrap();
    repo.merge(&event);

    let mut files = Files::default();
    // The kind of thing that ends up in a repository without anybody deciding it should.
    repo.add_artifact(&mut files, ".gitkeep", b"");
    repo.add_artifact(&mut files, ".DS_Store", b"junk");
    repo.add_artifact(&mut files, "crates/.gitkeep", b"");
    repo.add_artifact(&mut files, "real.txt", b"an actual artifact");

    let mut event = repo.event_with(&files);
    let mut artifacts = repo.main.clone();
    artifacts.0.extend(files.0.clone());
    let updated = event.update_targets(&artifacts).unwrap();

    assert_eq!(
        updated,
        [RoleName::targets()],
        "only the role with a real artifact should change"
    );
    assert_eq!(
        event.artifact_changes(&RoleName::targets()),
        [ArtifactChange::Added("real.txt".into())],
    );
    assert!(event.artifact_changes(&crates).is_empty());
}

#[test]
fn changing_an_artifact_is_reported_as_a_modification() {
    let mut repo = Repo::new();
    bootstrap(&mut repo, &["@alice"], 1);

    let mut files = Files::default();
    repo.add_artifact(&mut files, "notes.txt", b"first");
    let mut event = repo.event_with(&files);
    let mut artifacts = repo.main.clone();
    artifacts.0.extend(files.0.clone());
    event.update_targets(&artifacts).unwrap();
    let mut alice = MemorySigner::for_owner("@alice");
    event.sign(&RoleName::targets(), &mut alice).unwrap();
    repo.merge(&event);
    repo.main.0.extend(files.0.clone());

    let mut changed = Files::default();
    repo.add_artifact(&mut changed, "notes.txt", b"second");
    let mut event = repo.event_with(&changed);
    let mut artifacts = repo.main.clone();
    artifacts.0.extend(changed.0.clone());
    event.update_targets(&artifacts).unwrap();

    assert_eq!(
        event.artifact_changes(&RoleName::targets()),
        [ArtifactChange::Modified("notes.txt".into())]
    );
}

#[test]
fn a_signing_event_that_touches_online_metadata_is_refused() {
    let mut repo = Repo::new();
    bootstrap(&mut repo, &["@alice"], 1);

    // Give the repository a snapshot, as online signing would.
    let snapshot = serde_json::json!({
        "_type": "snapshot",
        "spec_version": "1.0.31",
        "version": 1,
        "expires": "2027-01-01T00:00:00Z",
        "meta": {},
    });
    let published = serde_json::to_vec(&snapshot).unwrap();
    repo.main
        .0
        .insert("metadata/snapshot.json".into(), published);

    let mut tampered = snapshot.clone();
    tampered["version"] = serde_json::json!(99);
    let mut files = Files::default();
    files.0.insert(
        "metadata/snapshot.json".into(),
        serde_json::to_vec(&tampered).unwrap(),
    );

    let event = repo.event_with(&files);
    let status = event.status();
    assert!(
        status
            .problems
            .iter()
            .any(|problem| problem.contains("signed online")),
        "{status:#?}"
    );
    assert!(!status.is_mergeable());
}

#[test]
fn a_delegated_role_may_not_delegate_further() {
    let mut repo = Repo::new();
    bootstrap(&mut repo, &["@alice"], 1);

    let crates: RoleName = "crates".parse().unwrap();
    let mut event = repo.event();
    event
        .configure_role(&crates, &config(&["@alice"], 1))
        .unwrap();
    let alice_key = MemorySigner::for_owner("@alice").public_key().1;
    event.accept_invite(&crates, "@alice", alice_key).unwrap();

    // The state machine has no API for nesting a delegation, so this checks the guard
    // against metadata that arrived from somewhere else.
    let mut files = repo.persist(&event);
    let payload = files.0.get_mut("metadata/crates.json").unwrap();
    let mut json: serde_json::Value = serde_json::from_slice(payload).unwrap();
    json["delegations"] = serde_json::json!({
        "keys": {},
        "roles": [{
            "name": "deeper",
            "keyids": [],
            "threshold": 1,
            "paths": ["deeper/*"],
            "terminating": true,
            "x-tuf-ci-expiry-days": 365,
            "x-tuf-ci-signing-days": 60,
        }],
    });
    *payload = serde_json::to_vec_pretty(&json).unwrap();

    let event = repo.event_with(&files);
    let status = event.role_status(&crates);
    assert!(
        status
            .problems
            .iter()
            .any(|problem| problem.contains("may not delegate further")),
        "{status:#?}"
    );
}

#[test]
fn a_key_id_that_does_not_name_its_own_key_is_rejected() {
    let mut repo = Repo::new();
    bootstrap(&mut repo, &["@alice"], 1);

    let mut event = repo.event();
    event
        .configure_role(&RoleName::root(), &config(&["@alice", "@bob"], 1))
        .unwrap();
    let bob_key = MemorySigner::for_owner("@bob").public_key().1;
    event
        .accept_invite(&RoleName::root(), "@bob", bob_key)
        .unwrap();

    // Swap in a key id that does not hash to the key material filed under it.
    let mut files = repo.persist(&event);
    let payload = files.0.get_mut("metadata/root.json").unwrap();
    let mut json: serde_json::Value = serde_json::from_slice(payload).unwrap();
    let keys = json["keys"].as_object_mut().unwrap();
    let (id, key) = keys
        .iter()
        .next()
        .map(|(k, v)| (k.clone(), v.clone()))
        .unwrap();
    keys.remove(&id);
    let forged = "0".repeat(64);
    keys.insert(forged.clone(), key);
    for role in json["roles"].as_object_mut().unwrap().values_mut() {
        let keyids = role["keyids"].as_array_mut().unwrap();
        for keyid in keyids.iter_mut() {
            if keyid.as_str() == Some(id.as_str()) {
                *keyid = serde_json::json!(forged);
            }
        }
    }
    *payload = serde_json::to_vec_pretty(&json).unwrap();

    let event = repo.event_with(&files);
    let status = event.role_status(&RoleName::root());
    assert!(
        status
            .problems
            .iter()
            .any(|problem| problem.contains("does not match its own key material")),
        "{status:#?}"
    );
}

#[test]
fn snapshot_and_timestamp_must_share_a_signer() {
    let mut repo = Repo::new();
    bootstrap(&mut repo, &["@alice"], 1);

    let mut json: serde_json::Value =
        serde_json::from_slice(repo.main.0.get("metadata/root.json").unwrap()).unwrap();
    json["version"] = serde_json::json!(2);
    json["roles"]["timestamp"]["keyids"] = serde_json::json!([]);
    json["roles"]["timestamp"]["threshold"] = serde_json::json!(0);
    let mut files = Files::default();
    files.0.insert(
        "metadata/root.json".into(),
        serde_json::to_vec_pretty(&json).unwrap(),
    );

    let event = repo.event_with(&files);
    let status = event.role_status(&RoleName::root());
    assert!(
        status
            .problems
            .iter()
            .any(|problem| problem.contains("same keys")),
        "{status:#?}"
    );
}

#[test]
fn a_revoked_delegation_takes_its_metadata_with_it() {
    let mut repo = Repo::new();
    bootstrap(&mut repo, &["@alice"], 1);

    let crates: RoleName = "crates".parse().unwrap();
    let mut event = repo.event();
    event
        .configure_role(&crates, &config(&["@alice"], 1))
        .unwrap();
    let alice_key = MemorySigner::for_owner("@alice").public_key().1;
    event.accept_invite(&crates, "@alice", alice_key).unwrap();
    let mut alice = MemorySigner::for_owner("@alice");
    event.sign(&RoleName::targets(), &mut alice).unwrap();
    event.sign(&crates, &mut alice).unwrap();
    repo.merge(&event);

    let mut event = repo.event();
    assert!(event.revoke_delegation(&crates).unwrap());
    assert!(!event.current().targets.contains_key(&crates));

    let change = event
        .delegation_changes(&RoleName::targets())
        .into_iter()
        .find(|change| change.role == crates)
        .expect("the removal should be reported");
    assert!(change.current.is_none());
    assert!(change.previous.is_some());

    assert!(
        event.revoke_delegation(&RoleName::targets()).is_err(),
        "top-level roles cannot be revoked"
    );
}

#[test]
fn signatures_survive_a_write_and_read_cycle() {
    let mut repo = Repo::new();
    bootstrap(&mut repo, &["@alice", "@bob"], 2);

    let mut files = Files::default();
    repo.add_artifact(&mut files, "notes.txt", b"contents");
    let mut event = repo.event_with(&files);
    let mut artifacts = repo.main.clone();
    artifacts.0.extend(files.0.clone());
    event.update_targets(&artifacts).unwrap();

    let mut alice = MemorySigner::for_owner("@alice");
    event.sign(&RoleName::targets(), &mut alice).unwrap();

    // Alice pushes; Bob pulls and picks up where she left off.
    let mut pushed = files.clone();
    pushed.0.extend(repo.persist(&event).0);
    let mut event = repo.event_with(&pushed);

    let status = event.role_status(&RoleName::targets());
    assert_eq!(
        status
            .tally
            .signed
            .iter()
            .map(|s| &s.name)
            .collect::<Vec<_>>(),
        ["@alice"],
        "alice's signature should have survived the round trip"
    );

    let mut bob = MemorySigner::for_owner("@bob");
    event.sign(&RoleName::targets(), &mut bob).unwrap();
    assert!(event.status().is_mergeable(), "{:#?}", event.status());
}

#[test]
fn a_forged_signature_is_reported_as_invalid_rather_than_counted() {
    let mut repo = Repo::new();
    bootstrap(&mut repo, &["@alice"], 1);

    let mut files = Files::default();
    repo.add_artifact(&mut files, "notes.txt", b"contents");
    let mut event = repo.event_with(&files);
    let mut artifacts = repo.main.clone();
    artifacts.0.extend(files.0.clone());
    event.update_targets(&artifacts).unwrap();

    let mut written = files.clone();
    written.0.extend(repo.persist(&event).0);

    // Alice's key id, with somebody else's signature under it.
    let alice = MemorySigner::for_owner("@alice");
    let mut forger = MemorySigner::for_owner("@mallory");
    let event = repo.event_with(&written);
    let targets = event.current().targets.get(&RoleName::targets()).unwrap();
    let forged = forger.sign(&targets.signing_input()).unwrap();
    let sigs = serde_json::json!({
        "signatures": [{
            "keyid": alice.key_id().to_string(),
            "sig": base64_encode(&forged),
        }],
    });
    written.0.insert(
        "metadata/targets.sig.json".into(),
        serde_json::to_vec(&sigs).unwrap(),
    );

    let event = repo.event_with(&written);
    let status = event.role_status(&RoleName::targets());
    assert!(status.tally.signed.is_empty());
    assert_eq!(
        status
            .tally
            .invalid
            .iter()
            .map(|s| &s.name)
            .collect::<Vec<_>>(),
        ["@alice"]
    );
    assert!(!status.is_complete());
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[test]
fn an_event_with_no_changes_is_not_mergeable() {
    let mut repo = Repo::new();
    bootstrap(&mut repo, &["@alice"], 1);

    let event = repo.event();
    let status = event.status();
    assert!(status.roles.is_empty());
    assert!(!status.is_mergeable(), "there is nothing to merge");
}

#[test]
fn key_ids_do_not_change_when_a_key_is_annotated() {
    // The whole reason key ids are derived from key material rather than from the JSON key
    // object: adding or changing an owner must not rename the key, because renaming it
    // would invalidate every delegation that refers to it.
    let signer = MemorySigner::for_owner("@alice");
    let (bare_id, mut key) = Key::from_pem(signer.public_key_pem(), "@alice").unwrap();
    key.owner = Some("@alice-with-a-new-handle".into());
    key.extra
        .insert("x-invented-later".into(), serde_json::json!(true));
    assert_eq!(key.derived_key_id().unwrap(), bare_id);
}
