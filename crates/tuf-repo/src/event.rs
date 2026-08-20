//! The signing event: what changed, who still has to sign, and whether it can be merged.
//!
//! A signing event is a branch. Everything on it is judged against the *known-good* state
//! it branched from — the merge base with the main branch — and that comparison is the
//! whole model:
//!
//! * a role whose payload differs from the known-good one has changed, so it needs signing;
//! * its new version is one more than the known-good version, however many commits the
//!   branch has accumulated, so a signer who signs twice does not bump it twice;
//! * an invitation to a role is open until the invitee contributes a key.
//!
//! The signing tool and the CI tool both drive this one type. In the Python implementation
//! these were two classes with two slightly different sets of rules, which is how a signing
//! event could look complete to a signer and incomplete to CI.
//!
//! # Valid, but not yet signed
//!
//! Metadata written here is always structurally valid TUF metadata — it just has fewer
//! signatures than it needs. That is a deliberate line. A role whose threshold is being
//! raised to two while the second signer has yet to produce a key would be *invalid*, not
//! merely unsigned, and every reader is entitled to reject it. So intent that cannot be
//! written yet waits in [`EventState`] instead, and lands the moment it can be satisfied.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Duration, Utc};
use tuf::crypto::{KeyId, PublicKey};
use tuf::database::Database;
use tuf::metadata::{Metadata, MetadataPath, RawSignedMetadata, RootMetadata, TargetDescription};
use tuf::pouf::Pouf2;

use crate::crypto;
use crate::error::{Error, Result};
use crate::policy::{self, Periods};

pub use crate::policy::RoleConfig;
use crate::signer::Signer;
use crate::store::{
    Delegator, EventState, RepoState, RootParts, Signed, Source, TARGETS_DIR, Tally, TargetsParts,
    Writer, payload_path, signature_path,
};

/// How much clock skew between the machine that signed and the machine that checks is
/// tolerated before an expiry date is called implausible.
const EXPIRY_TOLERANCE: Duration = Duration::hours(24);

// ---------------------------------------------------------------------------
// Status reporting
// ---------------------------------------------------------------------------

/// A change to one artifact within a signing event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArtifactChange {
    /// The artifact is new in this event.
    Added(String),
    /// The artifact existed before, with different contents.
    Modified(String),
    /// The artifact has been withdrawn.
    Removed(String),
}

impl ArtifactChange {
    /// The artifact's path, relative to the `targets/` directory.
    pub fn path(&self) -> &str {
        match self {
            ArtifactChange::Added(path)
            | ArtifactChange::Modified(path)
            | ArtifactChange::Removed(path) => path,
        }
    }

    /// A one-word description of what happened.
    pub fn verb(&self) -> &'static str {
        match self {
            ArtifactChange::Added(_) => "added",
            ArtifactChange::Modified(_) => "modified",
            ArtifactChange::Removed(_) => "removed",
        }
    }
}

/// Who may sign a role, and how many of them are needed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Quorum {
    /// The signers, named the way a person would recognise them.
    pub signers: Vec<String>,
    /// How many of them must sign.
    pub threshold: u32,
}

/// A change to a delegation within a signing event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DelegationChange {
    /// The role being delegated to.
    pub role: MetadataPath,
    /// Who may sign it now. `None` if the delegation has been removed.
    pub current: Option<Quorum>,
    /// Who could sign it before. `None` if the delegation is new.
    pub previous: Option<Quorum>,
}

/// An open invitation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invitation {
    /// The invited signer's `@handle`.
    pub user: String,
    /// The role they have been invited to sign.
    pub role: MetadataPath,
}

/// Where one role stands in a signing event.
#[derive(Clone, Debug)]
pub struct RoleStatus {
    /// The role.
    pub role: MetadataPath,
    /// The version this event proposes.
    pub version: u32,
    /// Signatures against the keys this event's own metadata specifies.
    pub tally: Tally,
    /// For root only: signatures against the keys the *previous* root specified.
    ///
    /// A new root has to satisfy both the outgoing key set and the incoming one, so that
    /// rotating a key still requires the consent of whoever held the old one.
    pub previous_tally: Option<Tally>,
    /// Invitations that must be accepted before this role is worth signing, because
    /// accepting one changes this role's own metadata.
    pub blocking_invites: Vec<Invitation>,
    /// Artifact changes this role vouches for.
    pub artifacts: Vec<ArtifactChange>,
    /// Delegation changes this role makes.
    pub delegations: Vec<DelegationChange>,
    /// Reasons this role's metadata is not acceptable, irrespective of signatures.
    pub problems: Vec<String>,
    /// Whether an automated key signs this role rather than people.
    pub online: bool,
}

impl RoleStatus {
    /// Whether this role is fully signed, valid, and not waiting on an invitation.
    ///
    /// An online role is complete as soon as it is valid. Its signature is applied by
    /// automation when the repository is published, so holding a signing event open until
    /// it appears would be waiting for something nobody taking part can do.
    pub fn is_complete(&self) -> bool {
        self.problems.is_empty()
            && self.blocking_invites.is_empty()
            && (self.online
                || (self.tally.is_met()
                    && self
                        .previous_tally
                        .as_ref()
                        .is_none_or(|previous| previous.is_met())))
    }

    /// How many more signatures this role needs from people.
    pub fn outstanding(&self) -> u32 {
        if self.online {
            return 0;
        }
        let previous = self
            .previous_tally
            .as_ref()
            .map_or(0, |tally| tally.outstanding());
        self.tally.outstanding().max(previous)
    }

    /// Everyone whose signature is still wanted.
    pub fn waiting_on(&self) -> Vec<&str> {
        if self.online {
            return Vec::new();
        }
        let mut names: Vec<&str> = self
            .tally
            .missing
            .iter()
            .chain(self.previous_tally.iter().flat_map(|tally| &tally.missing))
            .map(|who| who.name.as_str())
            .collect();
        names.sort_unstable();
        names.dedup();
        names
    }
}

/// Where a whole signing event stands.
#[derive(Clone, Debug)]
pub struct EventStatus {
    /// One entry per role changed in this event, delegators before their delegates.
    pub roles: Vec<RoleStatus>,
    /// Invitations still open anywhere in the event.
    ///
    /// Taken from the event's own state rather than from the roles, because an event can
    /// consist of nothing but an invitation: a configuration that raises a threshold
    /// changes no metadata until the keys to meet it arrive, and until then this is the
    /// only thing there is to report.
    pub invitations: Vec<Invitation>,
    /// Problems with the event as a whole rather than with any one role.
    pub problems: Vec<String>,
}

impl EventStatus {
    /// Whether every changed role is signed and valid, so the event can be merged.
    pub fn is_mergeable(&self) -> bool {
        self.problems.is_empty()
            && self.invitations.is_empty()
            && !self.roles.is_empty()
            && self.roles.iter().all(RoleStatus::is_complete)
    }

    /// How many signatures the event is still short of, across all roles.
    pub fn outstanding(&self) -> u32 {
        self.roles.iter().map(RoleStatus::outstanding).sum()
    }

    /// Every open invitation in the event.
    pub fn invitations(&self) -> Vec<&Invitation> {
        self.invitations.iter().collect()
    }
}

/// What one signer has to do about a signing event.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SignerTasks {
    /// Roles the signer has been invited to and must contribute a key for.
    pub accept: Vec<MetadataPath>,
    /// Roles that are waiting on this signer's signature.
    pub sign: Vec<MetadataPath>,
}

impl SignerTasks {
    /// Whether this signer has nothing to do.
    pub fn is_empty(&self) -> bool {
        self.accept.is_empty() && self.sign.is_empty()
    }
}

// ---------------------------------------------------------------------------
// The event itself
// ---------------------------------------------------------------------------

/// A signing event: a proposed repository state, judged against the state it branched from.
pub struct SigningEvent {
    known_good: RepoState,
    current: RepoState,
    now: DateTime<Utc>,
    dirty: BTreeSet<MetadataPath>,
    state_dirty: bool,
}

impl SigningEvent {
    /// Load an event from the state it branched from and the state it proposes.
    pub fn load(known_good: &dyn Source, current: &dyn Source) -> Result<Self> {
        Ok(SigningEvent::from_states(
            RepoState::load(known_good)?,
            RepoState::load(current)?,
        ))
    }

    /// Build an event from two already-loaded states.
    pub fn from_states(known_good: RepoState, current: RepoState) -> Self {
        SigningEvent {
            known_good,
            current,
            now: Utc::now(),
            dirty: BTreeSet::new(),
            state_dirty: false,
        }
    }

    /// Pin the current time, so that expiry dates in tests are predictable.
    pub fn at(mut self, now: DateTime<Utc>) -> Self {
        self.now = now;
        self
    }

    /// The state this event proposes.
    pub fn current(&self) -> &RepoState {
        &self.current
    }

    /// The state this event branched from.
    pub fn known_good(&self) -> &RepoState {
        &self.known_good
    }

    /// The invitations and pending configuration.
    pub fn event_state(&self) -> &EventState {
        &self.current.event
    }

    /// Whether the repository exists yet.
    pub fn is_initialized(&self) -> bool {
        self.current.is_initialized()
    }

    // -- change detection ---------------------------------------------------

    /// Roles whose metadata this event changes, delegators before their delegates.
    pub fn changed_roles(&self) -> Vec<MetadataPath> {
        self.current
            .role_names()
            .into_iter()
            .filter(|role| self.role_changed(role))
            .collect()
    }

    /// Whether `role` is signed by an automated key rather than by people.
    ///
    /// Derived from the delegating document, which is where the repository records that a
    /// key is reachable by CI. Deliberately not a property of the role's name: `snapshot`
    /// and `timestamp` are online because an online key was configured for them, and a
    /// delegated role — a nightly channel whose artifacts land faster than people can sign
    /// for them — is online on exactly the same terms.
    pub fn is_online(&self, role: &MetadataPath) -> bool {
        self.current
            .delegator_of(role)
            .is_ok_and(|delegator| delegator.is_online(role))
    }

    /// Every role an automated key signs.
    ///
    /// Root is never among them however its keys are recorded: it is the trust anchor, and
    /// [`status`](Self::status) reports an online key in root as the fault it is rather
    /// than quietly treating root as automated.
    pub fn online_roles(&self) -> Vec<MetadataPath> {
        let mut roles = self.current.role_names();
        roles.push(MetadataPath::snapshot());
        roles.push(MetadataPath::timestamp());
        roles.retain(|role| *role != MetadataPath::root() && self.is_online(role));
        roles
    }

    fn role_changed(&self, role: &MetadataPath) -> bool {
        match (
            self.current.raw_payload(role),
            self.known_good.raw_payload(role),
        ) {
            (Some(current), Some(known_good)) => current != known_good,
            (Some(_), None) => true,
            (None, _) => false,
        }
    }

    /// Roles that this event changes and that need `user`'s attention.
    pub fn tasks_for(&self, user: &str) -> SignerTasks {
        let mut tasks = SignerTasks {
            accept: self.current.event.for_user(user).to_vec(),
            sign: Vec::new(),
        };

        for role in self.changed_roles() {
            if !self.blocking_invites(&role).is_empty() {
                // The key set is still moving; signing now would be wasted effort.
                continue;
            }
            if self.eligible_key_ids(&role, user).is_empty() {
                continue;
            }
            if !self.has_valid_signature_from(&role, user) {
                tasks.sign.push(role);
            }
        }

        tasks
    }

    /// The keys `user` holds that are permitted to sign `role`.
    ///
    /// For root this includes keys named by the *previous* root, because a signer being
    /// rotated out still has to consent to the root that removes them.
    fn eligible_key_ids(&self, role: &MetadataPath, user: &str) -> Vec<KeyId> {
        let mut key_ids = BTreeSet::new();
        for delegator in self.delegators_of(role) {
            for (key_id, _) in delegator.keys_for(role) {
                if delegator.policy().signers.get(&key_id).map(String::as_str) == Some(user) {
                    key_ids.insert(key_id);
                }
            }
        }
        key_ids.into_iter().collect()
    }

    /// The delegators whose opinion of `role` matters: the current one, plus for root the
    /// previous one.
    fn delegators_of(&self, role: &MetadataPath) -> Vec<Delegator<'_>> {
        let mut delegators = Vec::new();
        if let Ok(delegator) = self.current.delegator_of(role) {
            delegators.push(delegator);
        }
        if *role == MetadataPath::root()
            && let Some(previous) = &self.known_good.root
        {
            delegators.push(previous.delegator());
        }
        delegators
    }

    fn has_valid_signature_from(&self, role: &MetadataPath, user: &str) -> bool {
        let tallies: Vec<Tally> = if *role == MetadataPath::root() {
            match &self.current.root {
                Some(root) => self
                    .delegators_of(role)
                    .iter()
                    .map(|delegator| root.tally(delegator, role))
                    .collect(),
                None => Vec::new(),
            }
        } else {
            match self.current.targets.get(role) {
                Some(targets) => self
                    .delegators_of(role)
                    .iter()
                    .map(|delegator| targets.tally(delegator, role))
                    .collect(),
                None => Vec::new(),
            }
        };
        tallies
            .into_iter()
            .flat_map(|tally| tally.signed)
            .any(|who| who.name == user)
    }

    /// Every invitation the event is still waiting on.
    pub fn open_invitations(&self) -> Vec<Invitation> {
        let mut invitations: Vec<Invitation> = self
            .current
            .event
            .invites
            .iter()
            .flat_map(|(user, roles)| {
                roles.iter().map(move |role| Invitation {
                    user: user.clone(),
                    role: role.clone(),
                })
            })
            .collect();
        invitations.sort_by(|a, b| (&a.user, &a.role).cmp(&(&b.user, &b.role)));
        invitations
    }

    /// Invitations that block `role` from being signed.
    ///
    /// Accepting an invitation adds a key to the delegating role's metadata, so any role
    /// with an outstanding invitation to one of its delegates is still in flux. A pending
    /// configuration blocks for the same reason: it will rewrite this role when it lands.
    pub fn blocking_invites(&self, role: &MetadataPath) -> Vec<Invitation> {
        let Some(delegator) = self.current.delegator_view(role) else {
            return Vec::new();
        };
        let mut invitations = Vec::new();
        for delegated in delegator.delegated_roles() {
            for user in self.current.event.for_role(&delegated) {
                invitations.push(Invitation {
                    user: user.to_owned(),
                    role: delegated.clone(),
                });
            }
        }
        invitations.sort_by(|a, b| (&a.user, &a.role).cmp(&(&b.user, &b.role)));
        invitations.dedup();
        invitations
    }

    // -- status -------------------------------------------------------------

    /// Where the event stands.
    pub fn status(&self) -> EventStatus {
        let mut problems = Vec::new();

        // Online metadata is re-signed on every publish with a key CI holds. A signing
        // event that changes it either has a stale checkout or is trying something it
        // should not, and either way the change cannot be signed here.
        for role in self.online_roles() {
            let known_good = self.known_good.raw_payload(&role);
            if known_good.is_some() && self.current.raw_payload(&role) != known_good {
                problems.push(format!(
                    "{role} metadata is signed online and must not be changed in a signing event"
                ));
            }
        }

        let roles: Vec<RoleStatus> = self
            .changed_roles()
            .into_iter()
            .map(|role| self.role_status(&role))
            .collect();

        let mut status = EventStatus {
            roles,
            invitations: self.open_invitations(),
            problems,
        };

        // The last gate, and only on an event that is otherwise ready: `tuf` decides
        // whether the root transition is one a client would accept.
        if status.is_mergeable()
            && let Err(err) = self.check_root_chain()
        {
            status
                .problems
                .push(format!("root cannot be rolled forward: {err}"));
        }

        status
    }

    /// Replay the root transition this event proposes through `tuf`'s own trust engine.
    ///
    /// Everything the library knows about moving from one root to the next — that the
    /// version advances by exactly one, that the new root satisfies both the outgoing key
    /// set and its own, that neither has expired — is checked here rather than reimplemented.
    ///
    /// Only meaningful once the signatures are in, so [`status`](Self::status) runs it as a
    /// last gate on an event that already looks complete. Running it earlier would report
    /// "not enough signatures" as a defect, which is the one thing a signing event is
    /// supposed to be.
    pub fn check_root_chain(&self) -> Result<()> {
        let (Some(known_good), Some(current)) = (&self.known_good.root, &self.current.root) else {
            return Ok(());
        };
        if known_good.raw() == current.raw() {
            return Ok(());
        }

        let trusted = RawSignedMetadata::<Pouf2, RootMetadata>::new(known_good.envelope()?);
        let proposed = RawSignedMetadata::<Pouf2, RootMetadata>::new(current.envelope()?);
        let mut database =
            Database::from_trusted_root(&trusted).map_err(|err| Error::invalid(err.to_string()))?;
        database
            .update_root(&proposed)
            .map_err(|err| Error::invalid(err.to_string()))?;
        Ok(())
    }

    /// Where one role stands.
    pub fn role_status(&self, role: &MetadataPath) -> RoleStatus {
        let mut problems = Vec::new();

        let (version, tally, previous_tally) = match self.current.delegator_of(role) {
            Err(err) => {
                problems.push(err.to_string());
                (0, Tally::empty(role.clone()), None)
            }
            Ok(delegator) => {
                let (version, tally) = if *role == MetadataPath::root() {
                    match &self.current.root {
                        Some(root) => (root.payload().version(), root.tally(&delegator, role)),
                        None => (0, Tally::empty(role.clone())),
                    }
                } else {
                    match self.current.targets.get(role) {
                        Some(targets) => {
                            (targets.payload().version(), targets.tally(&delegator, role))
                        }
                        None => (0, Tally::empty(role.clone())),
                    }
                };

                // A new root must also satisfy the root it replaces.
                let previous_tally = match (*role == MetadataPath::root(), &self.current.root) {
                    (true, Some(current_root)) => self
                        .known_good
                        .root
                        .as_ref()
                        .map(|previous| current_root.tally(&previous.delegator(), role)),
                    _ => None,
                };

                (version, tally, previous_tally)
            }
        };

        problems.extend(self.validate(role));

        RoleStatus {
            role: role.clone(),
            version,
            tally,
            previous_tally,
            online: self.is_online(role),
            blocking_invites: self.blocking_invites(role),
            artifacts: self.artifact_changes(role),
            delegations: self.delegation_changes(role),
            problems,
        }
    }

    /// Artifact changes `role` vouches for in this event.
    pub fn artifact_changes(&self, role: &MetadataPath) -> Vec<ArtifactChange> {
        let current = self.artifacts_of(&self.current, role);
        let previous = self.artifacts_of(&self.known_good, role);

        let mut changes = Vec::new();
        for (path, target) in &current {
            match previous.get(path) {
                None => changes.push(ArtifactChange::Added(path.clone())),
                Some(before) if before != target => {
                    changes.push(ArtifactChange::Modified(path.clone()));
                }
                Some(_) => {}
            }
        }
        for path in previous.keys() {
            if !current.contains_key(path) {
                changes.push(ArtifactChange::Removed(path.clone()));
            }
        }
        changes.sort_by(|a, b| a.path().cmp(b.path()));
        changes
    }

    fn artifacts_of<'a>(
        &self,
        state: &'a RepoState,
        role: &MetadataPath,
    ) -> BTreeMap<String, &'a TargetDescription> {
        state
            .targets
            .get(role)
            .map(|signed| {
                signed
                    .payload()
                    .targets()
                    .iter()
                    .map(|(path, description)| (path.to_string(), description))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Delegation changes `role` makes in this event.
    pub fn delegation_changes(&self, role: &MetadataPath) -> Vec<DelegationChange> {
        let current = self.current.delegator_view(role);
        let previous = self.known_good.delegator_view(role);

        let mut names: BTreeSet<MetadataPath> = BTreeSet::new();
        if let Some(delegator) = &current {
            names.extend(delegator.delegated_roles());
        }
        if let Some(delegator) = &previous {
            names.extend(delegator.delegated_roles());
        }

        names
            .into_iter()
            .filter_map(|name| {
                let now = current.as_ref().and_then(|d| quorum_of(d, &name));
                let before = previous.as_ref().and_then(|d| quorum_of(d, &name));
                if now == before {
                    return None;
                }
                Some(DelegationChange {
                    role: name,
                    current: now,
                    previous: before,
                })
            })
            .collect()
    }

    /// Everything wrong with `role`'s metadata that signatures cannot fix.
    fn validate(&self, role: &MetadataPath) -> Vec<String> {
        let mut problems = Vec::new();

        let Some((version, expires)) = self.payload_facts(role) else {
            return problems;
        };

        // A published version must never be replaced by a different document with the same
        // number, and root in particular has to advance one at a time so that a client can
        // walk the chain.
        let expected = self.known_good.version_of(role) + 1;
        if version != expected {
            problems.push(format!(
                "{role} is version {version}, but this signing event branched from version {} \
                 and so must produce version {expected}",
                self.known_good.version_of(role)
            ));
        }

        if let Ok(delegator) = self.current.delegator_of(role) {
            match delegator.role_spec(role) {
                None => problems.push(format!("nothing delegates to {role}")),
                Some(spec) => {
                    if let Err(err) = spec.periods.validate(role) {
                        problems.push(err.to_string());
                    }
                    let latest = spec.periods.expires_at(self.now) + EXPIRY_TOLERANCE;
                    if expires > latest {
                        problems.push(format!(
                            "{role} expires {expires}, further ahead than its {} day expiry \
                             period allows",
                            spec.periods.expiry_days
                        ));
                    }
                    for key_id in &spec.keyids {
                        if delegator.key(key_id).is_none() {
                            problems.push(format!(
                                "{role} may be signed by key {}, which the delegating role does \
                                 not hold",
                                crypto::abbreviated(key_id)
                            ));
                        }
                    }
                }
            }

            // Every key has to be attributable to a person or to an automated signer,
            // because that is what decides whether this role waits for a signing event or
            // for the next publish. A key that is both, or neither, decides nothing.
            let policy = delegator.policy();
            let (mut online, mut offline) = (0usize, 0usize);
            for (key_id, _) in delegator.keys_for(role) {
                match (
                    policy.signers.contains_key(&key_id),
                    policy.is_online_key(&key_id),
                ) {
                    (true, false) => offline += 1,
                    (false, true) => online += 1,
                    (false, false) => problems.push(format!(
                        "{role} key {} has no owner, so nobody can be asked to sign with it",
                        crypto::abbreviated(&key_id)
                    )),
                    (true, true) => problems.push(format!(
                        "{role} key {} is recorded both as a person's key and as an online \
                         key, so what signs it is undecided",
                        crypto::abbreviated(&key_id)
                    )),
                }
            }
            if online > 0 && offline > 0 {
                problems.push(format!(
                    "{role} mixes an online key with a person's key. A role is signed either \
                     by automation on every publish or by people in a signing event, and the \
                     two cannot be combined into one threshold."
                ));
            }
        }

        if *role == MetadataPath::root() {
            problems.extend(self.validate_root());
        }

        // Only the top-level targets role delegates. Allowing delegates to delegate would
        // make the artifact-to-role mapping depend on a tree walk rather than on the path.
        if policy::is_targets(role)
            && *role != MetadataPath::targets()
            && let Some(targets) = self.current.targets.get(role)
            && !targets.payload().delegations().roles().is_empty()
        {
            problems.push(format!(
                "{role} is a delegated role and may not delegate further"
            ));
        }

        // The keys a targets role publishes for its own delegates get the same check root's
        // do. Nothing else would notice one key filed under two names, which is how a role
        // needing two signatures gets satisfied by one person.
        if let Some(targets) = self.current.targets.get(role) {
            check_key_ids(
                role.as_str(),
                targets.payload().delegations().keys(),
                &mut problems,
            );
        }

        problems
    }

    fn validate_root(&self) -> Vec<String> {
        let mut problems = Vec::new();
        let Some(signed) = &self.current.root else {
            return problems;
        };
        let root = signed.payload();

        if !root.consistent_snapshot() {
            problems.push(
                "root disables consistent snapshots, which this repository always uses".into(),
            );
        }

        // Root is the trust anchor. A key CI can reach is a key that can rewrite every
        // other role's key set with nobody signing for it, which is the one thing offline
        // signing exists to prevent.
        if self
            .current
            .root
            .as_ref()
            .is_some_and(|signed| signed.delegator().is_online(&MetadataPath::root()))
        {
            problems.push(
                "root is signed by an online key. Root must be signed offline: a key CI can \
                 reach could replace every other role's keys unopposed."
                    .into(),
            );
        }

        check_key_ids("root", root.keys(), &mut problems);
        problems
    }

    fn payload_facts(&self, role: &MetadataPath) -> Option<(u32, DateTime<Utc>)> {
        if *role == MetadataPath::root() {
            let root = self.current.root.as_ref()?;
            return Some((root.payload().version(), *root.payload().expires()));
        }
        let targets = self.current.targets.get(role)?;
        Some((targets.payload().version(), *targets.payload().expires()))
    }

    // -- mutation -----------------------------------------------------------

    /// Create the root and top-level targets metadata for a new repository.
    ///
    /// `key` is the key of whoever is creating the repository, and it starts out as the
    /// sole signer of all four roles. That is not a convenience: TUF metadata naming a
    /// threshold it has no keys to meet is not valid metadata, so there is no such thing
    /// as a repository with no keys at all. The online roles are handed to an automated
    /// key by [`configure_online`](Self::configure_online), and the offline ones opened up
    /// to more signers by [`configure_role`](Self::configure_role); every state in between
    /// is a valid repository with one signer.
    pub fn initialize(&mut self, periods: Periods, key: PublicKey, owner: &str) -> Result<()> {
        if self.current.is_initialized() {
            return Err(Error::invalid("this repository already has root metadata"));
        }
        periods.validate(&MetadataPath::root())?;

        let mut root = RootParts::empty(self.now, periods);
        root.version = self.known_good.version_of(&MetadataPath::root()) + 1;
        for entry in root.roles.values_mut() {
            entry.keyids.insert(key.key_id().clone());
        }
        root.policy
            .signers
            .insert(key.key_id().clone(), owner.to_owned());
        root.keys.insert(key.key_id().clone(), key);
        self.current.root = Some(Signed::new(root.build()?)?);
        self.dirty.insert(MetadataPath::root());

        let targets_role = MetadataPath::targets();
        let mut targets = TargetsParts::empty(self.now, periods);
        targets.version = self.known_good.version_of(&targets_role) + 1;
        self.current
            .targets
            .insert(targets_role.clone(), Signed::new(targets.build()?)?);
        self.dirty.insert(targets_role);
        Ok(())
    }

    /// Set who may sign `role`, how many of them are needed, and for how long.
    ///
    /// Signers who do not yet have a key are invited rather than added: their key material
    /// only enters the repository when they run the signing tool themselves. Until every
    /// named signer has a key the configuration cannot be written — a threshold of two with
    /// one key is not valid metadata — so it waits in the event state and lands as soon as
    /// the last invitation is accepted.
    ///
    /// Returns whether anything changed.
    pub fn configure_role(&mut self, role: &MetadataPath, config: &RoleConfig) -> Result<bool> {
        config.validate(role)?;

        let before = self.current.event.clone();
        let mut event = self.current.event.clone();
        event.remove_role(role);

        let held = self.keys_by_owner(role);
        for signer in &config.signers {
            if !held.contains_key(signer) {
                event.add(signer, role);
            }
        }

        // A targets role needs a document of its own to sign, even before it has any
        // artifacts in it. Create it first so the delegation has something to point at.
        let created = self.ensure_targets_exists(role)?;

        let ready = config
            .signers
            .iter()
            .all(|signer| held.contains_key(signer));
        let applied = if ready {
            self.apply_role_config(role, config)?
        } else {
            event
                .pending
                .insert(role.as_str().to_owned(), config.clone());
            false
        };

        let event_changed = event != before;
        if event_changed {
            self.current.event = event;
            self.state_dirty = true;
        }

        Ok(applied || created || event_changed)
    }

    /// Write `config` into the delegating role's metadata.
    ///
    /// Every signer named must already hold a key, which is what makes the result valid.
    fn apply_role_config(&mut self, role: &MetadataPath, config: &RoleConfig) -> Result<bool> {
        let held = self.keys_by_owner(role);
        let keyids: BTreeSet<KeyId> = config
            .signers
            .iter()
            .filter_map(|signer| held.get(signer).cloned())
            .collect();
        if keyids.len() < config.signers.len() {
            return Err(Error::invalid(format!(
                "{role} cannot be configured yet: not every signer has a key"
            )));
        }
        let periods = config.periods;
        let threshold = config.threshold;

        self.edit_delegation(role, |parts| {
            parts.set_quorum(role, keyids.clone(), threshold, periods)
        })
    }

    /// Which key each signer named in `role`'s delegation holds, by `@handle`.
    fn keys_by_owner(&self, role: &MetadataPath) -> BTreeMap<String, KeyId> {
        let Ok(delegator) = self.current.delegator_of(role) else {
            return BTreeMap::new();
        };
        delegator
            .policy()
            .signers
            .iter()
            .filter(|(key_id, _)| delegator.key(key_id).is_some())
            .map(|(key_id, owner)| (owner.clone(), key_id.clone()))
            .collect()
    }

    /// Hand a role to an automated key.
    ///
    /// The counterpart of [`configure_role`](Self::configure_role): that one says which
    /// people sign, this one says which key CI signs with. Either can be applied to any
    /// role, and either replaces whatever was there — so a channel can be moved to
    /// automation when it starts releasing nightly, and moved back to people when it stops.
    /// Whichever was displaced is forgotten, keys and all.
    ///
    /// A role signed this way takes no part in signing events: its metadata is re-signed by
    /// whatever holds `uri` whenever it changes, and a branch that edits it is an error.
    /// The delegation is also the whole of the key's authority. It may sign this one role's
    /// metadata, over the artifact paths the delegation already names, and nothing else: it
    /// cannot widen its own reach, touch another role, or change who is allowed to sign.
    /// Those still take people.
    ///
    /// Root is the exception, and the only role this refuses. It is the trust anchor, and a
    /// key CI can reach could rewrite every other role's keys unopposed.
    ///
    /// Returns whether anything changed.
    pub fn configure_online_role(
        &mut self,
        role: &MetadataPath,
        key: PublicKey,
        uri: &str,
        periods: Periods,
    ) -> Result<bool> {
        if *role == MetadataPath::root() {
            return Err(Error::invalid(
                "root must be signed offline: a key CI can reach could replace every other \
                 role's keys unopposed",
            ));
        }
        if uri.is_empty() {
            return Err(Error::invalid(
                "an online key needs a signing URI for CI to reach it",
            ));
        }
        periods.validate(role)?;
        let key_id = key.key_id().clone();

        // An automated role has nobody to invite and nothing pending: whatever the role was
        // waiting on stops mattering the moment its key arrives.
        let before = self.current.event.clone();
        let mut event = before.clone();
        event.remove_role(role);
        let event_changed = event != before;
        if event_changed {
            self.current.event = event;
            self.state_dirty = true;
        }

        let created = self.ensure_targets_exists(role)?;
        let applied = self.edit_delegation(role, |parts| {
            parts.authorize_online(key.clone(), uri);
            parts.set_quorum(role, BTreeSet::from([key_id.clone()]), 1, periods)
        })?;

        Ok(applied || created || event_changed)
    }

    /// Contribute `user`'s key in response to an invitation.
    ///
    /// The key joins the delegating role immediately, at the threshold already in force.
    /// If that was the last invitation a pending configuration was waiting on, the
    /// configuration lands in the same call, so the metadata is never written in a state
    /// between the two.
    ///
    /// Returns whether anything changed.
    pub fn accept_invite(
        &mut self,
        role: &MetadataPath,
        user: &str,
        key: PublicKey,
    ) -> Result<bool> {
        if !self.current.event.for_user(user).contains(role) {
            return Err(Error::invalid(format!(
                "{user} has not been invited to sign {role}"
            )));
        }
        let owner = user.to_owned();

        self.edit_delegation(role, |parts| parts.authorize(role, key.clone(), &owner))?;

        self.current.event.remove(user, role);
        self.state_dirty = true;

        // The invitation this answered may have been the last one a configuration was
        // waiting for.
        if let Some(config) = self.current.event.pending_for(role).cloned() {
            let held = self.keys_by_owner(role);
            if config.signers.iter().all(|s| held.contains_key(s)) {
                self.apply_role_config(role, &config)?;
                self.current.event.pending.remove(role.as_str());
            }
        }

        Ok(true)
    }

    /// Remove a delegation to `role` and delete its metadata.
    ///
    /// Returns whether there was a delegation to remove.
    pub fn revoke_delegation(&mut self, role: &MetadataPath) -> Result<bool> {
        if policy::is_top_level(role) {
            return Err(Error::invalid(format!(
                "{role} is a top-level role and cannot be removed"
            )));
        }

        let targets_role = MetadataPath::targets();
        if !self.current.targets.contains_key(&targets_role) {
            return Ok(false);
        }
        let removed = self.edit_targets(&targets_role, |targets| {
            targets.remove_delegation(role);
            Ok(())
        })?;
        if !removed {
            return Ok(false);
        }

        self.current.targets.remove(role);
        self.current.event.remove_role(role);
        self.state_dirty = true;
        self.dirty.insert(role.clone());
        Ok(true)
    }

    /// Rebuild every targets role's artifact list from the files in `targets/`.
    ///
    /// Returns the roles whose metadata changed. This is what turns a commit that adds a
    /// file under `targets/` into a signable metadata change.
    pub fn update_targets(&mut self, artifacts: &dyn Source) -> Result<Vec<MetadataPath>> {
        let paths = artifacts.list(TARGETS_DIR)?;
        let mut updated = Vec::new();

        for role in self.current.targets.keys().cloned().collect::<Vec<_>>() {
            let patterns = self.artifact_patterns(&role);
            let mut described = BTreeMap::new();

            for path in &paths {
                let Some(relative) = path
                    .strip_prefix(TARGETS_DIR)
                    .and_then(|p| p.strip_prefix('/'))
                else {
                    continue;
                };
                if is_hidden(relative) {
                    continue;
                }
                if !patterns
                    .iter()
                    .any(|pattern| policy::path_matches(pattern, relative))
                {
                    continue;
                }
                let Some(bytes) = artifacts.read(path)? else {
                    continue;
                };
                let description =
                    TargetDescription::from_slice(&bytes, &[tuf::crypto::HashAlgorithm::Sha256])
                        .map_err(Error::invalid)?;
                described.insert(relative.to_owned(), description);
            }

            let changed = self.edit_targets(&role, |targets| {
                targets.targets = described
                    .iter()
                    .map(|(path, description)| {
                        Ok((
                            tuf::metadata::TargetPath::new(path.clone()).map_err(Error::invalid)?,
                            description.clone(),
                        ))
                    })
                    .collect::<Result<_>>()?;
                Ok(())
            })?;
            if changed {
                updated.push(role);
            }
        }

        Ok(updated)
    }

    /// The artifact path patterns `role` is responsible for.
    fn artifact_patterns(&self, role: &MetadataPath) -> Vec<String> {
        if *role == MetadataPath::targets() {
            // The top-level role owns files sitting directly in `targets/`; everything in
            // a subdirectory belongs to the role of the same name.
            return vec!["*".to_owned()];
        }
        self.current
            .delegator_view(&MetadataPath::targets())
            .map(|delegator| delegator.paths_for(role))
            .unwrap_or_default()
    }

    /// Sign `role` with `signer`.
    pub fn sign(&mut self, role: &MetadataPath, signer: &mut dyn Signer) -> Result<()> {
        let permitted = self.delegators_of(role).iter().any(|delegator| {
            delegator
                .keys_for(role)
                .iter()
                .any(|(key_id, _)| key_id == signer.key_id())
        });
        if !permitted {
            return Err(Error::invalid(format!(
                "key {} is not permitted to sign {role}",
                crypto::abbreviated(signer.key_id())
            )));
        }

        if *role == MetadataPath::root() {
            self.current
                .root
                .as_mut()
                .ok_or_else(|| Error::NoSuchRole(role.to_string()))?
                .sign_with(signer)?;
        } else {
            self.current
                .targets
                .get_mut(role)
                .ok_or_else(|| Error::NoSuchRole(role.to_string()))?
                .sign_with(signer)?;
        }
        self.dirty.insert(role.clone());
        Ok(())
    }

    /// Write every role this event has modified into a working tree.
    ///
    /// Returns the paths written or removed, in the form a caller can hand to `git add`.
    pub fn persist(&self, writer: &Writer) -> Result<Vec<String>> {
        let mut paths = Vec::new();

        for role in &self.dirty {
            if *role == MetadataPath::root() {
                let Some(root) = &self.current.root else {
                    continue;
                };
                writer.write_role(role, root)?;
                writer.archive_root(root)?;
                let version = root.payload().version();
                paths.extend([
                    payload_path(role),
                    signature_path(role),
                    crate::store::root_history_payload_path(version),
                    crate::store::root_history_signature_path(version),
                ]);
            } else if let Some(targets) = self.current.targets.get(role) {
                writer.write_role(role, targets)?;
                paths.extend([payload_path(role), signature_path(role)]);
            } else if writer.remove_role(role)? {
                paths.extend([payload_path(role), signature_path(role)]);
            }
        }

        if self.state_dirty && writer.write_event_state(&self.current.event)? {
            paths.push(crate::store::EVENT_STATE_PATH.to_owned());
        }

        paths.sort();
        paths.dedup();
        Ok(paths)
    }

    /// Whether this event has unwritten changes.
    pub fn is_dirty(&self) -> bool {
        !self.dirty.is_empty() || self.state_dirty
    }

    // -- editing helpers ----------------------------------------------------

    /// Apply `edit` to whichever role delegates to `role`, and bump it if it changed.
    fn edit_delegation(
        &mut self,
        role: &MetadataPath,
        edit: impl FnOnce(&mut DelegatorParts<'_>) -> Result<()>,
    ) -> Result<bool> {
        if policy::is_top_level(role) {
            self.edit_root(|root| edit(&mut DelegatorParts::Root(root)))
        } else {
            let targets_role = MetadataPath::targets();
            self.edit_targets(&targets_role, |targets| {
                edit(&mut DelegatorParts::Targets(targets))
            })
        }
    }

    /// Rebuild root with `edit` applied, bumping its version and expiry if it changed.
    ///
    /// The version is one past the *known-good* one rather than one past the current one,
    /// so that several changes within one signing event still produce a single new version.
    fn edit_root(&mut self, edit: impl FnOnce(&mut RootParts) -> Result<()>) -> Result<bool> {
        let role = MetadataPath::root();
        let signed = self.current.root()?;
        let mut parts = RootParts::of(signed.payload(), signed.policy());
        let (version, expires) = (parts.version, parts.expires);
        edit(&mut parts)?;

        // Compare at the current version and expiry, so that an edit which changes nothing
        // does not bump the version and throw away everyone's signatures.
        parts.version = version;
        parts.expires = expires;
        let unchanged = Signed::new(parts.clone().build()?)?;
        if unchanged.raw() == signed.raw() {
            return Ok(false);
        }

        parts.version = self.known_good.version_of(&role) + 1;
        parts.expires = parts.policy.periods(&role).expires_at(self.now);
        self.current.root = Some(Signed::new(parts.build()?)?);
        self.dirty.insert(role);
        Ok(true)
    }

    /// Rebuild a targets role with `edit` applied, bumping it if it changed.
    fn edit_targets(
        &mut self,
        role: &MetadataPath,
        edit: impl FnOnce(&mut TargetsParts) -> Result<()>,
    ) -> Result<bool> {
        let signed = self
            .current
            .targets
            .get(role)
            .ok_or_else(|| Error::NoSuchRole(role.to_string()))?;
        let mut parts = TargetsParts::of(signed.payload(), signed.policy());
        let (version, expires) = (parts.version, parts.expires);
        edit(&mut parts)?;

        parts.version = version;
        parts.expires = expires;
        let unchanged = Signed::new(parts.clone().build()?)?;
        if unchanged.raw() == signed.raw() {
            return Ok(false);
        }

        parts.version = self.known_good.version_of(role) + 1;
        parts.expires = self.periods_for(role).expires_at(self.now);
        self.current
            .targets
            .insert(role.clone(), Signed::new(parts.build()?)?);
        self.dirty.insert(role.clone());
        Ok(true)
    }

    /// The validity periods configured for `role`, or the defaults.
    fn periods_for(&self, role: &MetadataPath) -> Periods {
        self.current
            .delegator_of(role)
            .ok()
            .and_then(|delegator| delegator.role_spec(role).map(|spec| spec.periods))
            .unwrap_or(policy::DEFAULT_PERIODS)
    }

    /// Create empty metadata for a targets role that does not have any yet.
    fn ensure_targets_exists(&mut self, role: &MetadataPath) -> Result<bool> {
        if !policy::is_targets(role) || self.current.targets.contains_key(role) {
            return Ok(false);
        }
        let periods = self.periods_for(role);
        let mut parts = TargetsParts::empty(self.now, periods);
        parts.version = self.known_good.version_of(role) + 1;
        self.current
            .targets
            .insert(role.clone(), Signed::new(parts.build()?)?);
        self.dirty.insert(role.clone());
        Ok(true)
    }
}

/// Whether any component of `path` starts with a dot.
///
/// Dotfiles under `targets/` are housekeeping, not artifacts: a `.gitkeep` holding an
/// empty directory open, a `.gitignore`, a `.DS_Store` somebody's file manager left
/// behind. Signing those and publishing them to every client is never what was meant, and
/// the mistake is silent, so they are skipped. An artifact that genuinely has to be
/// published under a dotted name needs a role whose paths name it explicitly.
fn is_hidden(path: &str) -> bool {
    path.split('/').any(|component| component.starts_with('.'))
}

/// A delegating document being edited.
///
/// Root and a targets role's delegations differ in shape but answer the same two requests,
/// so the state machine makes them here rather than at every call site.
enum DelegatorParts<'a> {
    Root(&'a mut RootParts),
    Targets(&'a mut TargetsParts),
}

impl DelegatorParts<'_> {
    /// Permit `key` to sign `role`, at whatever threshold is already in force, and record
    /// who holds it.
    fn authorize(&mut self, role: &MetadataPath, key: PublicKey, owner: &str) -> Result<()> {
        let key_id = key.key_id().clone();
        match self {
            DelegatorParts::Root(root) => {
                root.role_mut(role)?.keyids.insert(key_id.clone());
                root.keys.insert(key_id.clone(), key);
                root.policy.signers.insert(key_id, owner.to_owned());
            }
            DelegatorParts::Targets(targets) => {
                targets.delegation_mut(role).keyids.insert(key_id.clone());
                targets.keys.insert(key_id.clone(), key);
                targets.policy.signers.insert(key_id, owner.to_owned());
            }
        }
        Ok(())
    }

    /// Permit an automated key to sign, and record where CI reaches it.
    ///
    /// The key is removed from the roster of people's keys if it was ever listed there. A
    /// key is one or the other: recorded as both, nothing can say whether the role it signs
    /// waits for a signing event or for the next publish.
    fn authorize_online(&mut self, key: PublicKey, uri: &str) {
        let key_id = key.key_id().clone();
        let (keys, policy) = match self {
            DelegatorParts::Root(root) => (&mut root.keys, &mut root.policy),
            DelegatorParts::Targets(targets) => (&mut targets.keys, &mut targets.policy),
        };
        keys.insert(key_id.clone(), key);
        policy.signers.remove(&key_id);
        policy.online.insert(key_id, uri.to_owned());
    }

    /// Set exactly who may sign `role`, how many of them are needed, and for how long.
    fn set_quorum(
        &mut self,
        role: &MetadataPath,
        keyids: BTreeSet<KeyId>,
        threshold: u32,
        periods: Periods,
    ) -> Result<()> {
        match self {
            DelegatorParts::Root(root) => {
                let entry = root.role_mut(role)?;
                entry.keyids = keyids;
                entry.threshold = threshold;
                root.policy.set_periods(role, periods);
            }
            DelegatorParts::Targets(targets) => {
                let entry = targets.delegation_mut(role);
                entry.keyids = keyids;
                entry.threshold = threshold;
                targets.policy.set_periods(role, periods);
            }
        }
        Ok(())
    }
}

fn quorum_of(delegator: &Delegator<'_>, role: &MetadataPath) -> Option<Quorum> {
    let spec = delegator.role_spec(role)?;
    let mut signers: Vec<String> = spec
        .keyids
        .iter()
        .map(|key_id| delegator.signer_name(key_id))
        .collect();
    signers.sort();
    Some(Quorum {
        signers,
        threshold: spec.threshold,
    })
}

/// Check that every key in a key set is filed under the id its own material gives it.
///
/// Two things go wrong when it is not. A client resolving a delegation fetches a key the
/// metadata did not intend; and, worse, one key filed under two names counts twice towards
/// a threshold, so a role needing two signatures can be satisfied by one person. The TUF
/// spec puts the second directly: when computing the threshold each key must only
/// contribute one signature.
fn check_key_ids(
    what: &str,
    keys: &std::collections::HashMap<KeyId, PublicKey>,
    problems: &mut Vec<String>,
) {
    let ordered: BTreeMap<&KeyId, &PublicKey> = keys.iter().collect();
    for (key_id, key) in ordered {
        match crypto::derived_key_id(key) {
            Ok(derived) if derived == *key_id => {}
            Ok(derived) => problems.push(format!(
                "{what} key {} does not match its own key material, which hashes to {}",
                crypto::abbreviated(key_id),
                crypto::abbreviated(&derived)
            )),
            Err(err) => problems.push(format!(
                "{what} key {} cannot be read: {err}",
                crypto::abbreviated(key_id)
            )),
        }
    }
}
