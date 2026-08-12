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

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Duration, Utc};

use crate::crypto::KeyId;
use crate::error::{Error, Result};
use crate::metadata::{Delegator, Key, Periods, RoleName, Root, TargetFile, Targets, path_matches};
use crate::signer::Signer;
use crate::store::{
    Invites, RepoState, Signed, Source, TARGETS_DIR, Tally, Writer, payload_path,
    root_history_payload_path, root_history_signature_path, signature_path,
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
    pub role: RoleName,
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
    pub role: RoleName,
}

/// Where one role stands in a signing event.
#[derive(Clone, Debug)]
pub struct RoleStatus {
    /// The role.
    pub role: RoleName,
    /// The version this event proposes.
    pub version: u64,
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
}

impl RoleStatus {
    /// Whether this role is fully signed, valid, and not waiting on an invitation.
    pub fn is_complete(&self) -> bool {
        self.problems.is_empty()
            && self.blocking_invites.is_empty()
            && self.tally.is_met()
            && self
                .previous_tally
                .as_ref()
                .is_none_or(|previous| previous.is_met())
    }

    /// How many more signatures this role needs.
    pub fn outstanding(&self) -> u32 {
        let previous = self
            .previous_tally
            .as_ref()
            .map_or(0, |tally| tally.outstanding());
        self.tally.outstanding().max(previous)
    }

    /// Everyone whose signature is still wanted.
    pub fn waiting_on(&self) -> Vec<&str> {
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
    /// Problems with the event as a whole rather than with any one role.
    pub problems: Vec<String>,
}

impl EventStatus {
    /// Whether every changed role is signed and valid, so the event can be merged.
    pub fn is_mergeable(&self) -> bool {
        self.problems.is_empty()
            && !self.roles.is_empty()
            && self.roles.iter().all(RoleStatus::is_complete)
    }

    /// How many signatures the event is still short of, across all roles.
    pub fn outstanding(&self) -> u32 {
        self.roles.iter().map(RoleStatus::outstanding).sum()
    }

    /// Every open invitation in the event.
    pub fn invitations(&self) -> Vec<&Invitation> {
        let mut invitations: Vec<&Invitation> = self
            .roles
            .iter()
            .flat_map(|role| &role.blocking_invites)
            .collect();
        invitations.sort_by(|a, b| (&a.user, &a.role).cmp(&(&b.user, &b.role)));
        invitations.dedup();
        invitations
    }
}

/// What one signer has to do about a signing event.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SignerTasks {
    /// Roles the signer has been invited to and must contribute a key for.
    pub accept: Vec<RoleName>,
    /// Roles that are waiting on this signer's signature.
    pub sign: Vec<RoleName>,
}

impl SignerTasks {
    /// Whether this signer has nothing to do.
    pub fn is_empty(&self) -> bool {
        self.accept.is_empty() && self.sign.is_empty()
    }
}

/// Who may sign a role, how many of them are needed, and for how long the result is good.
#[derive(Clone, Debug, PartialEq, Eq)]
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
    pub fn validate(&self, role: &RoleName) -> Result<()> {
        if self.signers.is_empty() {
            return Err(Error::invalid(format!(
                "{role} must have at least one signer"
            )));
        }
        let unique: BTreeSet<&String> = self.signers.iter().collect();
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
// The event itself
// ---------------------------------------------------------------------------

/// A signing event: a proposed repository state, judged against the state it branched from.
pub struct SigningEvent {
    known_good: RepoState,
    current: RepoState,
    now: DateTime<Utc>,
    dirty: BTreeSet<RoleName>,
    invites_dirty: bool,
}

impl SigningEvent {
    /// Load an event from the state it branched from and the state it proposes.
    pub fn load(known_good: &dyn Source, current: &dyn Source) -> Result<Self> {
        Ok(SigningEvent {
            known_good: RepoState::load(known_good)?,
            current: RepoState::load(current)?,
            now: Utc::now(),
            dirty: BTreeSet::new(),
            invites_dirty: false,
        })
    }

    /// Build an event from two already-loaded states.
    pub fn from_states(known_good: RepoState, current: RepoState) -> Self {
        SigningEvent {
            known_good,
            current,
            now: Utc::now(),
            dirty: BTreeSet::new(),
            invites_dirty: false,
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

    /// The open invitations.
    pub fn invites(&self) -> &Invites {
        &self.current.invites
    }

    /// Whether the repository exists yet.
    pub fn is_initialized(&self) -> bool {
        self.current.is_initialized()
    }

    // -- change detection ---------------------------------------------------

    /// Roles whose metadata this event changes, delegators before their delegates.
    pub fn changed_roles(&self) -> Vec<RoleName> {
        self.current
            .role_names()
            .into_iter()
            .filter(|role| self.role_changed(role))
            .collect()
    }

    fn role_changed(&self, role: &RoleName) -> bool {
        let current = self.raw_payload(&self.current, role);
        let known_good = self.raw_payload(&self.known_good, role);
        match (current, known_good) {
            (Some(current), Some(known_good)) => current != known_good,
            (Some(_), None) => true,
            (None, _) => false,
        }
    }

    fn raw_payload<'a>(&self, state: &'a RepoState, role: &RoleName) -> Option<&'a [u8]> {
        if *role == RoleName::root() {
            return state.root.as_ref().map(Signed::raw);
        }
        state.targets.get(role).map(Signed::raw)
    }

    /// Roles that this event changes and that need `user`'s attention.
    pub fn tasks_for(&self, user: &str) -> SignerTasks {
        let mut tasks = SignerTasks {
            accept: self.current.invites.for_user(user).to_vec(),
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
    fn eligible_key_ids(&self, role: &RoleName, user: &str) -> Vec<KeyId> {
        let mut key_ids = BTreeSet::new();
        for delegator in self.delegators_of(role) {
            for (key_id, key) in delegator.keys_for(role) {
                if key.owner.as_deref() == Some(user) {
                    key_ids.insert(key_id);
                }
            }
        }
        key_ids.into_iter().collect()
    }

    /// The delegators whose opinion of `role` matters: the current one, plus for root the
    /// previous one.
    fn delegators_of(&self, role: &RoleName) -> Vec<Delegator> {
        let mut delegators = Vec::new();
        if let Ok(delegator) = self.current.delegator_of(role) {
            delegators.push(delegator);
        }
        if *role == RoleName::root()
            && let Some(previous) = &self.known_good.root
        {
            delegators.push(previous.delegator());
        }
        delegators
    }

    fn has_valid_signature_from(&self, role: &RoleName, user: &str) -> bool {
        let Some(signed) = self.current.targets.get(role) else {
            return match (&self.current.root, *role == RoleName::root()) {
                (Some(root), true) => self
                    .delegators_of(role)
                    .iter()
                    .flat_map(|delegator| root.tally(delegator, role).signed)
                    .any(|who| who.name == user),
                _ => false,
            };
        };
        self.delegators_of(role)
            .iter()
            .flat_map(|delegator| signed.tally(delegator, role).signed)
            .any(|who| who.name == user)
    }

    /// Invitations that block `role` from being signed.
    ///
    /// Accepting an invitation adds a key to the delegating role's metadata, so any role
    /// with an outstanding invitation to one of its delegates is still in flux.
    pub fn blocking_invites(&self, role: &RoleName) -> Vec<Invitation> {
        let Some(delegator) = self.delegator_view(&self.current, role) else {
            return Vec::new();
        };
        let mut invitations = Vec::new();
        for delegated in delegator.delegated_roles() {
            for user in self.current.invites.for_role(&delegated) {
                invitations.push(Invitation {
                    user: user.to_owned(),
                    role: delegated.clone(),
                });
            }
        }
        invitations.sort_by(|a, b| (&a.user, &a.role).cmp(&(&b.user, &b.role)));
        invitations
    }

    /// `role` seen as a delegator of other roles, if it is one.
    fn delegator_view(&self, state: &RepoState, role: &RoleName) -> Option<Delegator> {
        if *role == RoleName::root() {
            return state.root.as_ref().map(Signed::<Root>::delegator);
        }
        state.targets.get(role).map(Signed::<Targets>::delegator)
    }

    // -- status -------------------------------------------------------------

    /// Where the event stands.
    pub fn status(&self) -> EventStatus {
        let mut problems = Vec::new();

        // Online metadata is re-signed on every publish with a key CI holds. A signing
        // event that changes it either has a stale checkout or is trying something it
        // should not, and either way the change cannot be signed here.
        for role in [RoleName::snapshot(), RoleName::timestamp()] {
            let current = match role.as_str() {
                "snapshot" => self.current.snapshot.as_ref().map(Signed::raw),
                _ => self.current.timestamp.as_ref().map(Signed::raw),
            };
            let known_good = match role.as_str() {
                "snapshot" => self.known_good.snapshot.as_ref().map(Signed::raw),
                _ => self.known_good.timestamp.as_ref().map(Signed::raw),
            };
            if known_good.is_some() && current != known_good {
                problems.push(format!(
                    "{role} metadata is signed online and must not be changed in a signing event"
                ));
            }
        }

        let roles = self
            .changed_roles()
            .into_iter()
            .map(|role| self.role_status(&role))
            .collect();

        EventStatus { roles, problems }
    }

    /// Where one role stands.
    pub fn role_status(&self, role: &RoleName) -> RoleStatus {
        let mut problems = Vec::new();

        let (version, tally, previous_tally) = match self.current.delegator_of(role) {
            Err(err) => {
                problems.push(err.to_string());
                (0, Tally::empty(role.clone()), None)
            }
            Ok(delegator) => {
                let (version, tally) = if *role == RoleName::root() {
                    match &self.current.root {
                        Some(root) => (root.payload().version, root.tally(&delegator, role)),
                        None => (0, Tally::empty(role.clone())),
                    }
                } else {
                    match self.current.targets.get(role) {
                        Some(targets) => {
                            (targets.payload().version, targets.tally(&delegator, role))
                        }
                        None => (0, Tally::empty(role.clone())),
                    }
                };

                // A new root must also satisfy the root it replaces.
                let previous_tally = match (*role == RoleName::root(), &self.current.root) {
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
            blocking_invites: self.blocking_invites(role),
            artifacts: self.artifact_changes(role),
            delegations: self.delegation_changes(role),
            problems,
        }
    }

    /// Artifact changes `role` vouches for in this event.
    pub fn artifact_changes(&self, role: &RoleName) -> Vec<ArtifactChange> {
        let current = self.artifacts_of(&self.current, role);
        let previous = self.artifacts_of(&self.known_good, role);

        let mut changes = Vec::new();
        for (path, target) in &current {
            match previous.get(path) {
                None => changes.push(ArtifactChange::Added((*path).clone())),
                Some(before) if before != target => {
                    changes.push(ArtifactChange::Modified((*path).clone()));
                }
                Some(_) => {}
            }
        }
        for path in previous.keys() {
            if !current.contains_key(path) {
                changes.push(ArtifactChange::Removed((*path).clone()));
            }
        }
        changes.sort_by(|a, b| a.path().cmp(b.path()));
        changes
    }

    fn artifacts_of<'a>(
        &self,
        state: &'a RepoState,
        role: &RoleName,
    ) -> BTreeMap<&'a String, &'a TargetFile> {
        state
            .targets
            .get(role)
            .map(|signed| signed.payload().targets.iter().collect())
            .unwrap_or_default()
    }

    /// Delegation changes `role` makes in this event.
    pub fn delegation_changes(&self, role: &RoleName) -> Vec<DelegationChange> {
        let current = self.delegator_view(&self.current, role);
        let previous = self.delegator_view(&self.known_good, role);

        let mut names: BTreeSet<RoleName> = BTreeSet::new();
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
    fn validate(&self, role: &RoleName) -> Vec<String> {
        let mut problems = Vec::new();

        let (version, expires) = match self.payload_facts(role) {
            Some(facts) => facts,
            None => return problems,
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
            if let Some(spec) = delegator.role_spec(role) {
                if let Err(err) = spec.periods.validate(role) {
                    problems.push(err.to_string());
                }
                let latest = spec.periods.expires_at(self.now) + EXPIRY_TOLERANCE;
                if expires > latest {
                    problems.push(format!(
                        "{role} expires {expires}, further ahead than its {} day expiry period \
                         allows",
                        spec.periods.expiry_days
                    ));
                }
                if spec.threshold as usize > spec.keyids.len() {
                    problems.push(format!(
                        "{role} needs {} signatures but only {} keys may sign it",
                        spec.threshold,
                        spec.keyids.len()
                    ));
                }
                for key_id in spec.keyids {
                    if delegator.key(key_id).is_none() {
                        problems.push(format!(
                            "{role} may be signed by key {}, which the delegating role does not \
                             hold",
                            key_id.abbreviated()
                        ));
                    }
                }
            } else {
                problems.push(format!("nothing delegates to {role}"));
            }

            // Offline roles are signed by people, online roles by automation. A key with
            // neither marking cannot be attributed to either.
            for (key_id, key) in delegator.keys_for(role) {
                match (role.is_online(), &key.owner, &key.online_uri) {
                    (false, None, _) => problems.push(format!(
                        "{role} key {} has no owner, so nobody can be asked to sign with it",
                        key_id.abbreviated()
                    )),
                    (true, _, None) => problems.push(format!(
                        "{role} is signed online but key {} has no signing URI",
                        key_id.abbreviated()
                    )),
                    _ => {}
                }
            }
        }

        if *role == RoleName::root() {
            problems.extend(self.validate_root());
        }

        // Only the top-level targets role delegates. Allowing delegates to delegate would
        // make the artifact-to-role mapping depend on a tree walk rather than on the path.
        if role.is_targets()
            && *role != RoleName::targets()
            && let Some(targets) = self.current.targets.get(role)
            && targets
                .payload()
                .delegations
                .as_ref()
                .is_some_and(|d| !d.roles.is_empty())
        {
            problems.push(format!(
                "{role} is a delegated role and may not delegate further"
            ));
        }

        problems
    }

    fn validate_root(&self) -> Vec<String> {
        let mut problems = Vec::new();
        let Some(root) = &self.current.root else {
            return problems;
        };
        let root = root.payload();

        if !root.consistent_snapshot {
            problems.push(
                "root disables consistent snapshots, which this repository always uses".into(),
            );
        }

        // Snapshot and timestamp are produced together by the same automated signer, so a
        // configuration where one could be signed without the other is a mistake.
        match (
            root.roles.get(&RoleName::snapshot()),
            root.roles.get(&RoleName::timestamp()),
        ) {
            (Some(snapshot), Some(timestamp)) => {
                if snapshot.keyids != timestamp.keyids || snapshot.threshold != timestamp.threshold
                {
                    problems.push(
                        "snapshot and timestamp must be signed by the same keys, since both are \
                         produced by the same online signer"
                            .into(),
                    );
                }
            }
            _ => problems.push("root must delegate to both snapshot and timestamp".into()),
        }

        // Root is the only place these delegations are stated, and a signing event that
        // touches root is the only chance to catch them being unsatisfiable. Checking all
        // four here rather than only the role being signed means an event that leaves, say,
        // the online roles keyless cannot be merged.
        for role in [
            RoleName::root(),
            RoleName::targets(),
            RoleName::snapshot(),
            RoleName::timestamp(),
        ] {
            let Some(entry) = root.roles.get(&role) else {
                problems.push(format!("root must delegate to {role}"));
                continue;
            };
            if entry.threshold as usize > entry.keyids.len() {
                problems.push(format!(
                    "{role} needs {} signatures but root gives it only {} key(s)",
                    entry.threshold,
                    entry.keyids.len()
                ));
            }
        }

        // Every key id must name the key it is filed under, or a client resolving a
        // delegation would fetch a key the metadata did not intend.
        for (key_id, key) in &root.keys {
            match KeyId::for_pem(&key.keyval.public) {
                Ok(derived) if derived == *key_id => {}
                Ok(derived) => problems.push(format!(
                    "root key {} does not match its own key material, which hashes to {}",
                    key_id.abbreviated(),
                    derived.abbreviated()
                )),
                Err(err) => problems.push(format!(
                    "root key {} cannot be read: {err}",
                    key_id.abbreviated()
                )),
            }
        }

        problems
    }

    fn payload_facts(&self, role: &RoleName) -> Option<(u64, DateTime<Utc>)> {
        if *role == RoleName::root() {
            let root = self.current.root.as_ref()?;
            return Some((root.payload().version, root.payload().expires));
        }
        let targets = self.current.targets.get(role)?;
        Some((targets.payload().version, targets.payload().expires))
    }

    // -- mutation -----------------------------------------------------------

    /// Create the root and top-level targets metadata for a new repository.
    ///
    /// Neither has any keys yet; those come from [`configure_role`](Self::configure_role).
    pub fn initialize(&mut self, periods: Periods) -> Result<()> {
        if self.current.is_initialized() {
            return Err(Error::invalid("this repository already has root metadata"));
        }
        self.current.root = Some(Signed::new(Root::empty(self.now, periods))?);
        self.current
            .targets
            .insert(RoleName::targets(), Signed::new(Targets::empty(self.now))?);
        self.touch(&RoleName::root())?;
        self.touch(&RoleName::targets())?;
        Ok(())
    }

    /// Set who may sign `role`, how many of them are needed, and for how long.
    ///
    /// Signers who do not yet have a key are invited rather than added: their key material
    /// only enters the repository when they run the signing tool themselves. Signers no
    /// longer listed have their keys revoked.
    ///
    /// Returns whether anything changed.
    pub fn configure_role(&mut self, role: &RoleName, config: &RoleConfig) -> Result<bool> {
        if role.is_online() {
            return Err(Error::invalid(format!(
                "{role} is signed online; configure it with the online key instead"
            )));
        }
        config.validate(role)?;

        let mut invites = self.current.invites.clone();
        invites.remove_role(role);

        // Who already has a key for this role, and which keys have to go.
        let existing: Vec<(KeyId, String)> = self
            .current
            .delegator_of(role)
            .map(|delegator| {
                delegator
                    .keys_for(role)
                    .into_iter()
                    .filter_map(|(key_id, key)| key.owner.clone().map(|owner| (key_id, owner)))
                    .collect()
            })
            .unwrap_or_default();

        let keep: Vec<&KeyId> = existing
            .iter()
            .filter(|(_, owner)| config.signers.contains(owner))
            .map(|(key_id, _)| key_id)
            .collect();
        let revoke: Vec<KeyId> = existing
            .iter()
            .filter(|(key_id, _)| !keep.contains(&key_id))
            .map(|(key_id, _)| key_id.clone())
            .collect();

        for signer in &config.signers {
            let has_key = existing
                .iter()
                .any(|(key_id, owner)| owner == signer && keep.contains(&key_id));
            if !has_key {
                invites.add(signer, role);
            }
        }

        let changed = self.edit_delegation(role, config.periods, |delegator| {
            for key_id in &revoke {
                match delegator {
                    DelegatorMut::Root(root) => root.revoke(role, key_id),
                    DelegatorMut::Targets(targets) => targets.revoke(role, key_id),
                }
            }
            match delegator {
                DelegatorMut::Root(root) => {
                    let entry = root.roles.get_mut(role).expect("role exists");
                    entry.threshold = config.threshold;
                    entry.expiry_days = config.periods.expiry_days;
                    entry.signing_days = config.periods.signing_days;
                }
                DelegatorMut::Targets(targets) => {
                    let entry = targets.delegation_mut(role, config.periods);
                    entry.threshold = config.threshold;
                    entry.expiry_days = config.periods.expiry_days;
                    entry.signing_days = config.periods.signing_days;
                }
            }
        })?;

        // A targets role needs a document of its own to sign, even before it has any
        // artifacts in it.
        let created = self.ensure_targets_exists(role)?;

        let invites_changed = invites != self.current.invites;
        if invites_changed {
            self.current.invites = invites;
            self.invites_dirty = true;
        }

        // Report what *this* call changed. `invites_dirty` accumulates across the whole
        // event, so reporting it here would make every configuration after the first look
        // like a change even when it repeated the existing one exactly.
        Ok(changed || created || invites_changed)
    }

    /// Set the key and periods for the online roles.
    ///
    /// Snapshot and timestamp are always configured together and always with the same key,
    /// because one automated signer produces both: allowing them to differ would let a
    /// repository publish a timestamp for a snapshot nobody could have signed.
    ///
    /// Returns whether anything changed.
    pub fn configure_online(
        &mut self,
        key: Key,
        timestamp: Periods,
        snapshot: Periods,
    ) -> Result<bool> {
        if key.online_uri.is_none() {
            return Err(Error::invalid(
                "an online key needs a signing URI for CI to reach it",
            ));
        }
        timestamp.validate(&RoleName::timestamp())?;
        snapshot.validate(&RoleName::snapshot())?;
        let key_id = KeyId::for_pem(&key.keyval.public)?;

        let signed = self
            .current
            .root
            .as_ref()
            .ok_or_else(|| Error::invalid("this repository has no root metadata yet"))?;
        let mut payload = signed.payload().clone();

        for (role, periods) in [
            (RoleName::timestamp(), timestamp),
            (RoleName::snapshot(), snapshot),
        ] {
            let entry = payload
                .roles
                .get_mut(&role)
                .ok_or_else(|| Error::NoSuchRole(role.to_string()))?;
            entry.keyids = vec![key_id.clone()];
            entry.threshold = 1;
            entry.expiry_days = periods.expiry_days;
            entry.signing_days = periods.signing_days;
        }
        payload.keys.insert(key_id, key);
        payload.collect_unused_keys();

        self.replace_root(payload)
    }

    /// Contribute `user`'s key in response to an invitation.
    ///
    /// Returns whether anything changed.
    pub fn accept_invite(&mut self, role: &RoleName, user: &str, key: Key) -> Result<bool> {
        if !self.current.invites.for_user(user).contains(role) {
            return Err(Error::invalid(format!(
                "{user} has not been invited to sign {role}"
            )));
        }
        let owner = key.owner.as_deref().unwrap_or_default();
        if owner != user {
            return Err(Error::invalid(format!(
                "key is marked as belonging to {owner:?}, but is being contributed by {user:?}"
            )));
        }
        let key_id = KeyId::for_pem(&key.keyval.public)?;

        let periods = self
            .current
            .delegator_of(role)?
            .role_spec(role)
            .map(|spec| spec.periods)
            .ok_or_else(|| Error::NoSuchRole(role.to_string()))?;

        self.edit_delegation(role, periods, |delegator| match delegator {
            DelegatorMut::Root(root) => {
                let _ = root.authorize(role, key_id.clone(), key.clone());
            }
            DelegatorMut::Targets(targets) => {
                let _ = targets.authorize(role, key_id.clone(), key.clone(), periods);
            }
        })?;

        self.current.invites.remove(user, role);
        self.invites_dirty = true;
        Ok(true)
    }

    /// Remove a delegation to `role` and delete its metadata.
    ///
    /// Returns whether there was a delegation to remove.
    pub fn revoke_delegation(&mut self, role: &RoleName) -> Result<bool> {
        if role.is_top_level() {
            return Err(Error::invalid(format!(
                "{role} is a top-level role and cannot be removed"
            )));
        }

        let targets_role = RoleName::targets();
        let Some(signed) = self.current.targets.get(&targets_role) else {
            return Ok(false);
        };
        let mut payload = signed.payload().clone();
        if !payload.remove_delegation(role) {
            return Ok(false);
        }

        self.replace_targets(&targets_role, payload)?;
        self.current.targets.remove(role);
        self.current.invites.remove_role(role);
        self.invites_dirty = true;
        self.dirty.insert(role.clone());
        Ok(true)
    }

    /// Rebuild every targets role's artifact list from the files in `targets/`.
    ///
    /// Returns the roles whose metadata changed. This is what turns a commit that adds a
    /// file under `targets/` into a signable metadata change.
    pub fn update_targets(&mut self, artifacts: &dyn Source) -> Result<Vec<RoleName>> {
        let paths = artifacts.list(TARGETS_DIR)?;
        let mut updated = Vec::new();

        for role in self.current.targets.keys().cloned().collect::<Vec<_>>() {
            let patterns = self.artifact_patterns(&role);
            let mut targets = BTreeMap::new();

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
                    .any(|pattern| path_matches(pattern, relative))
                {
                    continue;
                }
                let Some(bytes) = artifacts.read(path)? else {
                    continue;
                };
                let mut target = TargetFile::from_bytes(&bytes);
                // Application-defined data on an artifact is not derived from its bytes,
                // so carry it across rather than dropping it on every rebuild.
                if let Some(existing) = self
                    .current
                    .targets
                    .get(&role)
                    .and_then(|signed| signed.payload().targets.get(relative))
                {
                    target.custom = existing.custom.clone();
                    target.extra = existing.extra.clone();
                }
                targets.insert(relative.to_owned(), target);
            }

            let signed = self.current.targets.get(&role).expect("iterating its keys");
            if signed.payload().targets == targets {
                continue;
            }
            let mut payload = signed.payload().clone();
            payload.targets = targets;
            self.replace_targets(&role, payload)?;
            updated.push(role);
        }

        Ok(updated)
    }

    /// The artifact path patterns `role` is responsible for.
    fn artifact_patterns(&self, role: &RoleName) -> Vec<String> {
        if *role == RoleName::targets() {
            // The top-level role owns files sitting directly in `targets/`; everything in
            // a subdirectory belongs to the role of the same name.
            return vec!["*".to_owned()];
        }
        self.current
            .targets
            .get(&RoleName::targets())
            .and_then(|signed| signed.payload().delegation(role).cloned())
            .map(|delegated| delegated.paths)
            .unwrap_or_default()
    }

    /// Sign `role` with `signer`.
    pub fn sign(&mut self, role: &RoleName, signer: &mut dyn Signer) -> Result<()> {
        let permitted = self.delegators_of(role).iter().any(|delegator| {
            delegator
                .keys_for(role)
                .iter()
                .any(|(key_id, _)| key_id == signer.key_id())
        });
        if !permitted {
            return Err(Error::invalid(format!(
                "key {} is not permitted to sign {role}",
                signer.key_id().abbreviated()
            )));
        }

        if *role == RoleName::root() {
            let root = self
                .current
                .root
                .as_mut()
                .ok_or_else(|| Error::NoSuchRole(role.to_string()))?;
            root.sign_with(signer)?;
        } else {
            let targets = self
                .current
                .targets
                .get_mut(role)
                .ok_or_else(|| Error::NoSuchRole(role.to_string()))?;
            targets.sign_with(signer)?;
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
            if *role == RoleName::root() {
                let Some(root) = &self.current.root else {
                    continue;
                };
                writer.write_role(role, root)?;
                let version = root.payload().version;
                paths.extend([
                    payload_path(role),
                    signature_path(role),
                    root_history_payload_path(version),
                    root_history_signature_path(version),
                ]);
            } else if let Some(targets) = self.current.targets.get(role) {
                writer.write_role(role, targets)?;
                paths.extend([payload_path(role), signature_path(role)]);
            } else if writer.remove_role(role)? {
                paths.extend([payload_path(role), signature_path(role)]);
            }
        }

        if self.invites_dirty && writer.write_invites(&self.current.invites)? {
            paths.push(crate::store::EVENT_STATE_PATH.to_owned());
        }

        paths.sort();
        paths.dedup();
        Ok(paths)
    }

    /// Whether this event has unwritten changes.
    pub fn is_dirty(&self) -> bool {
        !self.dirty.is_empty() || self.invites_dirty
    }

    // -- editing helpers ----------------------------------------------------

    /// Apply `edit` to whichever role delegates to `role`, and bump it if it changed.
    fn edit_delegation(
        &mut self,
        role: &RoleName,
        periods: Periods,
        edit: impl FnOnce(&mut DelegatorMut<'_>),
    ) -> Result<bool> {
        if role.is_top_level() {
            let signed = self
                .current
                .root
                .as_ref()
                .ok_or_else(|| Error::invalid("this repository has no root metadata yet"))?;
            let mut payload = signed.payload().clone();
            edit(&mut DelegatorMut::Root(&mut payload));
            self.replace_root(payload)
        } else {
            let targets_role = RoleName::targets();
            let signed = self
                .current
                .targets
                .get(&targets_role)
                .ok_or_else(|| Error::NoSuchRole(targets_role.to_string()))?;
            let mut payload = signed.payload().clone();
            edit(&mut DelegatorMut::Targets(&mut payload));
            let _ = periods;
            self.replace_targets(&targets_role, payload)
        }
    }

    fn replace_root(&mut self, mut payload: Root) -> Result<bool> {
        let role = RoleName::root();
        let signed = self
            .current
            .root
            .as_ref()
            .ok_or_else(|| Error::invalid("this repository has no root metadata yet"))?;

        // Compare at the current version and expiry, so that an edit which changes nothing
        // does not bump the version and throw away everyone's signatures.
        payload.version = signed.payload().version;
        payload.expires = signed.payload().expires;
        if payload == *signed.payload() {
            return Ok(false);
        }

        let mut signed = signed.clone();
        signed.set_payload(payload)?;
        self.current.root = Some(signed);
        self.touch(&role)?;
        Ok(true)
    }

    fn replace_targets(&mut self, role: &RoleName, mut payload: Targets) -> Result<bool> {
        let signed = self
            .current
            .targets
            .get(role)
            .ok_or_else(|| Error::NoSuchRole(role.to_string()))?;

        payload.version = signed.payload().version;
        payload.expires = signed.payload().expires;
        if payload == *signed.payload() {
            return Ok(false);
        }

        let mut signed = signed.clone();
        signed.set_payload(payload)?;
        self.current.targets.insert(role.clone(), signed);
        self.touch(role)?;
        Ok(true)
    }

    /// Give `role` the version and expiry a freshly changed role should have.
    ///
    /// The version is one past the known-good one rather than one past the current one, so
    /// that several changes within one signing event still produce a single new version.
    fn touch(&mut self, role: &RoleName) -> Result<()> {
        let version = self.known_good.version_of(role) + 1;
        let periods = self.periods_for(role);
        let expires = periods.expires_at(self.now);

        if *role == RoleName::root() {
            let signed = self
                .current
                .root
                .as_mut()
                .ok_or_else(|| Error::invalid("this repository has no root metadata yet"))?;
            let mut payload = signed.payload().clone();
            payload.version = version;
            payload.expires = expires;
            signed.set_payload(payload)?;
        } else {
            let signed = self
                .current
                .targets
                .get_mut(role)
                .ok_or_else(|| Error::NoSuchRole(role.to_string()))?;
            let mut payload = signed.payload().clone();
            payload.version = version;
            payload.expires = expires;
            signed.set_payload(payload)?;
        }

        self.dirty.insert(role.clone());
        Ok(())
    }

    /// The validity periods configured for `role`, falling back to a year if the
    /// delegation does not exist yet.
    fn periods_for(&self, role: &RoleName) -> Periods {
        self.current
            .delegator_of(role)
            .ok()
            .and_then(|delegator| delegator.role_spec(role).map(|spec| spec.periods))
            .unwrap_or(Periods {
                expiry_days: 365,
                signing_days: 60,
            })
    }

    /// Create empty metadata for a targets role that does not have any yet.
    fn ensure_targets_exists(&mut self, role: &RoleName) -> Result<bool> {
        if !role.is_targets() || self.current.targets.contains_key(role) {
            return Ok(false);
        }
        self.current
            .targets
            .insert(role.clone(), Signed::new(Targets::empty(self.now))?);
        self.touch(role)?;
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

/// A delegating payload being edited in place.
enum DelegatorMut<'a> {
    Root(&'a mut Root),
    Targets(&'a mut Targets),
}

fn quorum_of(delegator: &Delegator, role: &RoleName) -> Option<Quorum> {
    let spec = delegator.role_spec(role)?;
    let mut signers: Vec<String> = spec
        .keyids
        .iter()
        .map(|key_id| match delegator.key(key_id) {
            Some(key) => key.signer_name().to_owned(),
            None => format!("<unknown key {}>", key_id.abbreviated()),
        })
        .collect();
    signers.sort();
    Some(Quorum {
        signers,
        threshold: spec.threshold,
    })
}
