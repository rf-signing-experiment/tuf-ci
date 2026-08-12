//! Turning a git repository and a branch name into a signing event, and turning the
//! result back into a commit.
//!
//! Reading a signing event needs no checkout at all: both the branch and the commit it
//! branched from are read straight out of git's object store. A working tree is only
//! created when something is going to be written, and then it is a throwaway worktree
//! rather than the signer's own.

use anyhow::{Context, Result, bail};
use tuf_repo::event::SigningEvent;
use tuf_repo::store::{EmptySource, FsSource, GitSource, RepoState, Writer};

use crate::config::Config;
use crate::git::{Git, Worktree};

/// The branch prefix that marks a signing event.
pub const EVENT_PREFIX: &str = "sign/";

/// The branch signing events are merged into.
pub const MAIN_BRANCH: &str = "main";

/// A repository, and the settings of the person working on it.
pub struct Session {
    /// The git repository.
    pub git: Git,
    /// The signer's settings.
    pub config: Config,
}

/// Where a signing event's two ends live in git.
#[derive(Clone, Debug)]
pub struct EventRefs {
    /// The event's branch name, e.g. `sign/add-crates`.
    pub name: String,
    /// The revision holding the event's proposed state.
    ///
    /// The main branch, for an event that has not been pushed yet.
    pub head: String,
    /// The revision the event branched from, or `None` before the repository has any
    /// commits at all.
    pub base: Option<String>,
}

impl Session {
    /// Open the repository containing the current directory.
    pub fn open(config: Config) -> Result<Self> {
        Ok(Session {
            git: Git::discover()?,
            config,
        })
    }

    /// The remote-tracking ref for a branch on the pull remote.
    fn remote_ref(&self, branch: &str) -> String {
        format!("refs/remotes/{}/{branch}", self.config.git.pull_remote)
    }

    /// Fetch the pull remote, so that everything below sees current state.
    pub fn fetch(&self) -> Result<()> {
        self.git.fetch(&self.config.git.pull_remote)
    }

    /// Locate a signing event's branch and the commit it branched from.
    ///
    /// An event that does not exist on the remote is not an error: it is a new event, and
    /// it starts from the main branch.
    pub fn locate(&self, name: &str) -> Result<EventRefs> {
        let name = normalize_event_name(name)?;
        let main = self.remote_ref(MAIN_BRANCH);
        let event = self.remote_ref(&name);

        let main_exists = self.git.rev_exists(&main);

        let head = match (self.git.rev_exists(&event), main_exists) {
            (true, _) => self.git.rev_parse(&event)?,
            (false, true) => self.git.rev_parse(&main)?,
            (false, false) => bail!(
                "neither {name} nor {MAIN_BRANCH} exists on {}. Push an initial commit first",
                self.config.git.pull_remote
            ),
        };

        let base = if main_exists {
            Some(self.git.merge_base(&main, &head)?)
        } else {
            // The repository has no main branch yet, so this event is creating one.
            None
        };

        Ok(EventRefs { name, head, base })
    }

    /// Every signing event branch on the pull remote.
    pub fn list_events(&self) -> Result<Vec<String>> {
        let mut branches = self.git.remote_branches(
            &self.config.git.pull_remote,
            &format!("refs/heads/{EVENT_PREFIX}*"),
        )?;
        branches.sort();
        Ok(branches)
    }

    /// Read a signing event without checking anything out.
    pub fn read(&self, refs: &EventRefs) -> Result<SigningEvent> {
        let head = GitSource::new(self.git.root(), &refs.head);
        let current = RepoState::load(&head).context("reading the signing event branch")?;
        let known_good = match &refs.base {
            Some(base) => {
                let source = GitSource::new(self.git.root(), base);
                RepoState::load(&source).context("reading the commit this event branched from")?
            }
            None => RepoState::load(&EmptySource)?,
        };
        Ok(SigningEvent::from_states(known_good, current))
    }

    /// Check the event out into a throwaway worktree, ready to be modified.
    pub fn check_out(&self, refs: &EventRefs) -> Result<Checkout> {
        let worktree = self.git.worktree(&refs.head)?;
        let known_good = match &refs.base {
            Some(base) => {
                let source = GitSource::new(self.git.root(), base);
                RepoState::load(&source).context("reading the commit this event branched from")?
            }
            None => RepoState::load(&EmptySource)?,
        };
        let current = RepoState::load(&FsSource::new(worktree.path()))
            .context("reading the signing event branch")?;

        Ok(Checkout {
            event: SigningEvent::from_states(known_good, current),
            worktree,
        })
    }
}

/// A signing event checked out where it can be written to.
pub struct Checkout {
    /// The event's state.
    pub event: SigningEvent,
    worktree: Worktree,
}

impl Checkout {
    /// Write the event's changes and commit them.
    ///
    /// Returns `false` if there was nothing to commit.
    pub fn commit(&mut self, message: &str) -> Result<bool> {
        if !self.event.is_dirty() {
            return Ok(false);
        }

        let writer = Writer::new(self.worktree.path());
        let paths = self
            .event
            .persist(&writer)
            .context("writing the updated metadata")?;

        let git = self.worktree.git();
        let mut add = vec!["add".to_owned(), "--".to_owned()];
        add.extend(paths);
        git.run(&add).context("staging the updated metadata")?;

        if git.succeeds(&["diff", "--cached", "--quiet"]) {
            // The files were rewritten byte for byte; there is nothing to record.
            return Ok(false);
        }

        git.run(&["commit", "--signoff", "--message", message])
            .context("committing the updated metadata")?;
        Ok(true)
    }

    /// Whether this branch carries a workflow that would report on the signing event.
    ///
    /// A `push` event runs the workflow as it exists in the pushed commit, so a branch
    /// that took its history from a base branch without one will silently do nothing in
    /// CI. That is invisible from the signer's side — the push succeeds either way — so it
    /// is worth saying out loud.
    pub fn has_signing_event_workflow(&self) -> bool {
        let Ok(listing) = self.worktree.git().run(&[
            "ls-tree",
            "-r",
            "--name-only",
            "HEAD",
            "--",
            ".github/workflows",
        ]) else {
            return true; // Cannot tell; do not cry wolf.
        };
        listing
            .lines()
            .any(|path| path.ends_with(".yml") || path.ends_with(".yaml"))
    }

    /// Push the event branch, to `remote` under `branch`.
    pub fn push(&self, remote: &str, branch: &str, force: bool) -> Result<()> {
        let refspec = format!("HEAD:refs/heads/{branch}");
        let mut args = vec!["push"];
        if force {
            // Only ever used when pushing to the signer's own fork, where the previous
            // contents are either already merged or superseded by this push.
            args.push("--force");
        }
        args.push(remote);
        args.push(&refspec);
        self.worktree.git().run_attached(&args)
    }
}

/// Accept an event name with or without its `sign/` prefix, and check it is usable as a
/// branch name.
pub fn normalize_event_name(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        bail!("a signing event needs a name, for example {EVENT_PREFIX}add-crates");
    }

    let name = if trimmed.starts_with(EVENT_PREFIX) {
        trimmed.to_owned()
    } else {
        format!("{EVENT_PREFIX}{trimmed}")
    };

    let suffix = &name[EVENT_PREFIX.len()..];
    if suffix.is_empty() {
        bail!("a signing event needs a name after {EVENT_PREFIX:?}");
    }
    if !suffix
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/'))
    {
        bail!("{name:?} is not a usable branch name: use letters, digits, '-', '_' and '.' only");
    }
    if suffix.contains("..") || suffix.ends_with('/') || suffix.ends_with('.') {
        bail!("{name:?} is not a usable branch name");
    }

    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::normalize_event_name;

    #[test]
    fn event_names_gain_the_prefix_if_they_lack_it() {
        assert_eq!(
            normalize_event_name("add-crates").unwrap(),
            "sign/add-crates"
        );
        assert_eq!(
            normalize_event_name("sign/add-crates").unwrap(),
            "sign/add-crates"
        );
        assert_eq!(
            normalize_event_name("  add-crates ").unwrap(),
            "sign/add-crates"
        );
    }

    #[test]
    fn names_that_would_not_be_valid_branches_are_refused() {
        for bad in ["", "   ", "sign/", "a..b", "a b", "trailing/", "trailing."] {
            assert!(
                normalize_event_name(bad).is_err(),
                "{bad:?} should have been refused"
            );
        }
    }

    #[test]
    fn nested_event_names_are_allowed() {
        assert_eq!(
            normalize_event_name("sign/root/v2").unwrap(),
            "sign/root/v2"
        );
    }
}
