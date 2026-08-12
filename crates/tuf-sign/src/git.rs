//! Running git.
//!
//! The signing tool shells out to `git` rather than linking a library implementation,
//! because a signer's push has to go over whatever remote, credential helper, SSH agent and
//! commit-signing configuration they already have working. Reimplementing that is a lot of
//! surface for no gain; borrowing it costs one process spawn.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

/// A git repository on disk.
#[derive(Clone, Debug)]
pub struct Git {
    root: PathBuf,
}

impl Git {
    /// Find the repository containing the current directory.
    pub fn discover() -> Result<Self> {
        let output = Command::new("git")
            .args(["rev-parse", "--show-toplevel"])
            .output()
            .context("could not run git; is it installed?")?;
        if !output.status.success() {
            bail!("this is not a git repository. Run tuf-sign inside your TUF repository clone");
        }
        let root = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        Ok(Git { root: root.into() })
    }

    /// Use the repository rooted at `root`.
    pub fn at(root: impl Into<PathBuf>) -> Self {
        Git { root: root.into() }
    }

    /// The repository's working tree root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Run git and capture its output, failing if git fails.
    pub fn run<S: AsRef<OsStr>>(&self, args: &[S]) -> Result<String> {
        let output = self.output(args)?;
        if !output.status.success() {
            bail!(
                "git {} failed:\n{}",
                describe(args),
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    }

    /// Run git and capture its output, whether it succeeds or not.
    pub fn output<S: AsRef<OsStr>>(&self, args: &[S]) -> Result<std::process::Output> {
        Command::new("git")
            .arg("-C")
            .arg(&self.root)
            .args(args)
            .output()
            .with_context(|| format!("could not run git {}", describe(args)))
    }

    /// Run git with its output going to the terminal.
    ///
    /// Used for `push`, where the progress output and any credential prompt belong to the
    /// person running the tool.
    pub fn run_attached<S: AsRef<OsStr>>(&self, args: &[S]) -> Result<()> {
        let status = Command::new("git")
            .arg("-C")
            .arg(&self.root)
            .args(args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .with_context(|| format!("could not run git {}", describe(args)))?;
        if !status.success() {
            bail!("git {} failed", describe(args));
        }
        Ok(())
    }

    /// Whether git exits successfully for these arguments.
    pub fn succeeds<S: AsRef<OsStr>>(&self, args: &[S]) -> bool {
        self.output(args)
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    /// Fetch from `remote`.
    pub fn fetch(&self, remote: &str) -> Result<()> {
        self.run(&["fetch", "--quiet", remote])
            .with_context(|| format!("could not fetch from {remote}"))?;
        Ok(())
    }

    /// Resolve a revision to a commit id.
    pub fn rev_parse(&self, rev: &str) -> Result<String> {
        self.run(&[
            "rev-parse",
            "--verify",
            "--quiet",
            &format!("{rev}^{{commit}}"),
        ])
        .with_context(|| format!("no such revision: {rev}"))
    }

    /// Whether a revision exists.
    pub fn rev_exists(&self, rev: &str) -> bool {
        self.succeeds(&[
            "rev-parse",
            "--verify",
            "--quiet",
            &format!("{rev}^{{commit}}"),
        ])
    }

    /// The most recent common ancestor of two revisions.
    pub fn merge_base(&self, a: &str, b: &str) -> Result<String> {
        self.run(&["merge-base", a, b])
            .with_context(|| format!("{a} and {b} have no common ancestor"))
    }

    /// Branch names on `remote` matching a glob, with the `refs/heads/` prefix stripped.
    pub fn remote_branches(&self, remote: &str, pattern: &str) -> Result<Vec<String>> {
        let listing = self.run(&["ls-remote", "--heads", remote, pattern])?;
        Ok(listing
            .lines()
            .filter_map(|line| line.split_whitespace().nth(1))
            .filter_map(|reference| reference.strip_prefix("refs/heads/"))
            .map(str::to_owned)
            .collect())
    }

    /// The `owner/repo` part of a remote's GitHub URL.
    pub fn github_repo(&self, remote: &str) -> Result<String> {
        let url = self
            .run(&["config", "--get", &format!("remote.{remote}.url")])
            .with_context(|| format!("no remote named {remote}"))?;
        parse_github_repo(&url)
            .with_context(|| format!("could not read a GitHub repository out of {url:?}"))
    }

    /// Create a detached worktree at `rev` in a temporary directory.
    pub fn worktree(&self, rev: &str) -> Result<Worktree> {
        let dir = tempfile::tempdir().context("could not create a temporary directory")?;
        let path = dir.path().join("worktree");
        self.run(&[
            "worktree".as_ref(),
            "add".as_ref(),
            "--quiet".as_ref(),
            "--detach".as_ref(),
            path.as_os_str(),
            rev.as_ref(),
        ])
        .with_context(|| format!("could not check out {rev} into a temporary worktree"))?;

        Ok(Worktree {
            parent: self.clone(),
            git: Git::at(&path),
            path,
            _dir: dir,
        })
    }
}

/// A throwaway checkout, used so that signing never disturbs the working tree.
///
/// The Python signing tool checks the event branch out in place and returns with
/// `git checkout -`, which leaves the signer on a detached HEAD if anything fails in
/// between. A separate worktree cannot do that, and needs no clean working tree to start.
pub struct Worktree {
    parent: Git,
    git: Git,
    path: PathBuf,
    // Dropped after the worktree is unregistered, so the directory outlives its own removal.
    _dir: tempfile::TempDir,
}

impl Worktree {
    /// Git, operating inside the worktree.
    pub fn git(&self) -> &Git {
        &self.git
    }

    /// The worktree's path.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Worktree {
    fn drop(&mut self) {
        // Best effort: if this fails the temporary directory still goes away, and
        // `git worktree prune` will tidy the administrative file later.
        let _ = self.parent.output(&[
            "worktree".as_ref(),
            "remove".as_ref(),
            "--force".as_ref(),
            self.path.as_os_str(),
        ]);
    }
}

/// Extract `owner/repo` from any of the URL forms git remotes come in.
fn parse_github_repo(url: &str) -> Option<String> {
    // In every form the host comes first and the owner/repo path follows, separated by
    // ':' for scp-style URLs and '/' for the rest.
    let (after_scheme, separator) = match url.split_once("://") {
        // ssh://git@github.com/owner/repo.git, https://github.com/owner/repo
        Some(("ssh" | "https" | "http", rest)) => (rest, '/'),
        Some(_) => return None,
        // git@github.com:owner/repo.git
        None => (url.strip_prefix("git@")?, ':'),
    };
    let path = after_scheme.split_once(separator)?.1;

    let path = path.trim_end_matches('/').trim_end_matches(".git");
    let (owner, repo) = path.split_once('/')?;
    if owner.is_empty() || repo.is_empty() || repo.contains('/') {
        return None;
    }
    Some(format!("{owner}/{repo}"))
}

fn describe<S: AsRef<OsStr>>(args: &[S]) -> String {
    args.iter()
        .map(|arg| arg.as_ref().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::{Git, parse_github_repo};

    /// A repository with one commit on `main` and a second on `sign/event`.
    fn repository() -> (tempfile::TempDir, Git) {
        let dir = tempfile::tempdir().expect("temp dir");
        let git = Git::at(dir.path());
        git.run(&["init", "--quiet", "--initial-branch=main"])
            .unwrap();
        git.run(&["config", "user.name", "Test"]).unwrap();
        git.run(&["config", "user.email", "test@example.com"])
            .unwrap();
        git.run(&["config", "commit.gpgsign", "false"]).unwrap();

        std::fs::write(dir.path().join("on-main"), "main\n").unwrap();
        git.run(&["add", "on-main"]).unwrap();
        git.run(&["commit", "--quiet", "--message", "main"])
            .unwrap();

        git.run(&["switch", "--quiet", "--create", "sign/event"])
            .unwrap();
        std::fs::write(dir.path().join("on-branch"), "branch\n").unwrap();
        git.run(&["add", "on-branch"]).unwrap();
        git.run(&["commit", "--quiet", "--message", "branch"])
            .unwrap();
        git.run(&["switch", "--quiet", "main"]).unwrap();

        (dir, git)
    }

    #[test]
    fn a_worktree_holds_the_requested_revision() {
        let (_dir, git) = repository();
        let worktree = git.worktree("sign/event").unwrap();

        assert!(worktree.path().join("on-branch").exists());
        assert!(worktree.path().join("on-main").exists());
        assert_eq!(
            worktree.git().run(&["log", "-1", "--pretty=%s"]).unwrap(),
            "branch"
        );
    }

    #[test]
    fn the_signers_own_checkout_is_left_alone() {
        let (dir, git) = repository();
        // An uncommitted change, which the Python tool's in-place checkout would refuse to
        // work around.
        std::fs::write(dir.path().join("scratch"), "work in progress\n").unwrap();

        let worktree = git.worktree("sign/event").unwrap();
        std::fs::write(worktree.path().join("on-branch"), "signed\n").unwrap();
        worktree.git().run(&["add", "on-branch"]).unwrap();
        worktree
            .git()
            .run(&["commit", "--quiet", "--message", "sign"])
            .unwrap();

        assert_eq!(
            git.run(&["rev-parse", "--abbrev-ref", "HEAD"]).unwrap(),
            "main",
            "the signer should still be on their own branch"
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("scratch")).unwrap(),
            "work in progress\n"
        );
        assert!(!dir.path().join("on-branch").exists());
    }

    #[test]
    fn dropping_a_worktree_unregisters_it() {
        let (_dir, git) = repository();
        let path = {
            let worktree = git.worktree("sign/event").unwrap();
            worktree.path().to_path_buf()
        };

        assert!(!path.exists(), "the checkout should be gone");
        let listing = git.run(&["worktree", "list", "--porcelain"]).unwrap();
        assert!(
            !listing.contains(&path.display().to_string()),
            "a stale worktree registration was left behind:\n{listing}"
        );
    }

    #[test]
    fn github_urls_are_understood_in_every_form_git_writes_them() {
        for url in [
            "git@github.com:rf-signing-experiment/tuf-on-ci.git",
            "ssh://git@github.com/rf-signing-experiment/tuf-on-ci.git",
            "https://github.com/rf-signing-experiment/tuf-on-ci.git",
            "https://github.com/rf-signing-experiment/tuf-on-ci",
        ] {
            assert_eq!(
                parse_github_repo(url).as_deref(),
                Some("rf-signing-experiment/tuf-on-ci"),
                "failed on {url}"
            );
        }
    }

    #[test]
    fn non_github_remotes_are_not_guessed_at() {
        assert_eq!(parse_github_repo("/srv/git/repo.git"), None);
        assert_eq!(parse_github_repo("https://example.com/onlyowner"), None);
    }
}
