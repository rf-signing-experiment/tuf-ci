//! `tuf-ci`: the half of the system that runs in GitHub Actions.
//!
//! It does three things on every push to a signing event branch:
//!
//! 1. rebuilds targets metadata from whatever is under `targets/`, so that committing an
//!    artifact is enough to start a signing event;
//! 2. works out where the event stands;
//! 3. writes that into the pull request's description and into a check run, so the merge
//!    button reflects it.
//!
//! It never signs anything. Every signature in the repository is made on somebody's
//! YubiKey by `tuf-sign`.

mod github;

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use tuf_repo::event::{EventStatus, SigningEvent};
use tuf_repo::publish::{FsSink, Plan};
use tuf_repo::report;
use tuf_repo::store::{EmptySource, FsSource, GitSource, RepoState, Source, Writer};

use crate::github::{Conclusion, GitHub};

/// Manage TUF signing events from CI.
#[derive(Parser)]
#[command(name = "tuf-ci", version, about, long_about = None)]
struct Cli {
    /// The repository's working tree. Defaults to the current directory.
    #[arg(long, global = true)]
    repo: Option<PathBuf>,

    /// The branch signing events are merged into.
    #[arg(long, global = true, default_value = "main")]
    base_branch: String,

    #[command(subcommand)]
    command: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Rebuild targets metadata from the artifacts under `targets/`, and commit any change.
    ///
    /// Exits 0 if metadata was committed, 1 if nothing needed doing, so a workflow can
    /// branch on it.
    UpdateTargets {
        /// Push the commit to the signing event branch.
        #[arg(long)]
        push: bool,
    },
    /// Print where the signing event stands.
    ///
    /// Exits 0 if the event can be merged, 1 otherwise.
    Status {
        /// How to render the report.
        #[arg(long, value_enum, default_value_t = Format::Markdown)]
        format: Format,
    },
    /// Write the status into the pull request description and a check run.
    PrUpdate {
        /// Report the status without opening a pull request if there is not one already.
        #[arg(long)]
        no_create: bool,
    },
    /// Build the repository a client fetches from the signed metadata.
    ///
    /// Signs nothing and dates nothing: every byte written is either a document already
    /// signed in the repository or an artifact those documents describe. Run against the
    /// same commit twice and the output is identical, which is how somebody holding no
    /// keys can check that what is live is what was signed.
    ///
    /// Only files `--out` does not already hold are written, so pointing it at the
    /// previous publish and uploading what changed is the cheap path.
    ///
    /// Exits 0 if anything was written, 1 if the repository was already published.
    Publish {
        /// Where to write the published repository.
        #[arg(long)]
        out: PathBuf,

        /// Publish this commit rather than the working tree.
        #[arg(long)]
        rev: Option<String>,

        /// Write the list of published files and their digests here; `-` for stdout.
        #[arg(long)]
        manifest: Option<PathBuf>,

        /// Judge expiry as of this time rather than now, to reproduce an earlier publish.
        #[arg(long, value_name = "RFC3339")]
        as_of: Option<DateTime<Utc>>,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum Format {
    /// Markdown, for a pull request description.
    Markdown,
    /// The machine-readable form, for another tool to consume.
    Json,
}

fn main() {
    match run() {
        Ok(true) => std::process::exit(0),
        Ok(false) => std::process::exit(1),
        Err(err) => {
            eprintln!("error: {err:#}");
            std::process::exit(2);
        }
    }
}

fn run() -> Result<bool> {
    let cli = Cli::parse();
    let repo = match cli.repo {
        Some(path) => path,
        None => std::env::current_dir().context("could not read the current directory")?,
    };
    // Publishing is about the repository, not about a signing event, so it neither needs
    // nor looks for a branch to compare against.
    let event = || EventContext::discover(&repo, &cli.base_branch);

    match cli.command {
        Action::UpdateTargets { push } => update_targets(&event()?, push),
        Action::Status { format } => status(&event()?, format),
        Action::PrUpdate { no_create } => pr_update(&event()?, no_create),
        Action::Publish {
            out,
            rev,
            manifest,
            as_of,
        } => publish(&repo, &out, rev.as_deref(), manifest.as_deref(), as_of),
    }
}

// ---------------------------------------------------------------------------
// Where we are
// ---------------------------------------------------------------------------

/// The signing event this run is about.
struct EventContext {
    repo: PathBuf,
    /// The event's branch name.
    event: String,
    /// The commit under test.
    sha: String,
    /// The commit the event branched from, or `None` if the base branch does not exist.
    base: Option<String>,
    /// The branch events are merged into.
    base_branch: String,
}

impl EventContext {
    fn discover(repo: &Path, base_branch: &str) -> Result<Self> {
        let repo = repo.to_path_buf();
        let sha = git(&repo, &["rev-parse", "HEAD"])?;

        // In Actions the branch is in the environment, because the checkout is detached.
        let event = std::env::var("GITHUB_REF_NAME")
            .ok()
            .filter(|name| !name.is_empty())
            .map(Ok)
            .unwrap_or_else(|| git(&repo, &["rev-parse", "--abbrev-ref", "HEAD"]))?;

        // Prefer the remote-tracking ref: a workflow checkout has no local base branch.
        let base_ref = [
            format!("refs/remotes/origin/{base_branch}"),
            base_branch.to_owned(),
        ]
        .into_iter()
        .find(|reference| git(&repo, &["rev-parse", "--verify", "--quiet", reference]).is_ok());

        let base = match base_ref {
            Some(reference) => Some(
                git(&repo, &["merge-base", &reference, &sha])
                    .with_context(|| format!("{reference} and {sha} have no common ancestor"))?,
            ),
            None => None,
        };

        Ok(EventContext {
            repo,
            event,
            sha,
            base,
            base_branch: base_branch.to_owned(),
        })
    }

    /// Load the signing event from the working tree and the commit it branched from.
    fn load(&self) -> Result<SigningEvent> {
        let current = RepoState::load(&FsSource::new(&self.repo))
            .context("reading the metadata in the working tree")?;
        let known_good = match &self.base {
            Some(base) => {
                let source = GitSource::new(&self.repo, base);
                RepoState::load(&source).context("reading the commit this event branched from")?
            }
            None => RepoState::load(&EmptySource)?,
        };
        Ok(SigningEvent::from_states(known_good, current))
    }
}

fn git(repo: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .with_context(|| format!("could not run git {}", args.join(" ")))?;
    if !output.status.success() {
        bail!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// Run git as the automation identity, for commits this tool makes itself.
///
/// These are a fallback, not a decision: `GIT_AUTHOR_*` and `GIT_COMMITTER_*` take
/// precedence over `-c user.name`/`user.email`, so a caller running under a GitHub App
/// sets those and the commits are attributed to the App's own bot user. Without them
/// there would be no identity at all in a fresh runner checkout, and git would refuse to
/// commit.
fn git_as_bot(repo: &Path, args: &[&str]) -> Result<String> {
    let mut full = vec![
        "-c",
        "user.name=tuf-ci",
        "-c",
        "user.email=41898282+github-actions[bot]@users.noreply.github.com",
    ];
    full.extend_from_slice(args);
    git(repo, &full)
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// Bring targets metadata in line with the artifacts committed under `targets/`.
fn update_targets(context: &EventContext, push: bool) -> Result<bool> {
    let mut event = context.load()?;
    if !event.is_initialized() {
        eprintln!("This repository has no metadata yet; nothing to update.");
        return Ok(false);
    }

    let artifacts = FsSource::new(&context.repo);
    let updated = event
        .update_targets(&artifacts)
        .context("rebuilding targets metadata from the artifacts")?;
    if updated.is_empty() {
        eprintln!("Targets metadata already matches the artifacts.");
        return Ok(false);
    }

    let writer = Writer::new(&context.repo);
    let paths = event.persist(&writer).context("writing targets metadata")?;

    let mut add = vec!["add".to_owned(), "--".to_owned()];
    add.extend(paths);
    let add: Vec<&str> = add.iter().map(String::as_str).collect();
    git_as_bot(&context.repo, &add)?;

    if git(&context.repo, &["diff", "--cached", "--quiet"]).is_ok() {
        eprintln!("Targets metadata already matches the artifacts.");
        return Ok(false);
    }

    let roles: Vec<String> = updated.iter().map(ToString::to_string).collect();
    let message = format!("Update targets metadata for {}", roles.join(", "));
    git_as_bot(
        &context.repo,
        &["commit", "--signoff", "--message", &message],
    )?;

    println!("{message}");
    println!(
        "The new metadata is unsigned: signers can sign it with `tuf-sign {}`.",
        context.event
    );

    if push {
        // A signer may have pushed while this ran. Their push is the more important one,
        // and it will trigger this workflow again, so stand down rather than fight over
        // the branch.
        let refspec = format!("HEAD:refs/heads/{}", context.event);
        if git(&context.repo, &["push", "origin", &refspec]).is_err() {
            eprintln!(
                "The signing event branch moved while this ran; leaving the metadata update \
                 to the run triggered by that push."
            );
            return Ok(false);
        }
    }

    Ok(true)
}

/// Print where the event stands, and report whether it can be merged.
fn status(context: &EventContext, format: Format) -> Result<bool> {
    let event = context.load()?;
    let status = event.status();

    match format {
        Format::Markdown => print!("{}", report::markdown(&status, &context.event)),
        Format::Json => println!("{}", serde_json::to_string_pretty(&summarize(&status))?),
    }

    Ok(status.is_mergeable())
}

/// Write the status into the pull request description and a check run.
fn pr_update(context: &EventContext, no_create: bool) -> Result<bool> {
    let event = context.load()?;
    let status = event.status();
    let report = report::markdown(&status, &context.event);
    let headline = report::headline(&status);

    let github = GitHub::from_env()?;

    let pull_request = match github.pull_request_for(&context.sha)? {
        Some(existing) => Some(existing),
        None if no_create => None,
        None => {
            let title = format!("Signing event: {}", context.event);
            let body = github::splice_report("", &report);
            let created = github
                .create_pull_request(&context.event, &context.base_branch, &title, &body)
                .context("could not open a pull request for this signing event")?;
            println!("Opened pull request #{}", created.number);
            Some(created)
        }
    };

    if let Some(pull_request) = &pull_request {
        let body = github::splice_report(pull_request.body.as_deref().unwrap_or(""), &report);
        if pull_request.body.as_deref() == Some(body.as_str()) {
            println!(
                "Pull request #{} is already up to date",
                pull_request.number
            );
        } else {
            github
                .set_pull_request_body(pull_request.number, &body)
                .context("could not update the pull request description")?;
            println!("Updated pull request #{}", pull_request.number);
        }
    } else {
        println!(
            "No pull request for {}; reporting the check only",
            context.sha
        );
    }

    let has_problems =
        !status.problems.is_empty() || status.roles.iter().any(|role| !role.problems.is_empty());
    let conclusion = if status.is_mergeable() {
        Conclusion::Success
    } else if has_problems {
        Conclusion::Failure
    } else {
        Conclusion::Pending
    };

    github
        .report_check(&context.sha, conclusion, &headline, &report)
        .context("could not report the check run")?;

    Ok(status.is_mergeable())
}

/// The status in a form another tool can read.
/// Build the files a client fetches, and write the ones that are not already there.
fn publish(
    repo: &Path,
    out: &Path,
    rev: Option<&str>,
    manifest: Option<&Path>,
    as_of: Option<DateTime<Utc>>,
) -> Result<bool> {
    let source: Box<dyn Source> = match rev {
        Some(rev) => Box::new(GitSource::new(repo, rev)),
        None => Box::new(FsSource::new(repo)),
    };
    let as_of = as_of.unwrap_or_else(Utc::now);

    // Everything is verified the way a client verifies it before anything is written, so a
    // repository that would not satisfy a client never reaches the output directory.
    let plan =
        Plan::build(source.as_ref(), as_of).context("this repository cannot be published")?;

    let mut sink = FsSink::new(out);
    let report = plan
        .write(source.as_ref(), &mut sink)
        .context("writing the published repository")?;

    if let Some(path) = manifest {
        let bytes = tuf_repo::ser::to_bytes(&plan.manifest())?;
        if path == Path::new("-") {
            std::io::Write::write_all(&mut std::io::stdout(), &bytes)
                .context("writing the manifest")?;
        } else {
            std::fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))?;
        }
    }

    // What happened goes to stderr, so that `--manifest -` leaves stdout to the manifest.
    for path in &report.written {
        eprintln!("+ {path}");
    }
    eprintln!(
        "{} of {} files written ({} bytes) to {}",
        report.written.len(),
        report.written.len() + report.unchanged.len(),
        report.bytes,
        out.display()
    );

    Ok(report.changed())
}

fn summarize(status: &EventStatus) -> serde_json::Value {
    serde_json::json!({
        "mergeable": status.is_mergeable(),
        "headline": report::headline(status),
        "outstanding_signatures": status.outstanding(),
        "problems": status.problems,
        "invitations": status
            .invitations()
            .iter()
            .map(|invitation| serde_json::json!({
                "user": invitation.user,
                "role": invitation.role.to_string(),
            }))
            .collect::<Vec<_>>(),
        "roles": status
            .roles
            .iter()
            .map(|role| serde_json::json!({
                "role": role.role.to_string(),
                "version": role.version,
                "complete": role.is_complete(),
                "threshold": role.tally.threshold,
                "signed": role.tally.signed.iter().map(|s| &s.name).collect::<Vec<_>>(),
                "waiting_on": role.waiting_on(),
                "outstanding": role.outstanding(),
                "artifact_changes": role
                    .artifacts
                    .iter()
                    .map(|change| serde_json::json!({
                        "path": change.path(),
                        "change": change.verb(),
                    }))
                    .collect::<Vec<_>>(),
                "problems": role.problems,
            }))
            .collect::<Vec<_>>(),
    })
}
