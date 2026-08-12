//! `tuf-sign`: the tool a signer runs to take part in a signing event.
//!
//! Everything it does happens in a throwaway worktree, so it never disturbs whatever the
//! signer had checked out, and it never needs a clean working tree to start.

mod config;
mod git;
mod roles;
mod session;
mod ui;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use tuf_repo::event::RoleConfig;
use tuf_repo::metadata::{Periods, RoleName};
use tuf_yubikey::YubikeySigner;

use crate::config::{Config, GitRemotes, User};
use crate::session::{Checkout, EventRefs, Session};
use crate::ui::TerminalPrompt;

/// Sign TUF metadata with a YubiKey.
#[derive(Parser)]
#[command(name = "tuf-sign", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// The signing event to work on. Without one, you are shown the events awaiting you.
    event: Option<String>,
}

#[derive(Subcommand)]
enum Command {
    /// Take part in a signing event: accept invitations and sign what is waiting on you.
    Sign {
        /// The signing event. Without one, you are shown the events awaiting you.
        event: Option<String>,
    },
    /// Create the root and targets metadata for a new repository.
    Init {
        /// The signing event to create the repository in.
        #[arg(default_value = "sign/init")]
        event: String,
    },
    /// Change who may sign a role, how many of them are needed, and for how long.
    Delegate {
        /// The signing event to make the change in.
        event: String,
        /// The role to configure. You are asked if you leave it out.
        role: Option<String>,
    },
    /// Show the state of a signing event without changing anything.
    Status {
        /// The signing event. Without one, every open event is listed.
        event: Option<String>,
    },
    /// Set up this clone: your GitHub handle and which remotes to use.
    Configure,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("\nerror: {err:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        None => sign(cli.event),
        Some(Command::Sign { event }) => sign(event.or(cli.event)),
        Some(Command::Init { event }) => init(&event),
        Some(Command::Delegate { event, role }) => delegate(&event, role.as_deref()),
        Some(Command::Status { event }) => status(event),
        Some(Command::Configure) => {
            let git = git::Git::discover()?;
            let config = configure(&git)?;
            ui::success(&format!(
                "Signing as {} against {}",
                config.user.name, config.git.pull_remote
            ));
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Session setup
// ---------------------------------------------------------------------------

/// Open a session, asking for configuration the first time.
fn open_session() -> Result<Session> {
    let git = git::Git::discover()?;
    let config = match Config::load(git.root())? {
        Some(config) => config,
        None => {
            ui::heading("First run in this clone");
            ui::info(&format!(
                "Settings are saved to {} and kept out of git.",
                config::CONFIG_FILE
            ));
            configure(&git)?
        }
    };
    Session::open(config)
}

/// Ask for and save this clone's settings.
fn configure(git: &git::Git) -> Result<Config> {
    let existing = Config::load(git.root())?;

    let name = ui::text(
        "Your GitHub handle",
        existing.as_ref().map(|c| c.user.name.as_str()),
    )?;
    let name = config::normalize_handle(&name);

    let pull_remote = ui::text(
        "Git remote holding the TUF repository",
        Some(
            existing
                .as_ref()
                .map_or("origin", |c| c.git.pull_remote.as_str()),
        ),
    )?;
    ui::info(
        "If you cannot push to that repository, signatures go to your fork instead and \
         tuf-sign opens a pull request for you.",
    );
    let push_remote = ui::text(
        "Git remote to push your signatures to",
        Some(
            existing
                .as_ref()
                .map_or(pull_remote.as_str(), |c| c.git.push_remote.as_str()),
        ),
    )?;

    let config = Config {
        user: User { name },
        git: GitRemotes {
            pull_remote,
            push_remote,
        },
        yubikey: existing.and_then(|c| c.yubikey),
    };
    config.save(git.root())?;
    Ok(config)
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// Show the state of one event, or list the ones that are open.
fn status(event: Option<String>) -> Result<()> {
    let session = open_session()?;
    session.fetch()?;

    match event {
        Some(name) => {
            let refs = session.locate(&name)?;
            let event = session.read(&refs)?;
            ui::print_status(&event.status(), &refs.name);
        }
        None => {
            let events = session.list_events()?;
            if events.is_empty() {
                ui::info("No signing events are open.");
                return Ok(());
            }
            for name in events {
                let refs = session.locate(&name)?;
                let event = session.read(&refs)?;
                ui::print_status(&event.status(), &refs.name);
            }
        }
    }
    Ok(())
}

/// Accept invitations and sign whatever is waiting on this signer.
fn sign(event: Option<String>) -> Result<()> {
    let session = open_session()?;
    session.fetch()?;

    let name = match event {
        Some(name) => session::normalize_event_name(&name)?,
        None => choose_event(&session)?,
    };

    let refs = session.locate(&name)?;
    let mut checkout = session.check_out(&refs)?;
    let user = session.config.user.name.clone();

    if !checkout.event.is_initialized() {
        bail!(
            "this repository has no metadata yet. Create it with `tuf-sign init {}`",
            refs.name
        );
    }

    let tasks = checkout.event.tasks_for(&user);
    if tasks.is_empty() {
        ui::print_status(&checkout.event.status(), &refs.name);
        ui::info(&format!("\nNothing for {user} to do in this event."));
        return Ok(());
    }

    let mut signer = None;

    if !tasks.accept.is_empty() {
        ui::heading("You have been invited to sign");
        for role in &tasks.accept {
            ui::info(&format!("  {role}"));
        }
        ui::info(
            "Your public key will be added to the repository; the private key stays on the YubiKey.",
        );
        if !ui::confirm("Add your key?", true)? {
            bail!("cancelled; nothing was signed or pushed");
        }

        let opened = open_signer(&session, &mut signer)?;
        let (_, key) = opened
            .key()
            .as_metadata_key(&user)
            .context("could not read your YubiKey's public key")?;

        for role in &tasks.accept {
            checkout.event.accept_invite(role, &user, key.clone())?;
            ui::success(&format!("Added your key to {role}"));
        }
    }

    // Accepting an invitation changes the metadata, so what needs signing is worked out
    // again rather than reused from before.
    let tasks = checkout.event.tasks_for(&user);
    if !tasks.sign.is_empty() {
        ui::print_changes_to_sign(&checkout.event, &tasks.sign);
        if !ui::confirm("\nSign these changes?", true)? {
            bail!("cancelled; nothing was signed or pushed");
        }

        let opened = open_signer(&session, &mut signer)?;
        for role in &tasks.sign {
            checkout
                .event
                .sign(role, opened)
                .with_context(|| format!("signing {role}"))?;
            ui::success(&format!("Signed {role}"));
        }
    } else if tasks.accept.is_empty() {
        ui::info("Nothing left to sign.");
    }

    let summary = describe_contribution(&tasks.accept, &tasks.sign, &user);
    finish(&session, &mut checkout, &refs, &summary)
}

/// Create a new repository's metadata.
fn init(event: &str) -> Result<()> {
    let session = open_session()?;
    session.fetch()?;

    let refs = session.locate(event)?;
    let mut checkout = session.check_out(&refs)?;
    let user = session.config.user.name.clone();

    if checkout.event.is_initialized() {
        bail!(
            "this repository already has metadata. Use `tuf-sign delegate {}` to change it",
            refs.name
        );
    }

    ui::heading("Creating a new TUF repository");
    let default_periods = Periods {
        expiry_days: 365,
        signing_days: 60,
    };
    checkout.event.initialize(default_periods)?;

    let root_config = roles::prompt_config(
        &RoleName::root(),
        &RoleConfig {
            signers: vec![user.clone()],
            threshold: 1,
            periods: default_periods,
        },
    )?;
    checkout
        .event
        .configure_role(&RoleName::root(), &root_config)?;

    let targets_config = roles::prompt_config(
        &RoleName::targets(),
        &RoleConfig {
            signers: root_config.signers.clone(),
            threshold: root_config.threshold,
            periods: root_config.periods,
        },
    )?;
    checkout
        .event
        .configure_role(&RoleName::targets(), &targets_config)?;

    ui::heading("Online signing key");
    ui::info(
        "Snapshot and timestamp metadata are re-signed automatically, by a key that CI can \
         reach. Give the key CI will use.",
    );
    let (key, timestamp, snapshot) = roles::prompt_online_key()?;
    checkout.event.configure_online(key, timestamp, snapshot)?;

    accept_and_sign(&session, &mut checkout, &user)?;
    finish(
        &session,
        &mut checkout,
        &refs,
        "Create root and targets metadata",
    )
}

/// Change a role's signers, threshold or validity periods.
fn delegate(event: &str, role: Option<&str>) -> Result<()> {
    let session = open_session()?;
    session.fetch()?;

    let refs = session.locate(event)?;
    let mut checkout = session.check_out(&refs)?;
    let user = session.config.user.name.clone();

    if !checkout.event.is_initialized() {
        bail!(
            "this repository has no metadata yet. Create it with `tuf-sign init {}`",
            refs.name
        );
    }

    let role = match role {
        Some(role) => role.parse::<RoleName>()?,
        None => roles::choose_role(&checkout.event)?,
    };
    if role.is_online() {
        bail!(
            "{role} is signed automatically. Its key is configured together with snapshot's; \
             re-run `tuf-sign init` semantics are not needed, use the online key settings instead"
        );
    }

    let existing = roles::current_config(&checkout.event, &role);
    match &existing {
        Some(_) => ui::heading(&format!("Changing the delegation to {role}")),
        None => ui::heading(&format!("Creating a delegation to {role}")),
    }

    let default = existing.clone().unwrap_or(RoleConfig {
        signers: vec![user.clone()],
        threshold: 1,
        periods: Periods {
            expiry_days: 365,
            signing_days: 60,
        },
    });
    let config = roles::prompt_config(&role, &default)?;

    if Some(&config) == existing.as_ref() {
        ui::info("No changes.");
        return Ok(());
    }

    if !checkout.event.configure_role(&role, &config)? {
        ui::info("No changes.");
        return Ok(());
    }

    accept_and_sign(&session, &mut checkout, &user)?;
    finish(
        &session,
        &mut checkout,
        &refs,
        &format!("Change the delegation to {role}"),
    )
}

// ---------------------------------------------------------------------------
// Shared steps
// ---------------------------------------------------------------------------

/// Accept any invitation this change created for the signer, then sign what is waiting.
fn accept_and_sign(session: &Session, checkout: &mut Checkout, user: &str) -> Result<()> {
    let mut signer = None;

    let tasks = checkout.event.tasks_for(user);
    if !tasks.accept.is_empty() {
        ui::heading("Adding your own key");
        let opened = open_signer(session, &mut signer)?;
        let (_, key) = opened
            .key()
            .as_metadata_key(user)
            .context("could not read your YubiKey's public key")?;
        for role in &tasks.accept {
            checkout.event.accept_invite(role, user, key.clone())?;
            ui::success(&format!("Added your key to {role}"));
        }
    }

    let tasks = checkout.event.tasks_for(user);
    if tasks.sign.is_empty() {
        return Ok(());
    }

    ui::print_changes_to_sign(&checkout.event, &tasks.sign);
    if !ui::confirm("\nSign these changes?", true)? {
        bail!("cancelled; nothing was signed or pushed");
    }
    let opened = open_signer(session, &mut signer)?;
    for role in &tasks.sign {
        checkout
            .event
            .sign(role, opened)
            .with_context(|| format!("signing {role}"))?;
        ui::success(&format!("Signed {role}"));
    }
    Ok(())
}

/// Open the YubiKey once and reuse it, so a signer is not asked to insert it twice.
fn open_signer<'a>(
    session: &Session,
    slot: &'a mut Option<YubikeySigner<TerminalPrompt>>,
) -> Result<&'a mut YubikeySigner<TerminalPrompt>> {
    if slot.is_none() {
        let serial = session.config.yubikey.as_ref().map(|y| y.serial);
        *slot = Some(ui::open_yubikey(serial)?);
    }
    Ok(slot.as_mut().expect("just filled"))
}

/// Commit the event's changes and offer to push them.
fn finish(
    session: &Session,
    checkout: &mut Checkout,
    refs: &EventRefs,
    message: &str,
) -> Result<()> {
    if !checkout.commit(message)? {
        ui::info("Nothing to commit.");
        return Ok(());
    }

    ui::print_status(&checkout.event.status(), &refs.name);

    let config = &session.config;
    let destination = if config.signs_via_fork() {
        format!("{} (your fork)", config.git.push_remote)
    } else {
        config.git.push_remote.clone()
    };

    if !ui::confirm(&format!("\nPush {} to {destination}?", refs.name), true)? {
        ui::warn(&format!(
            "Not pushed. Your signature is committed in a temporary worktree and will be lost. \
             Re-run `tuf-sign {}` when you are ready.",
            refs.name
        ));
        return Ok(());
    }

    // Pushing to a fork force-updates it: whatever was there is either already merged or
    // superseded by this push, and the branch is the signer's own.
    checkout.push(&config.git.push_remote, &refs.name, config.signs_via_fork())?;
    ui::success(&format!("Pushed to {destination}"));

    if config.signs_via_fork() {
        let upstream = session.git.github_repo(&config.git.pull_remote)?;
        let fork = session.git.github_repo(&config.git.push_remote)?;
        let fork_owner = fork.split('/').next().unwrap_or(&fork);
        let url = format!(
            "https://github.com/{upstream}/compare/{event}...{fork_owner}:{event}?quick_pull=1&title={title}",
            event = refs.name,
            title = urlencode(message),
        );
        ui::heading("Open a pull request to contribute your signature");
        ui::info(&url);
    }

    Ok(())
}

/// Let the signer pick from the events that want something from them.
fn choose_event(session: &Session) -> Result<String> {
    let user = &session.config.user.name;
    let names = session.list_events()?;
    if names.is_empty() {
        bail!(
            "no signing events are open on {}",
            session.config.git.pull_remote
        );
    }

    let mut waiting = Vec::new();
    let mut others = Vec::new();
    for name in names {
        let refs = session.locate(&name)?;
        let Ok(event) = session.read(&refs) else {
            continue;
        };
        let tasks = event.tasks_for(user);
        let summary = tuf_repo::report::headline(&event.status());
        if tasks.is_empty() {
            others.push(format!("{name} — {summary}"));
        } else if tasks.accept.is_empty() {
            waiting.push(format!("{name} — your signature is needed"));
        } else {
            waiting.push(format!("{name} — you have been invited to sign"));
        }
    }

    if waiting.is_empty() {
        ui::info(&format!("Nothing is waiting on {user}."));
        if others.is_empty() {
            bail!("no signing events are open");
        }
        let choice = ui::select("Open a signing event anyway?", others)?;
        return Ok(event_name_of(&choice));
    }

    let choice = ui::select("Which signing event?", waiting)?;
    Ok(event_name_of(&choice))
}

fn event_name_of(label: &str) -> String {
    label.split(" — ").next().unwrap_or(label).to_owned()
}

/// A commit message describing what this run contributed.
fn describe_contribution(accepted: &[RoleName], signed: &[RoleName], user: &str) -> String {
    let list = |roles: &[RoleName]| {
        roles
            .iter()
            .map(RoleName::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    };
    match (accepted.is_empty(), signed.is_empty()) {
        (false, false) => format!(
            "Add {user} key to {} and sign {}",
            list(accepted),
            list(signed)
        ),
        (false, true) => format!("Add {user} key to {}", list(accepted)),
        (true, false) => format!("Sign {} as {user}", list(signed)),
        (true, true) => format!("Update metadata as {user}"),
    }
}

/// Percent-encode a string for use in a URL query value.
fn urlencode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            b' ' => out.push('+'),
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_messages_say_what_was_contributed() {
        let root = RoleName::root();
        let targets = RoleName::targets();
        assert_eq!(
            describe_contribution(&[], &[root.clone(), targets.clone()], "@alice"),
            "Sign root, targets as @alice"
        );
        assert_eq!(
            describe_contribution(std::slice::from_ref(&root), &[], "@alice"),
            "Add @alice key to root"
        );
        assert_eq!(
            describe_contribution(
                std::slice::from_ref(&root),
                std::slice::from_ref(&root),
                "@alice"
            ),
            "Add @alice key to root and sign root"
        );
    }

    #[test]
    fn event_labels_reduce_back_to_branch_names() {
        assert_eq!(
            event_name_of("sign/add-crates — your signature is needed"),
            "sign/add-crates"
        );
        assert_eq!(event_name_of("sign/add-crates"), "sign/add-crates");
    }

    #[test]
    fn url_encoding_escapes_what_a_query_value_cannot_hold() {
        assert_eq!(urlencode("Sign root, targets"), "Sign+root%2C+targets");
        assert_eq!(urlencode("a-b_c.d~e"), "a-b_c.d~e");
    }
}
