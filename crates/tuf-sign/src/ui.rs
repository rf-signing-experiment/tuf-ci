//! Terminal output and prompts.
//!
//! The signing tool is the thing a signer is told to trust: the pull request comment is a
//! notification, but what appears here is what they are actually agreeing to. So the
//! change summary is printed in full before anything is signed, and every prompt that
//! authorises something says what it will do.

use anyhow::{Context, Result, bail};
use owo_colors::OwoColorize;
use tuf_repo::event::{EventStatus, RoleStatus, SigningEvent};
use tuf_repo::metadata::RoleName;
use tuf_repo::report;
use tuf_yubikey::{Device, Prompt};

/// A section heading.
pub fn heading(text: &str) {
    println!("\n{}", text.bold().bright_blue());
}

/// A line of ordinary information.
pub fn info(text: &str) {
    println!("{text}");
}

/// Something that went well.
pub fn success(text: &str) {
    println!("{} {text}", "✓".green());
}

/// Something the signer should notice but that is not an error.
pub fn warn(text: &str) {
    println!("{} {text}", "!".yellow());
}

/// Print where a whole signing event stands.
pub fn print_status(status: &EventStatus, event_name: &str) {
    heading(&format!("Signing event {event_name}"));
    println!("{}", report::headline(status));

    for problem in &status.problems {
        println!("  {} {problem}", "✗".red());
    }

    for role in &status.roles {
        print_role(role);
    }
}

/// Print where one role stands, including everything it changes.
pub fn print_role(role: &RoleStatus) {
    let marker = if !role.problems.is_empty() {
        "✗".red().to_string()
    } else if role.is_complete() {
        "✓".green().to_string()
    } else {
        "…".yellow().to_string()
    };

    println!(
        "\n{marker} {} v{} — {}",
        role.role.to_string().bold(),
        role.version,
        report::signature_count(role)
    );

    for invitation in &role.blocking_invites {
        println!(
            "    waiting for {} to add a key for {}",
            invitation.user.bold(),
            invitation.role
        );
    }
    for change in &role.delegations {
        println!(
            "    {}",
            strip_backticks(&report::describe_delegation(change))
        );
    }
    if !role.artifacts.is_empty() {
        println!("    {}", report::summarize_artifacts(&role.artifacts));
        for change in &role.artifacts {
            println!("      {} {}", change.verb(), change.path());
        }
    }
    let signed: Vec<&str> = role.tally.signed.iter().map(|s| s.name.as_str()).collect();
    if !signed.is_empty() {
        println!("    signed by {}", signed.join(", "));
    }
    let waiting = role.waiting_on();
    if !waiting.is_empty() {
        println!("    waiting on {}", waiting.join(", "));
    }
    for invalid in &role.tally.invalid {
        println!(
            "    {} signature from {} does not verify",
            "✗".red(),
            invalid.name
        );
    }
    for problem in &role.problems {
        println!("    {} {problem}", "✗".red());
    }
}

/// Print what a signer is about to put their name to, ahead of asking them to.
pub fn print_changes_to_sign(event: &SigningEvent, roles: &[RoleName]) {
    heading("You are about to sign the following changes");
    for role in roles {
        print_role(&event.role_status(role));
    }
}

fn strip_backticks(text: &str) -> String {
    text.replace('`', "")
}

// ---------------------------------------------------------------------------
// Prompts
// ---------------------------------------------------------------------------

/// Ask a yes/no question, defaulting to `default`.
pub fn confirm(question: &str, default: bool) -> Result<bool> {
    inquire::Confirm::new(question)
        .with_default(default)
        .prompt()
        .map_err(cancelled)
}

/// Ask for a line of text.
pub fn text(question: &str, default: Option<&str>) -> Result<String> {
    let mut prompt = inquire::Text::new(question);
    if let Some(default) = default {
        prompt = prompt.with_default(default);
    }
    prompt.prompt().map_err(cancelled)
}

/// Ask for a whole number.
pub fn number(question: &str, default: u32) -> Result<u32> {
    inquire::CustomType::<u32>::new(question)
        .with_default(default)
        .with_error_message("Please enter a whole number")
        .prompt()
        .map_err(cancelled)
}

/// Ask the signer to choose one of `options`.
pub fn select<T: std::fmt::Display>(question: &str, options: Vec<T>) -> Result<T> {
    inquire::Select::new(question, options)
        .prompt()
        .map_err(cancelled)
}

fn cancelled(err: inquire::InquireError) -> anyhow::Error {
    match err {
        inquire::InquireError::OperationCanceled | inquire::InquireError::OperationInterrupted => {
            anyhow::anyhow!("cancelled; nothing was signed or pushed")
        }
        other => anyhow::Error::new(other),
    }
}

/// Asks for the PIV PIN at the terminal and says when to touch the key.
pub struct TerminalPrompt;

impl Prompt for TerminalPrompt {
    fn pin(&mut self, device: &Device, retries: Option<u8>) -> tuf_yubikey::Result<String> {
        let message = match retries {
            // Warn before the last attempt, since using it up blocks the key and needs the
            // PUK to recover.
            Some(1) => format!("PIV PIN for {device} (last attempt before the PIN is blocked)"),
            Some(n) if n <= 3 => format!("PIV PIN for {device} ({n} attempts left)"),
            _ => format!("PIV PIN for {device}"),
        };

        inquire::Password::new(&message)
            .without_confirmation()
            .with_display_mode(inquire::PasswordDisplayMode::Masked)
            .prompt()
            .map_err(|err| tuf_yubikey::Error::Key(format!("could not read the PIN: {err}")))
    }

    fn touch(&mut self, device: &Device) {
        println!("{} touch {device} now", "→".bright_blue().bold());
    }
}

/// Open the signer's YubiKey, explaining what to do if there isn't one.
pub fn open_yubikey(serial: Option<u32>) -> Result<tuf_yubikey::YubikeySigner<TerminalPrompt>> {
    if serial.is_none() {
        let devices = tuf_yubikey::devices().unwrap_or_default();
        if devices.is_empty() {
            info("Insert your YubiKey.");
            if !confirm("Ready?", true)? {
                bail!("cancelled; nothing was signed or pushed");
            }
        }
    }

    tuf_yubikey::YubikeySigner::open(serial.map(Into::into), TerminalPrompt)
        .context("could not use your YubiKey")
}
