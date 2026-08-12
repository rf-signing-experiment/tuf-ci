//! Asking about a role's signers, threshold and validity periods.

use anyhow::{Context, Result, bail};
use tuf_repo::event::{RoleConfig, SigningEvent};
use tuf_repo::metadata::{Key, Periods, RoleName};

use crate::config::normalize_handle;
use crate::ui;

/// A role's configuration as it currently stands, including anyone invited but not yet
/// accepted.
///
/// Invitees are included so that re-running the tool does not silently withdraw an
/// invitation that is merely outstanding.
pub fn current_config(event: &SigningEvent, role: &RoleName) -> Option<RoleConfig> {
    let delegator = event.current().delegator_of(role).ok()?;
    let spec = delegator.role_spec(role)?;

    let mut signers: Vec<String> = delegator
        .keys_for(role)
        .into_iter()
        .filter_map(|(_, key)| key.owner.clone())
        .collect();
    for invited in event.invites().for_role(role) {
        if !signers.iter().any(|signer| signer == invited) {
            signers.push(invited.to_owned());
        }
    }
    signers.sort();

    Some(RoleConfig {
        signers,
        threshold: spec.threshold,
        periods: spec.periods,
    })
}

/// Ask which role to configure.
pub fn choose_role(event: &SigningEvent) -> Result<RoleName> {
    let mut options: Vec<String> = event
        .current()
        .role_names()
        .into_iter()
        .filter(|role| !role.is_online())
        .map(|role| role.to_string())
        .collect();
    options.push("a new delegated role…".to_owned());

    let choice = ui::select("Which role?", options)?;
    if choice.starts_with("a new") {
        let name = ui::text("Name for the new role", None)?;
        return name
            .trim()
            .parse()
            .context("that is not a usable role name");
    }
    choice.parse().context("that is not a usable role name")
}

/// Walk through a role's settings, showing the current values and changing what is asked.
///
/// Modelled on a menu rather than a straight run of questions: most of the time only one
/// thing is being changed, and re-confirming everything else invites mistakes.
pub fn prompt_config(role: &RoleName, current: &RoleConfig) -> Result<RoleConfig> {
    let mut config = current.clone();

    loop {
        let signers = format!(
            "Signers: {} — {} of {} required",
            config.signers.join(", "),
            config.threshold,
            config.signers.len()
        );
        let periods = format!(
            "Validity: expires after {} days, re-signing starts {} days before that",
            config.periods.expiry_days, config.periods.signing_days
        );
        let done = "Done".to_owned();

        let choice = ui::select(
            &format!("Configuring {role}"),
            vec![done.clone(), signers.clone(), periods.clone()],
        )?;

        if choice == done {
            break;
        }
        if choice == signers {
            config.signers = prompt_signers(role, &config.signers)?;
            config.threshold = prompt_threshold(role, &config)?;
        } else {
            config.periods = prompt_periods(role, config.periods)?;
        }
    }

    config
        .validate(role)
        .with_context(|| format!("{role} cannot be configured that way"))?;
    Ok(config)
}

fn prompt_signers(role: &RoleName, current: &[String]) -> Result<Vec<String>> {
    let answer = ui::text(
        &format!("GitHub handles that may sign {role}, comma separated"),
        Some(&current.join(", ")),
    )?;

    let mut signers = Vec::new();
    for raw in answer.split(',') {
        if raw.trim().is_empty() {
            continue;
        }
        let handle = normalize_handle(raw);
        if handle.len() < 2 {
            bail!("{raw:?} is not a GitHub handle");
        }
        if !signers.contains(&handle) {
            signers.push(handle);
        }
    }

    if signers.is_empty() {
        bail!("{role} needs at least one signer");
    }
    Ok(signers)
}

fn prompt_threshold(role: &RoleName, config: &RoleConfig) -> Result<u32> {
    if config.signers.len() == 1 {
        // With one signer there is only one possible answer, so asking is noise.
        return Ok(1);
    }
    loop {
        let threshold = ui::number(
            &format!(
                "How many of the {} signers must sign {role}?",
                config.signers.len()
            ),
            config.threshold.min(config.signers.len() as u32).max(1),
        )?;
        if threshold >= 1 && threshold as usize <= config.signers.len() {
            return Ok(threshold);
        }
        ui::warn(&format!(
            "Enter a number between 1 and {}.",
            config.signers.len()
        ));
    }
}

fn prompt_periods(role: &RoleName, current: Periods) -> Result<Periods> {
    loop {
        let expiry_days = ui::number(
            &format!("How many days is {role} metadata valid for?"),
            current.expiry_days,
        )?;
        let signing_days = ui::number(
            &format!("How many days before expiry should signing of {role} start?"),
            current
                .signing_days
                .min(expiry_days.saturating_sub(1))
                .max(1),
        )?;

        let periods = Periods {
            expiry_days,
            signing_days,
        };
        match periods.validate(role) {
            Ok(()) => return Ok(periods),
            Err(err) => ui::warn(&err.to_string()),
        }
    }
}

/// Ask for the key that CI will use to sign snapshot and timestamp.
///
/// The public key is read from a file rather than fetched from the key service, because
/// this tool deliberately talks to nothing but git and the YubiKey. Export it once, with
/// e.g. `gcloud kms keys versions get-public-key`.
pub fn prompt_online_key() -> Result<(Key, Periods, Periods)> {
    let uri = ui::text(
        "URI CI will use to reach the online key (e.g. gcpkms:projects/…/cryptoKeyVersions/1)",
        None,
    )?;
    if uri.trim().is_empty() {
        bail!("an online key needs a URI so CI knows how to reach it");
    }

    let path = ui::text("Path to that key's public key, in PEM form", None)?;
    let pem =
        std::fs::read_to_string(path.trim()).with_context(|| format!("reading {}", path.trim()))?;

    let (_, key) = Key::online(&pem, uri.trim()).context("that is not a usable public key")?;

    ui::info(
        "Timestamp metadata is short-lived and re-signed often; snapshot follows the offline \
         roles.",
    );
    let timestamp = prompt_periods(
        &RoleName::timestamp(),
        Periods {
            expiry_days: 7,
            signing_days: 4,
        },
    )?;
    let snapshot = prompt_periods(
        &RoleName::snapshot(),
        Periods {
            expiry_days: 365,
            signing_days: 60,
        },
    )?;

    Ok((key, timestamp, snapshot))
}
