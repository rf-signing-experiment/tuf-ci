//! Asking about a role's signers, threshold and validity periods.

use anyhow::{Context, Result, bail};
use tuf_repo::crypto::{self, PublicKey};
use tuf_repo::event::{RoleConfig, SigningEvent};
use tuf_repo::policy::{self, Periods, RoleName};

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
        .filter_map(|(key_id, _)| delegator.policy().signers.get(&key_id).cloned())
        .collect();
    for invited in event.event_state().for_role(role) {
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
///
/// Every role is offered, however it is signed today: which key signs a role is one of the
/// things being configured here, so hiding the automated ones would hide the way back.
pub fn choose_role(event: &SigningEvent) -> Result<RoleName> {
    let mut roles = vec![
        RoleName::root(),
        RoleName::targets(),
        RoleName::snapshot(),
        RoleName::timestamp(),
    ];
    roles.extend(
        event
            .current()
            .role_names()
            .into_iter()
            .filter(|role| !policy::is_top_level(role)),
    );

    let mut options: Vec<String> = roles.iter().map(RoleName::to_string).collect();
    options.push("a new delegated role…".to_owned());

    let choice = ui::select("Which role?", options)?;
    if choice.starts_with("a new") {
        let name = ui::text("Name for the new role", None)?;
        return policy::role_name(name.trim()).context("that is not a usable role name");
    }
    policy::role_name(&choice).context("that is not a usable role name")
}

/// Ask how `role` is signed, and apply the answer.
///
/// The same question for every role: people, or a key CI holds. Nothing here knows that
/// `timestamp` is usually automated and `root` never is — that is read from the repository
/// and, when it is being decided for the first time, from whoever is running this.
///
/// Either answer replaces the other, so this is also how a role moves between the two.
///
/// Returns whether anything changed.
pub fn configure(event: &mut SigningEvent, role: &RoleName) -> Result<bool> {
    const PEOPLE: &str = "People, signing with hardware keys";
    const AUTOMATED: &str = "An automated key that CI can reach";

    // The current arrangement goes first, so that accepting the default keeps it.
    let options = if event.is_online(role) {
        vec![AUTOMATED, PEOPLE]
    } else {
        vec![PEOPLE, AUTOMATED]
    };
    let choice = ui::select(&format!("Who signs {role}?"), options)?;

    if choice == AUTOMATED {
        let current = current_periods(event, role);
        let (key, uri, periods) = prompt_online_key(role, current)?;
        return Ok(event.configure_online_role(role, key, &uri, periods)?);
    }

    let current = current_config(event, role).unwrap_or_else(|| RoleConfig {
        signers: Vec::new(),
        threshold: 1,
        periods: current_periods(event, role),
    });
    let config = prompt_config(role, &current)?;
    Ok(event.configure_role(role, &config)?)
}

/// The validity periods `role` has now, or a starting suggestion if it has none.
fn current_periods(event: &SigningEvent, role: &RoleName) -> Periods {
    current_config(event, role)
        .map(|config| config.periods)
        .unwrap_or(policy::DEFAULT_PERIODS)
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

/// Ask for the key CI will sign `role` with.
///
/// The public key is read from a file rather than fetched from the key service, because
/// this tool deliberately talks to nothing but git and the YubiKey. Export it once, with
/// e.g. `gcloud kms keys versions get-public-key`.
fn prompt_online_key(role: &RoleName, current: Periods) -> Result<(PublicKey, String, Periods)> {
    let uri = ui::text(
        &format!("URI CI will use to reach the key that signs {role}"),
        None,
    )?;
    if uri.trim().is_empty() {
        bail!("an online key needs a URI so CI knows how to reach it");
    }

    let path = ui::text("Path to that key's public key, in PEM form", None)?;
    let pem =
        std::fs::read_to_string(path.trim()).with_context(|| format!("reading {}", path.trim()))?;
    let key = crypto::public_key(&pem).context("that is not a usable public key")?;

    let periods = prompt_periods(role, current)?;
    Ok((key, uri.trim().to_owned(), periods))
}
