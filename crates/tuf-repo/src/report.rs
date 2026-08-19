//! Rendering a signing event's status as Markdown.
//!
//! This lives next to the state machine rather than in the CI binary so that what a signer
//! is told locally and what the pull request says are generated from the same values. The
//! signing tool renders its own, colourised version for the terminal, but the numbers
//! behind both come from [`EventStatus`].

use std::fmt::Write as _;

use crate::event::{ArtifactChange, DelegationChange, EventStatus, Quorum, RoleStatus};

/// How the status report refers to the tool a signer should run.
pub const SIGN_COMMAND: &str = "tuf-sign";

/// Render the status of `event` as Markdown, for a pull request body.
pub fn markdown(status: &EventStatus, event_name: &str) -> String {
    let mut out = String::new();

    let _ = writeln!(out, "### Signing event `{event_name}`");
    let _ = writeln!(out);
    let _ = writeln!(out, "{}", headline(status));
    let _ = writeln!(out);

    if status.roles.is_empty() && status.invitations.is_empty() {
        let _ = writeln!(
            out,
            "This branch changes no metadata yet. Commit an artifact under `targets/`, or run \
             `{SIGN_COMMAND} delegate {event_name} <role>` to change a delegation."
        );
        return finish(out, status);
    }

    // A configuration waiting on a key changes no metadata yet, so there can be
    // invitations to report with no roles beside them.
    if status.roles.is_empty() {
        let _ = writeln!(
            out,
            "This branch changes no metadata yet: the configuration it proposes needs a key \
             that has not arrived."
        );
        let _ = writeln!(out);
        write_invitations(&mut out, status, event_name);
        return finish(out, status);
    }

    let _ = writeln!(out, "| Role | Status | Signatures | Waiting on |");
    let _ = writeln!(out, "| --- | --- | --- | --- |");
    for role in &status.roles {
        let waiting = role.waiting_on();
        let _ = writeln!(
            out,
            "| `{}` v{} | {} | {} | {} |",
            role.role,
            role.version,
            role_state(role),
            signature_count(role),
            if waiting.is_empty() {
                "—".to_owned()
            } else {
                waiting
                    .iter()
                    .map(|name| format!("`{name}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        );
    }
    let _ = writeln!(out);

    write_invitations(&mut out, status, event_name);

    // The report is the notification: somebody reading it should not have to look up what
    // to do about it.
    if status
        .roles
        .iter()
        .any(|role| !role.waiting_on().is_empty())
    {
        let _ = writeln!(
            out,
            "Signers: run `{SIGN_COMMAND} {event_name}` to review and sign these changes."
        );
        let _ = writeln!(out);
    }

    for role in &status.roles {
        let has_detail = !role.artifacts.is_empty() || !role.delegations.is_empty();
        if !has_detail {
            continue;
        }
        let _ = writeln!(out, "#### Changes to `{}`", role.role);
        let _ = writeln!(out);
        for change in &role.delegations {
            let _ = writeln!(out, "- {}", describe_delegation(change));
        }
        if !role.artifacts.is_empty() {
            let _ = writeln!(out, "- {}", summarize_artifacts(&role.artifacts));
            let _ = writeln!(out);
            let _ = writeln!(out, "<details><summary>Artifacts</summary>");
            let _ = writeln!(out);
            for change in &role.artifacts {
                let _ = writeln!(out, "- {} `{}`", change.verb(), change.path());
            }
            let _ = writeln!(out);
            let _ = writeln!(out, "</details>");
        }
        let _ = writeln!(out);
    }

    let problems: Vec<&String> = status
        .problems
        .iter()
        .chain(status.roles.iter().flat_map(|role| &role.problems))
        .collect();
    if !problems.is_empty() {
        let _ = writeln!(out, "#### Problems");
        let _ = writeln!(out);
        for problem in problems {
            let _ = writeln!(out, "- {problem}");
        }
        let _ = writeln!(out);
    }

    finish(out, status)
}

fn finish(mut out: String, status: &EventStatus) -> String {
    if status.is_mergeable() {
        let _ = writeln!(
            out,
            "Every changed role has reached its signature threshold. This event can be reviewed \
             and merged."
        );
    }
    out
}

/// List who has been invited and how they answer.
fn write_invitations(out: &mut String, status: &EventStatus, event_name: &str) {
    let invitations = status.invitations();
    if invitations.is_empty() {
        return;
    }
    let _ = writeln!(out, "#### Invitations");
    let _ = writeln!(out);
    for invitation in invitations {
        let _ = writeln!(
            out,
            "- `{}` has been invited to sign `{}`",
            invitation.user, invitation.role
        );
    }
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "Invitees: run `{SIGN_COMMAND} {event_name}` to add your key."
    );
    let _ = writeln!(out);
}

/// The one-line summary at the top of the report.
pub fn headline(status: &EventStatus) -> String {
    if status.roles.is_empty() {
        return "No metadata changes yet.".to_owned();
    }
    if !status.problems.is_empty() || status.roles.iter().any(|role| !role.problems.is_empty()) {
        return "This event cannot be merged: see the problems below.".to_owned();
    }
    if status.is_mergeable() {
        return "Fully signed and ready to merge.".to_owned();
    }

    let invitations = status.invitations().len();
    let outstanding = status.outstanding();
    match (invitations, outstanding) {
        (0, 0) => "Waiting on the signing event to be validated.".to_owned(),
        (0, 1) => "Waiting on 1 more signature.".to_owned(),
        (0, n) => format!("Waiting on {n} more signatures."),
        (1, 0) => "Waiting on 1 invitation to be accepted.".to_owned(),
        (i, 0) => format!("Waiting on {i} invitations to be accepted."),
        (i, n) => format!(
            "Waiting on {i} invitation(s) to be accepted and {n} signature(s) to be gathered."
        ),
    }
}

/// A short state word for one role, for a table cell.
pub fn role_state(role: &RoleStatus) -> &'static str {
    if !role.problems.is_empty() {
        "❌ invalid"
    } else if !role.blocking_invites.is_empty() {
        "✉️ awaiting keys"
    } else if role.is_complete() {
        "✅ signed"
    } else {
        "⏳ needs signatures"
    }
}

/// The signature count for one role, showing both thresholds where root has two.
pub fn signature_count(role: &RoleStatus) -> String {
    let current = format!("{}/{}", role.tally.signed.len(), role.tally.threshold);
    match &role.previous_tally {
        // Root has to satisfy the outgoing key set as well as the incoming one, so one
        // number cannot describe it.
        Some(previous) => format!(
            "{current} new, {}/{} previous",
            previous.signed.len(),
            previous.threshold
        ),
        None => current,
    }
}

/// A sentence describing what happened to a delegation.
pub fn describe_delegation(change: &DelegationChange) -> String {
    let describe = |quorum: &Quorum| {
        format!(
            "{} of {}",
            quorum.threshold,
            if quorum.signers.is_empty() {
                "no signers".to_owned()
            } else {
                quorum
                    .signers
                    .iter()
                    .map(|signer| format!("`{signer}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        )
    };

    match (&change.current, &change.previous) {
        (Some(current), None) => {
            format!(
                "new delegation `{}`, signed by {}",
                change.role,
                describe(current)
            )
        }
        (None, Some(_)) => format!("delegation `{}` removed", change.role),
        (Some(current), Some(previous)) => format!(
            "delegation `{}` now signed by {} (was {})",
            change.role,
            describe(current),
            describe(previous)
        ),
        (None, None) => format!("delegation `{}` unchanged", change.role),
    }
}

/// A count of artifact changes, e.g. "2 artifacts added, 1 removed".
pub fn summarize_artifacts(changes: &[ArtifactChange]) -> String {
    let count = |want: fn(&ArtifactChange) -> bool| changes.iter().filter(|c| want(c)).count();
    let added = count(|c| matches!(c, ArtifactChange::Added(_)));
    let modified = count(|c| matches!(c, ArtifactChange::Modified(_)));
    let removed = count(|c| matches!(c, ArtifactChange::Removed(_)));

    let mut parts = Vec::new();
    for (n, word) in [
        (added, "added"),
        (modified, "modified"),
        (removed, "removed"),
    ] {
        if n > 0 {
            parts.push(format!(
                "{n} artifact{} {word}",
                if n == 1 { "" } else { "s" }
            ));
        }
    }
    if parts.is_empty() {
        "no artifact changes".to_owned()
    } else {
        parts.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{ArtifactChange, Invitation};
    use crate::policy::RoleName;
    use crate::store::{SignerRef, Tally};

    fn signer(name: &str) -> SignerRef {
        SignerRef {
            key_id: crate::crypto::public_key(
                "-----BEGIN PUBLIC KEY-----\n\
                 MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmcIqt4wpIdBCFSZv7EuQkTr7lHjR\n\
                 kyR5EgRkaB5Am9Zc61orKQc9DiOTs5e9d84px3ebGh1NhzMGBUZHiGB1ow==\n\
                 -----END PUBLIC KEY-----\n",
            )
            .unwrap()
            .key_id()
            .clone(),
            name: name.to_owned(),
        }
    }

    fn role(signed: &[&str], missing: &[&str], threshold: u32) -> RoleStatus {
        RoleStatus {
            role: RoleName::targets(),
            version: 3,
            tally: Tally {
                role: RoleName::targets(),
                threshold,
                signed: signed.iter().map(|n| signer(n)).collect(),
                missing: missing.iter().map(|n| signer(n)).collect(),
                invalid: Vec::new(),
            },
            previous_tally: None,
            blocking_invites: Vec::new(),
            artifacts: Vec::new(),
            delegations: Vec::new(),
            problems: Vec::new(),
        }
    }

    #[test]
    fn a_complete_event_says_so() {
        let status = EventStatus {
            roles: vec![role(&["@alice", "@bob"], &[], 2)],
            invitations: Vec::new(),
            problems: Vec::new(),
        };
        assert_eq!(headline(&status), "Fully signed and ready to merge.");
        let rendered = markdown(&status, "sign/add-crates");
        assert!(rendered.contains("can be reviewed \nand merged.") || rendered.contains("merged."));
        assert!(rendered.contains("✅ signed"));
    }

    #[test]
    fn an_incomplete_event_counts_what_is_missing() {
        let status = EventStatus {
            roles: vec![role(&["@alice"], &["@bob"], 2)],
            invitations: Vec::new(),
            problems: Vec::new(),
        };
        assert_eq!(headline(&status), "Waiting on 1 more signature.");
        let rendered = markdown(&status, "sign/add-crates");
        assert!(rendered.contains("| 1/2 |"), "{rendered}");
        assert!(rendered.contains("`@bob`"));
        assert!(!rendered.contains("can be reviewed"));
        assert!(
            rendered.contains("tuf-sign sign/add-crates"),
            "a report that asks for signatures should say how to give one: {rendered}"
        );
    }

    #[test]
    fn problems_outrank_signature_counts() {
        let mut role = role(&["@alice", "@bob"], &[], 2);
        role.problems.push("targets is version 9, but …".into());
        let status = EventStatus {
            roles: vec![role],
            invitations: Vec::new(),
            problems: Vec::new(),
        };
        assert!(headline(&status).contains("cannot be merged"));
        assert!(markdown(&status, "sign/x").contains("#### Problems"));
    }

    #[test]
    fn invitations_are_called_out_with_the_command_that_answers_them() {
        let mut role = role(&[], &["@alice"], 1);
        role.blocking_invites.push(Invitation {
            user: "@bob".into(),
            role: RoleName::targets(),
        });
        let status = EventStatus {
            roles: vec![role],
            invitations: vec![Invitation {
                user: "@bob".into(),
                role: RoleName::targets(),
            }],
            problems: Vec::new(),
        };
        let rendered = markdown(&status, "sign/add-bob");
        assert!(rendered.contains("`@bob` has been invited"));
        assert!(rendered.contains("tuf-sign sign/add-bob"));
        assert!(rendered.contains("✉️ awaiting keys"));
    }

    #[test]
    fn root_shows_both_thresholds_because_it_has_to_satisfy_both() {
        let mut role = role(&["@alice"], &[], 1);
        role.role = RoleName::root();
        role.previous_tally = Some(Tally {
            role: RoleName::root(),
            threshold: 2,
            signed: vec![signer("@alice")],
            missing: vec![signer("@carol")],
            invalid: Vec::new(),
        });
        assert_eq!(signature_count(&role), "1/1 new, 1/2 previous");
        assert!(!role.is_complete());
        assert_eq!(role.outstanding(), 1);
        assert_eq!(role.waiting_on(), ["@carol"]);
    }

    #[test]
    fn artifact_counts_are_pluralised() {
        assert_eq!(
            summarize_artifacts(&[ArtifactChange::Added("a".into())]),
            "1 artifact added"
        );
        assert_eq!(
            summarize_artifacts(&[
                ArtifactChange::Added("a".into()),
                ArtifactChange::Added("b".into()),
                ArtifactChange::Removed("c".into()),
            ]),
            "2 artifacts added, 1 artifact removed"
        );
        assert_eq!(summarize_artifacts(&[]), "no artifact changes");
    }

    #[test]
    fn an_empty_event_explains_what_to_do_instead_of_showing_an_empty_table() {
        let status = EventStatus {
            roles: Vec::new(),
            invitations: Vec::new(),
            problems: Vec::new(),
        };
        let rendered = markdown(&status, "sign/empty");
        assert!(rendered.contains("changes no metadata yet"));
        assert!(!rendered.contains("| Role |"));
    }
}
