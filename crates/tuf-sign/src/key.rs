//! `tuf-sign key`: what is on the YubiKey, and is it ready to sign.
//!
//! Deliberately independent of everything else: no git repository, no configuration, no
//! network. It is the thing to run when a signer says "it isn't working" and nobody yet
//! knows whether the problem is the key, the repository or the tool.
//!
//! It also answers the question that comes up during a signing event — *is the key in my
//! hand the one the metadata is waiting for?* — by printing the same key id the repository
//! files the key under.

use anyhow::{Context, Result, bail};
use owo_colors::OwoColorize;

use tuf_repo::signer::Signer as _;
use tuf_yubikey::{Device, PinPolicy, SlotKey, TouchPolicy};

use crate::ui;

/// The message signed by `--sign-test`.
///
/// Not repository metadata and not a DSSE pre-authentication encoding, so a signature over
/// it can never be mistaken for a signature over anything that matters.
const TEST_MESSAGE: &[u8] = b"tuf-sign key --sign-test";

/// Print what is on the attached YubiKeys.
pub fn run(serial: Option<u32>, sign_test: bool, pem_only: bool) -> Result<()> {
    let devices = tuf_yubikey::devices().context("could not enumerate smart card readers")?;

    let selected: Vec<Device> = match serial {
        Some(serial) => devices
            .iter()
            .filter(|device| u32::from(device.serial) == serial)
            .cloned()
            .collect(),
        None => devices.clone(),
    };

    if selected.is_empty() {
        match (devices.is_empty(), serial) {
            (true, _) => bail!(
                "no YubiKey found. Plug one in; if it is already plugged in, check that the \
                 pcscd service is running"
            ),
            (false, Some(serial)) => bail!(
                "no YubiKey with serial {serial}. Attached: {}",
                devices
                    .iter()
                    .map(|device| device.serial.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            (false, None) => unreachable!("devices is non-empty and no serial was given"),
        }
    }

    // In --pem mode nothing but the key goes to stdout, so the output can be redirected
    // into a file or pasted into an invitation.
    if pem_only {
        if selected.len() > 1 {
            bail!(
                "several YubiKeys are attached; choose one with --serial ({})",
                selected
                    .iter()
                    .map(|device| device.serial.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        let mut yubikey = tuf_yubikey::open(Some(selected[0].serial))?;
        let key = tuf_yubikey::slot_key(&mut yubikey)?;
        print!("{}", key.public_pem);
        return Ok(());
    }

    let mut ready = 0usize;
    for device in &selected {
        if report(device, sign_test)? {
            ready += 1;
        }
    }

    if ready == 0 {
        bail!("no attached YubiKey is ready to sign");
    }
    Ok(())
}

/// Print one device's details. Returns whether it can sign.
fn report(device: &Device, sign_test: bool) -> Result<bool> {
    ui::heading(&device.to_string());
    println!("  {:<14}{}", "Firmware", device.firmware());

    let mut yubikey = match tuf_yubikey::open(Some(device.serial)) {
        Ok(yubikey) => yubikey,
        Err(err) => {
            println!("  {} {err}", "✗".red());
            return Ok(false);
        }
    };

    let key = match tuf_yubikey::slot_key(&mut yubikey) {
        Ok(key) => key,
        Err(err) => {
            // The error types already carry the remedy — a missing key names the ykman
            // command that creates one — so there is nothing to add here.
            println!("\n  {} {err}", "✗".red());
            return Ok(false);
        }
    };

    println!("\n  {}", "PIV slot 9c (Digital Signature)".bold());
    println!("  {:<14}ECDSA P-256", "Algorithm");
    println!("  {:<14}{}", "Key id", key.key_id());
    println!("  {:<14}{}", "PIN policy", describe_pin(&key));
    println!("  {:<14}{}", "Touch policy", describe_touch(&key));
    println!("  {:<14}{}", "Read from", source(&key, device));
    println!();
    for line in key.public_pem.lines() {
        println!("  {line}");
    }

    if !key.pin_every_time() {
        ui::warn(
            "This key does not require the PIN before every signature. Slot 9c normally \
             does, and it is what makes each signature a deliberate act.",
        );
    }

    if sign_test {
        println!();
        return verify_signing(device, &key);
    }

    println!();
    ui::success("Ready to sign. Add --sign-test to check the PIN and touch as well.");
    Ok(true)
}

/// Sign a fixed message and check the signature against the slot's own public key.
///
/// This exercises everything a real signature does — PIN entry, the touch, the card's DER
/// encoding and the verification path — without a repository in the picture. If this works
/// and signing a role does not, the problem is not the key.
fn verify_signing(device: &Device, key: &SlotKey) -> Result<bool> {
    ui::info("Signing a test message to check the PIN and touch.");

    let mut signer = match tuf_yubikey::YubikeySigner::open(Some(device.serial), ui::TerminalPrompt)
    {
        Ok(signer) => signer,
        Err(err) => {
            println!("  {} {err}", "✗".red());
            return Ok(false);
        }
    };

    let signature = match signer.sign(TEST_MESSAGE) {
        Ok(signature) => signature,
        Err(err) => {
            println!("  {} {err}", "✗".red());
            return Ok(false);
        }
    };

    match key.public_key.verify_bytes(TEST_MESSAGE, &signature) {
        Ok(()) => {
            ui::success(&format!(
                "Signed and verified ({} byte signature).",
                signature.len()
            ));
            Ok(true)
        }
        Err(err) => {
            // The card produced something, but not something this key can verify. That
            // means the slot's advertised public key and its private key disagree.
            println!(
                "  {} the signature does not verify against slot 9c's own public key: {err}",
                "✗".red()
            );
            Ok(false)
        }
    }
}

fn describe_pin(key: &SlotKey) -> String {
    match key.pin_policy {
        Some(PinPolicy::Always) => "required before every signature".into(),
        Some(PinPolicy::Default) => "required before every signature (slot default)".into(),
        Some(PinPolicy::Once) => "required once per session".into(),
        Some(PinPolicy::Never) => "not required".into(),
        None => "not reported; assuming it is required every time".into(),
    }
}

fn describe_touch(key: &SlotKey) -> String {
    match key.touch_policy {
        Some(TouchPolicy::Always) => "required for every signature".into(),
        Some(TouchPolicy::Cached) => "required, then cached for 15 seconds".into(),
        Some(TouchPolicy::Never) => "not required".into(),
        Some(TouchPolicy::Default) => "not required (slot default)".into(),
        None => "not reported".into(),
    }
}

fn source(key: &SlotKey, device: &Device) -> String {
    if key.from_slot_metadata {
        "slot metadata".into()
    } else if device.reports_slot_metadata() {
        "the slot certificate (slot metadata was unreadable)".into()
    } else {
        format!(
            "the slot certificate (firmware {} predates slot metadata)",
            device.firmware()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tuf_repo::crypto;

    fn slot_key(pin: Option<PinPolicy>, touch: Option<TouchPolicy>, meta: bool) -> SlotKey {
        SlotKey {
            public_pem: String::new(),
            public_key: crypto::public_key(
                "-----BEGIN PUBLIC KEY-----\n\
                 MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmcIqt4wpIdBCFSZv7EuQkTr7lHjR\n\
                 kyR5EgRkaB5Am9Zc61orKQc9DiOTs5e9d84px3ebGh1NhzMGBUZHiGB1ow==\n\
                 -----END PUBLIC KEY-----\n",
            )
            .unwrap(),
            touch_policy: touch,
            pin_policy: pin,
            from_slot_metadata: meta,
        }
    }

    fn device(major: u8, minor: u8) -> Device {
        Device {
            reader: "reader".into(),
            serial: 12345678.into(),
            version: tuf_yubikey::Version {
                major,
                minor,
                patch: 0,
            },
        }
    }

    #[test]
    fn policies_are_described_in_terms_of_what_the_signer_will_experience() {
        assert!(describe_pin(&slot_key(Some(PinPolicy::Always), None, true)).contains("every"));
        assert!(describe_pin(&slot_key(Some(PinPolicy::Once), None, true)).contains("once"));
        assert!(describe_pin(&slot_key(None, None, true)).contains("assuming"));
        assert!(
            describe_touch(&slot_key(None, Some(TouchPolicy::Cached), true)).contains("15 seconds")
        );
        assert!(describe_touch(&slot_key(None, Some(TouchPolicy::Never), true)).contains("not"));
    }

    #[test]
    fn a_certificate_fallback_says_why_it_happened() {
        // Old firmware: expected, and explained by the version.
        let old = source(&slot_key(None, None, false), &device(5, 2));
        assert!(old.contains("predates"), "{old}");

        // New firmware falling back is a surprise worth naming, since it means slot
        // metadata could not be read rather than that it does not exist.
        let new = source(&slot_key(None, None, false), &device(5, 4));
        assert!(new.contains("unreadable"), "{new}");

        assert_eq!(
            source(&slot_key(None, None, true), &device(5, 4)),
            "slot metadata"
        );
    }
}
