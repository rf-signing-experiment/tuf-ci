//! Signing with a YubiKey's PIV digital signature key.
//!
//! Only PIV slot 9c is used, and only ECDSA P-256. That is the slot the PIV specification
//! reserves for digital signatures, and the one that requires the PIN to be entered
//! immediately before *every* signature rather than once per session — which is what you
//! want from a key that authorises changes to a trust root.
//!
//! This talks to the card over PC/SC directly, so there is no PKCS#11 module to install and
//! no `PYKCS11LIB` to configure. It also reads the public key straight out of the slot,
//! so there is no need to generate a self-signed certificate first; the certificate is only
//! consulted as a fallback for firmware too old to report slot metadata.
//!
//! # Setting a key up
//!
//! ```shell
//! ykman piv keys generate --algorithm ECCP256 --touch-policy cached 9c public.pem
//! ```

#![deny(missing_docs)]

use std::fmt;

use sha2::{Digest, Sha256};
use spki::der::Encode;
use tuf_repo::crypto::KeyId;
use tuf_repo::metadata::Key;
use tuf_repo::signer::Signer;
use yubikey::piv::{AlgorithmId, ManagementAlgorithmId, SlotId};

// Re-exported, so a caller can describe what this crate reports without depending on the
// `yubikey` crate itself and risking a version skew between the two.
pub use yubikey::{PinPolicy, Serial, TouchPolicy, Version, YubiKey};

/// The PIV slot this tool signs with.
const SLOT: SlotId = SlotId::Signature;

/// Something that went wrong talking to a YubiKey.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// No YubiKey is plugged in.
    #[error("no YubiKey found: plug one in and try again")]
    NotFound,

    /// More than one YubiKey is plugged in and none was chosen.
    #[error("several YubiKeys are plugged in: choose one by serial number ({0})")]
    Ambiguous(String),

    /// Slot 9c holds no key.
    #[error(
        "this YubiKey has no key in PIV slot 9c. Create one with:\n    \
         ykman piv keys generate --algorithm ECCP256 --touch-policy cached 9c public.pem"
    )]
    NoKey,

    /// Slot 9c holds a key this tool cannot use.
    #[error("PIV slot 9c holds a {0} key, but this repository signs with ECDSA P-256")]
    WrongAlgorithm(String),

    /// Anything else the card or the PC/SC stack reported.
    #[error("YubiKey error: {0}")]
    Device(#[from] yubikey::Error),

    /// The key material could not be encoded.
    #[error("could not read the public key from PIV slot 9c: {0}")]
    Key(String),
}

/// A `Result` whose error is this crate's [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

/// A YubiKey that is plugged in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Device {
    /// The card reader's name, as the operating system reports it.
    pub reader: String,
    /// The YubiKey's serial number.
    pub serial: Serial,
    /// The firmware version.
    pub version: Version,
}

impl Device {
    fn of(reader: String, yubikey: &YubiKey) -> Self {
        Device {
            reader,
            serial: yubikey.serial(),
            version: yubikey.version(),
        }
    }

    /// The firmware version, as `ykman` writes it.
    pub fn firmware(&self) -> String {
        let Version {
            major,
            minor,
            patch,
        } = self.version;
        format!("{major}.{minor}.{patch}")
    }

    /// Whether the firmware reports what a key slot holds.
    ///
    /// Slot metadata arrived in firmware 5.3. Below that the public key has to come from a
    /// certificate written into the slot, which is why older keys need
    /// `ykman piv certificates generate` and newer ones do not.
    pub fn reports_slot_metadata(&self) -> bool {
        (self.version.major, self.version.minor) >= (5, 3)
    }
}

impl fmt::Display for Device {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "YubiKey #{} ({})", self.serial, self.reader)
    }
}

/// Every YubiKey currently plugged in.
pub fn devices() -> Result<Vec<Device>> {
    let mut context = yubikey::reader::Context::open()?;
    let mut devices = Vec::new();
    for reader in context.iter()? {
        let name = reader.name().into_owned();
        // A reader that is present but not answering is not worth failing over; it just is
        // not a YubiKey we can sign with.
        if let Ok(yubikey) = reader.open() {
            devices.push(Device::of(name, &yubikey));
        }
    }
    Ok(devices)
}

/// How this crate asks the person at the keyboard for a PIN, and tells them to touch.
///
/// The signing tool implements this with terminal prompts. Keeping it a trait means the
/// PIN never has to be passed in ahead of time and so never has to be held anywhere.
pub trait Prompt {
    /// Ask for the PIV PIN.
    ///
    /// `retries` is how many attempts remain before the PIN is blocked, when the card
    /// reports it.
    fn pin(&mut self, device: &Device, retries: Option<u8>) -> Result<String>;

    /// Tell the person to touch the key, because the card is waiting for it.
    fn touch(&mut self, device: &Device);
}

/// What PIV slot 9c holds.
#[derive(Clone, Debug)]
pub struct SlotKey {
    /// The public key, PEM encoded as a `SubjectPublicKeyInfo`.
    pub public_pem: String,
    /// The id the repository files this key under.
    pub key_id: KeyId,
    /// Whether the key requires a physical touch to sign.
    pub touch_policy: Option<TouchPolicy>,
    /// When the PIN must be presented.
    pub pin_policy: Option<PinPolicy>,
    /// Whether the key was read from slot metadata rather than from a certificate.
    pub from_slot_metadata: bool,
}

impl SlotKey {
    /// This key as a repository key belonging to `owner`.
    pub fn as_metadata_key(&self, owner: &str) -> tuf_repo::Result<(KeyId, Key)> {
        Key::from_pem(&self.public_pem, owner)
    }

    /// Whether signing will ask for a physical touch.
    ///
    /// `Default` for slot 9c means no touch, so an unset policy is reported as no touch
    /// rather than as unknown.
    pub fn needs_touch(&self) -> bool {
        matches!(
            self.touch_policy,
            Some(TouchPolicy::Always | TouchPolicy::Cached)
        )
    }

    /// Whether the PIN has to be presented before every single signature.
    ///
    /// Slot 9c defaults to this, which is the reason it is the slot this tool uses: each
    /// signature needs the cardholder there for it, rather than one PIN unlocking a
    /// session in which any number of things can be signed.
    pub fn pin_every_time(&self) -> bool {
        matches!(
            self.pin_policy,
            None | Some(PinPolicy::Default | PinPolicy::Always)
        )
    }
}

/// Open a YubiKey.
///
/// With no serial number, opens the only one plugged in and reports [`Error::Ambiguous`]
/// if there is more than one — signing with whichever key happened to be enumerated first
/// is never what somebody meant.
pub fn open(serial: Option<Serial>) -> Result<YubiKey> {
    match serial {
        Some(serial) => YubiKey::open_by_serial(serial).map_err(|err| match err {
            yubikey::Error::NotFound => Error::NotFound,
            other => Error::Device(other),
        }),
        None => {
            let devices = devices()?;
            match devices.len() {
                0 => Err(Error::NotFound),
                1 => open(Some(devices[0].serial)),
                _ => Err(Error::Ambiguous(
                    devices
                        .iter()
                        .map(|device| device.serial.to_string())
                        .collect::<Vec<_>>()
                        .join(", "),
                )),
            }
        }
    }
}

/// Read the public key in PIV slot 9c.
///
/// Modern firmware reports the public key as slot metadata. Older firmware does not, so
/// fall back to the certificate in the slot, which is what `ykman piv certificates
/// generate` puts there.
pub fn slot_key(yubikey: &mut YubiKey) -> Result<SlotKey> {
    let (spki_pem, policy, from_slot_metadata) = match yubikey::piv::metadata(yubikey, SLOT) {
        Ok(metadata) => {
            match metadata.algorithm {
                ManagementAlgorithmId::Asymmetric(AlgorithmId::EccP256) => {}
                other => return Err(Error::WrongAlgorithm(describe_algorithm(other))),
            }
            let public = metadata.public.ok_or(Error::NoKey)?;
            let pem = spki_to_pem(&public)?;
            (pem, metadata.policy, true)
        }
        Err(_) => {
            let certificate =
                yubikey::certificate::Certificate::read(yubikey, SLOT).map_err(|_| Error::NoKey)?;
            let der = certificate
                .subject_pki()
                .to_der()
                .map_err(|err| Error::Key(err.to_string()))?;
            let pem = der_to_pem(&der)?;
            (pem, None, false)
        }
    };

    let key_id = KeyId::for_pem(&spki_pem).map_err(|err| Error::Key(err.to_string()))?;
    Ok(SlotKey {
        public_pem: spki_pem,
        key_id,
        touch_policy: policy.map(|(_, touch)| touch),
        pin_policy: policy.map(|(pin, _)| pin),
        from_slot_metadata,
    })
}

/// PEM-encode a parsed `SubjectPublicKeyInfo`.
fn spki_to_pem(spki: &spki::SubjectPublicKeyInfoOwned) -> Result<String> {
    let der = spki.to_der().map_err(|err| Error::Key(err.to_string()))?;
    der_to_pem(&der)
}

/// Wrap DER `SubjectPublicKeyInfo` bytes in a `PUBLIC KEY` PEM block.
fn der_to_pem(der: &[u8]) -> Result<String> {
    spki::der::pem::encode_string("PUBLIC KEY", spki::der::pem::LineEnding::LF, der)
        .map_err(|err| Error::Key(err.to_string()))
}

fn describe_algorithm(algorithm: ManagementAlgorithmId) -> String {
    match algorithm {
        ManagementAlgorithmId::Asymmetric(AlgorithmId::Rsa1024) => "1024-bit RSA".into(),
        ManagementAlgorithmId::Asymmetric(AlgorithmId::Rsa2048) => "2048-bit RSA".into(),
        ManagementAlgorithmId::Asymmetric(AlgorithmId::EccP256) => "ECDSA P-256".into(),
        ManagementAlgorithmId::Asymmetric(AlgorithmId::EccP384) => "ECDSA P-384".into(),
        ManagementAlgorithmId::ThreeDes => "3DES".into(),
        ManagementAlgorithmId::PinPuk => "PIN/PUK".into(),
    }
}

/// Signs with the key in PIV slot 9c.
pub struct YubikeySigner<P: Prompt> {
    yubikey: YubiKey,
    device: Device,
    key: SlotKey,
    prompt: P,
}

impl<P: Prompt> YubikeySigner<P> {
    /// Open a YubiKey and prepare to sign with slot 9c.
    pub fn open(serial: Option<Serial>, prompt: P) -> Result<Self> {
        let mut yubikey = open(serial)?;
        let device = Device::of(yubikey.name().to_owned(), &yubikey);
        let key = slot_key(&mut yubikey)?;
        Ok(YubikeySigner {
            yubikey,
            device,
            key,
            prompt,
        })
    }

    /// The YubiKey being signed with.
    pub fn device(&self) -> &Device {
        &self.device
    }

    /// What slot 9c holds.
    pub fn key(&self) -> &SlotKey {
        &self.key
    }
}

impl<P: Prompt> Signer for YubikeySigner<P> {
    fn public_key_pem(&self) -> &str {
        &self.key.public_pem
    }

    fn key_id(&self) -> &KeyId {
        &self.key.key_id
    }

    fn sign(&mut self, message: &[u8]) -> tuf_repo::Result<Vec<u8>> {
        // Slot 9c is PIN-ALWAYS: the PIN has to be presented immediately before the
        // signature, with nothing in between, so this cannot be hoisted out.
        let retries = self.yubikey.get_pin_retries().ok();
        let pin = self
            .prompt
            .pin(&self.device, retries)
            .map_err(|err| tuf_repo::Error::Invalid(err.to_string()))?;

        self.yubikey.verify_pin(pin.as_bytes()).map_err(|err| {
            let remaining = self.yubikey.get_pin_retries().ok();
            tuf_repo::Error::Invalid(describe_pin_failure(err, remaining))
        })?;

        if self.key.needs_touch() {
            self.prompt.touch(&self.device);
        }

        // PIV signs a digest the host computes, sized to the curve.
        let digest = Sha256::digest(message);
        let signature =
            yubikey::piv::sign_data(&mut self.yubikey, &digest, AlgorithmId::EccP256, SLOT)
                .map_err(|err| tuf_repo::Error::Invalid(describe_sign_failure(err)))?;

        Ok(signature.to_vec())
    }
}

fn describe_pin_failure(err: yubikey::Error, retries: Option<u8>) -> String {
    match err {
        yubikey::Error::WrongPin { tries } => {
            format!("incorrect PIN: {tries} attempt(s) left before the key is blocked")
        }
        yubikey::Error::PinLocked => {
            "the PIV PIN is blocked. Unblock it with `ykman piv access unblock-pin`".into()
        }
        other => match retries {
            Some(0) => format!("{other} (the PIV PIN is blocked)"),
            Some(tries) => format!("{other} ({tries} PIN attempt(s) left)"),
            None => other.to_string(),
        },
    }
}

fn describe_sign_failure(err: yubikey::Error) -> String {
    match err {
        // The card reports a missing touch as a security-status failure, which on its own
        // reads as though the PIN was wrong even though it was just accepted.
        yubikey::Error::AuthenticationError => {
            "the YubiKey did not produce a signature, most likely because it was not \
             touched in time. Try again and touch the key when it blinks"
                .into()
        }
        yubikey::Error::NotFound => "the YubiKey was removed before it finished signing".into(),
        other => format!("signing failed: {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every error a signer can hit should say what to do next, not just what happened.
    #[test]
    fn error_messages_are_actionable() {
        assert!(Error::NoKey.to_string().contains("ykman piv keys generate"));
        assert!(
            Error::Ambiguous("1, 2".into())
                .to_string()
                .contains("serial number")
        );
        assert!(describe_pin_failure(yubikey::Error::PinLocked, None).contains("ykman piv access"));
        assert!(
            describe_sign_failure(yubikey::Error::AuthenticationError).contains("touched"),
            "a missing touch must not be reported as an authentication failure"
        );
    }

    fn device(major: u8, minor: u8, patch: u8) -> Device {
        Device {
            reader: "reader".into(),
            serial: 12345678.into(),
            version: Version {
                major,
                minor,
                patch,
            },
        }
    }

    fn slot_key(touch: Option<TouchPolicy>, pin: Option<PinPolicy>) -> SlotKey {
        SlotKey {
            public_pem: String::new(),
            key_id: KeyId::for_pem(
                "-----BEGIN PUBLIC KEY-----\n\
                 MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmcIqt4wpIdBCFSZv7EuQkTr7lHjR\n\
                 kyR5EgRkaB5Am9Zc61orKQc9DiOTs5e9d84px3ebGh1NhzMGBUZHiGB1ow==\n\
                 -----END PUBLIC KEY-----\n",
            )
            .unwrap(),
            touch_policy: touch,
            pin_policy: pin,
            from_slot_metadata: true,
        }
    }

    #[test]
    fn slot_metadata_support_is_decided_by_firmware_version() {
        assert!(device(5, 3, 0).reports_slot_metadata());
        assert!(device(5, 4, 3).reports_slot_metadata());
        assert!(device(6, 0, 0).reports_slot_metadata());
        assert!(!device(5, 2, 7).reports_slot_metadata());
        assert!(!device(4, 4, 5).reports_slot_metadata());
        assert_eq!(device(5, 4, 3).firmware(), "5.4.3");
    }

    #[test]
    fn touch_is_expected_only_when_the_policy_asks_for_it() {
        assert!(slot_key(Some(TouchPolicy::Always), None).needs_touch());
        assert!(slot_key(Some(TouchPolicy::Cached), None).needs_touch());
        assert!(!slot_key(Some(TouchPolicy::Never), None).needs_touch());
        // Slot 9c's default is no touch, and an unreadable policy must not make the tool
        // sit waiting for one that will never come.
        assert!(!slot_key(Some(TouchPolicy::Default), None).needs_touch());
        assert!(!slot_key(None, None).needs_touch());
    }

    #[test]
    fn the_pin_is_assumed_to_be_needed_every_time_unless_told_otherwise() {
        assert!(slot_key(None, Some(PinPolicy::Always)).pin_every_time());
        assert!(slot_key(None, Some(PinPolicy::Default)).pin_every_time());
        // Unknown policy: assume the stricter behaviour, since presenting the PIN when it
        // was not needed costs a prompt, and not presenting it fails the signature.
        assert!(slot_key(None, None).pin_every_time());
        assert!(!slot_key(None, Some(PinPolicy::Once)).pin_every_time());
        assert!(!slot_key(None, Some(PinPolicy::Never)).pin_every_time());
    }

    #[test]
    fn algorithms_are_named_the_way_ykman_names_them() {
        assert_eq!(
            describe_algorithm(ManagementAlgorithmId::Asymmetric(AlgorithmId::Rsa2048)),
            "2048-bit RSA"
        );
    }
}
