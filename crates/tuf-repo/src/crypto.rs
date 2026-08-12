//! Key identity, key parsing, and signature verification.
//!
//! POUF-2 says a key id is an opaque string and that nothing may be inferred from its
//! contents. We take that at its word and name a key by the hash of its own key material:
//!
//! ```text
//! key_id = hex(sha256(DER SubjectPublicKeyInfo))
//! ```
//!
//! Deriving the id from the key alone — rather than from the whole JSON key object, as the
//! TUF spec's canonical key id does — means annotations such as
//! `x-tuf-ci-owner` can be added to a key without renaming it.

use std::fmt;
use std::str::FromStr;

use p256::ecdsa::signature::Verifier as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use spki::SubjectPublicKeyInfoOwned;
use spki::der::{DecodePem, Encode};

use crate::error::{Error, Result};

/// The scheme name for ECDSA over NIST P-256 with SHA-256, the only scheme this crate can
/// verify. Keys using any other scheme are kept and written back out untouched, but they
/// can never verify anything.
pub const ECDSA_SHA2_NISTP256: &str = "ecdsa-sha2-nistp256";

/// The `keytype` that accompanies [`ECDSA_SHA2_NISTP256`].
pub const KEYTYPE_ECDSA: &str = "ecdsa";

/// An opaque name for a public key.
///
/// Construct one with [`KeyId::for_pem`], which derives it from the key material, or parse
/// one out of existing metadata. Nothing may be inferred from the contents.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KeyId(String);

impl KeyId {
    /// Derive the id of the key held in a PEM-encoded `SubjectPublicKeyInfo`.
    ///
    /// The PEM is re-encoded to DER before hashing, so the id does not depend on how the
    /// PEM happened to be line-wrapped or labelled.
    pub fn for_pem(pem: &str) -> Result<Self> {
        let der = spki_der(pem)?;
        Ok(KeyId(hex::encode(Sha256::digest(&der))))
    }

    /// The id as it appears in metadata.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The first 12 characters, for display in a terminal or a PR comment.
    pub fn abbreviated(&self) -> &str {
        let end = self
            .0
            .char_indices()
            .nth(12)
            .map_or(self.0.len(), |(idx, _)| idx);
        &self.0[..end]
    }
}

impl FromStr for KeyId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        if s.is_empty() {
            return Err(Error::invalid("key id is empty"));
        }
        Ok(KeyId(s.to_owned()))
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyId({})", self.0)
    }
}

/// Decode a PEM `SubjectPublicKeyInfo` and re-encode it as DER.
fn spki_der(pem: &str) -> Result<Vec<u8>> {
    let spki = SubjectPublicKeyInfoOwned::from_pem(pem.as_bytes())
        .map_err(|err| Error::encoding(format!("not a PEM public key: {err}")))?;
    spki.to_der()
        .map_err(|err| Error::encoding(format!("public key cannot be re-encoded: {err}")))
}

/// Verify `signature` over `message` with the key held in `pem`.
///
/// `scheme` selects the algorithm. An unrecognised scheme is an error rather than a
/// silent pass: a signature this crate cannot check has not been checked.
pub fn verify(scheme: &str, pem: &str, message: &[u8], signature: &[u8]) -> Result<()> {
    match scheme {
        ECDSA_SHA2_NISTP256 => verify_ecdsa_p256(pem, message, signature),
        other => Err(Error::invalid(format!(
            "cannot verify signatures with unsupported scheme {other:?}"
        ))),
    }
}

fn verify_ecdsa_p256(pem: &str, message: &[u8], signature: &[u8]) -> Result<()> {
    use p256::ecdsa::{Signature, VerifyingKey};
    use p256::pkcs8::DecodePublicKey;

    let key = VerifyingKey::from_public_key_pem(pem)
        .map_err(|err| Error::invalid(format!("not a P-256 public key: {err}")))?;
    // PIV, and securesystemslib before it, emit DER-encoded ECDSA signatures.
    let signature = Signature::from_der(signature)
        .map_err(|err| Error::invalid(format!("not a DER ECDSA signature: {err}")))?;

    key.verify(message, &signature)
        .map_err(|_| Error::invalid("signature does not verify"))
}

/// Hex-encoded SHA-256 of `bytes`, the hash form used for artifact digests.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// SHA-256 of `bytes`, for handing to a signing device that signs a pre-computed digest.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A P-256 key generated for these tests only.
    pub(crate) const TEST_PEM: &str = "\
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmcIqt4wpIdBCFSZv7EuQkTr7lHjR
kyR5EgRkaB5Am9Zc61orKQc9DiOTs5e9d84px3ebGh1NhzMGBUZHiGB1ow==
-----END PUBLIC KEY-----
";

    #[test]
    fn key_id_is_the_hash_of_the_der_key() {
        let key_id = KeyId::for_pem(TEST_PEM).unwrap();
        let expected = hex::encode(Sha256::digest(spki_der(TEST_PEM).unwrap()));
        assert_eq!(key_id.as_str(), expected);
        assert_eq!(key_id.abbreviated().len(), 12);
    }

    #[test]
    fn key_id_ignores_pem_formatting() {
        // Same key, wrapped at a different width and without a trailing newline.
        let rewrapped = TEST_PEM.replace('\n', "\r\n");
        assert_eq!(
            KeyId::for_pem(TEST_PEM).unwrap(),
            KeyId::for_pem(&rewrapped).unwrap(),
        );
    }

    #[test]
    fn unsupported_scheme_is_refused_rather_than_ignored() {
        let err = verify("ed25519", TEST_PEM, b"payload", b"sig").unwrap_err();
        assert!(err.to_string().contains("unsupported scheme"), "{err}");
    }

    #[test]
    fn garbage_is_not_a_public_key() {
        assert!(KeyId::for_pem("not a pem").is_err());
    }
}
