//! Key identity and signature verification.
//!
//! Both are the `tuf` crate's. A key is parsed as a [`tuf::crypto::PublicKey`], which names
//! itself:
//!
//! ```text
//! key_id = hex(sha256(DER SubjectPublicKeyInfo))
//! ```
//!
//! POUF-2 says a key id is an opaque string and that nothing may be inferred from its
//! contents. Deriving it from the key material alone — rather than from the whole JSON key
//! object, as the TUF spec's canonical key id does — means annotations such as
//! `x-tuf-ci-owner` can be added to a key without renaming it.
//!
//! Using the same code a client uses is the point of the dependency: an id this crate files
//! a key under, and a signature it accepts, cannot drift from what a client computes.

use sha2::{Digest, Sha256};
use tuf::crypto::{KeyType, PublicKey, SignatureScheme};

pub use tuf::crypto::KeyId;

use crate::error::{Error, Result};

/// The scheme name for ECDSA over NIST P-256 with SHA-256, the only scheme this crate
/// signs with. Keys using any other scheme are kept and written back out untouched.
pub const ECDSA_SHA2_NISTP256: &str = "ecdsa-sha2-nistp256";

/// The `keytype` that accompanies [`ECDSA_SHA2_NISTP256`].
pub const KEYTYPE_ECDSA: &str = "ecdsa";

/// The id of the P-256 key held in a PEM-encoded `SubjectPublicKeyInfo`.
///
/// For a key that already exists in metadata, derive its id with
/// [`Key::derived_key_id`](crate::metadata::Key::derived_key_id) instead, which uses the
/// key's own declared type rather than assuming this one.
pub fn key_id(pem: &str) -> Result<KeyId> {
    Ok(parse(KEYTYPE_ECDSA, ECDSA_SHA2_NISTP256, pem)?
        .key_id()
        .clone())
}

/// The first 12 characters of a key id, for display in a terminal or a pull request.
pub fn abbreviated(key_id: &KeyId) -> &str {
    let id = key_id.as_str();
    let end = id.char_indices().nth(12).map_or(id.len(), |(idx, _)| idx);
    &id[..end]
}

/// Parse a PEM `SubjectPublicKeyInfo` as a key of the given type and scheme.
///
/// The declared type is checked against the key material, so metadata claiming a key is
/// something it is not is rejected here rather than at signature verification.
pub fn parse(keytype: &str, scheme: &str, pem: &str) -> Result<PublicKey> {
    PublicKey::from_pem(pem, KeyType::new(keytype), SignatureScheme::new(scheme))
        .map_err(|err| Error::encoding(format!("not a usable {keytype} public key: {err}")))
}

/// Verify `signature` over `message` with the key described by `keytype`, `scheme` and
/// `pem`.
///
/// A scheme this crate cannot check is an error rather than a silent pass: a signature that
/// has not been checked has not been checked.
pub fn verify(
    keytype: &str,
    scheme: &str,
    pem: &str,
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    parse(keytype, scheme, pem)?
        .verify_bytes(message, signature)
        .map_err(Error::invalid)
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
        // Hard-coded rather than recomputed, because this is the name a key already has in
        // repositories that exist: it is checked against `openssl pkey -pubin -outform DER
        // | sha256sum`, and changing it would orphan every signature in them.
        assert_eq!(
            key_id(TEST_PEM).unwrap().as_str(),
            "bd828d85ebaa1d4a1e59773e5056d384b87f98db8604b77f76af056d36b8e6f9",
        );
        assert_eq!(abbreviated(&key_id(TEST_PEM).unwrap()).len(), 12);
    }

    #[test]
    fn key_id_ignores_pem_formatting() {
        // Same key, with CRLF line endings.
        let rewrapped = TEST_PEM.replace('\n', "\r\n");
        assert_eq!(key_id(TEST_PEM).unwrap(), key_id(&rewrapped).unwrap());
    }

    #[test]
    fn the_scheme_and_key_type_this_crate_writes_are_the_ones_tuf_knows() {
        // These are written into metadata as strings, so they have to match the names the
        // library parses back, not merely look like them.
        assert_eq!(
            SignatureScheme::new(ECDSA_SHA2_NISTP256),
            SignatureScheme::EcdsaSha2NistP256
        );
        assert_eq!(KeyType::new(KEYTYPE_ECDSA), KeyType::Ecdsa);
    }

    #[test]
    fn unsupported_scheme_is_refused_rather_than_ignored() {
        let err = verify(KEYTYPE_ECDSA, "ed25519", TEST_PEM, b"payload", b"sig").unwrap_err();
        assert!(err.to_string().contains("ed25519"), "{err}");
    }

    #[test]
    fn a_key_that_is_not_what_the_metadata_claims_is_refused() {
        let err = verify("ed25519", ECDSA_SHA2_NISTP256, TEST_PEM, b"payload", b"sig").unwrap_err();
        assert!(err.to_string().contains("ed25519"), "{err}");
    }

    #[test]
    fn garbage_is_not_a_public_key() {
        assert!(key_id("not a pem").is_err());
    }
}
