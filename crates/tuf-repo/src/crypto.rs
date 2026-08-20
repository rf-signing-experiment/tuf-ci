//! Key identity and signature verification.
//!
//! A key is a [`tuf::crypto::PublicKey`], which names itself:
//!
//! ```text
//! key_id = hex(sha256(DER SubjectPublicKeyInfo))
//! ```
//!
//! POUF-2 says a key id is an opaque string and that nothing may be inferred from its
//! contents. Deriving it from the key material alone means a key can be annotated —
//! recording who holds it, say — without being renamed, which is why this project keeps
//! those annotations beside the key rather than inside it. See [`crate::policy`].
//!
//! Using the same code a client uses is the point of the dependency: an id this crate
//! files a key under, and a signature it accepts, cannot drift from what a client computes.

use sha2::{Digest, Sha256};
use tuf::crypto::{KeyType, SignatureScheme};

pub use tuf::crypto::{KeyId, PublicKey};

use crate::error::{Error, Result};

/// The scheme this project signs with: ECDSA over NIST P-256 with SHA-256.
pub const SCHEME: SignatureScheme = SignatureScheme::EcdsaSha2NistP256;

/// Read a PEM-encoded `SubjectPublicKeyInfo` as a signing key.
pub fn public_key(pem: &str) -> Result<PublicKey> {
    PublicKey::from_pem(pem, KeyType::Ecdsa, SCHEME)
        .map_err(|err| Error::encoding(format!("not a usable public key: {err}")))
}

/// The id `key`'s own material gives it, ignoring the one it was filed under.
///
/// Parsing keeps the key id the metadata wrote, because key ids are opaque and a
/// repository is free to name a key anything. That is the right default and the wrong one
/// for checking: a key filed under a name that is not its own is how one key comes to be
/// listed twice, and counts twice towards a threshold. So this recomputes from the key
/// material and lets the caller compare.
pub fn derived_key_id(key: &PublicKey) -> Result<KeyId> {
    let spki = key
        .as_spki()
        .map_err(|err| Error::encoding(format!("key cannot be re-encoded: {err}")))?;
    let recomputed = PublicKey::from_spki(&spki, key.scheme().clone())
        .map_err(|err| Error::encoding(format!("key cannot be read back: {err}")))?;
    Ok(recomputed.key_id().clone())
}

/// The first 12 characters of a key id, for display in a terminal or a pull request.
pub fn abbreviated(key_id: &KeyId) -> &str {
    let id = key_id.as_str();
    let end = id.char_indices().nth(12).map_or(id.len(), |(idx, _)| idx);
    &id[..end]
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
    fn a_key_is_named_by_the_hash_of_its_own_material() {
        // Hard-coded rather than recomputed, because this is the name the key already has
        // in repositories that exist: it matches `openssl pkey -pubin -outform DER |
        // sha256sum`, and changing it would orphan every signature made under it.
        let key = public_key(TEST_PEM).unwrap();
        assert_eq!(
            key.key_id().as_str(),
            "bd828d85ebaa1d4a1e59773e5056d384b87f98db8604b77f76af056d36b8e6f9",
        );
        assert_eq!(abbreviated(key.key_id()).len(), 12);
    }

    #[test]
    fn a_key_id_ignores_pem_formatting() {
        let rewrapped = TEST_PEM.replace('\n', "\r\n");
        assert_eq!(
            public_key(TEST_PEM).unwrap().key_id(),
            public_key(&rewrapped).unwrap().key_id()
        );
    }

    #[test]
    fn garbage_is_not_a_public_key() {
        assert!(public_key("not a pem").is_err());
    }
}
