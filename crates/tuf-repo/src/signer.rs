//! The interface between the repository model and whatever holds a private key.
//!
//! Keeping this a trait is what lets the state machine be tested without a YubiKey
//! plugged in: [`crate::testing::MemorySigner`] implements it with a software key, and
//! `tuf-yubikey` implements it with PIV slot 9c.

use crate::crypto::KeyId;
use crate::error::Result;

/// Something that can produce signatures with one key.
pub trait Signer {
    /// The PEM-encoded `SubjectPublicKeyInfo` of the key this signer holds.
    fn public_key_pem(&self) -> &str;

    /// The id the public key is filed under, derived from the key material.
    fn key_id(&self) -> &KeyId;

    /// Sign `message`.
    ///
    /// `message` is the DSSE pre-authentication encoding of a payload, not a digest: a
    /// signer that needs a digest (as PIV does) computes it itself. The returned bytes are
    /// a DER-encoded ECDSA signature.
    fn sign(&mut self, message: &[u8]) -> Result<Vec<u8>>;
}

impl<T: Signer + ?Sized> Signer for Box<T> {
    fn public_key_pem(&self) -> &str {
        (**self).public_key_pem()
    }

    fn key_id(&self) -> &KeyId {
        (**self).key_id()
    }

    fn sign(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        (**self).sign(message)
    }
}
