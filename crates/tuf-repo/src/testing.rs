//! A software signer, for tests.
//!
//! Behind the `testing` feature, because a tool whose whole point is that private keys
//! live on hardware should not ship a way to keep one in a file.
//!
//! Keys are derived from a name rather than generated randomly, so a test that signs the
//! same metadata twice gets the same bytes both times, and a fixture's key ids stay put
//! across runs.

use p256::ecdsa::signature::Signer as _;
use p256::pkcs8::EncodePublicKey;
use tuf::crypto::PublicKey;

use crate::crypto;
use crate::error::Result;
use crate::signer::Signer;

/// A signer holding a private key in memory.
#[derive(Clone)]
pub struct MemorySigner {
    signing_key: p256::ecdsa::SigningKey,
    public_key: PublicKey,
    public_pem: String,
    owner: String,
}

impl MemorySigner {
    /// Derive a signer for `owner` from the owner's name.
    ///
    /// The same name always yields the same key.
    pub fn for_owner(owner: &str) -> Self {
        let seed = crypto::sha256(owner.as_bytes());
        let signing_key = p256::ecdsa::SigningKey::from_bytes(&seed.into())
            .expect("sha256 output is a valid P-256 scalar");
        let public_pem = signing_key
            .verifying_key()
            .to_public_key_pem(p256::pkcs8::LineEnding::LF)
            .expect("a P-256 public key is encodable");
        let public_key = crypto::public_key(&public_pem).expect("a freshly encoded key parses");

        MemorySigner {
            signing_key,
            public_key,
            public_pem,
            owner: owner.to_owned(),
        }
    }

    /// The PEM this signer's public key was read from.
    pub fn public_pem(&self) -> &str {
        &self.public_pem
    }

    /// The `@handle` this signer signs as.
    pub fn owner(&self) -> &str {
        &self.owner
    }
}

impl Signer for MemorySigner {
    fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    fn sign(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        let signature: p256::ecdsa::Signature = self.signing_key.sign(message);
        Ok(signature.to_der().as_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_always_derives_the_same_key() {
        assert_eq!(
            MemorySigner::for_owner("@arlosi").key_id(),
            MemorySigner::for_owner("@arlosi").key_id(),
        );
        assert_ne!(
            MemorySigner::for_owner("@arlosi").key_id(),
            MemorySigner::for_owner("@other").key_id(),
        );
    }

    #[test]
    fn signatures_verify_against_the_advertised_public_key() {
        let mut signer = MemorySigner::for_owner("@arlosi");
        let signature = signer.sign(b"payload").unwrap();
        assert!(
            signer
                .public_key()
                .verify_bytes(b"payload", &signature)
                .is_ok()
        );
        assert!(
            signer
                .public_key()
                .verify_bytes(b"other payload", &signature)
                .is_err()
        );
    }
}
