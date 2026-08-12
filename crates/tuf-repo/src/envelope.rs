//! DSSE: what signatures are actually computed over, and how metadata is published.
//!
//! A signature covers the *pre-authentication encoding* of a payload:
//!
//! ```text
//! DSSEv1 ‖ SP ‖ LEN(payloadType) ‖ SP ‖ payloadType ‖ SP ‖ LEN(payload) ‖ SP ‖ payload
//! ```
//!
//! Because the payload appears in the signed bytes verbatim, producer and verifier never
//! have to agree on a canonical JSON dialect — the pervasive source of "it verified here
//! but not there" problems in TUF's older encoding. It also means the payload can be
//! stored as readable, reviewable JSON without that formatting being load-bearing for
//! anything except reproducing the same file again.
//!
//! In a working repository the payload and its signatures are two separate files, so that
//! adding a signature produces a diff that shows only the signature. [`Envelope`] is the
//! published form, assembled from the two at publish time.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};

use crate::crypto::KeyId;
use crate::error::{Error, Result};

/// The DSSE payload type of TUF metadata, as POUF-2 defines it.
pub const PAYLOAD_TYPE: &str = "application/vnd.tuf+json";

/// The bytes a signature over `payload` is computed over.
pub fn signing_input(payload: &[u8]) -> Vec<u8> {
    dsse::pae(PAYLOAD_TYPE, payload)
}

/// One signature over a payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    /// Which key produced the signature.
    pub keyid: KeyId,
    /// The signature bytes, base64 encoded.
    pub sig: String,
}

impl Signature {
    /// Build a signature entry from raw signature bytes.
    pub fn new(keyid: KeyId, signature: &[u8]) -> Self {
        Signature {
            keyid,
            sig: BASE64.encode(signature),
        }
    }

    /// Decode the signature bytes.
    pub fn decode(&self) -> Result<Vec<u8>> {
        BASE64
            .decode(&self.sig)
            .map_err(|err| Error::encoding(format!("signature by {}: {err}", self.keyid)))
    }
}

/// The contents of a `<role>.sig.json` file.
///
/// Only real signatures appear here. Which signatures are *expected* is a property of the
/// delegating role, not of this file, so there are no placeholder entries to keep in step.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signatures {
    /// The signatures, ordered by key id so the file is reproducible.
    #[serde(default)]
    pub signatures: Vec<Signature>,
}

impl Signatures {
    /// An empty signature set.
    pub fn new() -> Self {
        Self::default()
    }

    /// The signature made by `key_id`, if there is one.
    pub fn get(&self, key_id: &KeyId) -> Option<&Signature> {
        self.signatures.iter().find(|sig| &sig.keyid == key_id)
    }

    /// Add a signature, replacing any previous one by the same key.
    ///
    /// Entries are kept sorted by key id: two signers adding signatures concurrently then
    /// produce the same file whichever order the commits land in, which keeps merge
    /// conflicts to the genuine ones.
    pub fn insert(&mut self, signature: Signature) {
        self.signatures.retain(|sig| sig.keyid != signature.keyid);
        self.signatures.push(signature);
        self.signatures.sort_by(|a, b| a.keyid.cmp(&b.keyid));
    }

    /// Drop every signature.
    pub fn clear(&mut self) {
        self.signatures.clear();
    }

    /// Whether there are no signatures at all.
    pub fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }
}

/// A published DSSE envelope: payload and signatures in one document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Envelope {
    /// Always [`PAYLOAD_TYPE`].
    pub payload_type: String,
    /// The payload bytes, base64 encoded.
    pub payload: String,
    /// The signatures over the payload's pre-authentication encoding.
    pub signatures: Vec<Signature>,
}

impl Envelope {
    /// Combine a payload and its signatures into the form a client consumes.
    pub fn new(payload: &[u8], signatures: &Signatures) -> Self {
        Envelope {
            payload_type: PAYLOAD_TYPE.to_owned(),
            payload: BASE64.encode(payload),
            signatures: signatures.signatures.clone(),
        }
    }

    /// Recover the payload bytes.
    pub fn decode_payload(&self) -> Result<Vec<u8>> {
        if self.payload_type != PAYLOAD_TYPE {
            return Err(Error::invalid(format!(
                "expected payload type {PAYLOAD_TYPE:?}, got {:?}",
                self.payload_type
            )));
        }
        BASE64
            .decode(&self.payload)
            .map_err(|err| Error::encoding(format!("envelope payload: {err}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn key_id(s: &str) -> KeyId {
        KeyId::from_str(s).unwrap()
    }

    #[test]
    fn signing_input_matches_the_dsse_construction() {
        assert_eq!(
            signing_input(b"hello world"),
            format!("DSSEv1 24 {PAYLOAD_TYPE} 11 hello world").into_bytes(),
        );
    }

    #[test]
    fn signatures_are_ordered_regardless_of_insertion_order() {
        let mut forwards = Signatures::new();
        forwards.insert(Signature::new(key_id("aaa"), b"1"));
        forwards.insert(Signature::new(key_id("bbb"), b"2"));

        let mut backwards = Signatures::new();
        backwards.insert(Signature::new(key_id("bbb"), b"2"));
        backwards.insert(Signature::new(key_id("aaa"), b"1"));

        assert_eq!(forwards, backwards);
    }

    #[test]
    fn re_signing_replaces_rather_than_duplicates() {
        let mut sigs = Signatures::new();
        sigs.insert(Signature::new(key_id("aaa"), b"first"));
        sigs.insert(Signature::new(key_id("aaa"), b"second"));
        assert_eq!(sigs.signatures.len(), 1);
        assert_eq!(
            sigs.get(&key_id("aaa")).unwrap().decode().unwrap(),
            b"second"
        );
    }

    #[test]
    fn envelope_round_trips_the_payload() {
        let mut sigs = Signatures::new();
        sigs.insert(Signature::new(key_id("aaa"), b"sig"));
        let envelope = Envelope::new(b"{\"_type\":\"root\"}", &sigs);
        assert_eq!(envelope.decode_payload().unwrap(), b"{\"_type\":\"root\"}");
    }

    #[test]
    fn envelope_rejects_a_foreign_payload_type() {
        let mut envelope = Envelope::new(b"payload", &Signatures::new());
        envelope.payload_type = "application/vnd.in-toto+json".into();
        assert!(envelope.decode_payload().is_err());
    }
}
