//! The TUF repository model shared by the signing tool and the CI tool.
//!
//! This crate holds everything both halves of the system have to agree on: how metadata is
//! encoded, how keys are named, how a signing event's status is computed, and what makes
//! one mergeable. It touches no hardware, runs no git commands and opens no sockets, so
//! all of that logic is testable on its own.
//!
//! # Repository layout
//!
//! ```text
//! metadata/
//!   root.json            the payload: readable, reviewable JSON
//!   root.sig.json        the signatures over root.json's exact bytes
//!   targets.json
//!   targets.sig.json
//!   root_history/1.root.json …
//!   .signing-event.json  open invitations, present only during an event
//! targets/
//!   <artifacts>
//! ```
//!
//! Payload and signatures live in separate files so that a diff shows what it should: a
//! signature commit touches only the `.sig.json` file, and a metadata change is readable
//! JSON rather than a base64 blob. The two are combined into a
//! [DSSE](https://github.com/secure-systems-lab/dsse) envelope at publish time.
//!
//! The metadata model itself is the `tuf` crate's: [`tuf::metadata::RootMetadata`] and its
//! siblings, parsed and written through POUF-2. What this crate adds is the part TUF has
//! no opinion about — who holds a key, how long a role's word is good for, and how a
//! change gets from a pull request to a signature. See [`policy`] for the first two and
//! [`event`] for the last.

#![deny(missing_docs)]

pub mod crypto;
pub mod error;
pub mod event;
pub mod policy;
pub mod report;
pub mod ser;
pub mod signer;
pub mod store;
#[cfg(feature = "testing")]
pub mod testing;

pub use crate::error::{Error, Result};
