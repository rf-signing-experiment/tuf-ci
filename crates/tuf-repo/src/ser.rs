//! The one way this crate writes JSON.
//!
//! A payload's bytes are what its signatures cover, so they are authored exactly once —
//! by [`author`] — and never produced again. Everything after that reads the stored bytes.
//! Re-serializing a payload between collecting signatures would invalidate every one of
//! them, however identical the result looked.
//!
//! Output is two-space-indented pretty JSON with a trailing newline. That is not for the
//! machines: a metadata change has to be reviewable in a pull request, and DSSE signs
//! whatever bytes it is handed, so there is no reason for them to be compact.

use serde::Serialize;
use tuf::metadata::Metadata;
use tuf::pouf::Pouf2;

use crate::error::{Error, Result};

/// Author the payload bytes for a metadata document.
///
/// The only place payload bytes are made. `tuf` writes the document compact; it is
/// pretty-printed here, once, and frozen from then on.
pub fn author<M: Metadata>(payload: &M) -> Result<Vec<u8>> {
    let compact = payload.to_raw_data::<Pouf2>().map_err(Error::encoding)?;
    let value: serde_json::Value = serde_json::from_slice(compact.as_bytes())?;
    to_bytes(&value)
}

/// Serialize `value` the way this crate writes files to disk.
pub fn to_bytes<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Serialize `value` to a `String`, for tests and terminal output.
pub fn to_string<T: Serialize + ?Sized>(value: &T) -> Result<String> {
    let bytes = to_bytes(value)?;
    Ok(String::from_utf8(bytes).expect("serde_json emits UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_is_indented_and_newline_terminated() {
        let value = serde_json::json!({ "b": 1, "a": 2 });
        assert_eq!(
            to_string(&value).unwrap(),
            "{\n  \"a\": 2,\n  \"b\": 1\n}\n"
        );
    }
}
