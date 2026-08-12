//! The one way this crate writes JSON.
//!
//! Signatures cover the exact bytes of a payload file, so those bytes have to be
//! reproducible: the same payload must serialize identically on every machine and every
//! release. Everything written to a repository goes through [`to_bytes`].
//!
//! The output is two-space-indented pretty JSON with a trailing newline. Map keys sort,
//! because every map in the model is a [`BTreeMap`](std::collections::BTreeMap) and
//! `serde_json`'s own maps are ordered. Struct fields keep declaration order, which reads
//! better than alphabetical and is just as reproducible.
//!
//! Note that reproducibility is a convenience, not something the security of the
//! repository leans on: a signature is always checked against the bytes as they were
//! stored, never against a fresh serialization. See [`crate::store::Signed`].

use serde::Serialize;

use crate::error::Result;

/// Serialize `value` the way this crate writes metadata to disk.
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

/// `expires` timestamps, in the `YYYY-MM-DDThh:mm:ssZ` form POUF-2 specifies.
///
/// Chrono's own `serde` impl would write sub-second digits when it had them, which would
/// make the encoding depend on when a value happened to be created.
pub mod datetime {
    use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
    use serde::{Deserialize, Deserializer, Serializer};

    const FORMAT: &str = "%Y-%m-%dT%H:%M:%SZ";

    /// Serialize a UTC timestamp, truncated to whole seconds.
    pub fn serialize<S: Serializer>(
        value: &DateTime<Utc>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.format(FORMAT).to_string())
    }

    /// Deserialize a UTC timestamp.
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<DateTime<Utc>, D::Error> {
        let raw = String::deserialize(deserializer)?;
        let naive = NaiveDateTime::parse_from_str(&raw, FORMAT).map_err(|_| {
            serde::de::Error::custom(format!(
                "expected a timestamp of the form YYYY-MM-DDThh:mm:ssZ, got {raw:?}"
            ))
        })?;
        Ok(Utc.from_utc_datetime(&naive))
    }
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Doc {
        #[serde(with = "super::datetime")]
        expires: chrono::DateTime<Utc>,
    }

    #[test]
    fn output_is_indented_and_newline_terminated() {
        let doc = Doc {
            expires: Utc.with_ymd_and_hms(2027, 7, 17, 19, 49, 2).unwrap(),
        };
        assert_eq!(
            super::to_string(&doc).unwrap(),
            "{\n  \"expires\": \"2027-07-17T19:49:02Z\"\n}\n",
        );
    }

    #[test]
    fn sub_second_precision_is_dropped_rather_than_written() {
        let doc = Doc {
            expires: Utc
                .timestamp_micros(
                    Utc.with_ymd_and_hms(2027, 7, 17, 19, 49, 2)
                        .unwrap()
                        .timestamp()
                        * 1_000_000
                        + 500_000,
                )
                .unwrap(),
        };
        assert!(super::to_string(&doc).unwrap().contains("19:49:02Z"));
    }

    #[test]
    fn timestamps_round_trip() {
        let doc = Doc {
            expires: Utc.with_ymd_and_hms(2027, 7, 17, 19, 49, 2).unwrap(),
        };
        let bytes = super::to_bytes(&doc).unwrap();
        assert_eq!(serde_json::from_slice::<Doc>(&bytes).unwrap(), doc);
    }
}
