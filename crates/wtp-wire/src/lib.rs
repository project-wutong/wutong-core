// SPDX-License-Identifier: AGPL-3.0-only
//! # wtp-wire
//!
//! Byte-exact wire layer for the Wutong Protocol: strict JSON parsing, restricted RFC 8785
//! JCS canonicalization, RFC 8949 §4.2.1 deterministic CBOR, SHA-256 content digests and
//! (feature `schema`) validation against the normative JSON Schema.

pub mod dcbor;
pub mod jcs;
pub mod strict;

#[cfg(feature = "schema")]
pub mod schema;

use sha2::{Digest as _, Sha256};
use wtp_types::{Digest, Envelope, WtpError};

/// `sha256:<hex>` digest of raw bytes.
pub fn sha256_digest(bytes: &[u8]) -> Digest {
    Digest::from_hex(&hex::encode(Sha256::digest(bytes))).expect("valid digest")
}

/// Parse an `application/wtp+json` envelope: strict JSON, (optionally) schema, then typed decode.
pub fn parse_envelope(bytes: &[u8]) -> Result<Envelope, WtpError> {
    let v = strict::parse(bytes)?;
    #[cfg(feature = "schema")]
    schema::validate(&v)?;
    Envelope::from_value(v)
}

/// Canonical (JCS) SHA-256 digest of a JSON value.
pub fn canonical_digest(v: &serde_json::Value) -> Result<Digest, WtpError> {
    Ok(sha256_digest(&jcs::canonicalize(v)?))
}
