// SPDX-License-Identifier: AGPL-3.0-only
//! # wutong-core
//!
//! Facade over the WTP crates, used by `wutong` CLI, `wutong-networkd`, `wutong-server`, the
//! language SDKs and (through C++ bridges) the Qt desktop apps.
//!
//! ```
//! let raw = br#"{"protocol":"wutong/0.1","kind":"wutong.principal","id":"urn:uuid:019a1111-1111-7111-8111-000000000064","occurred_at":"2026-10-18T10:00:00Z","payload":{"principal_id":"urn:uuid:019a1111-1111-7111-8111-000000000065","principal_type":"agent"}}"#;
//! let env = wutong_core::parse_and_validate(raw).unwrap();
//! assert_eq!(env.kind(), wutong_core::types::Kind::Principal);
//! ```

pub mod semantic;

pub use wtp_agent as agent;
pub use wtp_crypto as crypto;
pub use wtp_document as document;
pub use wtp_policy as policy;
pub use wtp_types as types;
pub use wtp_wire as wire;

use wtp_types::{Envelope, WtpError};

/// Implementation identifier for `wutong.node_meta.implementation`.
pub const IMPLEMENTATION: &str = concat!("wutong-core-rs/", env!("CARGO_PKG_VERSION"));

/// Strict parse + schema validation + typed decode + semantic validation (no signature check).
pub fn parse_and_validate(bytes: &[u8]) -> Result<Envelope, WtpError> {
    let v = wire::strict::parse(bytes)?;
    wire::schema::validate(&v)?;
    let env = Envelope::from_value(v.clone())?;
    semantic::validate(&v, &env, None, &[])?;
    Ok(env)
}
