// SPDX-License-Identifier: AGPL-3.0-only
//! # wtp-types
//!
//! Data model of the Wutong Protocol (`wutong/0.1`, schema `urn:wutong:schema:core:0.1.2`):
//! validated identifiers, the 16 normative error codes, the envelope, and typed payloads for
//! all 24 normative message kinds. The payload types are generated from the normative JSON
//! Schema by `tools/gen_types.py`; structural bounds (string lengths, array sizes) are enforced
//! by `wtp-wire`'s schema validator, while these types enforce field sets, enums and ID formats.

pub mod envelope;
pub mod error;
pub mod generated;
pub mod ids;

pub use envelope::{Auth, Envelope, PROTOCOL, Proof, ProofEncoding};
pub use error::{ErrorCode, WtpError, WtpResult, err};
pub use generated::*;
pub use ids::{B64u, Digest, HexKey32, Timestamp, Urn};
