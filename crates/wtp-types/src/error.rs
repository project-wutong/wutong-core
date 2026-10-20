// SPDX-License-Identifier: AGPL-3.0-only
//! The 16 normative WTP error codes (WTP-STD-001 §9).

use serde::{Deserialize, Serialize};
use std::fmt;

/// Normative error codes registered in `schemas/registry.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[allow(missing_docs)]
pub enum ErrorCode {
    #[serde(rename = "ERR_SCHEMA")]
    Schema,
    #[serde(rename = "ERR_VERSION")]
    Version,
    #[serde(rename = "ERR_SIGNATURE")]
    Signature,
    #[serde(rename = "ERR_KEY_UNBOUND")]
    KeyUnbound,
    #[serde(rename = "ERR_KEY_REVOKED")]
    KeyRevoked,
    #[serde(rename = "ERR_REVOCATION_STALE")]
    RevocationStale,
    #[serde(rename = "ERR_PERMISSION")]
    Permission,
    #[serde(rename = "ERR_REPLAY")]
    Replay,
    #[serde(rename = "ERR_EQUIVOCATION")]
    Equivocation,
    #[serde(rename = "ERR_DECRYPTION_FAILED")]
    DecryptionFailed,
    #[serde(rename = "ERR_CONFLICT")]
    Conflict,
    #[serde(rename = "ERR_SYMLINK_OR_TRAVERSAL")]
    SymlinkOrTraversal,
    #[serde(rename = "ERR_SSRF_BLOCKED")]
    SsrfBlocked,
    #[serde(rename = "ERR_UNRESOLVED")]
    Unresolved,
    #[serde(rename = "ERR_RATE_LIMIT")]
    RateLimit,
    #[serde(rename = "ERR_UNSUPPORTED")]
    Unsupported,
}

impl ErrorCode {
    /// All 16 codes in registry order.
    pub const ALL: [ErrorCode; 16] = [
        Self::Schema,
        Self::Version,
        Self::Signature,
        Self::KeyUnbound,
        Self::KeyRevoked,
        Self::RevocationStale,
        Self::Permission,
        Self::Replay,
        Self::Equivocation,
        Self::DecryptionFailed,
        Self::Conflict,
        Self::SymlinkOrTraversal,
        Self::SsrfBlocked,
        Self::Unresolved,
        Self::RateLimit,
        Self::Unsupported,
    ];

    /// Wire string, e.g. `ERR_SCHEMA`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Schema => "ERR_SCHEMA",
            Self::Version => "ERR_VERSION",
            Self::Signature => "ERR_SIGNATURE",
            Self::KeyUnbound => "ERR_KEY_UNBOUND",
            Self::KeyRevoked => "ERR_KEY_REVOKED",
            Self::RevocationStale => "ERR_REVOCATION_STALE",
            Self::Permission => "ERR_PERMISSION",
            Self::Replay => "ERR_REPLAY",
            Self::Equivocation => "ERR_EQUIVOCATION",
            Self::DecryptionFailed => "ERR_DECRYPTION_FAILED",
            Self::Conflict => "ERR_CONFLICT",
            Self::SymlinkOrTraversal => "ERR_SYMLINK_OR_TRAVERSAL",
            Self::SsrfBlocked => "ERR_SSRF_BLOCKED",
            Self::Unresolved => "ERR_UNRESOLVED",
            Self::RateLimit => "ERR_RATE_LIMIT",
            Self::Unsupported => "ERR_UNSUPPORTED",
        }
    }

    /// Normative HTTP status mapping (WTP-STD-001 §9).
    pub const fn http_status(self) -> u16 {
        match self {
            Self::Schema | Self::Version | Self::DecryptionFailed | Self::SymlinkOrTraversal => 400,
            Self::Signature | Self::KeyUnbound | Self::KeyRevoked => 401,
            Self::Permission | Self::SsrfBlocked => 403,
            Self::Unresolved => 404,
            Self::Replay | Self::Equivocation | Self::Conflict => 409,
            Self::RateLimit => 429,
            Self::Unsupported => 501,
            Self::RevocationStale => 503,
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A WTP error: a normative code plus a human readable detail.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{code}: {detail}")]
pub struct WtpError {
    /// Normative code.
    pub code: ErrorCode,
    /// Diagnostic detail (not part of the wire contract).
    pub detail: String,
}

impl WtpError {
    /// Build an error.
    pub fn new(code: ErrorCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

/// Shorthand constructor: `err(ErrorCode::Schema, "...")`.
pub fn err(code: ErrorCode, detail: impl Into<String>) -> WtpError {
    WtpError::new(code, detail)
}

/// Result alias.
pub type WtpResult<T> = Result<T, WtpError>;
