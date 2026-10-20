// SPDX-License-Identifier: AGPL-3.0-only
//! The top-level `WutongEnvelope` (WTP-STD-001 §4.1).

use crate::error::{ErrorCode, WtpError, err};
use crate::generated::{Kind, Payload};
use crate::ids::{Timestamp, Urn};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// The only accepted value of the `protocol` field.
pub const PROTOCOL: &str = "wutong/0.1";

/// `auth` block of a signed envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Auth {
    /// Principal that signed.
    pub signer_id: Urn,
    /// Key identifier bound to the signer.
    pub key_id: String,
    /// Signing time.
    pub issued_at: Timestamp,
    /// 16..128 chars of `[A-Za-z0-9_-]`.
    pub nonce: String,
}

/// Canonicalization used to compute the signing input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProofEncoding {
    /// RFC 8785 JCS (`WUTONG-SIG-V0.1\0` prefix).
    Jcs,
    /// RFC 8949 §4.2.1 deterministic CBOR (`WUTONG-CBOR-SIG-V0.1\0` prefix).
    Dcbor,
}

/// `proof` block of a signed envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proof {
    /// Always `Ed25519`.
    pub alg: String,
    /// 86-char unpadded Base64URL of the 64-byte signature.
    pub sig: String,
    /// Original signing encoding (defaults to the transport encoding).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoding: Option<ProofEncoding>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEnvelope {
    protocol: String,
    kind: Kind,
    id: Urn,
    occurred_at: Timestamp,
    payload: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    extensions: Option<Map<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    critical: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    auth: Option<Auth>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    proof: Option<Proof>,
}

/// A typed WTP message envelope.
#[derive(Debug, Clone, PartialEq)]
pub struct Envelope {
    /// Envelope id (UUIDv7 URN).
    pub id: Urn,
    /// Business time (not a causal order).
    pub occurred_at: Timestamp,
    /// Typed payload; its kind is the envelope `kind`.
    pub payload: Payload,
    /// Reverse-domain namespaced extensions.
    pub extensions: Option<Map<String, Value>>,
    /// Extensions the receiver MUST understand.
    pub critical: Option<Vec<String>>,
    /// Signature metadata (covered by the signature).
    pub auth: Option<Auth>,
    /// Signature (not covered).
    pub proof: Option<Proof>,
}

impl Envelope {
    /// Message kind.
    pub fn kind(&self) -> Kind {
        self.payload.kind()
    }

    /// Decode from an already strictly-parsed JSON value.
    pub fn from_value(v: Value) -> Result<Self, WtpError> {
        let raw: RawEnvelope =
            serde_json::from_value(v).map_err(|e| err(ErrorCode::Schema, e.to_string()))?;
        if raw.protocol != PROTOCOL {
            return Err(err(
                ErrorCode::Version,
                format!("unsupported protocol {:?}", raw.protocol),
            ));
        }
        if raw.auth.is_some() != raw.proof.is_some() {
            return Err(err(
                ErrorCode::Schema,
                "auth and proof must appear together",
            ));
        }
        if raw.critical.is_some() && raw.extensions.is_none() {
            return Err(err(ErrorCode::Schema, "critical requires extensions"));
        }
        let payload = Payload::from_value(raw.kind, raw.payload)
            .map_err(|e| err(ErrorCode::Schema, format!("{}: {e}", raw.kind.as_str())))?;
        Ok(Self {
            id: raw.id,
            occurred_at: raw.occurred_at,
            payload,
            extensions: raw.extensions,
            critical: raw.critical,
            auth: raw.auth,
            proof: raw.proof,
        })
    }

    /// Encode to a JSON value (member order is irrelevant; canonicalize before hashing).
    pub fn to_value(&self) -> Result<Value, WtpError> {
        let raw = RawEnvelope {
            protocol: PROTOCOL.to_owned(),
            kind: self.kind(),
            id: self.id.clone(),
            occurred_at: self.occurred_at.clone(),
            payload: self
                .payload
                .to_value()
                .map_err(|e| err(ErrorCode::Schema, e.to_string()))?,
            extensions: self.extensions.clone(),
            critical: self.critical.clone(),
            auth: self.auth.clone(),
            proof: self.proof.clone(),
        };
        serde_json::to_value(raw).map_err(|e| err(ErrorCode::Schema, e.to_string()))
    }
}
