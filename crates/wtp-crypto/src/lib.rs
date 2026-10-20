// SPDX-License-Identifier: AGPL-3.0-only
//! # wtp-crypto
//!
//! Signed `WutongEnvelope`s (WTP-STD-001 §4.3):
//!
//! ```text
//! SigningInput_JCS   = "WUTONG-SIG-V0.1"      || 0x00 || JCS(envelope without "proof")
//! SigningInput_dCBOR = "WUTONG-CBOR-SIG-V0.1" || 0x00 || dCBOR(envelope without "proof")
//! ```
//!
//! Verification enforces canonical unpadded Base64URL, 64-byte signatures with `S < L`
//! (RFC 8032 §5.1.7), rejection of all-zero / small-order public keys, issuance drift,
//! live-mode clock skew and replay/equivocation detection through [`ReplayLedger`].
//!
//! **Status:** Security profile is experimental; this crate has not been audited.

pub mod replay;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde_json::{Map, Value, json};
use wtp_types::{ErrorCode, Timestamp, WtpError, err, ids::is_uuidv7_urn};
use wtp_wire::{dcbor, jcs, sha256_digest};

pub use replay::{MemoryReplayCache, ReplayLedger};

/// JCS signing domain separator.
pub const JCS_PREFIX: &[u8] = b"WUTONG-SIG-V0.1\x00";
/// dCBOR signing domain separator.
pub const CBOR_PREFIX: &[u8] = b"WUTONG-CBOR-SIG-V0.1\x00";

/// Ed25519 group order L, little-endian.
const ED25519_L_LE: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// Known all-zero / small-order Curve25519/Ed25519 encodings (same list as the reference).
pub const SMALL_ORDER_PUBKEYS_HEX: [&str; 11] = [
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000080",
    "0100000000000000000000000000000000000000000000000000000000000080",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
];

fn sig_err(m: impl Into<String>) -> WtpError {
    err(ErrorCode::Signature, m)
}

/// Encode unpadded Base64URL.
pub fn b64u_encode(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

/// Decode unpadded Base64URL, rejecting non-canonical encodings (non-zero trailing bits).
pub fn b64u_decode(s: &str) -> Result<Vec<u8>, WtpError> {
    if s.is_empty()
        || !s
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    {
        return Err(sig_err("bad base64url"));
    }
    let b = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| sig_err("bad base64url"))?;
    if b64u_encode(&b) != s {
        return Err(sig_err("noncanonical base64url"));
    }
    Ok(b)
}

/// Validate a 64-hex public key and reject weak/small-order encodings (`ERR_KEY_UNBOUND`).
pub fn validate_public_key_hex(h: &str) -> Result<[u8; 32], WtpError> {
    if h.len() != 64
        || !h
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(err(
            ErrorCode::KeyUnbound,
            "public_key must be 64 lowercase hex characters",
        ));
    }
    if SMALL_ORDER_PUBKEYS_HEX.contains(&h) {
        return Err(err(
            ErrorCode::KeyUnbound,
            "weak or small-order public key rejected",
        ));
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(h, &mut out).expect("validated hex");
    Ok(out)
}

/// RFC 8032 §5.1.7: the scalar half of the signature must satisfy `S < L`.
pub fn check_signature_canonical(sig: &[u8]) -> Result<(), WtpError> {
    if sig.len() != 64 {
        return Err(sig_err("signature length must be 64 bytes"));
    }
    // compare little-endian S against L from the most significant byte
    for i in (0..32).rev() {
        let (s, l) = (sig[32 + i], ED25519_L_LE[i]);
        if s < l {
            return Ok(());
        }
        if s > l {
            break;
        }
    }
    Err(sig_err("non-canonical Ed25519 scalar S >= L rejected"))
}

fn check_nonce(n: &str) -> Result<(), WtpError> {
    if (16..=128).contains(&n.len())
        && n.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    {
        Ok(())
    } else {
        Err(sig_err("bad nonce"))
    }
}

/// Re-export of the Ed25519 implementation used by this crate.
pub use ed25519_dalek;

/// Build a verifying key from 32 bytes (call [`validate_public_key_hex`] first for weak-key checks).
pub fn verifying_key(bytes: &[u8; 32]) -> Result<VerifyingKey, WtpError> {
    VerifyingKey::from_bytes(bytes)
        .map_err(|_| err(ErrorCode::KeyUnbound, "invalid Ed25519 public key"))
}

/// Ed25519 key from a 32-byte seed.
pub fn signing_key_from_seed(seed: &[u8; 32]) -> SigningKey {
    SigningKey::from_bytes(seed)
}

/// Signature canonicalization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// JCS / `application/wtp+json`.
    Jcs,
    /// dCBOR / `application/wtp+cbor`.
    Dcbor,
}

/// Parameters of the `auth` block.
#[derive(Debug, Clone)]
pub struct SignParams<'a> {
    /// Signer principal URN.
    pub signer_id: &'a str,
    /// Key id.
    pub key_id: &'a str,
    /// `YYYY-MM-DDTHH:MM:SSZ`.
    pub issued_at: &'a str,
    /// 16..128 chars `[A-Za-z0-9_-]`.
    pub nonce: &'a str,
    /// Encoding used for the signing input.
    pub encoding: Encoding,
    /// Emit `proof.encoding` explicitly (needed for cross-gateway transcoding).
    pub include_encoding: bool,
}

/// Compute the exact domain-separated signing input of an envelope value (any `proof` is removed).
pub fn signing_input(envelope: &Value, encoding: Encoding) -> Result<Vec<u8>, WtpError> {
    let mut unsigned = envelope
        .as_object()
        .ok_or_else(|| err(ErrorCode::Schema, "envelope must be an object"))?
        .clone();
    unsigned.remove("proof");
    let unsigned = Value::Object(unsigned);
    let (prefix, body) = match encoding {
        Encoding::Jcs => (JCS_PREFIX, jcs::canonicalize(&unsigned)?),
        Encoding::Dcbor => (CBOR_PREFIX, dcbor::encode(&unsigned)?),
    };
    let mut out = prefix.to_vec();
    out.extend_from_slice(&body);
    Ok(out)
}

/// Sign an unsigned envelope value, returning the signed value.
pub fn sign_envelope(
    message: &Value,
    key: &SigningKey,
    p: &SignParams<'_>,
) -> Result<Value, WtpError> {
    let obj = message
        .as_object()
        .ok_or_else(|| err(ErrorCode::Schema, "envelope must be an object"))?;
    if obj.contains_key("auth") || obj.contains_key("proof") {
        return Err(sig_err("already has auth/proof"));
    }
    if !is_uuidv7_urn(p.signer_id) {
        return Err(sig_err("invalid signer"));
    }
    Timestamp::parse(p.issued_at)?;
    check_nonce(p.nonce)?;
    let mut out: Map<String, Value> = obj.clone();
    out.insert(
        "auth".into(),
        json!({"signer_id": p.signer_id, "key_id": p.key_id, "issued_at": p.issued_at, "nonce": p.nonce}),
    );
    let mut v = Value::Object(out);
    let sig = key.sign(&signing_input(&v, p.encoding)?).to_bytes();
    check_signature_canonical(&sig)?;
    let mut proof = json!({"alg": "Ed25519", "sig": b64u_encode(&sig)});
    if p.include_encoding {
        proof["encoding"] = json!(match p.encoding {
            Encoding::Jcs => "jcs",
            Encoding::Dcbor => "dcbor",
        });
    }
    v["proof"] = proof;
    Ok(v)
}

/// Resolves `(signer_id, key_id)` at a given time and purpose to a verifying key.
pub trait KeyLookup {
    /// Return the bound key, or `None` if unbound. Implementations should apply key binding
    /// validity, purposes and revocation (incl. `compromised` retroactive rejection).
    fn lookup(
        &self,
        signer_id: &str,
        key_id: &str,
        at: &Timestamp,
        purpose: &str,
    ) -> Option<VerifyingKey>;
}

impl<F> KeyLookup for F
where
    F: Fn(&str, &str) -> Option<VerifyingKey>,
{
    fn lookup(&self, s: &str, k: &str, _at: &Timestamp, _p: &str) -> Option<VerifyingKey> {
        self(s, k)
    }
}

/// Verification mode (WTP-STD-001 §4.3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Live request: clock skew window and replay ledger consumption.
    Live,
    /// Archive proof: historical verification, equivocation check only.
    Archive,
}

/// Options for [`verify_envelope`].
pub struct VerifyOptions<'a> {
    /// Current time in Unix seconds (live mode).
    pub now: i64,
    /// Live or archive.
    pub mode: Mode,
    /// `|now − issued_at|` bound in live mode (default 300).
    pub max_clock_skew_seconds: i64,
    /// `|occurred_at − issued_at|` bound (default 300).
    pub max_issuance_drift_seconds: i64,
    /// Key purpose required (default `signing`).
    pub purpose: &'a str,
    /// Critical extensions this implementation understands.
    pub supported_extensions: &'a [&'a str],
    /// Encoding of the transport (used when `proof.encoding` is absent).
    pub transport: Encoding,
    /// Optional replay / equivocation ledger.
    pub replay: Option<&'a mut dyn ReplayLedger>,
}

impl Default for VerifyOptions<'_> {
    fn default() -> Self {
        Self {
            now: 0,
            mode: Mode::Archive,
            max_clock_skew_seconds: 300,
            max_issuance_drift_seconds: 300,
            purpose: "signing",
            supported_extensions: &[],
            transport: Encoding::Jcs,
            replay: None,
        }
    }
}

/// Reverse-domain extension namespace check used by `critical` (≥ 2 labels, as in the schema).
pub fn is_extension_namespace(ns: &str) -> bool {
    let mut parts = ns.split('.');
    let Some(first) = parts.next() else {
        return false;
    };
    let ok_first = !first.is_empty()
        && first
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    let rest: Vec<&str> = parts.collect();
    ok_first
        && !rest.is_empty()
        && rest.iter().all(|p| {
            !p.is_empty()
                && p.bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-')
        })
}

/// Critical-extension negotiation (WTP-STD-001 §4.2): fail closed.
pub fn check_critical_extensions(message: &Value, supported: &[&str]) -> Result<(), WtpError> {
    let Some(crit) = message.get("critical") else {
        return Ok(());
    };
    let crit = crit
        .as_array()
        .filter(|a| !a.is_empty())
        .ok_or_else(|| err(ErrorCode::Schema, "invalid critical extensions array"))?;
    let mut present: Vec<&str> = Vec::new();
    if let Some(e) = message.get("extensions").and_then(Value::as_object) {
        present.extend(e.keys().map(String::as_str));
    }
    if let Some(x) = message.pointer("/payload/x").and_then(Value::as_object) {
        present.extend(x.keys().map(String::as_str));
    }
    let mut seen = std::collections::BTreeSet::new();
    for ns in crit {
        let ns = ns
            .as_str()
            .filter(|s| is_extension_namespace(s))
            .ok_or_else(|| err(ErrorCode::Schema, "invalid critical extension namespace"))?;
        if !seen.insert(ns) {
            return Err(err(ErrorCode::Schema, "duplicate critical extension"));
        }
        if !present.contains(&ns) {
            return Err(err(
                ErrorCode::Schema,
                format!("critical extension {ns:?} not present in extensions"),
            ));
        }
        if !supported.contains(&ns) {
            return Err(err(
                ErrorCode::Version,
                format!("unsupported critical extension {ns:?}"),
            ));
        }
    }
    Ok(())
}

/// Verify a signed envelope value. Returns the canonical digest of the signed bytes.
pub fn verify_envelope(
    message: &Value,
    keys: &dyn KeyLookup,
    opts: VerifyOptions<'_>,
) -> Result<String, WtpError> {
    let (Some(auth), Some(proof)) = (
        message.get("auth").and_then(Value::as_object),
        message.get("proof").and_then(Value::as_object),
    ) else {
        return Err(sig_err("missing auth or proof"));
    };
    check_critical_extensions(message, opts.supported_extensions)?;
    let auth_keys: Vec<&str> = auth.keys().map(String::as_str).collect();
    let mut sorted = auth_keys.clone();
    sorted.sort_unstable();
    if sorted != ["issued_at", "key_id", "nonce", "signer_id"]
        || !proof
            .keys()
            .all(|k| matches!(k.as_str(), "alg" | "sig" | "encoding"))
        || proof.get("alg").and_then(Value::as_str) != Some("Ed25519")
        || !proof.contains_key("sig")
    {
        return Err(sig_err("invalid proof shape"));
    }
    let enc = match proof.get("encoding").map(|v| v.as_str()) {
        None => opts.transport,
        Some(Some("jcs")) => Encoding::Jcs,
        Some(Some("dcbor")) => Encoding::Dcbor,
        _ => return Err(sig_err("unsupported proof.encoding")),
    };
    let s = |k: &str| {
        auth.get(k)
            .and_then(Value::as_str)
            .ok_or_else(|| sig_err("invalid auth field"))
    };
    let (signer, key_id, issued, nonce) =
        (s("signer_id")?, s("key_id")?, s("issued_at")?, s("nonce")?);
    if !is_uuidv7_urn(signer) {
        return Err(sig_err("bad signer"));
    }
    check_nonce(nonce)?;
    let issued = Timestamp::parse(issued)?;
    if let Some(occ) = message.get("occurred_at").and_then(Value::as_str) {
        let occ = Timestamp::parse(occ)?;
        if (occ.unix_seconds() - issued.unix_seconds()).abs() > opts.max_issuance_drift_seconds {
            return Err(sig_err("occurred_at / auth.issued_at drift exceeds limit"));
        }
    }
    let input = signing_input(message, enc)?;
    let prefix_len = match enc {
        Encoding::Jcs => JCS_PREFIX.len(),
        Encoding::Dcbor => CBOR_PREFIX.len(),
    };
    let digest = sha256_digest(&input[prefix_len..]).to_string();
    let sig_bytes = b64u_decode(
        proof["sig"]
            .as_str()
            .ok_or_else(|| sig_err("sig must be a string"))?,
    )?;
    check_signature_canonical(&sig_bytes)?;
    let vk = keys
        .lookup(signer, key_id, &issued, opts.purpose)
        .ok_or_else(|| err(ErrorCode::KeyUnbound, "unknown authenticated key"))?;
    validate_public_key_hex(&hex::encode(vk.as_bytes()))?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| sig_err("malformed signature"))?;
    vk.verify_strict(&input, &sig)
        .map_err(|_| sig_err("signature mismatch"))?;
    let id = message
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    match opts.mode {
        Mode::Live => {
            if (opts.now - issued.unix_seconds()).abs() > opts.max_clock_skew_seconds {
                return Err(sig_err("timestamp outside live replay window"));
            }
            if let Some(r) = opts.replay {
                r.consume(signer, nonce, id, &digest)?;
            }
        }
        Mode::Archive => {
            if let Some(r) = opts.replay {
                r.check_equivocation(signer, id, &digest)?;
            }
        }
    }
    Ok(digest)
}

/// Verify a raw `application/wtp+cbor` envelope: strict dCBOR decode, then [`verify_envelope`].
pub fn verify_cbor_bytes(
    raw: &[u8],
    keys: &dyn KeyLookup,
    mut opts: VerifyOptions<'_>,
) -> Result<String, WtpError> {
    let v = dcbor::decode(raw)?;
    opts.transport = Encoding::Dcbor;
    verify_envelope(&v, keys, opts)
}
