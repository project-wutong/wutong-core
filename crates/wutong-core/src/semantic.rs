// SPDX-License-Identifier: AGPL-3.0-only
//! Cross-field semantic rules not expressible in JSON Schema (port of the reference
//! `semantic.py`, WTP-STD-001 §§4–7).

#![allow(clippy::collapsible_match)] // one arm per kind reads better than guards

use serde_json::Value;
use wtp_crypto::{b64u_decode, check_critical_extensions, validate_public_key_hex};
use wtp_document::{apply_source_patches, validate_provenance, validate_relative_path};
use wtp_types::{
    DocumentBindingKind, Envelope, ErrorCode, KeyBindingAlg, KeyBindingPurpose, Payload,
    SyncFrameStep, WtpError, err,
};
use wtp_wire::sha256_digest;

fn schema(m: &str) -> WtpError {
    err(ErrorCode::Schema, m)
}

fn check_body(body: Option<&[u8]>, len: i64, digest: &str) -> Result<(), WtpError> {
    if let Some(b) = body {
        if b.len() as i64 != len || sha256_digest(b).as_str() != digest {
            return Err(err(ErrorCode::Conflict, "size/digest mismatch"));
        }
    }
    Ok(())
}

/// Validate semantics. `raw` is the same envelope as JSON (for extension negotiation),
/// `body` the referenced content bytes when available.
pub fn validate(
    raw: &Value,
    env: &Envelope,
    body: Option<&[u8]>,
    supported_extensions: &[&str],
) -> Result<(), WtpError> {
    let occ = env.occurred_at.unix_seconds();
    if let Some(a) = &env.auth {
        if occ - a.issued_at.unix_seconds() > 300 {
            return Err(err(
                ErrorCode::Signature,
                "occurred_at cannot be in the future relative to auth.issued_at",
            ));
        }
    }
    check_critical_extensions(raw, supported_extensions)?;
    match &env.payload {
        Payload::Object(p) => {
            if let Some(b) = &p.binding {
                if b.kind == DocumentBindingKind::File {
                    validate_relative_path(b.relative_path.as_deref().unwrap_or_default())?;
                }
            }
            check_body(body, p.byte_length, p.content_digest.as_str())?;
        }
        Payload::Artifact(p) => {
            if let Some(pr) = &p.provenance {
                validate_provenance(pr)?;
            }
            check_body(body, p.byte_length, p.content_digest.as_str())?;
        }
        Payload::Revision(p) => {
            if let Some(pr) = &p.provenance {
                validate_provenance(pr)?;
            }
            if p.parents.contains(&p.revision_id) {
                return Err(schema("self parent revision"));
            }
        }
        Payload::Proposal(p) => {
            if let Some(pr) = &p.provenance {
                validate_provenance(pr)?;
            }
            if let Some(patches) = &p.patches {
                let mut prev = 0;
                for x in patches {
                    if x.start_byte < prev || x.end_byte < x.start_byte {
                        return Err(err(
                            ErrorCode::Conflict,
                            "overlapping or inverted proposal patches",
                        ));
                    }
                    prev = x.end_byte;
                }
                if let Some(b) = body {
                    apply_source_patches(
                        b,
                        patches,
                        Some(p.base_digest.as_str()),
                        Some(p.proposed_digest.as_str()),
                    )?;
                }
            }
        }
        Payload::Event(p) => {
            if p.causes.as_ref().is_some_and(|c| c.contains(&p.event_id)) {
                return Err(schema("self causal reference"));
            }
        }
        Payload::Capability(p) => {
            if p.not_before.unix_seconds() >= p.expires_at.unix_seconds() {
                return Err(schema("invalid capability duration"));
            }
            if p.parent_id.as_ref() == Some(&p.capability_id) {
                return Err(schema("self parent capability"));
            }
            if p.actions.iter().any(|a| a.contains('*')) {
                return Err(err(ErrorCode::Permission, "wildcard action undefined"));
            }
        }
        Payload::KeyBinding(p) => {
            validate_public_key_hex(p.public_key.as_str())?;
            if p.valid_from.unix_seconds() >= p.valid_until.unix_seconds() {
                return Err(schema("invalid key_binding duration"));
            }
            if p.previous_key_id.as_deref() == Some(p.key_id.as_str()) {
                return Err(schema("self previous_key_id in key_binding"));
            }
            let enc = p.purposes.contains(&KeyBindingPurpose::Encryption);
            match p.alg {
                KeyBindingAlg::X25519 if !(enc && p.purposes.len() == 1) => {
                    return Err(schema(
                        "X25519 key_binding must have purposes=['encryption']",
                    ));
                }
                KeyBindingAlg::Ed25519 if enc => {
                    return Err(schema("Ed25519 key_binding cannot have encryption purpose"));
                }
                _ => {}
            }
        }
        Payload::SpaceEpoch(p) => {
            validate_public_key_hex(p.sender_ephemeral_pub.as_str())?;
            validate_public_key_hex(p.space_x25519_pub.as_str())?;
            let mut seen = std::collections::HashSet::new();
            for w in &p.member_wraps {
                if !seen.insert((w.member_id.as_str(), w.member_key_id.as_str())) {
                    return Err(schema("duplicate member wrap in space_epoch"));
                }
                if b64u_decode(w.nonce_b64u.as_str())?.len() != 12 {
                    return Err(schema("invalid nonce_b64u in space_epoch member_wrap"));
                }
            }
        }
        Payload::Revocation(p) => {
            if p.revocation_id == p.target_id {
                return Err(schema("self revocation target"));
            }
        }
        Payload::ServiceInvocation(p) => {
            if p.action.contains('*') {
                return Err(err(
                    ErrorCode::Permission,
                    "wildcard action forbidden in service_invocation",
                ));
            }
            if env
                .auth
                .as_ref()
                .is_some_and(|a| a.signer_id != p.caller_id)
            {
                return Err(err(
                    ErrorCode::Permission,
                    "service_invocation caller_id must match auth.signer_id",
                ));
            }
        }
        Payload::Receipt(p) => {
            if p.receipt_id == p.request_id {
                return Err(schema("receipt_id cannot equal request_id"));
            }
            if env
                .auth
                .as_ref()
                .is_some_and(|a| a.signer_id != p.responder_id)
            {
                return Err(err(
                    ErrorCode::Permission,
                    "receipt responder_id must match auth.signer_id",
                ));
            }
        }
        Payload::Annotation(p) => {
            if let (Some(s), Some(e)) = (p.selector.start, p.selector.end) {
                if e < s {
                    return Err(schema("negative annotation span"));
                }
            }
        }
        Payload::SyncFrame(p) => match p.step {
            SyncFrameStep::Hello if p.supported_codecs.as_ref().is_none_or(Vec::is_empty) => {
                return Err(schema("HELLO sync_frame requires supported_codecs"));
            }
            SyncFrameStep::Presence => {
                if p.presence_state.is_none() || p.ttl_seconds.is_none() {
                    return Err(schema(
                        "PRESENCE sync_frame requires presence_state and ttl_seconds",
                    ));
                }
                if p.chunk_b64u.is_some() {
                    return Err(schema("PRESENCE sync_frame must not carry chunk_b64u"));
                }
            }
            SyncFrameStep::SyncChunk => {
                let (Some(c), Some(d)) = (&p.chunk_b64u, &p.chunk_digest) else {
                    return Err(schema("SYNC_CHUNK requires chunk_b64u and chunk_digest"));
                };
                if sha256_digest(&b64u_decode(c.as_str())?).as_str() != d.as_str() {
                    return Err(err(ErrorCode::Conflict, "sync_frame chunk_digest mismatch"));
                }
            }
            _ => {}
        },
        Payload::EncryptedEnvelope(p) => {
            validate_public_key_hex(p.sender_ephemeral_pub.as_str())?;
            if b64u_decode(p.nonce_b64u.as_str())?.len() != 12 {
                return Err(schema("encrypted_envelope nonce must be 12 bytes"));
            }
            if b64u_decode(p.ciphertext_b64u.as_str())?.len() < 16 {
                return Err(schema(
                    "encrypted_envelope ciphertext shorter than Poly1305 tag",
                ));
            }
        }
        Payload::NodeMeta(p) => {
            let base = &p.endpoints.base_url;
            if !base.starts_with("https://")
                || base["https://".len()..]
                    .split('/')
                    .next()
                    .is_some_and(|h| h.contains('@'))
            {
                return Err(err(
                    ErrorCode::SsrfBlocked,
                    "federation base_url must be https without credentials",
                ));
            }
            let e = &p.endpoints;
            let paths = [
                &e.meta_path,
                &e.objects_path,
                &e.revisions_path,
                &e.resolve_path,
                &e.subscriptions_path,
                &e.invocations_path,
            ];
            if paths.iter().any(|x| !x.starts_with("/_wutong/"))
                || e.sync_path
                    .as_ref()
                    .is_some_and(|x| !x.starts_with("/_wutong/"))
            {
                return Err(schema("endpoint paths must start with /_wutong/"));
            }
        }
        Payload::Subscription(p) => {
            if occ >= p.expires_at.unix_seconds() {
                return Err(schema("subscription expires_at must be after occurred_at"));
            }
        }
        _ => {}
    }
    Ok(())
}
