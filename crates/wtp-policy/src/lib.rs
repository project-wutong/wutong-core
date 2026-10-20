// SPDX-License-Identifier: AGPL-3.0-only
//! # wtp-policy
//!
//! Capability chain evaluation (WTP-STD-001 §6.2) **assuming every capability's signature has
//! already been verified** (see `wtp-crypto`) and revocation state is supplied and fresh.
//! Only exact resource + exact action matching is supported; wildcards are rejected.

use std::collections::{HashMap, HashSet};
use wtp_types::{CapabilityPayload, ErrorCode, WtpError, err};

/// A capability plus the `auth.issued_at` of its (verified) envelope, in Unix seconds.
#[derive(Debug, Clone)]
pub struct Grant {
    /// Capability payload.
    pub cap: CapabilityPayload,
    /// Signed issuance time.
    pub issued_at: i64,
}

/// Evaluation request.
#[derive(Debug, Clone)]
pub struct Request<'a> {
    /// Resource owner (root of trust for the resource).
    pub root_owner: &'a str,
    /// Executing principal.
    pub actor: &'a str,
    /// Exact resource ref.
    pub resource: &'a str,
    /// Exact action.
    pub action: &'a str,
    /// Evaluation time (Unix seconds).
    pub at: i64,
    /// Revoked capability ids.
    pub revoked: &'a HashSet<String>,
    /// Timestamp of the revocation snapshot (Unix seconds); `None` = unknown.
    pub revocation_freshness: Option<i64>,
    /// Max staleness of the revocation snapshot.
    pub max_revocation_staleness_seconds: i64,
    /// Max chain length (spec: k < 8).
    pub depth_limit: usize,
}

/// Returns `Ok(())` if some chain authorizes the request, else `ERR_PERMISSION`
/// (`ERR_REVOCATION_STALE` when revocation state is missing or too old: fail closed).
pub fn authorize(grants: &[Grant], req: &Request<'_>) -> Result<(), WtpError> {
    match req.revocation_freshness {
        Some(f) if (req.at - f).abs() <= req.max_revocation_staleness_seconds => {}
        _ => {
            return Err(err(
                ErrorCode::RevocationStale,
                "fail-closed when revocation state is unknown or stale",
            ));
        }
    }
    if req.action.contains('*') {
        return Err(err(ErrorCode::Permission, "wildcard action undefined"));
    }
    let by_id: HashMap<&str, &Grant> = grants
        .iter()
        .map(|g| (g.cap.capability_id.as_str(), g))
        .collect();
    let ts = |s: &wtp_types::Timestamp| s.unix_seconds();
    'leaf: for leaf in grants {
        if leaf.cap.audience_id.as_str() != req.actor {
            continue;
        }
        let mut cur = leaf;
        let mut seen = HashSet::new();
        loop {
            let c = &cur.cap;
            if seen.len() >= req.depth_limit
                || !seen.insert(c.capability_id.as_str())
                || req.revoked.contains(c.capability_id.as_str())
            {
                continue 'leaf;
            }
            if c.resource_ref != req.resource
                || !c.actions.iter().any(|a| a == req.action)
                || c.actions.iter().any(|a| a.contains('*'))
            {
                continue 'leaf;
            }
            if !(ts(&c.not_before) <= req.at && req.at < ts(&c.expires_at)) {
                continue 'leaf;
            }
            let Some(pid) = &c.parent_id else {
                if c.issuer_id.as_str() == req.root_owner {
                    return Ok(());
                }
                continue 'leaf;
            };
            let Some(parent) = by_id.get(pid.as_str()) else {
                continue 'leaf;
            };
            let p = &parent.cap;
            let attenuated = p.delegable
                && p.audience_id == c.issuer_id
                && p.resource_ref == c.resource_ref
                && c.actions.iter().all(|a| p.actions.contains(a))
                && ts(&p.not_before) <= ts(&c.not_before)
                && ts(&c.expires_at) <= ts(&p.expires_at)
                // v0.1.2 temporal issuance monotonicity
                && parent.issued_at <= cur.issued_at
                && ts(&p.not_before) <= cur.issued_at
                && cur.issued_at < ts(&p.expires_at);
            if !attenuated {
                continue 'leaf;
            }
            cur = parent;
        }
    }
    Err(err(ErrorCode::Permission, "no valid capability chain"))
}
