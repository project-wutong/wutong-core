// SPDX-License-Identifier: AGPL-3.0-only
//! Replay and equivocation detection. A durable SQLite ledger lives in `wtp-storage` (planned);
//! this module defines the trait and an in-memory implementation for tests and short-lived tools.

use std::collections::HashMap;
use wtp_types::{ErrorCode, WtpError, err};

/// Replay / equivocation ledger.
pub trait ReplayLedger {
    /// Reject if `message_id` was seen with a different signer or canonical digest.
    fn check_equivocation(
        &mut self,
        signer: &str,
        message_id: &str,
        digest: &str,
    ) -> Result<(), WtpError>;
    /// Consume `(signer, nonce)`; reject replays and equivocation.
    fn consume(
        &mut self,
        signer: &str,
        nonce: &str,
        message_id: &str,
        digest: &str,
    ) -> Result<(), WtpError>;
}

/// Volatile ledger (NOT sufficient for production live-mode verification).
#[derive(Debug, Default)]
pub struct MemoryReplayCache {
    nonces: HashMap<(String, String), (String, String)>,
    messages: HashMap<String, (String, String)>,
}

impl ReplayLedger for MemoryReplayCache {
    fn check_equivocation(
        &mut self,
        signer: &str,
        message_id: &str,
        digest: &str,
    ) -> Result<(), WtpError> {
        if let Some((s, d)) = self.messages.get(message_id) {
            if s != signer || d != digest {
                return Err(err(ErrorCode::Equivocation, "signed message ID fork"));
            }
        }
        Ok(())
    }

    fn consume(
        &mut self,
        signer: &str,
        nonce: &str,
        message_id: &str,
        digest: &str,
    ) -> Result<(), WtpError> {
        self.check_equivocation(signer, message_id, digest)?;
        let k = (signer.to_owned(), nonce.to_owned());
        if let Some((_, d)) = self.nonces.get(&k) {
            return Err(if d == digest {
                err(ErrorCode::Replay, "replayed nonce")
            } else {
                err(
                    ErrorCode::Equivocation,
                    "nonce reused with different content",
                )
            });
        }
        self.nonces
            .insert(k, (message_id.to_owned(), digest.to_owned()));
        self.messages.insert(
            message_id.to_owned(),
            (signer.to_owned(), digest.to_owned()),
        );
        Ok(())
    }
}
