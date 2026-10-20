// SPDX-License-Identifier: AGPL-3.0-only
//! # wtp-document
//!
//! Source-first document primitives (WTP-STD-001 §2.4, architecture v1.4 §3.1):
//! portable relative path validation, exact-byte digests and `apply_source_patches`.
//! The crash-safe `FileCoordinator` is tracked separately (it needs OS-specific handle APIs).

use wtp_types::{ErrorCode, Provenance, SourcePatch, WtpError, err};
use wtp_wire::sha256_digest;

const WINDOWS_RESERVED: [&str; 22] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

fn trav(m: &str) -> WtpError {
    err(ErrorCode::SymlinkOrTraversal, m)
}

/// Validate a portable workspace-relative path (`binding.relative_path`).
pub fn validate_relative_path(p: &str) -> Result<(), WtpError> {
    if p.is_empty() || p.contains('\0') || p.contains('\\') || p.starts_with('/') {
        return Err(trav("unsafe relative_path"));
    }
    for part in p.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            return Err(trav("path traversal or noncanonical path"));
        }
        if part.ends_with(' ')
            || part.ends_with('.')
            || part.contains(':')
            || part.chars().any(char::is_control)
        {
            return Err(trav("non-portable path"));
        }
        let stem = part
            .split('.')
            .next()
            .unwrap_or_default()
            .to_ascii_uppercase();
        if WINDOWS_RESERVED.contains(&stem.as_str()) {
            return Err(trav("Windows reserved device name"));
        }
    }
    Ok(())
}

/// Apply ordered, non-overlapping byte-range patches, verifying base, slice and result digests.
/// All untouched bytes (BOM, CRLF/LF, comments, macros) are preserved exactly.
pub fn apply_source_patches(
    base: &[u8],
    patches: &[SourcePatch],
    expected_base_digest: Option<&str>,
    expected_proposed_digest: Option<&str>,
) -> Result<Vec<u8>, WtpError> {
    if let Some(d) = expected_base_digest {
        if sha256_digest(base).as_str() != d {
            return Err(err(
                ErrorCode::Conflict,
                "base_digest mismatch before applying patches",
            ));
        }
    }
    if patches.is_empty() {
        return Err(err(ErrorCode::Schema, "patches must be a non-empty list"));
    }
    let mut out = Vec::with_capacity(base.len());
    let mut cursor = 0usize;
    for (i, p) in patches.iter().enumerate() {
        let (s, e) = (usize::try_from(p.start_byte), usize::try_from(p.end_byte));
        let (Ok(s), Ok(e)) = (s, e) else {
            return Err(err(ErrorCode::Schema, "negative patch offset"));
        };
        if s < cursor || e < s || e > base.len() {
            return Err(err(
                ErrorCode::Conflict,
                format!("overlapping or out-of-bounds patch at index {i} ({s}..{e})"),
            ));
        }
        if sha256_digest(&base[s..e]).as_str() != p.expected_slice_digest.as_str() {
            return Err(err(
                ErrorCode::Conflict,
                format!("patch[{i}] expected_slice_digest mismatch"),
            ));
        }
        out.extend_from_slice(&base[cursor..s]);
        out.extend_from_slice(p.replacement.as_bytes());
        cursor = e;
    }
    out.extend_from_slice(&base[cursor..]);
    if let Some(d) = expected_proposed_digest {
        if sha256_digest(&out).as_str() != d {
            return Err(err(
                ErrorCode::Conflict,
                "patched document digest does not match proposed_digest",
            ));
        }
    }
    Ok(out)
}

fn looks_like_secret(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    let after = |pfx: &str, min: usize| {
        l.match_indices(pfx).any(|(i, _)| {
            l[i + pfx.len()..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric())
                .count()
                >= min
        })
    };
    l.contains("-----begin private key-----")
        || l.split_whitespace()
            .collect::<Vec<_>>()
            .windows(2)
            .any(|w| w[0] == "bearer" && !w[1].is_empty())
        || after("sk-", 16)
        || after("ghp_", 16)
}

/// W3C PROV-O provenance checks: no self-review, no credential leakage.
pub fn validate_provenance(p: &Provenance) -> Result<(), WtpError> {
    if p.reviewer_id.as_ref() == Some(&p.was_associated_with) {
        return Err(err(
            ErrorCode::Permission,
            "reviewer_id must differ from was_associated_with (no self-review)",
        ));
    }
    let mut fields: Vec<&str> = vec![p.was_generated_by.as_str()];
    fields.extend(p.tool_id.as_deref());
    fields.extend(p.used.iter().flatten().map(String::as_str));
    fields.extend(p.was_derived_from.iter().flatten().map(String::as_str));
    if fields.iter().any(|f| looks_like_secret(f)) {
        return Err(err(
            ErrorCode::Schema,
            "credential-like secret detected in provenance",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wtp_types::Digest;

    fn patch(s: i64, e: i64, base: &[u8], rep: &str) -> SourcePatch {
        SourcePatch {
            start_byte: s,
            end_byte: e,
            expected_slice_digest: Digest::parse(
                sha256_digest(&base[s as usize..e as usize]).to_string(),
            )
            .unwrap(),
            replacement: rep.into(),
        }
    }

    #[test]
    fn patches_preserve_untouched_bytes() {
        let base = "\u{feff}# T\r\npara A\r\n% comment\r\n".as_bytes();
        let p = patch(8, 14, base, "段落 A");
        let out =
            apply_source_patches(base, std::slice::from_ref(&p), Some(sha256_digest(base).as_str()), None)
                .unwrap();
        assert_eq!(out, "\u{feff}# T\r\n段落 A\r\n% comment\r\n".as_bytes());
        assert!(apply_source_patches(base, &[p.clone(), p], None, None).is_err());
        let mut bad = patch(0, 3, base, "x");
        bad.expected_slice_digest = Digest::parse(sha256_digest(b"zz").to_string()).unwrap();
        assert_eq!(
            apply_source_patches(base, &[bad], None, None)
                .unwrap_err()
                .code,
            ErrorCode::Conflict
        );
    }
}
