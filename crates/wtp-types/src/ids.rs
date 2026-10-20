// SPDX-License-Identifier: AGPL-3.0-only
//! Validated scalar newtypes (WTP-STD-001 §2).

use crate::error::{ErrorCode, WtpError, err};
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;

fn is_lower_hex(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `true` if `s` is a lowercase UUIDv7 URN: `urn:uuid:xxxxxxxx-xxxx-7xxx-[89ab]xxx-xxxxxxxxxxxx`.
pub fn is_uuidv7_urn(s: &str) -> bool {
    let Some(u) = s.strip_prefix("urn:uuid:") else {
        return false;
    };
    let b = u.as_bytes();
    if b.len() != 36 {
        return false;
    }
    for (i, &c) in b.iter().enumerate() {
        match i {
            8 | 13 | 18 | 23 => {
                if c != b'-' {
                    return false;
                }
            }
            14 => {
                if c != b'7' {
                    return false;
                }
            }
            19 => {
                if !matches!(c, b'8' | b'9' | b'a' | b'b') {
                    return false;
                }
            }
            _ => {
                if !(c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
                    return false;
                }
            }
        }
    }
    true
}

/// `true` if `s` is `sha256:` followed by 64 lowercase hex characters.
pub fn is_sha256_digest(s: &str) -> bool {
    s.strip_prefix("sha256:")
        .is_some_and(|h| h.len() == 64 && is_lower_hex(h))
}

/// `true` for the schema's UTC second-resolution timestamp `YYYY-MM-DDTHH:MM:SSZ`
/// with a calendar-valid date and time.
pub fn is_utc_timestamp(s: &str) -> bool {
    parse_utc_seconds(s).is_some()
}

/// Parse `YYYY-MM-DDTHH:MM:SSZ` into seconds since the Unix epoch (proleptic Gregorian).
pub fn parse_utc_seconds(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() != 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
    {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let mut v = 0i64;
        for &c in &b[r] {
            if !c.is_ascii_digit() {
                return None;
            }
            v = v * 10 + i64::from(c - b'0');
        }
        Some(v)
    };
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, se) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mo) || h > 23 || mi > 59 || se > 59 {
        return None;
    }
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let dim = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if d < 1 || d > dim[(mo - 1) as usize] {
        return None;
    }
    // days_from_civil (Howard Hinnant)
    let y2 = if mo <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + h * 3600 + mi * 60 + se)
}

/// Format seconds since the Unix epoch as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn format_utc_seconds(t: i64) -> String {
    let days = t.div_euclid(86_400);
    let rem = t.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem / 60) % 60,
        rem % 60
    )
}

macro_rules! validated_string {
    ($(#[$m:meta])* $name:ident, $check:expr, $what:literal) => {
        $(#[$m])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Validate and wrap.
            pub fn parse(s: impl Into<String>) -> Result<Self, WtpError> {
                let s = s.into();
                let check: fn(&str) -> bool = $check;
                if check(&s) {
                    Ok(Self(s))
                } else {
                    Err(err(ErrorCode::Schema, concat!("invalid ", $what)))
                }
            }
            /// Borrow as `&str`.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s = String::deserialize(d)?;
                Self::parse(s).map_err(serde::de::Error::custom)
            }
        }
    };
}

validated_string!(
    /// Lowercase UUIDv7 URN (RFC 9562 §5.7), e.g. `urn:uuid:019a1111-1111-7111-8111-000000000001`.
    Urn,
    is_uuidv7_urn,
    "UUIDv7 URN"
);
validated_string!(
    /// `sha256:<64 lowercase hex>` content digest.
    Digest,
    is_sha256_digest,
    "sha256 digest"
);
validated_string!(
    /// UTC second-resolution RFC 3339 timestamp (`YYYY-MM-DDTHH:MM:SSZ`).
    Timestamp,
    is_utc_timestamp,
    "UTC timestamp"
);
validated_string!(
    /// 32-byte key encoded as 64 lowercase hex characters.
    HexKey32,
    |s| s.len() == 64 && is_lower_hex(s),
    "64-char lowercase hex key"
);
validated_string!(
    /// Unpadded Base64URL text (`[A-Za-z0-9_-]+`).
    B64u,
    |s| !s.is_empty() && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'),
    "base64url text"
);

impl Timestamp {
    /// Seconds since the Unix epoch.
    pub fn unix_seconds(&self) -> i64 {
        parse_utc_seconds(&self.0).expect("validated at construction")
    }
    /// Build from Unix seconds.
    pub fn from_unix_seconds(t: i64) -> Self {
        Self(format_utc_seconds(t))
    }
}

impl Digest {
    /// Digest of raw bytes is computed in `wtp-wire`; this builds from a hex string.
    pub fn from_hex(hex64: &str) -> Result<Self, WtpError> {
        Self::parse(format!("sha256:{hex64}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urn_validation() {
        assert!(is_uuidv7_urn(
            "urn:uuid:019a1111-1111-7111-8111-000000000001"
        ));
        assert!(!is_uuidv7_urn(
            "urn:uuid:019a1111-1111-4111-8111-000000000001"
        ));
        assert!(!is_uuidv7_urn(
            "urn:uuid:019A1111-1111-7111-8111-000000000001"
        ));
        assert!(!is_uuidv7_urn(
            "urn:uuid:019a1111-1111-7111-c111-000000000001"
        ));
        assert!(!is_uuidv7_urn(
            "urn:uuid:019a1111-1111-7111-8111-0000000000011"
        ));
    }

    #[test]
    fn timestamps_roundtrip() {
        for s in [
            "1970-01-01T00:00:00Z",
            "2026-10-18T10:00:00Z",
            "2024-02-29T23:59:59Z",
        ] {
            let t = parse_utc_seconds(s).unwrap();
            assert_eq!(format_utc_seconds(t), s);
        }
        assert_eq!(parse_utc_seconds("1970-01-01T00:00:00Z"), Some(0));
        assert!(parse_utc_seconds("2026-02-29T00:00:00Z").is_none());
        assert!(parse_utc_seconds("2026-10-18T10:00:00.5Z").is_none());
        assert!(parse_utc_seconds("2026-10-18T24:00:00Z").is_none());
    }
}
