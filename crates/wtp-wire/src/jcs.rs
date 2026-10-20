// SPDX-License-Identifier: AGPL-3.0-only
//! Restricted RFC 8785 JSON Canonicalization Scheme.
//!
//! The data model is restricted to the WTP JSON profile (no floats, safe integers only), so
//! number serialization is plain decimal. Member names are sorted by UTF-16 code units as
//! required by RFC 8785 §3.2.3; string escaping follows ECMAScript `JSON.stringify`.

use crate::strict::{Limits, check_value};
use serde_json::Value;
use wtp_types::WtpError;

fn utf16_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

fn write_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write_value(out: &mut String, v: &Value) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => write_str(out, s),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, x);
            }
            out.push(']');
        }
        Value::Object(o) => {
            let mut keys: Vec<&String> = o.keys().collect();
            keys.sort_by(|a, b| utf16_cmp(a, b));
            out.push('{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_str(out, k);
                out.push(':');
                write_value(out, &o[k]);
            }
            out.push('}');
        }
    }
}

/// Canonicalize a value (ASCII member names only, as for all protocol envelopes).
pub fn canonicalize(v: &Value) -> Result<Vec<u8>, WtpError> {
    canonicalize_with(v, Limits::default())
}

/// Canonicalize with explicit limits (e.g. `allow_unicode_keys` for RFC 8785 test vectors).
pub fn canonicalize_with(v: &Value, limits: Limits) -> Result<Vec<u8>, WtpError> {
    check_value(v, limits)?;
    let mut s = String::new();
    write_value(&mut s, v);
    Ok(s.into_bytes())
}
