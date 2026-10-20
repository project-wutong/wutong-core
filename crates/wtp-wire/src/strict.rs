// SPDX-License-Identifier: AGPL-3.0-only
//! Strict `application/wtp+json` parser (WTP-STD-001 §3.1).
//!
//! Rejects: invalid UTF-8, BOM, duplicate member names, non-integer numbers (fractions,
//! exponents, `NaN`, `Infinity`), integers outside ±(2^53−1), leading zeros, unpaired
//! surrogates, non-printable-ASCII member names (unless explicitly allowed), nesting deeper
//! than [`Limits::max_depth`], inputs larger than [`Limits::max_bytes`] and trailing data.

use serde_json::{Map, Number, Value};
use wtp_types::{ErrorCode, WtpError, err};

/// Largest safe integer, 2^53 − 1.
pub const MAX_SAFE_INT: i64 = 9_007_199_254_740_991;

/// Parser limits.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Maximum input size in bytes (default 1 MiB).
    pub max_bytes: usize,
    /// Maximum nesting depth (default 40, same as the Python reference).
    pub max_depth: usize,
    /// Allow non-ASCII member names (only for JCS test vectors; never for envelopes).
    pub allow_unicode_keys: bool,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_bytes: 1_048_576,
            max_depth: 40,
            allow_unicode_keys: false,
        }
    }
}

fn schema_err(msg: impl Into<String>) -> WtpError {
    err(ErrorCode::Schema, msg)
}

/// Parse with default limits.
pub fn parse(input: &[u8]) -> Result<Value, WtpError> {
    parse_with(input, Limits::default())
}

/// Parse with explicit limits.
pub fn parse_with(input: &[u8], limits: Limits) -> Result<Value, WtpError> {
    if input.len() > limits.max_bytes {
        return Err(schema_err("size exceeded"));
    }
    let text = std::str::from_utf8(input).map_err(|_| schema_err("invalid UTF-8"))?;
    if text.starts_with('\u{feff}') {
        return Err(schema_err("BOM not allowed"));
    }
    let mut p = Parser {
        s: text.as_bytes(),
        i: 0,
        limits,
    };
    p.ws();
    let v = p.value(0)?;
    p.ws();
    if p.i != p.s.len() {
        return Err(schema_err("trailing data"));
    }
    Ok(v)
}

/// `true` if `k` is non-empty printable ASCII (0x21..=0x7E).
pub fn is_ascii_member_name(k: &str) -> bool {
    !k.is_empty() && k.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

/// Check that an in-memory value is inside the restricted JSON data model.
pub fn check_value(v: &Value, limits: Limits) -> Result<(), WtpError> {
    fn rec(v: &Value, depth: usize, l: &Limits) -> Result<(), WtpError> {
        if depth > l.max_depth {
            return Err(schema_err("nesting limit"));
        }
        match v {
            Value::Number(n) => match n.as_i64() {
                Some(i) if (-MAX_SAFE_INT..=MAX_SAFE_INT).contains(&i) => Ok(()),
                _ => Err(schema_err("only safe integers are allowed")),
            },
            Value::Array(a) => a.iter().try_for_each(|x| rec(x, depth + 1, l)),
            Value::Object(o) => o.iter().try_for_each(|(k, x)| {
                if !l.allow_unicode_keys && !is_ascii_member_name(k) {
                    return Err(schema_err("non-ASCII member name"));
                }
                rec(x, depth + 1, l)
            }),
            _ => Ok(()),
        }
    }
    rec(v, 0, &limits)
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
    limits: Limits,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while self.i < self.s.len() && matches!(self.s[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn expect(&mut self, c: u8) -> Result<(), WtpError> {
        if self.peek() == Some(c) {
            self.i += 1;
            Ok(())
        } else {
            Err(schema_err(format!(
                "expected '{}' at byte {}",
                c as char, self.i
            )))
        }
    }

    fn lit(&mut self, word: &str, v: Value) -> Result<Value, WtpError> {
        if self.s[self.i..].starts_with(word.as_bytes()) {
            self.i += word.len();
            Ok(v)
        } else {
            Err(schema_err(format!("invalid literal at byte {}", self.i)))
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, WtpError> {
        if depth > self.limits.max_depth {
            return Err(schema_err("nesting limit"));
        }
        match self.peek() {
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => Ok(Value::String(self.string()?)),
            Some(b't') => self.lit("true", Value::Bool(true)),
            Some(b'f') => self.lit("false", Value::Bool(false)),
            Some(b'n') => self.lit("null", Value::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(_) => Err(schema_err(format!(
                "unexpected token at byte {} (non-finite numbers are not JSON)",
                self.i
            ))),
            None => Err(schema_err("unexpected end of input")),
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, WtpError> {
        self.expect(b'{')?;
        let mut m = Map::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(Value::Object(m));
        }
        loop {
            self.ws();
            if self.peek() != Some(b'"') {
                return Err(schema_err("member name must be a string"));
            }
            let k = self.string()?;
            if !self.limits.allow_unicode_keys && !is_ascii_member_name(&k) {
                return Err(schema_err("non-ASCII or empty member name"));
            }
            self.ws();
            self.expect(b':')?;
            self.ws();
            let v = self.value(depth + 1)?;
            if m.contains_key(&k) {
                return Err(schema_err(format!("duplicate key {k:?}")));
            }
            m.insert(k, v);
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    return Ok(Value::Object(m));
                }
                _ => return Err(schema_err("expected ',' or '}'")),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, WtpError> {
        self.expect(b'[')?;
        let mut a = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(Value::Array(a));
        }
        loop {
            self.ws();
            a.push(self.value(depth + 1)?);
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    return Ok(Value::Array(a));
                }
                _ => return Err(schema_err("expected ',' or ']'")),
            }
        }
    }

    fn number(&mut self) -> Result<Value, WtpError> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        let digits_start = self.i;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.i += 1;
        }
        let digits = &self.s[digits_start..self.i];
        if digits.is_empty() {
            return Err(schema_err("invalid number"));
        }
        if digits.len() > 1 && digits[0] == b'0' {
            return Err(schema_err("leading zeros are not allowed"));
        }
        if matches!(self.peek(), Some(b'.' | b'e' | b'E')) {
            return Err(schema_err(
                "floating numbers not supported by wtp/0.1 JSON profile",
            ));
        }
        let text = std::str::from_utf8(&self.s[start..self.i]).expect("ascii");
        if digits.len() > 16 {
            return Err(schema_err("unsafe integer"));
        }
        let n: i64 = text.parse().map_err(|_| schema_err("invalid integer"))?;
        if !(-MAX_SAFE_INT..=MAX_SAFE_INT).contains(&n) {
            return Err(schema_err("unsafe integer"));
        }
        Ok(Value::Number(Number::from(n)))
    }

    fn hex4(&mut self) -> Result<u32, WtpError> {
        let h = self
            .s
            .get(self.i..self.i + 4)
            .ok_or_else(|| schema_err("truncated \\u escape"))?;
        let t = std::str::from_utf8(h).map_err(|_| schema_err("bad \\u escape"))?;
        let v = u32::from_str_radix(t, 16).map_err(|_| schema_err("bad \\u escape"))?;
        self.i += 4;
        Ok(v)
    }

    fn string(&mut self) -> Result<String, WtpError> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let run_start = self.i;
            while let Some(c) = self.peek() {
                if c == b'"' || c == b'\\' || c < 0x20 {
                    break;
                }
                self.i += 1;
            }
            out.push_str(std::str::from_utf8(&self.s[run_start..self.i]).expect("validated utf8"));
            match self.peek() {
                Some(b'"') => {
                    self.i += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.i += 1;
                    let e = self.peek().ok_or_else(|| schema_err("truncated escape"))?;
                    self.i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hi = self.hex4()?;
                            let cp = if (0xD800..0xDC00).contains(&hi) {
                                if self.s.get(self.i..self.i + 2) != Some(b"\\u") {
                                    return Err(schema_err("unpaired surrogate"));
                                }
                                self.i += 2;
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return Err(schema_err("unpaired surrogate"));
                                }
                                0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                            } else if (0xDC00..0xE000).contains(&hi) {
                                return Err(schema_err("unpaired surrogate"));
                            } else {
                                hi
                            };
                            out.push(
                                char::from_u32(cp).ok_or_else(|| schema_err("bad code point"))?,
                            );
                        }
                        _ => return Err(schema_err("invalid escape")),
                    }
                }
                Some(_) => return Err(schema_err("unescaped control character in string")),
                None => return Err(schema_err("unterminated string")),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_basic() {
        let v = parse(br#"{"a":[1,-2,true,null,"x\u00e9\ud834\udd1e"],"b":{}}"#).unwrap();
        assert_eq!(v["a"][4], "x\u{e9}\u{1d11e}");
    }

    #[test]
    fn rejects_bad_inputs() {
        for bad in [
            &b"{\"a\":1,\"a\":2}"[..],
            b"{\"x\": NaN}",
            b"{\"x\":1.0}",
            b"{\"x\":1e2}",
            b"{\"x\":-0.5}",
            b"{\"x\":01}",
            b"{\"x\":9007199254740992}",
            b"{\"x\":\"\\udc00\"}",
            b"{\"x\":\"\\ud800x\"}",
            b"{\"\xc3\xa9\":1}",
            b"{\"\":1}",
            b"{} x",
            b"\xef\xbb\xbf{}",
            b"{\"a\":\"\x01\"}",
        ] {
            assert!(
                parse(bad).is_err(),
                "should reject {:?}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn depth_limit_matches_reference() {
        let ok = format!("{}0{}", "[".repeat(40), "]".repeat(40));
        assert!(parse(ok.as_bytes()).is_ok());
        let bad = format!("{}0{}", "[".repeat(41), "]".repeat(41));
        assert!(parse(bad.as_bytes()).is_err());
    }
}
