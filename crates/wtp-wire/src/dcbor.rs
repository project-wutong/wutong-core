// SPDX-License-Identifier: AGPL-3.0-only
//! `application/wtp+cbor`: RFC 8949 §4.2.1 deterministic CBOR restricted to the JSON data
//! model (WTP-STD-001 §3.2). Encoder + strict decoder that rejects non-shortest heads,
//! indefinite lengths, tags, floats/simple values other than false/true/null, byte strings,
//! unsorted or duplicate map keys and trailing bytes.

use crate::strict::{Limits, MAX_SAFE_INT, check_value, is_ascii_member_name};
use serde_json::{Map, Number, Value};
use wtp_types::{ErrorCode, WtpError, err};

fn schema_err(msg: impl Into<String>) -> WtpError {
    err(ErrorCode::Schema, msg)
}

fn head(out: &mut Vec<u8>, major: u8, arg: u64) {
    let m = major << 5;
    if arg < 24 {
        out.push(m | arg as u8);
    } else if arg <= 0xff {
        out.extend_from_slice(&[m | 24, arg as u8]);
    } else if arg <= 0xffff {
        out.push(m | 25);
        out.extend_from_slice(&(arg as u16).to_be_bytes());
    } else if arg <= 0xffff_ffff {
        out.push(m | 26);
        out.extend_from_slice(&(arg as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&arg.to_be_bytes());
    }
}

fn enc_text(s: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(s.len() + 3);
    head(&mut v, 3, s.len() as u64);
    v.extend_from_slice(s.as_bytes());
    v
}

fn encode_item(out: &mut Vec<u8>, v: &Value) {
    match v {
        Value::Null => out.push(0xf6),
        Value::Bool(false) => out.push(0xf4),
        Value::Bool(true) => out.push(0xf5),
        Value::Number(n) => {
            let i = n.as_i64().expect("checked safe integer");
            if i >= 0 {
                head(out, 0, i as u64);
            } else {
                head(out, 1, (-1 - i) as u64);
            }
        }
        Value::String(s) => out.extend_from_slice(&enc_text(s)),
        Value::Array(a) => {
            head(out, 4, a.len() as u64);
            for x in a {
                encode_item(out, x);
            }
        }
        Value::Object(o) => {
            let mut entries: Vec<(Vec<u8>, &Value)> =
                o.iter().map(|(k, v)| (enc_text(k), v)).collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            head(out, 5, entries.len() as u64);
            for (k, v) in entries {
                out.extend_from_slice(&k);
                encode_item(out, v);
            }
        }
    }
}

/// Encode a value as deterministic CBOR.
pub fn encode(v: &Value) -> Result<Vec<u8>, WtpError> {
    encode_with(v, Limits::default())
}

/// Encode with explicit limits.
pub fn encode_with(v: &Value, limits: Limits) -> Result<Vec<u8>, WtpError> {
    check_value(v, limits)?;
    let mut out = Vec::new();
    encode_item(&mut out, v);
    Ok(out)
}

/// Strictly decode deterministic CBOR into a JSON value.
pub fn decode(buf: &[u8]) -> Result<Value, WtpError> {
    decode_with(buf, Limits::default())
}

/// Strictly decode with explicit limits.
pub fn decode_with(buf: &[u8], limits: Limits) -> Result<Value, WtpError> {
    if buf.len() > limits.max_bytes {
        return Err(schema_err("size exceeded"));
    }
    let mut d = Decoder {
        b: buf,
        i: 0,
        limits,
    };
    let v = d.item(0)?;
    if d.i != buf.len() {
        return Err(schema_err("trailing bytes after CBOR root"));
    }
    Ok(v)
}

struct Decoder<'a> {
    b: &'a [u8],
    i: usize,
    limits: Limits,
}

impl Decoder<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], WtpError> {
        let end = self.i.checked_add(n).filter(|&e| e <= self.b.len());
        let end = end.ok_or_else(|| schema_err("truncated CBOR"))?;
        let s = &self.b[self.i..end];
        self.i = end;
        Ok(s)
    }

    fn head(&mut self) -> Result<(u8, u8, u64), WtpError> {
        let ib = self.take(1)?[0];
        let (major, ai) = (ib >> 5, ib & 0x1f);
        let arg = match ai {
            0..=23 => u64::from(ai),
            24 => {
                let v = u64::from(self.take(1)?[0]);
                if v < 24 {
                    return Err(schema_err("non-minimal 1-byte CBOR integer encoding"));
                }
                v
            }
            25 => {
                let v = u64::from(u16::from_be_bytes(self.take(2)?.try_into().expect("2")));
                if v <= 0xff {
                    return Err(schema_err("non-minimal 2-byte CBOR integer encoding"));
                }
                v
            }
            26 => {
                let v = u64::from(u32::from_be_bytes(self.take(4)?.try_into().expect("4")));
                if v <= 0xffff {
                    return Err(schema_err("non-minimal 4-byte CBOR integer encoding"));
                }
                v
            }
            27 => {
                let v = u64::from_be_bytes(self.take(8)?.try_into().expect("8"));
                if v <= 0xffff_ffff {
                    return Err(schema_err("non-minimal 8-byte CBOR integer encoding"));
                }
                v
            }
            31 => return Err(schema_err("indefinite-length CBOR is forbidden")),
            _ => return Err(schema_err("reserved CBOR additional info")),
        };
        Ok((major, ai, arg))
    }

    fn text(&mut self, len: u64) -> Result<String, WtpError> {
        let len = usize::try_from(len).map_err(|_| schema_err("length overflow"))?;
        let bytes = self.take(len)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| schema_err("invalid UTF-8 in CBOR text"))
    }

    fn item(&mut self, depth: usize) -> Result<Value, WtpError> {
        if depth > self.limits.max_depth {
            return Err(schema_err("nesting limit"));
        }
        let (major, ai, arg) = self.head()?;
        match major {
            0 => {
                if arg > MAX_SAFE_INT as u64 {
                    return Err(schema_err("unsafe integer"));
                }
                Ok(Value::Number(Number::from(arg as i64)))
            }
            1 => {
                if arg > (MAX_SAFE_INT - 1) as u64 {
                    return Err(schema_err("unsafe integer"));
                }
                Ok(Value::Number(Number::from(-1 - arg as i64)))
            }
            2 => Err(schema_err("raw CBOR byte strings are forbidden")),
            3 => Ok(Value::String(self.text(arg)?)),
            4 => {
                let n = usize::try_from(arg).map_err(|_| schema_err("length overflow"))?;
                if n > self.b.len() - self.i {
                    return Err(schema_err("truncated CBOR array"));
                }
                let mut a = Vec::with_capacity(n);
                for _ in 0..n {
                    a.push(self.item(depth + 1)?);
                }
                Ok(Value::Array(a))
            }
            5 => {
                let n = usize::try_from(arg).map_err(|_| schema_err("length overflow"))?;
                if n > self.b.len() - self.i {
                    return Err(schema_err("truncated CBOR map"));
                }
                let mut m = Map::new();
                let mut prev: Option<Vec<u8>> = None;
                for _ in 0..n {
                    let k_start = self.i;
                    let (km, _, klen) = self.head()?;
                    if km != 3 {
                        return Err(schema_err("CBOR map keys must be text strings"));
                    }
                    let k = self.text(klen)?;
                    let kbytes = self.b[k_start..self.i].to_vec();
                    if let Some(p) = &prev {
                        if kbytes <= *p {
                            return Err(schema_err("CBOR map keys out of order or duplicated"));
                        }
                    }
                    if !self.limits.allow_unicode_keys && !is_ascii_member_name(&k) {
                        return Err(schema_err("non-ASCII member name"));
                    }
                    prev = Some(kbytes);
                    let v = self.item(depth + 1)?;
                    m.insert(k, v);
                }
                Ok(Value::Object(m))
            }
            6 => Err(schema_err("CBOR tags are forbidden")),
            7 => match ai {
                20 => Ok(Value::Bool(false)),
                21 => Ok(Value::Bool(true)),
                22 => Ok(Value::Null),
                _ => Err(schema_err("CBOR floats/simple values are forbidden")),
            },
            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_noncanonical() {
        for hex_in in [
            "1801",           // non-minimal 1
            "190001",         // non-minimal 2-byte
            "9fff",           // indefinite array
            "4161",           // byte string
            "c100",           // tag
            "f93c00",         // half float
            "a2616201616101", // unsorted keys
            "a2616101616101", // duplicate keys
            "0000",           // trailing
        ] {
            assert!(decode(&hex::decode(hex_in).unwrap()).is_err(), "{hex_in}");
        }
    }
}
