// SPDX-License-Identifier: AGPL-3.0-only
//! C ABI over `wutong-core`. See `include/wutong.h`. This is the only crate allowed to use
//! `unsafe`; every entry point catches panics and validates pointers.
#![allow(unsafe_code)]

use std::ffi::{CString, c_char};
use std::panic::catch_unwind;

/// ABI version.
pub const ABI_VERSION: u32 = 0;

fn to_c(s: String) -> *mut c_char {
    CString::new(s.replace('\0', "\u{fffd}"))
        .expect("no NUL")
        .into_raw()
}

unsafe fn slice<'a>(p: *const u8, len: usize) -> &'a [u8] {
    if p.is_null() || len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(p, len) }
    }
}

unsafe fn set(out: *mut *mut c_char, v: String) {
    if !out.is_null() {
        unsafe { *out = to_c(v) };
    }
}

/// ABI version.
#[unsafe(no_mangle)]
pub extern "C" fn wutong_abi_version() -> u32 {
    ABI_VERSION
}

/// Static implementation identifier.
#[unsafe(no_mangle)]
pub extern "C" fn wutong_implementation() -> *const c_char {
    concat!("wutong-core-rs/", env!("CARGO_PKG_VERSION"), "\0")
        .as_ptr()
        .cast()
}

/// Strict parse + JCS canonicalization.
///
/// # Safety
/// `json` must point to `len` readable bytes; `out`/`err` must be null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wutong_jcs(
    json: *const u8,
    len: usize,
    out: *mut *mut c_char,
    err: *mut *mut c_char,
) -> i32 {
    let input = unsafe { slice(json, len) };
    let r = catch_unwind(|| {
        let v = wutong_core::wire::strict::parse(input)?;
        wutong_core::wire::jcs::canonicalize(&v)
    });
    match r {
        Ok(Ok(b)) => {
            unsafe { set(out, String::from_utf8(b).expect("JCS output is UTF-8")) };
            0
        }
        Ok(Err(e)) => {
            unsafe { set(err, e.to_string()) };
            1
        }
        Err(_) => {
            unsafe { set(err, "internal panic".into()) };
            -1
        }
    }
}

/// Validate an envelope.
///
/// # Safety
/// `json` must point to `len` readable bytes; `err` must be null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wutong_validate_envelope(
    json: *const u8,
    len: usize,
    err: *mut *mut c_char,
) -> i32 {
    let input = unsafe { slice(json, len) };
    match catch_unwind(|| wutong_core::parse_and_validate(input)) {
        Ok(Ok(_)) => 0,
        Ok(Err(e)) => {
            unsafe { set(err, e.to_string()) };
            1
        }
        Err(_) => {
            unsafe { set(err, "internal panic".into()) };
            -1
        }
    }
}

/// `sha256:<hex>` of bytes.
///
/// # Safety
/// `data` must point to `len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wutong_sha256(data: *const u8, len: usize) -> *mut c_char {
    let input = unsafe { slice(data, len) };
    to_c(wutong_core::wire::sha256_digest(input).to_string())
}

/// Free a string returned by this library.
///
/// # Safety
/// `s` must be null or a pointer previously returned by this library and not yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wutong_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(unsafe { CString::from_raw(s) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    #[test]
    fn jcs_roundtrip_through_abi() {
        let input = br#"{"b":1,"a":"x"}"#;
        let (mut out, mut err) = (std::ptr::null_mut(), std::ptr::null_mut());
        assert_eq!(
            unsafe { wutong_jcs(input.as_ptr(), input.len(), &mut out, &mut err) },
            0
        );
        assert_eq!(
            unsafe { CStr::from_ptr(out) }.to_str().unwrap(),
            r#"{"a":"x","b":1}"#
        );
        unsafe { wutong_string_free(out) };
        let bad = br#"{"a":1,"a":2}"#;
        assert_eq!(
            unsafe { wutong_jcs(bad.as_ptr(), bad.len(), &mut out, &mut err) },
            1
        );
        assert!(
            unsafe { CStr::from_ptr(err) }
                .to_str()
                .unwrap()
                .starts_with("ERR_SCHEMA")
        );
        unsafe { wutong_string_free(err) };
    }
}
