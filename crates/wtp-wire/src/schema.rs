// SPDX-License-Identifier: AGPL-3.0-only
//! Validation against the bundled normative schema `urn:wutong:schema:core:0.1.2`.

use serde_json::Value;
use std::sync::OnceLock;
use wtp_types::{ErrorCode, WtpError, err};

/// The normative schema text bundled at build time.
pub const CORE_SCHEMA_JSON: &str = include_str!("core.schema.json");

fn validator() -> &'static jsonschema::Validator {
    static V: OnceLock<jsonschema::Validator> = OnceLock::new();
    V.get_or_init(|| {
        let schema: Value = serde_json::from_str(CORE_SCHEMA_JSON).expect("bundled schema is JSON");
        jsonschema::validator_for(&schema).expect("bundled schema compiles")
    })
}

/// Validate an envelope value; returns `ERR_SCHEMA` with the first violation.
pub fn validate(v: &Value) -> Result<(), WtpError> {
    let val = validator();
    if val.is_valid(v) {
        return Ok(());
    }
    // `oneOf` errors are noisy; report the kind-specific branch when possible.
    let detail = val
        .iter_errors(v)
        .next()
        .map(|e| format!("{e} at {}", e.instance_path()))
        .unwrap_or_else(|| "schema violation".into());
    Err(err(ErrorCode::Schema, detail))
}
