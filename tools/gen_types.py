#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Generate crates/wtp-types/src/generated.rs from the normative JSON Schema.

Usage: python3 tools/gen_types.py [conformance/schemas/core.schema.json]
CI re-runs this and fails if the checked-in file differs (schema/type drift guard).
"""
import json, pathlib, re, sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCHEMA = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "conformance/schemas/core.schema.json"
OUT = ROOT / "crates/wtp-types/src/generated.rs"
s = json.loads(SCHEMA.read_text())

URN = "^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
PATTERN_TYPES = {
    URN: "Urn",
    "^sha256:[0-9a-f]{64}$": "Digest",
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$": "Timestamp",
    "^[0-9a-f]{64}$": "HexKey32",
    "^[A-Za-z0-9_-]+$": "B64u",
    "^[A-Za-z0-9_-]{16}$": "B64u",
}
NAME_OVERRIDES = {
    "provenance": "Provenance",
    "patches": "SourcePatch",
    "member_wraps": "MemberWrap",
    "binding": "DocumentBinding",
    "selector": "Selector",
    "endpoints": "NodeEndpoints",
}
RUST_KW = {"type": "r#type", "ref": "r#ref", "use": "r#use", "match": "r#match"}

def pascal(x):
    return "".join(p[:1].upper() + p[1:] for p in re.split(r"[^A-Za-z0-9]+", x) if p)

def variant(v):
    if v.upper() == v:
        v = v.lower()
    name = pascal(v.replace("+", " plus ").replace("/", " v "))
    if name[:1].isdigit():
        name = "V" + name
    return name

items = []          # emitted code blocks
emitted = {}        # name -> json signature (dedupe)

def emit_enum(name, values, doc):
    sig = json.dumps(values)
    if name in emitted:
        assert emitted[name] == sig, f"conflicting enum {name}"
        return name
    emitted[name] = sig
    lines = [f"/// {doc}", "#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]", f"pub enum {name} {{"]
    for v in values:
        lines.append(f"    /// `{v}`")
        lines.append(f'    #[serde(rename = "{v}")]')
        lines.append(f"    {variant(v)},")
    lines.append("}")
    lines.append(f"impl {name} {{")
    lines.append("    /// Wire string.")
    lines.append("    pub const fn as_str(self) -> &'static str {")
    lines.append("        match self {")
    for v in values:
        lines.append(f'            Self::{variant(v)} => "{v}",')
    lines.append("        }\n    }\n}")
    items.append("\n".join(lines))
    return name

def rust_type(owner, field, sch):
    if "enum" in sch or "const" in sch:
        if field == "error_code":
            return "crate::ErrorCode"
        values = sch.get("enum") or [sch["const"]]
        return emit_enum(owner + pascal(field), values, f"Allowed values of `{field}`.")
    t = sch.get("type")
    if t == "string":
        return PATTERN_TYPES.get(sch.get("pattern"), "String")
    if t == "integer":
        return "i64"
    if t == "boolean":
        return "bool"
    if t == "array":
        it = sch["items"]
        if it.get("type") == "object" and "properties" in it:
            return f"Vec<{emit_struct(NAME_OVERRIDES.get(field, owner + pascal(field)), it, f'Item of `{field}`.')}>"
        if "enum" in it or "const" in it:
            values = it.get("enum") or [it["const"]]
            base = owner + pascal(field)
            if base.endswith("s"):
                base = base[:-1]
            return f"Vec<{emit_enum(base, values, f'Allowed item values of `{field}`.')}>"
        return f"Vec<{rust_type(owner, field, it)}>"
    if t == "object":
        if "properties" in sch:
            return emit_struct(NAME_OVERRIDES.get(field, owner + pascal(field)), sch, f"`{field}` object.")
        return "Map<String, Value>"
    raise SystemExit(f"unsupported schema for {owner}.{field}: {sch}")

def emit_struct(name, sch, doc):
    sig = json.dumps(sch, sort_keys=True)
    if name in emitted:
        assert emitted[name] == sig, f"conflicting struct {name}"
        return name
    emitted[name] = sig
    req = set(sch.get("required", []))
    fields = []
    for f, fs in sch["properties"].items():
        ty = rust_type(name.removesuffix("Payload"), f, fs)
        fields.append((f, ty, f in req))
    lines = [f"/// {doc}", "#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]", "#[serde(deny_unknown_fields)]", f"pub struct {name} {{"]
    for f, ty, r in fields:
        lines.append(f"    /// `{f}`{' (required)' if r else ''}.")
        rf = RUST_KW.get(f, f)
        if rf != f or f != f.lower():
            lines.append(f'    #[serde(rename = "{f}")]')
            rf = RUST_KW.get(f, f.lower())
        if r:
            lines.append(f"    pub {rf}: {ty},")
        else:
            lines.append('    #[serde(default, skip_serializing_if = "Option::is_none")]')
            lines.append(f"    pub {rf}: Option<{ty}>,")
    lines.append("}")
    items.append("\n".join(lines))
    return name

kinds = []
for br in s["oneOf"]:
    kind = br["properties"]["kind"]["const"]
    short = kind.split(".", 1)[1]
    name = pascal(short) + "Payload"
    emit_struct(name, br["properties"]["payload"], f"Payload of `{kind}`.")
    kinds.append((kind, pascal(short), name))

hdr = f'''// SPDX-License-Identifier: AGPL-3.0-only
// @generated by tools/gen_types.py from `{s["$id"]}` — DO NOT EDIT BY HAND.
//! Typed payloads for all {len(kinds)} normative message kinds.
#![allow(clippy::large_enum_variant)]

use crate::ids::{{B64u, Digest, HexKey32, Timestamp, Urn}};
use serde::{{Deserialize, Serialize}};
use serde_json::{{Map, Value}};

/// Schema identifier this module was generated from.
pub const SCHEMA_ID: &str = "{s["$id"]}";
'''
kind_enum = ["/// The normative message kinds (`kind` field).", "#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]", "pub enum Kind {"]
for k, v, _ in kinds:
    kind_enum += [f"    /// `{k}`", f'    #[serde(rename = "{k}")]', f"    {v},"]
kind_enum.append("}")
kind_enum.append("impl Kind {")
kind_enum.append(f"    /// All kinds in schema order.\n    pub const ALL: [Kind; {len(kinds)}] = [" + ", ".join(f"Kind::{v}" for _, v, _ in kinds) + "];")
kind_enum.append("    /// Wire string, e.g. `wutong.object`.\n    pub const fn as_str(self) -> &'static str {\n        match self {")
for k, v, _ in kinds:
    kind_enum.append(f'            Kind::{v} => "{k}",')
kind_enum.append("        }\n    }")
kind_enum.append("    /// Parse a wire string.\n    pub fn from_wire(s: &str) -> Option<Self> {\n        Self::ALL.into_iter().find(|k| k.as_str() == s)\n    }\n}")
payload_enum = ["/// A typed payload, discriminated by [`Kind`].", "#[derive(Debug, Clone, PartialEq)]", "pub enum Payload {"]
for k, v, n in kinds:
    payload_enum += [f"    /// `{k}`", f"    {v}({n}),"]
payload_enum.append("}")
payload_enum.append("impl Payload {")
payload_enum.append("    /// The kind of this payload.\n    pub fn kind(&self) -> Kind {\n        match self {")
for _, v, _ in kinds:
    payload_enum.append(f"            Payload::{v}(_) => Kind::{v},")
payload_enum.append("        }\n    }")
payload_enum.append("    /// Decode a payload JSON object for the given kind (unknown members are rejected).\n    pub fn from_value(kind: Kind, v: Value) -> Result<Self, serde_json::Error> {\n        Ok(match kind {")
for _, v, n in kinds:
    payload_enum.append(f"            Kind::{v} => Payload::{v}(serde_json::from_value(v)?),")
payload_enum.append("        })\n    }")
payload_enum.append("    /// Encode back to a JSON value.\n    pub fn to_value(&self) -> Result<Value, serde_json::Error> {\n        match self {")
for _, v, _ in kinds:
    payload_enum.append(f"            Payload::{v}(p) => serde_json::to_value(p),")
payload_enum.append("        }\n    }\n}")
OUT.write_text(hdr + "\n" + "\n\n".join(["\n".join(kind_enum), "\n".join(payload_enum)] + items) + "\n")
print(f"generated {OUT.relative_to(ROOT)}: {len(kinds)} kinds, {len(emitted)} types")
