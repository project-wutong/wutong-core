#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Refresh vendored conformance assets from a local wutong-protocol checkout.
set -euo pipefail
SRC="${1:-../wutong-protocol}"
cd "$(dirname "$0")/.."
rm -rf conformance/{schemas,examples,vectors}
cp -r "$SRC"/schemas "$SRC"/examples "$SRC"/vectors conformance/
cp "$SRC"/schemas/core.schema.json crates/wtp-wire/src/core.schema.json
python3 tools/gen_types.py && cargo fmt --all
echo "conformance synced from $SRC"
