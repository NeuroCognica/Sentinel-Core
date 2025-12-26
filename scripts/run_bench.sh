#!/usr/bin/env bash
set -euo pipefail

WORKDIR="$(dirname "$0")/.."
cd "$WORKDIR"

OUT_DIR=crates/sentinel_bench/bench-results
mkdir -p "$OUT_DIR"
TS=$(date +%Y%m%dT%H%M%S)
OUT_FILE="$OUT_DIR/bench-${TS}.txt"

echo "Running sentinel_bench (release). Output -> $OUT_FILE"
cd crates/sentinel_bench
cargo run --release 2>&1 | tee "$PWD/../$OUT_FILE"
echo "Done. Results: $OUT_FILE"
