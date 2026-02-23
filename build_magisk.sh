#!/bin/bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIST_DIR="$PROJECT_DIR/dist"
BINARY="$DIST_DIR/ebpf-open-static"
CONFIG="$PROJECT_DIR/crates/res/config.toml"
MAGISK_DIR="$PROJECT_DIR/magisk"
OUTPUT="$DIST_DIR/ebpf-open-magisk.zip"

if [ "${1:-}" = "--build" ]; then
    echo "Building static binary..."
    "$PROJECT_DIR/build_musl.sh"
fi

for f in "$BINARY" "$CONFIG" "$MAGISK_DIR/module.prop" "$MAGISK_DIR/customize.sh" "$MAGISK_DIR/service.sh"; do
    if [ ! -f "$f" ]; then
        echo "ERROR: missing $f"
        exit 1
    fi
done

mkdir -p "$DIST_DIR"
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

cp "$MAGISK_DIR/module.prop"   "$TMPDIR/"
cp "$MAGISK_DIR/customize.sh"  "$TMPDIR/"
cp "$MAGISK_DIR/service.sh"    "$TMPDIR/"
cp "$BINARY"                   "$TMPDIR/ebpf-open"
cp "$CONFIG"                   "$TMPDIR/config.toml"

rm -f "$OUTPUT"
(cd "$TMPDIR" && zip -r "$OUTPUT" .)

echo "Magisk module: $OUTPUT"
