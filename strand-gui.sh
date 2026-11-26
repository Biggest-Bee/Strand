#!/bin/sh
# Launch the Strand GUI built from this repo's current source.
# Pulls latest main first (best-effort), then cargo run rebuilds
# only on source changes - the GUI always matches the checkout.
cd "$(dirname "$0")"
if ! command -v cargo >/dev/null 2>&1; then
    echo "cargo not found - install Rust from https://rustup.rs first" >&2
    exit 1
fi
git pull --ff-only >/dev/null 2>&1 || true
exec cargo run --release -p strand-gui "$@"
