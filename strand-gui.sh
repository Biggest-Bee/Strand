#!/bin/sh
# Launch the Strand GUI built from this repo's current source.
# `cargo run` rebuilds only when sources changed, so the GUI always
# matches the checkout - no drift vs. an installed strand-gui binary.
cd "$(dirname "$0")"
if ! command -v cargo >/dev/null 2>&1; then
    echo "cargo not found - install Rust from https://rustup.rs first" >&2
    exit 1
fi
exec cargo run --release -p strand-gui "$@"
