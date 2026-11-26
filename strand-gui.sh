#!/bin/sh
# Launch the Strand GUI from the repo root.
# Uses the installed strand-gui binary if present, else cargo run.
cd "$(dirname "$0")"
if command -v strand-gui >/dev/null 2>&1; then
    exec strand-gui "$@"
else
    exec cargo run -p strand-gui "$@"
fi
