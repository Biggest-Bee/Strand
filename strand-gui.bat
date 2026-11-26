@echo off
rem Launch the Strand GUI built from this repo's current source.
rem Pulls latest main first (best-effort), then cargo run rebuilds
rem only on source changes - the GUI always matches the checkout.
cd /d "%~dp0"
where cargo >nul 2>nul
if errorlevel 1 (
    echo cargo not found - install Rust from https://rustup.rs first
    pause
    exit /b 1
)
git pull --ff-only >nul 2>nul
cargo run --release -p strand-gui %*
