@echo off
rem Launch the Strand GUI built from this repo's current source.
rem `cargo run` rebuilds only when sources changed, so the GUI always
rem matches the checkout - no drift vs. an installed strand-gui.exe.
cd /d "%~dp0"
where cargo >nul 2>nul
if errorlevel 1 (
    echo cargo not found - install Rust from https://rustup.rs first
    pause
    exit /b 1
)
cargo run --release -p strand-gui %*
