@echo off
rem Launch the Strand GUI from the repo root.
rem Uses the installed strand-gui binary if present, else cargo run.
cd /d "%~dp0"
where strand-gui >nul 2>nul
if %errorlevel%==0 (
    strand-gui %*
) else (
    cargo run -p strand-gui %*
)
