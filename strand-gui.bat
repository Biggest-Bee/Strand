@echo off
rem Launch the Strand GUI from the repo root.
rem Uses the installed strand-gui.exe if present, else cargo run.
cd /d "%~dp0"
where strand-gui.exe >nul 2>nul
if %errorlevel%==0 (
    strand-gui.exe %*
) else (
    cargo run -p strand-gui %*
)
