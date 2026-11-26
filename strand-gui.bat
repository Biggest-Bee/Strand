@echo off
rem Launch the Strand GUI from the repo root.
rem Prefers an installed strand-gui.exe, else builds via cargo run.
cd /d "%~dp0"
if exist "%USERPROFILE%\.cargo\bin\strand-gui.exe" (
    "%USERPROFILE%\.cargo\bin\strand-gui.exe" %*
) else (
    cargo run -p strand-gui %*
)
