@echo off
setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"
chcp 65001 >nul 2>&1

:: 1. Check for Python
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo SecretGuard requires Python 3.11 or newer. Please install Python.
    exit /b 1
)

:: 2. Provision virtualenv if missing
if not exist ".venv" (
    echo Creating virtual environment in .venv...
    python -m venv .venv
)

:: 3. Quietly install dependencies if secretguard.exe is missing
if not exist ".venv\Scripts\secretguard.exe" (
    echo Provisioning dependencies...
    .venv\Scripts\pip install -q --upgrade pip
    .venv\Scripts\pip install -q -e .
)

:: 4. Launch SecretGuard
.venv\Scripts\secretguard.exe %*
