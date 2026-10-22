@echo off
setlocal enabledelayedexpansion

set "ROOT_DIR=%~dp0"
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"
chcp 65001 >nul 2>&1

if exist "%ROOT_DIR%SecretGuard-main\run.bat" (
    call "%ROOT_DIR%SecretGuard-main\run.bat" %*
    exit /b %ERRORLEVEL%
)

if exist "%ROOT_DIR%.venv\Scripts\secretguard.exe" (
    "%ROOT_DIR%.venv\Scripts\secretguard.exe" %*
    exit /b %ERRORLEVEL%
)

where python >nul 2>nul
if %errorlevel% neq 0 (
    echo SecretGuard requires Python 3.11 or newer. Please install Python.
    exit /b 1
)

python "%ROOT_DIR%run.py" %*
exit /b %ERRORLEVEL%
