@echo off
setlocal
set "ROOT_DIR=%~dp0"
if exist "%ROOT_DIR%SecretGuard-main\.venv\Scripts\pytest.exe" (
    "%ROOT_DIR%SecretGuard-main\.venv\Scripts\pytest.exe" "%ROOT_DIR%SecretGuard-main" %*
    exit /b %ERRORLEVEL%
)
python -m pytest "%ROOT_DIR%SecretGuard-main" %*
exit /b %ERRORLEVEL%
