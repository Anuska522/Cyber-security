@echo off
setlocal
set "ROOT_DIR=%~dp0"
echo Starting SecretGuard Web Studio at http://localhost:8000 ...
start http://localhost:8000
if exist "%ROOT_DIR%SecretGuard-main\.venv\Scripts\python.exe" (
    "%ROOT_DIR%SecretGuard-main\.venv\Scripts\python.exe" "%ROOT_DIR%web\server.py" 8000
) else (
    python "%ROOT_DIR%web\server.py" 8000
)
