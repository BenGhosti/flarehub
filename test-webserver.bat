@echo off
setlocal
rem pushd also maps UNC paths (network shares like \\NAS\...) to a drive letter -
rem "cd /d" would fail there.
pushd "%~dp0"

rem venv intentionally LOCAL: pip/Python on a network share is extremely slow.
set "VENV_DIR=%LOCALAPPDATA%\FlareHub\venv"
set "PORT=8000"
if not "%1"=="" set "PORT=%1"
set "DB_PATH=%CD%\data\test.db"

echo ==========================================================
echo    FlareHub - Test server (demo, UI tests only)
echo.
echo    URL:   http://localhost:%PORT%
echo    Login: PIN  1234
echo    Admin token (Settings): test-admin-token
echo ==========================================================
echo.

REM --- Find Python (python or py -3) ---
set "PY=python"
where python >nul 2>nul
if errorlevel 1 set "PY=py -3"

REM --- Create / update the Python environment ---
if not exist "%VENV_DIR%\Scripts\python.exe" (
    echo [1/3] Creating Python environment "%VENV_DIR%" ...
    %PY% -m venv "%VENV_DIR%" || goto :err
    echo [2/3] Installing dependencies ...
    "%VENV_DIR%\Scripts\python.exe" -m pip install --upgrade pip >nul
    "%VENV_DIR%\Scripts\python.exe" -m pip install -r requirements.txt || goto :err
) else (
    echo [1/3] Python environment "%VENV_DIR%" present.
    echo [2/3] Checking dependencies ...
    "%VENV_DIR%\Scripts\python.exe" -c "import fastapi, webauthn, httpx" 2>nul || (
        echo       -> installing requirements.txt ...
        "%VENV_DIR%\Scripts\python.exe" -m pip install -r requirements.txt || goto :err
    )
)

echo [3/3] Creating demo data (PIN: 1234) ...
if not exist "%CD%\data" mkdir "%CD%\data"
set "DATABASE_PATH=%DB_PATH%"
"%VENV_DIR%\Scripts\python.exe" -W ignore::DeprecationWarning scripts\seed_demo_data.py || goto :err

echo.
echo Starting server ... the browser will open in a few seconds.
rem ping = reliable delay without console input (timeout.exe would complain otherwise)
start "" /b cmd /c "ping -n 4 127.0.0.1 >nul & start http://localhost:%PORT%"

set "AUTH_MODE=pin"
rem Plaintext PIN (no bcrypt hash needed - avoids "$" escaping issues with Docker Compose)
set "AUTH_PIN=1234"
rem Demo PIN has 4 digits (1234), so set 4 explicitly instead of the default 6
set "AUTH_PIN_LENGTH=4"
set "ADMIN_TOKEN=test-admin-token"
set "SESSION_SECRET_KEY=test-secret-key-flarehub-1234-abcdef"
set "LOG_LEVEL=INFO"
set "COLLECTOR_RUN_ON_STARTUP=false"
set "COLLECTOR_INTERVAL_MINUTES=10"
set "DASHBOARD_AUTO_REFRESH_SECONDS=0"
set "CLOUDFLARE_API_TOKEN="
set "CLOUDFLARE_ZONE_ID="
set "DATABASE_PATH=%DB_PATH%"

"%VENV_DIR%\Scripts\python.exe" -m uvicorn app.main:app --host 127.0.0.1 --port %PORT%
goto :eof

:err
echo.
echo  ERROR - check the message above.
pause
