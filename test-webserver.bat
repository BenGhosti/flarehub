@echo off
setlocal
rem pushd mappt auch UNC-Pfade (Netzfreigabe wie \\NAS\...) auf einen
rem Laufwerksbuchstaben - cd /d wuerde dabei fehlschlagen.
pushd "%~dp0"

rem venv liegt bewusst LOKAL: pip/Python auf einer Netzfreigabe ist extrem langsam.
set "VENV_DIR=%LOCALAPPDATA%\FlareHub\venv"
set "PORT=8000"
if not "%1"=="" set "PORT=%1"
set "DB_PATH=%CD%\data\test.db"

echo ==========================================================
echo    FlareHub - Test-Server (Demo, nur fuer UI-Tests)
echo.
echo    URL:   http://localhost:%PORT%
echo    Login: PIN  1234
echo    Admin-Token (Einstellungen): test-admin-token
echo ==========================================================
echo.

REM --- Python finden (python oder py -3) ---
set "PY=python"
where python >nul 2>nul
if errorlevel 1 set "PY=py -3"

REM --- Python-Umgebung anlegen / aktualisieren ---
if not exist "%VENV_DIR%\Scripts\python.exe" (
    echo [1/3] Erstelle Python-Umgebung "%VENV_DIR%" ...
    %PY% -m venv "%VENV_DIR%" || goto :err
    echo [2/3] Installiere Abhaengigkeiten ...
    "%VENV_DIR%\Scripts\python.exe" -m pip install --upgrade pip >nul
    "%VENV_DIR%\Scripts\python.exe" -m pip install -r requirements.txt || goto :err
) else (
    echo [1/3] Python-Umgebung "%VENV_DIR%" vorhanden.
    echo [2/3] Abhaengigkeiten pruefen ...
    "%VENV_DIR%\Scripts\python.exe" -c "import fastapi, webauthn, httpx" 2>nul || (
        echo       -> installiere requirements.txt ...
        "%VENV_DIR%\Scripts\python.exe" -m pip install -r requirements.txt || goto :err
    )
)

REM --- bcrypt-Hash fuer PIN 1234 erzeugen (Ueber Temp-Datei, da for /f-Quoting zerbrechlich ist) ---
"%VENV_DIR%\Scripts\python.exe" -c "import bcrypt, pathlib; pathlib.Path(r'%TEMP%\flarehub_pin_hash.txt').write_text(bcrypt.hashpw(b'1234', bcrypt.gensalt()).decode())" || goto :err
set /p "AUTH_PIN_HASH="<"%TEMP%\flarehub_pin_hash.txt"
del "%TEMP%\flarehub_pin_hash.txt" >nul 2>nul

echo [3/3] Erzeuge Demo-Daten (PIN: 1234) ...
if not exist "%CD%\data" mkdir "%CD%\data"
set "DATABASE_PATH=%DB_PATH%"
"%VENV_DIR%\Scripts\python.exe" -W ignore::DeprecationWarning scripts\seed_demo_data.py || goto :err

echo.
echo Starte Server ... der Browser oeffnet sich in ein paar Sekunden.
rem ping = zuverlaessige Verzoegerung ohne Konsolen-Input (timeout.exe wuerde sonst meckern)
start "" /b cmd /c "ping -n 4 127.0.0.1 >nul & start http://localhost:%PORT%"

set "AUTH_MODE=pin"
set "AUTH_PIN_HASH=%AUTH_PIN_HASH%"
rem Demo-PIN hat 4 Stellen (1234), deshalb hier explizit 4 statt Default 6
set "AUTH_PIN_LENGTH=4"
set "ADMIN_TOKEN=test-admin-token"
set "SESSION_SECRET_KEY=test-secret-key-flarehub-1234-abcdef"
set "SESSION_COOKIE_SECURE=false"
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
echo  FEHLER - bitte die Meldung oben pruefen.
pause
