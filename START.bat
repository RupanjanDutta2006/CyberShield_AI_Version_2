@echo off
setlocal enabledelayedexpansion

title CYBERSHIELD AI - LAUNCHER

echo ===============================================================================
echo                CYBERSHIELD AI — ONE-CLICK LAUNCHER
echo          Intelligent Threat Detection and Blockchain Verification
echo ===============================================================================
echo.

set "PROJECT_ROOT=%~dp0"
if "%PROJECT_ROOT:~-1%"=="\" set "PROJECT_ROOT=%PROJECT_ROOT:~0,-1%"

set "BACKEND_DIR=%PROJECT_ROOT%\backend"
set "FRONTEND_DIR=%PROJECT_ROOT%\frontend"

:: -----------------------------------------------------------------------------
:: 1. Validate Project Directories
:: -----------------------------------------------------------------------------
if not exist "%BACKEND_DIR%" (
    echo [ERROR] Backend directory not found: "%BACKEND_DIR%"
    echo Please verify project folder integrity.
    echo.
    pause
    exit /b 1
)

if not exist "%FRONTEND_DIR%" (
    echo [ERROR] Frontend directory not found: "%FRONTEND_DIR%"
    echo Please verify project folder integrity.
    echo.
    pause
    exit /b 1
)

:: -----------------------------------------------------------------------------
:: 2. Check Python Environment and Dependencies
:: -----------------------------------------------------------------------------
set "PYTHON_EXE="
set "VENV_ACTIVATE="

if exist "%BACKEND_DIR%\venv\Scripts\python.exe" (
    set "PYTHON_EXE=%BACKEND_DIR%\venv\Scripts\python.exe"
    set "VENV_ACTIVATE=%BACKEND_DIR%\venv\Scripts\activate.bat"
    echo [INFO] Detected backend virtual environment: "%BACKEND_DIR%\venv"
    goto :PYTHON_READY
)

if exist "%PROJECT_ROOT%\venv\Scripts\python.exe" (
    set "PYTHON_EXE=%PROJECT_ROOT%\venv\Scripts\python.exe"
    set "VENV_ACTIVATE=%PROJECT_ROOT%\venv\Scripts\activate.bat"
    echo [INFO] Detected project virtual environment: "%PROJECT_ROOT%\venv"
    goto :PYTHON_READY
)

if exist "%BACKEND_DIR%\env\Scripts\python.exe" (
    set "PYTHON_EXE=%BACKEND_DIR%\env\Scripts\python.exe"
    set "VENV_ACTIVATE=%BACKEND_DIR%\env\Scripts\activate.bat"
    echo [INFO] Detected backend virtual environment: "%BACKEND_DIR%\env"
    goto :PYTHON_READY
)

where python >nul 2>&1
if !errorlevel! equ 0 (
    set "PYTHON_EXE=python"
    echo [INFO] Using system Python environment.
    goto :PYTHON_READY
)

echo [ERROR] Python is not installed or not found in system PATH.
echo Please install Python 3.11 or higher from https://www.python.org/
echo.
pause
exit /b 1

:PYTHON_READY
:: Verify backend application imports and required dependencies
echo [INFO] Verifying backend dependencies and application import...
"%PYTHON_EXE%" -c "import sys; sys.path.insert(0, r'%BACKEND_DIR%'); from app.main import app" >nul 2>&1
if !errorlevel! neq 0 (
    echo.
    echo [ERROR] Backend import verification failed!
    echo Required dependencies might be missing or broken.
    echo Please install dependencies manually using:
    echo   cd /d "%BACKEND_DIR%"
    echo   pip install -r requirements.txt
    echo.
    pause
    exit /b 1
)
echo [OK] Backend environment and dependencies verified.

:: -----------------------------------------------------------------------------
:: 3. Check Node.js, npm, and Frontend Dependencies
:: -----------------------------------------------------------------------------
where node >nul 2>&1
if !errorlevel! neq 0 (
    echo [ERROR] Node.js is not installed or not found in system PATH.
    echo Please install Node.js 18 or higher from https://nodejs.org/
    echo.
    pause
    exit /b 1
)

where npm >nul 2>&1
if !errorlevel! neq 0 (
    echo [ERROR] npm is not installed or not found in system PATH.
    echo.
    pause
    exit /b 1
)

if not exist "%FRONTEND_DIR%\package.json" (
    echo [ERROR] Frontend package.json not found in: "%FRONTEND_DIR%"
    echo.
    pause
    exit /b 1
)

if not exist "%FRONTEND_DIR%\node_modules" (
    echo.
    echo [ERROR] Frontend node_modules folder is missing!
    echo Please install frontend dependencies by running:
    echo   cd /d "%FRONTEND_DIR%"
    echo   npm install
    echo.
    pause
    exit /b 1
)
echo [OK] Node.js, npm, and frontend dependencies verified.
echo.

:: -----------------------------------------------------------------------------
:: 4. Start Backend Server (Port 8000)
:: -----------------------------------------------------------------------------
"%PYTHON_EXE%" -c "import socket; s = socket.socket(); s.settimeout(0.5); r = s.connect_ex(('127.0.0.1', 8000)); s.close(); exit(0 if r == 0 else 1)" >nul 2>&1
if !errorlevel! equ 0 (
    echo [INFO] Backend is already running on http://127.0.0.1:8000. Skipping duplicate launch.
    goto :CHECK_FRONTEND
)

echo [STARTING] Launching CyberShield AI Backend on http://127.0.0.1:8000 ...
if defined VENV_ACTIVATE (
    start "CYBERSHIELD AI - BACKEND (Port 8000)" cmd /k "title CYBERSHIELD AI - BACKEND (Port 8000) && cd /d "%BACKEND_DIR%" && call "%VENV_ACTIVATE%" && echo ======================================================== && echo   CYBERSHIELD AI BACKEND SERVER [Port 8000] && echo   API Docs: http://127.0.0.1:8000/docs && echo ======================================================== && echo. && python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload"
) else (
    start "CYBERSHIELD AI - BACKEND (Port 8000)" cmd /k "title CYBERSHIELD AI - BACKEND (Port 8000) && cd /d "%BACKEND_DIR%" && echo ======================================================== && echo   CYBERSHIELD AI BACKEND SERVER [Port 8000] && echo   API Docs: http://127.0.0.1:8000/docs && echo ======================================================== && echo. && "%PYTHON_EXE%" -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload"
)

:CHECK_FRONTEND
:: -----------------------------------------------------------------------------
:: 5. Start Frontend Server (Port 5173)
:: -----------------------------------------------------------------------------
"%PYTHON_EXE%" -c "import socket; s = socket.socket(); s.settimeout(0.5); r = s.connect_ex(('127.0.0.1', 5173)); s.close(); exit(0 if r == 0 else 1)" >nul 2>&1
if !errorlevel! equ 0 (
    echo [INFO] Frontend is already running on http://localhost:5173. Skipping duplicate launch.
    goto :SERVERS_STARTED
)

echo [STARTING] Launching CyberShield AI Frontend on http://localhost:5173 ...
start "CYBERSHIELD AI - FRONTEND (Port 5173)" cmd /k "title CYBERSHIELD AI - FRONTEND (Port 5173) && cd /d "%FRONTEND_DIR%" && echo ======================================================== && echo   CYBERSHIELD AI FRONTEND DEVELOPMENT SERVER [Port 5173] && echo   App URL: http://localhost:5173 && echo ======================================================== && echo. && npm.cmd run dev"

:SERVERS_STARTED
:: -----------------------------------------------------------------------------
:: 6. Health Check and Browser Launch
:: -----------------------------------------------------------------------------
echo.
echo [INFO] Initializing application services, please wait...
ping 127.0.0.1 -n 4 >nul

:: Health check ping
powershell -NoProfile -ExecutionPolicy Bypass -Command "try { $res = Invoke-WebRequest -Uri 'http://127.0.0.1:8000/api/v1/health' -UseBasicParsing -TimeoutSec 4; if ($res.StatusCode -eq 200) { Write-Host '[SUCCESS] Backend is responsive at http://127.0.0.1:8000' -ForegroundColor Green } } catch { Write-Host '[WAIT] Backend is still starting up. Please check the backend console window.' -ForegroundColor Yellow }"

echo [INFO] Opening CyberShield AI in your default web browser...
start http://localhost:5173

echo.
echo ===============================================================================
echo                      CYBERSHIELD AI IS RUNNING
echo ===============================================================================
echo   - Frontend Interface : http://localhost:5173
echo   - Backend API Base   : http://127.0.0.1:8000
echo   - Interactive Docs   : http://127.0.0.1:8000/docs
echo   - ReDoc Reference    : http://127.0.0.1:8000/redoc
echo.
echo   Keep both server command prompt windows open while using the application.
echo   To safely stop both servers, run STOP.bat
echo ===============================================================================
echo.
pause
