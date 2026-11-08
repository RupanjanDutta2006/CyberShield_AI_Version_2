@echo off
title CyberShield AI - Backend Server (Port 8000)
cd /d "%~dp0"

set "PY_EXE=%~1"
if "%PY_EXE%"=="" set "PY_EXE=python"

echo ==============================================================================
echo   CYBERSHIELD AI ? FASTAPI LIVE SERVER PROCESS
echo   Listening on: http://127.0.0.1:8000
echo   Press CTRL+C to terminate the server.
echo ==============================================================================
echo.

"%PY_EXE%" -m uvicorn app.main:app --host 127.0.0.1 --port 8000
if errorlevel 1 (
    echo.
    echo [ERROR] Server terminated with an error.
    pause
)

