@echo off
setlocal enabledelayedexpansion

title CYBERSHIELD AI - SAFE STOP

echo ===============================================================================
echo                 CYBERSHIELD AI — SAFE SHUTDOWN SCRIPT
echo ===============================================================================
echo.

set "PROJECT_ROOT=%~dp0"
if "%PROJECT_ROOT:~-1%"=="\" set "PROJECT_ROOT=%PROJECT_ROOT:~0,-1%"

set "PYTHON_EXE="
if exist "%PROJECT_ROOT%\backend\venv\Scripts\python.exe" (
    set "PYTHON_EXE=%PROJECT_ROOT%\backend\venv\Scripts\python.exe"
) else if exist "%PROJECT_ROOT%\venv\Scripts\python.exe" (
    set "PYTHON_EXE=%PROJECT_ROOT%\venv\Scripts\python.exe"
) else (
    set "PYTHON_EXE=python"
)

if exist "%PROJECT_ROOT%\backend\stop_servers.py" (
    "%PYTHON_EXE%" "%PROJECT_ROOT%\backend\stop_servers.py"
) else (
    echo [INFO] Inspecting active server processes on ports 8000 and 5173...
    for /f "tokens=5" %%a in ('netstat -a -n -o ^| findstr :8000 ^| findstr LISTENING') do (
        call :KILL_PROC %%a python.exe
    )
    for /f "tokens=5" %%a in ('netstat -a -n -o ^| findstr :5173 ^| findstr LISTENING') do (
        call :KILL_PROC %%a node.exe
    )
)

echo.
echo ===============================================================================
echo [DONE] Shutdown complete. Unrelated processes were unaffected.
echo ===============================================================================
echo.
pause
exit /b 0

:KILL_PROC
set "TARGET_PID=%1"
set "EXPECTED_NAME=%2"
if not defined TARGET_PID goto :eof
for /f "tokens=1" %%p in ('tasklist /FI "PID eq %TARGET_PID%" /NH 2^>nul') do (
    if /I "%%p"=="%EXPECTED_NAME%" (
        echo [STOPPING] Terminating %EXPECTED_NAME% [PID %TARGET_PID%]...
        taskkill /PID %TARGET_PID% /F /T >nul 2>&1
    )
)
goto :eof
