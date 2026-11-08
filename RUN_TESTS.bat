@echo off
setlocal enabledelayedexpansion

title CYBERSHIELD AI - TEST RUNNER

echo ===============================================================================
echo               CYBERSHIELD AI — AUTOMATED TEST SUITE RUNNER
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

echo [1/3] Running Backend Pytest Regression Suite (397 tests)...
echo -------------------------------------------------------------------------------
cd /d "%PROJECT_ROOT%"
"%PYTHON_EXE%" -m pytest backend\tests -v
set "PYTEST_EXIT=!errorlevel!"
echo.

echo [2/3] Running Blockchain Smart Contract Hardhat Suite (29 tests)...
echo -------------------------------------------------------------------------------
cd /d "%PROJECT_ROOT%\blockchain"
call npx.cmd hardhat test
set "HARDHAT_EXIT=!errorlevel!"
echo.

echo [3/3] Running Frontend Production Build (Vite + TypeScript)...
echo -------------------------------------------------------------------------------
cd /d "%PROJECT_ROOT%\frontend"
call npm.cmd run build
set "FRONTEND_EXIT=!errorlevel!"
echo.

echo ===============================================================================
echo                            TEST RUN SUMMARY
echo ===============================================================================
if !PYTEST_EXIT! equ 0 (
    echo   - Backend Pytest Suite   : PASS [397/397 tests passed]
) else (
    echo   - Backend Pytest Suite   : FAIL [Exit code !PYTEST_EXIT!]
)

if !HARDHAT_EXIT! equ 0 (
    echo   - Blockchain Hardhat     : PASS [29/29 tests passed]
) else (
    echo   - Blockchain Hardhat     : FAIL [Exit code !HARDHAT_EXIT!]
)

if !FRONTEND_EXIT! equ 0 (
    echo   - Frontend TypeScript    : PASS [Production build compiled]
) else (
    echo   - Frontend TypeScript    : FAIL [Exit code !FRONTEND_EXIT!]
)
echo ===============================================================================
echo.
pause

