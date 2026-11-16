@echo off
title CyberRecon Application
echo ========================================================
echo  Starting CyberRecon Web Vulnerability Assessment Platform
echo ========================================================
echo.

cd /d "%~dp0"

REM Check if uv is available
where uv >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo [INFO] Detected uv. Launching with 'uv run python run.py'...
    uv run python run.py
    goto end
)

REM Check if python is available
where python >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo [INFO] Detected python. Launching with 'python run.py'...
    python run.py
    goto end
)

echo [ERROR] Neither 'uv' nor 'python' was found in your PATH.
echo Please ensure Python 3.12+ or uv is installed and in your PATH.
echo.

:end
pause
