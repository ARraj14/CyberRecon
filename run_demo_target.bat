@echo off
title CyberRecon Demo Target
echo ========================================================
echo  Starting CyberRecon Controlled Demo Target (Port 5001)
echo ========================================================
echo.

cd /d "%~dp0"
set CYBERRECON_DEMO_PROFILE=missing

where uv >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo [INFO] Detected uv. Launching demo target...
    uv run python demo_target\app.py
    goto end
)

where python >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo [INFO] Detected python. Launching demo target...
    python demo_target\app.py
    goto end
)

echo [ERROR] Neither 'uv' nor 'python' was found in your PATH.
echo.

:end
pause
