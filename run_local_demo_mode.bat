@echo off
title CyberRecon (Local & Private Targets Allowed)
echo ========================================================
echo  Starting CyberRecon with Local Target Assessment Enabled
echo  (Enables scanning http://127.0.0.1:5001)
echo ========================================================
echo.

cd /d "%~dp0"

set CYBERRECON_ALLOW_PRIVATE_TARGETS=1
set CYBERRECON_SECURE_COOKIES=0
set CYBERRECON_ENABLE_HSTS=0
set CYBERRECON_DEBUG=1

where uv >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo [INFO] Detected uv. Launching CyberRecon...
    uv run python run.py
    goto end
)

where python >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo [INFO] Detected python. Launching CyberRecon...
    python run.py
    goto end
)

echo [ERROR] Neither 'uv' nor 'python' was found in your PATH.
echo.

:end
pause
