@echo off
title Push CyberRecon to GitHub
cd /d "%~dp0"

echo ========================================================
echo  CyberRecon Git Push Utility
echo  Target: https://github.com/okgoogle-tech/CyberRecon-S.git
echo  Branch: main
echo ========================================================
echo.

echo Current Git Status:
echo -------------------
git status --short
echo -------------------
echo.

set /p commit_msg="Enter commit message (press ENTER for 'Update CyberRecon'): "
if "%commit_msg%"=="" set commit_msg=Update CyberRecon

echo.
echo [1/3] Staging changes...
git add -A

echo [2/3] Committing changes...
git commit -m "%commit_msg%"

echo [3/3] Pushing to origin main...
git push -u origin main

if %ERRORLEVEL% equ 0 (
    echo.
    echo ========================================================
    echo  [SUCCESS] Successfully pushed to CyberRecon-S (main)!
    echo ========================================================
) else (
    echo.
    echo ========================================================
    echo  [ERROR / CONFLICT] Push failed.
    echo  If the remote repository already contains files (e.g. README/License),
    echo  you can try:
    echo     git pull origin main --rebase
    echo     git push -u origin main
    echo  Or if you want to overwrite the remote:
    echo     git push -u origin main --force
    echo ========================================================
)

echo.
pause
