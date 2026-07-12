@echo off
echo.
echo ========================================
echo   frida-rust v0.2.0 Release
echo ========================================
echo.
cd /d D:\project\codex\frida-rust
echo [1/4] Adding files...
git add -A
if errorlevel 1 goto err
echo [2/4] Committing...
git commit -m "feat: v0.2.0 - AI Smart Reverse Engineering"
if errorlevel 1 goto err
echo [3/4] Tagging...
git tag v0.2.0
echo [4/4] Pushing...
git push origin main
if errorlevel 1 goto err
git push origin v0.2.0
echo.
echo ========================================
echo   SUCCESS!
echo ========================================
echo.
pause
exit
:err
echo.
echo ERROR!
echo.
pause
