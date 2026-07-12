@echo off
echo.
echo ========================================
echo   frida-rust v0.3.0 Release Script
echo ========================================
echo.

cd /d D:\project\codex\frida-rust

echo [1/4] Adding files...
git add -A
if errorlevel 1 goto err

echo [2/4] Committing...
git commit -m "feat: v0.3.0 - Simplify MCP tools to tree structure"
if errorlevel 1 goto err

echo [3/4] Tagging...
git tag v0.3.0

echo [4/4] Pushing...
git push origin main
if errorlevel 1 goto err
git push origin v0.3.0

echo.
echo ========================================
echo   SUCCESS!
echo ========================================
echo.
goto end

:err
echo.
echo ========================================
echo   ERROR!
echo ========================================
echo.

:end
pause