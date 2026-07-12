@echo off
chcp 65001 >nul
echo.
echo ========================================
echo  frida-rust v0.2.0 ??
echo ========================================
echo.

cd /d D:\project\codex\frida-rust

echo [1/4] ????...
git add -A

echo [2/4] ????...
git commit -m "feat: v0.2.0 - AI????????"

echo [3/4] ????...
git tag -a v0.2.0 -m "v0.2.0"

echo [4/4] ??...
git push origin main
git push origin v0.2.0

echo.
echo ? ????!
echo.
pause
