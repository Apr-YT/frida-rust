@echo off
echo.
echo ========================================
echo   frida-rust v0.2.0 Release Script
echo ========================================
echo.

cd /d D:\project\codex\frida-rust

echo Step 1: Adding all files...
git add -A
if errorlevel 1 (
    echo ERROR: git add failed!
    pause
    exit /b 1
)

echo Step 2: Committing changes...
git commit -m "feat: v0.2.0 - AI Smart Reverse Engineering Framework"
if errorlevel 1 (
    echo ERROR: git commit failed!
    pause
    exit /b 1
)

echo Step 3: Creating release tag...
git tag -a v0.2.0 -m "Release v0.2.0"
if errorlevel 1 (
    echo WARNING: Tag creation failed (may already exist)
)

echo Step 4: Pushing to GitHub...
git push origin main
if errorlevel 1 (
    echo ERROR: git push failed!
    pause
    exit /b 1
)

git push origin v0.2.0
if errorlevel 1 (
    echo WARNING: Tag push failed
)

echo.
echo ========================================
echo   SUCCESS! v0.2.0 Released!
echo ========================================
echo.
echo GitHub: https://github.com/Apr-YT/frida-rust
echo.
pause