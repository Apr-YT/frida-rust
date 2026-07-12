# frida-rust v0.2.0 Release Script
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  frida-rust v0.2.0 Release Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Set-Location "D:\project\codex\frida-rust"

Write-Host "[1/4] Adding files..." -ForegroundColor Yellow
git add -A
if ( -ne 0) {
    Write-Host "ERROR: git add failed!" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "[2/4] Committing..." -ForegroundColor Yellow
git commit -m "feat: v0.2.0 - AI Smart Reverse Engineering Framework"
if ( -ne 0) {
    Write-Host "ERROR: git commit failed!" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "[3/4] Creating tag..." -ForegroundColor Yellow
git tag -a v0.2.0 -m "Release v0.2.0"

Write-Host "[4/4] Pushing..." -ForegroundColor Yellow
git push origin main
if ( -ne 0) {
    Write-Host "ERROR: git push failed!" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

git push origin v0.2.0

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  SUCCESS! v0.2.0 Released!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "GitHub: https://github.com/Apr-YT/frida-rust" -ForegroundColor Cyan
Write-Host ""
Read-Host "Press Enter to exit"
