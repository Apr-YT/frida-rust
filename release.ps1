# frida-rust v0.3.0 Release Script
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  frida-rust v0.3.0 发布脚本" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Set-Location "D:\project\codex\frida-rust"

Write-Host "[1/4] 添加文件..." -ForegroundColor Yellow
git add -A

Write-Host "[2/4] 提交更改..." -ForegroundColor Yellow
git commit -m "feat: v0.3.0 - 简化MCP工具为树状结构"

Write-Host "[3/4] 创建标签..." -ForegroundColor Yellow
git tag v0.3.0

Write-Host "[4/4] 推送..." -ForegroundColor Yellow
git push origin main
git push origin v0.3.0

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  发布成功!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Read-Host "按回车键退出"