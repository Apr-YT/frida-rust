@echo off
chcp 65001 >nul
echo.
echo ========================================
echo   frida-rust v0.35.0 发布脚本
echo ========================================
echo.

cd /d D:\project\codex\frida-rust

echo [1/4] 添加文件...
git add -A

echo [2/4] 提交更改...
git commit -m "feat: v0.35.0 - AI自我学习系统+Web UI可视化"

echo [3/4] 创建标签...
git tag v0.35.0

echo [4/4] 推送...
git push origin main
git push origin v0.35.0

echo.
echo ========================================
echo   发布成功!
echo ========================================
echo.
pause