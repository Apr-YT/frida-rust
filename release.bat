@echo off
cd /d D:\project\codex\frida-rust
git add -A
git commit -m "feat: v0.3.0 - Simplify MCP tools to tree structure"
git tag v0.3.0
git push origin main
git push origin v0.3.0
echo Done!
pause