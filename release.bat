@echo off
cd /d D:\project\codex\frida-rust
git add -A
git commit -m "feat: v0.2.0"
git tag v0.2.0
git push origin main
git push origin v0.2.0
echo Done!
pause