# ============================================
# frida-rust v0.2.0 发布脚本
# ============================================

Write-Host "🚀 开始发布 frida-rust v0.2.0..." -ForegroundColor Cyan

# 进入项目目录
Set-Location "D:\project\codex\frida-rust"

# 1. 检查状态
Write-Host "`n📊 检查项目状态..." -ForegroundColor Yellow
git status

# 2. 添加所有文件
Write-Host "`n📁 添加文件..." -ForegroundColor Yellow
git add -A

# 3. 提交更改
Write-Host "`n💾 提交更改..." -ForegroundColor Yellow
git commit -m "feat: v0.2.0 - AI智能逆向分析框架

🧠 AI智能分析系统:
- AI自我学习系统 - 记录经验、学习升级
- 智能反检测 - 自动分析反作弊并推荐策略
- 支持30+种反作弊检测

🎮 ESP绘制分析:
- 游戏引擎自动检测
- 内存结构启发式分析
- 偏移量自动查找
- 代码自动生成
- 内置PUBG/原神/CS:GO模板

🛡️ 反检测增强:
- 端口/FD/线程/网络/环境变量隐藏
- 国内反作弊支持 (ACE/TP/米哈游/网易)
- 30+反作弊检测支持

🔧 MCP工具增强:
- 15+新增AI专用工具
- 进程/模块/内存分析
- 反汇编/模式搜索

📝 文档:
- 新增技术文档
- 完整功能说明
- 游戏模板文档
"

# 4. 创建标签
Write-Host "`n🏷️ 创建标签..." -ForegroundColor Yellow
git tag -a v0.2.0 -m "v0.2.0 - AI智能逆向分析框架"

# 5. 推送
Write-Host "`n⬆️ 推送到 GitHub..." -ForegroundColor Yellow
git push origin main
git push origin v0.2.0

Write-Host "`n✅ v0.2.0 发布成功!" -ForegroundColor Green
Write-Host "📦 GitHub: https://github.com/Apr-YT/frida-rust" -ForegroundColor Cyan
Write-Host "🏷️ 标签: v0.2.0" -ForegroundColor Cyan
