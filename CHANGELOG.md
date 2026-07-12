# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.35.0] - 2026-07-12

### Added
- AI 全面自我学习系统
  - 自动经验收集 - 每次操作自动记录
  - 智能反馈循环 - 遇到问题自动分析原因
  - 策略迭代优化 - 根据成功率自动调整策略
  - 知识图谱构建 - 反作弊特征关系图
- Web UI 可视化模块
  - 实时日志流 - 显示 AI 每一步操作
  - 步骤可视化 - 展示 AI 执行流程
  - 学习进度 - 显示成功率和统计
  - 自动链接 - AI 执行时自动显示访问地址
- PE 解析器 (Windows)
  - 导出表解析
  - 符号查询支持
- 完整 Windows 支持
  - 内存读写搜索
  - 进程信息查询
  - 反调试分析
- 工程化配置
  - GitHub Actions CI/CD
  - rustfmt.toml 代码格式化
  - clippy.toml 代码检查
  - MIT LICENSE

### Changed
- 简化 MCP 工具为树状结构 (20个)
- 优化错误处理
- 清理 warnings

## [0.3.0] - 2026-07-12

### Added
- 树状结构 MCP 工具设计
- 14个核心工具

### Changed
- 工具从 36个 简化为 14个
- 参数总数从 ~80个 减少到 ~35个

## [0.2.0] - 2026-07-12

### Added
- 国内反作弊支持
  - 腾讯 ACE/TP/MTP
  - 米哈游 Protect
  - 网易 UProtect/Yidun
- ESP 绘制分析
  - 游戏引擎检测
  - 数据结构分析
  - 偏移量查找
  - 代码生成

## [0.1.0] - 2026-07-11

### Added
- 初始版本
- 基础 Frida 功能实现
- Inline Hook / GOT-PLT Hook / Java Hook
- ptrace 注入 / 反射注入
- 内存扫描 / ELF 解析
- Rhai 脚本引擎
- 基础反检测功能
- MCP 服务器基础功能
