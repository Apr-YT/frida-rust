# Changelog

## [0.2.0] - 2026-07-12

### 🧠 AI 智能分析系统 (新增)

- **AI 自我学习系统** - 记录经验、学习升级
  - `ai_report_problem` - 反馈问题并学习
  - `ai_query_experience` - 查询历史经验和知识库
  - `ai_learning_stats` - 学习统计报告
  - `ai_record_success` - 记录成功经验
  - `ai_update_knowledge` - 更新反作弊特征库

- **智能反检测** - 自动分析反作弊并推荐策略
  - `analyze_anti_debug` - 分析目标反调试技术
  - `apply_smart_stealth` - 智能应用反检测策略
  - 支持 30+ 种反作弊检测

### 🎮 ESP 绘制分析 (新增)

- **游戏引擎检测** - 自动识别 Unreal/Unity/Source 等引擎
  - `detect_game_engine` - 检测游戏使用的引擎

- **数据结构分析** - 启发式分析游戏对象内存结构
  - `analyze_object_structure` - 分析对象偏移量
  - 自动识别血量、坐标、指针等数据类型

- **代码生成** - 根据分析结果生成 ESP 绘制代码
  - `generate_esp_code` - 生成 Unreal/Unity/Source ESP 代码
  - `generate_offsets_config` - 导出偏移量配置
  - 内置 PUBG、原神、CS:GO 等游戏模板

### 🛡️ 反检测增强

- **端口隐藏** (`port_hide`) - 隐藏 /proc/net/tcp 中的 Frida 端口
- **FD 隐藏** (`fd_hide`) - 隐藏 /proc/self/fd 中的文件描述符
- **线程隐藏** (`thread_hide`) - 隐藏 Frida 相关线程
- **网络隐藏** (`net_hide`) - 隐藏网络连接信息
- **环境变量清理** (`env_clean`) - 清除 FRIDA_* 环境变量

### 🎮 国内反作弊支持

新增检测支持：
- 腾讯 ACE/TP/MTP
- 米哈游 MiHoYo Protect
- 网易 UProtect/Yidun
- 盛趣 GPProtect
- 完美世界 PWProtect
- 莉莉丝 Lilith Protect
- 阿里游戏盾 AliGameShield
- 360/金山游戏保护
- DRM (Denuvo/Steam/Epic)
- 游戏加固 (顶象/数美/极验)

### 🔧 MCP 工具增强

新增 15+ AI 专用工具：

#### 进程分析
- `get_process_info` - 获取进程详细信息
- `list_threads` - 列出所有线程

#### 模块分析
- `list_modules` - 列出加载的模块
- `get_module_info` - 获取模块详细信息
- `find_symbol` - 查找符号地址
- `list_symbols` - 列出导出符号

#### 内存操作
- `disassemble` - 反汇编指定地址代码
- `search_pattern` - 搜索字节模式
- `dump_memory` - dump内存到文件

### 🐛 Bug 修复

- 修复测试编译错误 (9个)
- 修复 Rhai API 兼容性问题
- 修复文件头偏移量计算错误
- 修复危险的 `.unwrap()` 调用
- 修复 MCP Hook 持久化问题

### 📝 文档

- 新增技术文档 `TECHNICAL_DOC.md`
- 更新 README 添加完整功能说明
- 添加内置游戏模板文档

## [0.1.0] - 2026-07-11

### 初始版本

- 基础 Frida 功能实现
- Inline Hook / GOT-PLT Hook / Java Hook
- ptrace 注入 / 反射注入
- 内存扫描 / ELF 解析
- Rhai 脚本引擎
- 基础反检测功能
- MCP 服务器基础功能
