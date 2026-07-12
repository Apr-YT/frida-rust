# Frida-Rust

[![Version](https://img.shields.io/badge/version-0.2.0-blue.svg)](https://github.com/Apr-YT/frida-rust)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

🚀 **Frida 核心功能的 Rust 实现** - 为 AI 助手打造的智能逆向分析框架

## ✨ 特性

### 🛡️ 完整的反检测系统

- **环境变量清理** - 清除 FRIDA_* 环境变量
- **特征擦除** - 擦除内存中的 Frida 特征字符串
- **TracerPid 隐藏** - 清除 /proc/self/status 中的 TracerPid
- **Maps 隐藏** - 隐藏 /proc/self/maps 中的 Frida 条目
- **FD 隐藏** - 隐藏 /proc/self/fd 中的文件描述符
- **线程隐藏** - 隐藏 Frida 相关线程
- **端口隐藏** - 隐藏 /proc/net/tcp 中的 Frida 端口
- **网络隐藏** - 隐藏网络连接信息
- **调用栈伪造** - 伪造调用栈信息

### 🎮 国内反作弊支持

| 反作弊系统 | 厂商 | 代表游戏 |
|-----------|------|----------|
| ACE/TP/MTP | 腾讯 | 王者荣耀、和平精英、LOL、CF |
| UProtect/Yidun | 网易 | 梦幻西游、阴阳师 |
| MiHoYo Protect | 米哈游 | 原神、崩坏3、星穹铁道 |
| GPProtect | 盛趣 | 传奇、龙之谷 |
| Lilith Protect | 莉莉丝 | 万国觉醒、剑与远征 |

### 🧠 AI 智能分析系统

- **自动反调试检测** - 分析目标进程使用的反作弊技术
- **智能策略推荐** - 根据检测结果推荐最佳反检测策略
- **经验学习系统** - 记录成功/失败经验，自动优化策略
- **知识库管理** - 内置主流反作弊特征库，支持动态更新

### 🎯 ESP 绘制分析

- **游戏引擎检测** - 自动识别 Unreal/Unity/Source 等引擎
- **数据结构分析** - 启发式分析游戏对象内存结构
- **偏移量查找** - 自动查找血量、坐标等关键偏移
- **代码生成** - 根据分析结果生成 ESP 绘制代码

### 🔧 MCP 工具 (36个)

#### 进程分析
- list_processes - 列出所有进程
- get_process_info - 获取进程详细信息
- list_threads - 列出进程线程

#### 模块分析
- list_modules - 列出加载的模块
- get_module_info - 获取模块详细信息
- find_symbol - 查找符号地址
- list_symbols - 列出导出符号

#### 内存操作
- read_memory - 读取进程内存
- write_memory - 写入进程内存
- search_pattern - 搜索字节模式
- disassemble - 反汇编代码
- dump_memory - dump内存到文件

#### Hook 操作
- hook_function - Hook目标函数
- inject_library - 注入共享库
- attach_process - 附着到进程

#### 反检测
- apply_stealth - 应用反检测措施
- apply_smart_stealth - 智能应用反检测
- analyze_anti_debug - 分析反调试技术
- list_stealth_modules - 列出反检测模块

#### AI 学习
- ai_report_problem - 反馈问题并学习
- ai_query_experience - 查询历史经验
- ai_learning_stats - 学习统计报告
- ai_record_success - 记录成功经验
- ai_update_knowledge - 更新知识库

#### ESP 分析
- detect_game_engine - 检测游戏引擎
- analyze_object_structure - 分析对象结构
- list_game_templates - 列出游戏模板
- load_game_template - 加载游戏模板
- generate_esp_code - 生成ESP代码
- generate_offsets_config - 生成偏移配置

## 🚀 快速开始

### 安装

`ash
cargo install frida-rust
`

### 使用 MCP Server

`ash
# 启动 MCP 服务器
frida-rust-mcp
`

### 配置到 AI 助手

`json
{
  "mcpServers": {
    "frida-rust": {
      "command": "frida-rust-mcp",
      "args": []
    }
  }
}
`

## 📖 使用示例

### AI 智能逆向分析

`python
# 1. 检测游戏引擎
detect_game_engine(pid=12345)

# 2. 分析反调试技术
analyze_anti_debug(pid=12345)

# 3. 智能应用反检测
apply_smart_stealth(pid=12345)

# 4. 分析游戏对象结构
analyze_object_structure(pid=12345, address="0x12345678")

# 5. 生成ESP绘制代码
generate_esp_code(pid=12345, engine="unreal")
`

### AI 自我学习

`python
# 遇到问题时反馈
ai_report_problem(
    problem="注入后被检测",
    context="游戏: PUBG, 反作弊: ACE",
    success=False
)

# 成功时记录经验
ai_record_success(
    target="PUBG",
    anti_cheat="ACE",
    problem="ACE内存检测",
    solution="延迟10秒注入+全面反检测"
)

# 查询历史经验
ai_query_experience(anti_cheat="TencentACE")
`

## 🏗️ 项目结构

`
src/
├── main.rs                # CLI 入口
├── lib.rs                 # 库入口
├── ai_learning.rs         # AI学习系统
├── esp_analyzer.rs        # ESP分析器
│
├── bin/
│   └── mcp_server.rs      # MCP 服务器入口
│
├── mcp/                   # MCP 工具实现
│   ├── handler.rs         # 36个 MCP 工具
│   └── mod.rs
│
├── hook/                  # Hook 模块
│   ├── inline.rs          # Inline Hook (x86_64/ARM64)
│   ├── got_plt.rs         # GOT/PLT Hook
│   ├── iat_hook.rs        # IAT Hook (Windows)
│   ├── java_hook.rs       # Java Hook (Android)
│   ├── manager.rs         # Hook 管理器
│   └── mod.rs
│
├── inject/                # 注入模块
│   ├── ptrace_inject.rs   # ptrace 注入 (Linux)
│   ├── reflect_inject.rs  # 内存反射注入
│   ├── zygote_inject.rs   # Zygote 注入 (Android)
│   ├── win_inject.rs      # DLL 注入 (Windows)
│   ├── process.rs         # 进程操作
│   └── mod.rs
│
├── memory/                # 内存操作
│   ├── scanner.rs         # 内存扫描器
│   ├── elf_parser.rs      # ELF 解析器
│   ├── allocator.rs       # 远程内存分配
│   ├── win_scanner.rs     # Windows 内存扫描
│   ├── win_allocator.rs   # Windows 内存分配
│   └── mod.rs
│
├── anti_detect/           # 反检测模块
│   ├── smart_stealth.rs   # 智能反检测 (自动分析)
│   ├── hide.rs            # 综合隐藏管理器
│   ├── maps_hide.rs       # /proc/self/maps 隐藏
│   ├── tracer.rs          # TracerPid 隐藏
│   ├── fd_hide.rs         # 文件描述符隐藏
│   ├── thread_hide.rs     # 线程隐藏
│   ├── port_hide.rs       # 端口隐藏
│   ├── net_hide.rs        # 网络连接隐藏
│   ├── env_clean.rs       # 环境变量清理
│   ├── signature.rs       # 特征字符串擦除
│   ├── stack_fake.rs      # 调用栈伪造
│   ├── win_hide.rs        # Windows 反检测
│   └── mod.rs
│
├── script/                # 脚本引擎
│   ├── engine.rs          # Rhai 脚本引擎
│   ├── host_context.rs    # 宿主上下文
│   ├── loader.rs          # 脚本加载器
│   └── mod.rs
│
├── communication/         # 通信模块
│   ├── channel.rs         # Unix Socket/共享内存
│   ├── protocol.rs        # 通信协议
│   ├── server.rs          # 通信服务器
│   ├── win_channel.rs     # Windows Named Pipe
│   └── mod.rs
│
└── common/                # 公共模块
    ├── types.rs           # 类型定义
    ├── error.rs           # 错误处理
    ├── constants.rs       # 常量定义
    ├── util.rs            # 工具函数
    ├── win_util.rs        # Windows 工具
    ├── syscall_wrapper.rs # 系统调用封装
    └── mod.rs
`

## 📋 支持的平台

- ✅ Linux (x86_64, aarch64)
- ✅ Android (arm64-v8a, armeabi-v7a)
- ⚠️ Windows (部分功能)

## 🎮 支持的游戏引擎

- Unreal Engine (UE4/UE5)
- Unity
- Source Engine
- Frostbite
- CryEngine

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

## 📄 许可证

MIT License

## 🔗 链接

- [GitHub](https://github.com/Apr-YT/frida-rust)
- [Issues](https://github.com/Apr-YT/frida-rust/issues)
