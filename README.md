# Frida-Rust

[![Version](https://img.shields.io/badge/version-0.3.0-blue.svg)](https://github.com/Apr-YT/frida-rust)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

🚀 **Frida 核心功能的 Rust 实现** - 为 AI 助手打造的智能逆向分析框架

## ✨ 特性

### 🛡️ 完整的反检测系统

- **智能反检测** - 自动分析反作弊并推荐策略
- **国内反作弊支持** - 腾讯ACE/TP、米哈游、网易Yidun
- **10+隐藏模块** - 端口/FD/线程/网络/环境变量

### 🧠 AI 智能分析

- **经验学习系统** - 记录成功/失败，自动优化
- **知识库管理** - 内置30+反作弊特征

### 🎯 ESP 绘制分析

- **游戏引擎检测** - Unreal/Unity/Source
- **数据结构分析** - 自动查找偏移量
- **代码生成** - 生成ESP绘制代码

## 🔧 MCP 工具 (14个树状结构)

### process/ - 进程操作
| 工具 | 说明 |
|------|------|
| `process_info` | 获取进程完整信息 |
| `process_attach` | 附着到进程 |
| `process_inject` | 注入库 |

### memory/ - 内存操作
| 工具 | 说明 |
|------|------|
| `memory_read` | 读取内存 |
| `memory_write` | 写入内存 |
| `memory_search` | 搜索模式 |
| `memory_disasm` | 反汇编 |
| `memory_dump` | dump内存 |

### hook/ - Hook操作
| 工具 | 说明 |
|------|------|
| `hook_set` | 设置Hook |

### stealth/ - 反检测
| 工具 | 说明 |
|------|------|
| `stealth_apply` | 应用反检测 |
| `stealth_analyze` | 分析反调试 |
| `stealth_info` | 模块信息 |

### ai/ - AI学习
| 工具 | 说明 |
|------|------|
| `ai_learn` | 记录经验 |
| `ai_query` | 查询知识 |

### esp/ - ESP分析
| 工具 | 说明 |
|------|------|
| `esp_analyze` | 分析游戏 |
| `esp_generate` | 生成代码 |

### symbols/ - 符号操作
| 工具 | 说明 |
|------|------|
| `symbols_list` | 列出符号 |
| `symbols_find` | 查找符号 |

## 🚀 快速开始

### 安装

```bash
cargo install frida-rust
```

### 配置到 AI 助手

```json
{
  "mcpServers": {
    "frida-rust": {
      "command": "frida-rust-mcp"
    }
  }
}
```

## 📖 使用示例

```python
# 进程分析
process_info(pid=12345)

# 内存读取
memory_read(pid=12345, address="0x1234", size=64)

# 智能反检测
stealth_apply(pid=12345, auto_detect=true)

# AI学习
ai_learn(action="report", problem="被检测", solution="延迟注入")

# ESP分析
esp_analyze(pid=12345)
esp_generate(pid=12345, engine="unreal")
```

## 🏗️ 项目结构

```
src/
├── main.rs, lib.rs
├── ai_learning.rs      # AI学习系统
├── esp_analyzer.rs     # ESP分析器
├── bin/mcp_server.rs   # MCP入口
├── mcp/handler.rs      # 14个MCP工具
├── hook/               # Hook模块
├── inject/             # 注入模块
├── memory/             # 内存操作
├── anti_detect/        # 反检测模块
├── script/             # 脚本引擎
├── communication/      # 通信模块
└── common/             # 公共模块
```

## 📋 支持的平台

- ✅ Linux (x86_64, aarch64)
- ✅ Android (arm64-v8a)
- ⚠️ Windows (部分)

## 🔗 链接

- [GitHub](https://github.com/Apr-YT/frida-rust)
