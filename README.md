# Frida-Rust

[![Version](https://img.shields.io/badge/version-0.35.0-blue.svg)](https://github.com/Apr-YT/frida-rust)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

🚀 **Frida 核心功能的 Rust 实现** - 为 AI 助手打造的智能逆向分析框架

## ✨ v0.35.0 新特性

### 🤖 AI 全面自我学习

- **自动经验收集** - 每次操作自动记录成功/失败
- **智能反馈循环** - 遇到问题自动分析原因
- **策略迭代优化** - 根据成功率自动调整策略
- **知识图谱构建** - 反作弊特征关系图

### 🖥️ Web UI 可视化

- **实时日志流** - 显示 AI 每一步操作
- **步骤可视化** - 展示 AI 执行流程
- **学习进度** - 显示成功率和统计
- **自动链接** - AI 执行时自动显示访问地址

### 🪟 完整 Windows 支持

- **PE 解析** - Windows 符号查询
- **内存操作** - 读写搜索全支持
- **进程分析** - 完整进程信息

## 🔧 MCP 工具 (24个, 按功能模块组织)

### process/ - 进程操作
| 工具 | Unix | Windows |
|------|------|---------|
| `process_info` | ✅ | ✅ |
| `process_attach` | ✅ | ✅ |
| `process_inject` | ✅ | ✅ |

### memory/ - 内存操作
| 工具 | Unix | Windows |
|------|------|---------|
| `memory_read` | ✅ | ✅ |
| `memory_write` | ✅ | ✅ |
| `memory_search` | ✅ | ✅ |
| `memory_disasm` | ✅ | ✅ |
| `memory_dump` | ✅ | ✅ |

### hook/ - Hook操作
| 工具 | Unix | Windows |
|------|------|---------|
| `hook_set` | ✅ | ✅ |

### stealth/ - 反检测
| 工具 | Unix | Windows |
|------|------|---------|
| `stealth_apply` | ✅ | ✅ |
| `stealth_analyze` | ✅ | ✅ |
| `stealth_info` | ✅ | ✅ |

### ai/ - AI学习
| 工具 | 说明 |
|------|------|
| `ai_learn` | 记录经验/反馈问题/获取建议 |
| `ai_query` | 查询知识图谱/策略/统计 |

### esp/ - ESP分析
| 工具 | Unix | Windows |
|------|------|---------|
| `esp_analyze` | ✅ | ✅ |
| `esp_generate` | ✅ | ✅ |

### symbols/ - 符号操作
| 工具 | Unix | Windows |
|------|------|---------|
| `symbols_list` | ✅ | ✅ |
| `symbols_find` | ✅ | ✅ |

### script/ - 脚本执行
| 工具 | 说明 |
|------|------|
| `run_script` | 执行 Rhai 脚本 (script 源码 或 script_file 文件路径; pid 可选目标进程; reset 可选重置) |
| `script_reset` | 重置脚本引擎 (pid 可选; 重置后脚本作用域清空) |

### android/ - Android 分析 (Linux/Android 平台)
| 工具 | 说明 |
|------|------|
| `android_processes` | 列出运行中的 Android 应用进程 |
| `android_find_pid` | 按包名查找进程 PID |
| `android_packages` | 列出已安装的 Android 包 |
| `android_logcat` | 获取 logcat 日志快照 |

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

# 智能反检测
stealth_apply(pid=12345, auto_detect=true)

# AI 学习
ai_learn(action="stats")

# 执行脚本
run_script(script="log_info('hello'); 21 * 2")

# Web UI
webui_status()
# 输出: 🔗 访问地址: http://localhost:8080
```

## 🎮 支持的反作弊

- 腾讯 ACE/TP/MTP
- 米哈游 Protect
- 网易 Yidun
- BattlEye/EAC/Vanguard

## 📋 支持的平台

- ✅ Linux (x86_64, aarch64)
- ✅ Android (arm64-v8a)
- ✅ Windows (x86_64)

## 🔗 链接

- [GitHub](https://github.com/Apr-YT/frida-rust)
