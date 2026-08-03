# Frida-Rust

[![Version](https://img.shields.io/badge/version-0.35.0-blue.svg)](https://github.com/Apr-YT/frida-rust)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

🚀 **类 Frida 的逆向分析框架（Rust 自研实现）** - 为 AI 助手打造的 MCP 逆向分析工具集

> **定位说明**：本项目是**借鉴 Frida 思路的自研实现**，并非 Frida 的 Rust 绑定，不依赖 Frida 运行时/Gadget/服务器，也不提供 Frida 的插桩深度与生态兼容性。请勿按真实 Frida 的使用预期对待本项目。

## ✨ v0.35.0 新特性

### 🤖 AI 全面自我学习

- **自动经验收集** - 每次操作自动记录成功/失败
- **智能反馈循环** - 遇到问题自动分析原因
- **策略迭代优化** - 根据成功率自动调整策略
- **知识图谱构建** - 反作弊特征关系图

### 🖥️ 执行日志与 HTML 报告

- **日志记录** - 内存聚合 AI 每一步操作的日志与统计
- **步骤记录** - 记录 AI 执行流程与耗时
- **学习统计** - 记录成功率和统计
- **HTML 报告生成** - 将日志/步骤渲染为静态 HTML 报告字符串（需外部自行保存或托管，无内置 HTTP 服务）

### 🪟 完整 Windows 支持

- **PE 解析** - Windows 符号查询
- **内存操作** - 读写搜索全支持
- **进程分析** - 完整进程信息

## 🔧 MCP 工具 (45个, 按功能模块组织)

### process/ - 进程操作
| 工具 | Unix | Windows |
|------|------|---------|
| `process_list` | ✅ | ✅ |
| `process_find` | ✅ | ✅ |
| `process_suspend` | ✅ | ✅ |
| `process_resume` | ✅ | ✅ |
| `process_kill` | ✅ | ✅ |
| `process_info` | ✅ | ✅ |
| `process_memory_stats` | ✅ | ✅ |
| `process_attach` | ✅ | ✅ |
| `process_inject` | ✅ | ✅ |
| `process_inject_reflect` | ❌ | ✅ |

### memory/ - 内存操作
| 工具 | Unix | Windows |
|------|------|---------|
| `memory_read` | ✅ | ✅ |
| `memory_write` | ✅ | ✅ |
| `memory_search` | ✅ | ✅ |
| `memory_search_text` | ✅ | ✅ |
| `memory_search_value` | ✅ | ✅ |
| `memory_read_string` | ✅ | ✅ |
| `memory_regions` | ✅ | ✅ |
| `memory_disasm` | ✅ | ✅ |
| `memory_dump` | ✅ | ✅ |
| `memory_alloc` | ✅ | ✅ |
| `memory_free` | ✅ | ✅ |
| `memory_protect` | ✅ | ✅ |
| `memory_write_string` | ✅ | ✅ |

### hook/ - Hook操作
| 工具 | Unix | Windows |
|------|------|---------|
| `hook_set` | ✅ | ✅ |
| `hook_uninstall` | ✅ | ✅ |
| `hook_list` | ✅ | ✅ |

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
| `module_info` | ✅ | ✅ |
| `module_list` | ✅ | ✅ |
| `module_hide` | ❌ | ✅ |
| `symbols_list` | ✅ | ✅ |
| `symbols_find` | ✅ | ✅ |

### script/ - 脚本执行
| 工具 | 说明 |
|------|------|
| `run_script` | 执行 Rhai 脚本 (script 源码 或 script_file 文件路径; pid 可选目标进程; reset 可选重置) |
| `script_reset` | 重置脚本引擎 (pid 可选; 重置后脚本作用域清空) |

### android/ - Android 分析 (adb 直连, 任意主机)
| 工具 | 说明 |
|------|------|
| `device_list` | 列出已连接的 adb 设备 |
| `android_processes` | 列出设备运行中的应用进程 (自动选择设备) |
| `android_find_pid` | 按包名/进程名查找 PID (自动选择设备) |
| `android_packages` | 列出已安装的第三方应用包 (自动选择设备) |
| `android_logcat` | 获取设备 logcat 日志快照 (自动选择设备) |

> 安卓工具走 adb 直连(Windows/Linux/macOS 主机均可),进程/包/日志通过
> `adb shell` 获取;注入/hook 能力将经由设备端 `frida-server` 守护进程
> (adb forward + 长度前缀 JSON 帧协议)提供。部署见 `scripts/deploy-frida-server.ps1`。

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

# 内存分配与字符串写入
memory_alloc(pid=12345, size=4096)
memory_write_string(pid=12345, address="0x1a2b3c00", text="hello", encoding="utf8")
memory_protect(pid=12345, address="0x1a2b3c00", size=4096, perm="rx")
memory_free(pid=12345, address="0x1a2b3c00")

# 数值扫描与信息查询
memory_search_value(pid=12345, value=100, value_type="i32", align=4)
module_list(pid=12345)
process_inject(pid=12345, lib_path="C:\\agent.dll", hide=true)  # 注入后自动隐藏模块（Windows）
process_inject_reflect(pid=12345, lib_path="C:\\agent.dll")  # 反射式注入：不调用 LoadLibrary，不注册到 PEB 模块链（Windows）
process_memory_stats(pid=12345)

```

## 🎮 反检测能力

面向反作弊对抗场景提供反调试手段，**不承诺绕过任何具体商业反作弊**：

- 跨进程 PEB 清理 - 清除目标进程 BeingDebugged / NtGlobalFlag / 堆调试标志
- 模块隐藏 - 从目标进程 PEB Ldr 链摘除模块（`module_hide`），对模块枚举 / GetModuleHandle 不可见
- 注入即隐身 - `process_inject(hide=true)` 注入 DLL 后自动从 PEB Ldr 链摘除（Windows）
- 反射式注入 - `process_inject_reflect` 本地构建完整 PE 映射映像，不调用 LoadLibrary、不进入 PEB 模块链，注入的 DLL 对模块枚举 / GetModuleHandle 天然不可见（Windows；依赖 DLL 需已在目标进程）
- 反调试检测（自身与跨进程只读） - DebugPort / DebugObjectHandle / 堆标志 / 时间差 / 父进程链
- Unix 目标进程分析 - 解析 /proc 状态（TracerPid / Seccomp / no_new_privs / LD_PRELOAD 注入痕迹）
- 调试寄存器清理 - Dr0-Dr7 清零
- Unix 侧隐藏 - 环境清理 / TracerPid / maps / FD / 端口 / 网络

> ⚠️ 商业反作弊（ACE/BattlEye/EAC/Vanguard 等）多为内核级检测，用户态手段存在被识别风险。

## 📋 支持的平台

- ✅ Linux (x86_64, aarch64)
- ✅ Android (arm64-v8a)
- ✅ Windows (x86_64)

## 🔗 链接

- [GitHub](https://github.com/Apr-YT/frida-rust)
