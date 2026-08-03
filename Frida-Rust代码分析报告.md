# Frida-Rust 工具包代码分析报告

## 目录

1. [项目结构概览](#1-项目结构概览)
   - [目录树](#目录树)
   - [主要文件职责](#主要文件职责)
2. [依赖与技术栈](#2-依赖与技术栈)
   - [完整依赖清单](#完整依赖清单)
   - [与 Frida 的交互方式](#与-frida-的交互方式)
3. [核心代码逻辑](#3-核心代码逻辑)
   - [进程注入流程](#进程注入流程)
   - [Inline Hook 实现](#inline-hook-实现)
   - [通信协议](#通信协议)
   - [Hook 管理器](#hook-管理器)
   - [反检测模块](#反检测模块)
   - [脚本引擎](#脚本引擎)
   - [MCP 服务器](#mcp-服务器)
4. [现存问题与 Bug 记录](#4-现存问题与-bug-记录)
   - [编译错误](#编译错误)
   - [编译警告](#编译警告)
   - [运行时潜在问题](#运行时潜在问题)
5. [期望完善的功能描述](#5-期望完善的功能描述)
   - [TODO 注释收集](#todo-注释收集)
   - [未实现的功能](#未实现的功能)
6. [总结](#6-总结)

---

## 1. 项目结构概览

### 目录树

```
frida-rust/
├── Cargo.toml                    # 项目配置与依赖声明
├── src/
│   ├── lib.rs                    # 库入口，公共模块导出
│   ├── main.rs                   # CLI 入口（inject/attach/script 子命令）
│   ├── bin/mcp_server.rs         # MCP 服务器二进制入口
│   ├── common/                   # 基础设施模块
│   │   ├── types.rs              # 公共类型定义（Architecture, HookType, MemoryRegion 等）
│   │   ├── error.rs              # 统一错误类型 FridaError
│   │   ├── util.rs               # 工具函数（process_vm_readv/writev, parse_proc_maps）
│   │   ├── constants.rs          # 常量定义（协议魔数、版本号等）
│   │   └── syscall_wrapper.rs    # 系统调用封装
│   ├── inject/                   # 进程注入模块
│   │   ├── injector.rs           # 核心注入器（封装 ptrace 注入流程）
│   │   ├── ptrace_inject.rs      # ptrace 底层操作（寄存器读写、远程调用）
│   │   ├── zygote_inject.rs      # Android Zygote 注入（fork 机制）
│   │   ├── reflect_inject.rs     # 内存反射注入（无文件落盘）
│   │   ├── process.rs            # 进程管理（枚举进程/模块/线程）
│   │   ├── win_inject.rs         # Windows CreateRemoteThread 注入
│   │   └── win_process.rs        # Windows 进程管理
│   ├── hook/                     # 函数 Hook 模块
│   │   ├── inline.rs             # Inline Hook 实现（x86_64/AArch64 指令解码）
│   │   ├── got_plt.rs            # GOT/PLT Hook（Unix ELF）
│   │   ├── iat_hook.rs           # IAT Hook（Windows PE）
│   │   ├── java_hook.rs          # Java Hook（Android JNI）
│   │   └── manager.rs            # Hook 管理器（统一生命周期管理）
│   ├── memory/                   # 内存操作模块
│   │   ├── scanner.rs            # 内存扫描器（跨进程读取、模式搜索）
│   │   ├── allocator.rs          # 远程内存分配器
│   │   ├── elf_parser.rs         # ELF 文件解析器
│   │   ├── pe_parser.rs          # PE 文件解析器
│   │   └── win_scanner.rs        # Windows 内存扫描器
│   ├── script/                   # 脚本引擎模块
│   │   ├── engine.rs             # Rhai 脚本引擎封装（极致裁剪配置）
│   │   ├── loader.rs             # 脚本加载器（AES-GCM 解密）
│   │   └── host_context.rs       # 宿主上下文（API 注册表）
│   ├── anti_detect/              # 反检测模块
│   │   ├── hide.rs               # 综合隐蔽管理器（StealthManager）
│   │   ├── maps_hide.rs          # /proc/maps 条目隐藏
│   │   ├── tracer.rs             # TracerPid 清零
│   │   ├── signature.rs          # Frida 特征字符串擦除
│   │   ├── stack_fake.rs         # 调用栈伪造
│   │   ├── port_hide.rs          # 端口隐藏
│   │   ├── fd_hide.rs            # 文件描述符隐藏
│   │   ├── thread_hide.rs        # 线程隐藏
│   │   ├── net_hide.rs           # 网络连接隐藏
│   │   ├── env_clean.rs          # 环境变量清理
│   │   ├── smart_stealth.rs      # 智能反检测分析
│   │   └── win_hide.rs           # Windows 反检测
│   ├── communication/            # 通信框架模块
│   │   ├── protocol.rs           # 自定义二进制协议（消息头+负载）
│   │   ├── channel.rs            # 通道实现（Unix Socket/共享内存）
│   │   ├── server.rs             # 通信服务端
│   │   └── win_channel.rs        # Windows NamedPipe 通道
│   ├── mcp/                      # MCP 服务器模块
│   │   └── handler.rs            # MCP 工具实现（14个核心工具）
│   ├── ai_learning.rs            # AI 学习引擎（经验记录与策略推荐）
│   ├── esp_analyzer.rs           # ESP 分析器（游戏引擎检测、代码生成）
│   └── webui.rs                  # Web UI 相关
```

### 主要文件职责

| 文件 | 职责 |
|------|------|
| `Cargo.toml` | 项目元数据、依赖声明、跨平台编译配置 |
| `src/lib.rs` | 库入口，统一导出所有公共模块和类型 |
| `src/main.rs` | CLI 命令行入口，支持 inject/attach/script 子命令 |
| `src/inject/injector.rs` | 核心注入器，封装完整的 ptrace 注入流程 |
| `src/hook/inline.rs` | Inline Hook 实现，支持 x86_64 和 AArch64 |
| `src/communication/protocol.rs` | 自定义二进制协议，消息头+负载结构 |
| `src/anti_detect/hide.rs` | 综合反检测管理器，支持 Full/Standard/Minimal 模式 |
| `src/mcp/handler.rs` | MCP 服务器工具实现，14 个核心工具函数 |

---

## 2. 依赖与技术栈

### 完整依赖清单

| 依赖 | 版本 | 用途 |
|------|------|------|
| **核心依赖** | | |
| `rhai` | 1.19 | 嵌入式脚本引擎（安全裁剪配置） |
| `libc` | 0.2 | Unix 系统调用绑定 |
| `goblin` | 0.9 | 二进制文件解析（ELF/PE） |
| `elf` | 0.7 | ELF 文件解析 |
| `byteorder` | 1.5 | 字节序处理 |
| `aes-gcm` | 0.10 | AES-256-GCM 加密 |
| `sha2` | 0.10 | SHA-256 哈希 |
| `rand` | 0.8 | 随机数生成 |
| `log` / `env_logger` | 0.4 / 0.11 | 日志系统 |
| `anyhow` | 1.0 | 错误处理 |
| `thiserror` | 2.0 | 自定义错误类型 |
| `serde` / `serde_json` | 1.0 | JSON 序列化 |
| `target-lexicon` | 0.12 | 目标平台识别 |
| **MCP 相关** | | |
| `rmcp` | 2.2.0 | MCP 服务器框架 |
| `schemars` | 1.2.1 | JSON Schema 生成 |
| `tokio` | 1 | 异步运行时（full 特性） |
| **平台条件依赖** | | |
| `nix` | 0.29 (unix) | Unix 高级 API（process/signal/socket） |
| `winapi` | 0.3 (windows) | Windows API 绑定（多模块） |

### 与 Frida 的交互方式

**本项目是从零实现的 Frida 核心功能，不依赖原生 frida-rs/frida-sys**。具体交互方式：

1. **进程注入**：通过 `ptrace` 系统调用直接附加目标进程，修改寄存器让目标进程调用 `dlopen` 加载共享库
2. **函数 Hook**：直接修改目标函数入口指令（Inline Hook）或修改 GOT/PLT 表（Unix）、IAT 表（Windows）
3. **内存操作**：使用 `process_vm_readv`/`process_vm_writev` 跨进程读写内存
4. **通信**：自定义基于 Unix Socket/NamedPipe 的加密双向通信协议

---

## 3. 核心代码逻辑

### 3.1 进程注入流程

**Injector::inject_library**（`src/inject/injector.rs` 第 85-131 行）

完整的 ptrace 注入流程：

1. **验证目标进程存活** → `util::is_process_alive(pid)`
2. **检查共享库文件存在** → `Path::new(lib_path).exists()`
3. **ptrace 附加目标进程** → 优先使用 `PTRACE_SEIZE`（无 SIGSTOP），回退 `PTRACE_ATTACH`
4. **查找目标进程中的 dlopen 地址** → 通过解析 `/proc/pid/maps` 获取 libc 基址，计算符号偏移
5. **在目标进程中分配远程内存** → 通过远程调用 `mmap` 分配内存
6. **将 so 路径写入远程内存** → `process_vm_writev` 或 `ptrace(PTRACE_POKEDATA)`
7. **保存目标线程原始寄存器** → `save_regs(tid)`
8. **执行远程 dlopen 调用** → 修改 PC 和参数寄存器，执行函数，通过 BKPT 陷阱捕获返回
9. **恢复原始寄存器** → `restore_regs(tid)`
10. **脱离 ptrace 并清理** → `PTRACE_DETACH`，释放远程内存

**关键技术点**：
- AArch64 使用自定义 `user_pt_regs` 结构体（libc 0.2 未暴露）
- 远程调用通过设置 LR 寄存器为 BKPT 地址实现干净的返回捕获
- `process_vm_readv`/`writev` 优先使用，失败回退到 `ptrace(PTRACE_PEEKDATA/POKEDATA)`

### 3.2 Inline Hook 实现

**InlineHooker::install**（`src/hook/inline.rs` 第 441-529 行）

**x86_64 Hook 流程**：

1. **读取目标函数入口指令** → 读取前 32 字节
2. **解码指令长度** → 使用 `x86_decoder::calculate_patch_size` 确定需要覆盖的字节数（至少 5 字节用于 `jmp rel32`）
3. **分配跳板内存** → `mmap` 分配 RWX 权限的内存页
4. **保存原始字节** → 备份被覆盖的指令
5. **构建跳板代码**：
   - 复制原始指令到跳板
   - 修正相对偏移（RIP-relative 寻址、相对跳转）
   - 在末尾追加 `jmp [rip+0] + 8字节绝对地址` 跳回原函数
6. **写入目标函数入口的跳转指令** → `jmp rel32` 或 `jmp [rip+0]` 跳转到替换函数
7. **刷新指令缓存** → `__clear_cache`（Unix）或 `FlushInstructionCache`（Windows）

**AArch64 Hook 流程**（`src/hook/inline.rs` 第 532-634 行）：

- 指令固定 4 字节，使用 `B` 指令（26位偏移，±128MB）或 `LDR X17, [PC, #8]; BR X17` 组合（全地址范围）
- 需要处理 B/BL/B.cond 等分支指令的偏移修正

### 3.3 通信协议

**MessageHeader**（`src/communication/protocol.rs` 第 29-139 行）

固定 20 字节消息头格式：

| 字段 | 偏移 | 大小 | 说明 |
|------|------|------|------|
| `magic` | 0 | 4 | 魔数 (0xF1D40001) |
| `version` | 4 | 2 | 协议版本 |
| `msg_type` | 6 | 2 | 消息类型 |
| `length` | 8 | 4 | 负载长度 |
| `seq` | 12 | 4 | 序列号（请求/响应匹配） |
| `reserved` | 16 | 4 | 保留字段 |

**MessageType** 枚举定义了 20+ 种消息类型，包括：
- 控制类：Ping/Pong
- 注入类：InjectRequest/InjectResponse
- Hook 类：HookInstallRequest/HookEvent
- 内存类：MemoryReadRequest/MemorySearchResponse
- 脚本类：ScriptExecRequest/ScriptLog
- 反检测类：AntiDetectRequest/AntiDetectResponse

### 3.4 Hook 管理器

**HookManager**（`src/hook/manager.rs` 第 114-560 行）

统一管理所有 Hook 点的生命周期：

- **注册 Hook** → `register_hook(hook_point, callback)` 返回 HookId
- **安装 Hook** → `install_hook(id)` 根据 HookType 选择 Inline/GOT-PLT/Java Hook
- **卸载 Hook** → `uninstall_hook(id)` 恢复原始指令/数据
- **析构自动清理** → Drop 实现自动卸载所有激活的 Hook

### 3.5 反检测模块

**StealthManager**（`src/anti_detect/hide.rs` 第 64-271 行）

支持四种隐蔽模式：

| 模式 | 描述 |
|------|------|
| `Full` | 完全隐蔽：maps_hide + tracer_cleaner + port_hide + fd_hide + thread_hide + net_hide + stack_faker |
| `Standard` | 标准隐蔽：tracer_cleaner + port_hide + net_hide + stack_faker |
| `Minimal` | 最小隐蔽：仅擦除特征字符串和清理环境变量 |
| `None` | 无隐蔽（调试模式） |

**智能反检测**（SmartStealth）：扫描目标进程的反调试手段，生成分析报告并应用推荐的绕过策略。

### 3.6 脚本引擎

**ScriptEngine**（`src/script/engine.rs` 第 67-349 行）

基于 Rhai 的极致裁剪配置：

- 禁用浮点数支持
- 限制调用栈深度（默认 64 层）
- 限制最大操作数（防止无限循环）
- 限制字符串长度（1MB）
- 支持 AES-GCM 加密脚本执行
- 支持热重载

注册的脚本 API：
- 日志：`log_info`, `log_warn`
- 内存：`read_memory`, `write_memory`, `search_bytes`
- Hook：`hook_function`
- 模块：`get_module_base`, `read_module`, `list_modules`
- 进程：`get_process_info`, `list_threads`

### 3.7 MCP 服务器

**FridaMcpServer**（`src/mcp/handler.rs` 第 96-647 行）

提供 14 个核心工具函数，按功能模块组织：

| 模块 | 工具 | 描述 |
|------|------|------|
| **process** | `process_info` | 获取进程完整信息 |
| | `process_attach` | 附着到目标进程 |
| | `process_inject` | 注入共享库到目标进程 |
| **memory** | `memory_read` | 读取目标进程内存 |
| | `memory_write` | 写入目标进程内存 |
| | `memory_search` | 搜索内存中的字节模式 |
| | `memory_disasm` | 反汇编指定地址的代码 |
| | `memory_dump` | dump 内存区域到文件 |
| **hook** | `hook_set` | 设置函数 Hook |
| **stealth** | `stealth_apply` | 应用反检测措施 |
| | `stealth_analyze` | 分析目标进程的反调试技术 |
| | `stealth_info` | 查看反检测模块列表 |
| **ai** | `ai_learn` | AI 学习（记录经验/获取建议） |
| | `ai_query` | AI 查询（知识库/策略） |
| **esp** | `esp_analyze` | 分析游戏引擎和结构 |
| | `esp_generate` | 生成 ESP 代码 |
| **symbols** | `symbols_list` | 列出模块的符号 |
| | `symbols_find` | 查找符号地址 |

---

## 4. 现存问题与 Bug 记录

### 4.1 编译错误

**链接错误 - CaptureStackBackTrace 未定义**（`src/anti_detect/stack_fake.rs` 第 359 行）

```
undefined reference to `CaptureStackBackTrace'
```

**原因**：`CaptureStackBackTrace` 是 Windows `dbghelp.dll` 中的函数，但项目没有正确链接该库。需要在 `Cargo.toml` 中添加 `winapi` 的 `dbghelp` 特性，或使用 `cargo:rustc-link-lib=dbghelp` 指令。

**修复方案**：在 `src/anti_detect/stack_fake.rs` 中添加链接属性：

```rust
#[cfg(windows)]
#[link(name = "dbghelp")]
extern "system" {
    fn CaptureStackBackTrace(
        FramesToSkip: u32,
        FramesToCapture: u32,
        BackTrace: *mut *mut u8,
        BackTraceHash: *mut u32,
    ) -> u32;
}
```

### 4.2 编译警告

| 文件 | 警告类型 | 位置 | 描述 |
|------|----------|------|------|
| `src/webui.rs` | unused_imports | 第 11 行 | `Duration` 未使用 |
| `src/mcp/handler.rs` | unused_mut | 第 208 行 | `s` 不需要 mutable |
| `src/mcp/handler.rs` | unused_mut | 第 487 行 | `engine` 不需要 mutable |
| `src/mcp/handler.rs` | dead_code | 第 78 行 | `StealthParams.pid` 字段未使用 |
| `src/mcp/handler.rs` | dead_code | 第 84 行 | `AIQueryParams.target` 字段未使用 |

### 4.3 运行时潜在问题

**1. Inline Hook 指令解码覆盖不全**

`src/hook/inline.rs` 中的 `x86_decoder::decode_instruction_length` 对某些复杂指令（如 VEX/EVEX 前缀的 AVX 指令）解码不完整，可能导致指令截断或 Hook 失败。

**2. AArch64 STP/LDP 指令重定位不完整**

`src/hook/inline.rs` 中的 `arm64_decoder::is_stp_instruction/is_ldp_instruction` 对某些 PC-relative 寻址的 STP/LDP 指令处理不完整，可能导致跳板执行错误。

**3. 远程调用超时处理**

`src/inject/ptrace_inject.rs` 中的 `call_remote_inner` 的超时处理逻辑不够健壮，超时后使用 `PTRACE_INTERRUPT` 强制停止，但没有检查线程状态。

**4. 符号解析依赖本地库**

`src/inject/ptrace_inject.rs` 中的 `find_local_symbol_offset` 搜索本地共享库路径来计算符号偏移，在 Android 环境下可能找不到匹配的库文件。

---

## 5. 期望完善的功能描述

### 5.1 TODO 注释收集

| 文件 | 位置 | 描述 |
|------|------|------|
| `src/ai_learning.rs` | 第 620 行 | 保存经验数据到文件 |
| `src/ai_learning.rs` | 第 624 行 | 从文件加载经验数据 |
| `src/esp_analyzer.rs` | 第 492-498 行 | 填入 Unreal Engine 游戏模板的实际偏移量 |
| `src/esp_analyzer.rs` | 第 558-559 行 | 填入 Unity 游戏模板的实际偏移量 |
| `src/esp_analyzer.rs` | 第 627 行 | 填入 Source 引擎的实际偏移量 |
| `src/memory/pe_parser.rs` | 第 166 行 | 从节表获取模块大小 |
| `src/memory/pe_parser.rs` | 第 168 行 | 解析 PE 导入表 |

### 5.2 未实现的功能

**1. Windows 符号解析**

`src/hook/manager.rs` 第 476-482 行的 `resolve_symbol` 在 Windows 下返回 `Err`，需要实现 PE 导出表解析。

**2. Android 反射注入完善**

`src/inject/reflect_inject.rs` 的内存反射注入需要完善 ELF 手动映射逻辑。

**3. 跨进程 Inline Hook**

当前 Inline Hook 仅支持自身进程（通过直接指针操作），跨进程 Hook 需要通过 ptrace 在目标进程中写入指令。

**4. 脚本引擎多线程安全**

`src/script/engine.rs` 的状态管理需要考虑多线程并发访问。

**5. 与 nova-daemon 集成**

需要实现与项目中 nova-daemon 的通信接口，将 frida-rust 的能力暴露给 Android 端。

**6. 动态脚本加载**

支持从远程服务器动态加载加密脚本，实现更灵活的插件系统。

**7. 完整的反汇编器**

当前 `src/mcp/handler.rs` 第 697-711 行的 `simple_disasm` 仅支持有限指令，需要集成完整的反汇编库（如 `capstone`）。

**8. 进程快照功能**

支持保存和恢复进程状态，用于调试和恢复。

---

## 6. 总结

Frida-Rust 是一个从零实现的 Frida 核心功能 Rust 框架，具有以下特点：

- **完全自主实现**：不依赖原生 frida-rs/frida-sys，从零实现进程注入、函数 Hook、内存操作等核心功能
- **跨平台支持**：覆盖 Linux/Android（完整功能）和 Windows（基础功能）
- **安全设计**：脚本引擎极致裁剪、加密通信、反检测模块
- **AI 辅助**：内置 AI 学习引擎，记录操作经验并推荐策略
- **MCP 接口**：提供 14 个核心工具函数，方便 AI 助手调用

**主要改进方向**：
1. 修复 Windows 编译错误（链接 dbghelp 库）
2. 完善指令解码器，支持更多复杂指令
3. 实现跨进程 Inline Hook
4. 完善 Windows 平台功能（符号解析、IAT Hook）
5. 填充游戏模板的实际偏移量
6. 实现 AI 经验数据的持久化存储

---

## 附录

### A. 核心类型定义

**HookType**（`src/common/types.rs`）：
- `Inline` - Inline Hook
- `GotPlt` - GOT/PLT Hook（Unix）
- `Java` - Java Hook（Android）

**StealthMode**（`src/anti_detect/hide.rs`）：
- `Full` - 完全隐蔽
- `Standard` - 标准隐蔽
- `Minimal` - 最小隐蔽
- `None` - 无隐蔽

### B. 协议版本

- **协议魔数**：0xF1D40001
- **协议版本**：1

### C. 测试命令

```bash
# 编译项目（Unix）
cargo build --target aarch64-linux-android --release

# 运行测试
cargo test

# 启动 MCP 服务器
cargo run --bin mcp_server
```

### D. CLI 用法

```bash
# 注入共享库
frida-rust inject <PID> [AGENT_PATH]

# 附着到进程
frida-rust attach <PROCESS_NAME>

# 执行脚本
frida-rust script <SCRIPT_PATH> [--pid <PID>] [--anti-detect]
```
