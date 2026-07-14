# frida-rust 技术文档

> Frida 核心功能的 Rust 实现 —— 动态插桩与逆向工程框架
> 版本：v0.35.0 | 平台：Linux / Android / Windows

---

## 目录

1. [项目概述](#1-项目概述)
2. [架构设计](#2-架构设计)
3. [代码工作流程](#3-代码工作流程)
4. [编译流程](#4-编译流程)
5. [部署流程](#5-部署流程)
6. [使用说明](#6-使用说明)

---

## 1. 项目概述

frida-rust 是用 Rust 从零实现的动态插桩框架，对标 Frida 的核心能力。项目不依赖 Frida 本身，完全自主实现进程注入、函数 Hook、内存操作、脚本引擎、反检测和 IPC 通信。

### 核心能力

| 模块 | 功能 |
|---|---|
| `inject` | 将共享库/DLL 注入到目标进程 |
| `hook` | Inline Hook / GOT-PLT Hook / IAT Hook / Java Hook |
| `memory` | 跨进程内存读写、搜索、保护属性修改 |
| `script` | 基于 Rhai 的脚本引擎，可编程 Hook 和内存操作 |
| `anti_detect` | 绕过进程检测、Frida 特征擦除、调试器隐藏 |
| `communication` | 控制端与 Agent 之间的安全双向通信 |

### 平台支持

| 功能 | Linux x86_64 | Linux AArch64 | Android AArch64 | Windows x86_64 |
|---|:---:|:---:|:---:|:---:|
| Inline Hook | ✅ | ✅ | ✅ | ✅ |
| GOT/PLT Hook | ✅ | ✅ | ✅ | — |
| IAT Hook | — | — | — | ✅ |
| Java Hook | — | — | ✅ | — |
| ptrace 注入 | ✅ | ✅ | ✅ | — |
| Zygote 注入 | — | — | ✅ | — |
| 反射注入 | ✅ | ✅ | ✅ | — |
| CreateRemoteThread 注入 | — | — | — | ✅ |
| /proc 反检测 | ✅ | ✅ | ✅ | — |
| PEB 反检测 | — | — | — | ✅ |
| Unix Socket IPC | ✅ | ✅ | ✅ | — |
| NamedPipe IPC | — | — | — | ✅ |
| Rhai 脚本 | ✅ | ✅ | ✅ | ✅ |

---

## 2. 架构设计

### 2.1 目录结构

```
frida-rust/
├── Cargo.toml              # 项目配置与依赖声明
├── .cargo/config.toml       # 交叉编译链接器配置
├── src/
│   ├── main.rs              # CLI 入口（inject/attach/script 子命令）
│   ├── lib.rs               # 库入口，公共模块导出
│   │
│   ├── common/              # 基础设施层
│   │   ├── constants.rs     # 全局常量（魔数、超时、路径）
│   │   ├── error.rs         # 统一错误类型 FridaError
│   │   ├── types.rs         # 核心数据类型（ProcessId, ModuleInfo, HookPoint 等）
│   │   ├── util.rs          # 跨平台工具函数（内存读写、页对齐）
│   │   ├── syscall_wrapper.rs  # Unix 系统调用封装
│   │   └── win_util.rs      # Windows 工具函数
│   │
│   ├── inject/              # 进程注入层
│   │   ├── injector.rs      # Unix 注入器核心实现
│   │   ├── ptrace_inject.rs # ptrace 底层操作
│   │   ├── zygote_inject.rs # Android Zygote 注入
│   │   ├── reflect_inject.rs# 内存反射注入（无文件落盘）
│   │   ├── process.rs       # Unix 进程枚举与管理
│   │   ├── win_inject.rs    # Windows CreateRemoteThread 注入
│   │   └── win_process.rs   # Windows 进程枚举（ToolHelp32）
│   │
│   ├── hook/                # 函数 Hook 层
│   │   ├── manager.rs       # Hook 生命周期管理器
│   │   ├── inline.rs        # Inline Hook（x86_64/AArch64 指令解码）
│   │   ├── got_plt.rs       # GOT/PLT Hook（Unix ELF）
│   │   ├── iat_hook.rs      # IAT Hook（Windows PE）
│   │   └── java_hook.rs     # Java 方法 Hook（JNI）
│   │
│   ├── memory/              # 内存操作层
│   │   ├── scanner.rs       # Unix 内存扫描器（/proc/maps + read）
│   │   ├── allocator.rs     # Unix 远程内存分配（mmap）
│   │   ├── elf_parser.rs    # ELF 文件解析
│   │   ├── win_allocator.rs# Windows 远程内存分配（VirtualAllocEx）
│   │   └── win_scanner.rs   # Windows 内存扫描器（VirtualQueryEx）
│   │
│   ├── script/              # 脚本引擎层
│   │   ├── engine.rs        # Rhai 引擎封装 + 内置 API 注册
│   │   ├── host_context.rs  # 宿主上下文（API 注册表）
│   │   └── loader.rs        # 脚本加载器（AES-GCM 解密）
│   │
│   ├── anti_detect/         # 反检测层
│   │   ├── hide.rs          # 综合隐蔽管理器 StealthManager
│   │   ├── maps_hide.rs     # /proc/self/maps 条目隐藏
│   │   ├── tracer.rs        # TracerPid 清零 + ptrace check 拦截
│   │   ├── signature.rs     # Frida 特征字符串擦除
│   │   ├── stack_fake.rs    # 调用栈伪造
│   │   └── win_hide.rs      # Windows 反调试（PEB/调试寄存器）
│   │
│   └── communication/      # 通信层
│       ├── protocol.rs      # 消息协议定义（头 + 负载 + 加密）
│       ├── channel.rs       # 传输通道（Unix Socket / Stdio / 共享内存）
│       ├── server.rs        # 通信服务端
│       └── win_channel.rs   # Windows NamedPipe 通道
```

### 2.2 分层架构

```
┌─────────────────────────────────────────┐
│              CLI (main.rs)              │  命令行入口
├─────────────────────────────────────────┤
│           Library API (lib.rs)          │  公共 API 导出
├──────────┬──────────┬─────────┬────────┤
│  inject   │   hook   │ memory  │ script │  功能模块层
├──────────┴──────────┴─────────┴────────┤
│         anti_detect / communication     │  支撑模块层
├─────────────────────────────────────────┤
│              common (types/error/       │  基础设施层
│           constants/util)              │
├─────────────────────────────────────────┤
│         OS API (libc / winapi)          │  系统接口层
└─────────────────────────────────────────┘
```

### 2.3 条件编译策略

所有跨平台差异通过 Rust 条件编译隔离：

| 属性 | 作用 |
|---|---|
| `#[cfg(unix)]` | 仅在 Linux/Android 编译（ptrace、GOT、/proc 等） |
| `#[cfg(windows)]` | 仅在 Windows 编译（IAT、PEB、NamedPipe 等） |
| `#[cfg(target_arch = "aarch64")]` | AArch64 专用代码路径（指令解码） |
| `#[cfg(target_arch = "x86_64")]` | x86_64 专用代码路径（指令解码） |

### 2.4 错误处理

统一使用 `FridaError` 枚举（基于 `thiserror`），通过 `anyhow::Result` 传播：

```
FridaError
├── Inject          # 注入失败（含 PID、原因）
├── Ptrace          # ptrace 操作失败（含操作类型、PID）
├── Hook            # Hook 安装失败（含模块、符号）
├── MemoryRead      # 内存读取失败（含地址、大小）
├── MemoryWrite     # 内存写入失败（含地址、大小）
├── Script          # 脚本编译/执行错误
├── Communication   # 通信通道错误
├── AntiDetect      # 反检测操作失败
├── Unsupported    # 不支持的操作
├── NotFound        # 未找到目标
└── Io              # 底层系统 IO 错误
```

---

## 3. 代码工作流程

### 3.1 进程注入流程

#### Unix（Linux/Android）— ptrace 注入

```
                    ┌──────────────┐
                    │  调用者      │
                    │  inject_library(pid, lib_path)
                    └──────┬───────┘
                           ▼
                    ┌──────────────┐
                    │  创建 Injector │
                    │  Injector::new(pid)
                    └──────┬───────┘
                           ▼
                    ┌──────────────┐
                    │ ptrace ATTACH │──── 失败 ──→ 重试（最多 50 次，间隔 100ms）
                    │ 暂停目标进程  │
                    └──────┬───────┘
                           ▼ 成功
                    ┌──────────────┐
                    │ 保存原始寄存器 │
                    │ getregs()    │
                    └──────┬───────┘
                           ▼
                    ┌──────────────┐
                    │  远程 mmap    │
                    │ 分配代码缓存  │
                    └──────┬───────┘
                           ▼
                    ┌──────────────┐
                    │  写入 shellcode│  shellcode 内容: 调用 dlopen(lib_path)
                    │  ptrace POKETEXT│
                    └──────┬───────┘
                           ▼
                    ┌──────────────┐
                    │  修改 PC 寄存器 │
                    │  指向 shellcode│
                    └──────┬───────┘
                           ▼
                    ┌──────────────┐
                    │  ptrace CONT  │
                    │  恢复进程执行  │
                    └──────┬───────┘
                           ▼
                    ┌──────────────┐
                    │  等待 dlopen   │
                    │  ptrace WAIT  │
                    └──────┬───────┘
                           ▼
                    ┌──────────────┐
                    │  恢复寄存器   │
                    │  ptrace DETACH│
                    └──────────────┘
```

#### Windows — CreateRemoteThread 注入

```
                    ┌──────────────┐
                    │  WinInjector │
                    │  open_target()│
                    └──────┬───────┘
                           ▼
                    ┌──────────────┐
                    │ OpenProcess  │
                    │ 获取进程句柄  │
                    │ (权限: ALL)  │
                    └──────┬───────┘
                           ▼
                    ┌──────────────┐
                    │ VirtualAllocEx│
                    │ 在目标进程分配│
                    │ 写入 DLL 路径│
                    └──────┬───────┘
                           ▼
                    ┌──────────────┐
                    │ GetProcAddress│
                    │ 获取 LoadLibrary│
                    │  函数地址     │
                    └──────┬───────┘
                           ▼
                    ┌──────────────┐
                    │CreateRemoteThread│
                    │ 在目标进程线程中│
                    │ 调用 LoadLibrary│
                    └──────┬───────┘
                           ▼
                    ┌──────────────┐
                    │ WaitForSingleObject│
                    │ 等待注入完成   │
                    └──────────────┘
```

### 3.2 函数 Hook 流程

#### Inline Hook（x86_64 示例）

```
目标函数原始字节:         55 48 89 e5 48 83 ec 20 ...
                    ┌─────────────────────────────────┐
                    │ 1. 保存原始字节                    │
                    │    前 N 字节 → original_bytes    │
                    └──────────────┬──────────────────┘
                                   ▼
                    ┌─────────────────────────────────┐
                    │ 2. 分配跳板页 (mmap RWX)         │
                    │    包含：恢复原始字节 + 跳回指令    │
                    └──────────────┬──────────────────┘
                                   ▼
                    ┌─────────────────────────────────┐
                    │ 3. 在目标函数入口写入跳转指令      │
                    │    x86_64: jmp rel32 → detour    │
                    │    aarch64: b <imm> → detour     │
                    └──────────────┬──────────────────┘
                                   ▼
                    ┌─────────────────────────────────┐
                    │ 4. 调用者函数执行时：              │
                    │    目标函数 → jmp → detour       │
                    │    → callback() 执行自定义逻辑    │
                    │    → trampoline 恢复原始字节      │
                    │    → 跳回原函数继续执行           │
                    └─────────────────────────────────┘
```

#### GOT/PLT Hook（Unix 独有）

```
                    ┌──────────────┐
                    │  解析 ELF    │
                    │  找到 .got   │
                    │  段中目标符号 │
                    └──────┬───────┘
                           ▼
                    ┌──────────────┐
                    │  修改页保护   │
                    │  mprotect RW │
                    └──────┬───────┘
                           ▼
                    ┌──────────────┐
                    │  替换 GOT 表  │
                    │  原始地址     │──────→ saved_original
                    │  → detour    │
                    └──────┬───────┘
                           ▼
                    ┌──────────────┐
                    │  恢复页保护   │
                    │  mprotect R  │
                    └──────────────┘
```

### 3.3 脚本引擎工作流程

```
                    ┌──────────────┐
                    │  创建引擎     │
                    │  ScriptEngine │
                    │  ::new()     │
                    └──────┬───────┘
                           ▼
                    ┌──────────────┐
                    │  初始化 Rhai  │
                    │  - 禁用文件IO │
                    │  - 禁用 eval  │
                    │  - 设置超时   │
                    │  - 限制调用深度│
                    └──────┬───────┘
                           ▼
                    ┌──────────────┐
                    │  注册内置 API │
                    │  - 内存操作   │
                    │  - 模块查找   │
                    │  - Hook 注册  │
                    │  - 日志输出   │
                    └──────┬───────┘
                           ▼
                    ┌──────────────┐
                    │  加载脚本     │
                    │  - 明文直接加载│
                    │  - 加密脚本解密│
                    │    (AES-256-GCM)│
                    └──────┬───────┘
                           ▼
                    ┌──────────────┐
                    │  编译 + 执行  │
                    │  AST 缓存加速  │
                    └──────┬───────┘
                           ▼
                    ┌──────────────┐
                    │  返回结果     │
                    │  ScriptResult │
                    │  (value+logs) │
                    └──────────────┘
```

### 3.4 反检测工作流程

```
                    ┌──────────────┐
                    │  StealthManager│
                    │  ::new()     │
                    └──────┬───────┘
                           ▼
                    ┌──────────────┐
                    │  set_mode()  │
                    │  Full/Standard│
                    │  /Minimal/None│
                    └──────┬───────┘
                           ▼
                    ┌──────────────────────────────────┐
                    │        load_on_demand()          │
                    │                                   │
                    │  Full:    maps + tracer + stack    │
                    │  Standard: tracer + stack         │
                    │  Minimal: (仅特征擦除)             │
                    └──────┬──────────────────────────┘
                           ▼
                    ┌──────────────────────────────────┐
                    │          apply_all()             │
                    │                                  │
                    │  1. erase_frida_signatures()     │
                    │     扫描内存 → 零填充 Frida 字符串 │
                    │                                  │
                    │  2. maps_hider.hide_default()     │
                    │     (Unix) 过滤 /proc/self/maps  │
                    │                                  │
                    │  3. tracer_cleaner.clear_tracer() │
                    │     (Unix) TracerPid → 0         │
                    │                                  │
                    │  4. stack_faker                  │
                    │     伪造 backtrace 帧             │
                    │                                  │
                    │  5. win_hide (Windows)            │
                    │     PEB.BeingDebugged = 0        │
                    │     PEB.NtGlobalFlag &= ~0x70     │
                    │     清除调试寄存器 DR0-DR3        │
                    └──────────────────────────────────┘
```

### 3.5 通信框架工作流程

```
控制端 (Controller)                  Agent 端
      │                                    │
      │  ── 1. 创建 Server ──→              │
      │     Unix Socket / NamedPipe         │
      │                                    │
      │  ←── 2. Agent 连接 ──               │
      │                                    │
      │  ── 3. 密钥协商 ──→                 │
      │     (AES-256-GCM)                   │
      │                                    │
      │  ══ 4. 加密双向通信 ══              │
      │     Message {                       │
      │       header: magic + type + len    │
      │       payload: encrypted data       │
      │     }                               │
      │                                    │
      │  ── 5. 关闭通道 ──→                 │
      │                                    │
```

---

## 4. 编译流程

### 4.1 前置依赖

#### Linux / Android 交叉编译

```bash
# Rust 工具链
rustup target add x86_64-unknown-linux-gnu
rustup target add aarch64-unknown-linux-gnu
rustup target add aarch64-linux-android

# 交叉编译工具链
apt install gcc-aarch64-linux-gnu   # AArch64 Linux 交叉编译器
apt install mingw-w64                # Windows 交叉编译器

# Android NDK（r27c）
# 下载并解压到 /tmp/android-ndk-r27c
# NDK 提供 aarch64-linux-android21-clang 链接器
```

#### Windows 原生编译

```powershell
# 安装 Rust（通过 rustup）
# 安装 MSVC 或 MinGW 工具链
# MSVC 需要 Visual Studio Build Tools
# MinGW: pacman -S mingw-w64-x86_64-gcc
```

### 4.2 依赖列表

| 依赖 | 版本 | 用途 |
|---|---|---|
| `rhai` | 1.19 | 脚本引擎 |
| `libc` | 0.2 | Unix 系统调用 |
| `goblin` | 0.9 | 跨平台二进制解析（ELF/PE） |
| `elf` | 0.7 | ELF 详细解析 |
| `byteorder` | 1.5 | 字节序处理 |
| `aes-gcm` | 0.10 | AES-256-GCM 加密（脚本/通信） |
| `sha2` | 0.10 | SHA-256 哈希 |
| `rand` | 0.8 | 随机数生成 |
| `log` + `env_logger` | 0.4 / 0.11 | 日志框架 |
| `anyhow` | 1.0 | 错误处理 |
| `thiserror` | 2.0 | 错误类型派生 |
| `serde` + `serde_json` | 1.0 | 序列化 |
| `nix` | 0.29 | Unix 高级 API（仅 Unix） |
| `winapi` | 0.3 | Windows API 绑定（仅 Windows） |

### 4.3 交叉编译配置

项目在 `.cargo/config.toml` 中配置了各平台的链接器：

```toml
# Android AArch64 — NDK clang 链接器
[target.aarch64-linux-android]
linker = "/tmp/android-ndk-r27c/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang"
rustflags = [
    "-C", "link-arg=-L.../sysroot/usr/lib/aarch64-linux-android/21",
    "-C", "link-arg=-lc",
    "-C", "link-arg=-ldl",
    "-C", "link-arg=-llog",
]

# AArch64 Linux
[target.aarch64-unknown-linux-gnu]
linker = "aarch64-linux-gnu-gcc"

# Windows x86_64 (MinGW)
[target.x86_64-pc-windows-gnu]
linker = "x86_64-w64-mingw32-gcc"
```

### 4.4 编译命令

```bash
# Debug 编译（快速迭代）
cargo build --target <TARGET>

# Release 编译（优化 + LTO + strip）
cargo build --release --target <TARGET>

# 仅类型检查（不生成二进制）
cargo check --target <TARGET>

# 四平台编译示例
cargo build --release --target x86_64-unknown-linux-gnu
cargo build --release --target aarch64-unknown-linux-gnu
cargo build --release --target aarch64-linux-android
cargo build --release --target x86_64-pc-windows-gnu
```

### 4.5 编译产物

| 平台 | 目标三元组 | 产物路径 | 格式 | 大小 |
|---|---|---|---|---|
| Linux x86_64 | `x86_64-unknown-linux-gnu` | `target/.../release/frida-rust` | ELF 64-bit PIE | ~3.3 MB |
| Linux AArch64 | `aarch64-unknown-linux-gnu` | `target/.../release/frida-rust` | ELF 64-bit PIE | ~3.0 MB |
| Android AArch64 | `aarch64-linux-android` | `target/.../release/frida-rust` | ELF 64-bit (linker64) | ~3.0 MB |
| Windows x86_64 | `x86_64-pc-windows-gnu` | `target/.../release/frida-rust.exe` | PE32+ console | ~2.8 MB |

### 4.6 Release 编译优化

`Cargo.toml` 中配置了以下 Release profile：

```toml
[profile.release]
opt-level = 3       # 最高优化级别
lto = true          # 链接时优化（减小体积 + 提升性能）
strip = true        # 剥离调试符号
codegen-units = 1   # 单 codegen unit（更好的优化）
```

---

## 5. 部署流程

### 5.1 Linux 部署

```bash
# 1. 编译
cargo build --release --target x86_64-unknown-linux-gnu

# 2. 拷贝到目标机器
scp target/x86_64-unknown-linux-gnu/release/frida-rust user@target:/usr/local/bin/

# 3. 确保运行权限
chmod +x /usr/local/bin/frida-rust

# 4. 验证
frida-rust --version
```

### 5.2 Android 部署

```bash
# 1. 编译（需要 Android NDK）
cargo build --release --target aarch64-linux-android

# 2. 推送到设备
adb push target/aarch64-linux-android/release/frida-rust /data/local/tmp/

# 3. 在设备上执行
adb shell
cd /data/local/tmp
chmod +x frida-rust
./frida-rust --version

# 4. 注入到目标 App（需要 root）
./frida-rust inject $(pidof com.example.app)
```

### 5.3 Windows 部署

```powershell
# 1. 编译（在 Linux 上交叉编译 或 Windows 原生编译）
cargo build --release --target x86_64-pc-windows-gnu

# 2. 拷贝 frida-rust.exe 和依赖的 DLL 到目标目录
# MinGW 链接的程序需要以下运行时 DLL（通常在 C:\mingw64\bin）：
#   - libgcc_s_seh-1.dll
#   - libwinpthread-1.dll
#   - libstdc++-6.dll

# 3. 验证
.\frida-rust.exe --version
```

### 5.4 Agent 库部署

注入模式需要一个 Agent 共享库（默认 `libfrida_agent.so`）：

```bash
# Agent 库是用户自定义的共享库
# 编译为 .so（Linux/Android）或 .dll（Windows）
# 约定：库应包含 __attribute__((constructor)) 入口函数
#     frida-rust 注入后会自动调用该初始化函数

# 示例 Agent 编译
gcc -shared -fPIC -o libfrida_agent.so agent.c

# 指定自定义 Agent 路径
frida-rust inject 1234 /path/to/custom_agent.so
```

---

## 6. 使用说明

### 6.1 CLI 使用

#### 全局选项

```bash
frida-rust [全局选项] <子命令> [子命令参数]

全局选项:
  -v, --verbose    启用 DEBUG 级别日志
  -q, --quiet      仅输出错误（ERROR 级别）
  -h, --help       显示帮助信息
  -V, --version    显示版本号
```

#### 子命令：inject（进程注入）

```bash
# 基本用法：注入默认 agent 到目标进程
frida-rust inject <PID> [AGENT_PATH]

# 注入到 PID 1234
frida-rust inject 1234

# 使用自定义 agent 库
frida-rust inject 1234 /path/to/custom_agent.so
```

#### 子命令：attach（进程附着）

```bash
# 通过进程名查找并附着
frida-rust attach <PROCESS_NAME>

# 示例
frida-rust attach com.example.app
```

#### 子命令：script（脚本执行）

```bash
# 执行脚本
frida-rust script <SCRIPT_PATH> [--pid <PID>] [--anti-detect]

# 本地执行
frida-rust script hook.rhai

# 针对目标进程执行 + 启用反检测
frida-rust script hook.rhai --pid 1234 --anti-detect

# 详细日志模式
frida-rust -v script analyze.rhai
```

### 6.2 作为 Rust 库使用

在 `Cargo.toml` 中添加：

```toml
[dependencies]
frida-rust = { path = "path/to/frida-rust" }
```

#### Hook 函数

```rust
use frida_rust::hook::HookManager;
use frida_rust::common::types::{HookPoint, HookType};

// 创建 Hook 管理器
let mut manager = HookManager::new();

// 注册 Hook 点
let id = manager.register_hook(
    HookPoint::named("libfoo.so", "target_func", HookType::Inline),
    |ctx| {
        println!("Hook 触发: {:?}", ctx);
    },
)?;

// 安装 Hook
manager.install(id)?;

// ... 程序运行，Hook 自动生效 ...

// 卸载 Hook
manager.uninstall(id)?;
```

#### Rhai 脚本

```rhai
// hook.rhai — Rhai 脚本示例

// 获取模块基址
let base = find_module_base("libfoo.so");
log_info("模块基址: " + to_string(base));

// 读取内存
let data = read_memory(base, 64);
log_info("读取了 " + to_string(data.len()) + " 字节");

// 搜索字节
let results = search_bytes(blob([0x48, 0x89, 0x5C, 0x24]));
for addr in results {
    log_info("找到: " + to_string(addr));
}

// 写入内存
write_memory(base + 0x100, blob([0x90, 0x90, 0x90]));

// 注册函数 Hook
let hook_id = hook_function("libfoo.so", "secret_func", "on_hook");
log_info("Hook 注册成功, ID: " + to_string(hook_id));

// 卸载 Hook
unhook_function(hook_id);
```

在 Rust 中执行脚本：

```rust
use frida_rust::script::ScriptEngine;

let mut engine = ScriptEngine::new()?;
let bytes = std::fs::read("hook.rhai")?;
let result = engine.execute(&bytes)?;
```

#### 内存扫描

```rust
use frida_rust::memory::MemoryScanner;
use frida_rust::common::types::ProcessId;

// 创建针对目标进程的扫描器
let mut scanner = MemoryScanner::new(ProcessId(1234));

// 搜索字节序列
let results = scanner.search_bytes(&[0x48, 0x89, 0x5C, 0x24], None)?;
for addr in &results {
    println!("匹配地址: {:#x}", addr);
}
```

#### 反检测

```rust
use frida_rust::anti_detect;

// 一键应用所有反检测措施
anti_detect::apply_stealth()?;

// 或使用隐蔽管理器进行精细控制
use frida_rust::anti_detect::hide::{StealthManager, StealthMode};

let mut manager = StealthManager::new();
manager.set_mode(StealthMode::Full);
manager.apply_all()?;
```

#### IPC 通信

```rust
use frida_rust::communication::server::CommServer;

// 创建通信服务端（Unix Socket / NamedPipe）
let mut server = CommServer::new("frida_pipe")?;
server.start()?;  // 阻塞，等待 Agent 连接
```

### 6.3 脚本引擎内置 API 参考

| API 函数 | 签名 | 说明 |
|---|---|---|
| `find_module_base` | `(name: str) -> int` | 获取模块基址 |
| `find_module_by_name` | `(name: str) -> map` | 获取模块详细信息 |
| `read_memory` | `(addr: int, size: int) -> blob` | 读取内存 |
| `write_memory` | `(addr: int, data: blob) -> bool` | 写入内存 |
| `search_bytes` | `(pattern: blob) -> array` | 搜索字节模式 |
| `get_pid` | `() -> int` | 获取当前 PID |
| `log_info` | `(msg: str)` | 输出 INFO 日志 |
| `log_warn` | `(msg: str)` | 输出 WARN 日志 |
| `log_error` | `(msg: str)` | 输出 ERROR 日志 |
| `hook_function` | `(module: str, symbol: str, callback: str) -> int` | 注册函数 Hook |
| `unhook_function` | `(id: int) -> bool` | 卸载 Hook |
| `protect_memory` | `(addr: int, size: int, prot: int) -> bool` | 修改内存保护属性 |

### 6.4 日志配置

通过环境变量控制日志级别：

```bash
# 输出所有 DEBUG 日志
RUST_LOG=debug frida-rust inject 1234

# 仅输出 frida_rust 模块的日志
RUST_LOG=frida_rust=debug frida-rust script hook.rhai

# 仅输出错误
RUST_LOG=error frida-rust attach com.example.app
```

---

## 附录

### A. 常用常量

| 常量 | 值 | 说明 |
|---|---|---|
| `PROTOCOL_MAGIC` | `0xF1D40001` | 通信协议魔数 |
| `INJECT_AGENT_MAGIC` | `0x46E37001` | 注入 Agent 魔数 |
| `DEFAULT_AGENT_LIB_NAME` | `libfrida_agent.so` | 默认 agent 库名 |
| `INJECT_TIMEOUT_MS` | 10000 | 注入超时 10 秒 |
| `MEMORY_SCAN_MAX_SIZE` | 256 MB | 内存扫描上限 |
| `COMM_BUFFER_SIZE` | 64 KB | 通信缓冲区大小 |
| `SCRIPT_TIMEOUT_MS` | 30000 | 脚本执行超时 30 秒 |

### B. 错误排查

| 错误信息 | 原因 | 解决方法 |
|---|---|---|
| `linker not found` | 缺少交叉编译工具链 | 安装对应平台的 gcc/clang |
| `permission denied` | 无权访问目标进程 | 使用 root 权限或 sudo |
| `No such file or directory` | Agent 文件不存在 | 检查 agent 路径是否正确 |
| `ptrace 操作失败` | 目标进程有 ptrace 保护 | 检查 seccomp/yama 配置 |
| `Hook 安装失败` | 目标函数不可写 | 检查内存保护属性 |
