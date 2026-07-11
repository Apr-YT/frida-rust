# frida-rust

Frida 核心功能的 Rust 实现 —— 支持 Linux、Android 和 Windows 的动态插桩与逆向工程框架。

不依赖 Frida 本身，从零自主实现进程注入、函数 Hook、内存操作、脚本引擎、反检测和 IPC 通信。

## 平台支持

| 功能                    | Linux x86_64 | Linux AArch64 | Android AArch64 | Windows x86_64 |
| ----------------------- | :----------: | :-----------: | :-------------: | :------------: |
| Inline Hook             |      ✅      |      ✅       |       ✅        |       ✅       |
| GOT/PLT Hook            |      ✅      |      ✅       |       ✅        |       —        |
| IAT Hook                |      —       |       —       |        —        |       ✅       |
| Java Hook               |      —       |       —       |       ✅        |       —        |
| ptrace 注入             |      ✅      |      ✅       |       ✅        |       —        |
| Zygote 注入             |      —       |       —       |       ✅        |       —        |
| 反射注入                |      ✅      |      ✅       |       ✅        |       —        |
| CreateRemoteThread 注入 |      —       |       —       |        —        |       ✅       |
| /proc 反检测            |      ✅      |      ✅       |       ✅        |       —        |
| PEB 反检测              |      —       |       —       |        —        |       ✅       |
| Rhai 脚本引擎           |      ✅      |      ✅       |       ✅        |       ✅       |
| MCP Server              |      ✅      |      ✅       |       ✅        |       ✅       |

## 快速开始

### 编译

```bash
# Linux x86_64
cargo build --release --target x86_64-unknown-linux-gnu

# Android AArch64（需要 NDK）
cargo build --release --target aarch64-linux-android

# Windows x86_64（MinGW 交叉编译）
cargo build --release --target x86_64-pc-windows-gnu
```

### CLI 使用

```bash
# 注入 agent 到目标进程
./frida-rust inject 1234
./frida-rust inject 1234 /path/to/agent.so

# 通过进程名附着
./frida-rust attach com.example.app

# 执行 Rhai 脚本
./frida-rust script hook.rhai --pid 1234 --anti-detect
```

## MCP Server 集成

内置 MCP (Model Context Protocol) 服务器，让 AI 助手可以直接调用逆向工程能力。

### 启动 MCP Server

```bash
# 直接运行（通过 stdio 通信）
./frida-rust-mcp
```

### 配置到 Codex / Claude

```json
{
  "mcpServers": {
    "frida-rust": {
      "command": "frida-rust-mcp",
      "args": []
    }
  }
}
```

### MCP Tools 列表

| Tool                    | 说明                                |
| ----------------------- | ----------------------------------- |
| `list_processes`        | 列出所有运行进程                    |
| `attach_process`        | ptrace 附着到目标进程               |
| `inject_library`        | 注入共享库到目标进程                |
| `hook_function`         | Hook 目标函数 (inline/got_plt/java) |
| `read_memory`           | 读取目标进程内存                    |
| `write_memory`          | 写入目标进程内存                    |
| `scan_memory`           | 搜索内存中的字节模式                |
| `execute_script`        | 执行 Rhai 脚本                      |
| `apply_stealth`         | 应用全部反检测措施                  |
| `clear_tracer_pid`      | 清除 TracerPid                      |
| `hide_maps_entries`     | 隐藏 /proc/self/maps 条目          |
| `erase_frida_signatures`| 擦除 Frida 特征字符串               |

### phone-mcp 集成

项目同时集成了 phone-mcp Python MCP Server，可通过 ADB 远程调用设备上的 frida-rust：

- `phone_frida_inject` — 远程注入共享库
- `phone_frida_attach` — 远程附着进程
- `phone_frida_script` — 远程执行 Rhai 脚本
- `phone_frida_read_mem` — 远程读取内存
- `phone_frida_write_mem` — 远程写入内存
- `phone_frida_scan_mem` — 远程搜索内存
- `phone_frida_stealth` — 远程应用反检测

## 功能模块

### 进程注入 (`inject`)

- **ptrace 注入** — 附加目标进程，写入 shellcode 调用 dlopen
- **Zygote 注入** — Android 特有，利用 Zygote fork 机制
- **反射注入** — 无文件落盘，直接解析 ELF 手动映射
- **CreateRemoteThread** — Windows 标准 DLL 注入

### 函数 Hook (`hook`)

- **Inline Hook** — 修改函数入口机器码，跳转到 trampoline
- **GOT/PLT Hook** — 替换 ELF 全局偏移表中的函数指针
- **IAT Hook** — 替换 Windows PE 导入地址表中的函数指针
- **Java Hook** — 通过 JNI 拦截 Java 虚拟机方法调用

### 内存操作 (`memory`)

- 跨进程内存读写（`process_vm_readv` / `ReadProcessMemory`）
- 内存扫描（字节模式搜索、字符串搜索）
- 内存保护属性修改（`mprotect` / `VirtualProtectEx`）
- ELF 文件解析（段、节、符号表）

### 脚本引擎 (`script`)

基于 Rhai 脚本引擎，提供可编程的动态插桩能力。内置 API：

| 函数                                  | 说明           |
| ------------------------------------- | -------------- |
| `find_module_base(name)`              | 获取模块基址   |
| `read_memory(addr, size)`             | 读取内存       |
| `write_memory(addr, data)`            | 写入内存       |
| `search_bytes(pattern)`               | 搜索字节模式   |
| `hook_function(module, symbol, callback)` | 注册函数 Hook |
| `get_pid()`                           | 获取当前进程 PID |

示例脚本：

```rhai
let base = find_module_base("libfoo.so");
let data = read_memory(base, 64);
let results = search_bytes(blob([0x48, 0x89, 0x5C, 0x24]));

for addr in results {
    log_info("匹配地址: " + to_string(addr));
}

write_memory(base + 0x100, blob([0x90, 0x90, 0x90]));
```

### 反检测 (`anti_detect`)

- 擦除 Frida 特征字符串（内存扫描 + 零填充）
- `/proc/self/maps` 条目隐藏
- `TracerPid` 清零 + ptrace check 拦截
- 调用栈伪造
- Windows PEB `BeingDebugged` / `NtGlobalFlag` 清零
- 调试寄存器清理

### 通信框架 (`communication`)

- Unix Socket 通道（Linux/Android）
- NamedPipe 通道（Windows）
- AES-256-GCM 消息加密
- 协议层：消息头（魔数 + 类型 + 长度）+ 加密负载

## 作为库使用

```toml
[dependencies]
frida-rust = { git = "https://github.com/Apr-YT/frida-rust" }
```

### Hook 函数

```rust
use frida_rust::hook::HookManager;
use frida_rust::common::types::{HookPoint, HookType};

let mut manager = HookManager::new();

let id = manager.register_hook(
    HookPoint::named("libfoo.so", "target_func", HookType::Inline),
    |ctx| {
        println!("Hook 触发: {:?}", ctx);
    },
)?;

manager.install(id)?;
// ...
manager.uninstall(id)?;
```

### 反检测

```rust
use frida_rust::anti_detect;

anti_detect::apply_stealth()?;
```

### 内存扫描

```rust
use frida_rust::memory::MemoryScanner;
use frida_rust::common::types::ProcessId;

let mut scanner = MemoryScanner::new(ProcessId(1234));
let results = scanner.search_bytes(&[0x48, 0x89, 0x5C, 0x24], None)?;
```

## 目录结构

```
frida-rust/
├── src/
│   ├── main.rs              # CLI 入口
│   ├── lib.rs               # 库入口
│   ├── bin/
│   │   └── mcp_server.rs    # MCP Server 入口
│   ├── common/              # 类型、错误、常量、工具函数
│   ├── inject/              # 进程注入（ptrace / Zygote / 反射 / Windows）
│   ├── hook/                # 函数 Hook（Inline / GOT-PLT / IAT / Java）
│   ├── memory/              # 内存操作（扫描、分配、ELF 解析）
│   ├── script/              # Rhai 脚本引擎
│   ├── anti_detect/         # 反检测模块
│   ├── communication/       # IPC 通信框架
│   └── mcp/                 # MCP Server 模块
│       ├── mod.rs
│       └── handler.rs
├── Cargo.toml
├── TECHNICAL_DOC.md         # 完整技术文档
└── examples/                # 示例脚本
```

## 交叉编译配置

项目已配置 `.cargo/config.toml`，支持四平台交叉编译：

| 平台              | 目标三元组                | 链接器                  |
| ----------------- | ------------------------- | ----------------------- |
| Linux x86_64      | `x86_64-unknown-linux-gnu`  | 系统默认 gcc            |
| Linux AArch64     | `aarch64-unknown-linux-gnu` | `aarch64-linux-gnu-gcc` |
| Android AArch64   | `aarch64-linux-android`     | NDK clang               |
| Windows x86_64    | `x86_64-pc-windows-gnu`     | `x86_64-w64-mingw32-gcc`|

## 技术文档

完整的架构设计、代码工作流程、编译流程、部署流程和使用说明见 [TECHNICAL_DOC.md](./TECHNICAL_DOC.md)。

## License

MIT
