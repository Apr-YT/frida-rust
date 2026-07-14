//! # frida-rust
//!
//! Frida 核心功能的 Rust 实现 —— 动态插桩与逆向工程框架。
//!
//! 本库提供以下核心能力：
//! - **进程注入** (`inject`) - 将共享库注入到目标进程中
//! - **函数 Hook** (`hook`) - 拦截和修改函数调用（Inline / GOT-PLT / Java）
//! - **内存操作** (`memory`) - 内存读写、搜索与保护属性修改
//! - **脚本引擎** (`script`) - 基于 Rhai 的脚本执行框架
//! - **反检测** (`anti_detect`) - 绕过常见的进程/Root/Frida 检测手段
//! - **通信框架** (`communication`) - 注入端与控制端之间的安全双向通信
//!
//! ## 平台支持
//! - **Linux / Android**: 完整支持所有功能
//! - **Windows**: 支持 IAT Hook、Inline Hook 和 NamedPipe 通信

// 公共模块
pub mod common;
pub mod inject;
pub mod hook;
pub mod memory;
pub mod script;
pub mod anti_detect;
pub mod communication;
pub mod mcp;
pub mod ai_learning;
pub mod webui;
pub mod esp_analyzer;
pub mod disasm;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod android;

// 顶层 Result 类型别名，简化返回值书写
/// 项目统一 Result 类型，使用 anyhow 进行错误传播
pub type Result<T> = anyhow::Result<T>;

// 重新导出常用类型，方便外部使用
pub use common::error::FridaError;
pub use common::types::{
    Architecture, HookPoint, HookType, MemoryRegion, ModuleInfo, ProcessId, ProcessInfo, SymbolInfo,
    ThreadId,
};
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use communication::kernel_channel::{KernelChannel, NovaCmd};


