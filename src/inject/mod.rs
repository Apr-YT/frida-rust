//! 进程注入模块
//!
//! 提供将共享库注入到目标进程的能力，支持以下注入方式：
//! - **ptrace 注入** - 经典方式，通过 ptrace 附加目标进程并调用 dlopen
//! - **Zygote 注入** - Android 特有，利用 Zygote fork 机制在子进程中注入
//! - **反射注入** - 不写磁盘的内存反射注入，解析 ELF 并手动映射到目标进程
//!
//! 子模块：
//! - `injector` - 注入器核心实现，提供统一的注入接口
//! - `ptrace_inject` - ptrace 底层操作封装（寄存器读写、远程内存分配等）
//! - `zygote_inject` - Zygote 注入方式实现
//! - `reflect_inject` - 内存反射注入实现
//! - `process` - 进程管理能力（枚举进程/模块/线程、解析 /proc 等）
//!
//! ## Linux/Android 平台
//! 使用 `ptrace(PTRACE_ATTACH, ...)` 暂停目标进程，
//! 通过 `ptrace(PTRACE_POKETEXT, ...)` 写入 shellcode，
//! 使目标进程调用 `dlopen()` 加载指定的共享库。

#[cfg(unix)]
pub mod injector;
#[cfg(unix)]
pub mod process;
#[cfg(unix)]
pub mod ptrace_inject;
#[cfg(unix)]
pub mod reflect_inject;
#[cfg(unix)]
pub mod zygote_inject;

#[cfg(windows)]
pub mod win_inject;
#[cfg(windows)]
pub mod win_process;

// 重新导出主要接口
#[cfg(unix)]
pub use injector::Injector;
#[cfg(unix)]
pub use process::*;

#[cfg(windows)]
pub use win_inject::WinInjector;
#[cfg(windows)]
pub use win_process::*;

/// 便捷注入函数：注入共享库到目标进程
#[cfg(unix)]
pub fn inject_library(pid: crate::common::types::ProcessId, lib_path: &str) -> Result<(), crate::FridaError> {
    let mut injector = Injector::new(pid);
    injector.inject_library(lib_path).map_err(|e| crate::FridaError::Inject {
        reason: format!("注入失败: {}", e),
        pid: pid.0,
        source: None,
    })
}

/// 便捷注入函数：注入 DLL 到目标进程（Windows）
#[cfg(windows)]
pub fn inject_library(pid: crate::common::types::ProcessId, lib_path: &str) -> Result<(), crate::FridaError> {
    let mut injector = WinInjector::new(pid.0);
    injector.open_target().map_err(|e| crate::FridaError::Inject {
        reason: format!("打开进程失败: {}", e),
        pid: pid.0,
        source: None,
    })?;
    injector.inject_library(lib_path).map_err(|e| crate::FridaError::Inject {
        reason: format!("注入失败: {}", e),
        pid: pid.0,
        source: None,
    })
}

/// 便捷附着函数：附着到目标进程
#[cfg(unix)]
pub fn attach_process(pid: crate::common::types::ProcessId) -> Result<(), crate::FridaError> {
    let mut injector = Injector::new(pid);
    injector.attach_process().map_err(|e| crate::FridaError::Inject {
        reason: format!("附着失败: {}", e),
        pid: pid.0,
        source: None,
    })
}

/// 便捷附着函数：打开目标进程（Windows）
#[cfg(windows)]
pub fn attach_process(pid: crate::common::types::ProcessId) -> Result<(), crate::FridaError> {
    let mut injector = WinInjector::new(pid.0);
    injector.open_target().map_err(|e| crate::FridaError::Inject {
        reason: format!("打开进程失败: {}", e),
        pid: pid.0,
        source: None,
    })
}
