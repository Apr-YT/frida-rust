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
#[cfg(windows)]
pub mod win_reflect;

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

/// 暂停目标进程（Unix: SIGSTOP）
#[cfg(unix)]
pub fn suspend_process(pid: crate::common::types::ProcessId) -> Result<(), crate::FridaError> {
    let ret = unsafe { libc::kill(pid.0 as libc::pid_t, libc::SIGSTOP) };
    if ret != 0 {
        return Err(crate::FridaError::Io(std::io::Error::last_os_error()).into());
    }
    Ok(())
}

/// 暂停目标进程（Windows: NtSuspendProcess）
#[cfg(windows)]
pub fn suspend_process(pid: crate::common::types::ProcessId) -> Result<(), crate::FridaError> {
    unsafe {
        use winapi::um::handleapi::CloseHandle;
        use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
        use winapi::um::processthreadsapi::OpenProcess;
        use winapi::um::winnt::{HANDLE, PROCESS_SUSPEND_RESUME};

        let handle = OpenProcess(PROCESS_SUSPEND_RESUME, 0, pid.0);
        if handle.is_null() {
            return Err(crate::FridaError::Io(std::io::Error::last_os_error()).into());
        }

        let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr() as *const i8);
        if ntdll.is_null() {
            CloseHandle(handle);
            return Err(crate::FridaError::Other("无法加载 ntdll.dll".into()).into());
        }
        let proc = GetProcAddress(ntdll, b"NtSuspendProcess\0".as_ptr() as *const i8);
        if proc.is_null() {
            CloseHandle(handle);
            return Err(crate::FridaError::Other("找不到 NtSuspendProcess".into()).into());
        }

        type NtSuspendProcess = unsafe extern "system" fn(HANDLE) -> i32;
        let func: NtSuspendProcess = std::mem::transmute(proc);
        let status = func(handle);
        CloseHandle(handle);
        if status < 0 {
            return Err(crate::FridaError::Other(format!("NtSuspendProcess 失败: status {:#x}", status)).into());
        }
    }
    Ok(())
}

/// 恢复已暂停的进程（Unix: SIGCONT）
#[cfg(unix)]
pub fn resume_process(pid: crate::common::types::ProcessId) -> Result<(), crate::FridaError> {
    let ret = unsafe { libc::kill(pid.0 as libc::pid_t, libc::SIGCONT) };
    if ret != 0 {
        return Err(crate::FridaError::Io(std::io::Error::last_os_error()).into());
    }
    Ok(())
}

/// 恢复已暂停的进程（Windows: NtResumeProcess）
#[cfg(windows)]
pub fn resume_process(pid: crate::common::types::ProcessId) -> Result<(), crate::FridaError> {
    unsafe {
        use winapi::um::handleapi::CloseHandle;
        use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
        use winapi::um::processthreadsapi::OpenProcess;
        use winapi::um::winnt::{HANDLE, PROCESS_SUSPEND_RESUME};

        let handle = OpenProcess(PROCESS_SUSPEND_RESUME, 0, pid.0);
        if handle.is_null() {
            return Err(crate::FridaError::Io(std::io::Error::last_os_error()).into());
        }

        let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr() as *const i8);
        if ntdll.is_null() {
            CloseHandle(handle);
            return Err(crate::FridaError::Other("无法加载 ntdll.dll".into()).into());
        }
        let proc = GetProcAddress(ntdll, b"NtResumeProcess\0".as_ptr() as *const i8);
        if proc.is_null() {
            CloseHandle(handle);
            return Err(crate::FridaError::Other("找不到 NtResumeProcess".into()).into());
        }

        type NtResumeProcess = unsafe extern "system" fn(HANDLE) -> i32;
        let func: NtResumeProcess = std::mem::transmute(proc);
        let status = func(handle);
        CloseHandle(handle);
        if status < 0 {
            return Err(crate::FridaError::Other(format!("NtResumeProcess 失败: status {:#x}", status)).into());
        }
    }
    Ok(())
}

/// 终止目标进程（Unix: SIGKILL）
#[cfg(unix)]
pub fn kill_process(pid: crate::common::types::ProcessId) -> Result<(), crate::FridaError> {
    let ret = unsafe { libc::kill(pid.0 as libc::pid_t, libc::SIGKILL) };
    if ret != 0 {
        return Err(crate::FridaError::Io(std::io::Error::last_os_error()).into());
    }
    Ok(())
}

/// 终止目标进程（Windows: TerminateProcess）
#[cfg(windows)]
pub fn kill_process(pid: crate::common::types::ProcessId) -> Result<(), crate::FridaError> {
    unsafe {
        use winapi::um::handleapi::CloseHandle;
        use winapi::um::processthreadsapi::{OpenProcess, TerminateProcess};
        use winapi::um::winnt::PROCESS_TERMINATE;

        let handle = OpenProcess(PROCESS_TERMINATE, 0, pid.0);
        if handle.is_null() {
            return Err(crate::FridaError::Io(std::io::Error::last_os_error()).into());
        }
        let ret = TerminateProcess(handle, 1);
        CloseHandle(handle);
        if ret == 0 {
            return Err(crate::FridaError::Io(std::io::Error::last_os_error()).into());
        }
    }
    Ok(())
}
