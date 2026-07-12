//! Windows 进程管理模块
//!
//! 使用 Windows ToolHelp32 API 枚举进程、模块和线程。
//! 提供与 Linux `/proc` 解析等效的功能。

use crate::common::error::FridaError;
use crate::common::types::{ModuleInfo, ProcessId, ProcessInfo, ThreadId};
use std::mem::{size_of, zeroed};

use winapi::shared::minwindef::{DWORD, FALSE, HMODULE};
use winapi::shared::ntdef::NULL;
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::psapi::GetModuleFileNameExW;
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Module32First, Module32Next, Process32First, Process32Next,
    Thread32First, Thread32Next, MODULEENTRY32, PROCESSENTRY32, THREADENTRY32,
    TH32CS_SNAPMODULE, TH32CS_SNAPPROCESS, TH32CS_SNAPTHREAD,
};
use winapi::um::winnt::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

/// 将 ASCII/UTF-8 字节数组（以 null 结尾）转换为 Rust String
fn c_str_to_string(buf: &[i8]) -> String {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, len) }).to_string()
}

/// 将 Windows 宽字符数组转换为 Rust String
fn wide_to_string(buf: &[u16]) -> String {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..len])
}

/// 枚举系统中所有进程
///
/// 使用 `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)` 遍历所有进程。
pub fn enum_processes() -> crate::Result<Vec<ProcessInfo>> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == NULL || snapshot == INVALID_HANDLE_VALUE {
        let err = std::io::Error::last_os_error();
        return Err(FridaError::Io(err).into());
    }

    let mut processes = Vec::new();
    let mut entry: PROCESSENTRY32 = unsafe { zeroed() };
    entry.dwSize = size_of::<PROCESSENTRY32>() as DWORD;

    let mut first = true;
    loop {
        let ok = if first {
            first = false;
            unsafe { Process32First(snapshot, &mut entry) }
        } else {
            unsafe { Process32Next(snapshot, &mut entry) }
        };

        if ok == FALSE {
            break;
        }

        let pid = entry.th32ProcessID;
        if pid == 0 {
            continue;
        }

        let name = c_str_to_string(&entry.szExeFile);

        processes.push(ProcessInfo {
            pid: ProcessId(pid),
            name: name.clone(),
            cmdline: vec![name],
            state: "unknown".to_string(),
            ppid: entry.th32ParentProcessID,
            uid: 0,
            exe_path: String::new(),
            cwd: String::new(),
        });
    }

    unsafe {
        CloseHandle(snapshot);
    }

    log::debug!("枚举到 {} 个进程", processes.len());
    Ok(processes)
}

/// 按名称查找进程
///
/// 在所有可见进程中搜索名称匹配的进程（不区分大小写）。
///
/// # 参数
/// - `name`: 要搜索的进程名称（部分匹配）
///
/// # 返回值
/// 返回第一个匹配的进程信息，如果没有找到则返回 None。
pub fn find_process_by_name(name: &str) -> crate::Result<Option<ProcessInfo>> {
    let processes = enum_processes()?;
    let name_lower = name.to_lowercase();

    for proc in processes {
        if proc.name.to_lowercase().contains(&name_lower) {
            return Ok(Some(proc));
        }
    }

    Ok(None)
}

/// 枚举指定进程的所有已加载模块
///
/// 使用 `CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid)` 获取模块列表。
///
/// # 参数
/// - `pid`: 目标进程 ID
///
/// # 返回值
/// 返回该进程所有已加载模块的列表。
pub fn enum_modules(pid: u32) -> crate::Result<Vec<ModuleInfo>> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid) };
    if snapshot == NULL || snapshot == INVALID_HANDLE_VALUE {
        let err = std::io::Error::last_os_error();
        return Err(FridaError::Io(err).into());
    }

    let mut modules = Vec::new();
    let mut entry: MODULEENTRY32 = unsafe { zeroed() };
    entry.dwSize = size_of::<MODULEENTRY32>() as DWORD;

    let mut first = true;
    loop {
        let ok = if first {
            first = false;
            unsafe { Module32First(snapshot, &mut entry) }
        } else {
            unsafe { Module32Next(snapshot, &mut entry) }
        };

        if ok == FALSE {
            break;
        }

        let name = c_str_to_string(&entry.szModule);
        let path = c_str_to_string(&entry.szExePath);

        modules.push(ModuleInfo {
            name,
            base_addr: entry.modBaseAddr as usize,
            size: entry.modBaseSize as usize,
            path,
        });
    }

    unsafe {
        CloseHandle(snapshot);
    }

    log::debug!("进程 PID {} 共有 {} 个已加载模块", pid, modules.len());
    Ok(modules)
}

/// 枚举指定进程的所有线程
///
/// 使用 `CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)` 获取所有线程，
/// 然后过滤出属于指定进程的线程。
///
/// # 参数
/// - `pid`: 目标进程 ID
///
/// # 返回值
/// 返回该进程所有线程 ID 的列表。
pub fn enum_threads(pid: u32) -> crate::Result<Vec<ThreadId>> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snapshot == NULL || snapshot == INVALID_HANDLE_VALUE {
        let err = std::io::Error::last_os_error();
        return Err(FridaError::Io(err).into());
    }

    let mut threads = Vec::new();
    let mut entry: THREADENTRY32 = unsafe { zeroed() };
    entry.dwSize = size_of::<THREADENTRY32>() as DWORD;

    let mut first = true;
    loop {
        let ok = if first {
            first = false;
            unsafe { Thread32First(snapshot, &mut entry) }
        } else {
            unsafe { Thread32Next(snapshot, &mut entry) }
        };

        if ok == FALSE {
            break;
        }

        if entry.th32OwnerProcessID == pid {
            threads.push(ThreadId(entry.th32ThreadID));
        }
    }

    unsafe {
        CloseHandle(snapshot);
    }

    log::debug!("进程 PID {} 共有 {} 个线程", pid, threads.len());
    Ok(threads)
}

/// 获取进程信息
///
/// 通过 ToolHelp32 获取基础信息，并尝试通过 `OpenProcess` + `GetModuleFileNameExW`
/// 获取完整可执行路径。
///
/// # 参数
/// - `pid`: 目标进程 ID
///
/// # 返回值
/// 返回进程的详细信息。如果进程不存在，返回错误。
pub fn get_process_info(pid: u32) -> crate::Result<ProcessInfo> {
    // 先枚举所有进程找到目标
    let processes = enum_processes()?;
    let mut info = processes
        .into_iter()
        .find(|p| p.pid.0 == pid)
        .ok_or_else(|| FridaError::NotFound {
            reason: format!("找不到进程 PID {}", pid),
        })?;

    // 尝试获取完整可执行路径
    let handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid) };
    if handle != NULL && handle != INVALID_HANDLE_VALUE {
        let mut buf = [0u16; 512];
        let len = unsafe { GetModuleFileNameExW(handle, NULL as HMODULE, buf.as_mut_ptr(), buf.len() as DWORD) };
        if len > 0 {
            info.exe_path = wide_to_string(&buf[..len as usize]);
        }
        unsafe {
            CloseHandle(handle);
        }
    }

    Ok(info)
}
