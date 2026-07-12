//! Windows 平台工具函数
//!
//! 提供 Windows 特有的进程枚举、模块枚举、内存区域解析等工具函数。
//! 跨平台函数（如 current_process_id、page_size 等）请优先使用 common::util。

pub use crate::common::util::{
    align_to_page, align_to_page_up, current_process_id, is_process_alive, page_size,
    parse_proc_maps, read_file_bytes, safe_read_bytes, safe_write_bytes, write_file_bytes,
};

use crate::common::types::{MemoryRegion, ModuleInfo, ProcessId, ProcessInfo};
use crate::FridaError;
use crate::Result;

/// 枚举所有进程（Windows 版本）
///
/// 使用 Toolhelp32 快照枚举系统中所有进程。
pub fn enum_processes_win() -> Result<Vec<ProcessInfo>> {
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::tlhelp32::{
        CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
    };

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == winapi::um::handleapi::INVALID_HANDLE_VALUE {
            return Err(FridaError::Io(std::io::Error::last_os_error()).into());
        }

        let mut processes = Vec::new();
        let mut entry: PROCESSENTRY32 = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

        if Process32First(snapshot, &mut entry) != 0 {
            loop {
                let name = c_char_slice_to_string(&entry.szExeFile);
                processes.push(ProcessInfo {
                    pid: ProcessId(entry.th32ProcessID),
                    name,
                    cmdline: Vec::new(),
                    state: String::from("?"),
                    ppid: entry.th32ParentProcessID,
                    uid: 0,
                    exe_path: String::new(),
                    cwd: String::new(),
                });

                if Process32Next(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }

        CloseHandle(snapshot);
        Ok(processes)
    }
}

/// 枚举指定进程的模块（Windows 版本）
///
/// 使用 `EnumProcessModules` + `GetModuleInformation` 获取模块列表。
pub fn enum_modules_win(pid: u32) -> Result<Vec<ModuleInfo>> {
    use winapi::shared::minwindef::{DWORD, HMODULE};
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::processthreadsapi::OpenProcess;
    use winapi::um::psapi::{EnumProcessModules, GetModuleBaseNameA, GetModuleInformation};
    use winapi::um::winnt::{
        PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
        if handle.is_null() {
            return Err(FridaError::Io(std::io::Error::last_os_error()).into());
        }

        let mut needed: DWORD = 0;
        // 第一次调用获取所需缓冲区大小
        EnumProcessModules(handle, std::ptr::null_mut(), 0, &mut needed);

        let count = needed as usize / std::mem::size_of::<HMODULE>();
        let mut modules: Vec<HMODULE> = vec![std::ptr::null_mut(); count];

        let result = if EnumProcessModules(handle, modules.as_mut_ptr(), needed, &mut needed) != 0 {
            let mut infos = Vec::with_capacity(count);
            for &module in &modules {
                if module.is_null() {
                    continue;
                }
                let mut info: winapi::um::psapi::MODULEINFO = std::mem::zeroed();
                if GetModuleInformation(
                    handle,
                    module,
                    &mut info,
                    std::mem::size_of::<winapi::um::psapi::MODULEINFO>() as u32,
                ) == 0
                {
                    continue;
                }

                let mut name_buf = vec![0u8; 512];
                let len = GetModuleBaseNameA(
                    handle,
                    module,
                    name_buf.as_mut_ptr() as *mut i8,
                    name_buf.len() as u32,
                );

                let name = if len > 0 {
                    name_buf.truncate(len as usize);
                    String::from_utf8_lossy(&name_buf).to_string()
                } else {
                    String::new()
                };

                infos.push(ModuleInfo {
                    name,
                    base_addr: info.lpBaseOfDll as usize,
                    size: info.SizeOfImage as usize,
                    path: String::new(), // 可通过 GetModuleFileNameEx 扩展
                });
            }
            Ok(infos)
        } else {
            Err(FridaError::Io(std::io::Error::last_os_error()).into())
        };

        CloseHandle(handle);
        result
    }
}

/// 解析进程内存区域（Windows 版本）
///
/// 这是 `parse_proc_maps` 的别名，保持与 Unix 接口一致。
pub fn parse_memory_regions_win(pid: u32) -> Result<Vec<MemoryRegion>> {
    parse_proc_maps(ProcessId(pid))
}

/// 将 C 风格字符数组转换为 Rust String
unsafe fn c_char_slice_to_string(buf: &[i8]) -> String {
    let bytes: Vec<u8> = buf.iter().map(|&b| b as u8).collect();
    let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..len]).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enum_processes() {
        let procs = enum_processes_win().unwrap();
        assert!(!procs.is_empty());
        // 当前进程一定在列表中
        let current = current_process_id();
        assert!(procs.iter().any(|p| p.pid == current));
    }

    #[test]
    fn test_enum_modules() {
        let current_pid = current_process_id().0;
        let mods = enum_modules_win(current_pid).unwrap();
        assert!(!mods.is_empty());
    }

    #[test]
    fn test_parse_memory_regions() {
        let current_pid = current_process_id().0;
        let regions = parse_memory_regions_win(current_pid).unwrap();
        assert!(!regions.is_empty());
    }
}
