//! 工具函数集
//!
//! 提供内存对齐、进程信息获取、文件读取等通用工具函数。

#[cfg(unix)]
use crate::common::constants::DEFAULT_PAGE_SIZE;
use crate::common::types::ProcessId;
use crate::FridaError;

/// 将地址对齐到页面边界（向下取整）
///
/// # 参数
/// - `addr`: 待对齐的地址
///
/// # 返回值
/// 对齐到页面起始地址后的值
#[inline]
pub fn align_to_page(addr: usize) -> usize {
    addr & !(page_size() - 1)
}

/// 将地址对齐到页面边界（向上取整）
///
/// # 参数
/// - `addr`: 待对齐的地址
///
/// # 返回值
/// 对齐到下一个页面起始地址后的值
#[inline]
pub fn align_to_page_up(addr: usize) -> usize {
    let ps = page_size();
    (addr + ps - 1) & !(ps - 1)
}

/// 获取系统内存页大小
///
/// 通过 `sysconf(_SC_PAGESIZE)` 获取实际值，如果失败则返回默认值 4096。
#[cfg(unix)]
#[inline]
pub fn page_size() -> usize {
    // SAFETY: sysconf 只读取系统信息，不会产生副作用
    unsafe {
        let ps = libc::sysconf(libc::_SC_PAGESIZE);
        if ps > 0 {
            ps as usize
        } else {
            DEFAULT_PAGE_SIZE
        }
    }
}

/// 获取系统内存页大小（Windows 版本）
///
/// 通过 `GetSystemInfo` 获取实际值。
#[cfg(windows)]
#[inline]
pub fn page_size() -> usize {
    unsafe {
        let mut si = std::mem::zeroed::<winapi::um::sysinfoapi::SYSTEM_INFO>();
        winapi::um::sysinfoapi::GetSystemInfo(&mut si);
        si.dwPageSize as usize
    }
}

/// 获取当前进程 ID
///
/// 通过 `getpid()` 系统调用获取。
#[cfg(unix)]
#[inline]
pub fn current_process_id() -> ProcessId {
    // SAFETY: getpid 是安全的系统调用
    ProcessId(unsafe { libc::getpid() as u32 })
}

/// 获取当前进程 ID（Windows 版本）
#[cfg(windows)]
#[inline]
pub fn current_process_id() -> ProcessId {
    ProcessId(unsafe { winapi::um::processthreadsapi::GetCurrentProcessId() })
}

/// 获取当前线程 ID
///
/// 通过 `gettid()` 系统调用获取。
#[cfg(unix)]
#[inline]
pub fn current_thread_id() -> crate::common::types::ThreadId {
    // SAFETY: gettid 是安全的系统调用
    crate::common::types::ThreadId(unsafe { libc::gettid() as u32 })
}

/// 获取当前线程 ID（Windows 版本）
#[cfg(windows)]
#[inline]
pub fn current_thread_id() -> crate::common::types::ThreadId {
    crate::common::types::ThreadId(unsafe { winapi::um::processthreadsapi::GetCurrentThreadId() })
}

/// 将文件内容读取为字节向量
///
/// # 参数
/// - `path`: 文件路径
///
/// # 错误
/// 文件不存在或读取失败时返回错误
pub fn read_file_bytes(path: &str) -> crate::Result<Vec<u8>> {
    use std::fs;
    let data = fs::read(path)?;
    Ok(data)
}

/// 将字节向量写入文件
///
/// # 参数
/// - `path`: 目标文件路径
/// - `data`: 要写入的数据
pub fn write_file_bytes(path: &str, data: &[u8]) -> crate::Result<()> {
    use std::fs;
    fs::write(path, data)?;
    Ok(())
}

/// 安全地向目标进程内存写入数据
///
/// 通过 `process_vm_writev` 系统调用实现跨进程内存写入，
/// 比传统的 ptrace POKEDATA 方式效率更高。
///
/// # 参数
/// - `pid`: 目标进程 ID
/// - `addr`: 目标虚拟地址
/// - `data`: 要写入的数据
///
/// # 错误
/// 写入失败时返回详细的错误信息
///
/// # 安全性
/// 调用者需确保有足够的权限，且目标地址在合法的内存区域内。
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn safe_write_bytes(pid: ProcessId, addr: usize, data: &[u8]) -> crate::Result<()> {

    let local_iovec = libc::iovec {
        iov_base: data.as_ptr() as *mut libc::c_void,
        iov_len: data.len(),
    };

    let remote_iovec = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: data.len(),
    };

    // SAFETY: process_vm_writev 需要调用者确保目标地址合法
    let ret = unsafe {
        crate::common::syscall_wrapper::process_vm_writev(
            pid.0 as libc::pid_t,
            &local_iovec,
            1,  // local_count
            &remote_iovec,
            1,  // remote_count
            0,  // flags (reserved, 必须为 0)
        )
    };

    if ret < 0 {
        return Err(FridaError::MemoryWrite {
            address: addr,
            size: data.len(),
            reason: format!("process_vm_writev 失败: {}", std::io::Error::last_os_error()),
        }
        .into());
    }

    if ret as usize != data.len() {
        return Err(FridaError::MemoryWrite {
            address: addr,
            size: data.len(),
            reason: format!("部分写入: 写入 {} 字节，预期 {} 字节", ret, data.len()),
        }
        .into());
    }

    log::debug!(
        "成功写入 {} 字节到 PID {} 地址 {:#x}",
        data.len(),
        pid.0,
        addr
    );
    Ok(())
}

/// 安全地向目标进程内存写入数据（Windows 版本）
#[cfg(windows)]
pub fn safe_write_bytes(pid: ProcessId, addr: usize, data: &[u8]) -> crate::Result<()> {
    unsafe {
        let handle = winapi::um::processthreadsapi::OpenProcess(
            winapi::um::winnt::PROCESS_VM_WRITE | winapi::um::winnt::PROCESS_VM_OPERATION,
            0,
            pid.0,
        );
        if handle.is_null() {
            return Err(FridaError::MemoryWrite {
                address: addr,
                size: data.len(),
                reason: format!("OpenProcess 失败: {}", std::io::Error::last_os_error()),
            }
            .into());
        }

        let mut written: usize = 0;
        let ok = winapi::um::memoryapi::WriteProcessMemory(
            handle,
            addr as *mut winapi::ctypes::c_void,
            data.as_ptr() as *const winapi::ctypes::c_void,
            data.len(),
            &mut written,
        );

        winapi::um::handleapi::CloseHandle(handle);

        if ok == 0 {
            return Err(FridaError::MemoryWrite {
                address: addr,
                size: data.len(),
                reason: format!("WriteProcessMemory 失败: {}", std::io::Error::last_os_error()),
            }
            .into());
        }

        if written != data.len() {
            return Err(FridaError::MemoryWrite {
                address: addr,
                size: data.len(),
                reason: format!("部分写入: 写入 {} 字节，预期 {} 字节", written, data.len()),
            }
            .into());
        }

        log::debug!(
            "成功写入 {} 字节到 PID {} 地址 {:#x}",
            data.len(),
            pid.0,
            addr
        );
        Ok(())
    }
}

/// 安全地从目标进程内存读取数据
///
/// 通过 `process_vm_readv` 系统调用实现跨进程内存读取。
///
/// # 参数
/// - `pid`: 目标进程 ID
/// - `addr`: 目标虚拟地址
/// - `size`: 要读取的字节数
///
/// # 错误
/// 读取失败时返回详细的错误信息
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn safe_read_bytes(pid: ProcessId, addr: usize, size: usize) -> crate::Result<Vec<u8>> {
    let mut buf = vec![0u8; size];

    let local_iovec = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: size,
    };

    let remote_iovec = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: size,
    };

    // SAFETY: process_vm_readv 需要调用者确保目标地址合法
    let ret = unsafe {
        crate::common::syscall_wrapper::process_vm_readv(
            pid.0 as libc::pid_t,
            &local_iovec,
            1,  // local_count
            &remote_iovec,
            1,  // remote_count
            0,  // flags (reserved)
        )
    };

    if ret < 0 {
        return Err(FridaError::MemoryRead {
            address: addr,
            size,
            reason: format!("process_vm_readv 失败: {}", std::io::Error::last_os_error()),
        }
        .into());
    }

    if ret as usize != size {
        buf.truncate(ret as usize);
        log::warn!(
            "部分读取: 从 PID {} 地址 {:#x} 读取 {} 字节，预期 {} 字节",
            pid.0,
            addr,
            ret,
            size
        );
    }

    Ok(buf)
}

/// 安全地从目标进程内存读取数据（Windows 版本）
#[cfg(windows)]
pub fn safe_read_bytes(pid: ProcessId, addr: usize, size: usize) -> crate::Result<Vec<u8>> {
    let mut buf = vec![0u8; size];

    unsafe {
        let handle = winapi::um::processthreadsapi::OpenProcess(
            winapi::um::winnt::PROCESS_VM_READ,
            0,
            pid.0,
        );
        if handle.is_null() {
            return Err(FridaError::MemoryRead {
                address: addr,
                size,
                reason: format!("OpenProcess 失败: {}", std::io::Error::last_os_error()),
            }
            .into());
        }

        let mut read: usize = 0;
        let ok = winapi::um::memoryapi::ReadProcessMemory(
            handle,
            addr as *const winapi::ctypes::c_void,
            buf.as_mut_ptr() as *mut winapi::ctypes::c_void,
            size,
            &mut read,
        );

        winapi::um::handleapi::CloseHandle(handle);

        if ok == 0 {
            return Err(FridaError::MemoryRead {
                address: addr,
                size,
                reason: format!("ReadProcessMemory 失败: {}", std::io::Error::last_os_error()),
            }
            .into());
        }

        if read != size {
            buf.truncate(read);
            log::warn!(
                "部分读取: 从 PID {} 地址 {:#x} 读取 {} 字节，预期 {} 字节",
                pid.0,
                addr,
                read,
                size
            );
        }

        Ok(buf)
    }
}

/// 检查指定进程是否存活
///
/// 通过检查 /proc/[pid] 目录是否存在来判断进程是否存活，
/// 这种方式在 Android 上不需要特殊权限。
///
/// # 参数
/// - `pid`: 目标进程 ID
#[cfg(unix)]
pub fn is_process_alive(pid: ProcessId) -> bool {
    let proc_path = format!("/proc/{}", pid.0);
    std::path::Path::new(&proc_path).exists()
}

/// 检查指定进程是否存活（Windows 版本）
#[cfg(windows)]
pub fn is_process_alive(pid: ProcessId) -> bool {
    unsafe {
        let handle = winapi::um::processthreadsapi::OpenProcess(
            winapi::um::winnt::PROCESS_QUERY_INFORMATION,
            0,
            pid.0,
        );
        if handle.is_null() {
            return false;
        }
        let mut code: winapi::shared::minwindef::DWORD = 0;
        let ok = winapi::um::processthreadsapi::GetExitCodeProcess(handle, &mut code);
        winapi::um::handleapi::CloseHandle(handle);
        ok != 0 && code == winapi::um::minwinbase::STILL_ACTIVE
    }
}

/// 解析 /proc/[pid]/maps 获取指定进程的所有内存映射区域
///
/// # 参数
/// - `pid`: 目标进程 ID
///
/// # 错误
/// 无法读取或解析 maps 文件时返回错误
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn parse_proc_maps(pid: ProcessId) -> crate::Result<Vec<crate::common::types::MemoryRegion>> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    let maps_path = if pid.0 == 0 {
        "/proc/self/maps".to_string()
    } else {
        format!("/proc/{}/maps", pid.0)
    };

    let file = File::open(&maps_path)?;
    let reader = BufReader::new(file);
    let mut regions = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // 解析格式: address           perms offset  dev   inode   pathname
        // 例如: 7f1234567000-7f1234568000 r-xp 00000000 08:01 12345  /path/to/lib.so
        let parts: Vec<&str> = line.splitn(6, |c: char| c == ' ' || c == '\t').collect();
        if parts.len() < 5 {
            continue;
        }

        // 解析地址范围
        let addr_range: Vec<&str> = parts[0].split('-').collect();
        if addr_range.len() != 2 {
            continue;
        }

        let start = usize::from_str_radix(addr_range[0], 16).unwrap_or(0);
        let end = usize::from_str_radix(addr_range[1], 16).unwrap_or(0);

        // 解析权限
        let perms_str = if parts.len() > 1 { parts[1] } else { "---p" };
        let perms = crate::common::types::MemoryPerms::from_str_perms(perms_str);

        // 解析路径名
        let name = if parts.len() >= 6 {
            parts[5].to_string()
        } else {
            String::new()
        };

        regions.push(crate::common::types::MemoryRegion {
            start,
            end,
            perms,
            name,
        });
    }

    log::debug!("从 {} 解析出 {} 个内存区域", maps_path, regions.len());
    Ok(regions)
}

/// 解析进程内存区域（Windows 版本）
///
/// 使用 `VirtualQueryEx` 枚举指定进程的内存映射区域。
#[cfg(windows)]
pub fn parse_proc_maps(pid: ProcessId) -> crate::Result<Vec<crate::common::types::MemoryRegion>> {
    use crate::common::types::MemoryPerms;
    use winapi::shared::minwindef::DWORD;
    use winapi::um::memoryapi::VirtualQueryEx;
    use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcess};
    use winapi::um::winnt::{
        MEMORY_BASIC_INFORMATION, MEM_IMAGE, MEM_PRIVATE, PAGE_EXECUTE, PAGE_EXECUTE_READ,
        PAGE_EXECUTE_READWRITE, PAGE_READONLY, PAGE_READWRITE, PROCESS_QUERY_INFORMATION,
        PROCESS_VM_READ,
    };

    unsafe {
        let process = if pid.0 == 0 {
            GetCurrentProcess()
        } else {
            let h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid.0);
            if h.is_null() {
                return Err(FridaError::Io(std::io::Error::last_os_error()).into());
            }
            h
        };

        let close_handle = pid.0 != 0;
        let mut regions = Vec::new();
        let mut addr: usize = 0;

        loop {
            let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
            let ret = VirtualQueryEx(
                process,
                addr as *const winapi::ctypes::c_void,
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );

            if ret == 0 {
                break;
            }

            let base = mbi.BaseAddress as usize;
            let size = mbi.RegionSize;
            let end = base.saturating_add(size);

            let perms = match mbi.Protect as DWORD {
                PAGE_EXECUTE_READWRITE => MemoryPerms::rwx(),
                PAGE_EXECUTE_READ => MemoryPerms::read_execute(),
                PAGE_READWRITE => MemoryPerms::readwrite(),
                PAGE_READONLY => MemoryPerms::readonly(),
                _ => MemoryPerms {
                    read: matches!(
                        mbi.Protect as DWORD,
                        PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE
                    ),
                    write: matches!(
                        mbi.Protect as DWORD,
                        PAGE_READWRITE | PAGE_EXECUTE_READWRITE
                    ),
                    execute: matches!(
                        mbi.Protect as DWORD,
                        PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE
                    ),
                    private: mbi.Type == MEM_PRIVATE,
                },
            };

            let name = if mbi.Type == MEM_IMAGE {
                get_module_name_for_address(process, base).unwrap_or_default()
            } else {
                String::new()
            };

            regions.push(crate::common::types::MemoryRegion {
                start: base,
                end,
                perms,
                name,
            });

            addr = end;
        }

        if close_handle {
            winapi::um::handleapi::CloseHandle(process);
        }

        log::debug!("从 Windows 内存查询解析出 {} 个内存区域", regions.len());
        Ok(regions)
    }
}

#[cfg(windows)]
unsafe fn get_module_name_for_address(
    process: winapi::shared::ntdef::HANDLE,
    addr: usize,
) -> Option<String> {
    use winapi::shared::minwindef::{DWORD, HMODULE};
    use winapi::um::psapi::{EnumProcessModules, GetModuleBaseNameA, GetModuleInformation};

    let mut needed: DWORD = 0;
    if EnumProcessModules(
        process,
        std::ptr::null_mut(),
        0,
        &mut needed,
    ) == 0
    {
        return None;
    }

    let count = needed as usize / std::mem::size_of::<HMODULE>();
    let mut modules: Vec<HMODULE> = vec![std::ptr::null_mut(); count];

    if EnumProcessModules(process, modules.as_mut_ptr(), needed, &mut needed) == 0 {
        return None;
    }

    for &module in &modules {
        let mut info: winapi::um::psapi::MODULEINFO = std::mem::zeroed();
        if GetModuleInformation(
            process,
            module,
            &mut info,
            std::mem::size_of::<winapi::um::psapi::MODULEINFO>() as u32,
        ) == 0
        {
            continue;
        }

        let base = info.lpBaseOfDll as usize;
        let size = info.SizeOfImage as usize;
        if addr >= base && addr < base + size {
            let mut buf = vec![0u8; 512];
            let len = GetModuleBaseNameA(
                process,
                module,
                buf.as_mut_ptr() as *mut i8,
                buf.len() as u32,
            );
            if len > 0 {
                buf.truncate(len as usize);
                return Some(String::from_utf8_lossy(&buf).to_string());
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_align_to_page() {
        let ps = page_size();
        assert_eq!(align_to_page(0), 0);
        assert_eq!(align_to_page(ps - 1), 0);
        assert_eq!(align_to_page(ps), ps);
        assert_eq!(align_to_page(ps + 1), ps);
        assert_eq!(align_to_page(ps * 10 + 123), ps * 10);
    }

    #[test]
    fn test_align_to_page_up() {
        let ps = page_size();
        assert_eq!(align_to_page_up(0), 0);
        assert_eq!(align_to_page_up(1), ps);
        assert_eq!(align_to_page_up(ps), ps);
        assert_eq!(align_to_page_up(ps + 1), ps * 2);
    }

    #[test]
    fn test_process_id() {
        let pid = current_process_id();
        assert!(pid.0 > 0);
    }
}
