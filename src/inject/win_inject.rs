//! Windows DLL 注入器
//!
//! 使用 `CreateRemoteThread` + `LoadLibraryA` 实现经典的 Windows DLL 注入。
//!
//! 注入流程：
//! 1. `OpenProcess` 获取目标进程句柄
//! 2. `VirtualAllocEx` 在目标进程分配内存
//! 3. `WriteProcessMemory` 写入 DLL 路径
//! 4. `GetProcAddress(GetModuleHandleA("kernel32"), "LoadLibraryA")` 获取函数地址
//! 5. `CreateRemoteThread` 在目标进程中调用 `LoadLibraryA`
//! 6. `WaitForSingleObject` 等待线程完成
//! 7. `VirtualFreeEx` 释放分配的内存
//! 8. `CloseHandle` 关闭句柄

use crate::common::error::FridaError;
use std::ffi::CString;
use std::ptr;
use winapi::shared::minwindef::{DWORD, FALSE, LPVOID};
use winapi::shared::ntdef::NULL;
use winapi::um::handleapi::CloseHandle;
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use winapi::um::memoryapi::{VirtualAllocEx, VirtualFreeEx, WriteProcessMemory};
use winapi::um::processthreadsapi::{CreateRemoteThread, OpenProcess};
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winnt::{HANDLE, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, PROCESS_ALL_ACCESS};

/// Windows 注入器
///
/// 封装 Windows 平台的 DLL 注入流程，持有目标进程 PID 和句柄。
pub struct WinInjector {
    /// 目标进程 ID
    target_pid: u32,
    /// 目标进程句柄（NULL 表示未打开）
    process_handle: HANDLE,
}

impl WinInjector {
    /// 创建新的 Windows 注入器
    ///
    /// # 参数
    /// - `pid`: 目标进程 ID
    pub fn new(pid: u32) -> Self {
        WinInjector {
            target_pid: pid,
            process_handle: NULL,
        }
    }

    /// 打开目标进程
    ///
    /// 使用 `OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid)` 获取目标进程句柄。
    /// 成功后 `process_handle` 字段将被设置为有效句柄。
    pub fn open_target(&mut self) -> crate::Result<()> {
        if self.process_handle != NULL {
            log::debug!("目标进程句柄已打开");
            return Ok(());
        }

        let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, FALSE, self.target_pid) };
        if handle.is_null() {
            let err = std::io::Error::last_os_error();
            return Err(FridaError::Inject {
                reason: format!("OpenProcess 失败: {}", err),
                pid: self.target_pid,
                source: Some(err),
            }
            .into());
        }

        log::debug!("成功打开进程 PID={}, 句柄={:p}", self.target_pid, handle);
        self.process_handle = handle;
        Ok(())
    }

    /// 使用 `CreateRemoteThread` + `LoadLibraryA` 注入 DLL
    ///
    /// 完整的注入流程：
    /// 1. 确保已打开目标进程
    /// 2. 在目标进程中分配内存（strlen(lib_path) + 1）
    /// 3. 将 DLL 路径写入目标进程内存
    /// 4. 获取 `LoadLibraryA` 地址
    /// 5. 创建远程线程调用 `LoadLibraryA`
    /// 6. 等待线程执行完毕
    /// 7. 释放分配的内存
    ///
    /// # 参数
    /// - `lib_path`: DLL 的完整路径
    pub fn inject_library(&self, lib_path: &str) -> crate::Result<()> {
        if self.process_handle.is_null() {
            return Err(FridaError::Inject {
                reason: "进程句柄未打开，请先调用 open_target()".to_string(),
                pid: self.target_pid,
                source: None,
            }
            .into());
        }

        // 验证路径非空
        if lib_path.is_empty() {
            return Err(FridaError::Inject {
                reason: "DLL 路径为空".to_string(),
                pid: self.target_pid,
                source: None,
            }
            .into());
        }

        let path_c = CString::new(lib_path).map_err(|e| FridaError::Inject {
            reason: format!("DLL 路径包含非法空字符: {}", e),
            pid: self.target_pid,
            source: None,
        })?;

        let path_bytes = path_c.as_bytes_with_nul();
        let path_len = path_bytes.len();

        log::info!("开始注入: PID={}, DLL={}", self.target_pid, lib_path);

        // 2. 在目标进程中分配内存
        let remote_addr = unsafe {
            VirtualAllocEx(
                self.process_handle,
                ptr::null_mut(),
                path_len,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };

        if remote_addr.is_null() {
            let err = std::io::Error::last_os_error();
            return Err(FridaError::Inject {
                reason: format!("VirtualAllocEx 失败: {}", err),
                pid: self.target_pid,
                source: Some(err),
            }
            .into());
        }

        log::debug!(
            "在目标进程中分配内存: addr={:p}, size={}",
            remote_addr,
            path_len
        );

        // 3. 写入 DLL 路径
        let mut written = 0usize;
        let write_ok = unsafe {
            WriteProcessMemory(
                self.process_handle,
                remote_addr,
                path_bytes.as_ptr() as LPVOID,
                path_len,
                &mut written,
            )
        };

        if write_ok == 0 {
            unsafe {
                VirtualFreeEx(self.process_handle, remote_addr, 0, MEM_RELEASE);
            }
            let err = std::io::Error::last_os_error();
            return Err(FridaError::MemoryWrite {
                address: remote_addr as usize,
                size: path_len,
                reason: format!("WriteProcessMemory 失败: {}", err),
            }
            .into());
        }

        if written != path_len {
            log::warn!("部分写入: 期望 {} 字节, 实际 {} 字节", path_len, written);
        }

        log::debug!("DLL 路径已写入远程内存");

        // 4. 获取 LoadLibraryA 地址
        let kernel32 = unsafe { GetModuleHandleA(b"kernel32.dll\0".as_ptr() as *const i8) };
        if kernel32.is_null() {
            unsafe {
                VirtualFreeEx(self.process_handle, remote_addr, 0, MEM_RELEASE);
            }
            let err = std::io::Error::last_os_error();
            return Err(FridaError::Inject {
                reason: format!("GetModuleHandleA(kernel32.dll) 失败: {}", err),
                pid: self.target_pid,
                source: Some(err),
            }
            .into());
        }

        let load_library = unsafe { GetProcAddress(kernel32, b"LoadLibraryA\0".as_ptr() as *const i8) };
        if load_library.is_null() {
            unsafe {
                VirtualFreeEx(self.process_handle, remote_addr, 0, MEM_RELEASE);
            }
            let err = std::io::Error::last_os_error();
            return Err(FridaError::Inject {
                reason: format!("GetProcAddress(LoadLibraryA) 失败: {}", err),
                pid: self.target_pid,
                source: Some(err),
            }
            .into());
        }

        log::debug!("LoadLibraryA 地址={:p}", load_library);

        // 5. 创建远程线程调用 LoadLibraryA
        let mut thread_id: DWORD = 0;
        let thread_handle = unsafe {
            CreateRemoteThread(
                self.process_handle,
                ptr::null_mut(),
                0,
                Some(std::mem::transmute(load_library)),
                remote_addr,
                0,
                &mut thread_id,
            )
        };

        if thread_handle.is_null() {
            unsafe {
                VirtualFreeEx(self.process_handle, remote_addr, 0, MEM_RELEASE);
            }
            let err = std::io::Error::last_os_error();
            return Err(FridaError::Inject {
                reason: format!("CreateRemoteThread 失败: {}", err),
                pid: self.target_pid,
                source: Some(err),
            }
            .into());
        }

        log::debug!("远程线程已创建, tid={}", thread_id);

        // 6. 等待线程完成
        let wait_result = unsafe { WaitForSingleObject(thread_handle, winapi::um::winbase::INFINITE) };
        if wait_result == winapi::um::winbase::WAIT_FAILED {
            let err = std::io::Error::last_os_error();
            log::warn!("WaitForSingleObject 失败: {}", err);
        } else {
            log::debug!("远程线程执行完毕");
        }

        // 关闭线程句柄
        unsafe {
            CloseHandle(thread_handle);
        }

        // 7. 释放分配的内存
        unsafe {
            VirtualFreeEx(self.process_handle, remote_addr, 0, MEM_RELEASE);
        }

        log::info!("DLL 注入完成: PID={}, DLL={}", self.target_pid, lib_path);
        Ok(())
    }

    /// 关闭进程句柄
    ///
    /// 释放 `OpenProcess` 获取的句柄。注入器仍可再次调用 `open_target()` 重新打开。
    pub fn close(&mut self) {
        if self.process_handle != NULL {
            unsafe {
                CloseHandle(self.process_handle);
            }
            log::debug!("已关闭进程 PID={} 的句柄", self.target_pid);
            self.process_handle = NULL;
        }
    }

    /// 获取目标 PID
    pub fn target_pid(&self) -> u32 {
        self.target_pid
    }

    /// 检查是否已打开目标进程
    pub fn is_open(&self) -> bool {
        self.process_handle != NULL
    }

    /// 获取原始进程句柄
    ///
    /// # 安全
    /// 调用者必须确保不关闭此句柄（避免 use-after-free），
    /// 或在调用 `close()` 后不再使用。
    pub fn raw_handle(&self) -> HANDLE {
        self.process_handle
    }
}

impl Drop for WinInjector {
    /// 析构时自动关闭句柄
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_win_injector_creation() {
        let injector = WinInjector::new(1234);
        assert_eq!(injector.target_pid(), 1234);
        assert!(!injector.is_open());
    }
}
