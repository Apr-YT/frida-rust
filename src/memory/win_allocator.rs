//! Windows 远程内存分配器
//!
//! 使用 `VirtualAllocEx` / `VirtualFreeEx` / `VirtualProtectEx` /
//! `WriteProcessMemory` / `ReadProcessMemory` 在目标进程中分配、读写和保护内存。

use crate::common::error::FridaError;
use winapi::shared::minwindef::{FALSE, LPVOID};
use winapi::shared::ntdef::NULL;
use winapi::um::handleapi::CloseHandle;
use winapi::um::memoryapi::{
    ReadProcessMemory, VirtualAllocEx, VirtualFreeEx, VirtualProtectEx, WriteProcessMemory,
};
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::winnt::{
    HANDLE, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE,
    PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
};

/// Windows 远程内存分配器
///
/// 封装 `VirtualAllocEx` 系列 API，在目标进程中分配和管理内存。
pub struct WinRemoteAllocator {
    /// 目标进程 ID
    pid: u32,
    /// 目标进程句柄
    handle: HANDLE,
}

impl WinRemoteAllocator {
    /// 创建远程内存分配器并打开目标进程
    ///
    /// # 参数
    /// - `pid`: 目标进程 ID
    pub fn new(pid: u32) -> crate::Result<Self> {
        let handle = unsafe {
            OpenProcess(
                PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
                FALSE,
                pid,
            )
        };
        if handle.is_null() {
            let err = std::io::Error::last_os_error();
            return Err(FridaError::Inject {
                reason: format!("OpenProcess 失败: {}", err),
                pid,
                source: Some(err),
            }
            .into());
        }

        log::debug!("WinRemoteAllocator 已打开进程 PID={}", pid);
        Ok(WinRemoteAllocator { pid, handle })
    }

    /// 在目标进程中分配内存
    ///
    /// # 参数
    /// - `size`: 分配大小（字节）
    /// - `executable`: 是否需要可执行权限（`PAGE_EXECUTE_READWRITE` 或 `PAGE_READWRITE`）
    ///
    /// # 返回值
    /// 返回分配到的远程内存地址
    pub fn alloc(&self, size: usize, executable: bool) -> crate::Result<u64> {
        let prot = if executable {
            PAGE_EXECUTE_READWRITE
        } else {
            PAGE_READWRITE
        };

        let addr = unsafe {
            VirtualAllocEx(
                self.handle,
                NULL as LPVOID,
                size,
                MEM_COMMIT | MEM_RESERVE,
                prot,
            )
        };

        if addr.is_null() {
            let err = std::io::Error::last_os_error();
            return Err(FridaError::MemoryWrite {
                address: 0,
                size,
                reason: format!("VirtualAllocEx 失败: {}", err),
            }
            .into());
        }

        log::debug!(
            "VirtualAllocEx 成功: PID={}, addr={:p}, size={}, exec={}",
            self.pid,
            addr,
            size,
            executable
        );
        Ok(addr as u64)
    }

    /// 释放已分配的远程内存
    ///
    /// # 参数
    /// - `addr`: 之前 `alloc` 返回的内存地址
    pub fn free(&self, addr: u64) -> crate::Result<()> {
        let ok = unsafe { VirtualFreeEx(self.handle, addr as LPVOID, 0, MEM_RELEASE) };
        if ok == 0 {
            let err = std::io::Error::last_os_error();
            return Err(FridaError::MemoryWrite {
                address: addr as usize,
                size: 0,
                reason: format!("VirtualFreeEx 失败: {}", err),
            }
            .into());
        }

        log::debug!("VirtualFreeEx 成功: PID={}, addr={:#x}", self.pid, addr);
        Ok(())
    }

    /// 向远程内存写入数据
    ///
    /// # 参数
    /// - `addr`: 目标地址
    /// - `data`: 要写入的数据
    pub fn write(&self, addr: u64, data: &[u8]) -> crate::Result<()> {
        if data.is_empty() {
            return Ok(());
        }

        let mut written = 0usize;
        let ok = unsafe {
            WriteProcessMemory(
                self.handle,
                addr as LPVOID,
                data.as_ptr() as LPVOID,
                data.len(),
                &mut written,
            )
        };

        if ok == 0 {
            let err = std::io::Error::last_os_error();
            return Err(FridaError::MemoryWrite {
                address: addr as usize,
                size: data.len(),
                reason: format!("WriteProcessMemory 失败: {}", err),
            }
            .into());
        }

        if written != data.len() {
            log::warn!(
                "部分写入: 期望 {} 字节, 实际 {} 字节",
                data.len(),
                written
            );
        }

        Ok(())
    }

    /// 从远程内存读取数据
    ///
    /// # 参数
    /// - `addr`: 目标地址
    /// - `size`: 读取大小（字节）
    ///
    /// # 返回值
    /// 返回读取到的数据
    pub fn read(&self, addr: u64, size: usize) -> crate::Result<Vec<u8>> {
        if size == 0 {
            return Ok(Vec::new());
        }

        let mut buf = vec![0u8; size];
        let mut read = 0usize;
        let ok = unsafe {
            ReadProcessMemory(
                self.handle,
                addr as LPVOID,
                buf.as_mut_ptr() as LPVOID,
                size,
                &mut read,
            )
        };

        if ok == 0 {
            let err = std::io::Error::last_os_error();
            return Err(FridaError::MemoryRead {
                address: addr as usize,
                size,
                reason: format!("ReadProcessMemory 失败: {}", err),
            }
            .into());
        }

        if read != size {
            buf.truncate(read);
            log::warn!("部分读取: 期望 {} 字节, 实际 {} 字节", size, read);
        }

        Ok(buf)
    }

    /// 修改远程内存保护属性
    ///
    /// # 参数
    /// - `addr`: 内存地址
    /// - `size`: 大小
    /// - `exec`: 是否需要可执行权限
    pub fn protect(&self, addr: u64, size: usize, exec: bool) -> crate::Result<()> {
        let new_prot = if exec {
            PAGE_EXECUTE_READWRITE
        } else {
            PAGE_READWRITE
        };

        let mut old_prot = 0u32;
        let ok = unsafe {
            VirtualProtectEx(self.handle, addr as LPVOID, size, new_prot, &mut old_prot)
        };

        if ok == 0 {
            let err = std::io::Error::last_os_error();
            return Err(FridaError::MemoryProtect {
                address: addr as usize,
                reason: format!("VirtualProtectEx 失败: {}", err),
            }
            .into());
        }

        log::debug!(
            "VirtualProtectEx 成功: addr={:#x}, size={}, exec={}, old_prot={}",
            addr,
            size,
            exec,
            old_prot
        );
        Ok(())
    }

    /// 获取原始进程句柄
    ///
    /// # 安全
    /// 调用者必须确保不关闭此句柄。
    pub fn raw_handle(&self) -> HANDLE {
        self.handle
    }
}

impl Drop for WinRemoteAllocator {
    /// 析构时自动关闭进程句柄
    fn drop(&mut self) {
        if self.handle != NULL {
            unsafe {
                CloseHandle(self.handle);
            }
            log::debug!("WinRemoteAllocator 已关闭进程句柄 PID={}", self.pid);
        }
    }
}
