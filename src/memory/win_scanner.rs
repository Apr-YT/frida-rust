//! Windows 内存扫描器
//!
//! 使用 `VirtualQueryEx` 遍历目标进程的内存区域，
//! 通过 `ReadProcessMemory` 读取数据并进行字节模式搜索。

use crate::common::error::FridaError;
use crate::common::types::{MemoryPerms, MemoryRegion};
use std::mem::zeroed;

use winapi::shared::minwindef::FALSE;
use winapi::shared::ntdef::NULL;
use winapi::um::handleapi::CloseHandle;
use winapi::um::memoryapi::{ReadProcessMemory, VirtualQueryEx};
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::winnt::{
    HANDLE, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_EXECUTE, PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_READONLY, PAGE_READWRITE,
    PAGE_WRITECOPY, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};

/// Windows 内存扫描器
///
/// 封装 `VirtualQueryEx` 和 `ReadProcessMemory`，在目标进程内存空间中搜索字节模式。
pub struct WinMemoryScanner {
    /// 目标进程 ID
    pid: u32,
    /// 目标进程句柄
    handle: HANDLE,
}

impl WinMemoryScanner {
    /// 创建新的内存扫描器
    ///
    /// # 参数
    /// - `pid`: 目标进程 ID
    pub fn new(pid: u32) -> crate::Result<Self> {
        let handle =
            unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid) };
        if handle.is_null() {
            let err = std::io::Error::last_os_error();
            return Err(FridaError::Inject {
                reason: format!("OpenProcess 失败: {}", err),
                pid,
                source: Some(err),
            }
            .into());
        }

        log::debug!("WinMemoryScanner 已打开进程 PID={}", pid);
        Ok(WinMemoryScanner { pid, handle })
    }

    /// 搜索字节模式
    ///
    /// 遍历所有已提交的、可读的内存区域，搜索给定的字节模式。
    ///
    /// # 参数
    /// - `pattern`: 要搜索的字节模式
    ///
    /// # 返回值
    /// 返回所有匹配的地址列表
    pub fn search_bytes(&self, pattern: &[u8]) -> crate::Result<Vec<u64>> {
        if pattern.is_empty() {
            return Ok(Vec::new());
        }

        let regions = self.parse_regions()?;
        let mut matches = Vec::new();

        for region in regions {
            if !region.perms.read {
                continue;
            }

            let size = region.size();
            if size < pattern.len() {
                continue;
            }

            // 限制单次读取大小，避免读取过多内存
            let read_size = size.min(16 * 1024 * 1024);
            let data = match self.dump_region(region.start as u64, read_size) {
                Ok(d) => d,
                Err(_) => continue,
            };

            Self::find_pattern_in_data(&data, pattern, region.start as u64, &mut matches);
        }

        log::debug!("字节模式搜索完成: {} 处匹配", matches.len());
        Ok(matches)
    }

    /// 转储指定内存区域的数据
    ///
    /// # 参数
    /// - `start`: 起始地址
    /// - `size`: 读取大小（字节）
    ///
    /// # 返回值
    /// 返回读取到的原始字节数据
    pub fn dump_region(&self, start: u64, size: usize) -> crate::Result<Vec<u8>> {
        if size == 0 {
            return Ok(Vec::new());
        }

        let mut buf = vec![0u8; size];
        let mut read = 0usize;
        let ok = unsafe {
            ReadProcessMemory(
                self.handle,
                start as *mut winapi::ctypes::c_void,
                buf.as_mut_ptr() as *mut winapi::ctypes::c_void,
                size,
                &mut read,
            )
        };

        if ok == 0 {
            let err = std::io::Error::last_os_error();
            return Err(FridaError::MemoryRead {
                address: start as usize,
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

    /// 解析目标进程的所有内存区域
    ///
    /// 使用 `VirtualQueryEx` 从地址 0 开始遍历整个地址空间，
    /// 收集所有已提交（`MEM_COMMIT`）的内存区域。
    ///
    /// # 返回值
    /// 返回所有内存区域的列表
    pub fn parse_regions(&self) -> crate::Result<Vec<MemoryRegion>> {
        let mut regions = Vec::new();
        let mut addr: usize = 0;

        loop {
            let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { zeroed() };
            let ret = unsafe {
                VirtualQueryEx(
                    self.handle,
                    addr as *mut winapi::ctypes::c_void,
                    &mut mbi,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };

            if ret == 0 {
                break;
            }

            if mbi.State == MEM_COMMIT {
                let perms = Self::protect_to_perms(mbi.Protect);
                regions.push(MemoryRegion {
                    start: mbi.BaseAddress as usize,
                    end: (mbi.BaseAddress as usize) + mbi.RegionSize,
                    perms,
                    name: String::new(),
                });
            }

            // 移动到下一个区域
            let next = (mbi.BaseAddress as usize) + mbi.RegionSize;
            if next <= addr {
                break; // 防止溢出或无限循环
            }
            addr = next;
        }

        log::debug!("解析到 {} 个内存区域", regions.len());
        Ok(regions)
    }

    /// 将 Windows 内存保护标志转换为 `MemoryPerms`
    fn protect_to_perms(protect: u32) -> MemoryPerms {
        MemoryPerms {
            read: protect
                & (PAGE_READONLY
                    | PAGE_READWRITE
                    | PAGE_EXECUTE_READ
                    | PAGE_EXECUTE_READWRITE
                    | PAGE_EXECUTE_WRITECOPY
                    | PAGE_WRITECOPY)
                != 0,
            write: protect
                & (PAGE_READWRITE
                    | PAGE_EXECUTE_READWRITE
                    | PAGE_EXECUTE_WRITECOPY
                    | PAGE_WRITECOPY)
                != 0,
            execute: protect
                & (PAGE_EXECUTE
                    | PAGE_EXECUTE_READ
                    | PAGE_EXECUTE_READWRITE
                    | PAGE_EXECUTE_WRITECOPY)
                != 0,
            private: true,
        }
    }

    /// 在数据块中搜索字节模式
    ///
    /// 使用逐步扫描算法，在给定数据块中查找所有匹配位置。
    fn find_pattern_in_data(
        data: &[u8],
        pattern: &[u8],
        base_addr: u64,
        matches: &mut Vec<u64>,
    ) {
        if data.len() < pattern.len() {
            return;
        }

        let mut idx = 0;
        while idx <= data.len() - pattern.len() {
            if data[idx] == pattern[0] {
                let mut found = true;
                for j in 1..pattern.len() {
                    if data[idx + j] != pattern[j] {
                        found = false;
                        break;
                    }
                }
                if found {
                    matches.push(base_addr + idx as u64);
                    idx += pattern.len();
                    continue;
                }
            }
            idx += 1;
        }
    }
}

impl Drop for WinMemoryScanner {
    /// 析构时自动关闭进程句柄
    fn drop(&mut self) {
        if self.handle != NULL {
            unsafe {
                CloseHandle(self.handle);
            }
            log::debug!("WinMemoryScanner 已关闭进程句柄 PID={}", self.pid);
        }
    }
}
