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
    /// 兼容旧调用：将固定字节模式包装为 `Option<u8>` 后委托给 [`Self::search_pattern`]。
    pub fn search_bytes(&self, pattern: &[u8]) -> crate::Result<Vec<u64>> {
        let pattern: Vec<Option<u8>> = pattern.iter().map(|b| Some(*b)).collect();
        self.search_pattern(&pattern, None, None)
    }

    /// 搜索内存中的字节模式（`None` 为通配符，匹配任意字节）
    ///
    /// 遍历所有已提交的、可读的内存区域，搜索给定的模式。
    ///
    /// # 参数
    /// - `pattern`: `Some(byte)` 表示固定字节，`None` 匹配任意字节
    ///
    /// # 返回值
    /// 返回所有匹配的地址列表
    pub fn search_pattern(&self, pattern: &[Option<u8>], max: Option<usize>, range: Option<(u64, u64)>) -> crate::Result<Vec<u64>> {
        if pattern.is_empty() {
            return Ok(Vec::new());
        }

        let regions = self.parse_regions()?;
        let mut matches = Vec::new();

        // 单次读取上限，避免一次性读取超大区域（块间重叠防止跨块漏检）
        const CHUNK_SIZE: usize = 16 * 1024 * 1024;
        let overlap = pattern.len() - 1;

        for region in regions {
            if !region.perms.read {
                continue;
            }

            // 计算实际扫描区间（按 range 裁剪区域）
            let r_start = region.start as u64;
            let r_end = region.end as u64;
            let (scan_start, scan_end) = match range {
                Some((sa, ea)) => (r_start.max(sa), r_end.min(ea)),
                None => (r_start, r_end),
            };
            if scan_start >= scan_end {
                continue;
            }

            let size = (scan_end - scan_start) as usize;
            if size < pattern.len() {
                continue;
            }

            let mut offset = 0usize;
            while offset < size {
                let want = (size - offset).min(CHUNK_SIZE);
                let data = self.dump_region_tolerant(scan_start + offset as u64, want);
                Self::find_wildcard_in_data(
                    &data,
                    pattern,
                    scan_start + offset as u64,
                    &mut matches,
                    max,
                );

                if offset + want >= size {
                    break;
                }
                offset += want - overlap;
            }
            if let Some(m) = max {
                if matches.len() >= m {
                    break;
                }
            }
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
            if read > 0 {
                // 部分读取：保留已读前缀数据
                buf.truncate(read);
                log::warn!("部分读取: 期望 {} 字节, 实际 {} 字节", size, read);
                return Ok(buf);
            }
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

    /// 宽容读取：整体读取失败或不足时，继续逐页补读剩余部分（跳过不可读页）
    fn dump_region_tolerant(&self, start: u64, size: usize) -> Vec<u8> {
        if size == 0 {
            return Vec::new();
        }

        // 先尝试整体读取（可能返回部分数据）
        let mut out = match self.dump_region(start, size) {
            Ok(data) => data,
            Err(_) => Vec::with_capacity(size),
        };

        // 已读满则直接返回
        if out.len() >= size {
            return out;
        }

        // 从已读位置继续逐页读取，不可读页以零填充，保证匹配地址与区域偏移对齐
        let mut offset = out.len();
        while offset < size {
            let page = (size - offset).min(4096);
            match self.dump_region(start + offset as u64, page) {
                Ok(d) => out.extend_from_slice(&d),
                Err(_) => out.extend(std::iter::repeat(0u8).take(page)),
            }
            offset += page;
        }
        out
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

    /// 在数据块中搜索模式（`None` 为通配符，匹配任意字节）
    fn find_wildcard_in_data(
        data: &[u8],
        pattern: &[Option<u8>],
        base_addr: u64,
        matches: &mut Vec<u64>,
        max: Option<usize>,
    ) {
        if data.len() < pattern.len() {
            return;
        }

        let mut idx = 0;
        while idx <= data.len() - pattern.len() {
            let mut found = true;
            for (j, byte) in pattern.iter().enumerate() {
                if let Some(expected) = byte {
                    if data[idx + j] != *expected {
                        found = false;
                        break;
                    }
                }
            }
            if found {
                matches.push(base_addr + idx as u64);
                if let Some(m) = max {
                    if matches.len() >= m {
                        return;
                    }
                }
                idx += pattern.len();
                continue;
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

#[cfg(test)]
mod tests {
    use super::*;

    /// 端到端：在自身进程堆上放置唯一标记，验证 search_bytes 可扫描到
    #[test]
    fn test_search_bytes_finds_marker_in_self() {
        let marker: Vec<u8> = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xC0, 0xDE, 0x13, 0x37, 0x99];
        std::hint::black_box(&marker);

        let pid = crate::common::util::current_process_id().0;
        let scanner = WinMemoryScanner::new(pid).expect("打开自身进程失败");
        let matches = scanner.search_bytes(&marker).expect("搜索失败");
        assert!(!matches.is_empty(), "应在自身进程堆中找到标记");
    }

    /// 端到端：在自身进程堆上放置唯一标记，验证通配符模式可扫描到
    #[test]
    fn test_search_pattern_wildcard_in_self() {
        let marker: Vec<u8> = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xC0, 0xDE, 0x13, 0x37, 0x99];
        std::hint::black_box(&marker);

        // 模式：前两个字节固定，中间 4 个字节任意，后两个字节固定
        let pattern: Vec<Option<u8>> = vec![
            Some(0xDE),
            Some(0xAD),
            None,
            None,
            None,
            None,
            Some(0x13),
            Some(0x37),
        ];

        let pid = crate::common::util::current_process_id().0;
        let scanner = WinMemoryScanner::new(pid).expect("打开自身进程失败");
        let matches = scanner.search_pattern(&pattern, None, None).expect("搜索失败");
        assert!(!matches.is_empty(), "应在自身进程堆中找到通配符模式");
    }

    /// 端到端：验证自身进程的内存区域枚举可用
    #[test]
    fn test_parse_regions_self() {
        let pid = crate::common::util::current_process_id().0;
        let scanner = WinMemoryScanner::new(pid).expect("打开自身进程失败");
        let regions = scanner.parse_regions().expect("解析区域失败");
        assert!(!regions.is_empty(), "自身进程应至少有一个内存区域");
        for r in &regions {
            assert!(r.start < r.end, "区域结束地址应大于起始地址");
        }
        assert!(regions.iter().any(|r| r.perms.read), "应存在可读区域");
    }

    /// 端到端：limit 上限生效，最多返回指定数量匹配
    #[test]
    fn test_search_pattern_limit_in_self() {
        let marker: Vec<u8> = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xC0, 0xDE, 0x13, 0x37, 0x99];
        std::hint::black_box(&marker);

        let pattern: Vec<Option<u8>> = vec![
            Some(0xDE),
            Some(0xAD),
            None,
            None,
            None,
            None,
            Some(0x13),
            Some(0x37),
        ];

        let pid = crate::common::util::current_process_id().0;
        let scanner = WinMemoryScanner::new(pid).expect("打开自身进程失败");
        let matches = scanner.search_pattern(&pattern, Some(1), None).expect("搜索失败");
        assert!(
            matches.len() <= 1,
            "limit=1 时最多返回 1 个匹配, 实际 {}",
            matches.len()
        );
    }

    /// 端到端：range 范围过滤只返回指定区间内的匹配
    #[test]
    fn test_search_pattern_range_in_self() {
        // 使用唯一 marker 模式，避免与并行测试的 marker 相互干扰
        let marker: Vec<u8> = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33];
        std::hint::black_box(&marker);

        let pattern: Vec<Option<u8>> = vec![
            Some(0xAA),
            Some(0xBB),
            None,
            None,
            None,
            None,
            Some(0x11),
            Some(0x22),
        ];

        let pid = crate::common::util::current_process_id().0;
        let scanner = WinMemoryScanner::new(pid).expect("打开自身进程失败");

        // 先全量搜索拿到标记地址
        let all = scanner.search_pattern(&pattern, None, None).expect("全量搜索失败");
        assert!(!all.is_empty(), "应能找到标记");
        let target = all[0];

        // 用紧贴标记的区间再搜，应能命中同一地址
        let ranged = scanner
            .search_pattern(&pattern, None, Some((target.saturating_sub(1), target + 16)))
            .expect("范围搜索失败");
        assert!(ranged.contains(&target), "范围搜索应包含标记地址 {:#x}", target);

        // 用完全不重叠的区间搜索，应为空
        let far = scanner
            .search_pattern(&pattern, None, Some((0x1, 0x1000)))
            .expect("范围搜索失败");
        assert!(
            !far.contains(&target),
            "不重叠区间不应包含标记地址 {:#x}",
            target
        );
    }
}
