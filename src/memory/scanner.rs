//! 内存扫描器 - 在目标进程内存中搜索特定模式
//!
//! 通过解析 `/proc/[pid]/maps` 获取内存布局，使用 `process_vm_readv`
//! 跨进程读取内存数据，支持字节模式搜索和字符串搜索。

use crate::common::types::{MemoryRegion, ProcessId};
use crate::common::util::{parse_proc_maps, safe_read_bytes};
use crate::Result;

// ======================== 内存扫描器 ========================

/// 内存扫描器
///
/// 在目标进程的内存空间中搜索特定的字节模式或字符串。
pub struct MemoryScanner {
    /// 目标进程 ID
    pid: ProcessId,
    /// 内存区域缓存
    regions: Vec<MemoryRegion>,
    /// 是否已加载内存布局
    regions_loaded: bool,
}

impl MemoryScanner {
    /// 创建新的内存扫描器
    ///
    /// # 参数
    /// - `pid`: 目标进程 ID（0 表示当前进程）
    pub fn new(pid: ProcessId) -> Self {
        MemoryScanner {
            pid,
            regions: Vec::new(),
            regions_loaded: false,
        }
    }

    /// 强制重新加载内存布局
    pub fn refresh_maps(&mut self) -> Result<()> {
        self.regions = parse_proc_maps(self.pid)?;
        self.regions_loaded = true;
        log::debug!(
            "PID {} 的内存布局已刷新: {} 个区域",
            self.pid.0,
            self.regions.len()
        );
        Ok(())
    }

    /// 获取内存布局（延迟加载）
    fn ensure_regions(&mut self) -> Result<()> {
        if !self.regions_loaded {
            self.refresh_maps()?;
        }
        Ok(())
    }

    /// 获取所有可读的内存区域
    fn readable_regions(&mut self) -> Result<Vec<MemoryRegion>> {
        self.ensure_regions()?;
        Ok(self
            .regions
            .iter()
            .filter(|r| r.perms.read)
            .cloned()
            .collect())
    }

    /// 在目标进程中搜索字节模式
    ///
    /// # 参数
    /// - `pattern`: 要搜索的字节模式
    /// - `search_regions`: 可选的内存区域列表。如果为 None，则搜索所有可读区域
    ///
    /// # 返回值
    /// 返回所有匹配的地址列表
    pub fn search_bytes(
        &mut self,
        pattern: &[u8],
        search_regions: Option<&[MemoryRegion]>,
    ) -> Result<Vec<u64>> {
        if pattern.is_empty() {
            return Ok(Vec::new());
        }

        log::debug!(
            "在 PID {} 中搜索字节模式: {} 字节",
            self.pid.0,
            pattern.len()
        );

        let regions = match search_regions {
            Some(r) => r.to_vec(),
            None => self.readable_regions()?,
        };

        let mut matches = Vec::new();

        for region in &regions {
            if region.size() < pattern.len() {
                continue;
            }

            // 限制单次读取大小，避免读取过多匿名映射
            let read_size = region.size().min(16 * 1024 * 1024); // 最大 16MB
            let data = match self.read_region(region.start, read_size) {
                Ok(d) => d,
                Err(_) => continue, // 跳过无法读取的区域
            };

            // 使用简单的字节模式匹配（Boyer-Moore 的简化版）
            self.find_pattern_in_data(&data, pattern, region.start as u64, &mut matches);
        }

        log::debug!("字节模式搜索完成: {} 处匹配", matches.len());
        Ok(matches)
    }

    /// 在目标进程中搜索字符串
    ///
    /// # 参数
    /// - `text`: 要搜索的文本字符串
    /// - `search_regions`: 可选的内存区域列表
    ///
    /// # 返回值
    /// 返回所有匹配的地址列表
    pub fn search_string(
        &mut self,
        text: &str,
        search_regions: Option<&[MemoryRegion]>,
    ) -> Result<Vec<u64>> {
        self.search_bytes(text.as_bytes(), search_regions)
    }

    /// 在目标进程中搜索文本模式（支持简单的通配符）
    ///
    /// 使用字节模式匹配在目标进程内存中搜索文本字符串。
    ///
    /// # 参数
    /// - `pattern`: 要搜索的文本模式
    /// - `search_regions`: 可选的内存区域列表
    ///
    /// # 返回值
    /// 返回所有匹配的地址列表
    pub fn search_pattern(
        &mut self,
        pattern: &str,
        search_regions: Option<&[MemoryRegion]>,
    ) -> Result<Vec<u64>> {
        self.search_bytes(pattern.as_bytes(), search_regions)
    }

    /// 转储指定内存区域的数据
    ///
    /// # 参数
    /// - `start`: 起始地址
    /// - `size`: 读取大小（字节）
    ///
    /// # 返回值
    /// 返回读取到的原始字节数据
    pub fn dump_region(&self, start: u64, size: usize) -> Result<Vec<u8>> {
        if size == 0 {
            return Ok(Vec::new());
        }

        log::debug!(
            "转储内存区域: PID {}, 起始={:#x}, 大小={}",
            self.pid.0,
            start,
            size
        );

        self.read_region(start as usize, size)
    }

    /// 转储指定模块的完整内存
    ///
    /// # 参数
    /// - `module_name`: 模块名称（如 "libc.so.6"）
    ///
    /// # 返回值
    /// 返回 (模块基址, 模块数据) 的元组
    pub fn dump_module(&mut self, module_name: &str) -> Result<(u64, Vec<u8>)> {
        self.ensure_regions()?;

        // 找到模块的所有内存区域
        let module_regions: Vec<&MemoryRegion> = self
            .regions
            .iter()
            .filter(|r| {
                !r.name.is_empty()
                    && (r.name.ends_with(module_name) || r.name.contains(module_name))
            })
            .collect();

        if module_regions.is_empty() {
            return Err(crate::FridaError::NotFound {
                reason: format!("未找到模块 '{}' 的内存区域", module_name),
            }
            .into());
        }

        // 获取模块基址（第一个可执行区域）
        let base_addr = module_regions
            .iter()
            .find(|r| r.perms.execute)
            .map(|r| r.start as u64)
            .or_else(|| module_regions.first().map(|r| r.start as u64))
            .unwrap();

        // 计算模块总大小
        let min_addr = module_regions.iter().map(|r| r.start).min().unwrap();
        let max_addr = module_regions.iter().map(|r| r.end).max().unwrap();
        let total_size = max_addr - min_addr;

        log::debug!(
            "转储模块 '{}': 基址={:#x}, 大小={}",
            module_name,
            base_addr,
            total_size
        );

        // 读取整个模块（包含间隔）
        let mut data = vec![0u8; total_size];

        for region in &module_regions {
            let offset = region.start - min_addr;
            let region_data = self.read_region(region.start, region.size())?;
            if offset + region_data.len() <= data.len() {
                data[offset..offset + region_data.len()].copy_from_slice(&region_data);
            }
        }

        Ok((base_addr, data))
    }

    /// 转储目标进程的所有已映射模块
    ///
    /// # 返回值
    /// 返回 HashMap<模块名, 模块数据>
    pub fn dump_process(&mut self) -> Result<std::collections::HashMap<String, Vec<u8>>> {
        self.ensure_regions()?;

        // 收集所有唯一的模块名称
        let mut module_names: Vec<String> = self
            .regions
            .iter()
            .filter(|r| !r.name.is_empty())
            .map(|r| {
                // 提取模块名（去掉路径前缀）
                r.name
                    .rsplit('/')
                    .next()
                    .unwrap_or(&r.name)
                    .to_string()
            })
            .collect();

        module_names.sort();
        module_names.dedup();

        let mut result = std::collections::HashMap::new();

        for name in &module_names {
            if let Ok((_base, data)) = self.dump_module(name) {
                result.insert(name.clone(), data);
                log::debug!("已转储模块: {}", name);
            }
        }

        log::info!("已转储 {} 个模块", result.len());
        Ok(result)
    }

    /// 解析 /proc/[pid]/maps 获取内存布局
    ///
    /// # 参数
    /// - `pid`: 目标进程 ID
    ///
    /// # 返回值
    /// 返回所有内存区域
    pub fn parse_maps(pid: ProcessId) -> Result<Vec<MemoryRegion>> {
        parse_proc_maps(pid)
    }

    /// 读取目标进程中指定地址的数据
    ///
    /// 对于当前进程（pid=0）直接通过指针读取，
    /// 对于远程进程通过 process_vm_readv 读取。
    fn read_region(&self, addr: usize, size: usize) -> Result<Vec<u8>> {
        if self.pid.0 == 0 {
            // 当前进程：直接读取
            let mut buf = vec![0u8; size];
            // SAFETY: 调用者需确保地址有效
            unsafe {
                libc::memcpy(
                    buf.as_mut_ptr() as *mut libc::c_void,
                    addr as *const libc::c_void,
                    size,
                );
            }
            Ok(buf)
        } else {
            // 远程进程：通过 process_vm_readv
            safe_read_bytes(self.pid, addr, size)
        }
    }

    /// 在数据块中搜索字节模式
    ///
    /// 使用简化的搜索算法（逐步扫描），在给定数据块中查找所有匹配位置。
    fn find_pattern_in_data(
        &self,
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
            // 快速检查第一个字节
            if data[idx] == pattern[0] {
                // 检查完整模式
                let mut found = true;
                for j in 1..pattern.len() {
                    if data[idx + j] != pattern[j] {
                        found = false;
                        break;
                    }
                }
                if found {
                    matches.push(base_addr + idx as u64);
                    idx += pattern.len(); // 跳过已匹配的部分
                    continue;
                }
            }
            idx += 1;
        }
    }

    /// 获取已加载的内存区域数量
    pub fn region_count(&mut self) -> Result<usize> {
        self.ensure_regions()?;
        Ok(self.regions.len())
    }

    /// 获取所有内存区域列表的只读引用
    pub fn regions(&mut self) -> Result<&[MemoryRegion]> {
        self.ensure_regions()?;
        Ok(&self.regions)
    }

    /// 查找指定名称的模块区域
    pub fn find_module_regions(&mut self, module_name: &str) -> Result<Vec<MemoryRegion>> {
        self.ensure_regions()?;
        let regions: Vec<MemoryRegion> = self
            .regions
            .iter()
            .filter(|r| {
                !r.name.is_empty()
                    && (r.name.ends_with(module_name) || r.name.contains(module_name))
            })
            .cloned()
            .collect();

        if regions.is_empty() {
            return Err(crate::FridaError::NotFound {
                reason: format!("未找到模块 '{}'", module_name),
            }
            .into());
        }

        Ok(regions)
    }
}

impl Default for MemoryScanner {
    fn default() -> Self {
        Self::new(ProcessId(0))
    }
}
