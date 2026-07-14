use crate::common::types::{MemoryRegion, ProcessId};
use crate::common::util::{parse_proc_maps, safe_read_bytes};
use crate::Result;

#[cfg(any(target_os = "linux", target_os = "android"))]
use crate::communication::kernel_channel::KernelChannel;

pub struct MemoryScanner {
    pid: ProcessId,
    regions: Vec<MemoryRegion>,
    regions_loaded: bool,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    kernel_channel: Option<KernelChannel>,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    kernel_channel_available: bool,
}

impl MemoryScanner {
    pub fn new(pid: ProcessId) -> Self {
        MemoryScanner {
            pid,
            regions: Vec::new(),
            regions_loaded: false,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            kernel_channel: None,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            kernel_channel_available: true,
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn ensure_kernel_channel(&mut self) -> Option<&KernelChannel> {
        if !self.kernel_channel_available {
            return None;
        }

        if self.kernel_channel.is_none() {
            match KernelChannel::new() {
                Ok(channel) => {
                    match channel.ping() {
                        Ok(_) => {
                            log::info!("内核通道已连接");
                            self.kernel_channel = Some(channel);
                        }
                        Err(e) => {
                            log::warn!("内核通道不可用，回退到用户态: {}", e);
                            self.kernel_channel_available = false;
                            return None;
                        }
                    }
                }
                Err(e) => {
                    log::warn!("创建内核通道失败，回退到用户态: {}", e);
                    self.kernel_channel_available = false;
                    return None;
                }
            }
        }

        self.kernel_channel.as_ref()
    }

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

    fn ensure_regions(&mut self) -> Result<()> {
        if !self.regions_loaded {
            self.refresh_maps()?;
        }
        Ok(())
    }

    fn readable_regions(&mut self) -> Result<Vec<MemoryRegion>> {
        self.ensure_regions()?;
        Ok(self
            .regions
            .iter()
            .filter(|r| r.perms.read)
            .cloned()
            .collect())
    }

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

            let read_size = region.size().min(16 * 1024 * 1024);
            let data = match self.read_region(region.start, read_size) {
                Ok(d) => d,
                Err(_) => continue,
            };

            self.find_pattern_in_data(&data, pattern, region.start as u64, &mut matches);
        }

        log::debug!("字节模式搜索完成: {} 处匹配", matches.len());
        Ok(matches)
    }

    pub fn search_string(
        &mut self,
        text: &str,
        search_regions: Option<&[MemoryRegion]>,
    ) -> Result<Vec<u64>> {
        self.search_bytes(text.as_bytes(), search_regions)
    }

    pub fn search_pattern(
        &mut self,
        pattern: &str,
        search_regions: Option<&[MemoryRegion]>,
    ) -> Result<Vec<u64>> {
        self.search_bytes(pattern.as_bytes(), search_regions)
    }

    pub fn dump_region(&mut self, start: u64, size: usize) -> Result<Vec<u8>> {
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

    pub fn dump_module(&mut self, module_name: &str) -> Result<(u64, Vec<u8>)> {
        self.ensure_regions()?;

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

        let base_addr = module_regions
            .iter()
            .find(|r| r.perms.execute)
            .map(|r| r.start as u64)
            .or_else(|| module_regions.first().map(|r| r.start as u64))
            .unwrap();

        let min_addr = module_regions.iter().map(|r| r.start).min().unwrap();
        let max_addr = module_regions.iter().map(|r| r.end).max().unwrap();
        let total_size = max_addr - min_addr;

        log::debug!(
            "转储模块 '{}': 基址={:#x}, 大小={}",
            module_name,
            base_addr,
            total_size
        );

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

    pub fn dump_process(&mut self) -> Result<std::collections::HashMap<String, Vec<u8>>> {
        self.ensure_regions()?;

        let mut module_names: Vec<String> = self
            .regions
            .iter()
            .filter(|r| !r.name.is_empty())
            .map(|r| {
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

    pub fn parse_maps(pid: ProcessId) -> Result<Vec<MemoryRegion>> {
        parse_proc_maps(pid)
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn read_region_kernel(&mut self, addr: usize, size: usize) -> Result<Vec<u8>> {
        if let Some(channel) = self.ensure_kernel_channel() {
            match channel.read_mem(self.pid.0 as i32, addr, size) {
                Ok(data) => {
                    log::trace!("内核通道读取成功: addr={:#x}, size={}", addr, size);
                    return Ok(data);
                }
                Err(e) => {
                    log::debug!("内核通道读取失败，回退到用户态: {}", e);
                    self.kernel_channel_available = false;
                }
            }
        }

        self.read_region_fallback(addr, size)
    }

    fn read_region_fallback(&self, addr: usize, size: usize) -> Result<Vec<u8>> {
        if self.pid.0 == 0 {
            let mut buf = vec![0u8; size];
            unsafe {
                libc::memcpy(
                    buf.as_mut_ptr() as *mut libc::c_void,
                    addr as *const libc::c_void,
                    size,
                );
            }
            Ok(buf)
        } else {
            safe_read_bytes(self.pid, addr, size)
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    fn read_region(&self, addr: usize, size: usize) -> Result<Vec<u8>> {
        self.read_region_fallback(addr, size)
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn read_region(&mut self, addr: usize, size: usize) -> Result<Vec<u8>> {
        if self.pid.0 == 0 {
            self.read_region_fallback(addr, size)
        } else {
            self.read_region_kernel(addr, size)
        }
    }

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

    pub fn region_count(&mut self) -> Result<usize> {
        self.ensure_regions()?;
        Ok(self.regions.len())
    }

    pub fn regions(&mut self) -> Result<&[MemoryRegion]> {
        self.ensure_regions()?;
        Ok(&self.regions)
    }

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