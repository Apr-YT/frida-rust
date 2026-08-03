//! Windows 反射式 DLL 注入器（Reflective DLL Injection）
//!
//! 与经典 `CreateRemoteThread + LoadLibraryA` 注入的区别：
//! - 不调用 `LoadLibrary` 加载主 DLL，不触发 `LdrLoadDll` 通知回调
//! - 注入的 DLL 不会出现在目标进程的 PEB 模块链中（对模块枚举 / GetModuleHandle 天然不可见）
//! - 在本地构建完整映射映像（PE 头 + 节区 + 重定位 + IAT 全部本地修正），
//!   目标进程只需一次 `VirtualAllocEx + WriteProcessMemory` 写入
//!
//! 流程：
//! 1. 解析 PE32/PE32+ 文件（DOS/NT 头、节区表、导入表、重定位表）
//! 2. `VirtualAllocEx` 分配 `SizeOfImage` 远程内存
//! 3. 本地构建映像：拷贝头与节区、应用重定位（delta = 实际基址 - ImageBase）、
//!    填充 IAT（依赖 DLL 基址取自目标进程模块表，函数 RVA 取自注入器进程解析）
//! 4. `WriteProcessMemory` 一次性写入目标进程
//! 5. 可选：注入 x64 thunk 调用 `DllMain(DLL_PROCESS_ATTACH)`
//!
//! 局限：依赖 DLL 必须在目标进程中已加载（系统 DLL 通常满足），
//! 否则无法解析其目标基址；ordinal 导入项会被跳过并告警。

use crate::common::error::FridaError;
use std::collections::HashMap;
use winapi::um::memoryapi::{VirtualAllocEx, VirtualFreeEx, WriteProcessMemory};
use winapi::um::processthreadsapi::{CreateRemoteThread, OpenProcess};
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winbase::INFINITE;
use winapi::um::winnt::{HANDLE, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PROCESS_ALL_ACCESS};

// ==================== PE 解析（纯逻辑，可单测） ====================

/// PE 映像解析结果
#[derive(Debug, Clone)]
pub struct PeImage {
    /// 是否为 PE32+（x64）；false 表示 PE32（x86）
    pub is_pe32_plus: bool,
    /// 首选映像基址（ImageBase）
    pub image_base: u64,
    /// 映像总大小（SizeOfImage，按 SectionAlignment 对齐）
    pub size_of_image: usize,
    /// 入口点 RVA（AddressOfEntryPoint）
    pub entry_point: usize,
    /// 头部大小（SizeOfHeaders）
    pub size_of_headers: usize,
    /// 节区表
    pub sections: Vec<PeSection>,
    /// 导入目录 (RVA, Size)，无则 None
    pub import_dir: Option<(u32, u32)>,
    /// 重定位目录 (RVA, Size)，无则 None
    pub reloc_dir: Option<(u32, u32)>,
    /// 原始文件字节
    data: Vec<u8>,
    /// 节区数
    section_count: u16,
}

/// PE 节区
#[derive(Debug, Clone)]
pub struct PeSection {
    pub name: [u8; 8],
    /// 内存中大小（VirtualSize）
    pub virtual_size: u32,
    /// 内存中 RVA（VirtualAddress）
    pub virtual_address: u32,
    /// 文件中大小（SizeOfRawData）
    pub raw_size: u32,
    /// 文件中偏移（PointerToRawData）
    pub raw_offset: u32,
}

impl PeImage {
    /// 从文件字节解析 PE 映像
    pub fn parse(data: &[u8]) -> crate::Result<Self> {
        if data.len() < 0x40 || data[0] != b'M' || data[1] != b'Z' {
            return Err(FridaError::Inject {
                reason: "不是有效的 PE 文件（缺少 MZ 头）".to_string(),
                pid: 0,
                source: None,
            }
            .into());
        }
        let e_lfanew = read_u32(data, 0x3C) as usize;
        if e_lfanew + 0x18 > data.len() {
            return Err(FridaError::Inject {
                reason: "PE 头越界".to_string(),
                pid: 0,
                source: None,
            }
            .into());
        }
        if &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
            return Err(FridaError::Inject {
                reason: "不是有效的 PE 文件（缺少 PE 签名）".to_string(),
                pid: 0,
                source: None,
            }
            .into());
        }
        let opt = e_lfanew + 4 + 20; // FileHeader 20 字节
        let magic = read_u16(data, opt);
        let is_pe32_plus = match magic {
            0x10B => false, // PE32
            0x20B => true,  // PE32+
            m => {
                return Err(FridaError::Inject {
                    reason: format!("不支持的 PE 可选头 magic: {:#x}", m),
                    pid: 0,
                    source: None,
                }
                .into())
            }
        };
        // FileHeader.NumberOfSections @ +2
        let section_count = read_u16(data, e_lfanew + 4 + 2);
        if section_count == 0 || section_count > 96 {
            return Err(FridaError::Inject {
                reason: format!("异常的节区数量: {}", section_count),
                pid: 0,
                source: None,
            }
            .into());
        }
        let entry_point = read_u32(data, opt + 16) as usize;
        let image_base = if is_pe32_plus {
            read_u64(data, opt + 24)
        } else {
            read_u32(data, opt + 28) as u64
        };
        let size_of_image = read_u32(data, opt + 56) as usize;
        let size_of_headers = read_u32(data, opt + 60) as usize;
        // NumberOfRvaAndSizes：PE32+ @ +108，PE32 @ +92
        let number_of_rva = if is_pe32_plus {
            read_u32(data, opt + 108) as usize
        } else {
            read_u32(data, opt + 92) as usize
        };
        let data_dir_off = if is_pe32_plus { opt + 112 } else { opt + 96 };

        // 导入目录 index=1，重定位目录 index=5
        let import_dir = if number_of_rva > 1 {
            Some((read_u32(data, data_dir_off + 1 * 8), read_u32(data, data_dir_off + 1 * 8 + 4)))
        } else {
            None
        };
        let reloc_dir = if number_of_rva > 5 {
            Some((read_u32(data, data_dir_off + 5 * 8), read_u32(data, data_dir_off + 5 * 8 + 4)))
        } else {
            None
        };

        // 节区表紧随可选头
        let size_of_opt = read_u16(data, e_lfanew + 4 + 16) as usize;
        let section_table = opt + size_of_opt;
        let mut sections = Vec::with_capacity(section_count as usize);
        for i in 0..section_count as usize {
            let off = section_table + i * 40;
            if off + 40 > data.len() {
                break;
            }
            let mut name = [0u8; 8];
            name.copy_from_slice(&data[off..off + 8]);
            sections.push(PeSection {
                name,
                virtual_size: read_u32(data, off + 8),
                virtual_address: read_u32(data, off + 12),
                raw_size: read_u32(data, off + 16),
                raw_offset: read_u32(data, off + 20),
            });
        }

        Ok(PeImage {
            is_pe32_plus,
            image_base,
            size_of_image,
            entry_point,
            size_of_headers,
            sections,
            import_dir,
            reloc_dir,
            data: data.to_vec(),
            section_count,
        })
    }

    /// 节区数量
    pub fn section_count(&self) -> u16 {
        self.section_count
    }

    /// 将 RVA 转换为文件偏移（按节区匹配），失败返回 None
    pub fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        for sec in &self.sections {
            let va = sec.virtual_address;
            let vs = sec.virtual_size;
            if rva >= va && rva < va.saturating_add(vs.max(sec.raw_size)) {
                return Some(sec.raw_offset as usize + (rva - va) as usize);
            }
        }
        // 头部区域
        if rva < self.size_of_headers as u32 {
            return Some(rva as usize);
        }
        None
    }

    /// 读取以 NUL 结尾的 ASCII 字符串（按 RVA）
    pub fn read_cstring_at_rva(&self, rva: u32) -> Option<String> {
        let off = self.rva_to_offset(rva)?;
        let end = self.data[off..]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.data.len() - off);
        let bytes = &self.data[off..off + end];
        Some(String::from_utf8_lossy(bytes).to_string())
    }
}

impl PeImage {
    /// 构建完整的本地映射映像（应用重定位并填充 IAT）
    ///
    /// - `delta`: 实际基址 - ImageBase（重定位修正值）
    /// - `dep_base`: 解析依赖 DLL 在目标进程中的基址（按 DLL 名，小写）
    /// - `func_rva`: 解析依赖 DLL 中导出函数相对其基址的偏移（注入器进程解析）
    ///
    /// 返回按 `SizeOfImage` 对齐的完整映像字节。
    pub fn build_mapped_image(
        &self,
        delta: i64,
        dep_base: &HashMap<String, u64>,
        func_rva: &dyn Fn(&str, &str) -> Option<u64>,
    ) -> crate::Result<Vec<u8>> {
        let mut out = vec![0u8; self.size_of_image];
        // 1. 拷贝头部
        let head_len = self.size_of_headers.min(self.data.len());
        out[..head_len].copy_from_slice(&self.data[..head_len]);
        // 2. 拷贝各节区 raw data
        for sec in &self.sections {
            let dst = sec.virtual_address as usize;
            let raw = sec.raw_offset as usize;
            let len = sec.raw_size as usize;
            if dst < self.size_of_image && raw + len <= self.data.len() {
                let n = len.min(self.size_of_image - dst);
                out[dst..dst + n].copy_from_slice(&self.data[raw..raw + n]);
            }
        }
        // 3. 应用重定位
        self.apply_relocations(&mut out, delta);
        // 4. 填充 IAT
        self.fill_imports(&mut out, dep_base, func_rva)?;
        Ok(out)
    }

    /// 应用重定位：将映像内绝对地址修正 delta
    fn apply_relocations(&self, image: &mut [u8], delta: i64) {
        if delta == 0 {
            return;
        }
        let Some((rva, size)) = self.reloc_dir else {
            return;
        };
        let base_off = match self.rva_to_offset(rva) {
            Some(o) => o,
            None => return,
        };
        let mut off = base_off;
        let end = base_off.saturating_add(size as usize).min(self.data.len());
        while off + 8 <= end {
            let page_rva = read_u32(&self.data, off);
            let block_size = read_u32(&self.data, off + 4) as usize;
            if block_size < 8 {
                break;
            }
            let entries = (block_size - 8) / 2;
            for i in 0..entries {
                let entry_off = off + 8 + i * 2;
                if entry_off + 2 > self.data.len() {
                    break;
                }
                let item = read_u16(&self.data, entry_off);
                let typ = item >> 12;
                let offset = (item & 0x0FFF) as usize;
                if typ == 0 {
                    continue; // ABS
                }
                let addr = page_rva as usize + offset;
                if addr + 8 > image.len() {
                    continue;
                }
                match typ {
                    3 => {
                        // HIGHLOW (32-bit)
                        let mut v = read_u32(image, addr);
                        v = (v as i64 + delta) as u32;
                        write_u32(image, addr, v);
                    }
                    10 => {
                        // DIR64
                        let mut v = read_u64(image, addr);
                        v = (v as i64 + delta) as u64;
                        write_u64(image, addr, v);
                    }
                    _ => {}
                }
            }
            off += block_size;
        }
    }

    /// 填充导入表（IAT）：依赖 DLL 基址取自目标进程，函数 RVA 由 func_rva 提供
    fn fill_imports(
        &self,
        image: &mut [u8],
        dep_base: &HashMap<String, u64>,
        func_rva: &dyn Fn(&str, &str) -> Option<u64>,
    ) -> crate::Result<()> {
        let Some((rva, size)) = self.import_dir else {
            return Ok(());
        };
        let base_off = match self.rva_to_offset(rva) {
            Some(o) => o,
            None => return Ok(()),
        };
        let end = base_off.saturating_add(size as usize);
        let mut off = base_off;
        // 每个 IMAGE_IMPORT_DESCRIPTOR 20 字节，以全 0 结束
        while off + 20 <= end {
            let original_first_thunk = read_u32(&self.data, off);
            let name_rva = read_u32(&self.data, off + 12);
            let first_thunk = read_u32(&self.data, off + 16);
            if original_first_thunk == 0 && first_thunk == 0 {
                break;
            }
            let dll_name = self
                .read_cstring_at_rva(name_rva)
                .unwrap_or_default()
                .to_lowercase();
            let target_base = match dep_base.get(&dll_name) {
                Some(&b) => b,
                None => {
                    log::warn!("反射注入: 依赖 DLL '{}' 未在目标进程模块表中", dll_name);
                    off += 20;
                    continue;
                }
            };
            let thunk_rva = if first_thunk != 0 { first_thunk } else { original_first_thunk };
            self.fill_thunk(image, target_base, thunk_rva, original_first_thunk, &dll_name, func_rva);
            off += 20;
        }
        Ok(())
    }

    /// 填充单个导入描述符的 thunk 数组
    fn fill_thunk(
        &self,
        image: &mut [u8],
        target_base: u64,
        iat_rva: u32,
        int_rva: u32,
        dll_name: &str,
        func_rva: &dyn Fn(&str, &str) -> Option<u64>,
    ) {
        let thunk_size = if self.is_pe32_plus { 8usize } else { 4usize };
        let ordinal_flag: u64 = if self.is_pe32_plus { 0x8000_0000_0000_0000 } else { 0x8000_0000 };
        let mut i = 0usize;
        loop {
            let iat_addr = iat_rva as usize + i * thunk_size;
            if iat_addr + thunk_size > image.len() {
                break;
            }
            // 从 INT（若存在）读取 thunk 值；否则从 IAT 位置读取原始值
            // 注意：INT/IAT 均为 RVA，读文件字节需经 rva_to_offset 转换
            let src_rva = if int_rva != 0 {
                int_rva + (i * thunk_size) as u32
            } else {
                iat_rva + (i * thunk_size) as u32
            };
            let src_addr = match self.rva_to_offset(src_rva) {
                Some(o) => o,
                None => break,
            };
            if src_addr + thunk_size > self.data.len() {
                break;
            }
            let raw = if self.is_pe32_plus {
                read_u64(&self.data, src_addr)
            } else {
                read_u32(&self.data, src_addr) as u64
            };
            if raw == 0 {
                break;
            }
            if raw & ordinal_flag != 0 {
                log::warn!("反射注入: 跳过 ordinal 导入项 (0x{:x})", raw);
                i += 1;
                continue;
            }
            let by_name_rva = (raw & 0xFFFF_FFFF) as u32;
            // IMAGE_IMPORT_BY_NAME: Hint(u16) + Name[]
            let name_off = match self.rva_to_offset(by_name_rva) {
                Some(o) => o + 2,
                None => {
                    i += 1;
                    continue;
                }
            };
            let name_end = self.data[name_off..]
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(self.data.len() - name_off);
            let func_name = String::from_utf8_lossy(&self.data[name_off..name_off + name_end]);
            // 函数地址 = 目标模块基址 + 函数 RVA
            let resolved = func_rva(dll_name, &func_name).map(|rva| target_base + rva);
            match resolved {
                Some(addr) => {
                    if self.is_pe32_plus {
                        write_u64(image, iat_addr, addr);
                    } else {
                        write_u32(image, iat_addr, addr as u32);
                    }
                }
                None => {
                    log::warn!("反射注入: 无法解析 {}.{}", dll_name, func_name);
                }
            }
            i += 1;
        }
    }
}

// ==================== 反射注入器（跨进程） ====================

/// Windows 反射注入器
pub struct WinReflectInjector {
    /// 目标进程 ID
    target_pid: u32,
    /// 目标进程句柄
    process_handle: HANDLE,
}

impl WinReflectInjector {
    /// 创建反射注入器
    pub fn new(pid: u32) -> Self {
        WinReflectInjector {
            target_pid: pid,
            process_handle: std::ptr::null_mut(),
        }
    }

    /// 打开目标进程（PROCESS_ALL_ACCESS）
    pub fn open_target(&mut self) -> crate::Result<()> {
        if !self.process_handle.is_null() {
            return Ok(());
        }
        let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, self.target_pid) };
        if handle.is_null() {
            let err = std::io::Error::last_os_error();
            return Err(FridaError::Inject {
                reason: format!("OpenProcess({}) 失败: {}", self.target_pid, err),
                pid: self.target_pid,
                source: Some(err),
            }
            .into());
        }
        self.process_handle = handle;
        Ok(())
    }

    /// 反射注入 DLL（从文件读取字节）
    pub fn inject_from_file(&mut self, dll_path: &str) -> crate::Result<u64> {
        let data = std::fs::read(dll_path).map_err(|e| FridaError::Inject {
            reason: format!("读取 DLL 文件失败: {}", e),
            pid: self.target_pid,
            source: Some(e),
        })?;
        self.inject(&data)
    }

    /// 反射注入 DLL 字节，返回远程映像基址
    pub fn inject(&mut self, dll_bytes: &[u8]) -> crate::Result<u64> {
        self.open_target()?;
        let pe = PeImage::parse(dll_bytes)?;
        if pe.size_of_image == 0 {
            return Err(FridaError::Inject {
                reason: "PE SizeOfImage 为 0".to_string(),
                pid: self.target_pid,
                source: None,
            }
            .into());
        }

        // 1. 分配远程内存
        let remote_base = unsafe {
            VirtualAllocEx(
                self.process_handle,
                std::ptr::null_mut(),
                pe.size_of_image,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        };
        if remote_base.is_null() {
            let err = std::io::Error::last_os_error();
            return Err(FridaError::Inject {
                reason: format!("VirtualAllocEx 失败: {}", err),
                pid: self.target_pid,
                source: Some(err),
            }
            .into());
        }
        let remote_addr = remote_base as usize;

        // 2. 构建目标模块表（依赖 DLL 基址）
        let target_modules = crate::inject::win_process::enum_modules(self.target_pid)
            .map_err(|e| FridaError::Inject {
                reason: format!("枚举目标进程模块失败: {}", e),
                pid: self.target_pid,
                source: None,
            })?;
        let mut dep_base: HashMap<String, u64> = HashMap::new();
        for m in &target_modules {
            dep_base
                .entry(m.name.to_lowercase())
                .or_insert(m.base_addr as u64);
        }

        // 3. 本地构建映射映像（注入器进程解析函数 RVA）
        let delta = remote_addr as i64 - pe.image_base as i64;
        let func_rva = |dll_name: &str, func_name: &str| -> Option<u64> {
            let dll_c = std::ffi::CString::new(dll_name).ok()?;
            let h = unsafe { winapi::um::libloaderapi::GetModuleHandleA(dll_c.as_ptr()) };
            if h.is_null() {
                return None;
            }
            let func_c = std::ffi::CString::new(func_name).ok()?;
            let proc = unsafe { winapi::um::libloaderapi::GetProcAddress(h, func_c.as_ptr()) };
            if proc.is_null() {
                return None;
            }
            Some(proc as usize as u64 - h as usize as u64)
        };
        let image = pe.build_mapped_image(delta, &dep_base, &func_rva)?;

        // 4. 写入目标进程
        let mut written = 0usize;
        let ok = unsafe {
            WriteProcessMemory(
                self.process_handle,
                remote_base,
                image.as_ptr() as *const winapi::ctypes::c_void,
                image.len(),
                &mut written,
            )
        };
        if ok == 0 {
            unsafe {
                VirtualFreeEx(self.process_handle, remote_base, 0, MEM_RELEASE);
            }
            let err = std::io::Error::last_os_error();
            return Err(FridaError::Inject {
                reason: format!("WriteProcessMemory 失败: {}", err),
                pid: self.target_pid,
                source: Some(err),
            }
            .into());
        }
        log::info!(
            "反射注入完成: PID={}, base={:#x}, size={}, entry={:#x}",
            self.target_pid,
            remote_addr,
            pe.size_of_image,
            pe.entry_point
        );
        Ok(remote_addr as u64)
    }

    /// 调用远程映像的 DllMain(DLL_PROCESS_ATTACH)（x64 thunk），返回 DllMain 返回值
    pub fn call_dllmain(&mut self, remote_base: u64) -> crate::Result<u32> {
        self.open_target()?;
        // 读取远程映像入口点 RVA（PE 可选头 AddressOfEntryPoint @ +0x10）
        let entry_rva = self.read_remote_u32(remote_base as usize + 0x10)?;
        let entry = remote_base + entry_rva as u64;
        self.call_entry(remote_base, entry, true)
    }

    /// 在远程进程中通过 x64 thunk 调用指定函数
    fn call_entry(&mut self, remote_base: u64, entry: u64, is_dllmain: bool) -> crate::Result<u32> {
        let thunk = build_entry_thunk(remote_base, entry, is_dllmain);
        let thunk_mem = unsafe {
            VirtualAllocEx(
                self.process_handle,
                std::ptr::null_mut(),
                thunk.len(),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        };
        if thunk_mem.is_null() {
            let err = std::io::Error::last_os_error();
            return Err(FridaError::Inject {
                reason: format!("分配 thunk 内存失败: {}", err),
                pid: self.target_pid,
                source: Some(err),
            }
            .into());
        }
        let mut written = 0usize;
        unsafe {
            WriteProcessMemory(
                self.process_handle,
                thunk_mem,
                thunk.as_ptr() as *const winapi::ctypes::c_void,
                thunk.len(),
                &mut written,
            );
        }
        let mut thread_id = 0u32;
        let thread = unsafe {
            CreateRemoteThread(
                self.process_handle,
                std::ptr::null_mut(),
                0,
                Some(std::mem::transmute(thunk_mem)),
                std::ptr::null_mut(),
                0,
                &mut thread_id,
            )
        };
        if thread.is_null() {
            unsafe {
                VirtualFreeEx(self.process_handle, thunk_mem, 0, MEM_RELEASE);
            }
            let err = std::io::Error::last_os_error();
            return Err(FridaError::Inject {
                reason: format!("CreateRemoteThread 失败: {}", err),
                pid: self.target_pid,
                source: Some(err),
            }
            .into());
        }
        unsafe {
            WaitForSingleObject(thread, INFINITE);
        }
        let mut exit: u32 = 0;
        unsafe {
            winapi::um::processthreadsapi::GetExitCodeThread(thread, &mut exit);
        }
        unsafe {
            winapi::um::handleapi::CloseHandle(thread);
            winapi::um::memoryapi::VirtualFreeEx(self.process_handle, thunk_mem, 0, MEM_RELEASE);
        }
        Ok(exit)
    }

    /// 读取远程进程 u32
    fn read_remote_u32(&mut self, addr: usize) -> crate::Result<u32> {
        let mut v = 0u32;
        let mut read_len = 0usize;
        let ok = unsafe {
            winapi::um::memoryapi::ReadProcessMemory(
                self.process_handle,
                addr as *const winapi::ctypes::c_void,
                &mut v as *mut u32 as *mut winapi::ctypes::c_void,
                4,
                &mut read_len,
            )
        };
        if ok == 0 {
            return Err(FridaError::Inject {
                reason: format!("ReadProcessMemory({:#x}) 失败", addr),
                pid: self.target_pid,
                source: None,
            }
            .into());
        }
        Ok(v)
    }

    /// 关闭句柄
    pub fn close(&mut self) {
        if !self.process_handle.is_null() {
            unsafe {
                winapi::um::handleapi::CloseHandle(self.process_handle);
            }
            self.process_handle = std::ptr::null_mut();
        }
    }
}

impl Drop for WinReflectInjector {
    fn drop(&mut self) {
        self.close();
    }
}

/// 构造 x64 thunk 机器码：设置参数并调用入口
///
/// DllMain 模式：rcx=hinst, rdx=1(DLL_PROCESS_ATTACH), r8=0
/// 导出函数模式：rcx=remote_base
fn build_entry_thunk(remote_base: u64, entry: u64, is_dllmain: bool) -> Vec<u8> {
    let mut code = Vec::new();
    // sub rsp, 0x28
    code.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);
    if is_dllmain {
        // mov rcx, imm64
        code.push(0x48);
        code.push(0xB9);
        code.extend_from_slice(&remote_base.to_le_bytes());
        // mov edx, 1
        code.extend_from_slice(&[0xBA, 0x01, 0x00, 0x00, 0x00]);
        // xor r8d, r8d
        code.extend_from_slice(&[0x45, 0x33, 0xC0]);
    } else {
        // mov rcx, imm64
        code.push(0x48);
        code.push(0xB9);
        code.extend_from_slice(&remote_base.to_le_bytes());
    }
    // mov rax, imm64
    code.push(0x48);
    code.push(0xB8);
    code.extend_from_slice(&entry.to_le_bytes());
    // call rax
    code.extend_from_slice(&[0xFF, 0xD0]);
    // add rsp, 0x28
    code.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]);
    // ret
    code.push(0xC3);
    code
}

// ==================== 字节读取辅助 ====================

fn read_u16(data: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([data[off], data[off + 1]])
}

fn read_u32(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}

fn read_u64(data: &[u8], off: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&data[off..off + 8]);
    u64::from_le_bytes(b)
}

#[allow(dead_code)] // 测试构造 PE 时使用
fn write_u16(data: &mut [u8], off: usize, v: u16) {
    data[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

fn write_u32(data: &mut [u8], off: usize, v: u32) {
    data[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn write_u64(data: &mut [u8], off: usize, v: u64) {
    data[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造最小 PE32+ 头（含指定数量的空节区占位）
    fn make_min_pe(sections: u16) -> Vec<u8> {
        let mut data = vec![0u8; 0x1000];
        data[0] = b'M';
        data[1] = b'Z';
        write_u32(&mut data, 0x3C, 0x80); // e_lfanew
        data[0x80..0x84].copy_from_slice(b"PE\0\0");
        write_u16(&mut data, 0x84 + 2, sections); // NumberOfSections
        write_u16(&mut data, 0x84 + 16, 0xF0); // SizeOfOptionalHeader (PE32+)
        let opt = 0x80 + 4 + 20;
        write_u16(&mut data, opt, 0x20B); // PE32+
        write_u64(&mut data, opt + 24, 0x180000000); // ImageBase
        write_u32(&mut data, opt + 56, 0x3000); // SizeOfImage
        write_u32(&mut data, opt + 60, 0x200); // SizeOfHeaders
        write_u32(&mut data, opt + 108, 16); // NumberOfRvaAndSizes
        data
    }

    #[test]
    fn test_pe_magic_validation() {
        assert!(PeImage::parse(b"not a pe").is_err());
        let mut fake = vec![0u8; 0x100];
        fake[0] = b'M';
        fake[1] = b'Z';
        assert!(PeImage::parse(&fake).is_err(), "缺 PE 签名应报错");
    }

    #[test]
    fn test_parse_min_pe() {
        let data = make_min_pe(1);
        let pe = PeImage::parse(&data).expect("解析最小 PE 失败");
        assert!(pe.is_pe32_plus);
        assert_eq!(pe.image_base, 0x180000000);
        assert_eq!(pe.size_of_image, 0x3000);
        assert_eq!(pe.section_count(), 1);
    }

    #[test]
    fn test_rva_to_offset_section() {
        let mut data = make_min_pe(1);
        let opt = 0x80 + 4 + 20;
        let sec = opt + 0xF0;
        data[sec..sec + 8].copy_from_slice(b".text\0\0\0");
        write_u32(&mut data, sec + 8, 0x400); // VirtualSize
        write_u32(&mut data, sec + 12, 0x1000); // VirtualAddress
        write_u32(&mut data, sec + 16, 0x400); // SizeOfRawData
        write_u32(&mut data, sec + 20, 0x200); // PointerToRawData
        let pe = PeImage::parse(&data).expect("解析失败");
        assert_eq!(pe.rva_to_offset(0x1000), Some(0x200));
        assert_eq!(pe.rva_to_offset(0x13FF), Some(0x200 + 0x3FF));
        assert_eq!(pe.rva_to_offset(0x1400), None);
        // 头部区域（小于 SizeOfHeaders 的 RVA 直接映射）
        assert_eq!(pe.rva_to_offset(0x100), Some(0x100));
    }

    #[test]
    fn test_apply_relocations_dir64() {
        // 构造含 .reloc 节的 PE，含 2 个 DIR64 重定位项
        let mut data = make_min_pe(1);
        let opt = 0x80 + 4 + 20;
        // 数据目录 index 5 = BaseReloc
        write_u32(&mut data, opt + 112 + 5 * 8, 0x2000); // RVA
        write_u32(&mut data, opt + 112 + 5 * 8 + 4, 0x120); // Size
        let sec = opt + 0xF0;
        data[sec..sec + 8].copy_from_slice(b".reloc\0\0");
        write_u32(&mut data, sec + 8, 0x1000);
        write_u32(&mut data, sec + 12, 0x2000);
        write_u32(&mut data, sec + 16, 0x120);
        write_u32(&mut data, sec + 20, 0x200);
        // 重定位块 @ 文件偏移 0x200
        write_u32(&mut data, 0x200, 0x2000); // PageRVA
        write_u32(&mut data, 0x204, 16); // BlockSize = 8 + 2*4
        write_u16(&mut data, 0x208, (10 << 12) | 0x100); // DIR64 @ +0x100
        write_u16(&mut data, 0x20A, (10 << 12) | 0x108); // DIR64 @ +0x108
        // 被重定位位置写入初始值（放在 .reloc 节区数据中，RVA 0x2100/0x2108 位于文件 0x300/0x308）
        // .reloc raw 只有 0x20 字节，扩展文件容纳
        data.resize(0x1000 + 0x100, 0);
        write_u64(&mut data, 0x300, 0x180001000);
        write_u64(&mut data, 0x308, 0x180002000);

        let pe = PeImage::parse(&data).expect("解析失败");
        // 构建映像：节区数据拷贝后，RVA 0x2100/0x2108 应等于初始值
        let delta = 0x4000i64;
        let mut image = pe
            .build_mapped_image(delta, &HashMap::new(), &|_, _| None)
            .expect("构建映像失败");
        // build_mapped_image 已应用重定位
        let v1 = read_u64(&image, 0x2100);
        let v2 = read_u64(&image, 0x2108);
        assert_eq!(v1, 0x180005000, "DIR64 重定位修正错误");
        assert_eq!(v2, 0x180006000, "DIR64 重定位修正错误");
        // 未重定位位置不受影响
        let _ = &mut image;
    }

    #[test]
    fn test_fill_imports_basic() {
        // 构造含导入表的 PE：依赖 kernel32.dll，导入 GetTickCount
        let mut data = make_min_pe(1);
        let opt = 0x80 + 4 + 20;
        // 数据目录 index 1 = Import
        write_u32(&mut data, opt + 112 + 1 * 8, 0x1000); // RVA
        write_u32(&mut data, opt + 112 + 1 * 8 + 4, 0x28); // Size
        let sec = opt + 0xF0;
        data[sec..sec + 8].copy_from_slice(b".idata\0\0");
        write_u32(&mut data, sec + 8, 0x1000);
        write_u32(&mut data, sec + 12, 0x1000);
        write_u32(&mut data, sec + 16, 0x400);
        write_u32(&mut data, sec + 20, 0x200);
        // 文件偏移 0x200 = RVA 0x1000
        // IMAGE_IMPORT_DESCRIPTOR @ 0x200: INT=0x1020, Name=0x1040, IAT=0x1030
        write_u32(&mut data, 0x200, 0x1020); // OriginalFirstThunk
        write_u32(&mut data, 0x200 + 12, 0x1040); // Name RVA
        write_u32(&mut data, 0x200 + 16, 0x1030); // FirstThunk (IAT)
        // 终止描述符 @ 0x214
        // INT @ RVA 0x1020 (文件 0x220): thunk -> 0x1050 (IMAGE_IMPORT_BY_NAME)
        write_u64(&mut data, 0x220, 0x1050);
        write_u64(&mut data, 0x228, 0); // INT 结束
        // IAT @ RVA 0x1030 (文件 0x230): 待填充
        // DLL 名 @ RVA 0x1040 (文件 0x240)
        data[0x240..0x24D].copy_from_slice(b"kernel32.dll\0");
        // IMAGE_IMPORT_BY_NAME @ RVA 0x1050 (文件 0x250): Hint(2) + "GetTickCount\0"
        write_u16(&mut data, 0x250, 0);
        data[0x252..0x25F].copy_from_slice(b"GetTickCount\0");
        // IAT 结束 @ RVA 0x1038

        let pe = PeImage::parse(&data).expect("解析失败");
        let mut dep_base = HashMap::new();
        dep_base.insert("kernel32.dll".to_string(), 0x7FF000000000u64);
        let func_rva = |dll: &str, name: &str| -> Option<u64> {
            if dll == "kernel32.dll" && name == "GetTickCount" {
                Some(0x1000)
            } else {
                None
            }
        };
        let image = pe
            .build_mapped_image(0, &dep_base, &func_rva)
            .expect("构建映像失败");
        // IAT @ RVA 0x1030 -> 0x7FF000001000
        let v = read_u64(&image, 0x1030);
        assert_eq!(v, 0x7FF000001000, "IAT 填充错误");
    }

    #[test]
    fn test_parse_system_dll() {
        // 用系统 kernel32.dll 做真实解析验证（Windows 环境）
        let path = r"C:\Windows\System32\kernel32.dll";
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(_) => return, // 非 Windows 环境跳过
        };
        let pe = PeImage::parse(&data).expect("解析 kernel32.dll 失败");
        assert!(pe.size_of_image > 0x1000, "SizeOfImage 异常: {:#x}", pe.size_of_image);
        assert!(pe.section_count() >= 4, "节区数异常: {}", pe.section_count());
        assert!(pe.entry_point > 0, "入口点 RVA 为 0");
        assert!(pe.import_dir.is_some(), "kernel32 应有导入表");
        assert!(pe.reloc_dir.is_some(), "kernel32 应有重定位表");
        assert!(pe.image_base > 0, "ImageBase 为 0");
    }

    #[test]
    fn test_build_entry_thunk() {
        let code = build_entry_thunk(0x180000000, 0x180001234, true);
        // sub rsp, 0x28
        assert_eq!(&code[0..4], &[0x48, 0x83, 0xEC, 0x28]);
        // mov rcx, imm64
        assert_eq!(code[4], 0x48);
        assert_eq!(code[5], 0xB9);
        // ret 结尾
        assert_eq!(code.last(), Some(&0xC3));
        // 导出模式（单参数）比 DllMain 模式短（少 mov edx / xor r8d）
        let code2 = build_entry_thunk(0x180000000, 0x180001234, false);
        assert!(code2.len() < code.len());
    }
}
