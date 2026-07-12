//! 内存反射注入实现
//!
//! 实现完全不落地的共享库注入方式。通过手动解析 ELF 格式，
//! 将共享库的所有 PT_LOAD 段映射到目标进程的内存中，
//! 处理重定位和链接，最后调用 .init_array 中的初始化函数。
//!
//! # 优势
//! - **无文件落地**：不写入磁盘，绕过基于文件系统的检测
//! - **隐蔽性强**：不会在 /proc/pid/maps 中出现文件路径
//! - **灵活性高**：可以从内存中的数据直接注入
//!
//! # 工作流程
//! 1. 解析 ELF header 和 program headers
//! 2. 在目标进程中为每个 PT_LOAD segment 分配内存
//! 3. 将 segment 数据写入目标进程
//! 4. 处理动态链接重定位（.rel.plt / .rela.plt）
//! 5. 调用 .init_array 中的所有初始化函数
//!
//! # 限制
//! - 需要处理 TLS（线程局部存储）等复杂情况
//! - 不适用于有复杂依赖关系的共享库
//! - 需要手动处理符号解析

#[cfg(any(target_os = "linux", target_os = "android"))]
use crate::common::error::FridaError;
#[cfg(any(target_os = "linux", target_os = "android"))]
use crate::common::types::ProcessId;

/// ELF 文件头信息（简化版）
#[cfg(any(target_os = "linux", target_os = "android"))]
#[derive(Debug)]
#[allow(dead_code)]
struct ElfInfo {
    /// ELF 类型（32位/64位）
    is_64bit: bool,
    /// 入口点地址
    entry: u64,
    /// 程序头表偏移
    phoff: u64,
    /// 程序头数量
    phnum: u16,
    /// 程序头大小
    phentsize: u16,
    /// 基地址（PIE 库的实际加载地址偏移）
    load_bias: u64,
    /// 所有 PT_LOAD 段的信息
    load_segments: Vec<LoadSegment>,
    /// 动态段信息
    dynamic: Option<DynamicInfo>,
}

/// PT_LOAD 段信息
#[cfg(any(target_os = "linux", target_os = "android"))]
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct LoadSegment {
    /// 段在文件中的偏移
    file_offset: u64,
    /// 段在内存中的虚拟地址
    vaddr: u64,
    /// 段在文件中的大小
    file_size: u64,
    /// 段在内存中的大小（可能包含 BSS）
    mem_size: u64,
    /// 段的内存保护权限
    prot: libc::c_int,
    /// 段的对齐要求
    align: u64,
}

/// 动态段信息
#[cfg(any(target_os = "linux", target_os = "android"))]
#[derive(Debug)]
struct DynamicInfo {
    /// .init_array 地址
    init_array: u64,
    /// .init_array 元素数量
    init_array_size: usize,
    /// .fini_array 地址
    fini_array: u64,
    /// .fini_array 元素数量
    fini_array_size: usize,
    /// .init 函数地址
    init_func: u64,
    /// .fini 函数地址
    fini_func: u64,
    /// GOT 表地址
    got: u64,
    /// RELA 重定位表地址
    rela: u64,
    /// RELA 重定位表条目数量
    rela_size: usize,
    /// REL 重定位表地址
    rel: u64,
    /// REL 重定位表条目数量
    rel_size: usize,
    /// JMPREL（.rela.plt）地址
    jmprel: u64,
    /// JMPREL 大小
    jmprel_size: usize,
    /// PLTREL 类型（DT_RELA 或 DT_REL）
    pltrel_type: u8,
    /// 字符串表地址
    strtab: u64,
    /// 符号表地址
    symtab: u64,
    /// hash 表地址（用于计算符号表大小）
    hash: u64,
    /// GNU hash 表地址
    gnu_hash: u64,
}

/// 反射注入器
///
/// 实现完全无文件落地的内存反射注入。
/// 通过手动解析 ELF 文件并逐段映射到目标进程内存中。
#[cfg(any(target_os = "linux", target_os = "android"))]
pub struct ReflectInjector {
    /// 底层 ptrace 操作器
    ptrace: super::ptrace_inject::PtraceInjector,
    /// 是否已附加
    attached: bool,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl ReflectInjector {
    /// 创建新的反射注入器实例
    pub fn new() -> Self {
        ReflectInjector {
            ptrace: super::ptrace_inject::PtraceInjector::new(),
            attached: false,
        }
    }

    /// 将共享库数据反射注入到目标进程
    ///
    /// 完全在内存中完成注入，不写磁盘。
    ///
    /// # 参数
    /// - `pid`: 目标进程 ID
    /// - `lib_data`: 共享库的 ELF 文件数据（从内存中读取或网络接收）
    ///
    /// # 流程
    /// 1. 解析 ELF header
    /// 2. 枚举所有 PT_LOAD 段
    /// 3. 在目标进程中分配对应内存
    /// 4. 写入各段数据
    /// 5. 处理重定位
    /// 6. 调用 .init_array
    pub fn inject(&mut self, pid: ProcessId, lib_data: &[u8]) -> crate::Result<u64> {
        log::info!(
            "反射注入开始: PID={}, 库大小={} 字节",
            pid.0,
            lib_data.len()
        );

        // 附加到目标进程
        self.ptrace.attach(pid)?;
        self.attached = true;

        let result = self.inject_inner(pid, lib_data);

        // 无论成功失败都尝试脱离
        let detach_result = self.ptrace.detach();
        self.attached = false;

        if let Err(e) = detach_result {
            log::warn!("ptrace detach 失败: {}", e);
        }

        result
    }

    /// 内部注入实现
    fn inject_inner(
        &mut self,
        pid: ProcessId,
        lib_data: &[u8],
    ) -> crate::Result<u64> {
        // 1. 解析 ELF header
        let mut elf_info = self.parse_elf(lib_data)?;

        log::info!(
            "ELF 解析完成: {}bit, PT_LOAD 段数={}, 动态段={}",
            if elf_info.is_64bit { 64 } else { 32 },
            elf_info.load_segments.len(),
            elf_info.dynamic.is_some()
        );

        // 2. 计算基地址并分配所有 PT_LOAD 段的内存
        let base_addr = self.map_segments(pid, &elf_info)?;

        // 3. 将数据写入目标进程（传入原始 ELF 数据）
        self.write_segments(pid, &elf_info, base_addr, lib_data)?;

        // 更新 load_bias
        elf_info.load_bias = base_addr;

        // 4. 处理重定位
        if let Some(ref dynamic) = elf_info.dynamic {
            self.process_relocations(pid, &elf_info, dynamic, base_addr)?;
        }

        // 5. 调用 .init_array
        if let Some(ref dynamic) = elf_info.dynamic {
            self.call_init_array(pid, dynamic, base_addr)?;
        }

        log::info!(
            "反射注入完成，基地址: {:#x}",
            base_addr
        );

        Ok(base_addr)
    }

    /// 解析 ELF header
    ///
    /// 验证 ELF 魔数，提取 header 信息，
    /// 解析 program headers 和 dynamic section。
    fn parse_elf(&self, data: &[u8]) -> crate::Result<ElfInfo> {
        // 验证 ELF 魔数
        if data.len() < 64 {
            return Err(FridaError::ElfLoad {
                path: std::path::PathBuf::from("<memory>"),
                detail: "ELF 数据太短，无法解析 header".to_string(),
            }
            .into());
        }

        // 检查 ELF 魔数: 0x7F ELF
        if data[0] != 0x7F || data[1] != b'E' || data[2] != b'L' || data[3] != b'F' {
            return Err(FridaError::ElfLoad {
                path: std::path::PathBuf::from("<memory>"),
                detail: format!(
                    "无效的 ELF 魔数: {:02x} {:02x} {:02x} {:02x}",
                    data[0], data[1], data[2], data[3]
                ),
            }
            .into());
        }

        // 判断是 32 位还是 64 位
        let is_64bit = data[4] == 2; // EI_CLASS: 1=32bit, 2=64bit

        // 检查是否是共享库 (ET_DYN)
        let e_type = if is_64bit {
            let e_type_bytes: [u8; 2] = [data[16], data[17]];
            u16::from_le_bytes(e_type_bytes)
        } else {
            let e_type_bytes: [u8; 2] = [data[16], data[17]];
            u16::from_le_bytes(e_type_bytes)
        };

        if e_type != 3 {
            // ET_DYN = 3
            log::warn!(
                "ELF 类型不是共享库 (ET_DYN)，类型={}, 可能无法正常工作",
                e_type
            );
        }

        let (entry, phoff, phnum, phentsize) = if is_64bit {
            let entry = u64::from_le_bytes([
                data[24], data[25], data[26], data[27],
                data[28], data[29], data[30], data[31],
            ]);
            let phoff = u64::from_le_bytes([
                data[32], data[33], data[34], data[35],
                data[36], data[37], data[38], data[39],
            ]);
            let phentsize = u16::from_le_bytes([data[54], data[55]]);
            let phnum = u16::from_le_bytes([data[56], data[57]]);
            (entry, phoff, phnum, phentsize)
        } else {
            let entry = u32::from_le_bytes([data[24], data[25], data[26], data[27]]) as u64;
            let phoff = u32::from_le_bytes([data[28], data[29], data[30], data[31]]) as u64;
            let phentsize = u16::from_le_bytes([data[42], data[43]]);
            let phnum = u16::from_le_bytes([data[44], data[45]]);
            (entry, phoff, phnum, phentsize)
        };

        log::debug!(
            "ELF header: {}bit, entry={:#x}, phoff={:#x}, phnum={}, phentsize={}",
            if is_64bit { 64 } else { 32 },
            entry,
            phoff,
            phnum,
            phentsize
        );

        // 解析 program headers，收集 PT_LOAD 段
        let mut load_segments = Vec::new();
        let mut dynamic_info = None;

        for i in 0..phnum {
            let offset = phoff as usize + i as usize * phentsize as usize;
            if offset + phentsize as usize > data.len() {
                break;
            }

            let ph_data = &data[offset..offset + phentsize as usize];

            let (p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz, p_align) = if is_64bit {
                (
                    u32::from_le_bytes([ph_data[0], ph_data[1], ph_data[2], ph_data[3]]),
                    u32::from_le_bytes([ph_data[4], ph_data[5], ph_data[6], ph_data[7]]),
                    u64::from_le_bytes([
                        ph_data[8], ph_data[9], ph_data[10], ph_data[11],
                        ph_data[12], ph_data[13], ph_data[14], ph_data[15],
                    ]),
                    u64::from_le_bytes([
                        ph_data[16], ph_data[17], ph_data[18], ph_data[19],
                        ph_data[20], ph_data[21], ph_data[22], ph_data[23],
                    ]),
                    u64::from_le_bytes([
                        ph_data[32], ph_data[33], ph_data[34], ph_data[35],
                        ph_data[36], ph_data[37], ph_data[38], ph_data[39],
                    ]),
                    u64::from_le_bytes([
                        ph_data[40], ph_data[41], ph_data[42], ph_data[43],
                        ph_data[44], ph_data[45], ph_data[46], ph_data[47],
                    ]),
                    u64::from_le_bytes([
                        ph_data[48], ph_data[49], ph_data[50], ph_data[51],
                        ph_data[52], ph_data[53], ph_data[54], ph_data[55],
                    ]),
                )
            } else {
                (
                    u32::from_le_bytes([ph_data[0], ph_data[1], ph_data[2], ph_data[3]]),
                    u32::from_le_bytes([ph_data[24], ph_data[25], ph_data[26], ph_data[27]]),
                    u32::from_le_bytes([ph_data[4], ph_data[5], ph_data[6], ph_data[7]]) as u64,
                    u32::from_le_bytes([ph_data[8], ph_data[9], ph_data[10], ph_data[11]]) as u64,
                    u32::from_le_bytes([ph_data[16], ph_data[17], ph_data[18], ph_data[19]]) as u64,
                    u32::from_le_bytes([ph_data[20], ph_data[21], ph_data[22], ph_data[23]]) as u64,
                    u32::from_le_bytes([ph_data[28], ph_data[29], ph_data[30], ph_data[31]]) as u64,
                )
            };

            // PT_LOAD = 1
            if p_type == 1 {
                // 计算内存保护权限
                let prot = self.flags_to_prot(p_flags);

                load_segments.push(LoadSegment {
                    file_offset: p_offset,
                    vaddr: p_vaddr,
                    file_size: p_filesz,
                    mem_size: p_memsz,
                    prot,
                    align: p_align,
                });

                log::debug!(
                    "PT_LOAD: offset={:#x}, vaddr={:#x}, filesz={}, memsz={}, prot={:o}",
                    p_offset,
                    p_vaddr,
                    p_filesz,
                    p_memsz,
                    prot
                );
            }
            // PT_DYNAMIC = 2
            else if p_type == 2 {
                dynamic_info = Some(self.parse_dynamic(data, p_offset as usize, is_64bit)?);
            }
        }

        Ok(ElfInfo {
            is_64bit,
            entry,
            phoff,
            phnum,
            phentsize,
            load_bias: 0,
            load_segments,
            dynamic: dynamic_info,
        })
    }

    /// 解析 PT_DYNAMIC 段
    ///
    /// 遍历动态段条目，提取 .init_array、重定位表等信息。
    fn parse_dynamic(
        &self,
        data: &[u8],
        dyn_offset: usize,
        is_64bit: bool,
    ) -> crate::Result<DynamicInfo> {
        let mut info = DynamicInfo {
            init_array: 0,
            init_array_size: 0,
            fini_array: 0,
            fini_array_size: 0,
            init_func: 0,
            fini_func: 0,
            got: 0,
            rela: 0,
            rela_size: 0,
            rel: 0,
            rel_size: 0,
            jmprel: 0,
            jmprel_size: 0,
            pltrel_type: 0,
            strtab: 0,
            symtab: 0,
            hash: 0,
            gnu_hash: 0,
        };

        let entry_size = if is_64bit { 16 } else { 8 };
        let mut offset = dyn_offset;

        loop {
            if offset + entry_size > data.len() {
                break;
            }

            let entry = &data[offset..offset + entry_size];
            offset += entry_size;

            let (tag, val) = if is_64bit {
                (
                    u64::from_le_bytes([
                        entry[0], entry[1], entry[2], entry[3],
                        entry[4], entry[5], entry[6], entry[7],
                    ]),
                    u64::from_le_bytes([
                        entry[8], entry[9], entry[10], entry[11],
                        entry[12], entry[13], entry[14], entry[15],
                    ]),
                )
            } else {
                (
                    u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]) as u64,
                    u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]) as u64,
                )
            };

            // DT_NULL 标记动态段结束
            if tag == 0 {
                break;
            }

            match tag {
                25 => info.init_func = val,            // DT_INIT = 25
                26 => info.fini_func = val,            // DT_FINI = 26
                12 => info.init_array = val,           // DT_INIT_ARRAY = 12
                27 => info.init_array_size = val as usize, // DT_INIT_ARRAYSZ
                13 => info.fini_array = val,           // DT_FINI_ARRAY = 13
                28 => info.fini_array_size = val as usize, // DT_FINI_ARRAYSZ
                3 => info.got = val,                    // DT_PLTGOT
                7 => info.rela = val,                   // DT_RELA
                8 => info.rela_size = val as usize,     // DT_RELASZ
                17 => info.rel = val,                   // DT_REL
                18 => info.rel_size = val as usize,     // DT_RELSZ
                23 => info.jmprel = val,                // DT_JMPREL
                2 => info.pltrel_type = val as u8,      // DT_PLTREL
                5 => info.strtab = val,                 // DT_STRTAB
                6 => info.symtab = val,                 // DT_SYMTAB
                4 => info.hash = val,                   // DT_HASH
                0x6ffffef5 => info.gnu_hash = val,      // DT_GNU_HASH
                20 => info.jmprel_size = val as usize,  // DT_PLTRELSZ
                _ => {}
            }
        }

        log::debug!("动态段解析完成:");
        log::debug!("  init_array = {:#x}, size = {}", info.init_array, info.init_array_size);
        log::debug!("  rela = {:#x}, size = {}", info.rela, info.rela_size);
        log::debug!("  jmprel = {:#x}, size = {}", info.jmprel, info.jmprel_size);

        Ok(info)
    }

    /// 将 p_flags 转换为内存保护权限
    fn flags_to_prot(&self, flags: u32) -> libc::c_int {
        let mut prot = 0;
        if flags & 0x4 != 0 {
            prot |= libc::PROT_READ;
        }
        if flags & 0x2 != 0 {
            prot |= libc::PROT_WRITE;
        }
        if flags & 0x1 != 0 {
            prot |= libc::PROT_EXEC;
        }
        prot
    }

    /// 在目标进程中映射所有 PT_LOAD 段
    ///
    /// 为每个 PT_LOAD 段分配远程内存，返回库的基地址。
    fn map_segments(
        &mut self,
        pid: ProcessId,
        elf: &ElfInfo,
    ) -> crate::Result<u64> {
        if elf.load_segments.is_empty() {
            return Err(FridaError::ElfLoad {
                path: std::path::PathBuf::from("<memory>"),
                detail: "没有找到 PT_LOAD 段".to_string(),
            }
            .into());
        }

        // 计算最低的虚拟地址作为基地址偏移参考
        let min_vaddr = elf
            .load_segments
            .iter()
            .map(|s| s.vaddr)
            .min()
            .unwrap_or(0);

        // 使用目标进程的 mmap 分配一段连续的虚拟地址空间
        // 计算总大小
        let max_vaddr = elf
            .load_segments
            .iter()
            .map(|s| {
                let aligned_end = (s.vaddr + s.mem_size + 0xFFF) & !0xFFF;
                aligned_end
            })
            .max()
            .unwrap_or(0);

        let total_size = (max_vaddr - min_vaddr) as usize;

        // 分配一块足够大的 RWX 内存
        let base_addr = self.ptrace.alloc_remote(pid, total_size)?;

        log::info!(
            "段映射: 基地址={:#x}, 总大小={} 字节, PT_LOAD 段数={}",
            base_addr,
            total_size,
            elf.load_segments.len()
        );

        Ok(base_addr)
    }

    /// 将所有 PT_LOAD 段的数据写入目标进程
    ///
    /// 从 ELF 数据中提取每个段的内容并写入到目标进程的对应位置。
    fn write_segments(
        &mut self,
        pid: ProcessId,
        elf: &ElfInfo,
        base_addr: u64,
        lib_data: &[u8],
    ) -> crate::Result<()> {
        let min_vaddr = elf
            .load_segments
            .iter()
            .map(|s| s.vaddr)
            .min()
            .unwrap_or(0);

        for segment in &elf.load_segments {
            let remote_addr = base_addr + (segment.vaddr - min_vaddr);

            // 写入段数据（文件中有数据的部分）
            if segment.file_size > 0 {
                let file_start = segment.file_offset as usize;
                let file_end = file_start + segment.file_size as usize;

                // 检查是否在 ELF 数据范围内
                if file_end <= lib_data.len() {
                    let segment_data = &lib_data[file_start..file_end];

                    // 写入目标进程内存
                    self.ptrace.write_remote(
                        pid,
                        remote_addr as usize,
                        segment_data,
                    )?;

                    log::debug!(
                        "写入段: vaddr={:#x} -> remote={:#x}, 文件大小={}",
                        segment.vaddr,
                        remote_addr,
                        segment.file_size
                    );
                } else {
                    log::warn!(
                        "段数据超出 ELF 文件范围: offset={:#x}, size={}, 文件大小={}",
                        segment.file_offset,
                        segment.file_size,
                        lib_data.len()
                    );
                }
            }

            // BSS 部分（mem_size > file_size）自动被 mmap 的零初始化覆盖
            let bss_size = segment.mem_size.saturating_sub(segment.file_size);
            if bss_size > 0 {
                log::debug!(
                    "BSS 区域: remote={:#x}, 大小={}",
                    remote_addr + segment.file_size,
                    bss_size
                );
            }
        }

        Ok(())
    }

    /// 处理 ELF 重定位
    ///
    /// 遍历 RELA / REL / JMPREL 重定位表，根据重定位类型进行符号解析和地址修正：
    /// - R_*_RELATIVE: 直接加上基地址
    /// - R_*_GLOB_DAT / R_*_JUMP_SLOT: 查找符号名称并在目标进程中解析地址
    ///
    /// 支持 aarch64 和 x86_64 两种架构的重定位类型。
    fn process_relocations(
        &mut self,
        pid: ProcessId,
        elf: &ElfInfo,
        dynamic: &DynamicInfo,
        base_addr: u64,
    ) -> crate::Result<()> {
        log::info!("处理重定位: base_addr={:#x}", base_addr);

        let min_vaddr = elf
            .load_segments
            .iter()
            .map(|s| s.vaddr)
            .min()
            .unwrap_or(0);

        // 处理 RELA 重定位表（.rela.dyn）
        if dynamic.rela != 0 && dynamic.rela_size > 0 {
            log::debug!(
                "处理 RELA 重定位: addr={:#x}, size={}",
                dynamic.rela,
                dynamic.rela_size
            );
            // 将虚拟地址转换为远程地址（加上基地址偏移）
            let remote_rela_addr = base_addr + (dynamic.rela - min_vaddr);
            self.process_rela_relocations(
                pid,
                remote_rela_addr,
                dynamic.rela_size,
                dynamic,
                base_addr,
                elf,
            )?;
        }

        // 处理 JMPREL 重定位表（.rela.plt / .rel.plt）
        if dynamic.jmprel != 0 && dynamic.jmprel_size > 0 {
            log::debug!(
                "处理 JMPREL 重定位: addr={:#x}, size={}, pltrel_type={}",
                dynamic.jmprel,
                dynamic.jmprel_size,
                dynamic.pltrel_type
            );
            let remote_jmprel_addr = base_addr + (dynamic.jmprel - min_vaddr);

            if dynamic.pltrel_type == 7 {
                // DT_RELA = 7，JMPREL 使用 RELA 格式
                self.process_rela_relocations(
                    pid,
                    remote_jmprel_addr,
                    dynamic.jmprel_size,
                    dynamic,
                    base_addr,
                    elf,
                )?;
            } else {
                // DT_REL = 17，JMPREL 使用 REL 格式
                self.process_rel_relocations(
                    pid,
                    remote_jmprel_addr,
                    dynamic.jmprel_size,
                    dynamic,
                    base_addr,
                    elf,
                )?;
            }
        }

        // 处理 REL 重定位表（.rel.dyn）
        if dynamic.rel != 0 && dynamic.rel_size > 0 {
            log::debug!(
                "处理 REL 重定位: addr={:#x}, size={}",
                dynamic.rel,
                dynamic.rel_size
            );
            let remote_rel_addr = base_addr + (dynamic.rel - min_vaddr);
            self.process_rel_relocations(
                pid,
                remote_rel_addr,
                dynamic.rel_size,
                dynamic,
                base_addr,
                elf,
            )?;
        }

        log::info!("重定位处理完成");
        Ok(())
    }

    /// 处理 RELA 格式重定位条目
    ///
    /// RELA 条目结构（24 字节）:
    /// - r_offset (8B): 需要重定位的地址（GOT 条目地址）
    /// - r_info   (8B): 符号索引 + 重定位类型
    /// - r_addend (8B): 加数
    ///
    /// 支持的重定位类型:
    /// - aarch64: R_AARCH64_RELATIVE(0x403), R_AARCH64_GLOB_DAT(0x401), R_AARCH64_JUMP_SLOT(0x402)
    /// - x86_64:  R_X86_64_RELATIVE(8), R_X86_64_GLOB_DAT(6), R_X86_64_JUMP_SLOT(7)
    fn process_rela_relocations(
        &mut self,
        pid: ProcessId,
        remote_table_addr: u64,
        table_size: usize,
        dynamic: &DynamicInfo,
        base_addr: u64,
        _elf: &ElfInfo,
    ) -> crate::Result<()> {
        // 从远程进程读取重定位表
        let rela_data = self
            .ptrace
            .read_remote(pid, remote_table_addr as usize, table_size)?;

        let rela_entry_size = 24; // Elf64_Rela: 8 + 8 + 8 = 24 字节
        let entry_count = table_size / rela_entry_size;

        let mut resolved_count = 0u32;
        let mut skipped_count = 0u32;

        for i in 0..entry_count {
            let offset = i * rela_entry_size;
            if offset + rela_entry_size > rela_data.len() {
                break;
            }

            let entry = &rela_data[offset..offset + rela_entry_size];

            // 解析 RELA 条目
            let r_offset = u64::from_le_bytes([
                entry[0], entry[1], entry[2], entry[3],
                entry[4], entry[5], entry[6], entry[7],
            ]);
            let r_info = u64::from_le_bytes([
                entry[8], entry[9], entry[10], entry[11],
                entry[12], entry[13], entry[14], entry[15],
            ]);
            let r_addend = i64::from_le_bytes([
                entry[16], entry[17], entry[18], entry[19],
                entry[20], entry[21], entry[22], entry[23],
            ]);

            // 提取重定位类型和符号索引
            let reloc_type = (r_info >> 32) as u32;
            let _sym_idx = (r_info & 0xFFFFFFFF) as u32;

            // 计算 GOT 条目在远程进程中的实际地址
            let got_entry_remote = base_addr + r_offset;

            match reloc_type {
                // ===== AArch64 重定位类型 =====
                // R_AARCH64_RELATIVE (0x403): 基地址 + addend
                0x403 => {
                    let resolved_addr = (base_addr as i64 + r_addend) as u64;
                    self.write_relocation_value(pid, got_entry_remote, resolved_addr)?;
                    resolved_count += 1;
                }

                // R_AARCH64_GLOB_DAT (0x401): 全局数据引用
                0x401 => {
                    match self.resolve_relocation_symbol(
                        pid,
                        dynamic,
                        base_addr,
                        _sym_idx as usize,
                        r_addend,
                    )? {
                        Some(addr) => {
                            self.write_relocation_value(pid, got_entry_remote, addr)?;
                            resolved_count += 1;
                        }
                        None => {
                            log::debug!(
                                "RELA[{}]: R_AARCH64_GLOB_DAT 符号解析失败, sym_idx={}, offset={:#x}",
                                i, _sym_idx, r_offset
                            );
                            skipped_count += 1;
                        }
                    }
                }

                // R_AARCH64_JUMP_SLOT (0x402): PLT 跳转槽
                0x402 => {
                    match self.resolve_relocation_symbol(
                        pid,
                        dynamic,
                        base_addr,
                        _sym_idx as usize,
                        r_addend,
                    )? {
                        Some(addr) => {
                            self.write_relocation_value(pid, got_entry_remote, addr)?;
                            resolved_count += 1;
                        }
                        None => {
                            log::debug!(
                                "RELA[{}]: R_AARCH64_JUMP_SLOT 符号解析失败, sym_idx={}, offset={:#x}",
                                i, _sym_idx, r_offset
                            );
                            skipped_count += 1;
                        }
                    }
                }

                // ===== x86_64 重定位类型 =====
                // R_X86_64_RELATIVE (8): 基地址 + addend
                8 => {
                    let resolved_addr = (base_addr as i64 + r_addend) as u64;
                    self.write_relocation_value(pid, got_entry_remote, resolved_addr)?;
                    resolved_count += 1;
                }

                // R_X86_64_GLOB_DAT (6): 全局数据引用
                6 => {
                    match self.resolve_relocation_symbol(
                        pid,
                        dynamic,
                        base_addr,
                        _sym_idx as usize,
                        r_addend,
                    )? {
                        Some(addr) => {
                            self.write_relocation_value(pid, got_entry_remote, addr)?;
                            resolved_count += 1;
                        }
                        None => {
                            log::debug!(
                                "RELA[{}]: R_X86_64_GLOB_DAT 符号解析失败, sym_idx={}, offset={:#x}",
                                i, _sym_idx, r_offset
                            );
                            skipped_count += 1;
                        }
                    }
                }

                // R_X86_64_JUMP_SLOT (7): PLT 跳转槽
                7 => {
                    match self.resolve_relocation_symbol(
                        pid,
                        dynamic,
                        base_addr,
                        _sym_idx as usize,
                        r_addend,
                    )? {
                        Some(addr) => {
                            self.write_relocation_value(pid, got_entry_remote, addr)?;
                            resolved_count += 1;
                        }
                        None => {
                            log::debug!(
                                "RELA[{}]: R_X86_64_JUMP_SLOT 符号解析失败, sym_idx={}, offset={:#x}",
                                i, _sym_idx, r_offset
                            );
                            skipped_count += 1;
                        }
                    }
                }

                // R_X86_64_64 (1): 绝对 64 位地址
                1 => {
                    if _sym_idx == 0 {
                        // 无符号的绝对地址重定位
                        let resolved_addr = (base_addr as i64 + r_addend) as u64;
                        self.write_relocation_value(pid, got_entry_remote, resolved_addr)?;
                        resolved_count += 1;
                    } else {
                        skipped_count += 1;
                    }
                }

                // 其他未处理的重定位类型
                _ => {
                    log::trace!(
                        "RELA[{}]: 跳过未处理的重定位类型 {:#x}, offset={:#x}",
                        i, reloc_type, r_offset
                    );
                    skipped_count += 1;
                }
            }
        }

        log::debug!(
            "RELA 重定位完成: 共 {} 条, 成功解析 {}, 跳过 {}",
            entry_count, resolved_count, skipped_count
        );

        Ok(())
    }

    /// 处理 REL 格式重定位条目
    ///
    /// REL 条目结构（16 字节）:
    /// - r_offset (8B): 需要重定位的地址
    /// - r_info   (8B): 符号索引 + 重定位类型
    ///
    /// 注意: REL 没有 r_addend 字段，加数隐含在目标位置中。
    fn process_rel_relocations(
        &mut self,
        pid: ProcessId,
        remote_table_addr: u64,
        table_size: usize,
        dynamic: &DynamicInfo,
        base_addr: u64,
        _elf: &ElfInfo,
    ) -> crate::Result<()> {
        // 从远程进程读取重定位表
        let rel_data = self
            .ptrace
            .read_remote(pid, remote_table_addr as usize, table_size)?;

        let rel_entry_size = 16; // Elf64_Rel: 8 + 8 = 16 字节
        let entry_count = table_size / rel_entry_size;

        let mut resolved_count = 0u32;
        let mut skipped_count = 0u32;

        for i in 0..entry_count {
            let offset = i * rel_entry_size;
            if offset + rel_entry_size > rel_data.len() {
                break;
            }

            let entry = &rel_data[offset..offset + rel_entry_size];

            // 解析 REL 条目
            let r_offset = u64::from_le_bytes([
                entry[0], entry[1], entry[2], entry[3],
                entry[4], entry[5], entry[6], entry[7],
            ]);
            let r_info = u64::from_le_bytes([
                entry[8], entry[9], entry[10], entry[11],
                entry[12], entry[13], entry[14], entry[15],
            ]);

            let reloc_type = (r_info >> 32) as u32;
            let _sym_idx = (r_info & 0xFFFFFFFF) as u32;

            // 计算 GOT 条目在远程进程中的实际地址
            let got_entry_remote = base_addr + r_offset;

            match reloc_type {
                // R_X86_64_RELATIVE (8): 需要先读取 GOT 条目中隐含的 addend
                8 => {
                    // 读取 GOT 条目当前的值作为 addend
                    let current_val_data = self
                        .ptrace
                        .read_remote(pid, got_entry_remote as usize, 8)?;
                    let implicit_addend = i64::from_le_bytes([
                        current_val_data[0], current_val_data[1],
                        current_val_data[2], current_val_data[3],
                        current_val_data[4], current_val_data[5],
                        current_val_data[6], current_val_data[7],
                    ]);
                    let resolved_addr = (base_addr as i64 + implicit_addend) as u64;
                    self.write_relocation_value(pid, got_entry_remote, resolved_addr)?;
                    resolved_count += 1;
                }

                // R_X86_64_GLOB_DAT (6)
                6 => {
                    match self.resolve_relocation_symbol(
                        pid,
                        dynamic,
                        base_addr,
                        _sym_idx as usize,
                        0, // REL 无显式 addend
                    )? {
                        Some(addr) => {
                            self.write_relocation_value(pid, got_entry_remote, addr)?;
                            resolved_count += 1;
                        }
                        None => {
                            log::debug!(
                                "REL[{}]: R_X86_64_GLOB_DAT 符号解析失败, sym_idx={}",
                                i, _sym_idx
                            );
                            skipped_count += 1;
                        }
                    }
                }

                // R_X86_64_JUMP_SLOT (7)
                7 => {
                    match self.resolve_relocation_symbol(
                        pid,
                        dynamic,
                        base_addr,
                        _sym_idx as usize,
                        0,
                    )? {
                        Some(addr) => {
                            self.write_relocation_value(pid, got_entry_remote, addr)?;
                            resolved_count += 1;
                        }
                        None => {
                            log::debug!(
                                "REL[{}]: R_X86_64_JUMP_SLOT 符号解析失败, sym_idx={}",
                                i, _sym_idx
                            );
                            skipped_count += 1;
                        }
                    }
                }

                _ => {
                    log::trace!(
                        "REL[{}]: 跳过未处理的重定位类型 {:#x}, offset={:#x}",
                        i, reloc_type, r_offset
                    );
                    skipped_count += 1;
                }
            }
        }

        log::debug!(
            "REL 重定位完成: 共 {} 条, 成功解析 {}, 跳过 {}",
            entry_count, resolved_count, skipped_count
        );

        Ok(())
    }

    /// 解析重定位条目对应的符号地址
    ///
    /// 根据符号索引查找符号名称，然后在目标进程中查找对应符号的地址。
    /// 使用远程进程中的动态链接器（如 dlopen/dlsym）来解析外部符号。
    ///
    /// # 参数
    /// - `pid`: 目标进程 ID
    /// - `dynamic`: 动态段信息（包含 symtab 和 strtab 地址）
    /// - `base_addr`: 库的基地址
    /// - `sym_idx`: 符号在 .dynsym 中的索引
    /// - `addend`: 重定位加数
    ///
    /// # 返回值
    /// 解析成功返回 Some(地址)，失败返回 None
    fn resolve_relocation_symbol(
        &mut self,
        pid: ProcessId,
        dynamic: &DynamicInfo,
        _base_addr: u64,
        sym_idx: usize,
        addend: i64,
    ) -> crate::Result<Option<u64>> {
        // sym_idx == 0 表示无符号（R_*_NONE 或纯地址重定位），跳过
        if sym_idx == 0 {
            return Ok(None);
        }

        // Elf64_Sym 结构大小: 24 字节 (name(4) + info(1) + other(1) + shndx(2) + value(8) + size(8))
        let sym_entry_size: usize = 24;
        let sym_offset = dynamic.symtab + (sym_idx as u64) * (sym_entry_size as u64);

        // 从远程进程读取符号表条目
        let sym_data = self
            .ptrace
            .read_remote(pid, sym_offset as usize, sym_entry_size)?;

        if sym_data.len() < sym_entry_size {
            return Ok(None);
        }

        // 提取 st_name（符号名称在字符串表中的偏移）
        let st_name = u32::from_le_bytes([
            sym_data[0], sym_data[1], sym_data[2], sym_data[3],
        ]);

        // 如果 st_name 为 0，说明无名符号，无法解析
        if st_name == 0 {
            return Ok(None);
        }

        // 从远程进程的字符串表中读取符号名称
        // 限制名称最大长度为 256 字节，防止异常数据
        let str_addr = dynamic.strtab + st_name as u64;
        let name_buf = self.ptrace.read_remote(pid, str_addr as usize, 256)?;

        // 查找字符串结束符（null terminator）
        let name_len = name_buf
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(name_buf.len());
        let name = match std::str::from_utf8(&name_buf[..name_len]) {
            Ok(s) => s.to_string(),
            Err(_) => {
                log::debug!("符号名称不是有效的 UTF-8, sym_idx={}", sym_idx);
                return Ok(None);
            }
        };

        if name.is_empty() {
            return Ok(None);
        }

        log::debug!(
            "解析符号: sym_idx={}, name='{}', addend={}",
            sym_idx, name, addend
        );

        // 在目标进程中查找符号地址
        // 通过读取 /proc/pid/maps 获取已加载模块，
        // 然后在模块的符号表中查找
        let resolved_addr = self.find_symbol_in_target(pid, &name)?;

        if let Some(addr) = resolved_addr {
            // 加上 addend（通常为 0）
            let final_addr = (addr as i64 + addend) as u64;
            log::debug!(
                "符号 '{}' 解析成功: addr={:#x}, addend={}, final={:#x}",
                name, addr, addend, final_addr
            );
            Ok(Some(final_addr))
        } else {
            log::debug!("符号 '{}' 在目标进程中未找到", name);
            Ok(None)
        }
    }

    /// 在目标进程中查找指定符号的地址
    ///
    /// 通过解析 /proc/pid/maps 获取已加载的共享库列表，
    /// 然后在 libc 等基础库中查找常见符号。
    fn find_symbol_in_target(
        &mut self,
        pid: ProcessId,
        symbol_name: &str,
    ) -> crate::Result<Option<u64>> {
        // 读取 /proc/pid/maps 获取已加载模块列表
        let maps_path = format!("/proc/{}/maps", pid.0);
        let maps_content = match std::fs::read_to_string(&maps_path) {
            Ok(content) => content,
            Err(e) => {
                log::debug!("读取 {} 失败: {}", maps_path, e);
                return Ok(None);
            }
        };

        // 收集已加载的共享库及其基地址
        // 格式: address           perms offset  dev   inode   pathname
        let mut modules: Vec<(u64, u64, String)> = Vec::new(); // (start, end, path)

        for line in maps_content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 6 {
                continue;
            }

            let addr_range = parts[0];
            let perms = parts[1];
            let path = parts[5];

            // 只关注可执行映射且是文件映射（排除 [heap], [stack] 等）
            if !perms.contains('x') || path.starts_with('[') {
                continue;
            }

            // 解析地址范围
            if let Some(mid) = addr_range.find('-') {
                let start_str = &addr_range[..mid];
                let end_str = &addr_range[mid + 1..];
                if let (Ok(start), Ok(end)) = (
                    u64::from_str_radix(start_str, 16),
                    u64::from_str_radix(end_str, 16),
                ) {
                    modules.push((start, end, path.to_string()));
                }
            }
        }

        // 去重（同一文件可能有多行映射，只保留第一个可执行段）
        let mut seen = std::collections::HashSet::new();
        modules.retain(|(_, _, path)| {
            if seen.contains(path) {
                false
            } else {
                seen.insert(path.clone());
                true
            }
        });

        // 对于每个加载的模块，尝试读取其 ELF 头来查找符号
        for (mod_start, _mod_end, mod_path) in &modules {
            // 提取模块文件名（去除路径前缀）
            let mod_name = std::path::Path::new(mod_path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");

            // 优先在 libc 中查找（最常见的依赖库）
            let should_check = mod_name.contains("libc")
                || mod_name.contains("libdl")
                || mod_name.contains("libm")
                || mod_name.contains("libpthread")
                || mod_name.contains("librt")
                || mod_name.contains("ld-linux")
                || mod_name.contains("linker");

            if !should_check {
                continue;
            }

            // 尝试读取模块的 ELF 数据来查找符号
            if let Ok(mod_data) = std::fs::read(mod_path) {
                // 使用 elf_parser 查找符号
                if let Ok(elf_info) = crate::memory::elf_parser::parse_elf(&mod_data) {
                    if let Some(sym_value) = crate::memory::elf_parser::find_symbol(&elf_info, symbol_name) {
                        // sym_value 是符号在库中的偏移量，加上模块基地址
                        let resolved = mod_start + sym_value;
                        log::debug!(
                            "在模块 '{}' 中找到符号 '{}': base={:#x}, offset={:#x}, addr={:#x}",
                            mod_name, symbol_name, mod_start, sym_value, resolved
                        );
                        return Ok(Some(resolved));
                    }
                }
            }
        }

        // 如果在常见库中没找到，尝试读取 linker（动态链接器自身）来解析
        // 在 Android/Linux 上，linker 通常提供 dlsym 功能
        // 但由于我们无法远程调用 dlsym（需要额外的 shellcode），
        // 这里只做静态解析
        Ok(None)
    }

    /// 将重定位值写入目标进程的 GOT 条目
    ///
    /// 写入 8 字节（64 位地址）到指定远程地址。
    fn write_relocation_value(
        &mut self,
        pid: ProcessId,
        remote_addr: u64,
        value: u64,
    ) -> crate::Result<()> {
        let value_bytes = value.to_le_bytes();
        self.ptrace
            .write_remote(pid, remote_addr as usize, &value_bytes)?;

        log::trace!(
            "写入重定位值: addr={:#x}, value={:#x}",
            remote_addr,
            value
        );
        Ok(())
    }

    /// 调用 .init_array 中的初始化函数
    ///
    /// 依次远程调用 .init_array 中的每个函数指针。
    /// 这些函数通常用于 C++ 全局构造函数等初始化逻辑。
    fn call_init_array(
        &mut self,
        pid: ProcessId,
        dynamic: &DynamicInfo,
        base_addr: u64,
    ) -> crate::Result<()> {
        if dynamic.init_array == 0 || dynamic.init_array_size == 0 {
            log::debug!("没有 .init_array 需要调用");
            return Ok(());
        }

        let entry_size = if true { 8 } else { 4 }; // 64位为8字节，32位为4字节
        let count = dynamic.init_array_size / entry_size;

        log::info!(
            "调用 .init_array: addr={:#x}, 共 {} 个函数",
            dynamic.init_array,
            count
        );

        let tid = pid.0 as i32;

        for i in 0..count {
            // 读取函数指针
            let func_ptr_addr = dynamic.init_array + i as u64 * entry_size as u64;
            let func_addr_data = self
                .ptrace
                .read_remote(pid, func_ptr_addr as usize, entry_size)?;

            let func_addr = if entry_size == 8 {
                u64::from_le_bytes([
                    func_addr_data[0],
                    func_addr_data[1],
                    func_addr_data[2],
                    func_addr_data[3],
                    func_addr_data[4],
                    func_addr_data[5],
                    func_addr_data[6],
                    func_addr_data[7],
                ])
            } else {
                u32::from_le_bytes([
                    func_addr_data[0],
                    func_addr_data[1],
                    func_addr_data[2],
                    func_addr_data[3],
                ]) as u64
            };

            // 跳过空指针
            if func_addr == 0 {
                continue;
            }

            // 计算实际的函数地址（加上基地址偏移）
            // 注意: 对于 PIE 库，.init_array 中的地址可能已经是最终地址
            let actual_addr = if func_addr < base_addr {
                func_addr // 已经是绝对地址（很少见）
            } else {
                func_addr // 保持原样
            };

            log::debug!(
                "调用 .init_array[{}]: func_addr = {:#x}",
                i,
                actual_addr
            );

            // 远程调用初始化函数
            let _ = self.ptrace.call_remote(tid, actual_addr, &[]);
        }

        // 调用 .init 函数（如果存在）
        if dynamic.init_func != 0 {
            log::debug!("调用 .init: func_addr = {:#x}", dynamic.init_func);
            let _ = self.ptrace.call_remote(tid, dynamic.init_func, &[]);
        }

        log::info!(".init_array 调用完成");
        Ok(())
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl Default for ReflectInjector {
    fn default() -> Self {
        Self::new()
    }
}

// 非 Linux 平台的占位实现
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub struct ReflectInjector {
    _private: (),
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
impl ReflectInjector {
    pub fn new() -> Self {
        ReflectInjector { _private: () }
    }

    pub fn inject(&mut self, _pid: ProcessId, _lib_data: &[u8]) -> crate::Result<u64> {
        Err(crate::FridaError::Unsupported {
            reason: "反射注入仅支持 Linux/Android 平台".to_string(),
        }
        .into())
    }
}
