//! ELF 解析器
//!
//! 使用 goblin 库解析 ELF 文件，提取段信息、节信息、符号表、导入导出表等。
//!
//! ## 功能
//! - 解析 ELF 头和程序头/节头
//! - 提取动态符号表 (.dynsym) 和普通符号表 (.symtab)
//! - 区分导入符号和导出符号
//! - 查找指定符号的地址偏移
//! - 查找指定节区的信息

use crate::Result;
use std::collections::HashMap;

// ======================== 数据结构 ========================

/// 符号条目
#[derive(Debug, Clone)]
pub struct SymbolEntry {
    /// 符号名称
    pub name: String,
    /// 符号值（地址偏移）
    pub value: u64,
    /// 符号大小
    pub size: u64,
    /// 符号类型（FUNC, OBJECT, NOTYPE 等）
    pub sym_type: SymbolType,
    /// 绑定类型（LOCAL, GLOBAL, WEAK）
    pub bind: SymbolBind,
    /// 所属 section 索引
    pub section_index: u16,
}

/// 符号类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolType {
    /// 未指定类型
    NoType,
    /// 数据对象
    Object,
    /// 函数
    Func,
    /// 段
    Section,
    /// 文件
    File,
    /// 动态链接符号
    Dynamic,
    /// 其他
    Other(u8),
}

/// 符号绑定类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolBind {
    /// 局部符号
    Local,
    /// 全局符号
    Global,
    /// 弱符号
    Weak,
    /// 其他
    Other(u8),
}

/// 节区信息
#[derive(Debug, Clone)]
pub struct SectionInfo {
    /// 节区名称
    pub name: String,
    /// 节区类型（SHT_*）
    pub section_type: u64,
    /// 节区虚拟地址
    pub addr: u64,
    /// 节区文件偏移
    pub offset: u64,
    /// 节区大小
    pub size: u64,
    /// 节区标志
    pub flags: u64,
}

/// ELF 文件完整解析结果
#[derive(Debug, Clone)]
pub struct ElfInfo {
    /// ELF 类别（32/64 位）
    pub elf_class: u8,
    /// 数据编码（小端/大端）
    pub elf_data: u8,
    /// 机器架构
    pub machine: u16,
    /// 入口点地址
    pub entry_point: u64,
    /// 程序头（段）信息
    pub headers: Vec<SegmentInfo>,
    /// 节区信息
    pub sections: Vec<SectionInfo>,
    /// 所有符号
    pub symbols: Vec<SymbolEntry>,
    /// 导入符号（UND section 中的符号）
    pub imports: Vec<SymbolEntry>,
    /// 导出符号（GLOBAL/FUNC 且非 UND）
    pub exports: Vec<SymbolEntry>,
    /// 节区名称到索引的映射
    pub section_name_map: HashMap<String, usize>,
}

/// 程序段信息
#[derive(Debug, Clone)]
pub struct SegmentInfo {
    /// 段类型（PT_*）
    pub segment_type: u32,
    /// 段在文件中的偏移
    pub offset: u64,
    /// 段在内存中的虚拟地址
    pub vaddr: u64,
    /// 段在内存中的物理地址
    pub paddr: u64,
    /// 段在文件中的大小
    pub file_size: u64,
    /// 段在内存中的大小
    pub mem_size: u64,
    /// 段标志（PF_R, PF_W, PF_X）
    pub flags: u32,
    /// 段对齐
    pub align: u64,
}

// ======================== 解析函数 ========================

/// 解析 ELF 文件
///
/// # 参数
/// - `data`: ELF 文件的原始字节数据
///
/// # 返回值
/// 返回完整的 ELF 解析结果
pub fn parse_elf(data: &[u8]) -> Result<ElfInfo> {
    use goblin::Object;

    let elf = match Object::parse(data) {
        Ok(goblin::Object::Elf(elf)) => elf,
        Ok(_) => {
            return Err(crate::FridaError::ElfLoad {
                path: std::path::PathBuf::from("<memory>"),
                detail: "不是 ELF 文件".to_string(),
            }
            .into());
        }
        Err(e) => {
            return Err(crate::FridaError::ElfLoad {
                path: std::path::PathBuf::from("<memory>"),
                detail: format!("ELF 解析失败: {}", e),
            }
            .into());
        }
    };

    // 解析程序头（段信息）
    let headers: Vec<SegmentInfo> = elf
        .program_headers
        .iter()
        .map(|ph| SegmentInfo {
            segment_type: ph.p_type,
            offset: ph.p_offset,
            vaddr: ph.p_vaddr,
            paddr: ph.p_paddr,
            file_size: ph.p_filesz,
            mem_size: ph.p_memsz,
            flags: ph.p_flags,
            align: ph.p_align,
        })
        .collect();

    // 解析节区信息
    let mut sections = Vec::new();
    let mut section_name_map = HashMap::new();

    for (i, sh) in elf.section_headers.iter().enumerate() {
        let name = elf
            .shdr_strtab
            .get_at(sh.sh_name)
            .unwrap_or("<unknown>")
            .to_string();

        section_name_map.insert(name.clone(), i);

        sections.push(SectionInfo {
            name: name.clone(),
            section_type: sh.sh_type as u64,
            addr: sh.sh_addr,
            offset: sh.sh_offset,
            size: sh.sh_size,
            flags: sh.sh_flags,
        });
    }

    // 解析符号表
    let mut symbols = Vec::new();
    let mut imports = Vec::new();
    let mut exports = Vec::new();

    // 动态符号表（通常用于共享库）
    for sym in &elf.dynsyms {
        if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
            let entry = parse_symbol(name, &sym, &elf);
            let is_import = sym.st_shndx as u32 == goblin::elf::section_header::SHN_UNDEF;

            if is_import {
                imports.push(entry.clone());
            } else if sym.st_bind() == goblin::elf::sym::STB_GLOBAL
                || sym.st_bind() == goblin::elf::sym::STB_WEAK
            {
                exports.push(entry.clone());
            }

            symbols.push(entry);
        }
    }

    // 普通符号表（如果存在）
    for sym in &elf.syms {
        if let Some(name) = elf.strtab.get_at(sym.st_name) {
            // 避免重复添加已存在于 dynsyms 中的符号
            if symbols.iter().any(|s| s.name == name && s.value == sym.st_value) {
                continue;
            }

            let entry = parse_symbol(name, &sym, &elf);
            let is_import = sym.st_shndx as u32 == goblin::elf::section_header::SHN_UNDEF;

            if is_import {
                imports.push(entry.clone());
            } else if sym.st_bind() == goblin::elf::sym::STB_GLOBAL
                || sym.st_bind() == goblin::elf::sym::STB_WEAK
            {
                exports.push(entry.clone());
            }

            symbols.push(entry);
        }
    }

    log::debug!(
        "ELF 解析完成: {} 个段, {} 个节区, {} 个符号 ({} 导出, {} 导入)",
        headers.len(),
        sections.len(),
        symbols.len(),
        exports.len(),
        imports.len()
    );

    Ok(ElfInfo {
        elf_class: elf.header.e_ident[4], // EI_CLASS
        elf_data: elf.header.e_ident[5],  // EI_DATA
        machine: elf.header.e_machine,
        entry_point: elf.entry,
        headers,
        sections,
        symbols,
        imports,
        exports,
        section_name_map,
    })
}

/// 解析单个符号条目
fn parse_symbol(name: &str, sym: &goblin::elf::Sym, _elf: &goblin::elf::Elf) -> SymbolEntry {
    let sym_type = match sym.st_type() {
        goblin::elf::sym::STT_NOTYPE => SymbolType::NoType,
        goblin::elf::sym::STT_OBJECT => SymbolType::Object,
        goblin::elf::sym::STT_FUNC => SymbolType::Func,
        goblin::elf::sym::STT_SECTION => SymbolType::Section,
        goblin::elf::sym::STT_FILE => SymbolType::File,
        6u8 => SymbolType::Dynamic, // STT_TLS = 6，goblin 0.9 中未导出 STT_DYNAMIC
        other => SymbolType::Other(other),
    };

    let bind = match sym.st_bind() {
        goblin::elf::sym::STB_LOCAL => SymbolBind::Local,
        goblin::elf::sym::STB_GLOBAL => SymbolBind::Global,
        goblin::elf::sym::STB_WEAK => SymbolBind::Weak,
        other => SymbolBind::Other(other),
    };

    SymbolEntry {
        name: name.to_string(),
        value: sym.st_value,
        size: sym.st_size,
        sym_type,
        bind,
        section_index: sym.st_shndx as u16,
    }
}

/// 在 ELF 信息中查找指定符号
///
/// # 参数
/// - `info`: ELF 解析结果
/// - `name`: 符号名称
///
/// # 返回值
/// 返回符号的值（地址偏移），如果未找到则返回 None
pub fn find_symbol(info: &ElfInfo, name: &str) -> Option<u64> {
    // 优先在导出符号中查找
    if let Some(sym) = info.exports.iter().find(|s| s.name == name) {
        return Some(sym.value);
    }

    // 然后在所有符号中查找
    if let Some(sym) = info.symbols.iter().find(|s| s.name == name && s.value != 0) {
        return Some(sym.value);
    }

    // 最后在导入符号中查找（返回 0 表示需要运行时解析）
    if info.imports.iter().any(|s| s.name == name) {
        log::debug!("符号 '{}' 是导入符号，值为 0（需运行时解析）", name);
        return Some(0);
    }

    None
}

/// 在 ELF 信息中查找指定节区
///
/// # 参数
/// - `info`: ELF 解析结果
/// - `name`: 节区名称
///
/// # 返回值
/// 返回节区信息，如果未找到则返回 None
pub fn find_section(info: &ElfInfo, name: &str) -> Option<SectionInfo> {
    info.sections.iter().find(|s| s.name == name).cloned()
}

/// 列出 ELF 中所有导出符号
pub fn list_exports(info: &ElfInfo) -> Vec<&SymbolEntry> {
    info.exports.iter().collect()
}

/// 列出 ELF 中所有导入符号
pub fn list_imports(info: &ElfInfo) -> Vec<&SymbolEntry> {
    info.imports.iter().collect()
}

/// 获取指定名称的所有匹配符号（可能存在重载）
pub fn find_symbols_by_name<'a>(info: &'a ElfInfo, name: &str) -> Vec<&'a SymbolEntry> {
    info.symbols
        .iter()
        .filter(|s| s.name == name)
        .collect()
}

/// 通过地址偏移查找最近的符号
///
/// 在符号表中查找包含指定地址的函数/对象符号。
pub fn find_symbol_by_address(info: &ElfInfo, addr: u64) -> Option<&SymbolEntry> {
    // 找到 addr 落入的符号
    let mut best_match: Option<&SymbolEntry> = None;
    let mut best_size: u64 = 0;

    for sym in &info.symbols {
        if sym.sym_type == SymbolType::Func || sym.sym_type == SymbolType::Object {
            if sym.value <= addr && addr < sym.value + sym.size {
                // 精确匹配
                return Some(sym);
            }
            // 如果没有精确匹配，记住最近的一个
            if sym.value <= addr {
                let dist = addr - sym.value;
                if best_match.is_none() || dist < best_size {
                    best_match = Some(sym);
                    best_size = dist;
                }
            }
        }
    }

    best_match
}

/// 获取 ELF 中指定节区的原始数据
///
/// # 参数
/// - `elf_data`: 原始 ELF 文件数据
/// - `info`: ELF 解析结果
/// - `section_name`: 节区名称
///
/// # 返回值
/// 返回节区的原始字节数据
pub fn get_section_data<'a>(
    elf_data: &'a [u8],
    info: &ElfInfo,
    section_name: &str,
) -> Option<&'a [u8]> {
    let section = find_section(info, section_name)?;
    let end = section.offset as usize + section.size as usize;
    if end <= elf_data.len() {
        Some(&elf_data[section.offset as usize..end])
    } else {
        None
    }
}


/// 从进程内存中解析 ELF
///
/// 从目标进程的指定内存地址读取 ELF 头并解析
///
/// # 参数
/// - `pid`: 目标进程 ID
/// - `base_addr`: ELF 基址（通常是模块加载地址）
///
/// # 返回值
/// 返回 ELF 解析结果
#[cfg(unix)]
pub fn parse_elf_from_memory(pid: crate::common::types::ProcessId, base_addr: u64) -> Result<ElfInfo> {
    #[cfg(unix)]
    use crate::memory::scanner::MemoryScanner;
    
    let mut scanner = MemoryScanner::new(pid);
    
    // 先读取 ELF 头（64 字节足够判断基本信息）
    let elf_header_bytes = scanner.dump_region(base_addr, 64)
        .map_err(|e| crate::FridaError::MemoryRead {
            address: base_addr as usize,
            size: 64,
            reason: format!("读取 ELF 头失败: {}", e),
        })?;
    
    // 检查 ELF 魔数
    if elf_header_bytes.len() < 4 || &elf_header_bytes[0..4] != b"\x7fELF" {
        return Err(crate::FridaError::ElfLoad {
            path: std::path::PathBuf::from(format!("memory:{:#x}", base_addr)),
            detail: "无效的 ELF 魔数".to_string(),
        }.into());
    }
    
    // 确定需要读取的大小（读取程序头和节头表）
    // 对于 64 位 ELF，e_phoff 和 e_shoff 在偏移 32 和 40 处
    let is_64bit = elf_header_bytes[4] == 2;
    
    let (phoff, shoff, phnum, shnum) = if is_64bit && elf_header_bytes.len() >= 60 {
        let phoff = u64::from_le_bytes(elf_header_bytes[32..40].try_into().unwrap_or([0; 8]));
        let shoff = u64::from_le_bytes(elf_header_bytes[40..48].try_into().unwrap_or([0; 8]));
        let phnum = u16::from_le_bytes(elf_header_bytes[54..56].try_into().unwrap_or([0; 2]));
        let shnum = u16::from_le_bytes(elf_header_bytes[58..60].try_into().unwrap_or([0; 2]));
        (phoff, shoff, phnum, shnum)
    } else {
        return Err(crate::FridaError::ElfLoad {
            path: std::path::PathBuf::from(format!("memory:{:#x}", base_addr)),
            detail: "不支持的 ELF 格式".to_string(),
        }.into());
    };
    
    // 计算需要读取的总大小
    let ph_size = if is_64bit { 56 } else { 32 };  // 程序头大小
    let sh_size = if is_64bit { 64 } else { 40 };  // 节头大小
    let max_offset = std::cmp::max(
        phoff + (phnum as u64 * ph_size as u64),
        shoff + (shnum as u64 * sh_size as u64)
    );
    
    // 限制最大读取大小
    let read_size = std::cmp::min(max_offset as usize, 1024 * 1024);  // 最大 1MB
    
    let elf_data = scanner.dump_region(base_addr, read_size)
        .map_err(|e| crate::FridaError::MemoryRead {
            address: base_addr as usize,
            size: read_size,
            reason: format!("读取 ELF 数据失败: {}", e),
        })?;
    
    // 使用 goblin 解析
    parse_elf(&elf_data)
}

/// 获取导出符号列表
///
/// # 参数
/// - `info`: ELF 解析结果
///
/// # 返回值
/// 返回导出符号列表（GLOBAL 或 WEAK 绑定的符号）
pub fn get_exported_symbols(info: &ElfInfo) -> Vec<&SymbolEntry> {
    info.exports.iter().collect()
}

/// 获取指定地址附近的上下文（用于 AI 分析）
///
/// # 参数
/// - `pid`: 目标进程 ID
/// - `address`: 目标地址
/// - `context_size`: 上下文大小（字节）
///
/// # 返回值
/// 返回格式化的上下文信息
#[cfg(unix)]
pub fn get_memory_context(
    pid: crate::common::types::ProcessId,
    address: u64,
    context_size: usize,
) -> Result<String> {
    use crate::memory::scanner::MemoryScanner;
    
    let mut scanner = MemoryScanner::new(pid);
    let data = scanner.dump_region(address, context_size)
        .map_err(|e| crate::FridaError::MemoryRead {
            address: address as usize,
            size: context_size,
            reason: format!("读取内存失败: {}", e),
        })?;
    
    let mut result = format!("内存上下文 @ {:#x} ({} 字节):\n", address, data.len());
    
    // 十六进制 + ASCII 视图
    for (i, chunk) in data.chunks(16).enumerate() {
        let offset = i * 16;
        let hex: String = chunk.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .chunks(2)
            .map(|pair| pair.join(""))
            .collect::<Vec<_>>()
            .join(" ");
        
        let ascii: String = chunk.iter()
            .map(|&b| if b >= 0x20 && b < 0x7f { b as char } else { '.' })
            .collect();
        
        result.push_str(&format!(
            "{:#018x}: {:<48} |{}|\n",
            address + offset as u64,
            hex,
            ascii
        ));
    }
    
    Ok(result)
}