//! PE (Portable Executable) 解析器
//!
//! 解析 Windows PE 文件的导出表和导入表，
//! 提供符号查询功能。

// use crate::common::types::ProcessId; // TODO: 可能需要
use crate::Result;
use std::collections::HashMap;

// ======================== PE 结构定义 ========================

/// PE 符号条目
#[derive(Debug, Clone)]
pub struct PeSymbol {
    /// 符号名称
    pub name: String,
    /// 符号序号
    pub ordinal: u32,
    /// 函数地址 RVA (相对虚拟地址)
    pub rva: u64,
    /// 函数实际地址 (基址 + RVA)
    pub address: u64,
    /// 是否为转发导出
    pub forwarded: bool,
    /// 转发目标 (如果是转发导出)
    pub forward_name: Option<String>,
}

/// PE 模块信息
#[derive(Debug, Clone)]
pub struct PeModuleInfo {
    /// 模块基址
    pub base_address: u64,
    /// 模块大小
    pub size: u32,
    /// 导出符号列表
    pub exports: Vec<PeSymbol>,
    /// 导入符号列表
    pub imports: Vec<PeImportSymbol>,
}

/// PE 导入符号
#[derive(Debug, Clone)]
pub struct PeImportSymbol {
    /// 符号名称
    pub name: String,
    /// 来源模块
    pub from_module: String,
    /// 符号序号 (如果是序号导入)
    pub ordinal: Option<u32>,
}

// ======================== PE 解析器 ========================

/// PE 解析器
pub struct PeParser {
    pid: u32,
    modules: HashMap<String, PeModuleInfo>,
}

impl PeParser {
    /// 创建新的 PE 解析器
    pub fn new(pid: u32) -> Self {
        PeParser {
            pid,
            modules: HashMap::new(),
        }
    }

    /// 解析指定模块的 PE 信息
    #[cfg(windows)]
    pub fn parse_module(&mut self, module_name: &str) -> Result<&PeModuleInfo> {
        use crate::inject::win_process;

        // 如果已解析过，直接返回
        if self.modules.contains_key(module_name) {
            return Ok(self.modules.get(module_name).unwrap());
        }

        // 获取模块信息
        let modules = win_process::enum_modules(self.pid)?;
        let module = modules.iter()
            .find(|m| m.name.to_lowercase().contains(&module_name.to_lowercase()))
            .ok_or_else(|| crate::FridaError::ModuleNotFound {
                name: module_name.to_string(),
            })?;

        let base_addr = module.base_addr as u64;

        // 读取 PE 头
        let pe_info = self.read_pe_from_memory(base_addr)?;

        self.modules.insert(module_name.to_string(), pe_info);
        Ok(self.modules.get(module_name).unwrap())
    }

    /// 从内存读取并解析 PE
    #[cfg(windows)]
    fn read_pe_from_memory(&self, base_addr: u64) -> Result<PeModuleInfo> {
        use crate::memory::win_scanner::WinMemoryScanner;

        let scanner = WinMemoryScanner::new(self.pid)?;

        // 读取 DOS 头 (64字节)
        let dos_header = scanner.dump_region(base_addr, 64)?;

        // 检查 MZ 签名
        if dos_header[0] != b'M' || dos_header[1] != b'Z' {
            return Err(crate::FridaError::InvalidPE {
                reason: "无效的 DOS 签名".to_string(),
            }.into());
        }

        // 获取 PE 头偏移
        let pe_offset = u32::from_le_bytes([
            dos_header[0x3C], dos_header[0x3D],
            dos_header[0x3E], dos_header[0x3F],
        ]) as u64;

        // 读取 PE 头 (256字节足够)
        let pe_header = scanner.dump_region(base_addr + pe_offset, 256)?;

        // 检查 PE 签名
        if pe_header[0] != b'P' || pe_header[1] != b'E' {
            return Err(crate::FridaError::InvalidPE {
                reason: "无效的 PE 签名".to_string(),
            }.into());
        }

        // 解析可选头
        let magic = u16::from_le_bytes([pe_header[24], pe_header[25]]);
        let is_64bit = magic == 0x20B;

        // 获取数据目录偏移 (64位: 128, 32位: 112)
        let data_dir_offset = if is_64bit { 128 } else { 112 };

        // 获取导出表 RVA 和大小
        let export_rva = u32::from_le_bytes([
            pe_header[data_dir_offset], pe_header[data_dir_offset + 1],
            pe_header[data_dir_offset + 2], pe_header[data_dir_offset + 3],
        ]);
        let export_size = u32::from_le_bytes([
            pe_header[data_dir_offset + 4], pe_header[data_dir_offset + 5],
            pe_header[data_dir_offset + 6], pe_header[data_dir_offset + 7],
        ]);

        // 获取导入表 RVA 和大小 (DataDirectory[1])
        let import_rva = u32::from_le_bytes([
            pe_header[data_dir_offset + 8], pe_header[data_dir_offset + 9],
            pe_header[data_dir_offset + 10], pe_header[data_dir_offset + 11],
        ]);
        let import_size = u32::from_le_bytes([
            pe_header[data_dir_offset + 12], pe_header[data_dir_offset + 13],
            pe_header[data_dir_offset + 14], pe_header[data_dir_offset + 15],
        ]);

        // 解析导出表
        let exports = if export_rva > 0 && export_size > 0 {
            self.parse_export_table(&scanner, base_addr, export_rva, export_size)?
        } else {
            Vec::new()
        };

        // 解析导入表
        let imports = if import_rva > 0 && import_size > 0 {
            self.parse_import_table(&scanner, base_addr, import_rva, import_size)?
        } else {
            Vec::new()
        };

        Ok(PeModuleInfo {
            base_address: base_addr,
            size: 0,
            exports,
            imports,
        })
    }

    /// 解析导出表
    #[cfg(windows)]
    fn parse_export_table(
        &self,
        scanner: &crate::memory::win_scanner::WinMemoryScanner,
        base_addr: u64,
        export_rva: u32,
        export_size: u32,
    ) -> Result<Vec<PeSymbol>> {
        let export_addr = base_addr + export_rva as u64;

        // 读取导出表头 (40字节)
        let export_dir = scanner.dump_region(export_addr, 40)?;

        let _characteristics = u32::from_le_bytes([
            export_dir[0], export_dir[1], export_dir[2], export_dir[3],
        ]);
        let _time_date_stamp = u32::from_le_bytes([
            export_dir[4], export_dir[5], export_dir[6], export_dir[7],
        ]);
        let _major_version = u16::from_le_bytes([export_dir[8], export_dir[9]]);
        let _minor_version = u16::from_le_bytes([export_dir[10], export_dir[11]]);
        let _name_rva = u32::from_le_bytes([
            export_dir[12], export_dir[13], export_dir[14], export_dir[15],
        ]);
        let _ordinal_base = u32::from_le_bytes([
            export_dir[16], export_dir[17], export_dir[18], export_dir[19],
        ]);
        let num_functions = u32::from_le_bytes([
            export_dir[20], export_dir[21], export_dir[22], export_dir[23],
        ]) as usize;
        let num_names = u32::from_le_bytes([
            export_dir[24], export_dir[25], export_dir[26], export_dir[27],
        ]) as usize;
        let functions_rva = u32::from_le_bytes([
            export_dir[28], export_dir[29], export_dir[30], export_dir[31],
        ]);
        let names_rva = u32::from_le_bytes([
            export_dir[32], export_dir[33], export_dir[34], export_dir[35],
        ]);
        let ordinals_rva = u32::from_le_bytes([
            export_dir[36], export_dir[37], export_dir[38], export_dir[39],
        ]);

        let mut exports = Vec::new();

        // 读取函数地址表
        let functions_addr = base_addr + functions_rva as u64;
        let functions_data = scanner.dump_region(functions_addr, num_functions * 4)?;

        // 读取名称表
        let names_addr = base_addr + names_rva as u64;
        let names_data = scanner.dump_region(names_addr, num_names * 4)?;

        // 读取序号表
        let ordinals_addr = base_addr + ordinals_rva as u64;
        let ordinals_data = scanner.dump_region(ordinals_addr, num_names * 2)?;

        // 构建名称到序号的映射
        let mut name_map: HashMap<u16, String> = HashMap::new();
        for i in 0..num_names {
            let name_rva = u32::from_le_bytes([
                names_data[i * 4], names_data[i * 4 + 1],
                names_data[i * 4 + 2], names_data[i * 4 + 3],
            ]);
            let ordinal_index = u16::from_le_bytes([
                ordinals_data[i * 2], ordinals_data[i * 2 + 1],
            ]);

            // 读取函数名称
            let name_addr = base_addr + name_rva as u64;
            if let Ok(name_bytes) = scanner.dump_region(name_addr, 256) {
                let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(256);
                let name = String::from_utf8_lossy(&name_bytes[..name_end]).to_string();
                name_map.insert(ordinal_index, name);
            }
        }

        // 构建导出符号列表
        for i in 0..num_functions {
            let rva = u32::from_le_bytes([
                functions_data[i * 4], functions_data[i * 4 + 1],
                functions_data[i * 4 + 2], functions_data[i * 4 + 3],
            ]);

            if rva == 0 {
                continue;
            }

            let ordinal = i as u32 + _ordinal_base;
            let name = name_map.get(&(i as u16))
                .cloned()
                .unwrap_or_else(|| format!("ordinal_{}", ordinal));

            // 检查是否为转发导出
            let forwarded = rva >= export_rva && rva < export_rva + export_size;
            let forward_name = if forwarded {
                let forward_addr = base_addr + rva as u64;
                if let Ok(bytes) = scanner.dump_region(forward_addr, 256) {
                    let end = bytes.iter().position(|&b| b == 0).unwrap_or(256);
                    Some(String::from_utf8_lossy(&bytes[..end]).to_string())
                } else {
                    None
                }
            } else {
                None
            };

            exports.push(PeSymbol {
                name,
                ordinal,
                rva: rva as u64,
                address: base_addr + rva as u64,
                forwarded,
                forward_name,
            });
        }

        Ok(exports)
    }

    /// 解析导入表 (IAT)
    #[cfg(windows)]
    fn parse_import_table(
        &self,
        scanner: &crate::memory::win_scanner::WinMemoryScanner,
        base_addr: u64,
        import_rva: u32,
        _import_size: u32,
    ) -> Result<Vec<PeImportSymbol>> {
        let _import_addr = base_addr + import_rva as u64;
        let mut imports = Vec::new();
        let mut current_rva = import_rva;

        loop {
            let import_descriptor_addr = base_addr + current_rva as u64;
            let import_desc = scanner.dump_region(import_descriptor_addr, 20)?;

            let original_first_thunk = u32::from_le_bytes([
                import_desc[0], import_desc[1], import_desc[2], import_desc[3],
            ]);
            let time_date_stamp = u32::from_le_bytes([
                import_desc[4], import_desc[5], import_desc[6], import_desc[7],
            ]);
            let forwarder_chain = u32::from_le_bytes([
                import_desc[8], import_desc[9], import_desc[10], import_desc[11],
            ]);
            let name_rva = u32::from_le_bytes([
                import_desc[12], import_desc[13], import_desc[14], import_desc[15],
            ]);
            let first_thunk = u32::from_le_bytes([
                import_desc[16], import_desc[17], import_desc[18], import_desc[19],
            ]);

            if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
                break;
            }

            let module_name = if name_rva > 0 {
                let name_addr = base_addr + name_rva as u64;
                if let Ok(name_bytes) = scanner.dump_region(name_addr, 256) {
                    let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(256);
                    String::from_utf8_lossy(&name_bytes[..name_end]).to_string()
                } else {
                    format!("unknown_{}", time_date_stamp)
                }
            } else {
                format!("unnamed_{}", forwarder_chain)
            };

            let thunk_data = if original_first_thunk > 0 {
                original_first_thunk
            } else {
                first_thunk
            };

            if thunk_data > 0 {
                let thunk_addr = base_addr + thunk_data as u64;
                let mut thunk_index = 0;

                loop {
                    let entry_addr = thunk_addr + thunk_index * 4;
                    let entry_data = scanner.dump_region(entry_addr, 4)?;
                    let entry = u32::from_le_bytes([
                        entry_data[0], entry_data[1], entry_data[2], entry_data[3],
                    ]);

                    if entry == 0 {
                        break;
                    }

                    let (symbol_name, ordinal) = if (entry & 0x80000000) != 0 {
                        (None, Some(entry & 0x7FFFFFFF))
                    } else {
                        let hint_name_addr = base_addr + entry as u64;
                        if let Ok(hint_name_data) = scanner.dump_region(hint_name_addr, 256) {
                            let name_start = 2;
                            let name_end = hint_name_data[name_start..]
                                .iter()
                                .position(|&b| b == 0)
                                .unwrap_or(254);
                            let name = String::from_utf8_lossy(&hint_name_data[name_start..name_start + name_end]).to_string();
                            (Some(name), None)
                        } else {
                            (None, None)
                        }
                    };

                    if let Some(name) = symbol_name {
                        imports.push(PeImportSymbol {
                            name,
                            from_module: module_name.clone(),
                            ordinal,
                        });
                    }

                    thunk_index += 1;
                }
            }

            current_rva += 20;
        }

        Ok(imports)
    }

    /// 查找符号
    pub fn find_symbol(&self, module_name: &str, symbol_name: &str) -> Option<&PeSymbol> {
        self.modules.get(module_name)?.exports.iter()
            .find(|s| s.name == symbol_name || s.name.contains(symbol_name))
    }

    /// 列出所有导出符号
    pub fn list_symbols(&self, module_name: &str) -> Option<&Vec<PeSymbol>> {
        self.modules.get(module_name).map(|m| &m.exports)
    }
}

// ======================== 非 Windows 平台的桩实现 ========================

#[cfg(not(windows))]
impl PeParser {
    pub fn new(pid: u32) -> Self {
        PeParser {
            pid,
            modules: HashMap::new(),
        }
    }

    pub fn parse_module(&mut self, _module_name: &str) -> Result<&PeModuleInfo> {
        Err(crate::FridaError::Unsupported {
            reason: "PE 解析仅支持 Windows 平台".to_string(),
        }.into())
    }

    pub fn find_symbol(&self, _module_name: &str, _symbol_name: &str) -> Option<&PeSymbol> {
        None
    }

    pub fn list_symbols(&self, _module_name: &str) -> Option<&Vec<PeSymbol>> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pe_parser_creation() {
        let parser = PeParser::new(0);
        assert!(parser.modules.is_empty());
    }
}
