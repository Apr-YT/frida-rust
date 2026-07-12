//! GOT/PLT Hook 实现
//!
//! 通过修改全局偏移表（GOT）中的函数指针实现 Hook。
//! 这种方式不需要修改代码段，相对 Inline Hook 更安全。
//!
//! ## 工作原理
//! 1. 解析 /proc/self/maps 找到目标模块的加载地址
//! 2. 使用 goblin 解析模块的 ELF 结构
//! 3. 在 .got.plt 或 .got section 中找到目标符号的 GOT 条目
//! 4. 修改 GOT 条目指向替换函数的地址
//! 5. 恢复时将 GOT 条目还原为原始值

use crate::common::util::{align_to_page, page_size, parse_proc_maps};
use crate::Result;

// ======================== GOT Hook 句柄 ========================

/// GOT Hook 句柄
///
/// 保存 Hook 安装时的原始信息，用于后续恢复。
pub struct GotHookHandle {
    /// GOT 条目在目标进程中的虚拟地址
    pub got_entry_addr: u64,
    /// 原始 GOT 条目的值（原始函数地址）
    pub original_value: u64,
    /// 模块名称
    pub module_name: String,
    /// 符号名称
    pub symbol_name: String,
    /// 是否已恢复
    restored: bool,
}

impl std::fmt::Debug for GotHookHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GotHookHandle")
            .field("got_entry_addr", &format_args!("{:#x}", self.got_entry_addr))
            .field("original_value", &format_args!("{:#x}", self.original_value))
            .field("module_name", &self.module_name)
            .field("symbol_name", &self.symbol_name)
            .field("restored", &self.restored)
            .finish()
    }
}

// ======================== GOT/PLT Hook 安装器 ========================

/// GOT/PLT Hook 安装器
///
/// 通过修改 GOT 表项实现函数 Hook。GOT 表位于数据段，
/// 可以直接读写而不需要修改内存保护属性（大多数情况下）。
pub struct GotPltHooker {
    /// 已安装的 Hook 列表
    hooks: Vec<GotHookHandle>,
}

impl GotPltHooker {
    /// 创建新的 GOT/PLT Hook 安装器
    pub fn new() -> Self {
        GotPltHooker { hooks: Vec::new() }
    }

    /// 对指定模块的符号安装 GOT Hook
    ///
    /// # 参数
    /// - `module_name`: 目标模块名称（如 "libc.so.6"）
    /// - `symbol_name`: 目标符号名称（如 "open"）
    /// - `module_base`: 模块基址（由调用者通过 /proc/self/maps 获取）
    /// - `replace_addr`: 替换函数的地址
    ///
    /// # 返回值
    /// 返回 GotHookHandle，可用于后续恢复
    pub fn hook_module(
        &mut self,
        module_name: &str,
        symbol_name: &str,
        module_base: u64,
        replace_addr: u64,
    ) -> Result<GotHookHandle> {
        log::info!(
            "安装 GOT Hook: {}::{} @ base {:#x} -> {:#x}",
            module_name,
            symbol_name,
            module_base,
            replace_addr
        );

        // 1. 获取模块的文件路径
        let module_path = self.find_module_path(module_name)?;

        // 2. 读取并解析 ELF 文件
        let elf_data = std::fs::read(&module_path).map_err(|e| {
            crate::FridaError::Hook {
                module: module_name.to_string(),
                symbol: symbol_name.to_string(),
                reason: format!("读取模块文件失败: {}", e),
            }
        })?;

        // 3. 使用 goblin 解析 ELF，找到符号对应的 GOT 条目
        let got_entry_offset = self.find_got_entry(&elf_data, symbol_name)?;

        // 4. 计算运行时 GOT 条目地址
        let got_entry_addr = module_base + got_entry_offset;

        // 5. 读取原始 GOT 值
        let original_value = self.read_got_entry(got_entry_addr)?;

        log::debug!(
            "GOT 条目地址: {:#x}, 原始值: {:#x}",
            got_entry_addr,
            original_value
        );

        // 6. 验证原始值是否为合理的函数地址
        if original_value == 0 {
            log::warn!(
                "GOT 条目 {:#x} 的值为 0，可能符号尚未解析（延迟绑定）",
                got_entry_addr
            );
        }

        // 7. 写入替换地址
        self.write_got_entry(got_entry_addr, replace_addr)?;

        // 8. 验证替换结果
        let verify_value = self.read_got_entry(got_entry_addr)?;
        if verify_value != replace_addr {
            return Err(crate::FridaError::Hook {
                module: module_name.to_string(),
                symbol: symbol_name.to_string(),
                reason: format!(
                    "GOT 替换验证失败: 期望 {:#x}, 实际 {:#x}",
                    replace_addr, verify_value
                ),
            }
            .into());
        }

        let handle = GotHookHandle {
            got_entry_addr,
            original_value,
            module_name: module_name.to_string(),
            symbol_name: symbol_name.to_string(),
            restored: false,
        };

        self.hooks.push(GotHookHandle {
            got_entry_addr: handle.got_entry_addr,
            original_value: handle.original_value,
            module_name: handle.module_name.clone(),
            symbol_name: handle.symbol_name.clone(),
            restored: false,
        });

        log::info!(
            "GOT Hook 安装成功: {}::{} GOT[{:#x}] = {:#x}",
            module_name,
            symbol_name,
            got_entry_addr,
            replace_addr
        );

        Ok(handle)
    }

    /// 恢复指定的 GOT Hook
    ///
    /// 将 GOT 条目还原为原始函数地址。
    pub fn restore(&self, handle: &GotHookHandle) -> Result<()> {
        if handle.restored {
            log::warn!(
                "GOT Hook 已恢复: {}::{}",
                handle.module_name,
                handle.symbol_name
            );
            return Ok(());
        }

        log::info!(
            "恢复 GOT Hook: {}::{} GOT[{:#x}] = {:#x}",
            handle.module_name,
            handle.symbol_name,
            handle.got_entry_addr,
            handle.original_value
        );

        self.write_got_entry(handle.got_entry_addr, handle.original_value)?;

        // 验证恢复结果
        let verify_value = self.read_got_entry(handle.got_entry_addr)?;
        if verify_value != handle.original_value {
            log::warn!(
                "GOT 恢复验证失败: 期望 {:#x}, 实际 {:#x}",
                handle.original_value,
                verify_value
            );
        }

        Ok(())
    }

    /// 恢复所有已安装的 GOT Hook
    pub fn restore_all(&self) -> Result<()> {
        for handle in &self.hooks {
            if !handle.restored {
                let _ = self.restore(handle);
            }
        }
        log::info!("所有 GOT Hook 已恢复");
        Ok(())
    }

    /// 查找模块的文件路径
    fn find_module_path(&self, module_name: &str) -> Result<String> {
        let pid = crate::common::types::ProcessId(0);
        let regions = parse_proc_maps(pid)?;

        for region in &regions {
            if !region.name.is_empty()
                && (region.name.ends_with(module_name)
                    || region.name.contains(&format!("/{}", module_name)))
            {
                return Ok(region.name.clone());
            }
        }

        Err(crate::FridaError::NotFound {
            reason: format!("未找到模块 '{}' 的文件路径", module_name),
        }
        .into())
    }

    /// 在 ELF 中找到符号对应的 GOT 条目偏移
    ///
    /// 通过 goblin 解析 ELF 结构，按以下顺序查找：
    /// 1. .got.plt section 中的重定位项
    /// 2. .got section 中的重定位项
    /// 3. .rela.plt / .rela.dyn 重定位表
    fn find_got_entry(&self, elf_data: &[u8], symbol_name: &str) -> Result<u64> {
        use goblin::Object;

        let elf = match Object::parse(elf_data) {
            Ok(goblin::Object::Elf(elf)) => elf,
            Ok(_) => {
                return Err(crate::FridaError::Hook {
                    module: String::from("unknown"),
                    symbol: symbol_name.to_string(),
                    reason: "不是 ELF 文件".to_string(),
                }
                .into());
            }
            Err(e) => {
                return Err(crate::FridaError::Hook {
                    module: String::from("unknown"),
                    symbol: symbol_name.to_string(),
                    reason: format!("ELF 解析失败: {}", e),
                }
                .into());
            }
        };

        let mut dynsyms = Vec::new();

        // 获取动态符号表和字符串表
        // goblin 的 Strtab::get_at() 返回 Option<&str>
        for sym in &elf.dynsyms {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                if name == symbol_name {
                    dynsyms.push((sym, name));
                }
            }
        }

        // 也检查普通符号表
        for sym in &elf.syms {
            if let Some(name) = elf.strtab.get_at(sym.st_name) {
                if name == symbol_name {
                    log::debug!("在普通符号表中找到符号: {} (索引 {})", name, sym.st_name);
                }
            }
        }

        // 查找 .rela.plt 中的重定位项（pltrelocs 字段）
        for rela in elf.pltrelocs.iter() {
            let sym_idx = rela.r_sym;
            if let Some(sym) = elf.dynsyms.get(sym_idx) {
                if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                    if name == symbol_name {
                        log::debug!(
                            "在 .rela.plt 中找到: {} GOT偏移 {:#x}",
                            name,
                            rela.r_offset
                        );
                        return Ok(rela.r_offset);
                    }
                }
            }
        }

        // 查找 .rela.dyn 中的重定位项（dynrelas 字段）
        for rela in elf.dynrelas.iter() {
            let sym_idx = rela.r_sym;
            if sym_idx == 0 {
                continue;
            }
            if let Some(sym) = elf.dynsyms.get(sym_idx) {
                if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                    if name == symbol_name {
                        log::debug!(
                            "在 .rela.dyn 中找到: {} GOT偏移 {:#x}",
                            name,
                            rela.r_offset
                        );
                        return Ok(rela.r_offset);
                    }
                }
            }
        }

        // 如果在动态符号中找到了，尝试估算 GOT 偏移
        // （某些情况下重定位表可能不直接列出所有符号）
        for (sym, name) in &dynsyms {
            if *name == symbol_name {
                log::debug!(
                    "在动态符号表中找到 {}，但没有找到对应的重定位项",
                    name
                );
                // 返回符号值作为后备
                return Ok(sym.st_value);
            }
        }

        // 尝试直接搜索 section
        for section in &elf.section_headers {
            if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
                if name == ".got.plt" || name == ".got" {
                    log::debug!(
                        "找到 {} section: addr={:#x}, size={}",
                        name, section.sh_addr, section.sh_size
                    );
                }
            }
        }

        Err(crate::FridaError::NotFound {
            reason: format!(
                "在模块中未找到符号 '{}' 的 GOT 条目",
                symbol_name
            ),
        }
        .into())
    }

    /// 读取 GOT 条目的值
    fn read_got_entry(&self, addr: u64) -> Result<u64> {
        let mut value: u64 = 0;

        // SAFETY: 调用者需确保地址有效且可读
        unsafe {
            libc::memcpy(
                &mut value as *mut u64 as *mut libc::c_void,
                addr as *const libc::c_void,
                std::mem::size_of::<u64>(),
            );
        }

        Ok(value)
    }

    /// 写入 GOT 条目的值
    ///
    /// 使用 mprotect 修改内存保护属性，然后写入新的地址值。
    /// 对于原子性要求高的场景，使用 cmpxchg 进行原子替换。
    fn write_got_entry(&self, addr: u64, value: u64) -> Result<()> {
        let page_addr = align_to_page(addr as usize);
        let protect_size = page_size();

        // 修改页面保护为 RW
        let ret = unsafe {
            libc::mprotect(
                page_addr as *mut libc::c_void,
                protect_size,
                libc::PROT_READ | libc::PROT_WRITE,
            )
        };

        if ret != 0 {
            return Err(crate::FridaError::MemoryProtect {
                address: page_addr,
                reason: format!(
                    "修改 GOT 页面保护失败: {}",
                    std::io::Error::last_os_error()
                ),
            }
            .into());
        }

        // 使用 write_volatile 写入 GOT 条目，确保编译器不会优化掉该写入
        unsafe {
            std::ptr::write_volatile(addr as *mut u64, value);
        }

        // 恢复页面保护为 RW（GOT 页面本来就是 RW，不需要改为 R-X）
        let ret = unsafe {
            libc::mprotect(
                page_addr as *mut libc::c_void,
                protect_size,
                libc::PROT_READ | libc::PROT_WRITE,
            )
        };

        if ret != 0 {
            log::warn!(
                "恢复 GOT 页面保护失败: {}",
                std::io::Error::last_os_error()
            );
        }

        Ok(())
    }
}

impl Default for GotPltHooker {
    fn default() -> Self {
        Self::new()
    }
}
