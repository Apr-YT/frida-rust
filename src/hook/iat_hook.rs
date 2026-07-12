//! Windows IAT (Import Address Table) Hook 实现
//!
//! 通过修改 PE 文件的导入表，将目标函数的地址替换为自定义钩子函数。

use crate::{FridaError, Result};

use std::ffi::CString;
use winapi::um::libloaderapi::GetModuleHandleA;
use winapi::um::memoryapi::VirtualProtect;
use winapi::um::winnt::{
    IMAGE_DOS_HEADER, IMAGE_IMPORT_BY_NAME, IMAGE_IMPORT_DESCRIPTOR, IMAGE_NT_HEADERS64,
    IMAGE_ORDINAL_FLAG64, IMAGE_THUNK_DATA64, PAGE_EXECUTE_READWRITE,
};

/// IAT Hook 句柄
pub struct IatHookHandle {
    pub module_name: String,
    pub function_name: String,
    pub original_addr: u64,
    pub iat_entry_addr: u64,
}

impl std::fmt::Debug for IatHookHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IatHookHandle")
            .field("module_name", &self.module_name)
            .field("function_name", &self.function_name)
            .field("original_addr", &format_args!("{:#x}", self.original_addr))
            .field("iat_entry_addr", &format_args!("{:#x}", self.iat_entry_addr))
            .finish()
    }
}

/// 导入信息
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct ImportInfo {
    dll_name: String,
    function_name: String,
    iat_entry_addr: u64,
    original_addr: u64,
}

/// IAT Hook 引擎
pub struct IatHooker;

impl IatHooker {
    /// 创建新的 IAT Hook 引擎
    pub fn new() -> Self {
        Self
    }

    /// Hook 指定模块的导入函数
    ///
    /// # 参数
    /// - `target_module`: 被 Hook 的模块名（如 "user32.dll"）
    /// - `target_function`: 被 Hook 的函数名（如 "MessageBoxA"）
    /// - `replace_addr`: 替换函数的地址
    pub fn hook_function(
        &self,
        target_module: &str,
        target_function: &str,
        replace_addr: u64,
    ) -> Result<IatHookHandle> {
        let module_name_c = CString::new(target_module).map_err(|_| FridaError::InvalidHookPoint {
            reason: format!("模块名包含空字节: {}", target_module),
        })?;

        let module_base = unsafe { GetModuleHandleA(module_name_c.as_ptr()) } as u64;
        if module_base == 0 {
            return Err(FridaError::NotFound {
                reason: format!("无法获取模块句柄: {}", target_module),
            }
            .into());
        }

        let (iat_entry_addr, original_addr) =
            self.find_iat_entry(module_base, target_module, target_function)?;

        // 修改页面保护为 RWX
        let mut old_protect = 0u32;
        let ret = unsafe {
            VirtualProtect(
                iat_entry_addr as *mut _,
                std::mem::size_of::<u64>(),
                PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            )
        };
        if ret == 0 {
            return Err(FridaError::MemoryProtect {
                address: iat_entry_addr as usize,
                reason: format!("VirtualProtect 失败: {}", std::io::Error::last_os_error()),
            }
            .into());
        }

        // 原子替换地址
        unsafe {
            std::ptr::write_volatile(iat_entry_addr as *mut u64, replace_addr);
        }

        // 恢复原始保护属性
        let _ = unsafe {
            VirtualProtect(
                iat_entry_addr as *mut _,
                std::mem::size_of::<u64>(),
                old_protect,
                &mut old_protect,
            )
        };

        log::info!(
            "IAT Hook 安装成功: {}!{} -> {:#x} (原始={:#x})",
            target_module,
            target_function,
            replace_addr,
            original_addr
        );

        Ok(IatHookHandle {
            module_name: target_module.to_string(),
            function_name: target_function.to_string(),
            original_addr,
            iat_entry_addr,
        })
    }

    /// 恢复原始 IAT 条目
    pub fn restore(&self, handle: &IatHookHandle) -> Result<()> {
        let mut old_protect = 0u32;
        let ret = unsafe {
            VirtualProtect(
                handle.iat_entry_addr as *mut _,
                std::mem::size_of::<u64>(),
                PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            )
        };
        if ret == 0 {
            return Err(FridaError::MemoryProtect {
                address: handle.iat_entry_addr as usize,
                reason: format!("VirtualProtect 失败: {}", std::io::Error::last_os_error()),
            }
            .into());
        }

        unsafe {
            std::ptr::write_volatile(handle.iat_entry_addr as *mut u64, handle.original_addr);
        }

        let _ = unsafe {
            VirtualProtect(
                handle.iat_entry_addr as *mut _,
                std::mem::size_of::<u64>(),
                old_protect,
                &mut old_protect,
            )
        };

        log::info!(
            "IAT Hook 已恢复: {}!{} = {:#x}",
            handle.module_name,
            handle.function_name,
            handle.original_addr
        );

        Ok(())
    }

    /// 查找模块的 IAT 条目地址
    fn find_iat_entry(
        &self,
        module_base: u64,
        target_module: &str,
        target_function: &str,
    ) -> Result<(u64, u64)> {
        unsafe {
            let dos_header = module_base as *const IMAGE_DOS_HEADER;
            if (*dos_header).e_magic != 0x5A4D {
                return Err(FridaError::InvalidHookPoint {
                    reason: "无效的 PE DOS Header".to_string(),
                }
                .into());
            }

            let nt_headers =
                (module_base + (*dos_header).e_lfanew as u64) as *const IMAGE_NT_HEADERS64;
            if (*nt_headers).Signature != 0x00004550 {
                return Err(FridaError::InvalidHookPoint {
                    reason: "无效的 PE NT Header".to_string(),
                }
                .into());
            }

            let import_dir = &(*nt_headers).OptionalHeader.DataDirectory[1];
            if import_dir.VirtualAddress == 0 || import_dir.Size == 0 {
                return Err(FridaError::NotFound {
                    reason: format!("模块 {} 没有导入表", target_module),
                }
                .into());
            }

            let desc_ptr =
                (module_base + import_dir.VirtualAddress as u64) as *const IMAGE_IMPORT_DESCRIPTOR;
            let mut i = 0;

            loop {
                let desc = &*desc_ptr.add(i);
                if desc.Name == 0 {
                    break;
                }

                let dll_name_ptr = (module_base + desc.Name as u64) as *const i8;
                let _dll_name = std::ffi::CStr::from_ptr(dll_name_ptr)
                    .to_string_lossy()
                    .to_lowercase();

                let original_first_thunk = *desc.u.OriginalFirstThunk();
                let int = if original_first_thunk != 0 {
                    (module_base + original_first_thunk as u64) as *const IMAGE_THUNK_DATA64
                } else {
                    (module_base + desc.FirstThunk as u64) as *const IMAGE_THUNK_DATA64
                };

                let iat = (module_base + desc.FirstThunk as u64) as *mut u64;

                let mut j = 0;
                loop {
                    let thunk = &*int.add(j);
                    let func_val = *thunk.u1.Function();

                    if func_val == 0 {
                        break;
                    }

                    if *thunk.u1.Ordinal() & IMAGE_ORDINAL_FLAG64 == 0 {
                        let by_name =
                            (module_base + func_val as u64) as *const IMAGE_IMPORT_BY_NAME;
                        let name_ptr = (*by_name).Name.as_ptr() as *const i8;
                        let name = std::ffi::CStr::from_ptr(name_ptr).to_string_lossy();

                        if name == target_function {
                            let iat_entry = iat.add(j) as u64;
                            let original_addr = std::ptr::read_volatile(iat_entry as *const u64);
                            return Ok((iat_entry, original_addr));
                        }
                    }

                    j += 1;
                }

                i += 1;
            }

            Err(FridaError::NotFound {
                reason: format!(
                    "在 {} 中未找到函数 {} 的 IAT 条目",
                    target_module, target_function
                ),
            }
            .into())
        }
    }

    /// 解析 PE 导入表
    #[allow(dead_code)]
    fn parse_imports(&self, module_base: u64) -> Result<Vec<ImportInfo>> {
        let mut imports = Vec::new();

        unsafe {
            let dos_header = module_base as *const IMAGE_DOS_HEADER;
            if (*dos_header).e_magic != 0x5A4D {
                return Err(FridaError::InvalidHookPoint {
                    reason: "无效的 PE DOS Header".to_string(),
                }
                .into());
            }

            let nt_headers =
                (module_base + (*dos_header).e_lfanew as u64) as *const IMAGE_NT_HEADERS64;
            if (*nt_headers).Signature != 0x00004550 {
                return Err(FridaError::InvalidHookPoint {
                    reason: "无效的 PE NT Header".to_string(),
                }
                .into());
            }

            let import_dir = &(*nt_headers).OptionalHeader.DataDirectory[1];
            if import_dir.VirtualAddress == 0 || import_dir.Size == 0 {
                return Ok(imports);
            }

            let desc_ptr =
                (module_base + import_dir.VirtualAddress as u64) as *const IMAGE_IMPORT_DESCRIPTOR;
            let mut i = 0;

            loop {
                let desc = &*desc_ptr.add(i);
                if desc.Name == 0 {
                    break;
                }

                let dll_name_ptr = (module_base + desc.Name as u64) as *const i8;
                let dll_name = std::ffi::CStr::from_ptr(dll_name_ptr)
                    .to_string_lossy()
                    .to_string();

                let original_first_thunk = *desc.u.OriginalFirstThunk();
                let int = if original_first_thunk != 0 {
                    (module_base + original_first_thunk as u64) as *const IMAGE_THUNK_DATA64
                } else {
                    (module_base + desc.FirstThunk as u64) as *const IMAGE_THUNK_DATA64
                };

                let iat = (module_base + desc.FirstThunk as u64) as *mut u64;

                let mut j = 0;
                loop {
                    let thunk = &*int.add(j);
                    let func_val = *thunk.u1.Function();

                    if func_val == 0 {
                        break;
                    }

                    let function_name = if *thunk.u1.Ordinal() & IMAGE_ORDINAL_FLAG64 == 0 {
                        let by_name =
                            (module_base + func_val as u64) as *const IMAGE_IMPORT_BY_NAME;
                        let name_ptr = (*by_name).Name.as_ptr() as *const i8;
                        std::ffi::CStr::from_ptr(name_ptr)
                            .to_string_lossy()
                            .to_string()
                    } else {
                        format!("Ordinal_{}", *thunk.u1.Ordinal() & 0xFFFF)
                    };

                    let iat_entry_addr = iat.add(j) as u64;
                    let original_addr = std::ptr::read_volatile(iat_entry_addr as *const u64);

                    imports.push(ImportInfo {
                        dll_name: dll_name.clone(),
                        function_name,
                        iat_entry_addr,
                        original_addr,
                    });

                    j += 1;
                }

                i += 1;
            }
        }

        Ok(imports)
    }
}

impl Default for IatHooker {
    fn default() -> Self {
        Self::new()
    }
}
