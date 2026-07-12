//! Hook 管理器 - 统一管理所有 Hook 点的生命周期
//!
//! 提供注册、安装、卸载 Hook 的高层接口，内部委派给具体的 Hook 实现模块。

use crate::common::types::{HookPoint, HookType, MemoryRegion};
use crate::common::util::{parse_proc_maps, safe_read_bytes};
#[cfg(unix)]
use crate::hook::got_plt::GotPltHooker;
use crate::hook::inline::InlineHooker;
use crate::Result;

use std::collections::HashMap;

// ======================== Hook ID ========================

/// Hook 唯一标识符
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HookId(u64);

impl HookId {
    /// 创建新的 HookId
    pub fn new(id: u64) -> Self {
        HookId(id)
    }

    /// 获取内部数值
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for HookId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HookId({})", self.0)
    }
}

// ======================== Hook 上下文 ========================

/// Hook 回调函数的上下文信息
///
/// 在 Hook 回调被触发时传递给用户，包含当前函数调用的参数、返回值和寄存器快照。
#[derive(Debug, Clone)]
pub struct HookContext {
    /// Hook 点描述
    pub hook_point: HookPoint,
    /// 函数参数（通用字节表示，由用户自行解释）
    pub args: Vec<u64>,
    /// 返回值（通用字节表示）
    pub return_value: u64,
    /// 寄存器快照（键为寄存器名称，值为寄存器内容）
    pub registers: HashMap<String, u64>,
    /// 触发时的线程 ID
    pub thread_id: u32,
    /// 是否在函数入口（true = 入口，false = 出口）
    pub on_enter: bool,
}

impl HookContext {
    /// 创建空的 Hook 上下文
    pub fn new(hook_point: HookPoint) -> Self {
        HookContext {
            hook_point,
            args: Vec::new(),
            return_value: 0,
            registers: HashMap::new(),
            #[cfg(unix)]
            thread_id: unsafe { libc::gettid() as u32 },
            #[cfg(windows)]
            thread_id: unsafe { winapi::um::processthreadsapi::GetCurrentThreadId() },
            on_enter: true,
        }
    }

    /// 获取第 n 个参数
    pub fn get_arg(&self, index: usize) -> Option<u64> {
        self.args.get(index).copied()
    }

    /// 设置返回值
    pub fn set_return_value(&mut self, value: u64) {
        self.return_value = value;
    }
}

// ======================== Hook 条目 ========================

/// 内部 Hook 条目，包含注册信息和激活状态
#[allow(dead_code)]
struct HookEntry {
    /// Hook 点描述
    hook_point: HookPoint,
    /// 用户回调函数
    #[allow(clippy::type_complexity)]
    callback: Option<Box<dyn Fn(&HookContext) + Send + Sync>>,
    /// 原始数据备份（用于恢复）
    original_bytes: Vec<u8>,
    /// 是否已激活
    active: bool,
    /// Inline Hook 的跳板信息
    trampoline: Option<crate::hook::inline::Trampoline>,
    /// GOT Hook 的句柄（Unix 独有）
    #[cfg(unix)]
    got_handle: Option<crate::hook::got_plt::GotHookHandle>,
    /// 替换函数的地址（用于 inline hook）
    detour_addr: Option<u64>,
}

// ======================== Hook 管理器 ========================

/// Hook 管理器，负责 Hook 点的注册、安装和卸载
///
/// 统一管理 Inline Hook 和 GOT/PLT Hook 的生命周期。
pub struct HookManager {
    /// 已注册的 Hook 条目列表
    hooks: HashMap<HookId, HookEntry>,
    /// 下一个可用的 Hook ID
    next_id: u64,
    /// Inline Hook 安装器
    inline_hooker: InlineHooker,
    /// GOT/PLT Hook 安装器（Unix 独有）
    #[cfg(unix)]
    got_hooker: GotPltHooker,
    /// 模块基地址缓存
    module_bases: HashMap<String, usize>,
}

impl HookManager {
    /// 创建新的 Hook 管理器
    pub fn new() -> Self {
        HookManager {
            hooks: HashMap::new(),
            next_id: 1,
            inline_hooker: InlineHooker::new(),
            #[cfg(unix)]
            got_hooker: GotPltHooker::new(),
            module_bases: HashMap::new(),
        }
    }

    /// 注册一个新的 Hook 点并返回 HookId
    ///
    /// # 参数
    /// - `hook_point`: Hook 点描述（包含模块名、符号名、偏移量和类型）
    /// - `callback`: Hook 触发时的回调函数
    ///
    /// # 返回值
    /// 返回分配的 HookId，后续用此 ID 进行安装和卸载操作
    pub fn register_hook<F>(
        &mut self,
        hook_point: HookPoint,
        callback: F,
    ) -> Result<HookId>
    where
        F: Fn(&HookContext) + Send + Sync + 'static,
    {
        let id = HookId::new(self.next_id);
        self.next_id += 1;

        let entry = HookEntry {
            hook_point: hook_point.clone(),
            callback: Some(Box::new(callback)),
            original_bytes: Vec::new(),
            active: false,
            trampoline: None,
            #[cfg(unix)]
            got_handle: None,
            detour_addr: None,
        };

        self.hooks.insert(id, entry);
        log::info!("注册 Hook #{}: {}", id, hook_point);
        Ok(id)
    }

    /// 安装指定 Hook
    ///
    /// 根据注册的 Hook 类型选择对应的安装策略：
    /// - Inline Hook: 修改目标函数入口处的机器码
    /// - GOT/PLT Hook: 修改 GOT 表中的函数指针
    pub fn install_hook(&mut self, id: HookId) -> Result<()> {
        // 先检查 Hook 是否存在且未激活
        let hook_type = {
            let entry = self.hooks.get(&id).ok_or_else(|| {
                crate::FridaError::InvalidHookPoint {
                    reason: format!("HookId {} 不存在", id),
                }
            })?;
            if entry.active {
                log::warn!("Hook #{} 已经安装，跳过", id);
                return Ok(());
            }
            entry.hook_point.hook_type
        };

        match hook_type {
            HookType::Inline => {
                self.install_inline_hook(id)?;
            }
            #[cfg(unix)]
            HookType::GotPlt => {
                self.install_got_hook(id)?;
            }
            #[cfg(not(unix))]
            HookType::GotPlt => {
                return Err(crate::FridaError::Unsupported {
                    reason: "Windows 下不支持 GOT/PLT Hook".to_string(),
                }
                .into());
            }
            HookType::Java => {
                // Java Hook 需要单独处理，此处仅做标记
                log::info!("Java Hook #{} 已注册（需通过 JavaHooker 单独安装）", id);
                if let Some(entry) = self.hooks.get_mut(&id) {
                    entry.active = true;
                }
            }
        }

        if let Some(entry) = self.hooks.get(&id) {
            log::info!("Hook #{} 安装成功: {}", id, entry.hook_point);
        }
        Ok(())
    }

    /// 安装 Inline Hook（使用 HookId 避免借用冲突）
    fn install_inline_hook(&mut self, id: HookId) -> Result<()> {
        // 提取 Hook 信息
        let (module, symbol, offset, detour_addr) = {
            let entry = self.hooks.get(&id).ok_or_else(|| {
                crate::FridaError::InvalidHookPoint {
                    reason: format!("HookId {} 不存在", id),
                }
            })?;
            (
                entry.hook_point.module.clone(),
                entry.hook_point.symbol.clone(),
                entry.hook_point.offset,
                entry.detour_addr,
            )
        };

        // 解析目标地址
        let module_base = self.find_module_base(&module)?;
        let target_addr = if offset != 0 {
            module_base as u64 + offset as u64
        } else {
            self.resolve_symbol(module_base, &symbol)?
        };

        let detour = detour_addr.unwrap_or(target_addr);

        let trampoline = self.inline_hooker.install(target_addr, detour)?;

        // 备份原始字节并更新 Hook 条目
        let original = self.inline_hooker.read_original_bytes(target_addr, trampoline.patched_size);
        let entry = self.hooks.get_mut(&id).ok_or_else(|| {
            crate::FridaError::InvalidHookPoint {
                reason: format!("HookId {} 不存在", id),
            }
        })?;
        entry.original_bytes = original;
        entry.trampoline = Some(trampoline);
        entry.active = true;
        Ok(())
    }

    /// 安装 GOT/PLT Hook（使用 HookId 避免借用冲突，Unix 独有）
    #[cfg(unix)]
    fn install_got_hook(&mut self, id: HookId) -> Result<()> {
        // 提取 Hook 信息
        let (module, symbol, detour_addr) = {
            let entry = self.hooks.get(&id).unwrap();
            (
                entry.hook_point.module.clone(),
                entry.hook_point.symbol.clone(),
                entry.detour_addr.unwrap_or(0),
            )
        };

        let module_base = self.find_module_base(&module)?;

        let handle = self.got_hooker.hook_module(
            &module,
            &symbol,
            module_base as u64,
            detour_addr,
        )?;

        // 备份原始 GOT 条目值并更新 Hook 条目
        let entry = self.hooks.get_mut(&id).unwrap();
        entry.original_bytes = handle.original_value.to_le_bytes().to_vec();
        entry.got_handle = Some(handle);
        entry.active = true;
        Ok(())
    }

    /// 设置 Hook 的替换函数地址（必须在 install 之前调用）
    pub fn set_detour_addr(&mut self, id: HookId, addr: u64) -> Result<()> {
        let entry = self.hooks.get_mut(&id).ok_or_else(|| {
            crate::FridaError::InvalidHookPoint {
                reason: format!("HookId {} 不存在", id),
            }
        })?;
        entry.detour_addr = Some(addr);
        Ok(())
    }

    /// 卸载指定 Hook，恢复原始指令/数据
    pub fn uninstall_hook(&mut self, id: HookId) -> Result<()> {
        let entry = self.hooks.get_mut(&id).ok_or_else(|| {
            crate::FridaError::InvalidHookPoint {
                reason: format!("HookId {} 不存在", id),
            }
        })?;

        if !entry.active {
            log::warn!("Hook #{} 未安装，无需卸载", id);
            return Ok(());
        }

        match entry.hook_point.hook_type {
            HookType::Inline => {
                if let Some(ref trampoline) = entry.trampoline {
                    // 恢复原始字节
                    self.inline_hooker
                        .write_memory(trampoline.target_addr, &entry.original_bytes)?;
                    // 清理跳板内存
                    let _ = self.inline_hooker.uninstall(trampoline);
                }
            }
            #[cfg(unix)]
            HookType::GotPlt => {
                if let Some(ref handle) = entry.got_handle {
                    self.got_hooker.restore(handle)?;
                }
            }
            #[cfg(not(unix))]
            HookType::GotPlt => {
                log::warn!("GOT/PLT Hook 在 Windows 下不支持");
            }
            HookType::Java => {
                log::info!("Java Hook #{} 需通过 JavaHooker 单独卸载", id);
            }
        }

        entry.active = false;
        entry.trampoline = None;
        #[cfg(unix)]
        {
            entry.got_handle = None;
        }
        log::info!("Hook #{} 已卸载", id);
        Ok(())
    }

    /// 卸载所有已安装的 Hook，恢复原始状态
    pub fn uninstall_all(&mut self) -> Result<()> {
        // 收集所有已激活的 Hook ID，避免借用冲突
        let active_ids: Vec<HookId> = self
            .hooks
            .iter()
            .filter(|(_, e)| e.active)
            .map(|(id, _)| *id)
            .collect();

        let errors: Vec<String> = active_ids
            .into_iter()
            .filter_map(|id| match self.uninstall_hook(id) {
                Ok(()) => None,
                Err(e) => Some(format!("卸载 {} 失败: {}", id, e)),
            })
            .collect();

        if !errors.is_empty() {
            log::warn!("部分 Hook 卸载时出错: {}", errors.join("; "));
        }

        log::info!("所有 Hook 已尝试卸载");
        Ok(())
    }

    /// 查找指定模块的基地址
    ///
    /// 通过解析 /proc/self/maps 找到模块的首次映射地址。
    /// 结果会被缓存以提高后续查找速度。
    pub fn find_module_base(&mut self, module_name: &str) -> Result<usize> {
        // 先检查缓存
        if let Some(&base) = self.module_bases.get(module_name) {
            return Ok(base);
        }

        let pid = crate::common::types::ProcessId(0); // 0 表示当前进程
        let regions = parse_proc_maps(pid)?;

        let base = regions
            .iter()
            .filter(|r| {
                // 匹配路径末尾的模块名
                r.name.ends_with(module_name)
                    || r.name.contains(module_name)
            })
            .filter_map(|r| {
                // 优先选择可执行区域
                if r.perms.execute {
                    Some(r.start)
                } else {
                    None
                }
            })
            .min()
            .or_else(|| {
                // 如果没有找到可执行区域，使用第一个匹配的区域
                regions
                    .iter()
                    .filter(|r| r.name.ends_with(module_name) || r.name.contains(module_name))
                    .map(|r| r.start)
                    .min()
            })
            .ok_or_else(|| {
                crate::FridaError::NotFound {
                    reason: format!("未找到模块 '{}' 的基地址", module_name),
                }
            })?;

        // 写入缓存
        self.module_bases.insert(module_name.to_string(), base);
        log::debug!("模块 '{}' 基地址: {:#x}", module_name, base);
        Ok(base)
    }

    /// 解析模块中的符号地址
    ///
    /// 在模块基址上加上符号偏移得到实际地址。
    /// 首先尝试通过 ELF 解析获取符号偏移，如果失败则使用 dlsym。
    #[cfg(unix)]
    pub fn resolve_symbol(&self, module_base: usize, symbol_name: &str) -> Result<u64> {
        // 尝试通过 /proc/self/maps 获取模块路径，然后解析 ELF
        if let Some(path) = self.find_module_path(&self.get_cached_module_name(symbol_name)) {
            if let Ok(data) = std::fs::read(&path) {
                if let Ok(elf_info) = crate::memory::elf_parser::parse_elf(&data) {
                    if let Some(offset) =
                        crate::memory::elf_parser::find_symbol(&elf_info, symbol_name)
                    {
                        return Ok(module_base as u64 + offset);
                    }
                }
            }
        }

        // 回退到 dlsym
        let c_symbol = std::ffi::CString::new(symbol_name)
            .map_err(|_| crate::FridaError::InvalidHookPoint {
                reason: format!("符号名 '{}' 包含空字节", symbol_name),
            })?;

        let addr = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c_symbol.as_ptr()) };

        if addr.is_null() {
            return Err(crate::FridaError::NotFound {
                reason: format!("无法解析符号 '{}' (module_base={:#x})", symbol_name, module_base),
            }
            .into());
        }

        log::debug!(
            "符号 '{}' 解析地址: {:#x}",
            symbol_name,
            addr as u64
        );
        Ok(addr as u64)
    }

    /// 解析模块中的符号地址（Windows 桩函数）
    #[cfg(windows)]
    pub fn resolve_symbol(&self, _module_base: usize, symbol_name: &str) -> Result<u64> {
        // Windows 下暂未实现 PE 导出表解析
        Err(crate::FridaError::NotFound {
            reason: format!("Windows 下符号解析暂未实现: '{}'", symbol_name),
        }
        .into())
    }

    /// 清除模块基地址缓存
    pub fn clear_cache(&mut self) {
        self.module_bases.clear();
        log::debug!("模块基地址缓存已清除");
    }

    /// 返回已注册的 Hook 数量
    pub fn hook_count(&self) -> usize {
        self.hooks.len()
    }

    /// 返回已激活的 Hook 数量
    pub fn active_hook_count(&self) -> usize {
        self.hooks.values().filter(|e| e.active).count()
    }

    /// 列出所有已注册的 Hook 点信息
    pub fn list_hooks(&self) -> Vec<(HookId, bool, HookPoint)> {
        self.hooks
            .iter()
            .map(|(id, e)| (*id, e.active, e.hook_point.clone()))
            .collect()
    }

    // ---- 辅助方法 ----

    /// 根据符号名获取缓存的模块名（简化实现）
    #[allow(dead_code)]
    fn get_cached_module_name(&self, _symbol_name: &str) -> String {
        String::new()
    }

    /// 查找模块的文件路径
    #[allow(dead_code)]
    fn find_module_path(&self, module_name: &str) -> Option<String> {
        if module_name.is_empty() {
            return None;
        }
        let pid = crate::common::types::ProcessId(0);
        let regions = parse_proc_maps(pid).ok()?;
        for r in &regions {
            if !r.name.is_empty() && r.name.ends_with(module_name) {
                return Some(r.name.clone());
            }
        }
        None
    }

    /// 查找指定模块的所有内存区域
    #[allow(dead_code)]
    fn find_module_regions(&self, module_name: &str) -> Result<Vec<MemoryRegion>> {
        let pid = crate::common::types::ProcessId(0);
        let regions = parse_proc_maps(pid)?;
        let module_regions: Vec<MemoryRegion> = regions
            .into_iter()
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

        Ok(module_regions)
    }

    /// 读取远程进程内存（内部辅助方法）
    #[allow(dead_code)]
    fn read_remote_memory(&self, pid: u32, addr: u64, size: usize) -> Result<Vec<u8>> {
        safe_read_bytes(crate::common::types::ProcessId(pid), addr as usize, size)
    }
}

impl Default for HookManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for HookManager {
    fn drop(&mut self) {
        // 析构时自动卸载所有 Hook
        if self.hooks.values().any(|e| e.active) {
            let _ = self.uninstall_all();
            log::info!("HookManager 析构，所有 Hook 已清理");
        }
    }
}
