//! /proc 接口伪装模块
//!
//! 通过 Hook libc 的 openat / read 等函数来拦截 /proc 文件读取，
//! 隐藏 /proc/self/maps 中与 frida-rust 相关的内存映射条目，
//! 过滤掉包含敏感路径的行。

use crate::common::types::ProcessId;
use crate::common::util::parse_proc_maps;
use crate::hook::got_plt::GotPltHooker;
use crate::Result;
use std::collections::HashSet;

// ======================== maps_hide 模块全局状态 ========================

/// 保存原始 openat 函数指针（maps_hide 专用）
///
/// 注意：如果 tracer.rs 的 openat Hook 也已安装，此指针可能已被覆盖。
/// maps_hide 应在 tracer 之后安装（或使用统一的 Hook 管理器）。
#[cfg(any(target_os = "linux", target_os = "android"))]
static MAPS_ORIGINAL_OPENAT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// 保存原始 read 函数指针（maps_hide 专用）
#[cfg(any(target_os = "linux", target_os = "android"))]
static MAPS_ORIGINAL_READ: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// 被 maps_hide 拦截的 fd 标记数组
#[cfg(any(target_os = "linux", target_os = "android"))]
static mut MAPS_INTERCEPTED_FD_SET: [bool; 4096] = [false; 4096];

/// 被 maps_hide 拦截的 fd 对应的文件类型
/// 1=maps, 2=status, 0=other
#[cfg(any(target_os = "linux", target_os = "android"))]
static mut MAPS_INTERCEPTED_FD_TYPE: [u8; 4096] = [0u8; 4096];

/// DefaultProcInterceptor 全局指针
///
/// 替换函数通过此指针访问 hidden_modules / hidden_ranges 进行过滤。
#[cfg(any(target_os = "linux", target_os = "android"))]
static mut MAPS_INTERCEPTOR_PTR: Option<*mut std::ffi::c_void> = None;

/// 标记某个 fd 为被 maps_hide 拦截
#[cfg(any(target_os = "linux", target_os = "android"))]
#[inline]
unsafe fn maps_mark_fd_intercepted(fd: i32, intercepted: bool) {
    if fd >= 0 && (fd as usize) < MAPS_INTERCEPTED_FD_SET.len() {
        MAPS_INTERCEPTED_FD_SET[fd as usize] = intercepted;
    }
}

/// 检查 fd 是否被 maps_hide 拦截
#[cfg(any(target_os = "linux", target_os = "android"))]
#[inline]
unsafe fn maps_is_fd_intercepted(fd: i32) -> bool {
    if fd >= 0 && (fd as usize) < MAPS_INTERCEPTED_FD_SET.len() {
        MAPS_INTERCEPTED_FD_SET[fd as usize]
    } else {
        false
    }
}

/// 设置被拦截 fd 的文件类型：1=maps, 2=status
#[cfg(any(target_os = "linux", target_os = "android"))]
#[inline]
unsafe fn maps_set_fd_type(fd: i32, type_val: u8) {
    if fd >= 0 && (fd as usize) < MAPS_INTERCEPTED_FD_TYPE.len() {
        MAPS_INTERCEPTED_FD_TYPE[fd as usize] = type_val;
    }
}

/// 获取被拦截 fd 的文件类型
#[cfg(any(target_os = "linux", target_os = "android"))]
#[inline]
unsafe fn maps_get_fd_type(fd: i32) -> u8 {
    if fd >= 0 && (fd as usize) < MAPS_INTERCEPTED_FD_TYPE.len() {
        MAPS_INTERCEPTED_FD_TYPE[fd as usize]
    } else {
        0
    }
}

/// 清除所有 maps_hide 的 fd 标记
#[cfg(any(target_os = "linux", target_os = "android"))]
unsafe fn maps_clear_all_fds() {
    MAPS_INTERCEPTED_FD_SET.fill(false);
    MAPS_INTERCEPTED_FD_TYPE.fill(0);
}

/// 设置 errno（Android 使用 __errno()，Linux 使用 __errno_location()）
#[inline]
unsafe fn set_errno(err: i32) {
    #[cfg(target_os = "android")]
    {
        *libc::__errno() = err;
    }
    #[cfg(not(target_os = "android"))]
    {
        *libc::__errno_location() = err;
    }
}

// ======================== maps_hide 替换函数 ========================

/// maps_hide 模块的 openat 替换函数
///
/// 当检测到打开 /proc/self/maps 或 /proc/self/status 时，
/// 调用原始 openat 获取真实 fd，然后标记该 fd 为"已拦截"。
#[cfg(any(target_os = "linux", target_os = "android"))]
unsafe extern "C" fn maps_openat_replace_fn(
    dirfd: libc::c_int,
    pathname: *const libc::c_char,
    flags: libc::c_int,
) -> libc::c_int {
    let original_fn = MAPS_ORIGINAL_OPENAT.load(std::sync::atomic::Ordering::Relaxed);
    if original_fn == 0 {
        unsafe {
            set_errno(libc::EINVAL);
        }
        return -1;
    }

    // 读取路径字符串
    let path_str = if !pathname.is_null() {
        std::ffi::CStr::from_ptr(pathname).to_string_lossy()
    } else {
        return -1;
    };

    // 检查是否为 /proc/self/maps 或 /proc/self/status
    let is_maps = path_str.contains("/proc/self/maps");
    let is_status = path_str.contains("/proc/self/status");

    if is_maps || is_status {
        log::trace!("maps_hide openat 拦截到 /proc 文件: {}", path_str);
    }

    // 调用原始 openat
    // SAFETY: original_fn 是从 GOT 条目中读取的合法函数指针
    let original_openat: unsafe extern "C" fn(
        libc::c_int,
        *const libc::c_char,
        libc::c_int,
    ) -> libc::c_int = std::mem::transmute(original_fn);

    let fd = original_openat(dirfd, pathname, flags);

    if fd >= 0 && (is_maps || is_status) {
        // 标记该 fd 为已拦截
        maps_mark_fd_intercepted(fd, true);
        maps_set_fd_type(
            fd,
            if is_maps { 1 } else if is_status { 2 } else { 0 },
        );
    }

    fd
}

/// maps_hide 模块的 read 替换函数
///
/// 当读取被拦截的 maps fd 时，对返回数据逐行过滤，
/// 移除包含隐藏模块名称或敏感地址范围的行。
/// 当读取被拦截的 status fd 时，修改 TracerPid 字段。
#[cfg(any(target_os = "linux", target_os = "android"))]
unsafe extern "C" fn maps_read_replace_fn(
    fd: libc::c_int,
    buf: *mut libc::c_void,
    count: usize,
) -> isize {
    let original_fn = MAPS_ORIGINAL_READ.load(std::sync::atomic::Ordering::Relaxed);
    if original_fn == 0 {
        unsafe {
            set_errno(libc::EBADF);
        }
        return -1;
    }

    // 检查是否为被拦截的 fd
    let intercepted = maps_is_fd_intercepted(fd);
    let fd_type = if intercepted { maps_get_fd_type(fd) } else { 0 };

    // 调用原始 read
    // SAFETY: original_fn 是从 GOT 条目中读取的合法函数指针
    let original_read: unsafe extern "C" fn(libc::c_int, *mut libc::c_void, usize) -> isize =
        std::mem::transmute(original_fn);
    let n = original_read(fd, buf, count);

    if n > 0 && intercepted {
        let content =
            std::str::from_utf8(std::slice::from_raw_parts(buf as *const u8, n as usize));
        if let Ok(content_str) = content {
            match fd_type {
                1 => {
                    // /proc/self/maps：通过全局指针获取拦截器进行过滤
                    if let Some(ptr) = MAPS_INTERCEPTOR_PTR {
                        // SAFETY: 调用者保证 MAPS_INTERCEPTOR_PTR 在 Hook 期间指向有效的 DefaultProcInterceptor
                        let interceptor = &mut *(ptr as *mut DefaultProcInterceptor);
                        let filtered = interceptor.filter_maps_content(content_str);
                        let filtered_bytes = filtered.as_bytes();
                        let copy_len = std::cmp::min(filtered_bytes.len(), n as usize);
                        std::ptr::copy_nonoverlapping(
                            filtered_bytes.as_ptr(),
                            buf as *mut u8,
                            copy_len,
                        );
                        log::trace!("maps_hide read 拦截: maps fd={} 过滤完成", fd);
                        return copy_len as isize;
                    }
                }
                2 => {
                    // /proc/self/status：修改 TracerPid
                    if let Some(ptr) = MAPS_INTERCEPTOR_PTR {
                        let interceptor = &mut *(ptr as *mut DefaultProcInterceptor);
                        let filtered = interceptor.filter_status_content(content_str);
                        let filtered_bytes = filtered.as_bytes();
                        let copy_len = std::cmp::min(filtered_bytes.len(), n as usize);
                        std::ptr::copy_nonoverlapping(
                            filtered_bytes.as_ptr(),
                            buf as *mut u8,
                            copy_len,
                        );
                        log::trace!("maps_hide read 拦截: status fd={} 修改 TracerPid", fd);
                        return copy_len as isize;
                    }
                }
                _ => {}
            }
        }
    }

    n
}

// ======================== /proc 操作 Trait ========================

/// /proc 文件操作 trait
///
/// 使用 trait + 默认实现的方式，方便后续扩展不同的 /proc 拦截策略。
/// 例如可以切换为 LD_PRELOAD、inline hook、seccomp-bpf 等不同实现。
pub trait ProcInterceptor {
    /// 拦截 /proc/self/maps 的读取
    ///
    /// 过滤掉包含敏感模块名称的行。
    fn filter_maps_content(&self, content: &str) -> String;

    /// 拦截 /proc/self/status 的读取
    ///
    /// 修改 TracerPid 等敏感字段。
    fn filter_status_content(&self, content: &str) -> String;

    /// 安装 /proc 拦截 Hook
    fn install_hook(&mut self) -> Result<()>;

    /// 卸载 /proc 拦截 Hook
    fn uninstall_hook(&mut self) -> Result<()>;
}

// ======================== 默认拦截实现 ========================

/// 默认的 /proc 内容过滤器
///
/// 基于文本过滤的实现，通过修改 read() 返回的内容来隐藏敏感信息。
pub struct DefaultProcInterceptor {
    /// 需要隐藏的模块名称列表
    hidden_modules: HashSet<String>,
    /// 需要隐藏的地址范围列表
    hidden_ranges: Vec<(usize, usize)>,
    /// 是否已安装 Hook
    hooked: bool,
    /// GOT Hook 安装器实例
    #[cfg(any(target_os = "linux", target_os = "android"))]
    got_hooker: Option<GotPltHooker>,
    /// Hook openat 的原始函数指针备份
    #[cfg(any(target_os = "linux", target_os = "android"))]
    original_openat_fn: Option<usize>,
    /// Hook read 的原始函数指针备份
    #[cfg(any(target_os = "linux", target_os = "android"))]
    original_read_fn: Option<usize>,
}

impl DefaultProcInterceptor {
    /// 创建默认拦截器
    pub fn new() -> Self {
        DefaultProcInterceptor {
            hidden_modules: HashSet::new(),
            hidden_ranges: Vec::new(),
            hooked: false,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            got_hooker: None,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            original_openat_fn: None,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            original_read_fn: None,
        }
    }

    /// 添加需要隐藏的模块名称
    pub fn add_hidden_module(&mut self, name: &str) {
        self.hidden_modules.insert(name.to_lowercase());
    }

    /// 添加需要隐藏的地址范围
    pub fn add_hidden_range(&mut self, start: usize, end: usize) {
        self.hidden_ranges.push((start, end));
    }

    /// 检查一行 maps 内容是否应该被隐藏
    fn should_hide_line(&self, line: &str) -> bool {
        // 检查模块名称匹配
        for hidden in &self.hidden_modules {
            if line.to_lowercase().contains(hidden.as_str()) {
                return true;
            }
        }

        // 检查地址范围匹配
        // maps 行格式: address perms offset dev inode pathname
        if let Some(addr_part) = line.split_whitespace().next() {
            if let Some(dash_pos) = addr_part.find('-') {
                if let (Ok(start), Ok(end)) = (
                    usize::from_str_radix(&addr_part[..dash_pos], 16),
                    usize::from_str_radix(&addr_part[dash_pos + 1..], 16),
                ) {
                    for &(hidden_start, hidden_end) in &self.hidden_ranges {
                        // 检查是否有重叠
                        if start < hidden_end && end > hidden_start {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }

    /// 查找指定模块的基址
    ///
    /// 通过解析 /proc/self/maps 找到模块的加载基址。
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn find_module_base(module_name: &str) -> Result<u64> {
        let regions = parse_proc_maps(ProcessId(0))?;

        for region in &regions {
            if !region.name.is_empty()
                && (region.name.ends_with(module_name)
                    || region.name.contains(&format!("/{}", module_name)))
            {
                log::debug!("找到模块 {} 基址: {:#x}", module_name, region.start);
                return Ok(region.start as u64);
            }
        }

        Err(crate::FridaError::NotFound {
            reason: format!("未找到模块 '{}' 的基址", module_name),
        }
        .into())
    }

    /// 安装 GOT Hook 拦截 openat
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn hook_openat(&mut self, hooker: &mut GotPltHooker) -> Result<()> {
        log::info!("maps_hide: Hook openat 系统调用");

        // 查找 libc.so 的基址
        let libc_base = Self::find_module_base("libc.so.6")
            .or_else(|_| Self::find_module_base("libc.so"))?;

        // 使用 dlsym 确保 GOT 条目已解析（延迟绑定需要先触发解析）
        let sym_addr = unsafe {
            libc::dlsym(
                libc::RTLD_DEFAULT,
                b"openat\0".as_ptr() as *const libc::c_char,
            )
        };

        if sym_addr.is_null() {
            return Err(crate::FridaError::NotFound {
                reason: "dlsym 未找到符号 'openat'".to_string(),
            }
            .into());
        }

        // 将替换函数地址转换为 u64
        let replace_fn_addr = maps_openat_replace_fn as *const () as u64;

        // 安装 GOT Hook
        let handle = hooker.hook_module("libc.so.6", "openat", libc_base, replace_fn_addr)?;

        // 保存原始函数指针
        self.original_openat_fn = Some(handle.original_value as usize);
        MAPS_ORIGINAL_OPENAT.store(handle.original_value as usize, std::sync::atomic::Ordering::SeqCst);

        log::info!(
            "maps_hide openat Hook 已安装: 原始地址 {:#x} -> 替换地址 {:#x}",
            handle.original_value,
            replace_fn_addr
        );

        Ok(())
    }

    /// 安装 GOT Hook 拦截 read
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn hook_read(&mut self, hooker: &mut GotPltHooker) -> Result<()> {
        log::info!("maps_hide: Hook read 系统调用");

        // 查找 libc.so 的基址
        let libc_base = Self::find_module_base("libc.so.6")
            .or_else(|_| Self::find_module_base("libc.so"))?;

        // 使用 dlsym 确保 GOT 条目已解析
        let sym_addr = unsafe {
            libc::dlsym(libc::RTLD_DEFAULT, b"read\0".as_ptr() as *const libc::c_char)
        };

        if sym_addr.is_null() {
            return Err(crate::FridaError::NotFound {
                reason: "dlsym 未找到符号 'read'".to_string(),
            }
            .into());
        }

        // 将替换函数地址转换为 u64
        let replace_fn_addr = maps_read_replace_fn as *const () as u64;

        // 安装 GOT Hook
        let handle = hooker.hook_module("libc.so.6", "read", libc_base, replace_fn_addr)?;

        // 保存原始函数指针
        self.original_read_fn = Some(handle.original_value as usize);
        MAPS_ORIGINAL_READ.store(handle.original_value as usize, std::sync::atomic::Ordering::SeqCst);

        log::info!(
            "maps_hide read Hook 已安装: 原始地址 {:#x} -> 替换地址 {:#x}",
            handle.original_value,
            replace_fn_addr
        );

        Ok(())
    }
}

impl ProcInterceptor for DefaultProcInterceptor {
    /// 过滤 /proc/self/maps 内容
    ///
    /// 逐行检查，移除包含敏感模块名称或敏感地址范围的行。
    fn filter_maps_content(&self, content: &str) -> String {
        let mut filtered = String::with_capacity(content.len());
        let mut hidden_count = 0;

        for line in content.lines() {
            if self.should_hide_line(line) {
                hidden_count += 1;
                log::trace!("maps 过滤隐藏行: {}", line.trim());
            } else {
                filtered.push_str(line);
                filtered.push('\n');
            }
        }

        if hidden_count > 0 {
            log::info!("maps 过滤: 隐藏了 {} 行", hidden_count);
        }

        filtered
    }

    /// 过滤 /proc/self/status 内容
    ///
    /// 目前仅修改 TracerPid 字段。
    fn filter_status_content(&self, content: &str) -> String {
        let mut result = String::with_capacity(content.len());

        for line in content.lines() {
            if line.starts_with("TracerPid:") {
                // 将 TracerPid 的值替换为 0
                result.push_str("TracerPid:\t0\n");
                log::trace!("status 过滤: 修改 TracerPid 行");
            } else {
                result.push_str(line);
                result.push('\n');
            }
        }

        result
    }

    /// 安装 /proc 拦截 Hook
    ///
    /// 通过 GOT Hook 拦截 libc 的 openat / read 等函数。
    /// 当检测到读取 /proc/self/maps 或 /proc/self/status 时，
    /// 使用过滤后的内容替代原始内容。
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn install_hook(&mut self) -> Result<()> {
        if self.hooked {
            log::debug!("maps Hook 已安装");
            return Ok(());
        }

        log::info!("安装 /proc 拦截 Hook（GOT Hook 方式）");

        // 创建 GOT Hook 安装器
        let mut hooker = GotPltHooker::new();

        // 安装 openat Hook
        self.hook_openat(&mut hooker)?;

        // 安装 read Hook
        self.hook_read(&mut hooker)?;

        // 保存 GOT Hook 安装器实例
        self.got_hooker = Some(hooker);

        // 设置全局拦截器指针（供替换函数使用）
        // SAFETY: MAPS_INTERCEPTOR_PTR 在 Hook 期间指向有效的 DefaultProcInterceptor 实例
        unsafe {
            MAPS_INTERCEPTOR_PTR = Some(self as *mut _ as *mut std::ffi::c_void);
        }

        self.hooked = true;
        log::info!("/proc 拦截 Hook 已安装");
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    fn install_hook(&mut self) -> Result<()> {
        log::info!("非 Linux 平台，跳过 /proc 拦截 Hook 安装");
        self.hooked = true;
        Ok(())
    }

    /// 卸载 /proc 拦截 Hook
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn uninstall_hook(&mut self) -> Result<()> {
        if !self.hooked {
            return Ok(());
        }

        log::info!("卸载 /proc 拦截 Hook");

        // 恢复所有 GOT Hook
        if let Some(ref hooker) = self.got_hooker {
            hooker.restore_all()?;
            log::info!("所有 GOT 条目已恢复");
        }

        // 清除全局状态
        unsafe {
            MAPS_INTERCEPTOR_PTR = None;
            maps_clear_all_fds();
        }

        // 清除全局原始函数指针
        MAPS_ORIGINAL_OPENAT.store(0, std::sync::atomic::Ordering::SeqCst);
        MAPS_ORIGINAL_READ.store(0, std::sync::atomic::Ordering::SeqCst);

        // 清空内部状态
        self.got_hooker = None;
        self.original_openat_fn = None;
        self.original_read_fn = None;

        self.hooked = false;
        log::info!("/proc 拦截 Hook 已卸载");
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    fn uninstall_hook(&mut self) -> Result<()> {
        self.hooked = false;
        Ok(())
    }
}

impl Default for DefaultProcInterceptor {
    fn default() -> Self {
        Self::new()
    }
}

// ======================== Maps 隐藏器 ========================

/// Maps 隐藏器
///
/// 管理 /proc/self/maps 的隐藏策略，包括模块名隐藏和地址范围隐藏。
/// 内部使用 DefaultProcInterceptor 实现实际的过滤逻辑。
pub struct MapsHider {
    /// 内部拦截器
    interceptor: DefaultProcInterceptor,
    /// 是否已隐藏
    hidden: bool,
}

impl MapsHider {
    /// 创建新的 Maps 隐藏器
    pub fn new() -> Self {
        MapsHider {
            interceptor: DefaultProcInterceptor::new(),
            hidden: false,
        }
    }

    /// 隐藏指定模块在 maps 中的条目
    ///
    /// # 参数
    /// - `module_name`: 需要隐藏的模块名称（如 "libfrida_agent.so"）
    pub fn hide_module_maps(&mut self, module_name: &str) {
        log::info!("隐藏模块 maps 条目: {}", module_name);
        self.interceptor.add_hidden_module(module_name);
    }

    /// 隐藏指定地址范围在 maps 中的条目
    ///
    /// # 参数
    /// - `addrs`: 需要隐藏的地址列表
    pub fn hide_memory_regions(&mut self, addrs: &[u64]) {
        log::info!("隐藏 {} 个地址范围", addrs.len() / 2);
        for chunk in addrs.chunks(2) {
            if chunk.len() == 2 {
                self.interceptor
                    .add_hidden_range(chunk[0] as usize, chunk[1] as usize);
            }
        }
    }

    /// 使用默认特征关键词隐藏 maps 条目
    ///
    /// 自动隐藏包含 "frida"、"agent"、"gadget" 等关键词的映射条目。
    pub fn hide_default(&mut self) -> Result<()> {
        // 默认需要隐藏的特征关键词
        let keywords = [
            "frida",
            "agent",
            "gadget",
            "linjector",
            "gum-js",
            "gum-js-loop",
        ];

        for keyword in &keywords {
            self.interceptor.add_hidden_module(keyword);
        }

        log::info!("已配置 {} 个默认隐藏关键词", keywords.len());

        // 读取当前 maps，扫描并标记特征区域
        let regions = crate::common::util::parse_proc_maps(ProcessId(0))?;
        let mut found_count = 0;

        for region in &regions {
            for keyword in &keywords {
                if region.name.to_lowercase().contains(keyword) {
                    log::info!(
                        "发现特征映射: {} {:#x}-{:#x} ({} bytes)",
                        region.name,
                        region.start,
                        region.end,
                        region.size()
                    );
                    self.interceptor
                        .add_hidden_range(region.start, region.end);
                    found_count += 1;
                    break;
                }
            }
        }

        // 安装 Hook
        self.interceptor.install_hook()?;
        self.hidden = true;

        log::info!(
            "maps 隐藏配置完成: {} 个特征区域, {} 个关键词",
            found_count,
            keywords.len()
        );
        Ok(())
    }

    /// 恢复原始 maps（卸载 Hook）
    pub fn restore(&mut self) -> Result<()> {
        if !self.hidden {
            return Ok(());
        }

        self.interceptor.uninstall_hook()?;
        self.hidden = false;

        log::info!("maps 隐藏已恢复");
        Ok(())
    }

    /// 检查是否已隐藏
    pub fn is_hidden(&self) -> bool {
        self.hidden
    }

    /// 过滤 maps 内容（供外部调用）
    pub fn filter_maps(&self, content: &str) -> String {
        self.interceptor.filter_maps_content(content)
    }

    /// 获取已配置的隐藏模块数量
    pub fn hidden_module_count(&self) -> usize {
        self.interceptor.hidden_modules.len()
    }

    /// 获取已配置的隐藏范围数量
    pub fn hidden_range_count(&self) -> usize {
        self.interceptor.hidden_ranges.len()
    }
}

impl Default for MapsHider {
    fn default() -> Self {
        Self::new()
    }
}

// ======================== 便捷函数 ========================

/// 隐藏 /proc/self/maps 中包含特征字符串的条目（便捷函数）
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn hide_maps_entries() -> crate::Result<()> {
    let mut hider = MapsHider::new();
    hider.hide_default()?;
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn hide_maps_entries() -> crate::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_interceptor_filter_maps() {
        let interceptor = DefaultProcInterceptor::new();

        let content = "7f0000000000-7f0000001000 r-xp 00000000 08:01 1234 /usr/lib/libfoo.so\n\
                        7f0000001000-7f0000002000 rw-p 00000000 08:01 5678 /usr/lib/libfrida-agent.so\n\
                        7f0000002000-7f0000003000 r-xp 00000000 08:01 9012 /usr/lib/libbar.so\n";

        let filtered = interceptor.filter_maps_content(content);
        assert!(!filtered.contains("libfrida-agent.so"));
        assert!(filtered.contains("libfoo.so"));
        assert!(filtered.contains("libbar.so"));
    }

    #[test]
    fn test_interceptor_filter_status() {
        let interceptor = DefaultProcInterceptor::new();

        let content = "Name:\ttest\nTracerPid:\t1234\nPid:\t5678\n";
        let filtered = interceptor.filter_status_content(content);

        assert!(filtered.contains("TracerPid:\t0"));
        assert!(!filtered.contains("TracerPid:\t1234"));
        assert!(filtered.contains("Name:\ttest"));
    }

    #[test]
    fn test_maps_hider_creation() {
        let hider = MapsHider::new();
        assert!(!hider.is_hidden());
        assert_eq!(hider.hidden_module_count(), 0);
    }

    #[test]
    fn test_maps_hider_add_module() {
        let mut hider = MapsHider::new();
        hider.hide_module_maps("libfrida-agent.so");
        assert_eq!(hider.hidden_module_count(), 1);
    }

    #[test]
    fn test_maps_hider_filter() {
        let mut hider = MapsHider::new();
        hider.hide_module_maps("frida");

        let content = "7f0000000000-7f0000001000 r-xp 00000000 08:01 1234 /usr/lib/libtest.so\n\
                        7f0000001000-7f0000002000 r-xp 00000000 08:01 5678 /usr/lib/libfrida.so\n";

        let filtered = hider.filter_maps(content);
        assert!(!filtered.contains("libfrida.so"));
        assert!(filtered.contains("libtest.so"));
    }

    #[test]
    fn test_interceptor_range_filter() {
        let mut interceptor = DefaultProcInterceptor::new();
        interceptor.add_hidden_range(0x7f0000001000, 0x7f0000002000);

        let content = "7f0000000000-7f0000001000 r-xp 00000000 08:01 1234 /usr/lib/liba.so\n\
                        7f0000001000-7f0000002000 r-xp 00000000 08:01 5678 /usr/lib/libb.so\n\
                        7f0000002000-7f0000003000 r-xp 00000000 08:01 9012 /usr/lib/libc.so\n";

        let filtered = interceptor.filter_maps_content(content);
        assert!(!filtered.contains("libb.so"));
        assert!(filtered.contains("liba.so"));
        assert!(filtered.contains("libc.so"));
    }
}
