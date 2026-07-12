//! TracerPid 清除模块
//!
//! 当进程被 ptrace 附加后，/proc/self/status 中的 TracerPid 字段
//! 会显示调试者的 PID。本模块通过 Hook libc 函数拦截
//! 对 /proc/self/status 的读取操作，将 TracerPid 修改为 0。
//!
//! 实现策略：
//! 1. 读取 /proc/self/status 验证当前 TracerPid
//! 2. 通过 GOT Hook 拦截 openat/read 系统调用
//! 3. 在 read 返回数据中修改 TracerPid 字段

use crate::hook::got_plt::GotPltHooker;
use crate::FridaError;
use crate::Result;
use crate::common::types::ProcessId;
use crate::common::util::parse_proc_maps;

// ======================== 全局状态（用于替换函数访问） ========================

/// 保存原始 openat 函数指针
///
/// 替换函数通过此指针调用原始 openat。
/// 使用 atomic 便于跨线程安全访问。
#[cfg(any(target_os = "linux", target_os = "android"))]
static ORIGINAL_OPENAT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// 保存原始 read 函数指针
///
/// 替换函数通过此指针调用原始 read。
#[cfg(any(target_os = "linux", target_os = "android"))]
static ORIGINAL_READ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// 保存原始 ptrace 函数指针
#[cfg(any(target_os = "linux", target_os = "android"))]
static ORIGINAL_PTRACE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// 被 openat 拦截的 fd 标记数组
///
/// 当 openat 检测到 /proc/self/status 或 /proc/self/maps 时，
/// 调用原始 openat 获取真实 fd，然后将该 fd 在数组中标记为"已拦截"。
/// 后续 read 调用检查此数组来决定是否过滤内容。
#[cfg(any(target_os = "linux", target_os = "android"))]
static mut INTERCEPTED_FD_SET: [bool; 4096] = [false; 4096];

/// fd 对应的 /proc 文件类型
#[cfg(any(target_os = "linux", target_os = "android"))]
#[derive(Clone, Copy, PartialEq)]
enum InterceptFileType {
    /// /proc/self/status
    Status,
    /// /proc/self/maps
    Maps,
    /// 其他文件
    Other,
}

/// 保存每个被拦截 fd 对应的文件类型
/// 0=Other, 1=Status, 2=Maps
#[cfg(any(target_os = "linux", target_os = "android"))]
static mut INTERCEPTED_FD_TYPE: [u8; 4096] = [0u8; 4096];

/// 标记某个 fd 是否为被拦截的 /proc 文件
#[cfg(any(target_os = "linux", target_os = "android"))]
#[inline]
unsafe fn mark_fd_intercepted(fd: i32, intercepted: bool) {
    if fd >= 0 && (fd as usize) < INTERCEPTED_FD_SET.len() {
        INTERCEPTED_FD_SET[fd as usize] = intercepted;
    }
}

/// 检查 fd 是否为被拦截的 /proc 文件
#[cfg(any(target_os = "linux", target_os = "android"))]
#[inline]
unsafe fn is_fd_intercepted(fd: i32) -> bool {
    if fd >= 0 && (fd as usize) < INTERCEPTED_FD_SET.len() {
        INTERCEPTED_FD_SET[fd as usize]
    } else {
        false
    }
}

/// 设置被拦截 fd 对应的文件类型
#[cfg(any(target_os = "linux", target_os = "android"))]
#[inline]
unsafe fn set_fd_file_type(fd: i32, ftype: InterceptFileType) {
    if fd >= 0 && (fd as usize) < INTERCEPTED_FD_TYPE.len() {
        INTERCEPTED_FD_TYPE[fd as usize] = match ftype {
            InterceptFileType::Status => 1,
            InterceptFileType::Maps => 2,
            InterceptFileType::Other => 0,
        };
    }
}

/// 获取被拦截 fd 对应的文件类型
#[cfg(any(target_os = "linux", target_os = "android"))]
#[inline]
unsafe fn get_fd_file_type(fd: i32) -> InterceptFileType {
    if fd >= 0 && (fd as usize) < INTERCEPTED_FD_TYPE.len() {
        match INTERCEPTED_FD_TYPE[fd as usize] {
            1 => InterceptFileType::Status,
            2 => InterceptFileType::Maps,
            _ => InterceptFileType::Other,
        }
    } else {
        InterceptFileType::Other
    }
}

/// 清除所有被拦截的 fd 标记
#[cfg(any(target_os = "linux", target_os = "android"))]
unsafe fn clear_all_intercepted_fds() {
    INTERCEPTED_FD_SET.fill(false);
    INTERCEPTED_FD_TYPE.fill(0);
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

// ======================== 替换函数 ========================

/// openat 替换函数
///
/// 当检测到打开 /proc/self/status 或 /proc/self/maps 时，
/// 调用原始 openat 获取真实 fd，然后标记该 fd 为"已拦截"。
///
/// 注意：openat 是可变参数函数（第四个参数 mode 仅在 O_CREAT 时有效），
/// 在 GOT Hook 中，替换函数的签名需要匹配 libc 中的实际导出符号。
/// 这里使用不含可变参数的固定签名：openat(dirfd, path, flags)，
/// 对于不传 mode 的情况（打开 /proc 文件不需要 O_CREAT），这是安全的。
#[cfg(any(target_os = "linux", target_os = "android"))]
unsafe extern "C" fn openat_replace_fn(
    dirfd: libc::c_int,
    pathname: *const libc::c_char,
    flags: libc::c_int,
) -> libc::c_int {
    // 获取原始 openat 函数指针
    let original_fn = ORIGINAL_OPENAT.load(std::sync::atomic::Ordering::Relaxed);
    if original_fn == 0 {
        // 原始指针未设置，直接返回错误
        // SAFETY: 通过 set_errno 设置 errno
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

    // 检查是否为 /proc/self/status 或 /proc/self/maps
    let is_status = path_str.contains("/proc/self/status");
    let is_maps = path_str.contains("/proc/self/maps");

    if is_status || is_maps {
        log::trace!("openat 拦截到 /proc 文件: {}", path_str);
    }

    // 调用原始 openat（不含 mode 参数，对 /proc 文件足够）
    // SAFETY: original_fn 是从 GOT 条目中读取的合法函数指针
    let original_openat: unsafe extern "C" fn(
        libc::c_int,
        *const libc::c_char,
        libc::c_int,
    ) -> libc::c_int = std::mem::transmute(original_fn);

    let fd = original_openat(dirfd, pathname, flags);

    if fd >= 0 && (is_status || is_maps) {
        // 标记该 fd 为已拦截
        mark_fd_intercepted(fd, true);
        set_fd_file_type(
            fd,
            if is_status {
                InterceptFileType::Status
            } else {
                InterceptFileType::Maps
            },
        );
    }

    fd
}

/// read 替换函数
///
/// 当读取被拦截的 fd 时，对返回数据进行过滤修改：
/// - /proc/self/status：将 TracerPid 修改为 0
/// - /proc/self/maps：不做额外过滤（maps 过滤在 maps_hide 模块处理）
#[cfg(any(target_os = "linux", target_os = "android"))]
unsafe extern "C" fn read_replace_fn(
    fd: libc::c_int,
    buf: *mut libc::c_void,
    count: usize,
) -> isize {
    let original_fn = ORIGINAL_READ.load(std::sync::atomic::Ordering::Relaxed);
    if original_fn == 0 {
        unsafe {
            set_errno(libc::EBADF);
        }
        return -1;
    }

    // 检查是否为被拦截的 fd
    let intercepted = is_fd_intercepted(fd);
    let ftype = if intercepted { get_fd_file_type(fd) } else { InterceptFileType::Other };

    // 调用原始 read
    // SAFETY: original_fn 是从 GOT 条目中读取的合法函数指针
    let original_read: unsafe extern "C" fn(libc::c_int, *mut libc::c_void, usize) -> isize =
        std::mem::transmute(original_fn);
    let n = original_read(fd, buf, count);

    if n > 0 && intercepted {
        // 将读取的内容转换为字符串进行过滤
        let content =
            std::str::from_utf8(std::slice::from_raw_parts(buf as *const u8, n as usize));
        if let Ok(content_str) = content {
            match ftype {
                InterceptFileType::Status => {
                    // 过滤 TracerPid 字段
                    let filtered = patch_tracer_pid_static(content_str);
                    let filtered_bytes = filtered.as_bytes();
                    let copy_len = std::cmp::min(filtered_bytes.len(), n as usize);
                    // 将过滤后的内容写回 buf
                    std::ptr::copy_nonoverlapping(
                        filtered_bytes.as_ptr(),
                        buf as *mut u8,
                        copy_len,
                    );
                    log::trace!("read 拦截: status fd={} 修改 TracerPid", fd);
                    return copy_len as isize;
                }
                InterceptFileType::Maps => {
                    // maps 文件的过滤由 maps_hide 模块处理
                    log::trace!("read 拦截: maps fd={} (由 maps_hide 处理)", fd);
                }
                InterceptFileType::Other => {}
            }
        }
    }

    n
}

/// 修改 status 内容中的 TracerPid 字段（静态版本，不依赖 self）
#[cfg(any(target_os = "linux", target_os = "android"))]
fn patch_tracer_pid_static(content: &str) -> String {
    let mut result = String::with_capacity(content.len());
    for line in content.lines() {
        if line.starts_with("TracerPid:") {
            let trimmed = line.trim_start_matches("TracerPid:");
            let whitespace = if trimmed.starts_with('\t') {
                "\t"
            } else if trimmed.starts_with(' ') {
                " "
            } else {
                "\t"
            };
            result.push_str(&format!("TracerPid:{}0", whitespace));
        } else {
            result.push_str(line);
        }
        result.push('\n');
    }
    result
}

/// ptrace 替换函数
///
/// 当检测到 PTRACE_TRACEME 请求时，直接返回 0（成功），
/// 让调用者认为 ptrace 操作成功，进程未被调试。
/// 其他 ptrace 请求正常透传给原始函数。
#[cfg(any(target_os = "linux", target_os = "android"))]
unsafe extern "C" fn ptrace_replace_fn(
    request: libc::c_uint,
    pid: libc::pid_t,
    addr: *mut libc::c_void,
    data: *mut libc::c_void,
) -> libc::c_long {
    let original_fn = ORIGINAL_PTRACE.load(std::sync::atomic::Ordering::Relaxed);
    if original_fn == 0 {
        // 原始指针未设置
        unsafe {
            set_errno(libc::ENOSYS);
        }
        return -1;
    }

    // PTRACE_TRACEME = 0
    if request == 0 {
        log::debug!("ptrace 拦截: PTRACE_TRACEME -> 返回 0 (伪装未被调试)");
        return 0;
    }

    // 其他 ptrace 请求透传给原始函数
    // SAFETY: original_fn 是从 GOT 条目中读取的合法函数指针
    let original_ptrace: unsafe extern "C" fn(
        libc::c_uint,
        libc::pid_t,
        *mut libc::c_void,
        *mut libc::c_void,
    ) -> libc::c_long = std::mem::transmute(original_fn);

    original_ptrace(request, pid, addr, data)
}

// ======================== Tracer 操作 Trait ========================

/// Tracer 痕迹操作 trait
///
/// 使用 trait + 默认实现的方式，方便后续扩展不同的清除策略。
pub trait TracerInterceptor {
    /// 读取当前 TracerPid
    fn read_current_tracer_pid(&self) -> Result<u32>;

    /// 清除 TracerPid（设置为 0）
    fn clear_tracer_pid(&mut self) -> Result<()>;

    /// 安装拦截 Hook
    fn install_hook(&mut self) -> Result<()>;

    /// 卸载拦截 Hook，恢复正常
    fn uninstall_hook(&mut self) -> Result<()>;

    /// 检查是否已安装 Hook
    fn is_hooked(&self) -> bool;
}

// ======================== 默认 Tracer 清除实现（扩展方法） ========================

impl TracerCleaner {
    /// 恢复到清除前的状态（卸载 Hook 并恢复原始 TracerPid）
    pub fn restore(&mut self) -> Result<()> {
        self.uninstall_hook()
    }
}

// ======================== 默认 Tracer 清除实现 ========================

/// 默认 TracerPid 清除器
///
/// 通过 GOT Hook 拦截 libc 的 openat / read 函数来修改 TracerPid 字段。
#[allow(dead_code)]
pub struct TracerCleaner {
    /// 是否已安装 Hook
    hooked: bool,
    /// 原始 TracerPid 值（清除前保存）
    original_tracer_pid: u32,
    /// GOT Hook 安装器实例
    #[cfg(any(target_os = "linux", target_os = "android"))]
    got_hooker: Option<GotPltHooker>,
    /// Hook openat 的原始函数指针备份
    #[cfg(any(target_os = "linux", target_os = "android"))]
    original_openat_fn: Option<usize>,
    /// Hook read 的原始函数指针备份
    #[cfg(any(target_os = "linux", target_os = "android"))]
    original_read_fn: Option<usize>,
    /// Hook ptrace 的原始函数指针备份
    #[cfg(any(target_os = "linux", target_os = "android"))]
    original_ptrace_fn: Option<usize>,
    /// 被拦截的 fd 集合（已打开的 /proc/self/status 文件描述符）
    intercepted_fds: std::collections::HashSet<i32>,
}

impl TracerCleaner {
    /// 创建新的 TracerPid 清除器
    pub fn new() -> Self {
        TracerCleaner {
            hooked: false,
            original_tracer_pid: 0,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            got_hooker: None,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            original_openat_fn: None,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            original_read_fn: None,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            original_ptrace_fn: None,
            intercepted_fds: std::collections::HashSet::new(),
        }
    }

    /// 解析 status 内容中的 TracerPid 值
    fn parse_tracer_pid(content: &str) -> u32 {
        for line in content.lines() {
            if line.starts_with("TracerPid:") {
                let pid_str = line.trim_start_matches("TracerPid:").trim();
                return pid_str.parse().unwrap_or(0);
            }
        }
        0
    }

    /// 修改 status 内容中的 TracerPid 字段
    #[allow(dead_code)]
    fn patch_tracer_pid(content: &str) -> String {
        let mut result = String::with_capacity(content.len());
        for line in content.lines() {
            if line.starts_with("TracerPid:") {
                let trimmed = line.trim_start_matches("TracerPid:");
                // 保留原有格式，只替换数值
                let whitespace = if trimmed.starts_with('\t') {
                    "\t"
                } else if trimmed.starts_with(' ') {
                    " "
                } else {
                    "\t"
                };
                result.push_str(&format!("TracerPid:{}0", whitespace));
            } else {
                result.push_str(line);
            }
            result.push('\n');
        }
        result
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

    /// Hook openat 系统调用（通过 GOT hook）
    ///
    /// 当检测到打开 /proc/self/status 或 /proc/self/maps 时，
    /// 标记该 fd 为已拦截，后续 read 调用将自动过滤内容。
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn hook_openat(&mut self, hooker: &mut GotPltHooker) -> Result<()> {
        log::info!("Hook openat 系统调用");

        // 查找 libc.so 的基址
        let libc_base = Self::find_module_base("libc.so.6")
            .or_else(|_| Self::find_module_base("libc.so"))?;

        // 使用 dlsym 确保 GOT 条目已解析（延迟绑定需要先触发解析）
        let openat_sym = "openat";
        let sym_addr = unsafe {
            libc::dlsym(
                libc::RTLD_DEFAULT,
                openat_sym.as_ptr() as *const libc::c_char,
            )
        };

        if sym_addr.is_null() {
            return Err(crate::FridaError::NotFound {
                reason: format!("dlsym 未找到符号 '{}'", openat_sym),
            }
            .into());
        }

        // 将替换函数地址转换为 u64
        let replace_fn_addr = openat_replace_fn as *const () as u64;

        // 安装 GOT Hook
        let handle = hooker.hook_module("libc.so.6", openat_sym, libc_base, replace_fn_addr)?;

        // 保存原始函数指针（从 handle 中获取）
        self.original_openat_fn = Some(handle.original_value as usize);
        ORIGINAL_OPENAT.store(handle.original_value as usize, std::sync::atomic::Ordering::SeqCst);

        log::info!(
            "openat Hook 已安装: 原始地址 {:#x} -> 替换地址 {:#x}",
            handle.original_value,
            replace_fn_addr
        );

        Ok(())
    }

    /// Hook read 系统调用
    ///
    /// 当读取被拦截的 fd 时，对返回数据进行 TracerPid 修改。
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn hook_read(&mut self, hooker: &mut GotPltHooker) -> Result<()> {
        log::info!("Hook read 系统调用");

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
        let replace_fn_addr = read_replace_fn as *const () as u64;

        // 安装 GOT Hook
        let handle = hooker.hook_module("libc.so.6", "read", libc_base, replace_fn_addr)?;

        // 保存原始函数指针
        self.original_read_fn = Some(handle.original_value as usize);
        ORIGINAL_READ.store(handle.original_value as usize, std::sync::atomic::Ordering::SeqCst);

        log::info!(
            "read Hook 已安装: 原始地址 {:#x} -> 替换地址 {:#x}",
            handle.original_value,
            replace_fn_addr
        );

        Ok(())
    }

    /// Hook ptrace 系统调用
    ///
    /// 当 ptrace(PTRACE_TRACEME) 被调用时，返回 0（成功），
    /// 使调用者认为进程未被调试。
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn hook_ptrace(&mut self, hooker: &mut GotPltHooker) -> Result<()> {
        log::info!("Hook ptrace 系统调用");

        // 查找 libc.so 的基址
        let libc_base = Self::find_module_base("libc.so.6")
            .or_else(|_| Self::find_module_base("libc.so"))?;

        // 使用 dlsym 确保 GOT 条目已解析
        let sym_addr = unsafe {
            libc::dlsym(libc::RTLD_DEFAULT, b"ptrace\0".as_ptr() as *const libc::c_char)
        };

        if sym_addr.is_null() {
            return Err(crate::FridaError::NotFound {
                reason: "dlsym 未找到符号 'ptrace'".to_string(),
            }
            .into());
        }

        // 将替换函数地址转换为 u64
        let replace_fn_addr = ptrace_replace_fn as *const () as u64;

        // 安装 GOT Hook
        let handle = hooker.hook_module("libc.so.6", "ptrace", libc_base, replace_fn_addr)?;

        // 保存原始函数指针
        self.original_ptrace_fn = Some(handle.original_value as usize);
        ORIGINAL_PTRACE.store(handle.original_value as usize, std::sync::atomic::Ordering::SeqCst);

        log::info!(
            "ptrace Hook 已安装: 原始地址 {:#x} -> 替换地址 {:#x}",
            handle.original_value,
            replace_fn_addr
        );

        Ok(())
    }
}

impl TracerInterceptor for TracerCleaner {
    /// 读取当前 TracerPid
    fn read_current_tracer_pid(&self) -> Result<u32> {
        let content = std::fs::read_to_string("/proc/self/status").map_err(|e| {
            FridaError::AntiDetect {
                reason: format!("无法读取 /proc/self/status: {}", e),
            }
        })?;

        let tracer_pid = Self::parse_tracer_pid(&content);
        log::debug!("当前 TracerPid: {}", tracer_pid);
        Ok(tracer_pid)
    }

    /// 清除 TracerPid
    ///
    /// 读取当前值，安装 Hook，在后续读取中自动过滤。
    fn clear_tracer_pid(&mut self) -> Result<()> {
        log::info!("清除 TracerPid");

        // 读取当前值
        let current = self.read_current_tracer_pid()?;
        self.original_tracer_pid = current;

        if current != 0 {
            log::info!("检测到 TracerPid: {}，正在清除", current);

            // 安装拦截 Hook
            self.install_hook()?;
        } else {
            log::info!("TracerPid 已经为 0，无需清除");
        }

        // 验证：重新读取确认
        let verify_content =
            std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        let verify_pid = Self::parse_tracer_pid(&verify_content);
        log::info!("TracerPid 验证: {} (原始: {})", verify_pid, self.original_tracer_pid);

        Ok(())
    }

    /// 安装拦截 Hook
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn install_hook(&mut self) -> Result<()> {
        if self.hooked {
            return Ok(());
        }

        log::info!("安装 TracerPid 清除 Hook");

        // 创建 GOT Hook 安装器
        let mut hooker = GotPltHooker::new();

        // 安装 openat Hook
        self.hook_openat(&mut hooker)?;

        // 安装 read Hook
        self.hook_read(&mut hooker)?;

        // 安装 ptrace Hook
        self.hook_ptrace(&mut hooker)?;

        // 保存 GOT Hook 安装器实例
        self.got_hooker = Some(hooker);

        self.hooked = true;
        log::info!("TracerPid 清除 Hook 已安装");
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    fn install_hook(&mut self) -> Result<()> {
        log::info!("非 Linux 平台，跳过 TracerPid Hook 安装");
        Ok(())
    }

    /// 卸载拦截 Hook
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn uninstall_hook(&mut self) -> Result<()> {
        if !self.hooked {
            return Ok(());
        }

        log::info!("卸载 TracerPid 清除 Hook");

        // 恢复所有 GOT Hook
        if let Some(ref hooker) = self.got_hooker {
            hooker.restore_all()?;
            log::info!("所有 GOT 条目已恢复");
        }

        // 清除全局 fd 拦截标记
        unsafe {
            clear_all_intercepted_fds();
        }

        // 清除全局原始函数指针
        ORIGINAL_OPENAT.store(0, std::sync::atomic::Ordering::SeqCst);
        ORIGINAL_READ.store(0, std::sync::atomic::Ordering::SeqCst);
        ORIGINAL_PTRACE.store(0, std::sync::atomic::Ordering::SeqCst);

        // 清空内部状态
        self.got_hooker = None;
        self.original_openat_fn = None;
        self.original_read_fn = None;
        self.original_ptrace_fn = None;
        self.intercepted_fds.clear();

        self.hooked = false;
        log::info!("TracerPid 清除 Hook 已卸载");
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    fn uninstall_hook(&mut self) -> Result<()> {
        Ok(())
    }

    /// 检查是否已安装 Hook
    fn is_hooked(&self) -> bool {
        self.hooked
    }
}

impl Default for TracerCleaner {
    fn default() -> Self {
        Self::new()
    }
}

// ======================== 便捷函数 ========================

/// 清除 /proc/self/status 中的 TracerPid（便捷函数）
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn clear_tracer_pid() -> crate::Result<()> {
    let mut cleaner = TracerCleaner::new();
    cleaner.clear_tracer_pid()?;
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn clear_tracer_pid() -> crate::Result<()> {
    Ok(())
}

/// Hook 可能检查 ptrace 状态的函数
///
/// 使用 GOT Hook 安装 ptrace 替换函数，使 ptrace(PTRACE_TRACEME) 始终返回 0，
/// 从而欺骗反调试检测。
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn hook_ptrace_check() -> crate::Result<()> {
    log::info!("Hook ptrace 检查函数");

    let mut hooker = GotPltHooker::new();

    // 查找 libc.so 的基址
    let libc_base = TracerCleaner::find_module_base("libc.so.6")
        .or_else(|_| TracerCleaner::find_module_base("libc.so"))?;

    // 使用 dlsym 确保 GOT 条目已解析
    let sym_addr = unsafe {
        libc::dlsym(libc::RTLD_DEFAULT, b"ptrace\0".as_ptr() as *const libc::c_char)
    };

    if sym_addr.is_null() {
        return Err(crate::FridaError::NotFound {
            reason: "dlsym 未找到符号 'ptrace'".to_string(),
        }
        .into());
    }

    // 保存原始 ptrace 指针
    ORIGINAL_PTRACE.store(sym_addr as usize, std::sync::atomic::Ordering::SeqCst);

    // 将替换函数地址转换为 u64
    let replace_fn_addr = ptrace_replace_fn as *const () as u64;

    // 安装 GOT Hook
    hooker.hook_module("libc.so.6", "ptrace", libc_base, replace_fn_addr)?;

    log::info!("ptrace 检查 Hook 已安装: ptrace(PTRACE_TRACEME) -> 返回 0");
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn hook_ptrace_check() -> crate::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tracer_pid() {
        let content = "Name:\ttest\nTracerPid:\t1234\nPid:\t5678\n";
        assert_eq!(TracerCleaner::parse_tracer_pid(content), 1234);

        let content = "Name:\ttest\nTracerPid:\t0\nPid:\t5678\n";
        assert_eq!(TracerCleaner::parse_tracer_pid(content), 0);
    }

    #[test]
    fn test_parse_tracer_pid_no_field() {
        let content = "Name:\ttest\nPid:\t5678\n";
        assert_eq!(TracerCleaner::parse_tracer_pid(content), 0);
    }

    #[test]
    fn test_patch_tracer_pid() {
        let content = "Name:\ttest\nTracerPid:\t1234\nPid:\t5678\n";
        let patched = TracerCleaner::patch_tracer_pid(content);
        assert!(patched.contains("TracerPid:\t0"));
        assert!(!patched.contains("TracerPid:\t1234"));
    }

    #[test]
    fn test_patch_preserves_other_fields() {
        let content = "Name:\ttest\nTracerPid:\t999\nPid:\t123\nThreads:\t4\n";
        let patched = TracerCleaner::patch_tracer_pid(content);
        assert!(patched.contains("Name:\ttest"));
        assert!(patched.contains("Pid:\t123"));
        assert!(patched.contains("Threads:\t4"));
    }

    #[test]
    fn test_tracer_cleaner_creation() {
        let cleaner = TracerCleaner::new();
        assert!(!cleaner.is_hooked());
    }

    #[test]
    fn test_read_current_tracer_pid() {
        let cleaner = TracerCleaner::new();
        // 在正常情况下，TracerPid 应该为 0
        let pid = cleaner.read_current_tracer_pid().unwrap();
        // 可能为 0（未被调试）或非 0（被调试）
        log::debug!("测试中 TracerPid: {}", pid);
    }
}
