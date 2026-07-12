//! 线程隐藏模块
//!
//! 隐藏 Frida 创建的线程，防止通过线程枚举检测到 Frida。
//!
//! 实现策略：
//! 1. Hook /proc/self/task 目录读取
//! 2. 过滤 Frida 线程的 task ID
//! 3. 修改线程名称去除 Frida 特征

use crate::hook::got_plt::GotPltHooker;
use crate::Result;
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};

// ======================== 全局状态 ========================

/// 保存原始 openat 函数指针
#[cfg(any(target_os = "linux", target_os = "android"))]
static THREAD_ORIGINAL_OPENAT: AtomicUsize = AtomicUsize::new(0);

/// 保存原始 getdents64 函数指针
#[cfg(any(target_os = "linux", target_os = "android"))]
static THREAD_ORIGINAL_GETDENTS64: AtomicUsize = AtomicUsize::new(0);

/// 保存原始 prctl 函数指针
#[cfg(any(target_os = "linux", target_os = "android"))]
static THREAD_ORIGINAL_PRCTL: AtomicUsize = AtomicUsize::new(0);

/// 被拦截的 fd 标记（是否为 /proc/self/task 目录）
#[cfg(any(target_os = "linux", target_os = "android"))]
static mut TASK_INTERCEPTED_FDS: [bool; 4096] = [false; 4096];

/// 需要隐藏的线程名称关键词
#[cfg(any(target_os = "linux", target_os = "android"))]
static mut HIDDEN_THREAD_KEYWORDS: Option<HashSet<String>> = None;

/// 默认隐藏的线程名称关键词
const DEFAULT_THREAD_KEYWORDS: &[&str] = &[
    "frida",
    "gmain",        // GLib main loop (Frida 使用)
    "gdbus",        // D-Bus (Frida 使用)
    "pool-frida",
    "frida-agent",
    "frida-server",
];

// ======================== 工具函数 ========================

/// 初始化隐藏线程关键词列表
#[cfg(any(target_os = "linux", target_os = "android"))]
unsafe fn init_thread_keywords() {
    if HIDDEN_THREAD_KEYWORDS.is_some() {
        return;
    }
    
    let mut keywords = HashSet::new();
    for &kw in DEFAULT_THREAD_KEYWORDS {
        keywords.insert(kw.to_string());
    }
    HIDDEN_THREAD_KEYWORDS = Some(keywords);
    log::debug!("线程隐藏: 初始化完成，默认隐藏关键词 {:?}", DEFAULT_THREAD_KEYWORDS);
}

/// 添加自定义隐藏线程关键词
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn add_hidden_thread_keyword(keyword: &str) {
    unsafe {
        init_thread_keywords();
        if let Some(ref mut keywords) = HIDDEN_THREAD_KEYWORDS {
            keywords.insert(keyword.to_string());
            log::info!("线程隐藏: 添加自定义关键词 '{}'", keyword);
        }
    }
}

/// 设置 errno
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

/// 检查线程是否应该被隐藏
#[cfg(any(target_os = "linux", target_os = "android"))]
unsafe fn should_hide_thread(tid: &str) -> bool {
    // 首先检查线程名称
    let comm_path = format!("/proc/self/task/{}/comm", tid);
    if let Ok(name) = std::fs::read_to_string(&comm_path) {
        let name = name.trim().to_lowercase();
        if let Some(ref keywords) = HIDDEN_THREAD_KEYWORDS {
            for keyword in keywords {
                if name.contains(keyword) {
                    return true;
                }
            }
        }
    }
    
    false
}

// ======================== 替换函数 ========================

/// openat 替换函数 - 拦截 /proc/self/task 目录打开
#[cfg(any(target_os = "linux", target_os = "android"))]
unsafe extern "C" fn thread_openat_replace(
    dirfd: libc::c_int,
    pathname: *const libc::c_char,
    flags: libc::c_int,
) -> libc::c_int {
    let original_fn = THREAD_ORIGINAL_OPENAT.load(Ordering::Relaxed);
    if original_fn == 0 {
        set_errno(libc::EINVAL);
        return -1;
    }

    // 读取路径字符串
    let path_str = if !pathname.is_null() {
        std::ffi::CStr::from_ptr(pathname).to_string_lossy()
    } else {
        return -1;
    };

    // 检查是否为 /proc/self/task 目录
    let is_task_dir = path_str.contains("/proc/self/task") && 
                      !path_str.contains("/proc/self/task/");

    // 调用原始 openat
    let original_openat: unsafe extern "C" fn(
        libc::c_int,
        *const libc::c_char,
        libc::c_int,
    ) -> libc::c_int = std::mem::transmute(original_fn);

    let fd = original_openat(dirfd, pathname, flags);

    if fd >= 0 && is_task_dir {
        // 标记该 fd 为需要过滤
        if (fd as usize) < TASK_INTERCEPTED_FDS.len() {
            TASK_INTERCEPTED_FDS[fd as usize] = true;
            log::trace!("线程隐藏: 拦截 {} (fd={})", path_str, fd);
        }
    }

    fd
}

/// getdents64 替换函数 - 过滤线程目录条目
#[cfg(any(target_os = "linux", target_os = "android"))]
unsafe extern "C" fn thread_getdents64_replace(
    fd: libc::c_int,
    dirp: *mut libc::c_void,
    count: libc::size_t,
) -> libc::ssize_t {
    let original_fn = THREAD_ORIGINAL_GETDENTS64.load(Ordering::Relaxed);
    if original_fn == 0 {
        set_errno(libc::EINVAL);
        return -1;
    }

    // 调用原始 getdents64
    let original_getdents64: unsafe extern "C" fn(
        libc::c_int,
        *mut libc::c_void,
        libc::size_t,
    ) -> libc::ssize_t = std::mem::transmute(original_fn);

    let bytes_read = original_getdents64(fd, dirp, count);

    // 检查是否需要过滤
    if bytes_read > 0 
        && (fd as usize) < TASK_INTERCEPTED_FDS.len() 
        && TASK_INTERCEPTED_FDS[fd as usize] 
    {
        // 初始化隐藏关键词（如果需要）
        init_thread_keywords();
        
        // linux_dirent64 结构体大小
        const DIRENT_SIZE: usize = std::mem::size_of::<crate::anti_detect::fd_hide::LinuxDirent64>();
        
        // 遍历目录条目，过滤包含隐藏关键词的条目
        let mut offset = 0;
        let mut write_offset = 0;
        
        while offset < bytes_read as usize {
            let entry = &*(dirp.add(offset) as *const crate::anti_detect::fd_hide::LinuxDirent64);
            let entry_len = entry.d_reclen as usize;
            
            // 获取文件名（线程 ID）
            let name_bytes = &entry.d_name[..];
            let name_len = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_bytes.len());
            let name = std::str::from_utf8_unchecked(&name_bytes[..name_len]);
            
            // 检查是否需要隐藏
            let should_hide = should_hide_thread(name);
            
            if !should_hide {
                // 保留此条目
                if write_offset != offset {
                    std::ptr::copy(
                        dirp.add(offset) as *const u8,
                        dirp.add(write_offset) as *mut u8,
                        entry_len,
                    );
                }
                write_offset += entry_len;
            } else {
                log::trace!("线程隐藏: 过滤线程 {} (fd={})", name, fd);
            }
            
            offset += entry_len;
        }
        
        // 返回过滤后的大小
        if write_offset == 0 {
            return 0;
        }
        
        return write_offset as libc::ssize_t;
    }

    bytes_read
}

/// prctl 替换函数 - 阻止设置线程名称
#[cfg(any(target_os = "linux", target_os = "android"))]
unsafe extern "C" fn thread_prctl_replace(
    option: libc::c_int,
    arg2: libc::c_ulong,
    arg3: libc::c_ulong,
    arg4: libc::c_ulong,
    arg5: libc::c_ulong,
) -> libc::c_int {
    let original_fn = THREAD_ORIGINAL_PRCTL.load(Ordering::Relaxed);
    if original_fn == 0 {
        set_errno(libc::EINVAL);
        return -1;
    }

    // PR_SET_NAME = 15
    const PR_SET_NAME: libc::c_int = 15;
    
    // 如果是设置线程名称，检查是否包含隐藏关键词
    if option == PR_SET_NAME && arg2 != 0 {
        let name_ptr = arg2 as *const libc::c_char;
        if !name_ptr.is_null() {
            let name = std::ffi::CStr::from_ptr(name_ptr).to_string_lossy().to_lowercase();
            
            init_thread_keywords();
            if let Some(ref keywords) = HIDDEN_THREAD_KEYWORDS {
                for keyword in keywords {
                    if name.contains(keyword) {
                        // 替换为无害的线程名称
                        let harmless_name = "worker\0";
                        let harmless_ptr = harmless_name.as_ptr() as *const libc::c_char;
                        let original_prctl: unsafe extern "C" fn(
                            libc::c_int,
                            libc::c_ulong,
                            libc::c_ulong,
                            libc::c_ulong,
                            libc::c_ulong,
                        ) -> libc::c_int = std::mem::transmute(original_fn);
                        
                        log::trace!("线程隐藏: 拦截线程命名 '{}' -> 'worker'", name);
                        return original_prctl(option, harmless_ptr as libc::c_ulong, arg3, arg4, arg5);
                    }
                }
            }
        }
    }

    // 调用原始 prctl
    let original_prctl: unsafe extern "C" fn(
        libc::c_int,
        libc::c_ulong,
        libc::c_ulong,
        libc::c_ulong,
        libc::c_ulong,
    ) -> libc::c_int = std::mem::transmute(original_fn);
    
    original_prctl(option, arg2, arg3, arg4, arg5)
}

// ======================== 公共接口 ========================

/// 线程隐藏器
///
/// 管理线程隐藏功能的生命周期
pub struct ThreadHider {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    hooker: Option<GotPltHooker>,
}

impl ThreadHider {
    /// 创建新的线程隐藏器
    pub fn new() -> Self {
        ThreadHider {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            hooker: None,
        }
    }

    /// 安装线程隐藏 Hook
    ///
    /// 通过 GOT/PLT Hook 拦截 openat、getdents64 和 prctl 函数
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn install(&mut self) -> Result<()> {
        use crate::common::util::parse_proc_maps;
        use crate::common::types::ProcessId;

        log::info!("线程隐藏: 开始安装 Hook...");

        // 获取当前进程的 libc 基址
        let regions = parse_proc_maps(ProcessId(0))?;
        let libc_region = regions.iter().find(|r| r.name.contains("libc.so") || r.name.contains("libc-"));
        
        let libc_base = match libc_region {
            Some(r) => r.start,
            None => {
                return Err(crate::FridaError::AntiDetect {
                    reason: "找不到 libc.so".to_string(),
                }.into());
            }
        };

        let mut hooker = GotPltHooker::new(libc_base as u64);

        // Hook openat
        let openat_addr = hooker.resolve_symbol("openat")?;
        THREAD_ORIGINAL_OPENAT.store(openat_addr as usize, Ordering::Relaxed);
        hooker.hook_symbol("openat", thread_openat_replace as *const ())?;

        // Hook getdents64
        let getdents64_addr = hooker.resolve_symbol("getdents64")?;
        THREAD_ORIGINAL_GETDENTS64.store(getdents64_addr as usize, Ordering::Relaxed);
        hooker.hook_symbol("getdents64", thread_getdents64_replace as *const ())?;

        // Hook prctl
        let prctl_addr = hooker.resolve_symbol("prctl")?;
        THREAD_ORIGINAL_PRCTL.store(prctl_addr as usize, Ordering::Relaxed);
        hooker.hook_symbol("prctl", thread_prctl_replace as *const ())?;

        self.hooker = Some(hooker);

        // 初始化隐藏关键词列表
        unsafe {
            init_thread_keywords();
        }

        log::info!("线程隐藏: Hook 安装完成");
        Ok(())
    }

    /// 卸载线程隐藏 Hook
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn uninstall(&mut self) -> Result<()> {
        // 清除 fd 标记
        unsafe {
            TASK_INTERCEPTED_FDS.fill(false);
        }
        
        // 清除函数指针
        THREAD_ORIGINAL_OPENAT.store(0, Ordering::Relaxed);
        THREAD_ORIGINAL_GETDENTS64.store(0, Ordering::Relaxed);
        THREAD_ORIGINAL_PRCTL.store(0, Ordering::Relaxed);
        
        self.hooker = None;
        log::info!("线程隐藏: Hook 已卸载");
        Ok(())
    }

    /// 添加自定义隐藏关键词
    pub fn add_keyword(&self, keyword: &str) {
        add_hidden_thread_keyword(keyword);
    }
}

impl Default for ThreadHider {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_thread_hider_creation() {
        let hider = ThreadHider::new();
        assert!(hider.hooker.is_none());
    }
}
