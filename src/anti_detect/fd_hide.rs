//! 文件描述符隐藏模块
//!
//! 隐藏 /proc/self/fd 中与 Frida 相关的文件描述符，
//! 防止通过枚举文件描述符检测到 Frida 的存在。
//!
//! 实现策略：
//! 1. Hook openat 拦截 /proc/self/fd 目录打开
//! 2. Hook getdents64 过滤目录条目
//! 3. 支持自定义隐藏路径关键词

use crate::hook::got_plt::GotPltHooker;
use crate::Result;
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};

// ======================== 全局状态 ========================

/// 保存原始 openat 函数指针
#[cfg(any(target_os = "linux", target_os = "android"))]
static FD_ORIGINAL_OPENAT: AtomicUsize = AtomicUsize::new(0);

/// 保存原始 getdents64 函数指针
#[cfg(any(target_os = "linux", target_os = "android"))]
static FD_ORIGINAL_GETDENTS64: AtomicUsize = AtomicUsize::new(0);

/// 被拦截的 fd 标记（是否为 /proc/self/fd 目录）
#[cfg(any(target_os = "linux", target_os = "android"))]
static mut FD_INTERCEPTED_FDS: [bool; 4096] = [false; 4096];

/// 需要隐藏的路径关键词
#[cfg(any(target_os = "linux", target_os = "android"))]
static mut HIDDEN_FD_KEYWORDS: Option<HashSet<String>> = None;

/// 默认隐藏的关键词
const DEFAULT_HIDDEN_KEYWORDS: &[&str] = &[
    "frida",
    "gadget",
    "agent",
    "linjector",
    "re.frida.server",
];

// ======================== 工具函数 ========================

/// 初始化隐藏关键词列表
#[cfg(any(target_os = "linux", target_os = "android"))]
unsafe fn init_hidden_keywords() {
    if HIDDEN_FD_KEYWORDS.is_some() {
        return;
    }
    
    let mut keywords = HashSet::new();
    for &kw in DEFAULT_HIDDEN_KEYWORDS {
        keywords.insert(kw.to_string());
    }
    HIDDEN_FD_KEYWORDS = Some(keywords);
    log::debug!("FD隐藏: 初始化完成，默认隐藏关键词 {:?}", DEFAULT_HIDDEN_KEYWORDS);
}

/// 添加自定义隐藏关键词
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn add_hidden_fd_keyword(keyword: &str) {
    unsafe {
        init_hidden_keywords();
        if let Some(ref mut keywords) = HIDDEN_FD_KEYWORDS {
            keywords.insert(keyword.to_string());
            log::info!("FD隐藏: 添加自定义关键词 '{}'", keyword);
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

// ======================== linux_dirent64 结构 ========================

/// linux_dirent64 结构体（用于解析 getdents64 返回的数据）
#[repr(C)]
struct LinuxDirent64 {
    d_ino: u64,        // inode 号
    d_off: i64,        // 到下一个 dirent 的偏移
    d_reclen: u16,     // 当前 dirent 的长度
    d_type: u8,        // 文件类型
    d_name: [u8; 256], // 文件名（变长，这里用最大长度）
}

// ======================== 替换函数 ========================

/// openat 替换函数 - 拦截 /proc/self/fd 目录打开
#[cfg(any(target_os = "linux", target_os = "android"))]
unsafe extern "C" fn fd_openat_replace(
    dirfd: libc::c_int,
    pathname: *const libc::c_char,
    flags: libc::c_int,
) -> libc::c_int {
    let original_fn = FD_ORIGINAL_OPENAT.load(Ordering::Relaxed);
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

    // 检查是否为 /proc/self/fd 目录
    let is_fd_dir = path_str.contains("/proc/self/fd") || path_str.contains("/proc/thread-self/fd");

    // 调用原始 openat
    let original_openat: unsafe extern "C" fn(
        libc::c_int,
        *const libc::c_char,
        libc::c_int,
    ) -> libc::c_int = std::mem::transmute(original_fn);

    let fd = original_openat(dirfd, pathname, flags);

    if fd >= 0 && is_fd_dir {
        // 标记该 fd 为需要过滤
        if (fd as usize) < FD_INTERCEPTED_FDS.len() {
            FD_INTERCEPTED_FDS[fd as usize] = true;
            log::trace!("FD隐藏: 拦截 {} (fd={})", path_str, fd);
        }
    }

    fd
}

/// getdents64 替换函数 - 过滤目录条目
#[cfg(any(target_os = "linux", target_os = "android"))]
unsafe extern "C" fn fd_getdents64_replace(
    fd: libc::c_int,
    dirp: *mut libc::c_void,
    count: libc::size_t,
) -> libc::ssize_t {
    let original_fn = FD_ORIGINAL_GETDENTS64.load(Ordering::Relaxed);
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
        && (fd as usize) < FD_INTERCEPTED_FDS.len() 
        && FD_INTERCEPTED_FDS[fd as usize] 
    {
        // 初始化隐藏关键词（如果需要）
        init_hidden_keywords();
        
        // 获取隐藏关键词列表
        let hidden_keywords = HIDDEN_FD_KEYWORDS.as_ref().unwrap();
        
        // 遍历目录条目，过滤包含隐藏关键词的条目
        let mut offset = 0;
        let mut write_offset = 0;
        
        while offset < bytes_read as usize {
            let entry = &*(dirp.add(offset) as *const LinuxDirent64);
            let entry_len = entry.d_reclen as usize;
            
            // 获取文件名
            let name_bytes = &entry.d_name[..];
            let name_len = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_bytes.len());
            let name = std::str::from_utf8_unchecked(&name_bytes[..name_len]);
            
            // 检查是否需要隐藏
            let should_hide = hidden_keywords.iter().any(|kw| name.contains(kw));
            
            if !should_hide {
                // 保留此条目
                if write_offset != offset {
                    // 移动条目到新位置
                    std::ptr::copy(
                        dirp.add(offset) as *const u8,
                        dirp.add(write_offset) as *mut u8,
                        entry_len,
                    );
                }
                write_offset += entry_len;
            } else {
                log::trace!("FD隐藏: 过滤条目 '{}' (fd={})", name, fd);
            }
            
            offset += entry_len;
        }
        
        // 返回过滤后的大小
        if write_offset == 0 {
            // 所有条目都被过滤，返回 0 表示目录结束
            return 0;
        }
        
        return write_offset as libc::ssize_t;
    }

    bytes_read
}

// ======================== 公共接口 ========================

/// 文件描述符隐藏器
///
/// 管理文件描述符隐藏功能的生命周期
pub struct FdHider {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    hooker: Option<GotPltHooker>,
}

impl FdHider {
    /// 创建新的文件描述符隐藏器
    pub fn new() -> Self {
        FdHider {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            hooker: None,
        }
    }

    /// 安装文件描述符隐藏 Hook
    ///
    /// 通过 GOT/PLT Hook 拦截 openat 和 getdents64 函数
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn install(&mut self) -> Result<()> {
        use crate::common::util::parse_proc_maps;
        use crate::common::types::ProcessId;

        log::info!("FD隐藏: 开始安装 Hook...");

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
        FD_ORIGINAL_OPENAT.store(openat_addr as usize, Ordering::Relaxed);
        hooker.hook_symbol("openat", fd_openat_replace as *const ())?;

        // Hook getdents64
        let getdents64_addr = hooker.resolve_symbol("getdents64")?;
        FD_ORIGINAL_GETDENTS64.store(getdents64_addr as usize, Ordering::Relaxed);
        hooker.hook_symbol("getdents64", fd_getdents64_replace as *const ())?;

        self.hooker = Some(hooker);

        // 初始化隐藏关键词列表
        unsafe {
            init_hidden_keywords();
        }

        log::info!("FD隐藏: Hook 安装完成");
        Ok(())
    }

    /// 卸载文件描述符隐藏 Hook
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn uninstall(&mut self) -> Result<()> {
        // 清除 fd 标记
        unsafe {
            FD_INTERCEPTED_FDS.fill(false);
        }
        
        // 清除函数指针
        FD_ORIGINAL_OPENAT.store(0, Ordering::Relaxed);
        FD_ORIGINAL_GETDENTS64.store(0, Ordering::Relaxed);
        
        self.hooker = None;
        log::info!("FD隐藏: Hook 已卸载");
        Ok(())
    }

    /// 添加自定义隐藏关键词
    pub fn add_keyword(&self, keyword: &str) {
        add_hidden_fd_keyword(keyword);
    }
}

impl Default for FdHider {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fd_hider_creation() {
        let hider = FdHider::new();
        assert!(hider.hooker.is_none());
    }
}
