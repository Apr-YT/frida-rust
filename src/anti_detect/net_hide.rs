//! 网络连接隐藏模块
//!
//! 隐藏 /proc/net/tcp、/proc/net/tcp6、/proc/net/udp 等文件中的
//! Frida 网络连接条目，防止通过网络连接检测到 Frida。
//!
//! 实现策略：
//! 1. Hook openat 拦截 /proc/net/* 文件打开
//! 2. Hook read 过滤包含 Frida 端口的行
//! 3. 支持 TCP 和 UDP 协议

use crate::hook::got_plt::GotPltHooker;
use crate::Result;
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};

// ======================== 全局状态 ========================

/// 保存原始 openat 函数指针
#[cfg(any(target_os = "linux", target_os = "android"))]
static NET_ORIGINAL_OPENAT: AtomicUsize = AtomicUsize::new(0);

/// 保存原始 read 函数指针
#[cfg(any(target_os = "linux", target_os = "android"))]
static NET_ORIGINAL_READ: AtomicUsize = AtomicUsize::new(0);

/// 被拦截的 fd 标记（是否为 /proc/net/* 文件）
#[cfg(any(target_os = "linux", target_os = "android"))]
static mut NET_INTERCEPTED_FDS: [bool; 4096] = [false; 4096];

/// 需要隐藏的端口列表（十六进制格式）
#[cfg(any(target_os = "linux", target_os = "android"))]
static mut HIDDEN_NET_PORTS: Option<HashSet<String>> = None;

/// 需要监控的 /proc/net 文件路径
const PROC_NET_PATHS: &[&str] = &[
    "/proc/net/tcp",
    "/proc/net/tcp6",
    "/proc/net/udp",
    "/proc/net/udp6",
    "/proc/net/raw",
    "/proc/net/raw6",
];

/// 默认隐藏的网络端口
const DEFAULT_NET_PORTS: &[u16] = &[
    27042,  // Frida server 默认端口
    27043,  // Frida 备用端口
    27044,  // Frida 备用端口
];

// ======================== 工具函数 ========================

/// 将端口号转换为 /proc/net 中的十六进制格式
fn port_to_hex(port: u16) -> String {
    format!("{:04X}", port)
}

/// 初始化隐藏端口列表
#[cfg(any(target_os = "linux", target_os = "android"))]
unsafe fn init_net_ports() {
    if HIDDEN_NET_PORTS.is_some() {
        return;
    }
    
    let mut ports = HashSet::new();
    for &port in DEFAULT_NET_PORTS {
        ports.insert(port_to_hex(port));
    }
    HIDDEN_NET_PORTS = Some(ports);
    log::debug!("网络连接隐藏: 初始化完成，默认隐藏端口 {:?}", DEFAULT_NET_PORTS);
}

/// 添加自定义隐藏端口
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn add_hidden_net_port(port: u16) {
    unsafe {
        init_net_ports();
        if let Some(ref mut ports) = HIDDEN_NET_PORTS {
            ports.insert(port_to_hex(port));
            log::info!("网络连接隐藏: 添加自定义端口 {} ({})", port, port_to_hex(port));
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

/// 检查路径是否为 /proc/net 文件
fn is_proc_net_path(path: &str) -> bool {
    PROC_NET_PATHS.iter().any(|&p| path.contains(p))
}

// ======================== 替换函数 ========================

/// openat 替换函数 - 拦截 /proc/net/* 文件打开
#[cfg(any(target_os = "linux", target_os = "android"))]
unsafe extern "C" fn net_openat_replace(
    dirfd: libc::c_int,
    pathname: *const libc::c_char,
    flags: libc::c_int,
) -> libc::c_int {
    let original_fn = NET_ORIGINAL_OPENAT.load(Ordering::Relaxed);
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

    // 检查是否为 /proc/net 文件
    let is_net_file = is_proc_net_path(&path_str);

    // 调用原始 openat
    let original_openat: unsafe extern "C" fn(
        libc::c_int,
        *const libc::c_char,
        libc::c_int,
    ) -> libc::c_int = std::mem::transmute(original_fn);

    let fd = original_openat(dirfd, pathname, flags);

    if fd >= 0 && is_net_file {
        // 标记该 fd 为需要过滤
        if (fd as usize) < NET_INTERCEPTED_FDS.len() {
            NET_INTERCEPTED_FDS[fd as usize] = true;
            log::trace!("网络连接隐藏: 拦截 {} (fd={})", path_str, fd);
        }
    }

    fd
}

/// read 替换函数 - 过滤 /proc/net 中的隐藏端口
#[cfg(any(target_os = "linux", target_os = "android"))]
unsafe extern "C" fn net_read_replace(
    fd: libc::c_int,
    buf: *mut libc::c_void,
    count: libc::size_t,
) -> libc::ssize_t {
    let original_fn = NET_ORIGINAL_READ.load(Ordering::Relaxed);
    if original_fn == 0 {
        set_errno(libc::EINVAL);
        return -1;
    }

    // 调用原始 read
    let original_read: unsafe extern "C" fn(
        libc::c_int,
        *mut libc::c_void,
        libc::size_t,
    ) -> libc::ssize_t = std::mem::transmute(original_fn);

    let bytes_read = original_read(fd, buf, count);

    // 检查是否需要过滤
    if bytes_read > 0 
        && (fd as usize) < NET_INTERCEPTED_FDS.len() 
        && NET_INTERCEPTED_FDS[fd as usize] 
    {
        // 初始化隐藏端口（如果需要）
        init_net_ports();
        
        // 获取隐藏端口列表
        let hidden_ports = HIDDEN_NET_PORTS.as_ref().unwrap();
        
        // 将读取的数据转换为字符串进行过滤
        let data = std::slice::from_raw_parts(buf as *const u8, bytes_read as usize);
        let text = String::from_utf8_lossy(data);
        
        // 过滤包含隐藏端口的行
        let filtered_lines: Vec<&str> = text.lines().enumerate().filter(|(i, line)| {
            // 第一行是标题行，保留
            if *i == 0 {
                return true;
            }
            
            // 检查本地地址和远程地址中是否包含隐藏端口
            // /proc/net/tcp 格式: sl local_address rem_address ...
            // 地址格式: IP:PORT (十六进制)
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                // 检查本地地址 (parts[1])
                let local_addr = parts[1];
                if let Some(colon_pos) = local_addr.rfind(':') {
                    let port_hex = &local_addr[colon_pos + 1..];
                    if hidden_ports.contains(port_hex) {
                        log::trace!("网络连接隐藏: 过滤行 {} (本地端口 {})", i, port_hex);
                        return false;
                    }
                }
                
                // 检查远程地址 (parts[2])
                let remote_addr = parts[2];
                if let Some(colon_pos) = remote_addr.rfind(':') {
                    let port_hex = &remote_addr[colon_pos + 1..];
                    if hidden_ports.contains(port_hex) {
                        log::trace!("网络连接隐藏: 过滤行 {} (远程端口 {})", i, port_hex);
                        return false;
                    }
                }
            }
            
            true
        }).map(|(_, line)| line).collect();
        
        // 重新组装过滤后的数据
        let filtered_text = filtered_lines.join("\n");
        let filtered_bytes = filtered_text.as_bytes();
        
        // 将过滤后的数据复制回缓冲区
        let copy_len = filtered_bytes.len().min(count);
        std::ptr::copy_nonoverlapping(filtered_bytes.as_ptr(), buf as *mut u8, copy_len);
        
        // 如果过滤后的数据比原始数据短，添加换行符
        if copy_len < count && copy_len > 0 {
            *((buf as *mut u8).add(copy_len - 1)) = b'\n';
        }
        
        return copy_len as libc::ssize_t;
    }

    bytes_read
}

// ======================== 公共接口 ========================

/// 网络连接隐藏器
///
/// 管理网络连接隐藏功能的生命周期
pub struct NetHider {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    hooker: Option<GotPltHooker>,
}

impl NetHider {
    /// 创建新的网络连接隐藏器
    pub fn new() -> Self {
        NetHider {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            hooker: None,
        }
    }

    /// 安装网络连接隐藏 Hook
    ///
    /// 通过 GOT/PLT Hook 拦截 openat 和 read 函数
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn install(&mut self) -> Result<()> {
        use crate::common::util::parse_proc_maps;
        use crate::common::types::ProcessId;

        log::info!("网络连接隐藏: 开始安装 Hook...");

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
        NET_ORIGINAL_OPENAT.store(openat_addr as usize, Ordering::Relaxed);
        hooker.hook_symbol("openat", net_openat_replace as *const ())?;

        // Hook read
        let read_addr = hooker.resolve_symbol("read")?;
        NET_ORIGINAL_READ.store(read_addr as usize, Ordering::Relaxed);
        hooker.hook_symbol("read", net_read_replace as *const ())?;

        self.hooker = Some(hooker);

        // 初始化隐藏端口列表
        unsafe {
            init_net_ports();
        }

        log::info!("网络连接隐藏: Hook 安装完成");
        Ok(())
    }

    /// 卸载网络连接隐藏 Hook
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn uninstall(&mut self) -> Result<()> {
        // 清除 fd 标记
        unsafe {
            NET_INTERCEPTED_FDS.fill(false);
        }
        
        // 清除函数指针
        NET_ORIGINAL_OPENAT.store(0, Ordering::Relaxed);
        NET_ORIGINAL_READ.store(0, Ordering::Relaxed);
        
        self.hooker = None;
        log::info!("网络连接隐藏: Hook 已卸载");
        Ok(())
    }

    /// 添加自定义隐藏端口
    pub fn add_port(&self, port: u16) {
        add_hidden_net_port(port);
    }
}

impl Default for NetHider {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_to_hex() {
        assert_eq!(port_to_hex(27042), "69A2");
        assert_eq!(port_to_hex(80), "0050");
    }

    #[test]
    fn test_is_proc_net_path() {
        assert!(is_proc_net_path("/proc/net/tcp"));
        assert!(is_proc_net_path("/proc/net/tcp6"));
        assert!(is_proc_net_path("/proc/net/udp"));
        assert!(!is_proc_net_path("/proc/self/maps"));
    }

    #[test]
    fn test_net_hider_creation() {
        let hider = NetHider::new();
        assert!(hider.hooker.is_none());
    }
}
