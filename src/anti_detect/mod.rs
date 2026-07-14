//! 反检测模块
//!
//! 提供绕过常见进程检测手段的能力，包括：
//! - /proc/self/maps 信息隐藏
//! - /proc/self/status 修改（TracerPid 字段清零）
//! - 文件描述符隐藏
//! - Frida 特征字符串擦除
//! - 端口扫描伪装
//! - 调用栈伪造
//! - 综合隐蔽管理器（按需加载、检测感知联动）
//!
//! ## 子模块
//! - `maps_hide` - /proc 接口伪装（maps 行过滤、地址范围隐藏）
//! - `tracer` - ptrace 痕迹清除（TracerPid 清零、ptrace check Hook）
//! - `signature` - 特征字符串擦除（内存扫描 + 零填充）
//! - `hide` - 综合隐藏管理器（StealthManager）
//! - `stack_fake` - 调用栈伪造（帧过滤 + 伪造插入）

#[cfg(unix)]
pub mod maps_hide;
#[cfg(unix)]
pub mod tracer;
pub mod signature;
pub mod hide;
pub mod stack_fake;
#[cfg(unix)]
pub mod port_hide;
#[cfg(unix)]
pub mod fd_hide;
#[cfg(unix)]
pub mod thread_hide;
#[cfg(unix)]
pub mod env_clean;
#[cfg(unix)]
pub mod net_hide;
#[cfg(unix)]
pub mod smart_stealth;
#[cfg(target_os = "android")]
pub mod linker_hide;

#[cfg(windows)]
pub mod win_hide;

// 重新导出主要接口
#[cfg(unix)]
pub use maps_hide::{hide_maps_entries, MapsHider, ProcInterceptor, DefaultProcInterceptor};
#[cfg(unix)]
pub use tracer::{clear_tracer_pid, hook_ptrace_check, TracerCleaner, TracerInterceptor};
pub use signature::{erase_frida_signatures, known_signatures, DefaultSignatureEraser, SignatureEraser};
pub use hide::{StealthManager, StealthMode, DetectionEvent};
pub use stack_fake::{StackFaker, Frame, fake_call_stack};
#[cfg(unix)]
pub use port_hide::PortHider;
#[cfg(unix)]
pub use fd_hide::FdHider;
#[cfg(unix)]
pub use thread_hide::ThreadHider;
#[cfg(unix)]
pub use env_clean::EnvCleaner;
#[cfg(unix)]
pub use net_hide::NetHider;
#[cfg(unix)]
pub use smart_stealth::SmartStealth;
#[cfg(target_os = "android")]
pub use linker_hide::{LinkerHideManager, SoinfoNode, SoinfoHideStatus};

/// 应用所有反检测措施
///
/// 依次调用所有反检测子模块，隐藏 frida-rust 的痕迹。
/// 这是便捷函数，等同于创建 StealthManager 并调用 apply_all()。
#[cfg(unix)]
pub fn apply_stealth() -> crate::Result<()> {
    log::info!("开始应用反检测措施...");

    // 1. 清除环境变量（最先执行，因为其他模块可能依赖环境变量）
    env_clean::clear_frida_env_vars();

    // 2. 清除 TracerPid
    clear_tracer_pid()?;

    // 3. 隐藏 /proc/self/maps 中的特征条目
    hide_maps_entries()?;

    // 4. 擦除 Frida 特征字符串
    erase_frida_signatures()?;

    // 5. 安装端口隐藏 Hook
    let mut port_hider = port_hide::PortHider::new();
    if let Err(e) = port_hider.install() {
        log::warn!("端口隐藏安装失败: {}", e);
    }

    // 6. 安装文件描述符隐藏 Hook
    let mut fd_hider = fd_hide::FdHider::new();
    if let Err(e) = fd_hider.install() {
        log::warn!("FD隐藏安装失败: {}", e);
    }

    // 7. 安装线程隐藏 Hook
    let mut thread_hider = thread_hide::ThreadHider::new();
    if let Err(e) = thread_hider.install() {
        log::warn!("线程隐藏安装失败: {}", e);
    }

    // 8. 安装网络连接隐藏 Hook
    let mut net_hider = net_hide::NetHider::new();
    if let Err(e) = net_hider.install() {
        log::warn!("网络连接隐藏安装失败: {}", e);
    }

    log::info!("所有反检测措施已应用");
    Ok(())
}

/// 应用所有反检测措施（Windows 版本）
#[cfg(windows)]
pub fn apply_stealth() -> crate::Result<()> {
    log::info!("开始应用 Windows 反检测措施...");

    let mut manager = win_hide::WinStealthManager::new();
    manager.apply_all()?;

    // 擦除 Frida 特征字符串
    erase_frida_signatures()?;

    log::info!("所有 Windows 反检测措施已应用");
    Ok(())
}
