//! 综合隐藏管理器
//!
//! StealthManager 统一管理所有反检测子模块的生命周期，
//! 提供按需加载、检测感知联动等高级功能。

#[cfg(unix)]
use crate::anti_detect::maps_hide::MapsHider;
use crate::anti_detect::signature::erase_frida_signatures;
use crate::anti_detect::stack_fake::StackFaker;
#[cfg(unix)]
use crate::anti_detect::tracer::{TracerCleaner, TracerInterceptor};
#[cfg(unix)]
use crate::anti_detect::port_hide::PortHider;
#[cfg(unix)]
use crate::anti_detect::fd_hide::FdHider;
#[cfg(unix)]
use crate::anti_detect::thread_hide::ThreadHider;
#[cfg(unix)]
use crate::anti_detect::env_clean::EnvCleaner;
#[cfg(unix)]
use crate::anti_detect::net_hide::NetHider;
#[cfg(any(target_os = "linux", target_os = "android"))]
use crate::communication::kernel_channel::KernelChannel;
use crate::Result;

// ======================== 隐蔽模式状态 ========================

/// 隐蔽模式状态
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StealthMode {
    /// 完全隐蔽（最高级别）
    Full,
    /// 标准隐蔽（推荐级别）
    Standard,
    /// 最小隐蔽（仅擦除关键特征）
    Minimal,
    /// 无隐蔽（调试模式）
    None,
}

impl Default for StealthMode {
    fn default() -> Self {
        StealthMode::Standard
    }
}

// ======================== 检测事件 ========================

/// 检测事件类型
#[derive(Debug, Clone)]
pub enum DetectionEvent {
    /// 进程扫描检测
    ProcessScan { pid: u32, name: String },
    /// 内存扫描检测
    MemoryScan { region: crate::common::types::MemoryRegion },
    /// 系统调用 Hook 检测
    SyscallHook { syscall: String },
    /// 文件访问检测
    FileAccess { path: String },
    /// 网络连接检测
    NetworkConnection { addr: String },
}

// ======================== 隐蔽管理器 ========================

/// 综合隐蔽管理器
///
/// 按需加载各反检测模块，避免启动时集中暴露特征。
pub struct StealthManager {
    mode: StealthMode,
    #[cfg(unix)]
    maps_hider: Option<MapsHider>,
    #[cfg(unix)]
    tracer_cleaner: Option<TracerCleaner>,
    stack_faker: Option<StackFaker>,
    #[cfg(unix)]
    port_hider: Option<PortHider>,
    #[cfg(unix)]
    fd_hider: Option<FdHider>,
    #[cfg(unix)]
    thread_hider: Option<ThreadHider>,
    #[cfg(unix)]
    env_cleaner: Option<EnvCleaner>,
    #[cfg(unix)]
    net_hider: Option<NetHider>,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    kernel_channel: Option<KernelChannel>,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    kernel_available: bool,
    loaded: bool,
}

impl StealthManager {
    /// 创建新的隐蔽管理器
    pub fn new() -> Self {
        StealthManager {
            mode: StealthMode::Standard,
            #[cfg(unix)]
            maps_hider: None,
            #[cfg(unix)]
            tracer_cleaner: None,
            stack_faker: None,
            #[cfg(unix)]
            port_hider: None,
            #[cfg(unix)]
            fd_hider: None,
            #[cfg(unix)]
            thread_hider: None,
            #[cfg(unix)]
            env_cleaner: None,
            #[cfg(unix)]
            net_hider: None,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            kernel_channel: None,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            kernel_available: true,
            loaded: false,
        }
    }

    /// 设置隐蔽模式
    pub fn set_mode(&mut self, mode: StealthMode) {
        self.mode = mode;
        log::info!("隐蔽模式已设置为: {:?}", mode);
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn ensure_kernel_channel(&mut self) -> Option<&KernelChannel> {
        if !self.kernel_available {
            return None;
        }

        if self.kernel_channel.is_none() {
            match KernelChannel::new() {
                Ok(channel) => {
                    match channel.ping() {
                        Ok(_) => {
                            log::info!("内核通道已连接，优先使用内核级进程隐藏");
                            self.kernel_channel = Some(channel);
                        }
                        Err(e) => {
                            log::warn!("内核通道不可用，回退到用户态隐藏: {}", e);
                            self.kernel_available = false;
                            return None;
                        }
                    }
                }
                Err(e) => {
                    log::warn!("创建内核通道失败，回退到用户态隐藏: {}", e);
                    self.kernel_available = false;
                    return None;
                }
            }
        }

        self.kernel_channel.as_ref()
    }

    /// 按需加载反检测模块
    ///
    /// 根据当前模式决定加载哪些模块，避免一次性加载过多特征。
    pub fn load_on_demand(&mut self) -> Result<()> {
        if self.loaded {
            return Ok(());
        }

        // 环境变量清理总是执行（最小开销）
        #[cfg(unix)]
        {
            self.env_cleaner = Some(EnvCleaner::new());
        }

        match self.mode {
            StealthMode::Full => {
                #[cfg(unix)]
                {
                    self.maps_hider = Some(MapsHider::new());
                    self.tracer_cleaner = Some(TracerCleaner::new());
                    self.port_hider = Some(PortHider::new());
                    self.fd_hider = Some(FdHider::new());
                    self.thread_hider = Some(ThreadHider::new());
                    self.net_hider = Some(NetHider::new());
                }
                self.stack_faker = Some(StackFaker::new());
            }
            StealthMode::Standard => {
                #[cfg(unix)]
                {
                    self.tracer_cleaner = Some(TracerCleaner::new());
                    self.port_hider = Some(PortHider::new());
                    self.net_hider = Some(NetHider::new());
                }
                self.stack_faker = Some(StackFaker::new());
            }
            StealthMode::Minimal => {
                // 仅擦除特征字符串和清理环境变量
            }
            StealthMode::None => {}
        }

        self.loaded = true;
        log::info!("隐蔽模块按需加载完成 (模式: {:?})", self.mode);
        Ok(())
    }

    /// 应用所有可用的反检测措施
    ///
    /// 依次调用已加载模块的隐藏功能。
    pub fn apply_all(&mut self) -> Result<()> {
        self.load_on_demand()?;

        // 0. 优先尝试内核级进程隐藏（最高优先级）
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            let current_pid = unsafe { libc::getpid() };
            if let Some(channel) = self.ensure_kernel_channel() {
                match channel.hide_process(current_pid) {
                    Ok(()) => {
                        log::info!("内核级进程隐藏成功: PID={}", current_pid);
                    }
                    Err(e) => {
                        log::warn!("内核级进程隐藏失败，继续用户态隐藏: {}", e);
                    }
                }
            }
        }

        // 1. 清除环境变量（最先执行）
        #[cfg(unix)]
        {
            if let Some(ref cleaner) = self.env_cleaner {
                cleaner.clear_now();
            }
        }

        // 2. 擦除 Frida 特征字符串
        erase_frida_signatures()?;

        // 3. 应用 Unix 特定的隐藏措施
        #[cfg(unix)]
        {
            if let Some(ref mut hider) = self.maps_hider {
                hider.hide_default()?;
            }
            if let Some(ref mut cleaner) = self.tracer_cleaner {
                cleaner.clear_tracer_pid()?;
            }
            if let Some(ref mut hider) = self.port_hider {
                if let Err(e) = hider.install() {
                    log::warn!("端口隐藏安装失败: {}", e);
                }
            }
            if let Some(ref mut hider) = self.fd_hider {
                if let Err(e) = hider.install() {
                    log::warn!("FD隐藏安装失败: {}", e);
                }
            }
            if let Some(ref mut hider) = self.thread_hider {
                if let Err(e) = hider.install() {
                    log::warn!("线程隐藏安装失败: {}", e);
                }
            }
            if let Some(ref mut hider) = self.net_hider {
                if let Err(e) = hider.install() {
                    log::warn!("网络连接隐藏安装失败: {}", e);
                }
            }
        }

        log::info!("所有隐蔽措施已应用");
        Ok(())
    }

    /// 处理检测事件
    ///
    /// 当检测到潜在的对抗行为时，自动加强隐蔽措施。
    pub fn on_detection_event(&mut self, event: DetectionEvent) -> Result<()> {
        log::warn!("检测到对抗事件: {:?}", event);

        // 根据事件类型动态调整隐蔽策略
        match event {
            DetectionEvent::ProcessScan { .. } => {
                self.set_mode(StealthMode::Full);
                self.apply_all()?;
            }
            DetectionEvent::MemoryScan { .. } => {
                #[cfg(unix)]
                {
                    if let Some(ref mut hider) = self.maps_hider {
                        hider.hide_default()?;
                    }
                }
            }
            DetectionEvent::SyscallHook { .. } => {
                self.stack_faker = Some(StackFaker::new());
            }
            DetectionEvent::FileAccess { .. } => {
                erase_frida_signatures()?;
            }
            DetectionEvent::NetworkConnection { .. } => {}
        }

        Ok(())
    }

    /// 恢复所有修改（卸载 Hook 等）
    pub fn restore_all(&mut self) -> Result<()> {
        #[cfg(unix)]
        {
            if let Some(ref mut cleaner) = self.tracer_cleaner {
                cleaner.restore()?;
            }
            if let Some(ref mut hider) = self.port_hider {
                let _ = hider.uninstall();
            }
            if let Some(ref mut hider) = self.fd_hider {
                let _ = hider.uninstall();
            }
            if let Some(ref mut hider) = self.thread_hider {
                let _ = hider.uninstall();
            }
            if let Some(ref mut hider) = self.net_hider {
                let _ = hider.uninstall();
            }
        }
        log::info!("所有隐蔽措施已恢复");
        Ok(())
    }
}

impl Default for StealthManager {
    fn default() -> Self {
        Self::new()
    }
}
