//! Android 设备支持模块(主机侧)
//!
//! 提供通过 adb 操作 Android 设备的能力:
//! - `adb` - adb 命令行封装(设备发现 / shell / push / forward)
//! - `device` - 设备客户端(设备信息 / 进程 / 包 / logcat)
//! - `daemon` - 设备端 frida-server 守护进程通信
//! - `dex` - DEX 文件解析(纯逻辑)
//!
//! 旧版"本机 /proc 直读"实现(process/logcat)已废弃,仅保留在
//! Linux/Android 目标上编译,后续移除。

pub mod adb;
pub mod device;
pub mod daemon;
pub mod dex;

/// 旧版"本机 /proc 直读"实现,仅限 Linux/Android(已废弃)
#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod process;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod logcat;

pub use adb::{first_online, list_devices, AdbDevice};
pub use daemon::ping as daemon_ping;
pub use device::{DeviceClient, DeviceInfo, DeviceProcess};
pub use dex::DexFile;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use process::{
    get_pid_by_package, get_selinux_context, list_running_packages, AndroidPackageInfo,
    AndroidProcessInfo,
};
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use logcat::LogcatReader;
