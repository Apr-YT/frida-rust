//! Android 平台专用模块
//!
//! 提供 Android 特有的逆向工程能力，包括：
//! - 进程管理（按包名查找、SELinux 上下文）
//! - DEX 文件解析
//! - logcat 日志集成

pub mod process;
pub mod dex;
pub mod logcat;

pub use process::{AndroidProcessInfo, AndroidPackageInfo, get_pid_by_package, list_running_packages, get_selinux_context};
pub use dex::DexFile;
pub use logcat::LogcatReader;