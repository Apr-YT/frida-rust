//! 公共基础设施模块
//!
//! 提供项目范围内共享的错误类型、核心数据结构、常量定义和工具函数。

pub mod constants;
pub mod error;
#[cfg(unix)]
pub mod syscall_wrapper;
pub mod types;
pub mod util;

#[cfg(windows)]
pub mod win_util;
