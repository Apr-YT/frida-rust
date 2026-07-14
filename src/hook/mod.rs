//! 函数 Hook 模块
//!
//! 提供多种函数拦截能力：
//! - **Inline Hook**: 修改目标函数入口处的机器码，跳转到自定义处理函数
//! - **GOT/PLT Hook**: 修改全局偏移表中的函数指针，替换为目标地址
//! - **Java Hook**: 通过 JNI 拦截 Java 虚拟机中的方法调用
//!
//! 所有 Hook 通过 [`HookManager`] 统一管理生命周期。

pub mod inline;
#[cfg(unix)]
pub mod got_plt;
#[cfg(windows)]
pub mod iat_hook;
#[cfg(unix)]
pub mod java_hook;
pub mod manager;
#[cfg(unix)]
pub mod ebpf_hook;
#[cfg(unix)]
pub mod hw_breakpoint;

// 重新导出主要接口
pub use manager::{HookContext, HookId, HookManager};
pub use inline::{InlineHooker, Trampoline};
#[cfg(unix)]
pub use got_plt::{GotPltHooker, GotHookHandle};
#[cfg(windows)]
pub use iat_hook::{IatHooker, IatHookHandle};
#[cfg(unix)]
pub use java_hook::{JavaHooker, JavaHookHandle};
#[cfg(unix)]
pub use ebpf_hook::{EbpfHooker, EbpfHookConfig, EbpfHookEvent, EbpfHookHandle};
#[cfg(unix)]
pub use hw_breakpoint::{HardwareBreakpointManager, HardwareBreakpointConfig, HardwareBreakpointHandle};
