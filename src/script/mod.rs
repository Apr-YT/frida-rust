//! 脚本引擎模块
//!
//! 基于 Rhai 脚本引擎提供可编程的动态插桩能力。
//! 用户可以编写 Rhai 脚本来定义 Hook 行为、数据收集逻辑等。
//!
//! ## 子模块
//! - `engine` - Rhai 脚本引擎封装（极致裁剪配置）
//! - `loader` - 脚本加载器（AES-GCM 解密、预编译、嵌入区域加载）
//! - `host_context` - 宿主上下文（API 注册表、Hook/Memory 桥接）

pub mod engine;
pub mod host_context;
pub mod loader;

// 重新导出主要类型
pub use engine::{ScriptEngine, ScriptResult, ScriptState};
pub use host_context::{HostContext, ProcessInfo};
pub use loader::{ScriptAST, ScriptLoader, encrypt_script};
