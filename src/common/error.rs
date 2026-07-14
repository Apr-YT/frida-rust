//! 统一错误类型定义
//!
//! 使用 `thiserror` 为每个子系统定义独立的错误枚举变体，
//! 统一收口到 `FridaError` 中，便于在整个项目中使用 `?` 操作符进行错误传播。

use std::path::PathBuf;

/// frida-rust 统一错误类型
#[derive(Debug, thiserror::Error)]
pub enum FridaError {
    // ======================== 模块相关错误 ========================
    /// 模块未找到
    #[error("模块未找到: {name}")]
    ModuleNotFound {
        /// 模块名称
        name: String,
    },

    /// 无效的 PE 文件
    #[error("无效的 PE 文件: {reason}")]
    InvalidPE {
        /// 原因
        reason: String,
    },

    // ======================== 注入相关错误 ========================
    /// 进程注入失败
    #[error("注入失败: {reason} (PID: {pid})")]
    Inject {
        /// 错误原因描述
        reason: String,
        /// 目标进程 ID
        pid: u32,
        /// 底层 IO 错误（如有）
        #[source]
        source: Option<std::io::Error>,
    },

    /// ptrace 附加/分离失败
    #[error("ptrace 操作失败: {op} (PID: {pid}): {detail}")]
    Ptrace {
        /// 操作类型（attach/detach/peek/poke 等）
        op: String,
        /// 目标进程 ID
        pid: u32,
        /// 详细错误信息
        detail: String,
    },

    /// ELF 加载失败
    #[error("ELF 加载失败: {path}: {detail}")]
    ElfLoad {
        /// 文件路径
        path: PathBuf,
        /// 详细错误信息
        detail: String,
    },

    // ======================== Hook 相关错误 ========================
    /// 函数 Hook 安装失败
    #[error("Hook 安装失败 [{module}::{symbol}]: {reason}")]
    Hook {
        /// 所属模块名称
        module: String,
        /// 目标符号名称
        symbol: String,
        /// 错误原因
        reason: String,
    },

    /// Hook 点不存在或无效
    #[error("Hook 点无效: {reason}")]
    InvalidHookPoint {
        /// 错误原因
        reason: String,
    },

    // ======================== 内存操作错误 ========================
    /// 内存读取失败
    #[error("内存读取失败 (地址: {address:#x}, 大小: {size}): {reason}")]
    MemoryRead {
        /// 目标地址
        address: usize,
        /// 读取大小
        size: usize,
        /// 错误原因
        reason: String,
    },

    /// 内存写入失败
    #[error("内存写入失败 (地址: {address:#x}, 大小: {size}): {reason}")]
    MemoryWrite {
        /// 目标地址
        address: usize,
        /// 写入大小
        size: usize,
        /// 错误原因
        reason: String,
    },

    /// 内存保护属性修改失败
    #[error("内存保护修改失败 (地址: {address:#x}): {reason}")]
    MemoryProtect {
        /// 目标地址
        address: usize,
        /// 错误原因
        reason: String,
    },

    // ======================== 脚本引擎错误 ========================
    /// 脚本编译或执行错误
    #[error("脚本错误: {reason}")]
    Script {
        /// 错误原因
        reason: String,
    },

    /// 脚本引擎初始化失败
    #[error("脚本引擎初始化失败: {reason}")]
    ScriptEngineInit {
        /// 错误原因
        reason: String,
    },

    // ======================== 通信相关错误 ========================
    /// 通信通道错误
    #[error("通信通道错误: {reason}")]
    Communication {
        /// 错误原因
        reason: String,
        /// 底层 IO 错误（如有）
        #[source]
        source: Option<std::io::Error>,
    },

    /// 协议解析错误
    #[error("协议解析错误: {reason}")]
    Protocol {
        /// 错误原因
        reason: String,
    },

    /// 加密操作失败
    #[error("加密操作失败: {reason}")]
    Crypto {
        /// 错误原因
        reason: String,
    },

    // ======================== 反汇编相关错误 ========================
    /// 反汇编操作失败
    #[error("反汇编失败: {reason}")]
    Disasm {
        /// 错误原因
        reason: String,
    },

    // ======================== 反检测相关错误 ========================
    /// 反检测操作失败
    #[error("反检测操作失败: {reason}")]
    AntiDetect {
        /// 错误原因
        reason: String,
    },

    // ======================== 通用错误 ========================
    /// 不支持的操作或平台
    #[error("不支持: {reason}")]
    Unsupported {
        /// 错误原因
        reason: String,
    },

    /// 未找到目标进程或模块
    #[error("未找到: {reason}")]
    NotFound {
        /// 错误原因
        reason: String,
    },

    /// 底层系统 IO 错误
    #[error("IO 错误: {0}")]
    Io(#[from] std::io::Error),

    /// 其他未分类错误
    #[error("{0}")]
    Other(String),
}

// 为 FridaError 实现 From<anyhow::Error> 以便兼容
impl From<anyhow::Error> for FridaError {
    fn from(err: anyhow::Error) -> Self {
        FridaError::Other(err.to_string())
    }
}

/// 简化的 Result 类型别名
pub type Result<T> = std::result::Result<T, FridaError>;
