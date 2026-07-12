//! 全局常量定义
//!
//! 集中管理注入、内存、通信等子系统中使用的魔数、大小限制等常量值。

// ======================== 魔数与协议标识 ========================

/// 通信协议魔数，用于验证消息合法性
pub const PROTOCOL_MAGIC: u32 = 0xF1D4_0001;

/// 注入器标识魔数，用于校验注入 agent
pub const INJECT_AGENT_MAGIC: u32 = 0x46E37001;

// ======================== 注入相关常量 ========================

/// 注入用的默认共享库路径（agent so）
pub const DEFAULT_AGENT_LIB_NAME: &str = "libfrida_agent.so";

/// 注入超时时间（毫秒）
pub const INJECT_TIMEOUT_MS: u64 = 10_000;

/// ptrace attach 重试间隔（毫秒）
pub const PTRACE_RETRY_INTERVAL_MS: u64 = 100;

/// ptrace attach 最大重试次数
pub const PTRACE_MAX_RETRIES: u32 = 50;

/// 注入 shellcode 最大长度（字节）
pub const SHELLCODE_MAX_SIZE: usize = 4096;

// ======================== 内存相关常量 ========================

/// 默认内存页大小（字节）
/// 在运行时通过 sysconf 获取实际值，此为编译时后备
pub const DEFAULT_PAGE_SIZE: usize = 4096;

/// 内存搜索默认最大扫描大小（字节）
pub const MEMORY_SCAN_MAX_SIZE: usize = 256 * 1024 * 1024; // 256 MB

/// 内存分配对齐大小
pub const MEMORY_ALIGN_SIZE: usize = 16;

/// mmap 默认分配大小（字节）
pub const MMAP_DEFAULT_SIZE: usize = 4 * 1024 * 1024; // 4 MB

// ======================== 通信相关常量 ========================

/// 通信缓冲区默认大小（字节）
pub const COMM_BUFFER_SIZE: usize = 64 * 1024; // 64 KB

/// 通信最大消息负载大小（字节）
pub const COMM_MAX_PAYLOAD_SIZE: usize = 1024 * 1024; // 1 MB

/// 消息头大小（字节）
pub const MESSAGE_HEADER_SIZE: usize = 20;

/// Unix Socket 默认路径模板
pub const UNIX_SOCKET_PATH_TEMPLATE: &str = "/tmp/frida-rust-{}.sock";

/// 默认通信超时（秒）
pub const COMM_TIMEOUT_SECS: u64 = 30;

// ======================== 脚本引擎常量 ========================

/// Rhai 脚本最大执行超时（毫秒）
pub const SCRIPT_TIMEOUT_MS: u64 = 30_000;

/// 脚本最大调用栈深度
pub const SCRIPT_MAX_CALL_DEPTH: u32 = 64;

// ======================== 反检测相关常量 ========================

/// /proc/self/maps 文件路径
pub const PROC_SELF_MAPS: &str = "/proc/self/maps";

/// /proc/self/status 文件路径
pub const PROC_SELF_STATUS: &str = "/proc/self/status";

/// /proc/self/fd 目录路径
pub const PROC_SELF_FD: &str = "/proc/self/fd";

/// Frida 默认监听端口范围起始
pub const FRIDA_DEFAULT_PORT_START: u16 = 27042;

/// Frida 默认监听端口范围结束
pub const FRIDA_DEFAULT_PORT_END: u16 = 27043;

// ======================== 版本信息 ========================

/// 协议版本号
pub const PROTOCOL_VERSION: u16 = 1;

/// 代理版本号
pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");
