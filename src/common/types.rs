//! 核心类型定义
//!
//! 定义整个项目中使用的核心数据结构，包括进程/线程标识、
//! 模块/符号信息、内存区域描述以及 Hook 相关类型。

use serde::{Deserialize, Serialize};
use std::fmt;

// ======================== 进程与线程标识 ========================

/// 进程 ID 包装类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessId(pub u32);

/// 线程 ID 包装类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ThreadId(pub u32);

impl fmt::Display for ProcessId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for ThreadId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u32> for ProcessId {
    fn from(val: u32) -> Self {
        ProcessId(val)
    }
}

impl From<ProcessId> for u32 {
    fn from(pid: ProcessId) -> Self {
        pid.0
    }
}

impl From<u32> for ThreadId {
    fn from(val: u32) -> Self {
        ThreadId(val)
    }
}

impl From<ThreadId> for u32 {
    fn from(tid: ThreadId) -> Self {
        tid.0
    }
}

// ======================== 进程信息 ========================

/// 进程信息描述
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    /// 进程 ID
    pub pid: ProcessId,
    /// 进程名称（来自 /proc/pid/comm 或 cmdline）
    pub name: String,
    /// 完整命令行（来自 /proc/pid/cmdline）
    pub cmdline: Vec<String>,
    /// 进程状态（R=运行, S=睡眠, D=磁盘休眠, Z=僵尸, T=停止）
    pub state: String,
    /// 父进程 ID
    pub ppid: u32,
    /// 进程真实用户 ID
    pub uid: u32,
    /// 可执行文件路径
    pub exe_path: String,
    /// 进程工作目录
    pub cwd: String,
}

impl fmt::Display for ProcessInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PID={} ({}) [{}] ppid={} uid={} exe={}",
            self.pid.0,
            self.name,
            self.state,
            self.ppid,
            self.uid,
            self.exe_path
        )
    }
}

// ======================== 模块与符号信息 ========================

/// 模块信息（共享库/可执行文件）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleInfo {
    /// 模块名称（如 "libfoo.so"）
    pub name: String,
    /// 模块基址（在目标进程地址空间中的加载地址）
    pub base_addr: usize,
    /// 模块大小（字节）
    pub size: usize,
    /// 模块完整路径
    pub path: String,
}

impl fmt::Display for ModuleInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} @ {:#x} ({} bytes, path: {})",
            self.name, self.base_addr, self.size, self.path
        )
    }
}

/// 符号信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolInfo {
    /// 符号名称
    pub name: String,
    /// 符号地址（在目标进程地址空间中）
    pub addr: usize,
    /// 符号大小（字节）
    pub size: usize,
}

impl fmt::Display for SymbolInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} @ {:#x} ({} bytes)", self.name, self.addr, self.size)
    }
}

// ======================== 内存区域 ========================

/// 内存保护权限
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryPerms {
    /// 可读
    pub read: bool,
    /// 可写
    pub write: bool,
    /// 可执行
    pub execute: bool,
    /// 私有（写时复制）
    pub private: bool,
}

impl MemoryPerms {
    /// 创建只读权限
    pub const fn readonly() -> Self {
        MemoryPerms {
            read: true,
            write: false,
            execute: false,
            private: true,
        }
    }

    /// 创建读写权限
    pub const fn readwrite() -> Self {
        MemoryPerms {
            read: true,
            write: true,
            execute: false,
            private: true,
        }
    }

    /// 创建可读可执行权限
    pub const fn read_execute() -> Self {
        MemoryPerms {
            read: true,
            write: false,
            execute: true,
            private: true,
        }
    }

    /// 创建读写可执行权限（RWX）
    pub const fn rwx() -> Self {
        MemoryPerms {
            read: true,
            write: true,
            execute: true,
            private: true,
        }
    }

    /// 转换为 libc 风格的整数标志（Unix 独有）
    #[cfg(unix)]
    pub fn to_prot(&self) -> libc::c_int {
        use libc::{PROT_EXEC, PROT_READ, PROT_WRITE};
        let mut prot = 0;
        if self.read {
            prot |= PROT_READ;
        }
        if self.write {
            prot |= PROT_WRITE;
        }
        if self.execute {
            prot |= PROT_EXEC;
        }
        prot
    }

    /// 从字符串解析权限（如 "r-xp"，Unix 独有）
    #[cfg(unix)]
    pub fn from_str_perms(s: &str) -> Self {
        MemoryPerms {
            read: s.contains('r'),
            write: s.contains('w'),
            execute: s.contains('x'),
            private: s.contains('p'),
        }
    }
}

impl fmt::Display for MemoryPerms {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let r = if self.read { 'r' } else { '-' };
        let w = if self.write { 'w' } else { '-' };
        let x = if self.execute { 'x' } else { '-' };
        let p = if self.private { 'p' } else { 's' };
        write!(f, "{}{}{}{}", r, w, x, p)
    }
}

/// 内存区域描述
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegion {
    /// 区域起始地址
    pub start: usize,
    /// 区域结束地址
    pub end: usize,
    /// 内存保护权限
    pub perms: MemoryPerms,
    /// 区域名称（映射文件路径，匿名映射为空）
    pub name: String,
}

impl MemoryRegion {
    /// 返回区域大小
    pub fn size(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    /// 检查地址是否在该区域内
    pub fn contains_addr(&self, addr: usize) -> bool {
        addr >= self.start && addr < self.end
    }
}

impl fmt::Display for MemoryRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:#x}-{:#x} {} {} ({} bytes)",
            self.start,
            self.end,
            self.perms,
            self.name,
            self.size()
        )
    }
}

// ======================== Hook 相关类型 ========================

/// Hook 类型枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HookType {
    /// Inline Hook - 修改目标函数入口指令跳转到 trampoline
    Inline,
    /// GOT/PLT Hook - 修改全局偏移表中的函数指针
    GotPlt,
    /// Java 方法 Hook - 通过 JNI 拦截 Java 层方法调用
    Java,
}

impl fmt::Display for HookType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HookType::Inline => write!(f, "inline"),
            HookType::GotPlt => write!(f, "got/plt"),
            HookType::Java => write!(f, "java"),
        }
    }
}

/// Hook 点描述
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookPoint {
    /// 所属模块名称
    pub module: String,
    /// 目标符号名称
    pub symbol: String,
    /// 相对模块基址的偏移量（字节）
    pub offset: usize,
    /// Hook 类型
    pub hook_type: HookType,
}

impl fmt::Display for HookPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {}::{} + {:#x}",
            self.hook_type, self.module, self.symbol, self.offset
        )
    }
}

// ======================== 架构相关 ========================

/// 支持的 CPU 架构
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Architecture {
    /// x86-64 (AMD64)
    X86_64,
    /// AArch64 (ARMv8)
    Aarch64,
    /// ARM (ARMv7)
    Arm,
}

impl Architecture {
    /// 返回当前进程的架构
    #[cfg(target_arch = "x86_64")]
    pub const fn current() -> Self {
        Architecture::X86_64
    }

    #[cfg(target_arch = "aarch64")]
    pub const fn current() -> Self {
        Architecture::Aarch64
    }

    #[cfg(target_arch = "arm")]
    pub const fn current() -> Self {
        Architecture::Arm
    }

    /// 返回指针大小（字节）
    pub fn pointer_size(&self) -> usize {
        match self {
            Architecture::X86_64 | Architecture::Aarch64 => 8,
            Architecture::Arm => 4,
        }
    }

    /// 返回架构名称字符串
    pub fn as_str(&self) -> &'static str {
        match self {
            Architecture::X86_64 => "x86_64",
            Architecture::Aarch64 => "aarch64",
            Architecture::Arm => "arm",
        }
    }
}

impl fmt::Display for Architecture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
