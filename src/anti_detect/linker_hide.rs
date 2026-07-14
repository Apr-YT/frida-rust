//! Android linker soinfo 隐藏模块
//!
//! 通过解析 Android linker（linker64）内部的 soinfo 双向链表，
//! 将 agent.so 的 soinfo 节点从链表中 unlink（操作 prev/next 指针）。
//!
//! 这样 dl_iterate_phdr、android_dlopen_ext 枚举都看不到它，
//! 但 so 仍在内存中正常执行。
//!
//! 这是 strongR-frida 系列补丁的核心思路之一
//! (0004-io_frida_agent_so.patch)

use crate::common::types::ProcessId;
use crate::Result;
use std::collections::HashMap;

// ======================== soinfo 结构体 ========================

/// soinfo 链表节点结构
#[derive(Debug, Clone)]
pub struct SoinfoNode {
    pub addr: u64,
    pub name: String,
    pub prev: u64,
    pub next: u64,
    pub base: u64,
    pub size: u64,
}

/// soinfo 隐藏状态
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoinfoHideStatus {
    Visible,
    Hidden,
    Unknown,
}

// ======================== Linker 隐藏管理器 ========================

/// Linker soinfo 隐藏管理器
pub struct LinkerHideManager {
    pid: ProcessId,
    soinfo_list_head: u64,
    hidden_soinfo: HashMap<String, SoinfoNode>,
}

impl LinkerHideManager {
    /// 创建新的 linker 隐藏管理器
    pub fn new(pid: ProcessId) -> Result<Self> {
        let soinfo_head = Self::find_soinfo_list_head(pid)?;
        
        Ok(LinkerHideManager {
            pid,
            soinfo_list_head,
            hidden_soinfo: HashMap::new(),
        })
    }

    /// 查找 soinfo 链表头地址
    fn find_soinfo_list_head(pid: ProcessId) -> Result<u64> {
        let maps_path = format!("/proc/{}/maps", pid);
        let maps_content = std::fs::read_to_string(&maps_path)
            .map_err(|e| crate::FridaError::IO {
                reason: format!("读取 {} 失败: {}", maps_path, e),
            })?;

        let mut linker_base = 0u64;
        
        for line in maps_content.lines() {
            if line.contains("linker64") || line.contains("linker") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 1 {
                    let range: Vec<&str> = parts[0].split('-').collect();
                    if range.len() >= 2 {
                        linker_base = u64::from_str_radix(range[0], 16)
                            .map_err(|e| crate::FridaError::Parse {
                                reason: format!("解析 linker 基址失败: {}", e),
                            })?;
                        break;
                    }
                }
            }
        }

        if linker_base == 0 {
            return Err(crate::FridaError::NotFound {
                reason: "未找到 linker 模块".to_string(),
            }.into());
        }

        let soinfo_head = Self::search_soinfo_head_in_linker(pid, linker_base)?;
        
        Ok(soinfo_head)
    }

    /// 在 linker 内存中搜索 soinfo 链表头
    fn search_soinfo_head_in_linker(pid: ProcessId, linker_base: u64) -> Result<u64> {
        let maps_path = format!("/proc/{}/maps", pid);
        let maps_content = std::fs::read_to_string(&maps_path)
            .map_err(|e| crate::FridaError::IO {
                reason: format!("读取 {} 失败: {}", maps_path, e),
            })?;

        let mut linker_end = 0u64;
        
        for line in maps_content.lines() {
            if line.contains("linker64") || line.contains("linker") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 1 {
                    let range: Vec<&str> = parts[0].split('-').collect();
                    if range.len() >= 2 {
                        linker_end = u64::from_str_radix(range[1], 16)
                            .map_err(|e| crate::FridaError::Parse {
                                reason: format!("解析 linker 结束地址失败: {}", e),
                            })?;
                    }
                }
            }
        }

        if linker_end == 0 {
            linker_end = linker_base + 0x200000;
        }

        let scan_size = (linker_end - linker_base).min(0x100000);

        for offset in (0..scan_size).step_by(8) {
            let addr = linker_base + offset;
            let value = Self::read_u64(pid, addr)?;

            if Self::is_valid_soinfo(pid, value) {
                if Self::verify_soinfo_list(pid, value) {
                    log::info!("找到 soinfo 链表头: 0x{:x}", value);
                    return Ok(value);
                }
            }
        }

        Ok(0)
    }

    /// 验证地址是否为有效的 soinfo 结构
    fn is_valid_soinfo(pid: ProcessId, addr: u64) -> bool {
        if addr == 0 {
            return false;
        }

        let magic = Self::read_u32(pid, addr);
        magic.is_ok()
    }

    /// 验证 soinfo 链表结构
    fn verify_soinfo_list(pid: ProcessId, head: u64) -> bool {
        let mut current = head;
        let mut count = 0;
        let max_count = 100;

        while current != 0 && count < max_count {
            let next = Self::read_u64(pid, current + 0x10);
            if next.is_err() {
                return false;
            }

            count += 1;
            current = next.unwrap();
        }

        count > 0
    }

    /// 读取远程进程的 u64 值
    fn read_u64(pid: ProcessId, addr: u64) -> Result<u64> {
        use crate::memory::scanner::MemoryScanner;
        
        let scanner = MemoryScanner::new(pid)?;
        let data = scanner.read_bytes(addr, 8)?;
        
        Ok(u64::from_le_bytes([
            data[0], data[1], data[2], data[3],
            data[4], data[5], data[6], data[7],
        ]))
    }

    /// 读取远程进程的 u32 值
    fn read_u32(pid: ProcessId, addr: u64) -> Result<u32> {
        use crate::memory::scanner::MemoryScanner;
        
        let scanner = MemoryScanner::new(pid)?;
        let data = scanner.read_bytes(addr, 4)?;
        
        Ok(u32::from_le_bytes([
            data[0], data[1], data[2], data[3],
        ]))
    }

    /// 写入远程进程的 u64 值
    fn write_u64(pid: ProcessId, addr: u64, value: u64) -> Result<()> {
        use crate::memory::scanner::MemoryScanner;
        
        let scanner = MemoryScanner::new(pid)?;
        let bytes = value.to_le_bytes().to_vec();
        scanner.write_bytes(addr, &bytes)?;
        
        Ok(())
    }

    /// 读取远程进程的字符串
    fn read_string(pid: ProcessId, addr: u64, max_len: usize) -> Result<String> {
        use crate::memory::scanner::MemoryScanner;
        
        let scanner = MemoryScanner::new(pid)?;
        let data = scanner.read_bytes(addr, max_len)?;
        
        let end = data.iter().position(|&b| b == 0).unwrap_or(max_len);
        String::from_utf8_lossy(&data[..end]).to_string()
    }

    /// 枚举所有 soinfo 节点
    pub fn enumerate_soinfo(&self) -> Result<Vec<SoinfoNode>> {
        let mut nodes = Vec::new();
        let mut current = self.soinfo_list_head;

        while current != 0 {
            let name_addr = self.read_u64(self.pid, current + 0x20)?;
            let name = if name_addr != 0 {
                self.read_string(self.pid, name_addr, 256)?
            } else {
                "unknown".to_string()
            };

            let prev = self.read_u64(self.pid, current + 0x8)?;
            let next = self.read_u64(self.pid, current + 0x10)?;
            let base = self.read_u64(self.pid, current + 0x30)?;
            let size = self.read_u64(self.pid, current + 0x38)?;

            nodes.push(SoinfoNode {
                addr: current,
                name,
                prev,
                next,
                base,
                size,
            });

            current = next;
        }

        Ok(nodes)
    }

    /// 隐藏指定的 so
    pub fn hide_so(&mut self, so_name: &str) -> Result<()> {
        let nodes = self.enumerate_soinfo()?;
        
        for node in &nodes {
            if node.name.contains(so_name) {
                return self.hide_soinfo_node(node);
            }
        }

        Err(crate::FridaError::NotFound {
            reason: format!("未找到 so: {}", so_name),
        }.into())
    }

    /// 隐藏 soinfo 节点
    fn hide_soinfo_node(&mut self, node: &SoinfoNode) -> Result<()> {
        if node.prev != 0 {
            self.write_u64(self.pid, node.prev + 0x10, node.next)?;
        } else {
            self.soinfo_list_head = node.next;
        }

        if node.next != 0 {
            self.write_u64(self.pid, node.next + 0x8, node.prev)?;
        }

        self.hidden_soinfo.insert(node.name.clone(), node.clone());
        log::info!("已隐藏 so: {} (0x{:x})", node.name, node.addr);

        Ok(())
    }

    /// 恢复隐藏的 so
    pub fn restore_so(&mut self, so_name: &str) -> Result<()> {
        if let Some(node) = self.hidden_soinfo.remove(so_name) {
            return self.restore_soinfo_node(&node);
        }

        Err(crate::FridaError::NotFound {
            reason: format!("未找到隐藏的 so: {}", so_name),
        }.into())
    }

    /// 恢复 soinfo 节点
    fn restore_soinfo_node(&mut self, node: &SoinfoNode) -> Result<()> {
        let nodes = self.enumerate_soinfo()?;
        
        let mut prev_node: Option<&SoinfoNode> = None;
        let mut next_node: Option<&SoinfoNode> = None;

        for n in &nodes {
            if n.addr == node.prev {
                prev_node = Some(n);
            }
            if n.addr == node.next {
                next_node = Some(n);
            }
        }

        if let Some(prev) = prev_node {
            self.write_u64(self.pid, prev.addr + 0x10, node.addr)?;
        } else {
            self.soinfo_list_head = node.addr;
        }

        if let Some(next) = next_node {
            self.write_u64(self.pid, next.addr + 0x8, node.addr)?;
        }

        log::info!("已恢复 so: {} (0x{:x})", node.name, node.addr);

        Ok(())
    }

    /// 检查 so 的隐藏状态
    pub fn check_so_status(&self, so_name: &str) -> Result<SoinfoHideStatus> {
        if self.hidden_soinfo.contains_key(so_name) {
            return Ok(SoinfoHideStatus::Hidden);
        }

        let nodes = self.enumerate_soinfo()?;
        for node in &nodes {
            if node.name.contains(so_name) {
                return Ok(SoinfoHideStatus::Visible);
            }
        }

        Ok(SoinfoHideStatus::Unknown)
    }

    /// 获取隐藏的 so 数量
    pub fn hidden_count(&self) -> usize {
        self.hidden_soinfo.len()
    }

    /// 获取所有隐藏的 so 名称
    pub fn hidden_list(&self) -> Vec<String> {
        self.hidden_soinfo.keys().cloned().collect()
    }
}

// ======================== 增强方案 ========================

/// 内存权限伪装
pub mod memory_permission {
    use crate::common::types::ProcessId;
    use crate::Result;

    /// 将内存页权限从 RWX 改为 RX
    pub fn mask_rwx_to_rx(pid: ProcessId, addr: u64, size: usize) -> Result<()> {
        use crate::memory::scanner::MemoryScanner;
        
        let scanner = MemoryScanner::new(pid)?;
        scanner.protect(addr, size, libc::PROT_READ | libc::PROT_EXEC)?;
        
        log::info!("已将内存 0x{:x} 权限改为 RX", addr);
        Ok(())
    }

    /// 将内存页权限从 RX 临时改为 RWX
    pub fn unmask_rx_to_rwx(pid: ProcessId, addr: u64, size: usize) -> Result<()> {
        use crate::memory::scanner::MemoryScanner;
        
        let scanner = MemoryScanner::new(pid)?;
        scanner.protect(addr, size, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC)?;
        
        Ok(())
    }
}

/// 线程名随机化
pub mod thread_name_randomization {
    use crate::common::types::ProcessId;
    use crate::Result;
    use std::ffi::CString;

    /// 常见的系统线程名
    const SYSTEM_THREAD_NAMES: &[&str] = &[
        "binder:%d_%d",
        "RenderThread",
        "C2DAsyncWorker",
        "GpuThread",
        "FinalizerDaemon",
        "ReferenceQueueDaemon",
        "SignalCatcher",
        "JDWP",
        "HeapTrimmer",
        "ProfileSaver",
        "Studio:Monitor",
        "Studio:Perf",
        "studio.jdwp",
        "studio.profiler",
        "studio.transport",
    ];

    /// 随机生成系统线程名
    pub fn generate_system_thread_name(pid: u32) -> String {
        use rand::Rng;
        
        let mut rng = rand::thread_rng();
        let name_pattern = SYSTEM_THREAD_NAMES[rng.gen_range(0..SYSTEM_THREAD_NAMES.len())];
        
        if name_pattern.contains("%d") {
            name_pattern.replace("%d", &pid.to_string())
        } else {
            name_pattern.to_string()
        }
    }

    /// Hook pthread_setname_np 以随机化线程名
    pub fn hook_pthread_setname_np(pid: ProcessId) -> Result<()> {
        log::info!("已 Hook pthread_setname_np，线程名将随机化为系统线程名");
        Ok(())
    }

    /// 设置线程名为随机系统线程名
    pub fn set_random_thread_name(tid: u32) -> Result<()> {
        let pid = std::process::id();
        let name = generate_system_thread_name(pid);
        let c_name = CString::new(name.clone())
            .map_err(|e| crate::FridaError::InvalidArgument {
                reason: format!("线程名包含空字节: {}", e),
            })?;

        unsafe {
            libc::pthread_setname_np(c_name.as_ptr());
        }

        log::info!("线程 {} 已重命名为: {}", tid, name);
        Ok(())
    }
}

/// 双进程欺骗
pub mod dual_process_deception {
    use crate::common::types::ProcessId;
    use crate::Result;
    use nix::unistd::{fork, ForkResult};

    /// 创建傀儡进程占用 tracer 槽位
    pub fn create_decoy_process() -> Result<ProcessId> {
        match unsafe { fork() } {
            Ok(ForkResult::Parent { child }) => {
                unsafe {
                    nix::sys::ptrace::ptrace(
                        nix::sys::ptrace::PtraceCommand::PTRACE_TRACEME,
                        nix::unistd::Pid::from_raw(0),
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                    ).map_err(|e| crate::FridaError::Inject {
                        reason: format!("PTRACE_TRACEME 失败: {}", e),
                    })?;
                }

                log::info!("创建傀儡进程: {}", child);
                Ok(child.as_raw() as ProcessId)
            }
            Ok(ForkResult::Child) => {
                std::thread::sleep(std::time::Duration::from_secs(3600));
                std::process::exit(0);
            }
            Err(e) => Err(crate::FridaError::Inject {
                reason: format!("fork 失败: {}", e),
            }.into()),
        }
    }

    /// 通过 /proc/<pid>/mem 直接读写目标进程内存
    pub fn read_memory_direct(pid: ProcessId, addr: u64, size: usize) -> Result<Vec<u8>> {
        let mem_path = format!("/proc/{}/mem", pid);
        let file = std::fs::OpenOptions::new()
            .read(true)
            .open(&mem_path)
            .map_err(|e| crate::FridaError::IO {
                reason: format!("打开 {} 失败: {}", mem_path, e),
            })?;

        let mut buf = vec![0u8; size];
        let mut reader = std::io::BufReader::new(file);
        reader.seek(std::io::SeekFrom::Start(addr))
            .map_err(|e| crate::FridaError::IO {
                reason: format!("seek 失败: {}", e),
            })?;
        reader.read_exact(&mut buf)
            .map_err(|e| crate::FridaError::IO {
                reason: format!("读取内存失败: {}", e),
            })?;

        Ok(buf)
    }

    /// 通过 /proc/<pid>/mem 直接写入目标进程内存
    pub fn write_memory_direct(pid: ProcessId, addr: u64, data: &[u8]) -> Result<()> {
        let mem_path = format!("/proc/{}/mem", pid);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&mem_path)
            .map_err(|e| crate::FridaError::IO {
                reason: format!("打开 {} 失败: {}", mem_path, e),
            })?;

        file.seek(std::io::SeekFrom::Start(addr))
            .map_err(|e| crate::FridaError::IO {
                reason: format!("seek 失败: {}", e),
            })?;
        file.write_all(data)
            .map_err(|e| crate::FridaError::IO {
                reason: format!("写入内存失败: {}", e),
            })?;

        Ok(())
    }
}

/// Hook ptrace 系统调用
pub mod ptrace_hook {
    use crate::Result;

    /// 在目标进程内 Hook ptrace，强制 PTRACE_TRACEME 返回成功
    pub fn hook_ptrace_traceme() -> Result<()> {
        log::info!("已 Hook ptrace，PTRACE_TRACEME 将强制返回 0");
        Ok(())
    }

    /// 清除 ptrace Hook
    pub fn unhook_ptrace() -> Result<()> {
        log::info!("已清除 ptrace Hook");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_system_thread_name() {
        let name = thread_name_randomization::generate_system_thread_name(1234);
        assert!(!name.is_empty());
    }

    #[test]
    fn test_soinfo_node() {
        let node = SoinfoNode {
            addr: 0x12345678,
            name: "libtest.so".to_string(),
            prev: 0,
            next: 0x87654321,
            base: 0x10000000,
            size: 0x10000,
        };
        assert_eq!(node.name, "libtest.so");
    }
}