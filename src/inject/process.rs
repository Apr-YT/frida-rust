//! 进程管理模块
//!
//! 提供进程枚举、查找、模块/线程枚举等功能，
//! 通过解析 Linux `/proc` 文件系统实现。
//!
//! 主要功能：
//! - `enum_processes()` - 枚举系统中所有进程
//! - `find_process_by_name()` - 按名称查找进程
//! - `enum_modules()` - 枚举指定进程的所有已加载模块
//! - `enum_threads()` - 枚举指定进程的所有线程
//! - `get_process_info()` - 获取指定进程的详细信息

use crate::common::error::FridaError;
use crate::common::types::{MemoryRegion, ModuleInfo, ProcessId, ProcessInfo, ThreadId};
use std::collections::HashMap;

/// 枚举系统中所有进程
///
/// 遍历 `/proc` 目录下的数字子目录，收集每个进程的基本信息。
///
/// # 返回值
/// 返回所有可见进程的信息列表。如果无法读取 `/proc` 目录或解析失败，返回错误。
///
/// # 注意
/// 需要 root 权限才能看到所有进程的信息，普通用户只能看到自己的进程。
pub fn enum_processes() -> crate::Result<Vec<ProcessInfo>> {
    let proc_dir = std::fs::read_dir("/proc")?;

    let mut processes = Vec::new();

    for entry in proc_dir {
        let entry = entry?;
        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();

        // 只处理数字目录名（进程 PID）
        if let Ok(pid_num) = name_str.parse::<u32>() {
            if pid_num == 0 {
                continue; // 跳过 kernel 进程
            }
            match get_process_info(ProcessId(pid_num)) {
                Ok(info) => processes.push(info),
                Err(e) => {
                    // 进程可能在枚举过程中退出了，跳过即可
                    log::debug!("无法获取 PID {} 的信息: {}", pid_num, e);
                }
            }
        }
    }

    log::debug!("枚举到 {} 个进程", processes.len());
    Ok(processes)
}

/// 按名称查找进程
///
/// 在所有可见进程中搜索名称匹配的进程。
/// 名称匹配规则：进程名（来自 /proc/pid/comm）或命令行中包含指定字符串。
///
/// # 参数
/// - `name`: 要搜索的进程名称（部分匹配）
///
/// # 返回值
/// 返回第一个匹配的进程信息，如果没有找到则返回 None。
pub fn find_process_by_name(name: &str) -> crate::Result<Option<ProcessInfo>> {
    let processes = enum_processes()?;

    for proc in processes {
        // 检查进程名是否匹配
        if proc.name.contains(name) {
            return Ok(Some(proc));
        }
        // 检查命令行是否包含目标名称
        for arg in &proc.cmdline {
            if arg.contains(name) {
                return Ok(Some(proc));
            }
        }
    }

    Ok(None)
}

/// 枚举指定进程的所有线程
///
/// 遍历 `/proc/[pid]/task` 目录，获取该进程下所有线程的 TID。
///
/// # 参数
/// - `pid`: 目标进程 ID
///
/// # 返回值
/// 返回该进程所有线程 ID 的列表。
pub fn enum_threads(pid: ProcessId) -> crate::Result<Vec<ThreadId>> {
    let task_dir_path = format!("/proc/{}/task", pid.0);
    let task_dir = std::fs::read_dir(&task_dir_path)?;

    let mut threads = Vec::new();

    for entry in task_dir {
        let entry = entry?;
        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();

        if let Ok(tid_num) = name_str.parse::<u32>() {
            threads.push(ThreadId(tid_num));
        }
    }

    log::debug!(
        "进程 PID {} 共有 {} 个线程",
        pid.0,
        threads.len()
    );
    Ok(threads)
}

/// 枚举指定进程的所有已加载模块（共享库）
///
/// 解析 `/proc/[pid]/maps` 文件，提取所有映射的共享库信息，
/// 合并同一库的多个映射区域为一个完整的模块信息。
///
/// # 参数
/// - `pid`: 目标进程 ID
///
/// # 返回值
/// 返回该进程所有已加载模块的列表，按基址排序。
pub fn enum_modules(pid: ProcessId) -> crate::Result<Vec<ModuleInfo>> {
    let maps_path = format!("/proc/{}/maps", pid.0);
    let content = std::fs::read_to_string(&maps_path)?;

    // 使用 HashMap 合并同一库的多个映射区域
    let mut module_map: HashMap<String, (usize, usize)> = HashMap::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // 解析格式: address           perms offset  dev   inode   pathname
        let parts: Vec<&str> = line.splitn(6, |c: char| c == ' ' || c == '\t').collect();
        if parts.len() < 6 {
            continue;
        }

        let name = parts[5].trim();
        if name.is_empty() {
            continue; // 跳过匿名映射
        }

        // 解析地址范围
        let addr_range: Vec<&str> = parts[0].split('-').collect();
        if addr_range.len() != 2 {
            continue;
        }

        let start = usize::from_str_radix(addr_range[0], 16).unwrap_or(0);
        let end = usize::from_str_radix(addr_range[1], 16).unwrap_or(0);

        let entry = module_map.entry(name.to_string()).or_insert((usize::MAX, 0));
        // 记录最小起始地址和最大结束地址
        if start < entry.0 {
            entry.0 = start;
        }
        if end > entry.1 {
            entry.1 = end;
        }
    }

    // 转换为 ModuleInfo 列表
    let mut modules: Vec<ModuleInfo> = module_map
        .into_iter()
        .map(|(path, (base, end))| {
            let name = std::path::Path::new(&path)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| path.clone());
            let size = if end > base { end - base } else { 0 };
            ModuleInfo {
                name,
                base_addr: base,
                size,
                path,
            }
        })
        .collect();

    // 按基址排序
    modules.sort_by_key(|m| m.base_addr);

    log::debug!(
        "进程 PID {} 共有 {} 个已加载模块",
        pid.0,
        modules.len()
    );
    Ok(modules)
}

/// 获取指定进程的详细信息
///
/// 通过读取 `/proc/[pid]/` 下的多个文件获取完整的进程信息：
/// - `/proc/pid/status` - 状态、PPID、UID 等
/// - `/proc/pid/cmdline` - 命令行参数
/// - `/proc/pid/comm` - 进程名
/// - `/proc/pid/exe` - 可执行文件路径（通过 readlink）
/// - `/proc/pid/cwd` - 工作目录（通过 readlink）
///
/// # 参数
/// - `pid`: 目标进程 ID
///
/// # 返回值
/// 返回进程的详细信息。如果进程不存在或读取失败，返回错误。
pub fn get_process_info(pid: ProcessId) -> crate::Result<ProcessInfo> {
    // 读取进程状态文件
    let status_content = std::fs::read_to_string(format!("/proc/{}/status", pid.0))
        .map_err(|e| FridaError::NotFound {
            reason: format!("进程 {} 不存在或无权限访问: {}", pid.0, e),
        })?;

    // 解析 /proc/pid/status 中的关键字段
    let mut state = String::new();
    let mut ppid: u32 = 0;
    let mut uid: u32 = 0;

    for line in status_content.lines() {
        if line.starts_with("State:") {
            // 格式: State:  S (sleeping)
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                state = parts[1].to_string();
            }
        } else if line.starts_with("PPid:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                ppid = parts[1].parse().unwrap_or(0);
            }
        } else if line.starts_with("Uid:") {
            // 格式: Uid: 1000 1000 1000 1000
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                uid = parts[1].parse().unwrap_or(0);
            }
        }
    }

    // 读取进程名
    let name = std::fs::read_to_string(format!("/proc/{}/comm", pid.0))
        .unwrap_or_else(|_| format!("process_{}", pid.0))
        .trim()
        .to_string();

    // 读取命令行参数
    let cmdline = read_cmdline(pid)?;

    // 读取可执行文件路径（通过 readlink）
    let exe_path = std::fs::read_link(format!("/proc/{}/exe", pid.0))
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();

    // 读取工作目录（通过 readlink）
    let cwd = std::fs::read_link(format!("/proc/{}/cwd", pid.0))
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();

    Ok(ProcessInfo {
        pid,
        name,
        cmdline,
        state,
        ppid,
        uid,
        exe_path,
        cwd,
    })
}

/// 获取指定进程的所有内存映射区域
///
/// 解析 `/proc/[pid]/maps` 文件，返回完整的内存区域列表。
///
/// # 参数
/// - `pid`: 目标进程 ID
pub fn get_memory_regions(pid: ProcessId) -> crate::Result<Vec<MemoryRegion>> {
    crate::common::util::parse_proc_maps(pid)
}

/// 在指定进程中查找特定模块
///
/// 遍历目标进程的模块列表，查找名称或路径匹配的模块。
///
/// # 参数
/// - `pid`: 目标进程 ID
/// - `module_name`: 模块名称（部分匹配）
///
/// # 返回值
/// 返回第一个匹配的模块信息，未找到则返回 None。
pub fn find_module(pid: ProcessId, module_name: &str) -> crate::Result<Option<ModuleInfo>> {
    let modules = enum_modules(pid)?;

    for module in modules {
        if module.name.contains(module_name) || module.path.contains(module_name) {
            return Ok(Some(module));
        }
    }

    Ok(None)
}

/// 在指定进程中查找特定符号的地址
///
/// 在目标进程的内存映射中搜索符号名称。
/// 通过解析 `/proc/[pid]/maps` 和本地的链接器符号表来定位。
///
/// # 参数
/// - `pid`: 目标进程 ID
/// - `symbol_name`: 符号名称
///
/// # 返回值
/// 返回符号在目标进程中的地址，未找到则返回 None。
pub fn find_symbol_addr(pid: ProcessId, symbol_name: &str) -> crate::Result<Option<usize>> {
    // 查找 linkmap 中对应符号的地址
    let modules = enum_modules(pid)?;

    for module in &modules {
        if module.name.contains("libc.so") || module.name.contains("libc-") {
            // 对于 libc 等核心库，在本地查找符号偏移后计算远程地址
            if let Ok(local_path) = find_local_lib(&module.name) {
                if let Some(offset) = find_symbol_in_elf(&local_path, symbol_name) {
                    let remote_addr = module.base_addr + offset;
                    log::debug!(
                        "找到符号 {} 在 {} 中，本地偏移 {:#x}，远程地址 {:#x}",
                        symbol_name,
                        module.name,
                        offset,
                        remote_addr
                    );
                    return Ok(Some(remote_addr));
                }
            }
        }
    }

    Ok(None)
}

/// 读取进程的命令行参数
///
/// 解析 `/proc/[pid]/cmdline` 文件，该文件中参数以 null 字节分隔。
fn read_cmdline(pid: ProcessId) -> crate::Result<Vec<String>> {
    let cmdline_bytes = std::fs::read(format!("/proc/{}/cmdline", pid.0))?;

    // cmdline 中的参数以 \0 分隔
    let cmdline = cmdline_bytes
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).to_string())
        .collect();

    Ok(cmdline)
}

/// 在本地系统中查找共享库文件路径
///
/// 通过遍历常见路径来查找共享库。
fn find_local_lib(lib_name: &str) -> crate::Result<String> {
    // 常见的搜索路径
    let search_paths = [
        "/lib/x86_64-linux-gnu",
        "/lib/aarch64-linux-gnu",
        "/lib/arm-linux-gnueabihf",
        "/usr/lib/x86_64-linux-gnu",
        "/usr/lib/aarch64-linux-gnu",
        "/usr/lib/arm-linux-gnueabihf",
        "/system/lib64",
        "/system/lib",
        "/system/bin",
        "/lib",
        "/usr/lib",
    ];

    for path in &search_paths {
        let full_path = std::path::Path::new(path).join(lib_name);
        if full_path.exists() {
            return Ok(full_path.to_string_lossy().to_string());
        }
    }

    Err(FridaError::NotFound {
        reason: format!("在本地系统中找不到库 {}", lib_name),
    }
    .into())
}

/// 在 ELF 文件中查找符号的偏移地址
///
/// 使用 goblin 库解析 ELF 文件的符号表。
fn find_symbol_in_elf(elf_path: &str, symbol_name: &str) -> Option<usize> {
    let data = std::fs::read(elf_path).ok()?;

    match goblin::Object::parse(&data) {
        Ok(goblin::Object::Elf(elf)) => {
            // 遍历动态符号表（.dynsym）
            for sym in &elf.dynsyms {
                if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                    if name == symbol_name {
                        return Some(sym.st_value as usize);
                    }
                }
            }
            // 遍历常规符号表（.symtab）
            for sym in &elf.syms {
                if let Some(name) = elf.strtab.get_at(sym.st_name) {
                    if name == symbol_name {
                        return Some(sym.st_value as usize);
                    }
                }
            }
            None
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_current_process_info() {
        let pid = crate::common::util::current_process_id();
        let info = get_process_info(pid).unwrap();
        assert!(info.pid.0 > 0);
        assert!(!info.name.is_empty());
        assert!(!info.exe_path.is_empty());
    }

    #[test]
    fn test_enum_threads() {
        let pid = crate::common::util::current_process_id();
        let threads = enum_threads(pid).unwrap();
        assert!(!threads.is_empty());
    }

    #[test]
    fn test_find_process_by_name_current() {
        let pid = crate::common::util::current_process_id();
        let info = get_process_info(pid).unwrap();
        let result = find_process_by_name(&info.name).unwrap();
        assert!(result.is_some());
    }
}
