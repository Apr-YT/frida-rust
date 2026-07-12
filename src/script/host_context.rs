//! 宿主上下文模块
//!
//! 提供脚本引擎与宿主环境之间的桥梁，管理所有可供脚本调用的宿主 API。
//! 通过 HostContext 将 hook_manager、memory_scanner、process_info 等
//! 宿主能力暴露为脚本可调用的函数。

use crate::common::types::ProcessId;
use crate::hook::manager::HookManager;
#[cfg(unix)]
use crate::memory::scanner::MemoryScanner;
use crate::FridaError;
use crate::Result;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// ======================== 进程信息结构 ========================

/// 进程基本信息，供脚本通过 get_process_info() 查询
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    /// 进程 ID
    pub pid: u32,
    /// 父进程 ID
    pub ppid: u32,
    /// 进程名称
    pub name: String,
    /// 可执行文件路径
    pub exe_path: String,
    /// 当前工作目录
    pub cwd: String,
    /// 架构
    pub arch: String,
}

impl Default for ProcessInfo {
    fn default() -> Self {
        ProcessInfo {
            pid: std::process::id(),
            ppid: 0,
            name: String::new(),
            exe_path: String::new(),
            cwd: String::new(),
            arch: crate::common::types::Architecture::current().as_str().to_string(),
        }
    }
}

impl ProcessInfo {
    /// 从 /proc/self/status 和 /proc/self/cmdline 填充进程信息
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn from_proc() -> Self {
        let pid = std::process::id();

        let mut name = String::new();
        let mut ppid: u32 = 0;
        let mut exe_path = String::new();

        // 读取 /proc/self/status 获取 Name 和 PPid
        if let Ok(content) = std::fs::read_to_string("/proc/self/status") {
            for line in content.lines() {
                if line.starts_with("Name:") {
                    name = line.trim_start_matches("Name:").trim().to_string();
                } else if line.starts_with("PPid:") {
                    let ppid_str = line.trim_start_matches("PPid:").trim();
                    ppid = ppid_str.parse().unwrap_or(0);
                }
            }
        }

        // 读取可执行文件路径
        if let Ok(path) = std::fs::read_link("/proc/self/exe") {
            exe_path = path.to_string_lossy().to_string();
        }

        // 读取当前工作目录
        let cwd = std::env::current_dir()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        ProcessInfo {
            pid,
            ppid,
            name,
            exe_path,
            cwd,
            arch: crate::common::types::Architecture::current().as_str().to_string(),
        }
    }

    /// Windows 版本：从当前进程信息填充
    #[cfg(windows)]
    pub fn from_proc() -> Self {
        let pid = std::process::id();
        let name = std::env::current_exe()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
            .unwrap_or_default();
        let exe_path = std::env::current_exe()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        let cwd = std::env::current_dir()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        ProcessInfo {
            pid,
            ppid: 0,
            name,
            exe_path,
            cwd,
            arch: crate::common::types::Architecture::current().as_str().to_string(),
        }
    }
}

// ======================== API 回调类型 ========================

/// 脚本 API 函数签名类型
///
/// 每个 API 接收一个参数列表（Dynamic），返回一个 Dynamic 结果。
pub type ApiHandler =
    Box<dyn Fn(&[rhai::Dynamic]) -> Result<rhai::Dynamic> + Send + Sync>;

// ======================== 宿主上下文 ========================

/// 宿主上下文 —— 脚本引擎与宿主环境之间的桥梁
///
/// 持有 HookManager、MemoryScanner 等宿主子系统的引用，
/// 管理一个 API 注册表，供脚本引擎按名称查找和调用宿主函数。
pub struct HostContext {
    /// Hook 管理器（共享引用，允许多线程访问）
    pub hook_manager: Arc<Mutex<HookManager>>,
    /// 内存扫描器（Unix 独有）
    #[cfg(unix)]
    pub memory_scanner: Arc<MemoryScanner>,
    /// 当前进程信息
    pub process_info: ProcessInfo,
    /// API 注册表：名称 -> 处理函数
    api_registry: HashMap<String, ApiHandler>,
    /// 目标进程 PID（用于跨进程内存读写）；0 表示自身
    pub target_pid: ProcessId,
}

impl HostContext {
    /// 创建新的宿主上下文
    ///
    /// 初始化各子系统引用并注册默认 API 集合。
    pub fn new() -> Self {
        let ctx = HostContext {
            hook_manager: Arc::new(Mutex::new(HookManager::new())),
            #[cfg(unix)]
            memory_scanner: Arc::new(MemoryScanner::new(ProcessId(0))),
            process_info: ProcessInfo::from_proc(),
            api_registry: HashMap::new(),
            target_pid: ProcessId(0),
        };
        log::info!("宿主上下文初始化完成");
        ctx
    }

    /// 为指定的目标 PID 创建宿主上下文
    pub fn for_pid(pid: ProcessId) -> Self {
        let ctx = HostContext {
            hook_manager: Arc::new(Mutex::new(HookManager::new())),
            #[cfg(unix)]
            memory_scanner: Arc::new(MemoryScanner::new(pid)),
            process_info: ProcessInfo::from_proc(),
            api_registry: HashMap::new(),
            target_pid: pid,
        };
        log::info!("宿主上下文初始化完成 (目标 PID: {})", pid.0);
        ctx
    }

    /// 注册一个 API 处理函数
    ///
    /// # 参数
    /// - `name`: API 名称（脚本中通过此名称调用）
    /// - `handler`: 处理函数
    pub fn register_api<F>(&mut self, name: &str, handler: F)
    where
        F: Fn(&[rhai::Dynamic]) -> Result<rhai::Dynamic> + Send + Sync + 'static,
    {
        self.api_registry.insert(name.to_string(), Box::new(handler));
        log::debug!("注册宿主 API: {}", name);
    }

    /// 按名称执行 API
    ///
    /// 从注册表中查找指定的 API，传入参数并返回结果。
    ///
    /// # 参数
    /// - `name`: API 名称
    /// - `args`: 调用参数
    ///
    /// # 错误
    /// 如果 API 不存在或执行失败，返回错误
    pub fn execute_api(&self, name: &str, args: &[rhai::Dynamic]) -> Result<rhai::Dynamic> {
        let handler = self.api_registry.get(name).ok_or_else(|| {
            FridaError::Script {
                reason: format!("未知 API: {}", name),
            }
        })?;

        handler(args)
    }

    /// 检查指定 API 是否已注册
    pub fn has_api(&self, name: &str) -> bool {
        self.api_registry.contains_key(name)
    }

    /// 获取已注册的 API 数量
    pub fn api_count(&self) -> usize {
        self.api_registry.len()
    }

    /// 注册所有默认宿主 API
    ///
    /// 包括日志、内存操作、Hook 注册、进程查询等。
    pub fn register_default_apis(&mut self) {
        // --- 日志 API ---
        self.register_api("log_info", |args| {
            let msg = args.first().map(|a| a.clone_cast::<String>());
            log::info!("[脚本] {}", msg.as_deref().unwrap_or(""));
            Ok(rhai::Dynamic::UNIT)
        });

        self.register_api("log_warn", |args| {
            let msg = args.first().map(|a| a.clone_cast::<String>());
            log::warn!("[脚本] {}", msg.as_deref().unwrap_or(""));
            Ok(rhai::Dynamic::UNIT)
        });

        // --- 内存操作 API ---
        // read_memory: (addr: i64, size: int) -> Blob
        // 跨进程（target_pid != 0）: 通过 MemoryScanner / process_vm_readv 读取目标进程内存
        // 自身进程（target_pid == 0）: 直接指针解引用（与旧行为兼容）
        let target_pid = self.target_pid.0;
        #[cfg(unix)]
        let scanner = self.memory_scanner.clone();
        self.register_api("read_memory", move |args| {
            if args.len() < 2 {
                return Err(FridaError::Script {
                    reason: "read_memory 需要 2 个参数: addr, size".to_string(),
                }
                .into());
            }
            let addr = args[0].clone_cast::<i64>() as usize;
            let size = args[1].clone_cast::<i64>() as usize;

            if size == 0 || size > 1024 * 1024 {
                return Err(FridaError::Script {
                    reason: format!("read_memory size 无效: {}", size),
                }
                .into());
            }

            let buf = if target_pid == 0 {
                // 自身进程：直接用指针解引用（快速路径）
                let mut b = vec![0u8; size];
                unsafe {
                    std::ptr::copy_nonoverlapping(addr as *const u8, b.as_mut_ptr(), size);
                }
                b
            } else {
                // 跨进程：通过 scanner / /proc/<pid>/mem（需 root 或 ptrace）
                #[cfg(unix)]
                {
                    // 优先用 scanner（process_vm_readv）
                    match scanner.dump_region(addr as u64, size) {
                        Ok(data) => data,
                        Err(_) => {
                            // 回退：直接 /proc/<pid>/mem
                            use std::io::{Read, Seek, SeekFrom};
                            let mem_path = format!("/proc/{}/mem", target_pid);
                            let mut file = std::fs::File::open(&mem_path).map_err(|e| FridaError::MemoryRead {
                                address: addr, size,
                                reason: format!("无法打开 {}: {}", mem_path, e),
                            })?;
                            file.seek(SeekFrom::Start(addr as u64)).map_err(|e| FridaError::MemoryRead {
                                address: addr, size,
                                reason: format!("seek 失败: {}", e),
                            })?;
                            let mut b = vec![0u8; size];
                            file.read_exact(&mut b).map_err(|e| FridaError::MemoryRead {
                                address: addr, size,
                                reason: format!("读取失败: {}", e),
                            })?;
                            b
                        }
                    }
                }
                #[cfg(not(unix))]
                {
                    return Err(FridaError::Script {
                        reason: "跨进程 read_memory 仅在 Unix/Linux 上支持".to_string(),
                    }.into());
                }
            };

            let blob = rhai::Blob::from(buf);
            Ok(rhai::Dynamic::from_blob(blob))
        });

        // write_memory: (addr: i64, data: Blob) -> bool
        self.register_api("write_memory", |args| {
            if args.len() < 2 {
                return Err(FridaError::Script {
                    reason: "write_memory 需要 2 个参数: addr, data".to_string(),
                }
                .into());
            }
            let addr = args[0].clone_cast::<i64>() as usize;
            let data = args[1]
                .clone_cast::<rhai::Blob>()
                .to_vec();

            if data.is_empty() {
                return Ok(rhai::Dynamic::from_bool(true));
            }

            unsafe {
                std::ptr::copy_nonoverlapping(data.as_ptr(), addr as *mut u8, data.len());
            }
            Ok(rhai::Dynamic::from_bool(true))
        });

        // search_bytes: (pattern: Blob) -> Array
        // 注意：这是默认占位实现，返回空数组
        // engine.rs 会用真正的内存扫描实现覆盖此函数
        self.register_api("search_bytes", |_args| {
            log::warn!("[脚本] search_bytes 使用默认实现（返回空数组），请通过 engine.rs 调用");
            Ok(rhai::Dynamic::from_array(rhai::Array::new()))
        });

        // hook_function: (module: &str, symbol: &str, callback: FnPtr) -> bool
        // 注意：这是默认占位实现，仅记录日志
        // engine.rs 会用真正的 Hook 实现覆盖此函数
        self.register_api("hook_function", |_args| {
            log::warn!("[脚本] hook_function 使用默认实现（仅返回 true），请通过 engine.rs 调用");
            Ok(rhai::Dynamic::from_bool(true))
        });

        // read_module: (module: &str) -> Blob
        // 注意：这是默认占位实现，返回空 Blob
        // engine.rs 会用真正的模块读取实现覆盖此函数
        self.register_api("read_module", |_args| {
            log::warn!("[脚本] read_module 使用默认实现（返回空 Blob），请通过 engine.rs 调用");
            Ok(rhai::Dynamic::from_blob(rhai::Blob::new()))
        });

        // get_module_base: (module: &str) -> i64
        // 注意：这是默认占位实现，返回 0
        // engine.rs 会用真正的模块基址查询实现覆盖此函数
        self.register_api("get_module_base", |_args| {
            log::warn!("[脚本] get_module_base 使用默认实现（返回 0），请通过 engine.rs 调用");
            Ok(rhai::Dynamic::from_int(0))
        });

        // get_process_info: () -> Map
        self.register_api("get_process_info", |_args| {
            let info = ProcessInfo::from_proc();
            let mut map = rhai::Map::new();
            map.insert("pid".into(), rhai::Dynamic::from_int(info.pid as i64));
            map.insert("ppid".into(), rhai::Dynamic::from_int(info.ppid as i64));
            map.insert("name".into(), rhai::Dynamic::from(info.name));
            map.insert("exe_path".into(), rhai::Dynamic::from(info.exe_path));
            map.insert("cwd".into(), rhai::Dynamic::from(info.cwd));
            map.insert("arch".into(), rhai::Dynamic::from(info.arch));
            Ok(rhai::Dynamic::from_map(map))
        });

        // list_modules: () -> Array
        let list_pid = self.target_pid;
        self.register_api("list_modules", move |_args| {
            let mut arr = rhai::Array::new();
            if let Ok(regions) = crate::common::util::parse_proc_maps(list_pid) {
                // 收集唯一的模块名
                let mut seen = std::collections::HashSet::new();
                for region in regions {
                    if !region.name.is_empty() && seen.insert(region.name.clone()) {
                        let mut map = rhai::Map::new();
                        map.insert(
                            "name".into(),
                            rhai::Dynamic::from(region.name.clone()),
                        );
                        map.insert(
                            "start".into(),
                            rhai::Dynamic::from_int(region.start as i64),
                        );
                        map.insert(
                            "end".into(),
                            rhai::Dynamic::from_int(region.end as i64),
                        );
                        map.insert(
                            "size".into(),
                            rhai::Dynamic::from_int(region.size() as i64),
                        );
                        arr.push(rhai::Dynamic::from_map(map));
                    }
                }
            }
            Ok(rhai::Dynamic::from_array(arr))
        });

        // list_threads: () -> Array
        self.register_api("list_threads", |_args| {
            let mut arr = rhai::Array::new();
            let pid = std::process::id();
            // 读取 /proc/self/task/ 枚举所有线程
            let task_dir = format!("/proc/{}/task", pid);
            if let Ok(entries) = std::fs::read_dir(&task_dir) {
                for entry in entries.flatten() {
                    if let Ok(tid_str) = entry.file_name().into_string() {
                        if let Ok(tid) = tid_str.parse::<u32>() {
                            arr.push(rhai::Dynamic::from_int(tid as i64));
                        }
                    }
                }
            }
            Ok(rhai::Dynamic::from_array(arr))
        });

        log::info!("已注册 {} 个默认宿主 API", self.api_count());
    }
}

impl Default for HostContext {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_host_context_creation() {
        let ctx = HostContext::new();
        assert_eq!(ctx.api_count(), 0);
    }

    #[test]
    fn test_api_registration() {
        let mut ctx = HostContext::new();
        ctx.register_api("test_fn", |_args| {
            Ok(rhai::Dynamic::from_int(42))
        });
        assert!(ctx.has_api("test_fn"));
        assert_eq!(ctx.api_count(), 1);
    }

    #[test]
    fn test_api_execution() {
        let mut ctx = HostContext::new();
        ctx.register_api("add", |args| {
            let a = args.get(0).map(|v| v.clone_cast::<i64>()).unwrap_or(0);
            let b = args.get(1).map(|v| v.clone_cast::<i64>()).unwrap_or(0);
            Ok(rhai::Dynamic::from_int(a + b))
        });

        let result = ctx.execute_api("add", &[
            rhai::Dynamic::from_int(10),
            rhai::Dynamic::from_int(20),
        ]).unwrap();
        assert_eq!(result.as_int(), Ok(30));
    }

    #[test]
    fn test_process_info() {
        let info = ProcessInfo::from_proc();
        assert!(info.pid > 0);
        assert!(!info.arch.is_empty());
    }
}
