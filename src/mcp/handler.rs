//! MCP Server Handler - 简化版树状结构
//!
//! 24个核心工具，按功能模块组织：
//! - process/ - 进程操作
//! - memory/ - 内存操作
//! - hook/ - Hook操作
//! - stealth/ - 反检测
//! - ai/ - AI学习
//! - esp/ - ESP分析
//! - symbols/ - 符号操作
//! - script/ - 脚本执行

use rmcp::{
    ServerHandler, tool, tool_router, tool_handler,
    handler::server::wrapper::Parameters,
    ErrorData as McpError,
};
use schemars::JsonSchema;
use serde::Deserialize;
use crate::common::types::ProcessId;
use std::sync::{Mutex, OnceLock};
use std::collections::HashMap;

// 全局 HookManager
static HOOK_MANAGER: Mutex<Option<crate::hook::HookManager>> = Mutex::new(None);

// 全局 AI 学习引擎
static AI_ENGINE: Mutex<Option<crate::ai_learning::AILearningEngine>> = Mutex::new(None);

// 全局脚本引擎（按目标 PID 缓存，跨调用保留脚本作用域）
static SCRIPT_ENGINE: Mutex<Option<(ProcessId, crate::script::ScriptEngineHandle)>> = Mutex::new(None);

// 全局内存分配注册表：(pid, addr) -> size，跨调用跟踪 memory_alloc 的分配，供 memory_free 释放
static MEM_ALLOC_REGISTRY: OnceLock<Mutex<HashMap<(u32, u64), usize>>> = OnceLock::new();

fn mem_alloc_registry() -> &'static Mutex<HashMap<(u32, u64), usize>> {
    MEM_ALLOC_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

// 获取或初始化 AI 引擎
fn get_ai_engine() -> std::sync::MutexGuard<'static, Option<crate::ai_learning::AILearningEngine>> {
    let mut guard = AI_ENGINE.lock().unwrap();
    if guard.is_none() {
        *guard = Some(crate::ai_learning::AILearningEngine::new(None));
    }
    guard
}

// ======================== 参数定义 ========================

#[derive(Deserialize, JsonSchema)]
#[allow(dead_code)]
struct PidParams { pid: u32 }

#[derive(Deserialize, JsonSchema)]
#[allow(dead_code)]
struct RegionsParams { pid: u32, perm: Option<String> }

#[derive(Deserialize, JsonSchema)]
#[allow(dead_code)]
struct ProcessFindParams { name: String }

#[derive(Deserialize, JsonSchema)]
struct InjectParams { pid: u32, lib_path: String, hide: Option<bool> }

#[derive(Deserialize, JsonSchema)]
struct InjectReflectParams { pid: u32, lib_path: String }

#[derive(Deserialize, JsonSchema)]
#[allow(dead_code)]
struct HookParams { pid: u32, module: String, symbol: String, hook_type: String, offset: Option<u64> }

#[derive(Deserialize, JsonSchema)]
#[allow(dead_code)]
struct HookIdParams { id: u64 }

#[derive(Deserialize, JsonSchema)]
#[allow(dead_code)]
struct ReadMemoryParams { pid: u32, address: String, size: usize, module: Option<String>, offset: Option<String> }

#[derive(Deserialize, JsonSchema)]
#[allow(dead_code)]
struct WriteMemoryParams { pid: u32, address: String, hex_data: String, module: Option<String>, offset: Option<String> }

#[derive(Deserialize, JsonSchema)]
#[allow(dead_code)]
struct SearchParams { pid: u32, pattern: String, limit: Option<usize>, start: Option<String>, end: Option<String>, module: Option<String> }

#[derive(Deserialize, JsonSchema)]
#[allow(dead_code)]
struct SearchTextParams { pid: u32, text: String, limit: Option<usize>, start: Option<String>, end: Option<String>, wide: Option<bool>, module: Option<String> }

#[derive(Deserialize, JsonSchema)]
#[allow(dead_code)]
struct ReadStringParams { pid: u32, address: String, max_len: Option<usize>, encoding: Option<String> }

#[derive(Deserialize, JsonSchema)]
#[allow(dead_code)]
struct DisasmParams { pid: u32, address: String, count: Option<usize>, module: Option<String>, offset: Option<String> }

#[derive(Deserialize, JsonSchema)]
#[allow(dead_code)]
struct DumpParams { pid: u32, address: String, size: usize, output: Option<String>, module: Option<String>, to_hex: Option<bool> }

#[derive(Deserialize, JsonSchema)]
#[allow(dead_code)]
struct AllocParams { pid: u32, size: usize, executable: Option<bool> }

#[derive(Deserialize, JsonSchema)]
#[allow(dead_code)]
struct FreeMemoryParams { pid: u32, address: String }

#[derive(Deserialize, JsonSchema)]
#[allow(dead_code)]
struct ProtectMemoryParams { pid: u32, address: String, size: usize, perm: String }

#[derive(Deserialize, JsonSchema)]
#[allow(dead_code)]
struct WriteStringParams { pid: u32, address: String, text: String, encoding: Option<String>, null_terminated: Option<bool>, module: Option<String>, offset: Option<String> }

#[derive(Deserialize, JsonSchema)]
#[allow(dead_code)]
struct SearchValueParams { pid: u32, value: String, value_type: String, align: Option<usize>, limit: Option<usize>, start: Option<String>, end: Option<String>, module: Option<String> }

#[derive(Deserialize, JsonSchema)]
struct SymbolListParams { pid: u32, module: String }

#[derive(Deserialize, JsonSchema)]
struct SymbolFindParams { pid: u32, module: String, symbol: String }

#[derive(Deserialize, JsonSchema)]
#[allow(dead_code)]
struct ModuleParams { pid: u32, module: String }

#[derive(Deserialize, JsonSchema)]
struct StealthParams { #[allow(dead_code)] pid: u32, auto_detect: Option<bool> }

#[derive(Deserialize, JsonSchema)]
struct AILearnParams { action: String, problem: Option<String>, context: Option<String>, solution: Option<String>, success: Option<bool>, anti_cheat: Option<String> }

#[derive(Deserialize, JsonSchema)]
struct AIQueryParams { query_type: String, anti_cheat: Option<String>, #[allow(dead_code)] target: Option<String> }

#[derive(Deserialize, JsonSchema)]
struct ESPAnalyzeParams { pid: u32, template: Option<String> }

#[derive(Deserialize, JsonSchema)]
struct ESPGenerateParams { pid: u32, engine: String }

#[derive(Deserialize, JsonSchema)]
#[allow(dead_code)]
struct AndroidPackageParams { package_name: String }

#[derive(Deserialize, JsonSchema)]
#[allow(dead_code)]
struct AndroidLogcatParams { tag: Option<String>, level: Option<String>, pid: Option<u32> }

#[derive(Deserialize, JsonSchema)]
struct RunScriptParams {
    /// 目标进程 PID（可选；不传则作用于当前进程）
    #[serde(default)]
    pid: Option<u32>,
    /// Rhai 脚本源码
    script: String,
    /// 脚本文件路径（可选；与 script 二选一，文件内容自动检测加密）
    #[serde(default)]
    script_file: Option<String>,
    /// 是否重置引擎（清空作用域后重新初始化）
    #[serde(default)]
    reset: Option<bool>,
    /// 执行超时秒数（可选；默认 30 秒，防止脚本长时间占用调用）
    #[serde(default)]
    timeout: Option<u64>,
}

#[derive(Deserialize, JsonSchema)]
struct ScriptResetParams {
    /// 目标进程 PID（可选；不传则重置当前进程引擎）
    #[serde(default)]
    pid: Option<u32>,
}

#[derive(Clone)]
pub struct FridaMcpServer;

#[tool_router]
impl FridaMcpServer {

    // ==================== process/ ====================

    #[tool(description = "列出系统所有进程 (PID/名称/状态)")]
    async fn process_list(&self) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            #[cfg(unix)] {
                let procs = crate::inject::enum_processes()
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                Ok(format_process_list(&procs))
            }
            #[cfg(windows)] {
                let procs = crate::common::win_util::enum_processes_win()
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                Ok(format_process_list(&procs))
            }
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "按名称查找进程 (名称/命令行部分匹配)")]
    async fn process_find(&self, Parameters(p): Parameters<ProcessFindParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            let name = p.name.to_lowercase();
            #[cfg(unix)] {
                let procs = crate::inject::enum_processes()
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                Ok(format_process_find(&procs, &name))
            }
            #[cfg(windows)] {
                let procs = crate::common::win_util::enum_processes_win()
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                Ok(format_process_find(&procs, &name))
            }
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "暂停目标进程 (挂起所有线程)")]
    async fn process_suspend(&self, Parameters(p): Parameters<PidParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            crate::inject::suspend_process(ProcessId(p.pid))
                .map(|_| format!("已暂停进程 {}", p.pid))
                .map_err(|e| McpError::internal_error(format!("{}", e), None))
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "恢复已暂停的进程")]
    async fn process_resume(&self, Parameters(p): Parameters<PidParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            crate::inject::resume_process(ProcessId(p.pid))
                .map(|_| format!("已恢复进程 {}", p.pid))
                .map_err(|e| McpError::internal_error(format!("{}", e), None))
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "终止目标进程 (谨慎操作)")]
    async fn process_kill(&self, Parameters(p): Parameters<PidParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            crate::inject::kill_process(ProcessId(p.pid))
                .map(|_| format!("已终止进程 {}", p.pid))
                .map_err(|e| McpError::internal_error(format!("{}", e), None))
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "获取进程完整信息 (PID, 模块, 线程, 状态)")]
    async fn process_info(&self, Parameters(p): Parameters<PidParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            let mut output = String::new();

            // 1. 基本信息
            #[cfg(unix)] {
                let info = crate::inject::get_process_info(ProcessId(p.pid))
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                output.push_str(&format!("=== 进程信息 ===\n"));
                output.push_str(&format!("PID: {}\n", info.pid));
                output.push_str(&format!("名称: {}\n", info.name));
                output.push_str(&format!("路径: {}\n", info.exe_path));
                output.push_str(&format!("状态: {}\n", if info.state.is_empty() { "未知" } else { &info.state }));
                output.push_str(&format!("父进程 PID: {}\n", info.ppid));
                output.push_str(&format!("UID: {}\n", info.uid));
                if !info.cmdline.is_empty() {
                    output.push_str(&format!("命令行: {}\n", info.cmdline.join(" ")));
                }            }
            #[cfg(windows)] {
                let info = crate::inject::win_process::get_process_info(p.pid)
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                output.push_str(&format!("=== 进程信息 ===\n"));
                output.push_str(&format!("PID: {}\n", info.pid));
                output.push_str(&format!("名称: {}\n", info.name));
                output.push_str(&format!("路径: {}\n", info.exe_path));
                output.push_str(&format!("状态: {}\n", if info.state.is_empty() { "未知" } else { &info.state }));
                output.push_str(&format!("父进程 PID: {}\n", info.ppid));
                output.push_str(&format!("UID: {}\n", info.uid));
                if !info.cmdline.is_empty() {
                    output.push_str(&format!("命令行: {}\n", info.cmdline.join(" ")));
                }            }

            // 2. 模块列表
            output.push_str(&format!("\n=== 模块列表 ===\n"));
            #[cfg(unix)] {
                if let Ok(regions) = crate::common::util::parse_proc_maps(ProcessId(p.pid)) {
                    let mut modules: Vec<String> = regions.iter()
                        .filter(|r| !r.name.is_empty())
                        .map(|r| format!("  {} @ {:#x}", r.name, r.start))
                        .collect();
                    modules.dedup();
                    output.push_str(&format!("{} 个模块:\n", modules.len()));
                    for m in modules.iter().take(20) {
                        output.push_str(&format!("{}\n", m));
                    }
                    if modules.len() > 20 {
                        output.push_str(&format!("  ... 还有 {} 个\n", modules.len() - 20));
                    }
                }
            }
            #[cfg(windows)] {
                if let Ok(modules) = crate::inject::win_process::enum_modules(p.pid) {
                    output.push_str(&format!("{} 个模块:\n", modules.len()));
                    for m in modules.iter().take(20) {
                        output.push_str(&format!("  {} @ {:#x}\n", m.name, m.base_addr));
                    }
                    if modules.len() > 20 {
                        output.push_str(&format!("  ... 还有 {} 个\n", modules.len() - 20));
                    }
                }
            }

            // 3. 线程列表
            output.push_str(&format!("\n=== 线程列表 ===\n"));
            #[cfg(unix)] {
                if let Ok(threads) = crate::inject::enum_threads(ProcessId(p.pid)) {
                    output.push_str(&format!("{} 个线程:\n", threads.len()));
                    for t in threads.iter().take(10) {
                        output.push_str(&format!("  TID: {}\n", t));
                    }
                }
            }
            #[cfg(windows)] {
                if let Ok(threads) = crate::inject::win_process::enum_threads(p.pid) {
                    output.push_str(&format!("{} 个线程:\n", threads.len()));
                    for t in threads.iter().take(10) {
                        output.push_str(&format!("  TID: {}\n", t.0));
                    }
                }
            }

            Ok(output)
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "附着到目标进程")]
    async fn process_attach(&self, Parameters(p): Parameters<PidParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            crate::inject::attach_process(ProcessId(p.pid))
                .map(|_| format!("已附着到进程 {}", p.pid))
                .map_err(|e| McpError::internal_error(format!("{}", e), None))
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "注入共享库到目标进程 (hide=true 时 Windows 注入后自动隐藏模块)")]
    async fn process_inject(&self, Parameters(p): Parameters<InjectParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            #[cfg(windows)] {
                if p.hide.unwrap_or(false) {
                    use crate::inject::win_inject::WinInjector;
                    let mut injector = WinInjector::new(p.pid);
                    injector.open_target()
                        .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                    let base = injector.inject_library_hidden(&p.lib_path)
                        .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                    return Ok(format!(
                        "已注入 '{}' 到进程 {}（已隐藏模块，基址 {:#x}）",
                        p.lib_path, p.pid, base
                    ));
                }
            }
            crate::inject::inject_library(ProcessId(p.pid), &p.lib_path)
                .map(|_| format!("已注入 '{}' 到进程 {}", p.lib_path, p.pid))
                .map_err(|e| McpError::internal_error(format!("{}", e), None))
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "反射式注入 DLL 到目标进程 (Windows 专用: 不调用 LoadLibrary, 不注册到 PEB 模块链; 依赖 DLL 需已在目标进程, DllMain 不会自动调用)")]
    async fn process_inject_reflect(&self, Parameters(p): Parameters<InjectReflectParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            #[cfg(windows)] {
                use crate::inject::win_reflect::WinReflectInjector;
                let mut injector = WinReflectInjector::new(p.pid);
                injector.open_target()
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                let base = injector.inject_from_file(&p.lib_path)
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                Ok(format!(
                    "已反射注入 '{}' 到进程 {}（未注册到 PEB 模块链，基址 {:#x}）",
                    p.lib_path, p.pid, base
                ))
            }
            #[cfg(unix)] {
                Err(McpError::internal_error(
                    "process_inject_reflect 仅支持 Windows（Unix 请用 process_inject）",
                    None,
                ))
            }
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "获取目标进程内存统计 (虚拟/常驻/私有/峰值)")]
    async fn process_memory_stats(&self, Parameters(p): Parameters<PidParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            #[cfg(unix)] {
                let s = crate::inject::process::get_memory_stats(ProcessId(p.pid))
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                Ok(format_memory_stats(&s))
            }
            #[cfg(windows)] {
                let s = crate::inject::win_process::get_memory_stats(p.pid)
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                Ok(format_memory_stats(&s))
            }
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    // ==================== memory/ ====================

    #[tool(description = "读取目标进程内存 (返回十六进制)")]
    async fn memory_read(&self, Parameters(p): Parameters<ReadMemoryParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            let addr = resolve_addr(p.pid, &p.address, &p.module, &p.offset)?;
            if p.size > 0x100000 { return Err(McpError::invalid_params("最大 1MB", None)); }
            #[cfg(unix)] {
                let mut s = crate::memory::MemoryScanner::new(ProcessId(p.pid));
                let d = s.dump_region(addr as u64, p.size)
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                Ok(format_hex_dump(&d, addr))
            }
            #[cfg(windows)] {
                let s = crate::memory::win_scanner::WinMemoryScanner::new(p.pid)
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                let d = s.dump_region(addr as u64, p.size)
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                Ok(format_hex_dump(&d, addr))
            }
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "写入目标进程内存 (hex_data: 十六进制字符串)")]
    async fn memory_write(&self, Parameters(p): Parameters<WriteMemoryParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            let addr = resolve_addr(p.pid, &p.address, &p.module, &p.offset)?;
            let data = hex2bytes(&p.hex_data)?;
            #[cfg(unix)] {
                crate::common::util::safe_write_bytes(ProcessId(p.pid), addr, &data)
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
            }
            #[cfg(windows)] {
                crate::common::util::safe_write_bytes(ProcessId(p.pid), addr, &data)
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
            }
            Ok(format!("已写入 {} 字节到 {:#x}", data.len(), addr))
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "搜索内存中的字节模式 (pattern: 十六进制，支持 ?? 通配符; module: 可选限定模块; start/end: 可选范围; limit: 可选上限)")]
    async fn memory_search(&self, Parameters(p): Parameters<SearchParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            let pattern = crate::common::util::parse_hex_pattern(&p.pattern)
                .map_err(|e| McpError::invalid_params(format!("{}", e), None))?;
            let max = p.limit.or(Some(100));
            let (start, end, has_range) = match &p.module {
                Some(m) => {
                    let (s, e) = resolve_module_range(p.pid, m)?;
                    (s, e, true)
                }
                None => {
                    let s = p.start.as_deref().map(parse_hex).transpose()?.unwrap_or(0) as u64;
                    let e = p.end.as_deref().map(parse_hex).transpose()?.unwrap_or(usize::MAX) as u64;
                    (s, e, p.start.is_some() || p.end.is_some())
                }
            };
            run_memory_search(p.pid, &pattern, max, has_range, start, end, None)
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "按文本字符串搜索内存 (wide=true 按 UTF-16LE 搜索; module: 可选限定模块; start/end/limit 可选)")]
    async fn memory_search_text(&self, Parameters(p): Parameters<SearchTextParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            let pattern: Vec<Option<u8>> = if p.wide.unwrap_or(false) {
                p.text
                    .encode_utf16()
                    .flat_map(|u| u.to_le_bytes())
                    .map(Some)
                    .collect()
            } else {
                p.text.as_bytes().iter().map(|b| Some(*b)).collect()
            };
            if pattern.is_empty() {
                return Err(McpError::invalid_params("文本为空", None));
            }
            let max = p.limit.or(Some(100));
            let (start, end, has_range) = match &p.module {
                Some(m) => {
                    let (s, e) = resolve_module_range(p.pid, m)?;
                    (s, e, true)
                }
                None => {
                    let s = p.start.as_deref().map(parse_hex).transpose()?.unwrap_or(0) as u64;
                    let e = p.end.as_deref().map(parse_hex).transpose()?.unwrap_or(usize::MAX) as u64;
                    (s, e, p.start.is_some() || p.end.is_some())
                }
            };
            run_memory_search(p.pid, &pattern, max, has_range, start, end, None)
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "按数值扫描内存 (value: 数值或 0x十六进制; value_type: u8/i8/u16/i16/u32/i32/u64/i64/f32/f64; align: 可选对齐字节; module/start/end/limit 可选)")]
    async fn memory_search_value(&self, Parameters(p): Parameters<SearchValueParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            let pattern = parse_value_pattern(&p.value, &p.value_type)?;
            if pattern.is_empty() {
                return Err(McpError::invalid_params("数值无法编码为字节", None));
            }
            let max = p.limit.or(Some(100));
            let align = p.align;
            let (start, end, has_range) = match &p.module {
                Some(m) => {
                    let (s, e) = resolve_module_range(p.pid, m)?;
                    (s, e, true)
                }
                None => {
                    let s = p.start.as_deref().map(parse_hex).transpose()?.unwrap_or(0) as u64;
                    let e = p.end.as_deref().map(parse_hex).transpose()?.unwrap_or(usize::MAX) as u64;
                    (s, e, p.start.is_some() || p.end.is_some())
                }
            };
            run_memory_search(p.pid, &pattern, max, has_range, start, end, align)
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "读取内存中的字符串 (encoding: utf8/ascii/utf16，默认 utf8)")]
    async fn memory_read_string(&self, Parameters(p): Parameters<ReadStringParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            let addr = parse_hex(&p.address)?;
            let max_len = p.max_len.unwrap_or(256).min(4096);
            let encoding = p.encoding.as_deref().unwrap_or("utf8").to_ascii_lowercase();
            #[cfg(unix)] {
                let mut s = crate::memory::MemoryScanner::new(ProcessId(p.pid));
                let data = s.dump_region(addr as u64, max_len)
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                Ok(format_string_result(addr, &encoding, &data))
            }
            #[cfg(windows)] {
                let s = crate::memory::win_scanner::WinMemoryScanner::new(p.pid)
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                let data = s.dump_region(addr as u64, max_len)
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                Ok(format_string_result(addr, &encoding, &data))
            }
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "反汇编指定地址的代码")]
    async fn memory_disasm(&self, Parameters(p): Parameters<DisasmParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            let addr = resolve_addr(p.pid, &p.address, &p.module, &p.offset)?;
            let count = p.count.unwrap_or(20).min(100);
            #[cfg(unix)] {
                let mut s = crate::memory::MemoryScanner::new(ProcessId(p.pid));
                let bytes = s.dump_region(addr as u64, count * 8)
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                Ok(format_disassembly(&bytes, addr, count))
            }
            #[cfg(windows)] {
                let s = crate::memory::win_scanner::WinMemoryScanner::new(p.pid)
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                let bytes = s.dump_region(addr as u64, count * 8)
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                Ok(format_disassembly(&bytes, addr, count))
            }
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "dump内存区域到文件 (module: 可选模块名，从模块基址开始 dump)")]
    async fn memory_dump(&self, Parameters(p): Parameters<DumpParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            let addr = match &p.module {
                Some(m) => resolve_module_base(p.pid, m)?,
                None => parse_hex(&p.address)?,
            };
            if p.size > 0x10000000 { return Err(McpError::invalid_params("最大 256MB", None)); }
            #[cfg(unix)] {
                let mut s = crate::memory::MemoryScanner::new(ProcessId(p.pid));
                let data = s.dump_region(addr as u64, p.size)
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                if p.to_hex.unwrap_or(false) {
                    return Ok(format_hex_dump(&data, addr));
                }
                let path = p.output.unwrap_or_else(|| format!("dump_{:#x}.bin", addr));
                std::fs::write(&path, &data)
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                Ok(format!("已dump {} 字节到 {}", data.len(), path))
            }
            #[cfg(windows)] {
                let s = crate::memory::win_scanner::WinMemoryScanner::new(p.pid)
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                let data = s.dump_region(addr as u64, p.size)
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                if p.to_hex.unwrap_or(false) {
                    return Ok(format_hex_dump(&data, addr));
                }
                let path = p.output.unwrap_or_else(|| format!("dump_{:#x}.bin", addr));
                std::fs::write(&path, &data)
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                Ok(format!("已dump {} 字节到 {}", data.len(), path))
            }
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "列出目标进程内存区域 (地址范围/权限/大小; perm: 可选过滤, 如 \"rwx\"/\"r\"/\"x\", 缺省列出全部)")]
    async fn memory_regions(&self, Parameters(p): Parameters<RegionsParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            let perm = p
                .perm
                .as_deref()
                .map(|s| s.to_lowercase())
                .filter(|s| !s.is_empty());
            #[cfg(unix)] {
                let mut s = crate::memory::MemoryScanner::new(ProcessId(p.pid));
                let regions = s.regions()
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?
                    .to_vec();
                let filtered: Vec<crate::common::types::MemoryRegion> = match &perm {
                    Some(pf) => filter_regions_by_perm(&regions, pf).into_iter().cloned().collect(),
                    None => regions,
                };
                Ok(format_regions(&filtered))
            }
            #[cfg(windows)] {
                let s = crate::memory::win_scanner::WinMemoryScanner::new(p.pid)
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                let regions = s.parse_regions()
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                let filtered: Vec<crate::common::types::MemoryRegion> = match &perm {
                    Some(pf) => filter_regions_by_perm(&regions, pf).into_iter().cloned().collect(),
                    None => regions,
                };
                Ok(format_regions(&filtered))
            }
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    // ==================== memory/ (分配管理) ====================

    #[tool(description = "在目标进程分配内存 (size: 字节; executable: 可选，是否可执行)")]
    async fn memory_alloc(&self, Parameters(p): Parameters<AllocParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            if p.size == 0 || p.size > 0x10000000 {
                return Err(McpError::invalid_params("大小须在 1..=256MB", None));
            }
            let exec = p.executable.unwrap_or(false);
            #[cfg(unix)] {
                let mut a = crate::memory::RemoteAllocator::new(ProcessId(p.pid));
                let addr = a.alloc(p.size, exec)
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                mem_alloc_registry().lock().unwrap().insert((p.pid, addr), p.size);
                Ok(format!("已分配 {} 字节 @ {:#x} (exec={})", p.size, addr, exec))
            }
            #[cfg(windows)] {
                let a = crate::memory::WinRemoteAllocator::new(p.pid)
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                let addr = a.alloc(p.size, exec)
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                mem_alloc_registry().lock().unwrap().insert((p.pid, addr), p.size);
                Ok(format!("已分配 {} 字节 @ {:#x} (exec={})", p.size, addr, exec))
            }
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "释放目标进程中已分配的内存 (address: memory_alloc 返回的地址)")]
    async fn memory_free(&self, Parameters(p): Parameters<FreeMemoryParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            let addr = parse_hex(&p.address)? as u64;
            #[cfg(unix)] {
                let size = mem_alloc_registry().lock().unwrap().remove(&(p.pid, addr));
                let mut a = crate::memory::RemoteAllocator::new(ProcessId(p.pid));
                let sz = size.ok_or_else(|| {
                    McpError::invalid_params("地址不在分配注册表中，无法确定释放大小", None)
                })?;
                a.free_remote(addr, sz)
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                Ok(format!("已释放内存 @ {:#x}", addr))
            }
            #[cfg(windows)] {
                let _ = mem_alloc_registry().lock().unwrap().remove(&(p.pid, addr));
                let a = crate::memory::WinRemoteAllocator::new(p.pid)
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                a.free(addr)
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                Ok(format!("已释放内存 @ {:#x}", addr))
            }
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "修改目标进程内存页保护属性 (perm: r/w/x 组合，如 rw/rx/rwx)")]
    async fn memory_protect(&self, Parameters(p): Parameters<ProtectMemoryParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            let addr = parse_hex(&p.address)? as u64;
            let perm = p.perm.to_ascii_lowercase();
            if perm.is_empty() || perm.chars().any(|c| !"rwx".contains(c)) {
                return Err(McpError::invalid_params("perm 仅支持 r/w/x 组合", None));
            }
            if p.size == 0 || p.size > 0x10000000 {
                return Err(McpError::invalid_params("大小须在 1..=256MB", None));
            }
            #[cfg(unix)] {
                let mut prot = 0i32;
                if perm.contains('r') { prot |= libc::PROT_READ; }
                if perm.contains('w') { prot |= libc::PROT_WRITE; }
                if perm.contains('x') { prot |= libc::PROT_EXEC; }
                let a = crate::memory::RemoteAllocator::new(ProcessId(p.pid));
                a.protect(addr, p.size, prot)
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                Ok(format!("已设置 {:#x} 保护为 '{}'", addr, perm))
            }
            #[cfg(windows)] {
                let a = crate::memory::WinRemoteAllocator::new(p.pid)
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                a.protect_perms(addr, p.size, &perm)
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                Ok(format!("已设置 {:#x} 保护为 '{}'", addr, perm))
            }
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "写入字符串到目标进程内存 (encoding: utf8/ascii/utf16; null_terminated: 默认 true)")]
    async fn memory_write_string(&self, Parameters(p): Parameters<WriteStringParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            let addr = resolve_addr(p.pid, &p.address, &p.module, &p.offset)?;
            let encoding = p.encoding.as_deref().unwrap_or("utf8").to_ascii_lowercase();
            let null_term = p.null_terminated.unwrap_or(true);
            let data = encode_string_bytes(&p.text, &encoding, null_term)
                .map_err(|e| McpError::invalid_params(e, None))?;
            crate::common::util::safe_write_bytes(ProcessId(p.pid), addr, &data)
                .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
            Ok(format!("已写入字符串 ({} 字节, {}) 到 {:#x}", data.len(), encoding, addr))
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    // ==================== hook/ ====================

    #[tool(description = "设置函数Hook (hook_type: inline/got_plt/java; offset: 可选模块内偏移)")]
    async fn hook_set(&self, Parameters(p): Parameters<HookParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            let ht = match p.hook_type.as_str() {
                "inline" => crate::common::types::HookType::Inline,
                "got_plt" => crate::common::types::HookType::GotPlt,
                "java" => crate::common::types::HookType::Java,
                _ => return Err(McpError::invalid_params("类型: inline/got_plt/java", None)),
            };
            let mut guard = HOOK_MANAGER.lock()
                .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
            if guard.is_none() { *guard = Some(crate::hook::HookManager::new()); }
            let mgr = guard.as_mut().ok_or_else(|| McpError::internal_error("HookManager not initialized", None))?;
            let point = crate::common::types::HookPoint {
                module: p.module,
                symbol: p.symbol.clone(),
                offset: p.offset.unwrap_or(0) as usize,
                hook_type: ht,
            };
            let id = mgr.register_hook(point, |_| {})
                .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
            mgr.install_hook(id)
                .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
            Ok(format!("已Hook {} ({}) (id: {})", p.symbol, p.hook_type, id.as_u64()))
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "卸载已安装的 Hook (id: hook_set 返回的 Hook id)")]
    async fn hook_uninstall(&self, Parameters(p): Parameters<HookIdParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            let mut guard = HOOK_MANAGER.lock()
                .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
            let mgr = guard.as_mut().ok_or_else(|| McpError::internal_error("HookManager not initialized", None))?;
            mgr.uninstall_hook(crate::hook::HookId::new(p.id))
                .map(|_| format!("已卸载 Hook #{}", p.id))
                .map_err(|e| McpError::internal_error(format!("{}", e), None))
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "列出已注册的 Hook (id/状态/目标)")]
    async fn hook_list(&self) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            let guard = HOOK_MANAGER.lock()
                .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
            if guard.is_none() {
                return Ok("暂无 Hook".to_string());
            }
            let mgr = guard.as_ref().ok_or_else(|| McpError::internal_error("HookManager not initialized", None))?;
            let hooks = mgr.list_hooks();
            if hooks.is_empty() {
                return Ok("暂无 Hook".to_string());
            }
            let mut out = format!("共 {} 个 Hook:\n", hooks.len());
            for (i, (id, active, point)) in hooks.iter().enumerate() {
                out.push_str(&format!(
                    "  [{}] id={} {}\n      {}\n",
                    i,
                    id.as_u64(),
                    if *active { "已安装" } else { "未安装" },
                    point
                ));
            }
            Ok(out)
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    // ==================== stealth/ ====================

    #[tool(description = "应用反检测措施 (pid: 目标进程, 传0表示自身; auto_detect=true 自动分析并应用)")]
    async fn stealth_apply(&self, Parameters(p): Parameters<StealthParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            let self_pid = crate::common::util::current_process_id().0;
            let target_is_self = p.pid == 0 || p.pid == self_pid;
            if p.auto_detect.unwrap_or(true) {
                #[cfg(unix)] {
                    if target_is_self {
                        use crate::anti_detect::SmartStealth;
                        let mut smart = SmartStealth::new(ProcessId(p.pid));
                        smart.scan()
                            .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                        let report = smart.report();
                        smart.apply_recommended()
                            .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                        return Ok(format!("智能反检测已应用\n\n{}", report));
                    }
                }
                #[cfg(windows)] {
                    let analysis = analyze_windows_stealth(p.pid, target_is_self);
                    let applied = apply_windows_stealth(p.pid, target_is_self)?;
                    return Ok(format!("智能反检测已应用（{}）\n\n{}", applied, analysis));
                }
            }
            #[cfg(unix)] {
                if !target_is_self {
                    // Unix 无跨进程清理手段：目标进程仅做只读分析，避免误作用到自身
                    return Ok(format!(
                        "目标进程 {} 仅支持只读分析（Unix 跨进程清理暂不支持）\n\n{}",
                        p.pid,
                        analyze_unix_stealth(p.pid)
                    ));
                }
                crate::anti_detect::apply_stealth()
                    .map(|_| "反检测已应用（自身进程）".to_string())
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))
            }
            #[cfg(windows)] {
                apply_windows_stealth(p.pid, target_is_self)
            }
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "分析目标进程的反调试技术")]
    async fn stealth_analyze(&self, Parameters(_p): Parameters<PidParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            let mut output = String::from("=== 反调试分析 ===\n\n");

            #[cfg(unix)] {
                use crate::anti_detect::SmartStealth;
                let mut smart = SmartStealth::new(ProcessId(_p.pid));
                smart.scan()
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                output.push_str(&smart.report());
                output.push_str("\n");
                output.push_str(&analyze_unix_stealth(_p.pid));
            }

            #[cfg(windows)] {
                let self_pid = crate::common::util::current_process_id().0;
                let target_is_self = _p.pid == 0 || _p.pid == self_pid;
                output.push_str(&analyze_windows_stealth(_p.pid, target_is_self));
            }

            Ok(output)
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "查看反检测模块列表和知识库")]
    async fn stealth_info(&self) -> Result<String, McpError> {
        let mut output = String::from("=== 反检测模块 ===\n\n");
        output.push_str("模块列表:\n");
        output.push_str("  - env_clean    环境变量清理\n");
        output.push_str("  - signature    特征字符串擦除\n");
        output.push_str("  - tracer       TracerPid隐藏\n");
        output.push_str("  - maps_hide    Maps隐藏\n");
        output.push_str("  - fd_hide      FD隐藏\n");
        output.push_str("  - thread_hide  线程隐藏\n");
        output.push_str("  - port_hide    端口隐藏\n");
        output.push_str("  - net_hide     网络隐藏\n");
        output.push_str("  - stack_fake   调用栈伪造\n\n");
        output.push_str("说明:\n");
        output.push_str("  提供跨进程 PEB/堆标志清理等反调试手段，不承诺绕过具体商业反作弊\n");
        output.push_str("  Windows: stealth_apply(pid=目标) 跨进程清理; stealth_analyze 检测 DebugPort/时间差等\n");
        output.push_str("  注意: 商业反作弊多为内核级检测，用户态手段存在被识别风险\n");
        Ok(output)
    }

    // ==================== ai/ ====================

    #[tool(description = "AI学习 - 记录经验/反馈问题/获取建议 (action: report/record/recommend/stats)")]
    async fn ai_learn(&self, Parameters(p): Parameters<AILearnParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            let mut engine = get_ai_engine();
            let engine = engine.as_mut().unwrap();

            match p.action.as_str() {
                "report" => {
                    // 记录失败经验
                    let action_type = match p.context.as_deref() {
                        Some(ctx) if ctx.contains("hook") => crate::ai_learning::ActionType::Hook,
                        Some(ctx) if ctx.contains("inject") => crate::ai_learning::ActionType::Inject,
                        Some(ctx) if ctx.contains("stealth") => crate::ai_learning::ActionType::StealthApply,
                        _ => crate::ai_learning::ActionType::Hook,
                    };

                    engine.record_operation(crate::ai_learning::OperationResult {
                        id: String::new(),
                        timestamp: 0,
                        action: action_type,
                        target_pid: 0,
                        target_name: p.context.unwrap_or_default(),
                        anti_cheat: None,
                        success: p.success.unwrap_or(false),
                        error: p.problem.clone(),
                        strategy: Vec::new(),
                        duration_ms: 0,
                        metadata: HashMap::new(),
                    });

                    Ok(format!("✅ 问题已记录并学习\n\n问题: {}\n解决方案: {}", 
                        p.problem.unwrap_or_default(),
                        p.solution.unwrap_or_else(|| "待解决".to_string())
                    ))
                }
                "record" => {
                    // 记录成功经验
                    engine.record_operation(crate::ai_learning::OperationResult {
                        id: String::new(),
                        timestamp: 0,
                        action: crate::ai_learning::ActionType::Hook,
                        target_pid: 0,
                        target_name: p.context.unwrap_or_default(),
                        anti_cheat: None,
                        success: true,
                        error: None,
                        strategy: vec![p.solution.unwrap_or_default()],
                        duration_ms: 0,
                        metadata: HashMap::new(),
                    });
                    Ok("✅ 成功经验已记录".to_string())
                }
                "recommend" => {
                    // 获取策略推荐
                    let strategies = engine.recommend_strategy(
                        &crate::ai_learning::ActionType::Hook,
                        p.anti_cheat.as_deref()
                    );
                    let mut output = String::from("🎯 推荐策略:\n\n");
                    for (i, s) in strategies.iter().take(3).enumerate() {
                        output.push_str(&format!("{}. {} (成功率: {:.0}%)\n", 
                            i + 1, s.name, s.success_rate * 100.0));
                    }
                    Ok(output)
                }
                "stats" => {
                    Ok(engine.report())
                }
                _ => Err(McpError::invalid_params("action: report/record/recommend/stats", None))
            }
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "AI查询 - 查询知识库/经验/策略 (type: knowledge/strategy/stats)")]
    async fn ai_query(&self, Parameters(p): Parameters<AIQueryParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            let engine = get_ai_engine();
            let engine = engine.as_ref().unwrap();

            match p.query_type.as_str() {
                "knowledge" => {
                    if let Some(ref ac) = p.anti_cheat {
                        let report = engine.query_knowledge(ac);
                        let mut output = format!("=== {} 知识图谱 ===\n\n", ac);
                        output.push_str(&format!("置信度: {:.0}%\n\n", report.confidence * 100.0));
                        output.push_str("检测方法:\n");
                        for m in &report.detection_methods { output.push_str(&format!("  - {}\n", m)); }
                        output.push_str("\n绕过方法:\n");
                        for m in &report.bypass_methods { output.push_str(&format!("  - {}\n", m)); }
                        if !report.related_games.is_empty() {
                            output.push_str("\n相关游戏:\n");
                            for g in &report.related_games { output.push_str(&format!("  - {}\n", g)); }
                        }
                        return Ok(output);
                    }
                    Ok("请指定 anti_cheat 参数".to_string())
                }
                "strategy" => {
                    let strategies = engine.recommend_strategy(
                        &crate::ai_learning::ActionType::Hook,
                        p.anti_cheat.as_deref()
                    );
                    let mut output = String::from("=== 推荐策略 ===\n\n");
                    for (i, s) in strategies.iter().take(5).enumerate() {
                        output.push_str(&format!("{}. {}\n", i + 1, s.name));
                        output.push_str(&format!("   成功率: {:.0}%, 使用: {}次\n", 
                            s.success_rate * 100.0, s.usage_count));
                    }
                    Ok(output)
                }
                "stats" => Ok(engine.report()),
                _ => Err(McpError::invalid_params("type: knowledge/strategy/stats", None))
            }
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    // ==================== esp/ ====================

    #[tool(description = "分析游戏 (自动检测引擎、分析结构)")]
    async fn esp_analyze(&self, Parameters(p): Parameters<ESPAnalyzeParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            use crate::esp_analyzer::ESPAnalyzer;
            let mut analyzer = ESPAnalyzer::new(ProcessId(p.pid));
            let engine = analyzer.detect_engine()
                .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
            let report = analyzer.report();

            let mut output = format!("=== ESP 分析 ===\n\n引擎: {:?}\n\n{}", engine, report);

            // 加载模板（如果有）
            if let Some(ref template_name) = p.template {
                use crate::esp_analyzer;
                let templates = esp_analyzer::builtin_templates();
                if let Some(t) = templates.iter().find(|t| t.game_name.to_lowercase().contains(&template_name.to_lowercase())) {
                    output.push_str(&format!("\n=== 游戏模板 ===\n"));
                    output.push_str(&format!("游戏: {}\n", t.game_name));
                    output.push_str(&format!("进程: {}\n", t.process_name));
                }
            }

            Ok(output)
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "生成ESP代码 (engine: unreal/unity/source)")]
    async fn esp_generate(&self, Parameters(p): Parameters<ESPGenerateParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            use crate::esp_analyzer::{ESPAnalyzer, GameEngine};
            let analyzer = ESPAnalyzer::new(ProcessId(p.pid));
            let engine = match p.engine.to_lowercase().as_str() {
                "unreal" | "ue4" | "ue5" => GameEngine::UnrealEngine,
                "unity" => GameEngine::Unity,
                "source" => GameEngine::Source,
                _ => GameEngine::Custom(p.engine.clone()),
            };
            let code = analyzer.generate_esp_code(&engine);
            Ok(format!("=== ESP 代码 ({:?}) ===\n\n{}", engine, code))
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    // ==================== android/ (adb 直连) ====================

    #[tool(description = "列出已连接的 Android 设备 (adb devices)")]
    async fn device_list(&self) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            use crate::android::adb::list_devices;
            let devices = list_devices()
                .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
            if devices.is_empty() {
                return Ok("未检测到 adb 设备(请检查 USB 调试连接 / adb devices)".to_string());
            }
            let mut out = format!("=== adb 设备 ({}) ===\n\n", devices.len());
            for d in &devices {
                out.push_str(&format!("{} [{}]\n", d.display_name(), d.state));
                if d.is_online() {
                    out.push_str(&format!("  serial: {}\n", d.serial));
                    if !d.product.is_empty() {
                        out.push_str(&format!("  product: {}\n", d.product));
                    }
                    if d.transport_id != 0 {
                        out.push_str(&format!("  transport_id: {}\n", d.transport_id));
                    }
                }
                out.push('\n');
            }
            Ok(out)
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "列出设备上运行中的 Android 应用进程 (自动选择设备, adb 直连)")]
    async fn android_processes(&self) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            use crate::android::device::DeviceClient;
            let client = DeviceClient::auto()
                .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
            let procs = client
                .process_list()
                .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
            // 应用进程名通常含点(包名),借此与系统进程区分
            let apps: Vec<_> = procs.iter().filter(|p| p.name.contains('.')).collect();
            let mut out = format!(
                "=== {} 运行中的应用进程 ({}) ===\n\n",
                client.serial,
                apps.len()
            );
            for p in apps.iter().take(100) {
                out.push_str(&format!("{}  {}\n", p.pid, p.name));
            }
            if apps.len() > 100 {
                out.push_str(&format!("\n... 还有 {} 个", apps.len() - 100));
            }
            Ok(out)
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "按包名/进程名查找 PID (自动选择设备, adb 直连)")]
    async fn android_find_pid(
        &self,
        Parameters(p): Parameters<AndroidPackageParams>,
    ) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            use crate::android::device::DeviceClient;
            let client = DeviceClient::auto()
                .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
            let pids = client
                .find_pid(&p.package_name)
                .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
            if pids.is_empty() {
                Ok(format!("未找到包名 '{}' 的进程", p.package_name))
            } else {
                let mut out = format!("包名 '{}' 的进程:\n", p.package_name);
                for pid in pids {
                    out.push_str(&format!("  PID: {}\n", pid));
                }
                Ok(out)
            }
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "列出设备上已安装的第三方应用包 (自动选择设备, pm list packages -3)")]
    async fn android_packages(&self) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            use crate::android::device::DeviceClient;
            let client = DeviceClient::auto()
                .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
            let pkgs = client
                .package_list()
                .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
            let mut out = format!(
                "=== {} 已安装第三方包 ({}) ===\n\n",
                client.serial,
                pkgs.len()
            );
            for p in &pkgs {
                out.push_str(&format!("{}\n", p));
            }
            Ok(out)
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "获取设备 logcat 日志快照 (自动选择设备; tag/level/pid 可选)")]
    async fn android_logcat(
        &self,
        Parameters(p): Parameters<AndroidLogcatParams>,
    ) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            use crate::android::device::DeviceClient;
            let client = DeviceClient::auto()
                .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
            let entries = client
                .logcat_snapshot(p.tag.as_deref(), p.level.as_deref(), p.pid)
                .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
            let mut out = format!("=== Logcat 快照 ({}) ===\n\n", entries.len());
            for line in entries.iter().take(100) {
                out.push_str(line);
                out.push('\n');
            }
            if entries.len() > 100 {
                out.push_str(&format!("\n... 还有 {} 条", entries.len() - 100));
            }
            Ok(out)
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    // ==================== symbols/ ====================

    #[tool(description = "查询模块基址与大小")]
    async fn module_info(&self, Parameters(p): Parameters<ModuleParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            #[cfg(unix)] {
                use crate::common::util::parse_proc_maps;
                let regions = parse_proc_maps(ProcessId(p.pid))
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                let matches: Vec<&crate::common::types::MemoryRegion> = regions
                    .iter()
                    .filter(|r| !r.name.is_empty() && r.name.contains(&p.module))
                    .collect();
                if matches.is_empty() {
                    return Err(McpError::invalid_params(format!("找不到模块 '{}'", p.module), None));
                }
                let r = matches[0];
                Ok(format!(
                    "模块: {}\n基址: {:#x}\n大小: {} bytes ({:#x})\n",
                    r.name,
                    r.start,
                    r.size(),
                    r.size()
                ))
            }
            #[cfg(windows)] {
                let modules = crate::inject::win_process::enum_modules(p.pid)
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                let name_lower = p.module.to_lowercase();
                let matches: Vec<&crate::common::types::ModuleInfo> = modules
                    .iter()
                    .filter(|m| m.name.to_lowercase().contains(&name_lower))
                    .collect();
                if matches.is_empty() {
                    return Err(McpError::invalid_params(format!("找不到模块 '{}'", p.module), None));
                }
                let m = matches[0];
                Ok(format!(
                    "模块: {}\n基址: {:#x}\n大小: {} bytes\n路径: {}\n",
                    m.name, m.base_addr, m.size, m.path
                ))
            }
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "列出目标进程所有模块 (名称/基址/大小/路径)")]
    async fn module_list(&self, Parameters(p): Parameters<PidParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            #[cfg(unix)] {
                let modules = crate::inject::process::enum_modules(ProcessId(p.pid))
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                Ok(format_module_list(&modules))
            }
            #[cfg(windows)] {
                let modules = crate::inject::win_process::enum_modules(p.pid)
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                Ok(format_module_list(&modules))
            }
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "隐藏目标进程中的模块 (Windows: 从 PEB Ldr 链摘除, 使其对模块枚举/GetModuleHandle 不可见; Unix: 不支持, 可用 stealth 模块替代)")]
    async fn module_hide(&self, Parameters(p): Parameters<ModuleParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            #[cfg(windows)] {
                use crate::anti_detect::win_hide::WinStealthManager;
                WinStealthManager::hide_remote_module(p.pid, &p.module)
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))
            }
            #[cfg(unix)] {
                Err(McpError::internal_error(
                    "module_hide 仅支持 Windows（Unix 可用 maps_hide/stealth 隐藏映射）",
                    None,
                ))
            }
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "列出模块的符号")]
    async fn symbols_list(&self, Parameters(p): Parameters<SymbolListParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            #[cfg(unix)] {
                use crate::memory::elf_parser;
                use crate::common::util::parse_proc_maps;
                let regions = parse_proc_maps(ProcessId(p.pid))
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                let module = regions.iter()
                    .find(|r| r.name.contains(&p.module))
                    .ok_or_else(|| McpError::invalid_params("找不到模块", None))?;
                let elf = elf_parser::parse_elf_from_memory(ProcessId(p.pid), module.start as u64)
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                let symbols = elf_parser::get_exported_symbols(&elf);
                let mut output = format!("{} 个导出符号:\n", symbols.len());
                for s in symbols.iter().take(50) {
                    output.push_str(&format!("  {:#x} {}\n", s.value, s.name));
                }
                Ok(output)
            }
            #[cfg(windows)] {
                use crate::memory::pe_parser::PeParser;
                let mut parser = PeParser::new(p.pid);
                parser.parse_module(&p.module)
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                let symbols = parser.list_symbols(&p.module)
                    .ok_or_else(|| McpError::invalid_params("找不到模块", None))?;
                let mut output = format!("{} 个导出符号:\n", symbols.len());
                for s in symbols.iter().take(50) {
                    output.push_str(&format!("  {:#x} {} (ordinal: {})\n", s.address, s.name, s.ordinal));
                }
                Ok(output)
            }
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "查找符号地址")]
    async fn symbols_find(&self, Parameters(p): Parameters<SymbolFindParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            #[cfg(unix)] {
                use crate::memory::elf_parser;
                use crate::common::util::parse_proc_maps;
                let regions = parse_proc_maps(ProcessId(p.pid))
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                let module = regions.iter()
                    .find(|r| r.name.contains(&p.module))
                    .ok_or_else(|| McpError::invalid_params("找不到模块", None))?;
                let elf = elf_parser::parse_elf_from_memory(ProcessId(p.pid), module.start as u64)
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                let symbols = elf_parser::find_symbols_by_name(&elf, &p.symbol);
                if symbols.is_empty() { return Err(McpError::invalid_params("找不到符号", None)); }
                let mut output = format!("找到 {} 个匹配:\n", symbols.len());
                for s in &symbols {
                    output.push_str(&format!("  {} @ {:#x}\n", s.name, s.value));
                }
                Ok(output)
            }
            #[cfg(windows)] {
                use crate::memory::pe_parser::PeParser;
                let mut parser = PeParser::new(p.pid);
                parser.parse_module(&p.module)
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                let symbols = parser.list_symbols(&p.module)
                    .ok_or_else(|| McpError::invalid_params("找不到模块", None))?;
                let name_lower = p.symbol.to_lowercase();
                let matches: Vec<&crate::memory::pe_parser::PeSymbol> = symbols
                    .iter()
                    .filter(|s| s.name.to_lowercase().contains(&name_lower))
                    .collect();
                if matches.is_empty() {
                    return Err(McpError::invalid_params("找不到符号", None));
                }
                let mut output = format!("找到 {} 个匹配:\n", matches.len());
                for s in matches.iter().take(50) {
                    output.push_str(&format!(
                        "  {} @ {:#x} (ordinal: {})\n",
                        s.name, s.address, s.ordinal
                    ));
                }
                if matches.len() > 50 {
                    output.push_str(&format!("  ... 还有 {} 个\n", matches.len() - 50));
                }
                Ok(output)
            }
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    // ==================== script/ ====================

    #[tool(description = "执行 Rhai 脚本 (script: Rhai 源码 或 script_file: 脚本文件路径; pid: 可选目标进程; reset: 可选重置引擎; timeout: 可选超时秒数, 默认 30)")]
    async fn run_script(&self, Parameters(p): Parameters<RunScriptParams>) -> Result<String, McpError> {
        let timeout_secs = p.timeout.unwrap_or(30);
        let future = tokio::task::spawn_blocking(move || {
            if p.script_file.is_none() && p.script.trim().is_empty() {
                return Err(McpError::invalid_params("script 与 script_file 至少提供一个", None));
            }
            let handle = get_script_engine(p.pid, p.reset.unwrap_or(false))?;
            let result = if let Some(path) = p.script_file {
                handle.execute_file(&path)
            } else {
                handle.execute_text(&p.script)
            }
            .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
            let mut output = format!("返回值: {}\n", result.value);
            if !result.logs.is_empty() {
                output.push_str("脚本日志:\n");
                for line in &result.logs {
                    output.push_str(&format!("  {}\n", line));
                }
            }
            Ok(output)
        });
        match tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), future).await {
            Ok(Ok(res)) => res,
            Ok(Err(e)) => Err(McpError::internal_error(format!("{}", e), None)),
            Err(_) => Err(McpError::internal_error(
                format!("脚本执行超时（{} 秒），已放弃等待", timeout_secs),
                None,
            )),
        }
    }

    #[tool(description = "重置脚本引擎 (pid: 可选目标进程；重置后脚本作用域清空)")]
    async fn script_reset(&self, Parameters(p): Parameters<ScriptResetParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            get_script_engine(p.pid, true)?;
            Ok(format!("脚本引擎已重置 (PID: {})", p.pid.unwrap_or(0)))
        })
        .await
        .map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }
}

#[tool_handler(
    name = "frida-rust-mcp",
    version = "0.35.0",
    instructions = "Frida-Rust MCP: 进程分析、内存操作、Hook、反检测、AI学习、ESP分析"
)]
impl ServerHandler for FridaMcpServer {}

// ======================== 辅助函数 ========================

/// Unix：分析目标进程反调试状态（跨进程只读 /proc 分析）
#[cfg(unix)]
fn analyze_unix_stealth(target_pid: u32) -> String {
    let effective_pid = if target_pid == 0 {
        crate::common::util::current_process_id().0
    } else {
        target_pid
    };
    let mut out = String::from("Unix 目标进程状态:\n\n");
    if target_pid != 0 {
        if let Some(comm) = crate::inject::process::get_process_comm(effective_pid) {
            out.push_str(&format!("  目标进程: PID {} ({})\n\n", target_pid, comm));
        } else {
            out.push_str(&format!("  目标进程: PID {}\n\n", target_pid));
        }
    }
    match crate::inject::process::read_proc_target_info(ProcessId(effective_pid)) {
        Ok(info) => {
            out.push_str(&format!(
                "  进程状态: {} {}\n",
                info.state,
                match info.state.as_str() {
                    "T" => "⚠️ 已停止（可能被跟踪）",
                    "Z" => "僵尸进程",
                    _ => "✅",
                }
            ));
            out.push_str(&format!(
                "  TracerPid: {} {}\n",
                info.tracer_pid,
                if info.tracer_pid != 0 { "⚠️ 正被 ptrace 附加" } else { "✅" }
            ));
            out.push_str(&format!(
                "  Seccomp: {} {}\n",
                info.seccomp,
                match info.seccomp.as_str() {
                    "0" => "未启用 ✅",
                    "1" => "strict 模式 ⚠️",
                    "2" => "filter 模式 ⚠️",
                    _ => "",
                }
            ));
            out.push_str(&format!(
                "  NoNewPrivs: {} {}\n",
                info.no_new_privs,
                if info.no_new_privs != 0 { "⚠️ 已设置" } else { "✅" }
            ));
            if info.ppid != 0 {
                let parent = crate::inject::process::get_process_comm(info.ppid)
                    .unwrap_or_else(|| "未知".to_string());
                out.push_str(&format!("  父进程: PID {} ({})\n", info.ppid, parent));
            }
            if info.preloads.is_empty() {
                out.push_str("  LD_PRELOAD 等预加载: 无 ✅\n");
            } else {
                out.push_str("  LD_PRELOAD 等预加载: ⚠️\n");
                for v in &info.preloads {
                    out.push_str(&format!("    - {}\n", v));
                }
            }
        }
        Err(e) => out.push_str(&format!("  目标进程状态读取失败 ({})\n", e)),
    }
    out.push_str("\n建议: TracerPid 非 0 可用 tracer 模块隐藏; Seccomp filter 会限制 ptrace 注入\n");
    out
}

/// Windows：分析反调试状态（自身或目标进程，跨进程只读）
#[cfg(windows)]
fn analyze_windows_stealth(target_pid: u32, target_is_self: bool) -> String {
    use crate::anti_detect::win_hide::WinStealthManager;
    let effective_pid = if target_pid == 0 {
        crate::common::util::current_process_id().0
    } else {
        target_pid
    };
    let mut out = String::from("Windows 反调试检测:\n\n");
    if !target_is_self {
        out.push_str(&format!("目标进程: PID {}（跨进程只读分析）\n\n", target_pid));
    }

    // 目标 PEB 状态（自身直读 / 跨进程 ReadProcessMemory）
    match WinStealthManager::read_remote_peb(effective_pid) {
        Ok(info) => {
            out.push_str(&format!(
                "  PEB BeingDebugged: {}\n",
                if info.being_debugged != 0 { "是 ⚠️" } else { "否 ✅" }
            ));
            let flag_suspicious = info.nt_global_flag & 0x70 != 0;
            out.push_str(&format!(
                "  PEB NtGlobalFlag: {:#x} {}\n",
                info.nt_global_flag,
                if flag_suspicious { "⚠️ 可疑（堆调试标志）" } else { "✅" }
            ));
            let heap_suspicious = info.heap_flags & 0x70 != 0 || info.heap_force_flags != 0;
            out.push_str(&format!(
                "  堆 Flags: {:#x}, ForceFlags: {:#x} {}\n",
                info.heap_flags,
                info.heap_force_flags,
                if heap_suspicious { "⚠️ 可疑" } else { "✅" }
            ));
        }
        Err(e) => out.push_str(&format!("  目标 PEB 读取失败 ({})\n", e)),
    }

    if target_is_self {
        // DebugPort
        match WinStealthManager::check_debug_port() {
            Ok(port) => out.push_str(&format!(
                "  DebugPort: {} {}\n",
                port,
                if port != 0 { "⚠️ 被调试" } else { "✅" }
            )),
            Err(e) => out.push_str(&format!("  DebugPort: 读取失败 ({})\n", e)),
        }
        // DebugObjectHandle
        match WinStealthManager::check_debug_object_handle() {
            Ok(v) => out.push_str(&format!(
                "  DebugObjectHandle: {}\n",
                if v { "存在 ⚠️" } else { "无 ✅" }
            )),
            Err(e) => out.push_str(&format!("  DebugObjectHandle: 读取失败 ({})\n", e)),
        }
        // 时间差（实验性）
        match WinStealthManager::check_timing_diff() {
            Ok(diff) => out.push_str(&format!(
                "  时间差检测: {} QPC 计数 {}\n",
                diff,
                if diff > 500 { "⚠️ 可疑（可能被介入）" } else { "✅" }
            )),
            Err(e) => out.push_str(&format!("  时间差检测: 失败 ({})\n", e)),
        }
        // 调试寄存器
        match WinStealthManager::check_debug_registers() {
            Ok(v) => out.push_str(&format!(
                "  调试寄存器 Dr0-Dr7: {}\n",
                if v { "已设置 ⚠️" } else { "干净 ✅" }
            )),
            Err(e) => out.push_str(&format!("  调试寄存器 Dr0-Dr7: 读取失败 ({})\n", e)),
        }
        // 父进程链
        if let Ok(info) = crate::inject::win_process::get_process_info(effective_pid) {
            out.push_str(&format!("  父进程 PID: {}（PID {} 的父进程）\n", info.ppid, effective_pid));
        }
    } else {
        // 跨进程只读查询（最小权限 PROCESS_QUERY_INFORMATION）
        match WinStealthManager::check_remote_debug_port(effective_pid) {
            Ok(port) => out.push_str(&format!(
                "  DebugPort: {} {}\n",
                port,
                if port != 0 { "⚠️ 被调试" } else { "✅" }
            )),
            Err(e) => out.push_str(&format!("  DebugPort: 查询失败 ({})\n", e)),
        }
        match WinStealthManager::check_remote_debug_object_handle(effective_pid) {
            Ok(v) => out.push_str(&format!(
                "  DebugObjectHandle: {}\n",
                if v { "存在 ⚠️" } else { "无 ✅" }
            )),
            Err(e) => out.push_str(&format!("  DebugObjectHandle: 查询失败 ({})\n", e)),
        }
        // 父进程链（跨进程同样可读）
        if let Ok(info) = crate::inject::win_process::get_process_info(effective_pid) {
            out.push_str(&format!("  父进程 PID: {}（PID {} 的父进程）\n", info.ppid, effective_pid));
        }
        out.push_str("  （时间差/调试寄存器等自身检测项仅在目标为自身时可用）\n");
    }

    out.push_str("\n建议: 使用 stealth_apply(pid=目标) 对目标进程应用跨进程反调试清理\n");
    out
}

/// Windows：应用反检测（自身进程或跨进程清理目标 PEB）
#[cfg(windows)]
fn apply_windows_stealth(target_pid: u32, target_is_self: bool) -> Result<String, McpError> {
    use crate::anti_detect::win_hide::WinStealthManager;
    let effective_pid = if target_pid == 0 {
        crate::common::util::current_process_id().0
    } else {
        target_pid
    };
    if target_is_self {
        let mut mgr = WinStealthManager::new();
        mgr.apply_all()
            .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
        Ok("自身进程反检测已应用".to_string())
    } else {
        WinStealthManager::apply_to_process(effective_pid)
            .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
        Ok(format!("已对进程 {} 应用跨进程反调试清理", target_pid))
    }
}

/// 获取（或按目标 PID 重建）脚本引擎句柄
///
/// 引擎按 PID 缓存：首次调用或 PID 变化/显式 reset 时重新初始化，
/// 其余调用复用同一个引擎，脚本作用域（let 变量等）跨调用保留。
fn get_script_engine(pid: Option<u32>, reset: bool) -> Result<crate::script::ScriptEngineHandle, McpError> {
    let target = ProcessId(pid.unwrap_or(0));
    let mut guard = SCRIPT_ENGINE.lock().unwrap();
    let needs_rebuild = reset || guard.as_ref().map(|(cur, _)| *cur != target).unwrap_or(true);
    if needs_rebuild {
        let engine = if target.0 == 0 {
            crate::script::ScriptEngine::new()
        } else {
            crate::script::ScriptEngine::for_pid(target)
        }
        .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
        let handle = engine.into_handle();
        *guard = Some((target, handle.clone()));
        Ok(handle)
    } else {
        Ok(guard.as_ref().expect("脚本引擎已初始化").1.clone())
    }
}

fn parse_hex(s: &str) -> Result<usize, McpError> {
    let s = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    usize::from_str_radix(s, 16).map_err(|e| McpError::invalid_params(format!("无效地址: {}", e), None))
}

fn hex2bytes(hex: &str) -> Result<Vec<u8>, McpError> {
    let hex = hex.trim().replace(' ', "").replace("0x", "");
    if hex.len() % 2 != 0 { return Err(McpError::invalid_params("长度须为偶数", None)); }
    (0..hex.len()).step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i+2], 16)
            .map_err(|e| McpError::invalid_params(format!("无效: {}", e), None)))
        .collect()
}

/// 将字符串按指定编码转为字节（可选追加结束符）
///
/// encoding 支持 utf8/ascii/utf16；utf16 采用小端（LE）编码。
fn encode_string_bytes(text: &str, encoding: &str, null_terminated: bool) -> Result<Vec<u8>, String> {
    match encoding {
        "utf8" | "utf-8" => {
            let mut b = text.as_bytes().to_vec();
            if null_terminated { b.push(0); }
            Ok(b)
        }
        "ascii" => {
            let mut b = Vec::with_capacity(text.len() + 1);
            for c in text.chars() {
                if c as u32 > 0x7f {
                    return Err(format!("ASCII 无法编码字符 '{}'", c));
                }
                b.push(c as u8);
            }
            if null_terminated { b.push(0); }
            Ok(b)
        }
        "utf16" | "utf-16" | "utf16le" | "utf-16le" => {
            let mut b: Vec<u8> = text.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
            if null_terminated { b.extend_from_slice(&0u16.to_le_bytes()); }
            Ok(b)
        }
        other => Err(format!("不支持的编码: {}", other)),
    }
}

/// 将数值字符串按类型转为小端字节模式（用于 memory_search_value）
///
/// 支持十进制与 `0x` 十六进制（整数）；浮点按小端 IEEE-754 编码。
fn parse_value_pattern(value: &str, value_type: &str) -> Result<Vec<Option<u8>>, McpError> {
    let vt = value_type.to_ascii_lowercase();
    let v = value.trim();
    let int_val = |s: &str| -> Result<i128, McpError> {
        if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            i128::from_str_radix(hex, 16)
                .map_err(|e| McpError::invalid_params(format!("无效数值: {}", e), None))
        } else {
            s.parse::<i128>()
                .map_err(|e| McpError::invalid_params(format!("无效数值: {}", e), None))
        }
    };
    let bytes: Vec<u8> = match vt.as_str() {
        "u8" => vec![int_val(v)? as u8],
        "i8" => vec![int_val(v)? as i8 as u8],
        "u16" => (int_val(v)? as u16).to_le_bytes().to_vec(),
        "i16" => (int_val(v)? as i16).to_le_bytes().to_vec(),
        "u32" => (int_val(v)? as u32).to_le_bytes().to_vec(),
        "i32" => (int_val(v)? as i32).to_le_bytes().to_vec(),
        "u64" => (int_val(v)? as u64).to_le_bytes().to_vec(),
        "i64" => (int_val(v)? as i64).to_le_bytes().to_vec(),
        "f32" => {
            let f: f32 = v
                .parse()
                .map_err(|e| McpError::invalid_params(format!("无效浮点: {}", e), None))?;
            f.to_le_bytes().to_vec()
        }
        "f64" => {
            let f: f64 = v
                .parse()
                .map_err(|e| McpError::invalid_params(format!("无效浮点: {}", e), None))?;
            f.to_le_bytes().to_vec()
        }
        other => {
            return Err(McpError::invalid_params(
                format!("不支持的数值类型: {} (u8/i8/u16/i16/u32/i32/u64/i64/f32/f64)", other),
                None,
            ))
        }
    };
    Ok(bytes.into_iter().map(Some).collect())
}

fn format_hex_dump(data: &[u8], base_addr: usize) -> String {
    let mut output = format!("Hex Dump @ {:#x} ({} bytes):\n\n", base_addr, data.len());
    for (i, chunk) in data.chunks(16).enumerate() {
        let addr = base_addr + i * 16;
        let hex: Vec<String> = chunk.iter().map(|b| format!("{:02x}", b)).collect();
        let ascii: String = chunk.iter().map(|&b| if b >= 0x20 && b < 0x7f { b as char } else { '.' }).collect();
        output.push_str(&format!("{:#010x}  {:<48}  |{}|\n", addr, hex.join(" "), ascii));
    }
    output
}

/// 解析模块基址（Unix: /proc/maps；Windows: 模块枚举）
fn resolve_module_base(pid: u32, module: &str) -> Result<usize, McpError> {
    #[cfg(unix)] {
        let regions = crate::common::util::parse_proc_maps(ProcessId(pid))
            .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
        let r = regions
            .iter()
            .find(|r| !r.name.is_empty() && r.name.contains(module))
            .ok_or_else(|| McpError::invalid_params(format!("找不到模块 '{}'", module), None))?;
        Ok(r.start)
    }
    #[cfg(windows)] {
        let modules = crate::inject::win_process::enum_modules(pid)
            .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
        let name_lower = module.to_lowercase();
        let m = modules
            .iter()
            .find(|m| m.name.to_lowercase().contains(&name_lower))
            .ok_or_else(|| McpError::invalid_params(format!("找不到模块 '{}'", module), None))?;
        Ok(m.base_addr)
    }
}

/// 解析目标地址：优先 module + offset（基址 + 偏移），否则直接解析 hex 地址
fn resolve_addr(
    pid: u32,
    address: &str,
    module: &Option<String>,
    offset: &Option<String>,
) -> Result<usize, McpError> {
    match module {
        Some(m) => {
            let base = resolve_module_base(pid, m)?;
            match offset {
                Some(off) => Ok(base + parse_hex(off)?),
                None => Ok(base),
            }
        }
        None => parse_hex(address),
    }
}

/// 按权限字符串过滤区域（perm: 如 "rwx"/"r"/"w"/"x" 组合）
fn filter_regions_by_perm<'a>(
    regions: &'a [crate::common::types::MemoryRegion],
    perm: &str,
) -> Vec<&'a crate::common::types::MemoryRegion> {
    let want_r = perm.contains('r');
    let want_w = perm.contains('w');
    let want_x = perm.contains('x');
    regions
        .iter()
        .filter(|r| {
            (!want_r || r.perms.read) && (!want_w || r.perms.write) && (!want_x || r.perms.execute)
        })
        .collect()
}

/// 解析模块地址范围（基址与结束地址；Unix: maps region；Windows: base+size）
fn resolve_module_range(pid: u32, module: &str) -> Result<(u64, u64), McpError> {
    #[cfg(unix)] {
        let regions = crate::common::util::parse_proc_maps(ProcessId(pid))
            .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
        let r = regions
            .iter()
            .find(|r| !r.name.is_empty() && r.name.contains(module))
            .ok_or_else(|| McpError::invalid_params(format!("找不到模块 '{}'", module), None))?;
        Ok((r.start as u64, r.end as u64))
    }
    #[cfg(windows)] {
        let modules = crate::inject::win_process::enum_modules(pid)
            .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
        let name_lower = module.to_lowercase();
        let m = modules
            .iter()
            .find(|m| m.name.to_lowercase().contains(&name_lower))
            .ok_or_else(|| McpError::invalid_params(format!("找不到模块 '{}'", module), None))?;
        Ok((m.base_addr as u64, (m.base_addr + m.size) as u64))
    }
}

fn format_process_list(procs: &[crate::common::types::ProcessInfo]) -> String {
    if procs.is_empty() {
        return "未找到进程".to_string();
    }
    let mut sorted: Vec<&crate::common::types::ProcessInfo> = procs.iter().collect();
    sorted.sort_by_key(|p| p.pid.0);
    let mut out = format!("共 {} 个进程:\n", procs.len());
    for (i, p) in sorted.iter().enumerate().take(200) {
        out.push_str(&format!("  [{:4}] {}\n", i, p));
    }
    if procs.len() > 200 {
        out.push_str(&format!("  ... 其余 {} 个进程省略\n", procs.len() - 200));
    }
    out
}

fn format_process_find(procs: &[crate::common::types::ProcessInfo], name: &str) -> String {
    let matches: Vec<&crate::common::types::ProcessInfo> = procs
        .iter()
        .filter(|p| {
            p.name.to_lowercase().contains(name)
                || p.cmdline.iter().any(|c| c.to_lowercase().contains(name))
        })
        .collect();
    if matches.is_empty() {
        return format!("未找到名称包含 '{}' 的进程", name);
    }
    let mut out = format!("找到 {} 个匹配进程:\n", matches.len());
    for (i, p) in matches.iter().enumerate().take(20) {
        out.push_str(&format!("  [{:2}] {}\n", i, p));
    }
    out
}

/// 执行内存模式搜索并格式化结果（Unix/Windows 共用逻辑）
fn run_memory_search(
    pid: u32,
    pattern: &[Option<u8>],
    max: Option<usize>,
    has_range: bool,
    start: u64,
    end: u64,
    align: Option<usize>,
) -> Result<String, McpError> {
    #[cfg(unix)] {
        let mut s = crate::memory::MemoryScanner::new(ProcessId(pid));
        let r = if has_range {
            let all = s.readable_regions()
                .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
            let filtered: Vec<crate::common::types::MemoryRegion> = all.into_iter()
                .filter(|rg| (rg.start as u64) < end && (rg.end as u64) > start)
                .map(|mut rg| {
                    rg.start = rg.start.max(start as usize);
                    rg.end = rg.end.min(end as usize);
                    rg
                })
                .collect();
            s.search_wildcard(pattern, Some(&filtered), max)
        } else {
            s.search_wildcard(pattern, None, max)
        };
        let r = r.map_err(|e| McpError::internal_error(format!("{}", e), None))?;
        let r = apply_search_align(r, align);
        Ok(format_matches(r, max, |addr| {
            s.dump_region(addr, 16).unwrap_or_default()
        }))
    }
    #[cfg(windows)] {
        let s = crate::memory::win_scanner::WinMemoryScanner::new(pid)
            .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
        let range = if has_range { Some((start, end)) } else { None };
        let r = s.search_pattern(pattern, max, range)
            .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
        let r = apply_search_align(r, align);
        Ok(format_matches(r, max, |addr| {
            s.dump_region(addr, 16).unwrap_or_default()
        }))
    }
}

/// 按对齐字节过滤匹配地址（align=Some(a) 时仅保留 a 的整数倍地址）
fn apply_search_align(r: Vec<u64>, align: Option<usize>) -> Vec<u64> {
    match align {
        Some(a) if a > 1 => r.into_iter().filter(|addr| addr % a as u64 == 0).collect(),
        _ => r,
    }
}

/// 格式化搜索结果（最多显示 20 个，含地址上下文）
fn format_matches<F>(r: Vec<u64>, max: Option<usize>, mut dump: F) -> String
where
    F: FnMut(u64) -> Vec<u8>,
{
    if r.is_empty() {
        return "未找到匹配".to_string();
    }
    let mut sorted = r;
    sorted.sort_unstable();
    let mut output = format!("找到 {} 个匹配:\n", sorted.len());
    for (i, addr) in sorted.iter().enumerate().take(20) {
        let ctx = dump(*addr);
        output.push_str(&format_match_context(i, *addr, &ctx));
        output.push_str("\n");
    }
    if sorted.len() >= max.unwrap_or(usize::MAX) {
        output.push_str(&format!("(已达上限 {} 个，可用 limit 参数调整)\n", max.unwrap_or(100)));
    }
    output
}

/// 格式化读取到的字符串结果
fn format_string_result(addr: usize, encoding: &str, data: &[u8]) -> String {
    let decoded = match encoding {
        "utf16" | "utf16le" => {
            let nul = data
                .chunks_exact(2)
                .position(|pair| pair[0] == 0 && pair[1] == 0)
                .map(|n| n * 2)
                .unwrap_or(data.len());
            let units: Vec<u16> = data[..nul]
                .chunks_exact(2)
                .map(|p| u16::from_le_bytes([p[0], p[1]]))
                .collect();
            String::from_utf16_lossy(&units)
        }
        "ascii" => {
            let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
            data[..end]
                .iter()
                .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
                .collect()
        }
        _ => {
            let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
            String::from_utf8_lossy(&data[..end]).into_owned()
        }
    };
    let hex: Vec<String> = data.iter().take(16).map(|b| format!("{:02x}", b)).collect();
    format!(
        "地址: {:#x}\n编码: {}\n长度: {} 字节\n字符串: {:?}\nHex: {}\n",
        addr,
        encoding,
        data.len(),
        decoded,
        hex.join(" ")
    )
}

/// 格式化匹配地址及其上下文（前 16 字节 hex + ASCII）
fn format_match_context(idx: usize, addr: u64, data: &[u8]) -> String {
    let hex: Vec<String> = data.iter().take(16).map(|b| format!("{:02x}", b)).collect();
    let ascii: String = data
        .iter()
        .take(16)
        .map(|&b| if b >= 0x20 && b < 0x7f { b as char } else { '.' })
        .collect();
    format!("  [{:2}] {:#x}  {:<48}  |{}|", idx, addr, hex.join(" "), ascii)
}

fn format_regions(regions: &[crate::common::types::MemoryRegion]) -> String {
    if regions.is_empty() {
        return "未找到内存区域".to_string();
    }
    let mut total = 0usize;
    let mut readable = 0usize;
    let mut writable = 0usize;
    let mut out = format!("共 {} 个内存区域:\n", regions.len());
    for (i, r) in regions.iter().enumerate().take(100) {
        out.push_str(&format!(
            "  [{:3}] {:#x}-{:#x} {} {} ({} bytes)\n",
            i, r.start, r.end, r.perms, r.name, r.size()
        ));
        total += r.size();
        if r.perms.read { readable += r.size(); }
        if r.perms.write { writable += r.size(); }
    }
    if regions.len() > 100 {
        out.push_str(&format!("  ... 其余 {} 个区域省略\n", regions.len() - 100));
    }
    out.push_str(&format!(
        "总计 {} bytes, 可读 {} bytes, 可写 {} bytes",
        total, readable, writable
    ));
    out
}

fn format_module_list(modules: &[crate::common::types::ModuleInfo]) -> String {
    if modules.is_empty() {
        return "未找到模块".to_string();
    }
    let mut out = format!("共 {} 个模块:\n", modules.len());
    for (i, m) in modules.iter().enumerate().take(100) {
        out.push_str(&format!(
            "  [{:3}] {} @ {:#x} ({} KB, {})\n",
            i,
            m.name,
            m.base_addr,
            m.size / 1024,
            m.path
        ));
    }
    if modules.len() > 100 {
        out.push_str(&format!("  ... 其余 {} 个模块省略\n", modules.len() - 100));
    }
    out
}

fn format_memory_stats(s: &crate::common::types::MemoryStats) -> String {
    format!(
        "=== 进程内存统计 ===\n虚拟内存: {} MB\n常驻内存: {} MB\n私有提交: {} MB\n峰值常驻: {} MB",
        s.virtual_size / (1024 * 1024),
        s.resident_size / (1024 * 1024),
        s.private_size / (1024 * 1024),
        s.peak_resident_size / (1024 * 1024),
    )
}

fn format_disassembly(bytes: &[u8], base_addr: usize, max_instr: usize) -> String {
    match crate::disasm::Disassembler::for_current_arch() {
        Ok(disasm) => {
            match disasm.disassemble_to_string(bytes, base_addr as u64, Some(max_instr)) {
                Ok(output) => output,
                Err(e) => format!("反汇编失败: {}\n", e),
            }
        }
        Err(e) => {
            format!("创建反汇编器失败: {}\n", e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 从 memory_regions 输出首行解析区域数量
    fn parse_region_count(out: &str) -> usize {
        out.lines()
            .next()
            .and_then(|l| l.split('共').nth(1))
            .and_then(|l| l.trim().trim_end_matches(':').split('个').next())
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0)
    }

    /// 串行化脚本引擎相关测试（共享全局 SCRIPT_ENGINE 状态）
    static SCRIPT_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_get_script_engine_persists_scope() {
        let _guard = SCRIPT_TEST_LOCK.lock().unwrap();
        let handle = get_script_engine(None, false).expect("获取引擎失败");
        handle.execute_text("let mcp_val = 7;").expect("初始化作用域失败");
        let result = handle.execute_text("mcp_val + 1").expect("执行失败");
        assert_eq!(result.value.as_int().unwrap(), 8);
    }

    #[test]
    fn test_get_script_engine_rebuilds_on_reset() {
        let _guard = SCRIPT_TEST_LOCK.lock().unwrap();
        let handle = get_script_engine(None, false).expect("获取引擎失败");
        handle.execute_text("let mcp_val = 7;").expect("初始化作用域失败");

        // 显式 reset 后引擎重建，旧变量不可见
        let handle = get_script_engine(None, true).expect("重建引擎失败");
        assert!(handle.execute_text("mcp_val + 1").is_err());
    }

    #[test]
    fn test_get_script_engine_rebuilds_on_pid_change() {
        let _guard = SCRIPT_TEST_LOCK.lock().unwrap();
        let handle = get_script_engine(Some(1), false).expect("获取引擎失败");
        handle.execute_text("let mcp_val = 1;").expect("初始化作用域失败");

        let handle = get_script_engine(Some(2), false).expect("获取引擎失败");
        assert!(handle.execute_text("mcp_val + 1").is_err());
    }

    #[test]
    fn test_run_script_logs_and_value() {
        let _guard = SCRIPT_TEST_LOCK.lock().unwrap();
        let handle = get_script_engine(None, true).expect("获取引擎失败");
        let result = handle
            .execute_text(r#"log_info("mcp hello"); 21 * 2"#)
            .expect("执行失败");
        assert_eq!(result.value.as_int().unwrap(), 42);
        assert!(result.logs.iter().any(|l| l.contains("mcp hello")));
    }

    #[test]
    fn test_run_script_with_file() {
        let _guard = SCRIPT_TEST_LOCK.lock().unwrap();
        let path = std::env::temp_dir().join(format!("frida_mcp_test_{}.rhai", std::process::id()));
        std::fs::write(&path, "21 * 2").expect("写入临时脚本失败");

        let handle = get_script_engine(None, true).expect("获取引擎失败");
        let result = handle
            .execute_file(path.to_str().expect("路径非 UTF-8"))
            .expect("执行脚本文件失败");
        assert_eq!(result.value.as_int().unwrap(), 42);

        let _ = std::fs::remove_file(&path);
    }

    /// 端到端：process_list 输出统计信息并按 PID 排序
    #[cfg(windows)]
    #[test]
    fn test_process_list_self() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let handler = FridaMcpServer;
        let out = rt.block_on(handler.process_list()).expect("process_list 失败");
        assert!(out.contains("共 "), "输出应包含统计信息");
        assert!(out.contains("进程"), "输出应包含进程字样");
    }

    /// 端到端：按当前可执行文件名查找自身进程
    #[cfg(windows)]
    #[test]
    fn test_process_find_self() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let handler = FridaMcpServer;
        let exe = std::env::current_exe().expect("获取当前 exe 失败");
        let name = exe.file_name().expect("无文件名").to_string_lossy().to_string();
        let out = rt
            .block_on(handler.process_find(Parameters(ProcessFindParams { name })))
            .expect("process_find 失败");
        assert!(out.contains("找到"), "应找到匹配进程: {}", out);
    }

    /// 端到端：process_inject_reflect 无效 pid 应报错（不执行注入）
    #[cfg(windows)]
    #[test]
    fn test_process_inject_reflect_invalid_pid() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let handler = FridaMcpServer;
        let err = rt
            .block_on(handler.process_inject_reflect(Parameters(InjectReflectParams {
                pid: 0,
                lib_path: r"C:\Windows\System32\kernel32.dll".to_string(),
            })))
            .expect_err("无效 pid 应返回错误");
        assert!(err.to_string().contains("OpenProcess"), "应报告 OpenProcess 失败: {}", err);
    }

    /// 端到端：process_inject_reflect Unix 应明确返回不支持
    #[cfg(unix)]
    #[test]
    fn test_process_inject_reflect_unix_unsupported() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let handler = FridaMcpServer;
        let err = rt
            .block_on(handler.process_inject_reflect(Parameters(InjectReflectParams {
                pid: 1,
                lib_path: "/tmp/x.so".to_string(),
            })))
            .expect_err("Unix 应返回不支持");
        assert!(err.to_string().contains("仅支持 Windows"), "错误信息: {}", err);
    }

    /// 端到端：stealth_analyze Windows 分支不再输出占位文案
    #[cfg(windows)]
    #[test]
    fn test_stealth_analyze_windows() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let handler = FridaMcpServer;
        let out = rt
            .block_on(handler.stealth_analyze(Parameters(PidParams { pid: 0 })))
            .expect("stealth_analyze 失败");
        assert!(!out.contains("检查中"), "不应再有占位输出: {}", out);
        assert!(
            out.contains("BeingDebugged") || out.contains("NtGlobalFlag"),
            "应包含 PEB 检测结果: {}",
            out
        );
        // 新检测项
        assert!(out.contains("DebugPort"), "应包含 DebugPort 检测: {}", out);
        assert!(out.contains("时间差检测"), "应包含时间差检测: {}", out);
        assert!(out.contains("堆 Flags"), "应包含堆标志检测: {}", out);
    }

    /// 端到端：stealth_analyze 跨进程模式应执行只读 DebugPort/DebugObject 查询
    #[cfg(windows)]
    #[test]
    fn test_stealth_analyze_windows_remote() {
        let self_pid = crate::common::util::current_process_id().0;
        // 以父进程为跨进程分析目标，避开自身分支
        let target_pid = crate::inject::win_process::get_process_info(self_pid)
            .map(|i| i.ppid)
            .unwrap_or(4);
        let out = analyze_windows_stealth(target_pid, false);
        assert!(out.contains("目标进程: PID"), "应标记目标进程: {}", out);
        assert!(out.contains("DebugPort"), "跨进程模式应包含 DebugPort 查询: {}", out);
        assert!(out.contains("DebugObjectHandle"), "跨进程模式应包含 DebugObjectHandle 查询: {}", out);
        assert!(out.contains("父进程 PID"), "跨进程模式应包含父进程链: {}", out);
    }

    /// 端到端：stealth_apply 对自身进程应用反检测
    #[cfg(windows)]
    #[test]
    fn test_stealth_apply_self() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let handler = FridaMcpServer;
        let pid = crate::common::util::current_process_id().0;
        let out = rt
            .block_on(handler.stealth_apply(Parameters(StealthParams {
                pid,
                auto_detect: Some(false),
            })))
            .expect("stealth_apply 失败");
        assert!(out.contains("反检测已应用"), "应应用成功: {}", out);
    }

    /// 端到端：stealth_apply 跨进程模式（对自身也走跨进程 PEB 清理路径）
    #[cfg(windows)]
    #[test]
    fn test_stealth_apply_auto_detect_self() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let handler = FridaMcpServer;
        let pid = crate::common::util::current_process_id().0;
        let out = rt
            .block_on(handler.stealth_apply(Parameters(StealthParams {
                pid,
                auto_detect: Some(true),
            })))
            .expect("stealth_apply(auto) 失败");
        assert!(out.contains("智能反检测已应用"), "应自动分析并应用: {}", out);
        assert!(out.contains("Windows 反调试检测"), "应含分析报告: {}", out);
    }

    /// Unix：stealth_apply 对目标进程应只读分析，不得误作用到自身
    #[cfg(unix)]
    #[test]
    fn test_stealth_apply_unix_remote_target_readonly() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let handler = FridaMcpServer;
        let out = rt
            .block_on(handler.stealth_apply(Parameters(StealthParams {
                pid: 1,
                auto_detect: Some(true),
            })))
            .expect("stealth_apply 失败");
        assert!(
            out.contains("仅支持只读分析") || out.contains("TracerPid"),
            "Unix 目标进程应返回只读分析而非误操作自身: {}",
            out
        );
    }

    /// 从输出文本中提取第一个 0x 十六进制地址
    fn extract_first_hex_addr(out: &str) -> Option<u64> {
        out.lines().find(|l| l.contains("0x")).and_then(|l| {
            let idx = l.find("0x")?;
            let token = l[idx + 2..].split_whitespace().next()?;
            u64::from_str_radix(token, 16).ok()
        })
    }

    /// 端到端：memory_search 支持 start/end 范围过滤
    #[cfg(windows)]
    #[test]
    fn test_memory_search_range() {
        // 使用唯一 marker 模式，避免与并行测试的 marker 相互干扰
        let marker: Vec<u8> = vec![0x13, 0x37, 0x41, 0x42, 0x43, 0x44, 0xAB, 0xCD, 0x99];
        std::hint::black_box(&marker);
        let pid = crate::common::util::current_process_id().0;
        let rt = tokio::runtime::Runtime::new().unwrap();
        let handler = FridaMcpServer;
        let pattern = "13 37 ?? ?? ?? ?? AB CD".to_string();

        // 全量搜索拿地址
        let out = rt
            .block_on(handler.memory_search(Parameters(SearchParams {
                pid,
                pattern: pattern.clone(),
                limit: Some(10),
                start: None,
                end: None,
                module: None,
            })))
            .expect("全量搜索失败");
        assert!(out.contains("找到"), "全量搜索应命中: {}", out);
        let addr = extract_first_hex_addr(&out).expect("解析地址失败");

        // 带范围搜索应命中同一区域
        let out2 = rt
            .block_on(handler.memory_search(Parameters(SearchParams {
                pid,
                pattern: pattern.clone(),
                limit: Some(10),
                start: Some(format!("{:#x}", addr.saturating_sub(1))),
                end: Some(format!("{:#x}", addr + 16)),
                module: None,
            })))
            .expect("范围搜索失败");
        assert!(out2.contains("找到"), "范围搜索应命中: {}", out2);

        // 无效范围地址应返回错误
        let res = rt.block_on(handler.memory_search(Parameters(SearchParams {
            pid,
            pattern,
            limit: Some(10),
            start: Some("zz".to_string()),
            end: None,
            module: None,
        })));
        assert!(res.is_err(), "无效 start 应返回错误");
    }

    /// 端到端：module_info 应返回自身进程 exe 模块信息
    #[cfg(windows)]
    #[test]
    fn test_module_info_self() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let handler = FridaMcpServer;
        let exe = std::env::current_exe().expect("获取当前 exe 失败");
        let name = exe.file_name().expect("无文件名").to_string_lossy().to_string();
        let pid = crate::common::util::current_process_id().0;
        let out = rt
            .block_on(handler.module_info(Parameters(ModuleParams { pid, module: name })))
            .expect("module_info 失败");
        assert!(out.contains("基址"), "应返回基址: {}", out);
    }

    /// 端到端：memory_read_string 应读回自身进程字符串
    #[cfg(windows)]
    #[test]
    fn test_memory_read_string_self() {
        let data: Vec<u8> = b"hello_frida_123\0trailing".to_vec();
        std::hint::black_box(&data);
        let addr = data.as_ptr() as usize;
        let pid = crate::common::util::current_process_id().0;
        let rt = tokio::runtime::Runtime::new().unwrap();
        let handler = FridaMcpServer;
        let out = rt
            .block_on(handler.memory_read_string(Parameters(ReadStringParams {
                pid,
                address: format!("{:#x}", addr),
                max_len: Some(64),
                encoding: Some("utf8".to_string()),
            })))
            .expect("读取失败");
        assert!(out.contains("hello_frida_123"), "应读到字符串: {}", out);
    }

    /// 端到端：memory_search_text 支持 UTF-8 与 UTF-16LE 文本搜索
    #[cfg(windows)]
    #[test]
    fn test_memory_search_text_self() {
        let marker: Vec<u8> = b"unique_text_marker_9x8z".to_vec();
        let wide_marker: Vec<u8> = "wide_marker_77"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        std::hint::black_box(&marker);
        std::hint::black_box(&wide_marker);

        let pid = crate::common::util::current_process_id().0;
        let rt = tokio::runtime::Runtime::new().unwrap();
        let handler = FridaMcpServer;

        let out = rt
            .block_on(handler.memory_search_text(Parameters(SearchTextParams {
                pid,
                text: "unique_text_marker_9x8z".to_string(),
                limit: Some(10),
                start: None,
                end: None,
                wide: Some(false),
                module: None,
            })))
            .expect("文本搜索失败");
        assert!(out.contains("找到"), "UTF-8 文本应命中: {}", out);

        let out2 = rt
            .block_on(handler.memory_search_text(Parameters(SearchTextParams {
                pid,
                text: "wide_marker_77".to_string(),
                limit: Some(10),
                start: None,
                end: None,
                wide: Some(true),
                module: None,
            })))
            .expect("宽字符搜索失败");
        assert!(out2.contains("找到"), "UTF-16LE 文本应命中: {}", out2);
    }

    /// 端到端：process_info 应包含增强字段
    #[cfg(windows)]
    #[test]
    fn test_process_info_enhanced_fields() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let handler = FridaMcpServer;
        let pid = crate::common::util::current_process_id().0;
        let out = rt
            .block_on(handler.process_info(Parameters(PidParams { pid })))
            .expect("process_info 失败");
        assert!(out.contains("父进程 PID"), "应包含父进程字段: {}", out);
        assert!(out.contains("模块列表"), "应包含模块列表: {}", out);
        assert!(out.contains("线程列表"), "应包含线程列表: {}", out);
    }

    /// 端到端：memory_dump 支持从模块基址 dump
    #[cfg(windows)]
    #[test]
    fn test_memory_dump_module_self() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let handler = FridaMcpServer;
        let exe = std::env::current_exe().expect("获取当前 exe 失败");
        let name = exe.file_name().expect("无文件名").to_string_lossy().to_string();
        let pid = crate::common::util::current_process_id().0;
        let path = std::env::temp_dir().join(format!("dump_test_{}.bin", std::process::id()));
        let out = rt
            .block_on(handler.memory_dump(Parameters(DumpParams {
                pid,
                address: "0x0".to_string(),
                size: 16,
                output: Some(path.to_string_lossy().to_string()),
                module: Some(name),
                to_hex: None,
            })))
            .expect("dump 失败");
        assert!(out.contains("已dump"), "应 dump 成功: {}", out);
        let _ = std::fs::remove_file(&path);
    }

    /// 端到端：memory_regions 支持 perm 权限过滤
    #[cfg(windows)]
    #[test]
    fn test_memory_regions_perm_filter() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let handler = FridaMcpServer;
        let pid = crate::common::util::current_process_id().0;
        let all = rt
            .block_on(handler.memory_regions(Parameters(RegionsParams { pid, perm: None })))
            .expect("memory_regions 失败");
        assert!(all.starts_with("共"), "应有区域列表: {}", all);
        let only_x = rt
            .block_on(handler.memory_regions(Parameters(RegionsParams {
                pid,
                perm: Some("x".to_string()),
            })))
            .expect("memory_regions(x) 失败");
        assert!(only_x.starts_with("共"), "应有区域列表: {}", only_x);
        for line in only_x.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 && parts[0].starts_with('[') {
                assert!(parts[2].contains('x'), "可执行过滤后仍有非执行区域: {}", line);
            }
        }
        let count_all = parse_region_count(&all);
        let count_x = parse_region_count(&only_x);
        assert!(
            count_x > 0 && count_x < count_all,
            "可执行区域应少于全部区域: {} < {}",
            count_x,
            count_all
        );
    }

    /// 端到端：memory_dump to_hex=true 输出 hex dump 而非文件
    #[cfg(windows)]
    #[test]
    fn test_memory_dump_to_hex() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let handler = FridaMcpServer;
        let exe = std::env::current_exe().expect("获取当前 exe 失败");
        let name = exe.file_name().expect("无文件名").to_string_lossy().to_string();
        let pid = crate::common::util::current_process_id().0;
        let out = rt
            .block_on(handler.memory_dump(Parameters(DumpParams {
                pid,
                address: "0x0".to_string(),
                size: 16,
                output: None,
                module: Some(name),
                to_hex: Some(true),
            })))
            .expect("dump to_hex 失败");
        assert!(out.contains("Hex Dump"), "应输出 hex dump: {}", out);
        assert!(!out.contains("已dump"), "to_hex 不应写文件: {}", out);
    }

    /// 端到端：memory_alloc / memory_free 分配与释放内存
    #[cfg(windows)]
    #[test]
    fn test_memory_alloc_free_self() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let handler = FridaMcpServer;
        let pid = crate::common::util::current_process_id().0;

        let out = rt
            .block_on(handler.memory_alloc(Parameters(AllocParams {
                pid,
                size: 0x1000,
                executable: None,
            })))
            .expect("alloc 失败");
        assert!(out.contains("已分配"), "应分配成功: {}", out);
        let addr = parse_hex(
            out.split('@')
                .nth(1)
                .and_then(|s| s.split_whitespace().next())
                .unwrap_or("0"),
        )
        .expect("解析地址失败");
        assert!(addr > 0, "地址应有效: {:#x}", addr);

        let free_out = rt
            .block_on(handler.memory_free(Parameters(FreeMemoryParams {
                pid,
                address: format!("{:#x}", addr),
            })))
            .expect("free 失败");
        assert!(free_out.contains("已释放"), "应释放成功: {}", free_out);
    }

    /// 端到端：memory_protect 修改内存保护属性
    #[cfg(windows)]
    #[test]
    fn test_memory_protect_self() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let handler = FridaMcpServer;
        let pid = crate::common::util::current_process_id().0;

        let out = rt
            .block_on(handler.memory_alloc(Parameters(AllocParams {
                pid,
                size: 0x1000,
                executable: Some(true),
            })))
            .expect("alloc 失败");
        let addr = parse_hex(
            out.split('@')
                .nth(1)
                .and_then(|s| s.split_whitespace().next())
                .unwrap_or("0"),
        )
        .expect("解析地址失败");

        let p_out = rt
            .block_on(handler.memory_protect(Parameters(ProtectMemoryParams {
                pid,
                address: format!("{:#x}", addr),
                size: 0x1000,
                perm: "rw".to_string(),
            })))
            .expect("protect 失败");
        assert!(p_out.contains("已设置"), "应修改保护: {}", p_out);

        let _ = rt.block_on(handler.memory_free(Parameters(FreeMemoryParams {
            pid,
            address: format!("{:#x}", addr),
        })));
    }

    /// 端到端：memory_write_string 写入 utf8/utf16 字符串并可回读
    #[cfg(windows)]
    #[test]
    fn test_memory_write_string_self() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let handler = FridaMcpServer;
        let pid = crate::common::util::current_process_id().0;

        let out = rt
            .block_on(handler.memory_alloc(Parameters(AllocParams {
                pid,
                size: 0x100,
                executable: None,
            })))
            .expect("alloc 失败");
        let addr = parse_hex(
            out.split('@')
                .nth(1)
                .and_then(|s| s.split_whitespace().next())
                .unwrap_or("0"),
        )
        .expect("解析地址失败");

        // utf8 + 结束符
        rt.block_on(handler.memory_write_string(Parameters(WriteStringParams {
            pid,
            address: format!("{:#x}", addr),
            text: "hi".to_string(),
            encoding: Some("utf8".to_string()),
            null_terminated: Some(true),
            module: None,
            offset: None,
        })))
        .expect("写 utf8 失败");
        let s = crate::memory::win_scanner::WinMemoryScanner::new(pid).expect("扫描器创建失败");
        let data = s.dump_region(addr as u64, 4).expect("读取失败");
        assert_eq!(&data[..3], &[b'h', b'i', 0], "utf8 写入应带结束符: {:?}", data);

        // utf16 + 结束符
        rt.block_on(handler.memory_write_string(Parameters(WriteStringParams {
            pid,
            address: format!("{:#x}", addr),
            text: "hi".to_string(),
            encoding: Some("utf16".to_string()),
            null_terminated: Some(true),
            module: None,
            offset: None,
        })))
        .expect("写 utf16 失败");
        let data = s.dump_region(addr as u64, 8).expect("读取失败");
        assert_eq!(
            &data[..6],
            &[b'h', 0, b'i', 0, 0, 0],
            "utf16 写入应带结束符: {:?}",
            data
        );

        let _ = rt.block_on(handler.memory_free(Parameters(FreeMemoryParams {
            pid,
            address: format!("{:#x}", addr),
        })));
    }

    /// 单元级：encode_string_bytes 编码与结束符
    #[test]
    fn test_encode_string_bytes() {
        assert_eq!(
            encode_string_bytes("ab", "utf8", true).unwrap(),
            vec![b'a', b'b', 0]
        );
        assert_eq!(
            encode_string_bytes("ab", "utf8", false).unwrap(),
            vec![b'a', b'b']
        );
        assert_eq!(
            encode_string_bytes("中文", "ascii", true).unwrap_err(),
            "ASCII 无法编码字符 '中'"
        );
        assert_eq!(
            encode_string_bytes("hi", "utf16", true).unwrap(),
            vec![b'h', 0, b'i', 0, 0, 0]
        );
        assert_eq!(
            encode_string_bytes("hi", "utf16", false).unwrap(),
            vec![b'h', 0, b'i', 0]
        );
        assert!(encode_string_bytes("x", "gbk", true).is_err());
    }

    /// 端到端：memory_search_value 按数值扫描内存
    #[cfg(windows)]
    #[test]
    fn test_memory_search_value_self() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let handler = FridaMcpServer;
        let pid = crate::common::util::current_process_id().0;

        let out = rt
            .block_on(handler.memory_alloc(Parameters(AllocParams {
                pid,
                size: 0x1000,
                executable: None,
            })))
            .expect("alloc 失败");
        let addr = parse_hex(
            out.split('@')
                .nth(1)
                .and_then(|s| s.split_whitespace().next())
                .unwrap_or("0"),
        )
        .expect("解析地址失败");

        let marker: u32 = 0xDEAD_BEEF;
        crate::common::util::safe_write_bytes(ProcessId(pid), addr, &marker.to_le_bytes())
            .expect("写入标记失败");

        let s_out = rt
            .block_on(handler.memory_search_value(Parameters(SearchValueParams {
                pid,
                value: "3735928559".to_string(),
                value_type: "u32".to_string(),
                align: None,
                limit: None,
                start: Some(format!("{:#x}", addr)),
                end: Some(format!("{:#x}", addr + 0x1000)),
                module: None,
            })))
            .expect("搜索失败");
        assert!(s_out.contains("找到"), "应找到数值: {}", s_out);
        assert!(!s_out.contains("未找到"), "不应未找到: {}", s_out);

        // 对齐过滤后仍应命中（区域页对齐）
        let a_out = rt
            .block_on(handler.memory_search_value(Parameters(SearchValueParams {
                pid,
                value: "0xdeadbeef".to_string(),
                value_type: "u32".to_string(),
                align: Some(4),
                limit: None,
                start: Some(format!("{:#x}", addr)),
                end: Some(format!("{:#x}", addr + 0x1000)),
                module: None,
            })))
            .expect("对齐搜索失败");
        assert!(a_out.contains("找到"), "对齐过滤后应仍命中: {}", a_out);

        let _ = rt.block_on(handler.memory_free(Parameters(FreeMemoryParams {
            pid,
            address: format!("{:#x}", addr),
        })));
    }

    /// 端到端：module_list 列出自身模块
    #[cfg(windows)]
    #[test]
    fn test_module_list_self() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let handler = FridaMcpServer;
        let pid = crate::common::util::current_process_id().0;
        let out = rt
            .block_on(handler.module_list(Parameters(PidParams { pid })))
            .expect("module_list 失败");
        assert!(out.contains("共"), "应有模块列表: {}", out);
        let exe = std::env::current_exe().expect("获取 exe 失败");
        let name = exe.file_name().expect("无文件名").to_string_lossy().to_string();
        assert!(out.contains(&name), "应包含自身 exe '{}': {}", name, out);
    }

    /// 端到端：process_memory_stats 获取自身内存统计
    #[cfg(windows)]
    #[test]
    fn test_process_memory_stats_self() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let handler = FridaMcpServer;
        let pid = crate::common::util::current_process_id().0;
        let out = rt
            .block_on(handler.process_memory_stats(Parameters(PidParams { pid })))
            .expect("process_memory_stats 失败");
        assert!(out.contains("进程内存统计"), "应有统计输出: {}", out);
        assert!(out.contains("虚拟内存"), "应含虚拟内存: {}", out);
        assert!(out.contains("常驻内存"), "应含常驻内存: {}", out);
    }

    /// 单元级：parse_value_pattern 数值编码
    #[test]
    fn test_parse_value_pattern() {
        assert_eq!(
            parse_value_pattern("0x1234", "u32").unwrap(),
            vec![Some(0x34), Some(0x12), Some(0), Some(0)]
        );
        assert_eq!(
            parse_value_pattern("-5", "i32").unwrap(),
            vec![Some(0xFB), Some(0xFF), Some(0xFF), Some(0xFF)]
        );
        assert_eq!(
            parse_value_pattern("0x1122334455667788", "u64").unwrap().len(),
            8
        );
        assert_eq!(
            parse_value_pattern("1.5", "f32").unwrap(),
            vec![Some(0x00), Some(0x00), Some(0xC0), Some(0x3F)]
        );
        assert_eq!(parse_value_pattern("255", "u8").unwrap(), vec![Some(0xFF)]);
        assert!(parse_value_pattern("abc", "u32").is_err());
        assert!(parse_value_pattern("1", "double").is_err());
    }

    /// 端到端：hook_list 无 Hook 时可正常返回
    #[cfg(windows)]
    #[test]
    fn test_hook_list_empty() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let handler = FridaMcpServer;
        let out = rt.block_on(handler.hook_list()).expect("hook_list 失败");
        assert!(!out.is_empty(), "hook_list 应有输出");
    }

    /// 单元级：resolve_addr 支持 module + offset 解析
    #[cfg(windows)]
    #[test]
    fn test_resolve_addr_module() {
        let exe = std::env::current_exe().expect("获取当前 exe 失败");
        let name = exe.file_name().expect("无文件名").to_string_lossy().to_string();
        let pid = crate::common::util::current_process_id().0;

        let base = resolve_addr(pid, "0x0", &Some(name.clone()), &None).expect("解析模块基址失败");
        assert!(base > 0x10000, "模块基址应有效: {:#x}", base);

        let with_offset =
            resolve_addr(pid, "0x0", &Some(name), &Some("0x10".to_string())).expect("解析偏移失败");
        assert_eq!(with_offset, base + 0x10);
    }

    /// 端到端：memory_disasm 支持 module + offset
    #[cfg(windows)]
    #[test]
    fn test_memory_disasm_module_self() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let handler = FridaMcpServer;
        let exe = std::env::current_exe().expect("获取当前 exe 失败");
        let name = exe.file_name().expect("无文件名").to_string_lossy().to_string();
        let pid = crate::common::util::current_process_id().0;
        let out = rt
            .block_on(handler.memory_disasm(Parameters(DisasmParams {
                pid,
                address: "0x0".to_string(),
                count: Some(5),
                module: Some(name),
                offset: Some("0x1000".to_string()),
            })))
            .expect("disasm 失败");
        assert!(!out.is_empty(), "应有输出");
    }

    /// 端到端：memory_search 支持 module 限定搜索（exe 模块内应含 MZ 头）
    #[cfg(windows)]
    #[test]
    fn test_memory_search_module_self() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let handler = FridaMcpServer;
        let exe = std::env::current_exe().expect("获取当前 exe 失败");
        let name = exe.file_name().expect("无文件名").to_string_lossy().to_string();
        let pid = crate::common::util::current_process_id().0;
        let out = rt
            .block_on(handler.memory_search(Parameters(SearchParams {
                pid,
                pattern: "4D 5A".to_string(),
                limit: Some(5),
                start: None,
                end: None,
                module: Some(name),
            })))
            .expect("模块内搜索失败");
        assert!(out.contains("找到"), "exe 模块应包含 MZ 头: {}", out);
    }

    /// 端到端：memory_read 支持 module 定位（读 exe 模块基址应为 MZ 头）
    #[cfg(windows)]
    #[test]
    fn test_memory_read_module_self() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let handler = FridaMcpServer;
        let exe = std::env::current_exe().expect("获取当前 exe 失败");
        let name = exe.file_name().expect("无文件名").to_string_lossy().to_string();
        let pid = crate::common::util::current_process_id().0;
        let out = rt
            .block_on(handler.memory_read(Parameters(ReadMemoryParams {
                pid,
                address: "0x0".to_string(),
                size: 2,
                module: Some(name),
                offset: None,
            })))
            .expect("模块读取失败");
        assert!(out.contains("4d 5a"), "应读到 MZ 头: {}", out);
    }

    /// 端到端：run_script 支持 timeout 参数，正常脚本不受影响
    #[cfg(windows)]
    #[test]
    fn test_run_script_with_timeout() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let handler = FridaMcpServer;
        let out = rt
            .block_on(handler.run_script(Parameters(RunScriptParams {
                pid: None,
                script: "21 * 2".to_string(),
                script_file: None,
                reset: Some(true),
                timeout: Some(60),
            })))
            .expect("run_script 失败");
        assert!(out.contains("42"), "应返回 42: {}", out);
    }
}
