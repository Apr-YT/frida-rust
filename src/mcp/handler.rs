//! MCP Server Handler - 简化版树状结构
//!
//! 14个核心工具，按功能模块组织：
//! - process/ - 进程操作
//! - memory/ - 内存操作
//! - hook/ - Hook操作
//! - stealth/ - 反检测
//! - ai/ - AI学习
//! - esp/ - ESP分析
//! - symbols/ - 符号操作

use rmcp::{
    ServerHandler, tool, tool_router, tool_handler,
    handler::server::wrapper::Parameters,
    ErrorData as McpError,
};
use schemars::JsonSchema;
use serde::Deserialize;
use crate::common::types::ProcessId;
use std::sync::Mutex;

// 全局 HookManager
static HOOK_MANAGER: Mutex<Option<crate::hook::HookManager>> = Mutex::new(None);

// ======================== 参数定义 ========================

#[derive(Deserialize, JsonSchema)]
struct PidParams { pid: u32 }

#[derive(Deserialize, JsonSchema)]
struct InjectParams { pid: u32, lib_path: String }

#[derive(Deserialize, JsonSchema)]
struct HookParams { pid: u32, module: String, symbol: String, hook_type: String }

#[derive(Deserialize, JsonSchema)]
struct ReadMemoryParams { pid: u32, address: String, size: usize }

#[derive(Deserialize, JsonSchema)]
struct WriteMemoryParams { pid: u32, address: String, hex_data: String }

#[derive(Deserialize, JsonSchema)]
struct SearchParams { pid: u32, pattern: String }

#[derive(Deserialize, JsonSchema)]
struct DisasmParams { pid: u32, address: String, count: Option<usize> }

#[derive(Deserialize, JsonSchema)]
struct DumpParams { pid: u32, address: String, size: usize, output: Option<String> }

#[derive(Deserialize, JsonSchema)]
struct SymbolListParams { pid: u32, module: String }

#[derive(Deserialize, JsonSchema)]
struct SymbolFindParams { pid: u32, module: String, symbol: String }

#[derive(Deserialize, JsonSchema)]
struct StealthParams { pid: u32, auto_detect: Option<bool> }

#[derive(Deserialize, JsonSchema)]
struct AILearnParams { action: String, problem: Option<String>, context: Option<String>, solution: Option<String>, success: Option<bool> }

#[derive(Deserialize, JsonSchema)]
struct AIQueryParams { query_type: String, anti_cheat: Option<String>, target: Option<String> }

#[derive(Deserialize, JsonSchema)]
struct ESPAnalyzeParams { pid: u32, template: Option<String> }

#[derive(Deserialize, JsonSchema)]
struct ESPGenerateParams { pid: u32, engine: String }

#[derive(Clone)]
pub struct FridaMcpServer;

#[tool_router]
impl FridaMcpServer {

    // ==================== process/ ====================

    #[tool(description = "获取进程完整信息 (PID, 模块, 线程, 状态)")]
    async fn process_info(&self, Parameters(p): Parameters<PidParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            let pid = ProcessId(p.pid);
            let mut output = String::new();

            // 1. 基本信息
            #[cfg(unix)] {
                let info = crate::inject::get_process_info(pid)
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                output.push_str(&format!("=== 进程信息 ===\n"));
                output.push_str(&format!("PID: {}\n", info.pid));
                output.push_str(&format!("名称: {}\n", info.name));
                output.push_str(&format!("路径: {}\n", info.exe_path));
            }

            // 2. 模块列表
            #[cfg(unix)] {
                output.push_str(&format!("\n=== 模块列表 ===\n"));
                if let Ok(regions) = crate::common::util::parse_proc_maps(pid) {
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

            // 3. 线程列表
            #[cfg(unix)] {
                output.push_str(&format!("\n=== 线程列表 ===\n"));
                if let Ok(threads) = crate::inject::enum_threads(pid) {
                    output.push_str(&format!("{} 个线程:\n", threads.len()));
                    for t in threads.iter().take(10) {
                        output.push_str(&format!("  TID: {}\n", t));
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

    #[tool(description = "注入共享库到目标进程")]
    async fn process_inject(&self, Parameters(p): Parameters<InjectParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            crate::inject::inject_library(ProcessId(p.pid), &p.lib_path)
                .map(|_| format!("已注入 '{}' 到进程 {}", p.lib_path, p.pid))
                .map_err(|e| McpError::internal_error(format!("{}", e), None))
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    // ==================== memory/ ====================

    #[tool(description = "读取目标进程内存 (返回十六进制)")]
    async fn memory_read(&self, Parameters(p): Parameters<ReadMemoryParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            let addr = parse_hex(&p.address)?;
            if p.size > 0x100000 { return Err(McpError::invalid_params("最大 1MB", None)); }
            #[cfg(unix)] {
                let mut s = crate::memory::MemoryScanner::new(ProcessId(p.pid));
                let d = s.dump_region(addr as u64, p.size)
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                Ok(format_hex_dump(&d, addr))
            }
            #[cfg(windows)] {
                Err(McpError::internal_error("Windows 暂不支持", None))
            }
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "写入目标进程内存 (hex_data: 十六进制字符串)")]
    async fn memory_write(&self, Parameters(p): Parameters<WriteMemoryParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            let addr = parse_hex(&p.address)?;
            let data = hex2bytes(&p.hex_data)?;
            #[cfg(unix)] {
                crate::common::util::safe_write_bytes(ProcessId(p.pid), addr, &data)
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
            }
            Ok(format!("已写入 {} 字节到 {:#x}", data.len(), addr))
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "搜索内存中的字节模式")]
    async fn memory_search(&self, Parameters(p): Parameters<SearchParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            let bytes = hex2bytes(&p.pattern)?;
            #[cfg(unix)] {
                let mut s = crate::memory::MemoryScanner::new(ProcessId(p.pid));
                let r = s.search_bytes(&bytes, None)
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                if r.is_empty() { return Ok("未找到匹配".to_string()); }
                let mut output = format!("找到 {} 个匹配:\n", r.len());
                for (i, addr) in r.iter().enumerate().take(20) {
                    output.push_str(&format!("  [{:2}] {:#x}\n", i, addr));
                }
                Ok(output)
            }
            #[cfg(windows)] {
                Err(McpError::internal_error("Windows 暂不支持", None))
            }
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "反汇编指定地址的代码")]
    async fn memory_disasm(&self, Parameters(p): Parameters<DisasmParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            let addr = parse_hex(&p.address)?;
            let count = p.count.unwrap_or(20).min(100);
            #[cfg(unix)] {
                let mut s = crate::memory::MemoryScanner::new(ProcessId(p.pid));
                let bytes = s.dump_region(addr as u64, count * 8)
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                Ok(format_disassembly(&bytes, addr, count))
            }
            #[cfg(windows)] {
                Err(McpError::internal_error("Windows 暂不支持", None))
            }
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "dump内存区域到文件")]
    async fn memory_dump(&self, Parameters(p): Parameters<DumpParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            let addr = parse_hex(&p.address)?;
            if p.size > 0x10000000 { return Err(McpError::invalid_params("最大 256MB", None)); }
            #[cfg(unix)] {
                let mut s = crate::memory::MemoryScanner::new(ProcessId(p.pid));
                let data = s.dump_region(addr as u64, p.size)
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                let path = p.output.unwrap_or_else(|| format!("dump_{:#x}.bin", addr));
                std::fs::write(&path, &data)
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                Ok(format!("已dump {} 字节到 {}", data.len(), path))
            }
            #[cfg(windows)] {
                Err(McpError::internal_error("Windows 暂不支持", None))
            }
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    // ==================== hook/ ====================

    #[tool(description = "设置函数Hook (hook_type: inline/got_plt/java)")]
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
            let mgr = guard.as_mut().unwrap();
            let point = crate::common::types::HookPoint {
                module: p.module, symbol: p.symbol.clone(), offset: 0, hook_type: ht,
            };
            let id = mgr.register_hook(point, |_| {})
                .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
            mgr.install_hook(id)
                .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
            Ok(format!("已Hook {} ({})", p.symbol, p.hook_type))
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    // ==================== stealth/ ====================

    #[tool(description = "应用反检测措施 (auto_detect=true 自动分析并应用)")]
    async fn stealth_apply(&self, Parameters(p): Parameters<StealthParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            if p.auto_detect.unwrap_or(true) {
                #[cfg(unix)] {
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
            crate::anti_detect::apply_stealth()
                .map(|_| "反检测已应用".to_string())
                .map_err(|e| McpError::internal_error(format!("{}", e), None))
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "分析目标进程的反调试技术")]
    async fn stealth_analyze(&self, Parameters(p): Parameters<PidParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            #[cfg(unix)] {
                use crate::anti_detect::SmartStealth;
                let mut smart = SmartStealth::new(ProcessId(p.pid));
                smart.scan()
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                Ok(smart.report())
            }
            #[cfg(windows)] {
                Err(McpError::internal_error("Windows 暂不支持", None))
            }
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
        output.push_str("支持的反作弊:\n");
        output.push_str("  腾讯 ACE/TP/MTP, 米哈游, 网易 Yidun\n");
        output.push_str("  BattlEye, EasyAntiCheat, Vanguard\n");
        Ok(output)
    }

    // ==================== ai/ ====================

    #[tool(description = "AI学习 - 记录经验/反馈问题 (action: report/record)")]
    async fn ai_learn(&self, Parameters(p): Parameters<AILearnParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            let mut system = crate::ai_learning::AILearningSystem::new(None);
            match p.action.as_str() {
                "report" => {
                    let result = system.feedback_loop(
                        &p.problem.unwrap_or_default(),
                        &p.context.unwrap_or_default(),
                        p.solution.as_deref(),
                        p.success.unwrap_or(false),
                    );
                    Ok(format!("已记录: {}", result))
                }
                "record" => {
                    let id = system.record_experience(
                        crate::ai_learning::ExperienceType::AntiCheatBypass,
                        &p.context.unwrap_or_default(),
                        None,
                        &p.problem.unwrap_or_default(),
                        &p.solution.unwrap_or_default(),
                        Vec::new(),
                        true,
                    );
                    Ok(format!("成功经验已记录: {}", id))
                }
                _ => Err(McpError::invalid_params("action: report/record", None))
            }
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "AI查询 - 查询知识库/经验 (type: knowledge/experience/stats)")]
    async fn ai_query(&self, Parameters(p): Parameters<AIQueryParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            let system = crate::ai_learning::AILearningSystem::new(None);
            match p.query_type.as_str() {
                "knowledge" => {
                    if let Some(ref ac) = p.anti_cheat {
                        if let Some(k) = system.query_knowledge(ac) {
                            let mut output = format!("=== {} 知识库 ===\n\n", ac);
                            output.push_str("检测方法:\n");
                            for m in &k.detection_methods { output.push_str(&format!("  - {}\n", m)); }
                            output.push_str("\n绕过方法:\n");
                            for m in &k.bypass_methods { output.push_str(&format!("  - {}\n", m)); }
                            return Ok(output);
                        }
                    }
                    Ok("请指定 anti_cheat 参数".to_string())
                }
                "experience" => {
                    let exps = system.query_experiences(p.target.as_deref(), p.anti_cheat.as_deref(), None);
                    let mut output = format!("{} 条经验:\n", exps.len());
                    for (i, e) in exps.iter().take(5).enumerate() {
                        output.push_str(&format!("{}. {} - {}\n", i+1, e.problem, if e.success {"成功"} else {"失败"}));
                    }
                    Ok(output)
                }
                "stats" => Ok(system.report()),
                _ => Err(McpError::invalid_params("type: knowledge/experience/stats", None))
            }
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    // ==================== esp/ ====================

    #[tool(description = "分析游戏 (自动检测引擎、分析结构)")]
    async fn esp_analyze(&self, Parameters(p): Parameters<ESPAnalyzeParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            #[cfg(unix)] {
                use crate::esp_analyzer::ESPAnalyzer;
                let mut analyzer = ESPAnalyzer::new(ProcessId(p.pid));
                let engine = analyzer.detect_engine()
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                let report = analyzer.report();
                Ok(format!("=== ESP 分析 ===\n\n引擎: {:?}\n\n{}", engine, report))
            }
            #[cfg(windows)] {
                Err(McpError::internal_error("Windows 暂不支持", None))
            }
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

    // ==================== symbols/ ====================

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
                Err(McpError::internal_error("Windows 暂不支持", None))
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
                Err(McpError::internal_error("Windows 暂不支持", None))
            }
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }
}

#[tool_handler(
    name = "frida-rust-mcp",
    version = "0.3.0",
    instructions = "Frida-Rust MCP: 进程分析、内存操作、Hook、反检测、AI学习、ESP分析"
)]
impl ServerHandler for FridaMcpServer {}

// ======================== 辅助函数 ========================

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

fn format_disassembly(bytes: &[u8], base_addr: usize, max_instr: usize) -> String {
    let mut output = format!("Disassembly @ {:#x}:\n\n", base_addr);
    let mut offset = 0;
    let mut count = 0;
    while offset < bytes.len() && count < max_instr {
        let (instr, len) = simple_disasm(&bytes[offset..]);
        output.push_str(&format!("{:#010x}: {}\n", base_addr + offset, instr));
        offset += len;
        count += 1;
    }
    output
}

fn simple_disasm(bytes: &[u8]) -> (String, usize) {
    if bytes.is_empty() { return ("???".to_string(), 1); }
    match bytes[0] {
        0x55 => ("push rbp".to_string(), 1),
        0x5D => ("pop rbp".to_string(), 1),
        0xC3 => ("ret".to_string(), 1),
        0x90 => ("nop".to_string(), 1),
        0xCC => ("int3".to_string(), 1),
        0xE8 if bytes.len() > 4 => {
            let off = i32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
            (format!("call {:+#x}", off), 5)
        },
        _ => (format!("db {:#04x}", bytes[0]), 1),
    }
}
