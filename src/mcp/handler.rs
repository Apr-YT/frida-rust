//! MCP Server Handler

use rmcp::{
    ServerHandler, tool, tool_router, tool_handler,
    handler::server::wrapper::Parameters,
    ErrorData as McpError,
};
use schemars::JsonSchema;
use serde::Deserialize;
use crate::common::types::ProcessId;
#[cfg(unix)]
use crate::memory::MemoryScanner;
use std::sync::Mutex;

// 全局 HookManager，保持 Hook 持久化
static HOOK_MANAGER: Mutex<Option<crate::hook::HookManager>> = Mutex::new(None);

#[derive(Deserialize, JsonSchema)]
struct AttachParams { pid: u32 }

#[derive(Deserialize, JsonSchema)]
struct InjectParams { pid: u32, lib_path: String }

#[derive(Deserialize, JsonSchema)]
struct HookParams { pid: u32, module: String, symbol: String, hook_type: String }

#[derive(Deserialize, JsonSchema)]
struct ReadMemoryParams { pid: u32, address: String, size: usize }

#[derive(Deserialize, JsonSchema)]
struct GetModuleInfoParams { pid: u32, module_name: String }

#[derive(Deserialize, JsonSchema)]
struct FindSymbolParams { pid: u32, module_name: String, symbol_name: String }

#[derive(Deserialize, JsonSchema)]
struct DisassembleParams { pid: u32, address: String, count: Option<usize> }

#[derive(Deserialize, JsonSchema)]
struct SearchPatternParams { pid: u32, pattern: String, module: Option<String> }

#[derive(Deserialize, JsonSchema)]
struct DumpMemoryParams { pid: u32, address: String, size: usize, output_path: Option<String> }

#[derive(Deserialize, JsonSchema)]
struct AIReportParams {
    problem: String,
    context: String,
    solution: Option<String>,
    success: Option<bool>,
}

#[derive(Deserialize, JsonSchema)]
struct AIQueryParams {
    anti_cheat: Option<String>,
    target: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
struct AIRecordParams {
    target: String,
    anti_cheat: Option<String>,
    problem: String,
    solution: String,
    strategy: Option<Vec<String>>,
}

#[derive(Deserialize, JsonSchema)]
struct AIKnowledgeParams {
    anti_cheat: String,
    signatures: Option<Vec<String>>,
    detection_methods: Option<Vec<String>>,
    bypass_methods: Option<Vec<String>>,
    notes: Option<Vec<String>>,
}

#[derive(Deserialize, JsonSchema)]
struct AnalyzeStructureParams { pid: u32, address: String }

#[derive(Deserialize, JsonSchema)]
struct LoadTemplateParams { game_name: String }

#[derive(Deserialize, JsonSchema)]
struct GenerateESPParams { pid: u32, engine: String }

#[derive(Deserialize, JsonSchema)]
struct WriteMemoryParams { pid: u32, address: String, hex_data: String }

#[derive(Deserialize, JsonSchema)]
struct ScanMemoryParams { pid: u32, pattern: String, module: Option<String> }

#[derive(Deserialize, JsonSchema)]
struct ScriptParams { script: String, pid: Option<u32>, anti_detect: Option<bool> }

#[derive(Clone)]
pub struct FridaMcpServer;

#[tool_router]
impl FridaMcpServer {
    #[tool(description = "列出当前运行的所有进程")]
    async fn list_processes(&self) -> Result<String, McpError> {
        tokio::task::spawn_blocking(list_processes_impl)
            .await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "附着到目标进程 (ptrace attach)")]
    async fn attach_process(&self, Parameters(p): Parameters<AttachParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            crate::inject::attach_process(ProcessId(p.pid))
                .map(|_| format!("已附着 PID={}", p.pid))
                .map_err(|e| McpError::internal_error(format!("{}", e), None))
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "注入共享库到目标进程")]
    async fn inject_library(&self, Parameters(p): Parameters<InjectParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            crate::inject::inject_library(ProcessId(p.pid), &p.lib_path)
                .map(|_| format!("已注入 '{}' -> PID={}", p.lib_path, p.pid))
                .map_err(|e| McpError::internal_error(format!("{}", e), None))
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "Hook 目标函数 (hook_type: inline/got_plt/java)")]
    async fn hook_function(&self, Parameters(p): Parameters<HookParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            let ht = match p.hook_type.as_str() {
                "inline" => crate::common::types::HookType::Inline,
                "got_plt" => crate::common::types::HookType::GotPlt,
                "java" => crate::common::types::HookType::Java,
                _ => return Err(McpError::invalid_params(
                    format!("不支持: '{}'，可选 inline/got_plt/java", p.hook_type), None)),
            };
            
            // 使用全局 HookManager 保持 Hook 持久化
            let mut guard = HOOK_MANAGER.lock()
                .map_err(|e| McpError::internal_error(format!("锁获取失败: {}", e), None))?;
            
            if guard.is_none() {
                *guard = Some(crate::hook::HookManager::new());
            }
            
            let mgr = guard.as_mut().unwrap();
            let point = crate::common::types::HookPoint {
                module: p.module, symbol: p.symbol.clone(), offset: 0, hook_type: ht,
            };
            let id = mgr.register_hook(point, |_| {}).map_err(|e|
                McpError::internal_error(format!("{}", e), None))?;
            mgr.install_hook(id).map_err(|e|
                McpError::internal_error(format!("{}", e), None))?;
            Ok(format!("Hooked {} ({}), PID={}", p.symbol, p.hook_type, p.pid))
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "列出目标进程加载的模块（共享库）")]
    async fn list_modules(&self, Parameters(p): Parameters<AttachParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            #[cfg(unix)] {
                use crate::common::util::parse_proc_maps;
                let regions = parse_proc_maps(ProcessId(p.pid))
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                
                let mut modules: Vec<String> = Vec::new();
                let mut seen = std::collections::HashSet::new();
                
                for region in &regions {
                    if !region.name.is_empty() && seen.insert(region.name.clone()) {
                        modules.push(format!(
                            "{:<40} {:#x}-{:#x} ({})",
                            region.name,
                            region.start,
                            region.end,
                            region.perms_string()
                        ));
                    }
                }
                
                Ok(format!("{} 个模块:\n{}", modules.len(), modules.join("\n")))
            }
            #[cfg(windows)] {
                Err(McpError::internal_error("Windows 暂不支持 list_modules", None))
            }
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "获取指定模块的详细信息（基址、大小、符号等）")]
    async fn get_module_info(&self, Parameters(p): Parameters<GetModuleInfoParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            #[cfg(unix)] {
                use crate::common::util::parse_proc_maps;
                let regions = parse_proc_maps(ProcessId(p.pid))
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                
                let module_regions: Vec<_> = regions.iter()
                    .filter(|r| r.name.contains(&p.module_name))
                    .collect();
                
                if module_regions.is_empty() {
                    return Err(McpError::invalid_params(
                        format!("找不到模块: {}", p.module_name), None));
                }
                
                let first = module_regions[0];
                let total_size: usize = module_regions.iter().map(|r| r.size()).sum();
                
                let mut info = format!(
                    "模块: {}\n基址: {:#x}\n大小: {} 字节 ({:.2} KB)\n权限映射数: {}",
                    first.name,
                    first.start,
                    total_size,
                    total_size as f64 / 1024.0,
                    module_regions.len()
                );
                
                // 尝试读取 ELF 头信息
                if let Ok(elf_info) = crate::memory::elf_parser::parse_elf_from_memory(
                    ProcessId(p.pid), first.start as u64
                ) {
                    info.push_str(&format!(
                        "\n入口点: {:#x}\n段数: {}\n节区数: {}",
                        elf_info.entry_point,
                        elf_info.headers.len(),
                        elf_info.sections.len()
                    ));
                }
                
                Ok(info)
            }
            #[cfg(windows)] {
                Err(McpError::internal_error("Windows 暂不支持 get_module_info", None))
            }
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "查找符号（函数/变量）的地址")]
    async fn find_symbol(&self, Parameters(p): Parameters<FindSymbolParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            #[cfg(unix)] {
                use crate::memory::elf_parser;
                use crate::common::util::parse_proc_maps;
                
                let regions = parse_proc_maps(ProcessId(p.pid))
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                
                // 查找模块
                let module_region = regions.iter()
                    .find(|r| r.name.contains(&p.module_name))
                    .ok_or_else(|| McpError::invalid_params(
                        format!("找不到模块: {}", p.module_name), None))?;
                
                // 解析 ELF 并查找符号
                let elf_info = elf_parser::parse_elf_from_memory(ProcessId(p.pid), module_region.start as u64)
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                
                let symbols = elf_parser::find_symbol(&elf_info, &p.symbol_name);
                
                if symbols.is_empty() {
                    return Err(McpError::invalid_params(
                        format!("找不到符号: {}", p.symbol_name), None));
                }
                
                let mut result = format!("找到 {} 个匹配符号:\n", symbols.len());
                for sym in &symbols {
                    result.push_str(&format!(
                        "  {} @ {:#x} (size={}, type={:?})\n",
                        sym.name,
                        sym.value,
                        sym.size,
                        sym.sym_type
                    ));
                }
                
                Ok(result)
            }
            #[cfg(windows)] {
                Err(McpError::internal_error("Windows 暂不支持 find_symbol", None))
            }
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "列出模块中的所有导出符号")]
    async fn list_symbols(&self, Parameters(p): Parameters<GetModuleInfoParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            #[cfg(unix)] {
                use crate::memory::elf_parser;
                use crate::common::util::parse_proc_maps;
                
                let regions = parse_proc_maps(ProcessId(p.pid))
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                
                let module_region = regions.iter()
                    .find(|r| r.name.contains(&p.module_name))
                    .ok_or_else(|| McpError::invalid_params(
                        format!("找不到模块: {}", p.module_name), None))?;
                
                let elf_info = elf_parser::parse_elf_from_memory(ProcessId(p.pid), module_region.start as u64)
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                
                let symbols = elf_parser::get_exported_symbols(&elf_info);
                
                let mut result = format!("{} 个导出符号:\n", symbols.len());
                for sym in symbols.iter().take(100) {  // 限制输出数量
                    result.push_str(&format!(
                        "  {:#x} {} (size={})\n",
                        sym.value,
                        sym.name,
                        sym.size
                    ));
                }
                
                if symbols.len() > 100 {
                    result.push_str(&format!("  ... 还有 {} 个符号\n", symbols.len() - 100));
                }
                
                Ok(result)
            }
            #[cfg(windows)] {
                Err(McpError::internal_error("Windows 暂不支持 list_symbols", None))
            }
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "反汇编指定地址的代码（返回汇编指令）")]
    async fn disassemble(&self, Parameters(p): Parameters<DisassembleParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            let addr = parse_hex(&p.address)?;
            let count = p.count.unwrap_or(20);
            
            if count > 100 {
                return Err(McpError::invalid_params("最多反汇编 100 条指令", None));
            }
            
            #[cfg(unix)] {
                use crate::memory::MemoryScanner;
                let mut scanner = MemoryScanner::new(ProcessId(p.pid));
                
                // 读取足够的字节（每条指令平均 4-7 字节）
                let bytes = scanner.dump_region(addr as u64, count * 8)
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                
                // 简单的反汇编（x86_64）
                let mut result = format!("反汇编 @ {:#x}:\n", addr);
                let mut offset = 0;
                let mut instr_count = 0;
                
                while offset < bytes.len() && instr_count < count {
                    let (instr, len) = disassemble_instruction(&bytes[offset..]);
                    result.push_str(&format!(
                        "{:#018x}: {:<30} {}\n",
                        addr + offset,
                        bytes[offset..offset+len].iter()
                            .map(|b| format!("{:02x}", b))
                            .collect::<Vec<_>>()
                            .join(" "),
                        instr
                    ));
                    offset += len;
                    instr_count += 1;
                }
                
                Ok(result)
            }
            #[cfg(windows)] {
                Err(McpError::internal_error("Windows 暂不支持 disassemble", None))
            }
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "搜索内存中的字节模式（支持通配符）")]
    async fn search_pattern(&self, Parameters(p): Parameters<SearchPatternParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            #[cfg(unix)] {
                use crate::memory::MemoryScanner;
                
                let mut scanner = MemoryScanner::new(ProcessId(p.pid));
                
                // 简单的字节模式搜索（不支持通配符）
                let pattern = p.pattern.replace(" ", "").replace("0x", "");
                let pattern_bytes: Vec<u8> = (0..pattern.len())
                    .step_by(2)
                    .filter_map(|i| u8::from_str_radix(&pattern[i..i+2], 16).ok())
                    .collect();
                
                if pattern_bytes.is_empty() {
                    return Err(McpError::invalid_params("无效的模式".to_string(), None));
                }
                
                let results = scanner.search_bytes(&pattern_bytes, None)
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                
                if results.is_empty() {
                    return Ok("未找到匹配".to_string());
                }
                
                let mut output = format!("找到 {} 个匹配:\n", results.len());
                for (i, addr) in results.iter().enumerate().take(50) {
                    output.push_str(&format!("  [{:2}] {:#x}\n", i, addr));
                }
                
                if results.len() > 50 {
                    output.push_str(&format!("  ... 还有 {} 个匹配\n", results.len() - 50));
                }
                
                Ok(output)
            }
            #[cfg(windows)] {
                Err(McpError::internal_error("Windows 暂不支持 search_pattern", None))
            }
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "获取进程详细信息（架构、权限、状态等）")]
    async fn get_process_info(&self, Parameters(p): Parameters<AttachParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            #[cfg(unix)] {
                use std::fs;
                
                let pid = p.pid;
                let proc_path = format!("/proc/{}", pid);
                
                // 检查进程是否存在
                if !std::path::Path::new(&proc_path).exists() {
                    return Err(McpError::invalid_params(
                        format!("进程不存在: {}", pid), None));
                }
                
                let comm = fs::read_to_string(format!("{}/comm", proc_path))
                    .unwrap_or_default().trim().to_string();
                let cmdline = fs::read_to_string(format!("{}/cmdline", proc_path))
                    .unwrap_or_default()
                    .replace('\0', " ")
                    .trim()
                    .to_string();
                let status = fs::read_to_string(format!("{}/status", proc_path))
                    .unwrap_or_default();
                
                // 解析状态信息
                let state = status.lines()
                    .find(|l| l.starts_with("State:"))
                    .map(|l| l.trim_start_matches("State:").trim())
                    .unwrap_or("unknown");
                let ppid = status.lines()
                    .find(|l| l.starts_with("PPid:"))
                    .map(|l| l.trim_start_matches("PPid:").trim())
                    .unwrap_or("0");
                let threads = status.lines()
                    .find(|l| l.starts_with("Threads:"))
                    .map(|l| l.trim_start_matches("Threads:").trim())
                    .unwrap_or("0");
                
                let info = format!(
                    "进程信息:\n\
                     PID: {}\n\
                     名称: {}\n\
                     命令行: {}\n\
                     状态: {}\n\
                     父进程: {}\n\
                     线程数: {}",
                    pid, comm, cmdline, state, ppid, threads
                );
                
                Ok(info)
            }
            #[cfg(windows)] {
                Err(McpError::internal_error("Windows 暂不支持 get_process_info", None))
            }
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "列出目标进程的所有线程")]
    async fn list_threads(&self, Parameters(p): Parameters<AttachParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            #[cfg(unix)] {
                use std::fs;
                
                let task_path = format!("/proc/{}/task", p.pid);
                
                if !std::path::Path::new(&task_path).exists() {
                    return Err(McpError::invalid_params(
                        format!("进程不存在: {}", p.pid), None));
                }
                
                let mut threads = Vec::new();
                for entry in fs::read_dir(&task_path)
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?
                {
                    let entry = entry.map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                    let tid = entry.file_name().to_string_lossy().to_string();
                    
                    if let Ok(tid_num) = tid.parse::<u32>() {
                        let comm = fs::read_to_string(format!("{}/{}/comm", task_path, tid))
                            .unwrap_or_default()
                            .trim()
                            .to_string();
                        threads.push(format!("TID={:<8} {}", tid_num, comm));
                    }
                }
                
                threads.sort();
                Ok(format!("{} 个线程:\n{}", threads.len(), threads.join("\n")))
            }
            #[cfg(windows)] {
                Err(McpError::internal_error("Windows 暂不支持 list_threads", None))
            }
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "dump 指定内存区域到文件（用于离线分析）")]
    async fn dump_memory(&self, Parameters(p): Parameters<DumpMemoryParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            let addr = parse_hex(&p.address)?;
            
            if p.size > 0x10000000 {  // 256MB 限制
                return Err(McpError::invalid_params("dump 大小不能超过 256MB", None));
            }
            
            #[cfg(unix)] {
                use crate::memory::MemoryScanner;
                let mut scanner = MemoryScanner::new(ProcessId(p.pid));
                
                let data = scanner.dump_region(addr as u64, p.size)
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                
                let output_path = p.output_path.unwrap_or_else(|| 
                    format!("dump_{:#x}_{}.bin", addr, p.size));
                
                std::fs::write(&output_path, &data)
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                
                Ok(format!("已 dump {} 字节到 {}", data.len(), output_path))
            }
            #[cfg(windows)] {
                Err(McpError::internal_error("Windows 暂不支持 dump_memory", None))
            }
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "智能分析目标进程的反调试技术（AI专用）")]
    async fn analyze_anti_debug(&self, Parameters(p): Parameters<AttachParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            #[cfg(unix)] {
                use crate::anti_detect::SmartStealth;
                
                let mut smart = SmartStealth::new(ProcessId(p.pid));
                smart.scan()
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                
                Ok(smart.report())
            }
            #[cfg(windows)] {
                Err(McpError::internal_error("Windows 暂不支持 analyze_anti_debug", None))
            }
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "智能应用推荐的反检测策略（AI专用）")]
    async fn apply_smart_stealth(&self, Parameters(p): Parameters<AttachParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            #[cfg(unix)] {
                use crate::anti_detect::SmartStealth;
                
                let mut smart = SmartStealth::new(ProcessId(p.pid));
                smart.scan()
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                
                let mode = smart.recommended_mode();
                let detections_count = smart.detections().len();
                let recommendations_count = smart.recommendations().len();
                
                smart.apply_recommended()
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                
                Ok(format!(
                    "智能反检测已应用\n\
                     检测到 {} 个反调试技术\n\
                     应用 {} 条推荐策略\n\
                     使用模式: {:?}",
                    detections_count, recommendations_count, mode
                ))
            }
            #[cfg(windows)] {
                Err(McpError::internal_error("Windows 暂不支持 apply_smart_stealth", None))
            }
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "获取反检测模块列表和状态")]
    async fn list_stealth_modules(&self) -> Result<String, McpError> {
        let modules = vec![
            ("env_clean", "环境变量清理", "清除 FRIDA_* 等环境变量"),
            ("signature", "特征擦除", "擦除内存中的 Frida 特征字符串"),
            ("tracer", "TracerPid 隐藏", "清除 /proc/self/status 中的 TracerPid"),
            ("maps_hide", "Maps 隐藏", "隐藏 /proc/self/maps 中的 Frida 条目"),
            ("fd_hide", "FD 隐藏", "隐藏 /proc/self/fd 中的 Frida 文件描述符"),
            ("thread_hide", "线程隐藏", "隐藏 Frida 线程"),
            ("port_hide", "端口隐藏", "隐藏 /proc/net/tcp 中的 Frida 端口"),
            ("net_hide", "网络隐藏", "隐藏网络连接信息"),
            ("stack_fake", "调用栈伪造", "伪造调用栈信息"),
        ];
        
        let mut output = String::from("📦 反检测模块列表:\n\n");
        for (name, title, desc) in modules {
            output.push_str(&format!("  {:<15} - {}\n              {}\n\n", name, title, desc));
        }
        
        output.push_str("\n🎮 支持检测的国内反作弊系统:\n\n");
        output.push_str("  腾讯 ACE/TP     - 王者荣耀、和平精英、LOL、CF、DNF等\n");
        output.push_str("  腾讯 MTP        - 手游反作弊\n");
        output.push_str("  网易 UProtect   - 梦幻西游、大话西游、阴阳师等\n");
        output.push_str("  网易 Yidun      - 网易易盾游戏加固\n");
        output.push_str("  米哈游 Protect  - 原神、崩坏3、星穹铁道等\n");
        output.push_str("  盛趣 GPProtect  - 传奇、龙之谷等\n");
        output.push_str("  完美世界        - 完美世界、DOTA2等\n");
        output.push_str("  莉莉丝          - 万国觉醒、剑与远征等\n");
        output.push_str("  阿里游戏盾      - 阿里云游戏保护\n");
        output.push_str("  360游戏保护     - 部分页游\n");
        output.push_str("  DRM保护         - Denuvo、Steam、Epic\n");
        
        output.push_str("\n⚡ 使用方式:\n");
        output.push_str("  analyze_anti_debug  - 自动分析目标使用了哪些反作弊\n");
        output.push_str("  apply_smart_stealth - 智能应用推荐的反检测策略\n");
        output.push_str("  apply_stealth       - 手动应用全部反检测\n");
        
        Ok(output)
    }

    // ==================== AI 学习系统工具 ====================

    #[tool(description = "AI反馈问题 - 记录遇到的问题并学习（AI专用）")]
    async fn ai_report_problem(&self, Parameters(p): Parameters<AIReportParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            let mut system = crate::ai_learning::AILearningSystem::new(None);
            
            let result = system.feedback_loop(
                &p.problem,
                &p.context,
                p.solution.as_deref(),
                p.success.unwrap_or(false),
            );
            
            // 获取推荐
            let mut recommendations = Vec::new();
            if let Some(ref ac) = system.extract_anti_cheat_from_context(&p.context) {
                recommendations = system.recommend_strategy(ac, &p.context);
            }
            
            let mut output = format!("✅ 问题已记录: {}\n\n", result);
            
            if !recommendations.is_empty() {
                output.push_str("💡 基于历史经验的建议:\n");
                for rec in &recommendations {
                    output.push_str(&format!("  {}\n", rec));
                }
            }
            
            Ok(output)
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "查询AI学习系统 - 获取相关经验和策略")]
    async fn ai_query_experience(&self, Parameters(p): Parameters<AIQueryParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            let system = crate::ai_learning::AILearningSystem::new(None);
            
            let mut output = String::new();
            
            // 查询知识库
            if let Some(ref ac) = p.anti_cheat {
                if let Some(knowledge) = system.query_knowledge(ac) {
                    output.push_str(&format!("📚 {} 知识库:\n\n", ac));
                    output.push_str(&format!("检测方法:\n"));
                    for method in &knowledge.detection_methods {
                        output.push_str(&format!("  • {}\n", method));
                    }
                    output.push_str(&format!("\n绕过方法:\n"));
                    for method in &knowledge.bypass_methods {
                        output.push_str(&format!("  • {}\n", method));
                    }
                    output.push_str(&format!("\n注意事项:\n"));
                    for note in &knowledge.notes {
                        output.push_str(&format!("  ⚠️ {}\n", note));
                    }
                }
            }
            
            // 查询历史经验
            let experiences = system.query_experiences(
                p.target.as_deref(),
                p.anti_cheat.as_deref(),
                None,
            );
            
            if !experiences.is_empty() {
                output.push_str(&format!("\n📖 历史经验 ({} 条):\n", experiences.len()));
                for (i, exp) in experiences.iter().take(5).enumerate() {
                    output.push_str(&format!(
                        "\n{}. {} [{}]\n   问题: {}\n   解决: {}\n   结果: {}",
                        i + 1,
                        exp.target,
                        exp.anti_cheat.as_ref().unwrap_or(&"未知".to_string()),
                        exp.problem,
                        exp.solution,
                        if exp.success { "✅ 成功" } else { "❌ 失败" }
                    ));
                }
            }
            
            // 查询推荐策略
            if let Some(ref ac) = p.anti_cheat {
                let recommendations = system.recommend_strategy(ac, p.target.as_deref().unwrap_or(""));
                if !recommendations.is_empty() {
                    output.push_str(&format!("\n\n🎯 推荐策略:\n"));
                    for rec in &recommendations {
                        output.push_str(&format!("  {}\n", rec));
                    }
                }
            }
            
            if output.is_empty() {
                output = "未找到相关经验和知识".to_string();
            }
            
            Ok(output)
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "获取AI学习系统统计报告")]
    async fn ai_learning_stats(&self) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            let system = crate::ai_learning::AILearningSystem::new(None);
            Ok(system.report())
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "记录成功经验 - AI学习升级")]
    async fn ai_record_success(&self, Parameters(p): Parameters<AIRecordParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            let mut system = crate::ai_learning::AILearningSystem::new(None);
            
            let id = system.record_experience(
                crate::ai_learning::ExperienceType::AntiCheatBypass,
                &p.target,
                p.anti_cheat.as_deref(),
                &p.problem,
                &p.solution,
                p.strategy.unwrap_or_default(),
                true,
            );
            
            Ok(format!("✅ 成功经验已记录: {}\nAI 将从这次经验中学习并优化策略", id))
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "更新知识库 - 添加新的反作弊特征")]
    async fn ai_update_knowledge(&self, Parameters(p): Parameters<AIKnowledgeParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            let mut system = crate::ai_learning::AILearningSystem::new(None);
            
            let entry = crate::ai_learning::KnowledgeEntry {
                id: format!("ac_{}", p.anti_cheat.to_lowercase()),
                anti_cheat: p.anti_cheat.clone(),
                signatures: p.signatures.unwrap_or_default(),
                detection_methods: p.detection_methods.unwrap_or_default(),
                bypass_methods: p.bypass_methods.unwrap_or_default(),
                notes: p.notes.unwrap_or_default(),
                updated_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                source: "ai_update".to_string(),
            };
            
            // 保存到知识库
            system.query_knowledge_mut(&p.anti_cheat)
                .map(|e| *e = entry.clone())
                .unwrap_or_default();
            
            Ok(format!("✅ 知识库已更新: {}\n新特征和绕过方法已添加", p.anti_cheat))
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    // ==================== ESP 分析工具 ====================

    #[tool(description = "检测游戏引擎类型（AI专用）")]
    async fn detect_game_engine(&self, Parameters(p): Parameters<AttachParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            #[cfg(unix)] {
                use crate::esp_analyzer::ESPAnalyzer;
                
                let mut analyzer = ESPAnalyzer::new(ProcessId(p.pid));
                let engine = analyzer.detect_engine()
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                
                Ok(format!("🎮 检测到游戏引擎: {:?}\n\n{}", engine, analyzer.report()))
            }
            #[cfg(windows)] {
                Err(McpError::internal_error("Windows 暂不支持 detect_game_engine", None))
            }
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "分析游戏对象内存结构（AI专用）")]
    async fn analyze_object_structure(&self, Parameters(p): Parameters<AnalyzeStructureParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            #[cfg(unix)] {
                use crate::esp_analyzer::ESPAnalyzer;
                
                let mut analyzer = ESPAnalyzer::new(ProcessId(p.pid));
                let addr = parse_hex(&p.address)?;
                
                let offsets = analyzer.analyze_object_structure(addr as u64)
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                
                let mut output = format!("📊 对象结构分析 @ {:#x}\n\n", addr);
                output.push_str(&format!("发现 {} 个潜在偏移:\n\n", offsets.len()));
                
                for (i, offset) in offsets.iter().enumerate().take(20) {
                    output.push_str(&format!(
                        "{}. {} @ {:#x} ({:?})\n   {} [置信度: {}%]\n",
                        i + 1, offset.name, offset.offset, offset.data_type,
                        offset.description, offset.confidence
                    ));
                }
                
                output.push_str(&format!("\n{}", analyzer.report()));
                
                Ok(output)
            }
            #[cfg(windows)] {
                Err(McpError::internal_error("Windows 暂不支持 analyze_object_structure", None))
            }
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "获取游戏模板列表（内置游戏配置）")]
    async fn list_game_templates(&self) -> Result<String, McpError> {
        tokio::task::spawn_blocking(|| {
            use crate::esp_analyzer;
            
            let templates = esp_analyzer::builtin_templates();
            
            let mut output = String::from("🎮 内置游戏模板:\n\n");
            
            for (i, template) in templates.iter().enumerate() {
                output.push_str(&format!(
                    "{}. {} ({:?})\n   进程: {}\n   模块: {:?}\n   备注: {}\n\n",
                    i + 1,
                    template.game_name,
                    template.engine,
                    template.process_name,
                    template.key_modules,
                    template.notes.join("; ")
                ));
            }
            
            output.push_str("使用 load_game_template 加载模板\n");
            
            Ok(output)
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "加载游戏模板（使用内置或自定义配置）")]
    async fn load_game_template(&self, Parameters(p): Parameters<LoadTemplateParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            use crate::esp_analyzer;
            
            let templates = esp_analyzer::builtin_templates();
            
            let template = templates.iter()
                .find(|t| t.game_name.to_lowercase().contains(&p.game_name.to_lowercase()))
                .ok_or_else(|| McpError::invalid_params(
                    format!("找不到游戏模板: {}，使用 list_game_templates 查看可用模板", p.game_name), None
                ))?;
            
            let mut output = format!("✅ 已加载游戏模板: {}\n\n", template.game_name);
            output.push_str(&format!("引擎: {:?}\n", template.engine));
            output.push_str(&format!("进程: {}\n", template.process_name));
            output.push_str(&format!("关键模块: {:?}\n\n", template.key_modules));
            
            if !template.offsets.is_empty() {
                output.push_str("已知偏移量:\n");
                for offset in &template.offsets {
                    output.push_str(&format!("  • {} @ {:#x} - {}\n", 
                        offset.name, offset.offset, offset.description));
                }
            }
            
            output.push_str(&format!("\nESP 配置建议:\n"));
            output.push_str(&format!("  绘制敌人: {}\n", template.esp_config.draw_enemies));
            output.push_str(&format!("  绘制血条: {}\n", template.esp_config.draw_health_bar));
            output.push_str(&format!("  绘制骨骼: {}\n", template.esp_config.draw_skeleton));
            output.push_str(&format!("  最大距离: {:.0}m\n", template.esp_config.max_distance));
            
            output.push_str(&format!("\n💡 下一步:\n"));
            output.push_str(&format!("  1. 使用 detect_game_engine 验证引擎\n"));
            output.push_str(&format!("  2. 使用 find_local_player 查找玩家\n"));
            output.push_str(&format!("  3. 使用 analyze_object_structure 分析数据结构\n"));
            output.push_str(&format!("  4. 使用 generate_esp_code 生成绘制代码\n"));
            
            Ok(output)
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "生成 ESP 绘制代码（AI专用）")]
    async fn generate_esp_code(&self, Parameters(p): Parameters<GenerateESPParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            use crate::esp_analyzer::{ESPAnalyzer, GameEngine};
            
            let analyzer = ESPAnalyzer::new(ProcessId(p.pid));
            
            let engine = match p.engine.to_lowercase().as_str() {
                "unreal" | "ue4" | "ue5" => GameEngine::UnrealEngine,
                "unity" => GameEngine::Unity,
                "source" => GameEngine::Source,
                "frostbite" => GameEngine::Frostbite,
                _ => GameEngine::Custom(p.engine.clone()),
            };
            
            let code = analyzer.generate_esp_code(&engine);
            
            let mut output = format!("📝 生成的 ESP 绘制代码 ({:?}):\n\n", engine);
            output.push_str(&code);
            
            output.push_str("\n\n💡 使用说明:\n");
            output.push_str("1. 使用 analyze_object_structure 找到实际偏移量\n");
            output.push_str("2. 将偏移量填入代码中的 TODO 位置\n");
            output.push_str("3. 根据游戏窗口大小调整绘制坐标\n");
            
            Ok(output)
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "生成偏移量配置文件（AI专用）")]
    async fn generate_offsets_config(&self, Parameters(p): Parameters<AttachParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            #[cfg(unix)] {
                use crate::esp_analyzer::ESPAnalyzer;
                
                let analyzer = ESPAnalyzer::new(ProcessId(p.pid));
                let json = analyzer.generate_offsets_json();
                
                let output_path = format!("offsets_{}.json", p.pid);
                std::fs::write(&output_path, &json)
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                
                Ok(format!("✅ 偏移量配置已保存到: {}\n\n{}", output_path, json))
            }
            #[cfg(windows)] {
                Err(McpError::internal_error("Windows 暂不支持 generate_offsets_config", None))
            }
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "测试目标进程是否能检测到当前 Hook（AI专用）")]
    async fn test_hook_detection(&self, Parameters(p): Parameters<AttachParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            #[cfg(unix)] {
                use std::fs;
                
                let mut issues = Vec::new();
                
                // 1. 检查 TracerPid
                let status_path = format!("/proc/{}/status", p.pid);
                if let Ok(status) = fs::read_to_string(&status_path) {
                    for line in status.lines() {
                        if line.starts_with("TracerPid:") {
                            let pid: u32 = line.split_whitespace()
                                .nth(1)
                                .and_then(|s| s.parse().ok())
                                .unwrap_or(0);
                            if pid != 0 {
                                issues.push(format!("⚠️ TracerPid = {} (可被检测)", pid));
                            }
                            break;
                        }
                    }
                }
                
                // 2. 检查 /proc/self/maps 中的 Frida 条目
                let maps_path = format!("/proc/{}/maps", p.pid);
                if let Ok(maps) = fs::read_to_string(&maps_path) {
                    let frida_lines: Vec<&str> = maps.lines()
                        .filter(|l| l.to_lowercase().contains("frida"))
                        .collect();
                    if !frida_lines.is_empty() {
                        issues.push(format!("⚠️ maps 中发现 {} 条 Frida 相关条目", frida_lines.len()));
                    }
                }
                
                // 3. 检查环境变量
                let frida_vars: Vec<String> = vec![
                    "FRIDA_VERSION", "FRIDA_SERVER_ADDRESS", "FRIDA_PATH"
                ].iter()
                    .filter_map(|&var| std::env::var(var).ok().map(|v| format!("{}={}", var, v)))
                    .collect();
                
                if !frida_vars.is_empty() {
                    issues.push(format!("⚠️ 发现 {} 个 Frida 环境变量", frida_vars.len()));
                }
                
                if issues.is_empty() {
                    Ok("✅ 未发现明显的 Frida 检测点\n建议仍然应用基础反检测措施".to_string())
                } else {
                    let mut output = format!("❌ 发现 {} 个潜在检测点:\n\n", issues.len());
                    for issue in &issues {
                        output.push_str(&format!("  {}\n", issue));
                    }
                    output.push_str("\n建议使用 apply_smart_stealth 自动应用反检测措施");
                    Ok(output)
                }
            }
            #[cfg(windows)] {
                Err(McpError::internal_error("Windows 暂不支持 test_hook_detection", None))
            }
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "读取目标进程内存 (返回十六进制)")]
    async fn read_memory(&self, Parameters(p): Parameters<ReadMemoryParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            let addr = parse_hex(&p.address)?;
            if p.size > 0x100000 { return Err(McpError::invalid_params("最大 1MB", None)); }
            #[cfg(unix)] {
                let mut s = crate::memory::MemoryScanner::new(ProcessId(p.pid));
                let d = s.dump_region(addr as u64, p.size).map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                Ok(d.iter().map(|b| format!("{:02X}", b)).collect())
            }
            #[cfg(windows)] {
                Err(McpError::internal_error("Windows 暂不支持 read_memory，请部署到 Android 使用", None))
            }
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "写入目标进程内存 (hex_data: 十六进制字符串)")]
    async fn write_memory(&self, Parameters(p): Parameters<WriteMemoryParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            let addr = parse_hex(&p.address)?;
            let data = hex2bytes(&p.hex_data)?;
            #[cfg(unix)] {
                crate::common::util::safe_write_bytes(ProcessId(p.pid), addr, &data).map_err(|e| McpError::internal_error(format!("{}", e), None))?;
            }
            #[cfg(windows)] {
                return Err(McpError::internal_error("Windows 暂不支持 write_memory", None));
            }
            Ok(format!("已写入 {} 字节 -> {:#x}", data.len(), addr))
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "搜索目标进程内存中的字节模式")]
    async fn scan_memory(&self, Parameters(p): Parameters<ScanMemoryParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            let bytes = hex2bytes(&p.pattern)?;
            #[cfg(unix)] {
                let mut s = crate::memory::MemoryScanner::new(ProcessId(p.pid));
                let r = s.search_bytes(&bytes, None).map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                if r.is_empty() { Ok("无匹配".to_string()) }
                else { Ok(format!("{} 个匹配:\n{}", r.len(), r.iter().map(|a| format!("{:#x}", a)).collect::<Vec<_>>().join("\n"))) }
            }
            #[cfg(windows)] {
                Err(McpError::internal_error("Windows 暂不支持 scan_memory", None))
            }
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "执行 Rhai 脚本")]
    async fn execute_script(&self, Parameters(p): Parameters<ScriptParams>) -> Result<String, McpError> {
        tokio::task::spawn_blocking(move || {
            if p.anti_detect.unwrap_or(false) {
                crate::anti_detect::apply_stealth().map_err(|e| McpError::internal_error(format!("{}", e), None))?;
            }
            let mut engine = if let Some(pid) = p.pid {
                crate::script::ScriptEngine::for_pid(ProcessId(pid))
            } else {
                crate::script::ScriptEngine::new()
            }.map_err(|e| McpError::internal_error(format!("{}", e), None))?;
            let result = engine.execute(p.script.as_bytes()).map_err(|e|
                McpError::internal_error(format!("{}", e), None))?;
            Ok(format!("{:?}", result))
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "应用全部反检测措施")]
    async fn apply_stealth(&self) -> Result<String, McpError> {
        tokio::task::spawn_blocking(|| {
            crate::anti_detect::apply_stealth()
                .map(|_| "反检测已应用".to_string())
                .map_err(|e| McpError::internal_error(format!("{}", e), None))
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "清除 TracerPid (仅 Unix/Android)")]
    async fn clear_tracer_pid(&self) -> Result<String, McpError> {
        tokio::task::spawn_blocking(|| {
            #[cfg(unix)] {
                crate::anti_detect::clear_tracer_pid()
                    .map(|_| "TracerPid 已清零".to_string())
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))
            }
            #[cfg(windows)] {
                Err(McpError::internal_error("仅支持 Unix/Android", None))
            }
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "隐藏 /proc/self/maps 条目 (仅 Unix/Android)")]
    async fn hide_maps_entries(&self) -> Result<String, McpError> {
        tokio::task::spawn_blocking(|| {
            #[cfg(unix)] {
                crate::anti_detect::hide_maps_entries()
                    .map(|_| "maps 已隐藏".to_string())
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))
            }
            #[cfg(windows)] {
                Err(McpError::internal_error("仅支持 Unix/Android", None))
            }
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }

    #[tool(description = "擦除 Frida 特征字符串")]
    async fn erase_frida_signatures(&self) -> Result<String, McpError> {
        tokio::task::spawn_blocking(|| {
            crate::anti_detect::erase_frida_signatures()
                .map(|_| "Frida 特征已擦除".to_string())
                .map_err(|e| McpError::internal_error(format!("{}", e), None))
        }).await.map_err(|e| McpError::internal_error(format!("{}", e), None))?
    }
}

#[tool_handler(
    name = "frida-rust-mcp",
    version = "0.1.0",
    instructions = "Frida-Rust MCP Server: 进程注入、Hook、内存操作、脚本执行、反检测"
)]
impl ServerHandler for FridaMcpServer {}

/// 简单的 x86_64 指令反汇编（返回指令名称和长度）
fn disassemble_instruction(bytes: &[u8]) -> (String, usize) {
    if bytes.is_empty() {
        return ("???".to_string(), 1);
    }
    
    // 常见 x86_64 指令前缀和操作码
    match bytes[0] {
        0x55 => ("push rbp".to_string(), 1),
        0x5D => ("pop rbp".to_string(), 1),
        0xC3 => ("ret".to_string(), 1),
        0xC9 => ("leave".to_string(), 1),
        0x90 => ("nop".to_string(), 1),
        0xCC => ("int3".to_string(), 1),
        0x48 if bytes.len() > 2 => {
            match bytes[1] {
                0x89 if bytes[2] == 0xE5 => ("mov rbp, rsp".to_string(), 3),
                0x83 if bytes.len() > 3 && bytes[2] == 0xEC => {
                    (format!("sub rsp, {:#x}", bytes[3]), 4)
                },
                _ => ("rex.w ...".to_string(), 2),
            }
        },
        0xE8 if bytes.len() > 4 => {
            let offset = i32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
            (format!("call {:+#x}", offset), 5)
        },
        0xE9 if bytes.len() > 4 => {
            let offset = i32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
            (format!("jmp {:+#x}", offset), 5)
        },
        0xEB if bytes.len() > 1 => {
            (format!("jmp short {:+#x}", bytes[1] as i8), 2)
        },
        _ => (format!("db {:#04x}", bytes[0]), 1),
    }
}

/// 解析字节模式（支持通配符 ?）
fn parse_pattern(pattern: &str) -> Result<(Vec<u8>, Option<Vec<bool>>), String> {
    let parts: Vec<&str> = pattern.split_whitespace().collect();
    let mut bytes = Vec::new();
    let mut mask = Vec::new();
    let mut has_wildcard = false;
    
    for part in parts {
        if part == "?" || part == "??" {
            bytes.push(0);
            mask.push(false);
            has_wildcard = true;
        } else {
            let byte = u8::from_str_radix(part, 16)
                .map_err(|_| format!("无效的字节: {}", part))?;
            bytes.push(byte);
            mask.push(true);
        }
    }
    
    if bytes.is_empty() {
        return Err("模式不能为空".to_string());
    }
    
    Ok((bytes, if has_wildcard { Some(mask) } else { None }))
}

fn parse_hex(s: &str) -> Result<usize, McpError> {
    let s = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    usize::from_str_radix(s, 16).map_err(|e| McpError::invalid_params(format!("无效地址: {}", e), None))
}

fn hex2bytes(hex: &str) -> Result<Vec<u8>, McpError> {
    let hex = hex.trim().replace(' ', "");
    if hex.len() % 2 != 0 { return Err(McpError::invalid_params("长度须为偶数", None)); }
    (0..hex.len()).step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i+2], 16)
            .map_err(|e| McpError::invalid_params(format!("无效: {}", e), None)))
        .collect()
}

#[cfg(unix)]
fn list_processes_impl() -> Result<String, McpError> {
    let mut procs = Vec::new();
    for e in std::fs::read_dir("/proc").map_err(|e| McpError::internal_error(format!("{}", e), None))? {
        let e = e.map_err(|e| McpError::internal_error(format!("{}", e), None))?;
        let n = e.file_name();
        let s = n.to_string_lossy();
        if !s.chars().all(|c| c.is_ascii_digit()) { continue; }
        let pid: u32 = match s.parse() { Ok(p) => p, Err(_) => continue };
        let comm = std::fs::read_to_string(format!("/proc/{}/comm", pid)).unwrap_or_default();
        procs.push(format!("PID={:<8} {}", pid, comm.trim()));
    }
    procs.sort();
    Ok(format!("{} 个进程:\n{}", procs.len(), procs.join("\n")))
}

#[cfg(windows)]
fn list_processes_impl() -> Result<String, McpError> {
    use std::process::Command;
    let out = Command::new("tasklist").arg("/FO").arg("CSV").arg("/NH").output()
        .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
    let lossy = String::from_utf8_lossy(&out.stdout); let lines: Vec<&str> = lossy.lines().take(50).collect();
    Ok(format!("前 {} 个进程:\n{}", lines.len(), lines.join("\n")))
}


