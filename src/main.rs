//! # frida-rust CLI 入口
//!
//! 提供命令行接口，支持以下子命令：
//! - `inject` - 进程注入模式：将 agent 共享库注入到目标进程
//! - `attach` - 进程附着模式：附着到运行中的进程进行插桩
//! - `script` - 脚本执行模式：执行 Rhai 脚本文件

use frida_rust::Result;
use std::env;
use std::process;

// ======================== CLI 数据结构 ========================

/// 支持的子命令枚举
#[derive(Debug)]
enum SubCommand {
    /// 进程注入模式
    Inject {
        /// 目标进程 ID
        pid: u32,
        /// 注入的 agent 路径
        agent_path: Option<String>,
    },
    /// 进程附着模式
    Attach {
        /// 目标进程名称（用于查找 PID）
        process_name: String,
    },
    /// 脚本执行模式
    Script {
        /// 脚本文件路径
        script_path: String,
        /// 目标进程 ID（可选，默认为自身）
        pid: Option<u32>,
        /// 是否启用反检测
        anti_detect: bool,
    },
}

/// 全局 CLI 配置
#[derive(Debug)]
struct CliConfig {
    /// 子命令
    command: SubCommand,
    /// 日志级别
    log_level: log::LevelFilter,
    /// 是否显示帮助信息
    help: bool,
    /// 是否显示版本信息
    version: bool,
}

// ======================== 帮助与版本信息 ========================

const USAGE: &str = r#"
frida-rust - Frida 核心功能的 Rust 实现

用法:
    frida-rust [选项] <子命令> [子命令参数]

选项:
    -v, --verbose    启用详细日志输出 (DEBUG 级别)
    -q, --quiet      安静模式，仅输出错误 (ERROR 级别)
    -h, --help       显示帮助信息
    -V, --version    显示版本号

子命令:
    inject <PID> [AGENT_PATH]
        将 agent 共享库注入到目标进程

        参数:
            PID         目标进程 ID
            AGENT_PATH  agent 共享库路径 (可选，默认: libfrida_agent.so)

    attach <PROCESS_NAME>
        通过进程名查找并附着到目标进程

        参数:
            PROCESS_NAME  目标进程名称

    script <SCRIPT_PATH> [--pid <PID>] [--anti-detect]
        执行 Rhai 脚本文件

        参数:
            SCRIPT_PATH  脚本文件路径
            --pid <PID>  目标进程 ID (可选)
            --anti-detect  启用反检测 (可选)

示例:
    frida-rust inject 1234
    frida-rust inject 1234 /path/to/custom_agent.so
    frida-rust attach com.example.app
    frida-rust script hook.js --pid 1234 --anti-detect
    frida-rust -v script analyze.rs
"#;

const VERSION: &str = env!("CARGO_PKG_VERSION");

// ======================== 参数解析 ========================

/// 解析命令行参数（手动实现，不依赖 clap）
///
/// 从 `std::env::args()` 获取参数列表，按照子命令结构进行解析。
fn parse_args() -> Result<CliConfig> {
    let args: Vec<String> = env::args().skip(1).collect();

    let mut log_level = log::LevelFilter::Info;
    let mut help = false;
    let mut version = false;
    let mut command_args: Vec<String> = Vec::new();

    // 第一轮：提取全局选项
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-v" | "--verbose" => {
                log_level = log::LevelFilter::Debug;
            }
            "-q" | "--quiet" => {
                log_level = log::LevelFilter::Error;
            }
            "-h" | "--help" => {
                help = true;
            }
            "-V" | "--version" => {
                version = true;
            }
            _ => {
                command_args.push(args[i].clone());
            }
        }
        i += 1;
    }

    // 如果请求了帮助或版本信息，不需要解析子命令
    if help || version {
        return Ok(CliConfig {
            command: SubCommand::Script {
                script_path: String::new(),
                pid: None,
                anti_detect: false,
            },
            log_level,
            help,
            version,
        });
    }

    // 解析子命令
    if command_args.is_empty() {
        anyhow::bail!("未指定子命令。使用 -h 查看帮助信息。");
    }

    let command = match command_args[0].as_str() {
        "inject" => {
            if command_args.len() < 2 {
                anyhow::bail!("inject 子命令需要指定目标进程 PID。用法: inject <PID> [AGENT_PATH]");
            }
            let pid: u32 = command_args[1]
                .parse()
                .map_err(|_| anyhow::anyhow!("无效的进程 ID: {}", command_args[1]))?;
            let agent_path = command_args.get(2).cloned();
            SubCommand::Inject { pid, agent_path }
        }
        "attach" => {
            if command_args.len() < 2 {
                anyhow::bail!("attach 子命令需要指定目标进程名称。用法: attach <PROCESS_NAME>");
            }
            let process_name = command_args[1].clone();
            SubCommand::Attach { process_name }
        }
        "script" => {
            if command_args.len() < 2 {
                anyhow::bail!("script 子命令需要指定脚本文件路径。用法: script <SCRIPT_PATH>");
            }
            let script_path = command_args[1].clone();

            // 解析 script 子命令的可选参数
            let mut pid: Option<u32> = None;
            let mut anti_detect = false;
            let mut j = 2;
            while j < command_args.len() {
                match command_args[j].as_str() {
                    "--pid" => {
                        j += 1;
                        if j >= command_args.len() {
                            anyhow::bail!("--pid 需要指定进程 ID");
                        }
                        pid = Some(
                            command_args[j]
                                .parse()
                                .map_err(|_| anyhow::anyhow!("无效的进程 ID: {}", command_args[j]))?,
                        );
                    }
                    "--anti-detect" => {
                        anti_detect = true;
                    }
                    other => {
                        anyhow::bail!("未知参数: {}", other);
                    }
                }
                j += 1;
            }

            SubCommand::Script {
                script_path,
                pid,
                anti_detect,
            }
        }
        other => {
            anyhow::bail!("未知子命令: {}。支持: inject, attach, script", other);
        }
    };

    Ok(CliConfig {
        command,
        log_level,
        help: false,
        version: false,
    })
}

// ======================== 子命令执行 ========================

/// 执行 inject 子命令
fn run_inject(pid: u32, agent_path: Option<String>) -> Result<()> {
    log::info!("进入注入模式");
    log::info!("目标 PID: {}", pid);

    let agent = agent_path.unwrap_or_else(|| {
        frida_rust::common::constants::DEFAULT_AGENT_LIB_NAME.to_string()
    });
    log::info!("Agent 路径: {}", agent);

    // 验证 agent 文件是否存在
    match std::fs::metadata(&agent) {
        Ok(_) => log::info!("Agent 文件验证通过"),
        Err(e) => {
            anyhow::bail!("无法访问 agent 文件 '{}': {}", agent, e);
        }
    }

    // 调用注入模块
    let pid = frida_rust::common::types::ProcessId(pid);
    frida_rust::inject::inject_library(pid, &agent)?;

    log::info!("注入完成");
    Ok(())
}

/// 执行 attach 子命令
fn run_attach(process_name: &str) -> Result<()> {
    log::info!("进入附着模式");
    log::info!("目标进程: {}", process_name);

    // 通过 /proc 查找匹配名称的进程
    let pid = find_process_by_name(process_name)?;
    log::info!("找到目标进程 PID: {}", pid.0);

    // 调用注入模块进行附着
    frida_rust::inject::attach_process(pid)?;

    log::info!("附着完成");
    Ok(())
}

/// 执行 script 子命令
fn run_script(script_path: &str, pid: Option<u32>, anti_detect: bool) -> Result<()> {
    log::info!("进入脚本执行模式");
    log::info!("脚本路径: {}", script_path);

    if anti_detect {
        log::info!("反检测已启用");
    }

    // 读取并验证脚本文件
    let script_content = frida_rust::common::util::read_file_bytes(script_path)?;
    log::info!("脚本大小: {} 字节", script_content.len());

    // 初始化脚本引擎（如果指定了 PID，使用 for_pid 创建跨进程上下文）
    let mut engine = if let Some(target_pid) = pid {
        log::info!("目标 PID: {}", target_pid);
        frida_rust::script::ScriptEngine::for_pid(
            frida_rust::common::types::ProcessId(target_pid as u32)
        )?
    } else {
        frida_rust::script::ScriptEngine::new()?
    };

    // 如果启用反检测，执行反检测措施
    if anti_detect {
        frida_rust::anti_detect::apply_stealth()?;
        log::info!("反检测措施已应用");
    }

    // 执行脚本（直接传递字节内容）
    let _ = engine.execute(&script_content)?;

    log::info!("脚本执行完成");
    Ok(())
}

/// 通过进程名在 /proc 中查找进程 PID
fn find_process_by_name(name: &str) -> Result<frida_rust::common::types::ProcessId> {
    log::debug!("正在查找进程: {}", name);

    // 读取 /proc 目录查找匹配的进程
    let proc_entries = std::fs::read_dir("/proc")?;

    for entry in proc_entries {
        let entry = entry?;
        let dir_name = entry.file_name();
        let dir_str = dir_name.to_string_lossy();

        // 过滤出数字目录（进程目录）
        if !dir_str.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }

        let pid: u32 = match dir_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        // 读取 /proc/[pid]/cmdline 获取进程命令行
        let cmdline_path = format!("/proc/{}/cmdline", pid);
        if let Ok(cmdline) = std::fs::read(&cmdline_path) {
            // cmdline 以 \0 分隔，取第一个参数（程序名）
            let cmdline_str = String::from_utf8_lossy(&cmdline);
            let program_name = cmdline_str.split('\0').next().unwrap_or("");

            // 提取程序名（去掉路径前缀）
            let binary_name = program_name
                .rsplit('/')
                .next()
                .unwrap_or(program_name);

            if binary_name == name {
                log::debug!("匹配进程: PID={}, 命令行: {}", pid, cmdline_str.trim_end_matches('\0'));
                return Ok(frida_rust::common::types::ProcessId(pid));
            }
        }
    }

    anyhow::bail!("未找到名称为 '{}' 的进程", name)
}

// ======================== 主函数 ========================

fn main() {
    // 解析命令行参数
    let config = match parse_args() {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("参数解析错误: {}", e);
            eprintln!("{}", USAGE);
            process::exit(1);
        }
    };

    // 处理帮助和版本信息
    if config.help {
        println!("frida-rust v{}", VERSION);
        print!("{}", USAGE);
        process::exit(0);
    }

    if config.version {
        println!("frida-rust v{}", VERSION);
        process::exit(0);
    }

    // 初始化日志系统
    env_logger::Builder::new()
        .filter_level(config.log_level)
        .format_timestamp_secs()
        .init();

    log::info!("frida-rust v{} 启动", VERSION);
    log::debug!("架构: {}", frida_rust::common::types::Architecture::current());

    // 根据子命令调用对应处理函数
    let result = match config.command {
        SubCommand::Inject { pid, agent_path } => run_inject(pid, agent_path),
        SubCommand::Attach { process_name } => run_attach(&process_name),
        SubCommand::Script {
            script_path,
            pid,
            anti_detect,
        } => run_script(&script_path, pid, anti_detect),
    };

    // 处理执行结果
    match result {
        Ok(()) => {
            log::info!("执行成功");
            process::exit(0);
        }
        Err(e) => {
            log::error!("执行失败: {}", e);
            let bt = std::backtrace::Backtrace::capture();
            if bt.status() == std::backtrace::BacktraceStatus::Captured {
                log::debug!("{:?}", bt);
            }
            process::exit(1);
        }
    }
}
