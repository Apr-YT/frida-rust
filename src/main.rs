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
    /// 内核通道模式：与 nova_stealth 内核模块通信
    Kernel {
        /// 操作类型：ping/version/status/read/write/hide/unhide
        action: String,
        /// 操作参数
        args: Vec<String>,
    },
    /// ioctl 通道模式：通过 /dev/nova_stealth 字符设备通信（hide_mod 后仍可用）
    KernelIoctl {
        /// 操作类型：ping/version/status/read/write/hide/unhide/hide_mod/unhide_mod
        action: String,
        /// 操作参数
        args: Vec<String>,
    },
    /// 硬件断点模式：设置/清除/列出 ARM64 硬件断点
    Hwbp {
        /// 通道：netlink 或 ioctl
        channel: String,
        /// 操作：set/clear/list/clear_all
        action: String,
        /// 操作参数
        args: Vec<String>,
    },
    /// 通信测试模式：测试 Unix Socket/Stdio 通道通信
    Comm {
        /// 测试类型：demo/encrypted
        action: String,
        /// 可选的 socket 路径
        args: Vec<String>,
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

    kernel <ACTION> [参数...]
        与 nova_stealth 内核模块通信（NETLINK_FIREWALL）

        操作:
            ping                              测试内核模块连通性
            version                           获取内核模块版本
            status                            获取内核模块运行状态
            read <PID> <HEX_ADDR> <SIZE>      读取进程内存
            write <PID> <HEX_ADDR> <HEX_DATA> 写入进程内存
            hide <PID>                        隐藏进程
            unhide <PID>                     取消隐藏进程
            hide_mod                          隐藏内核模块（破坏 Netlink，慎用）
            unhide_mod                        恢复内核模块可见

    kernel-ioctl <ACTION> [参数...]
        通过 /dev/nova_stealth 字符设备通信（hide_mod 后仍可用）

        操作:
            ping                              测试 ioctl 通道连通性
            version                           获取内核模块版本
            status                            获取内核模块运行状态
            read <PID> <HEX_ADDR> <SIZE>      读取进程内存（最大 4096 字节）
            write <PID> <HEX_ADDR> <HEX_DATA> 写入进程内存（最大 4096 字节）
            hide <PID>                        隐藏进程
            unhide <PID>                     取消隐藏进程
            hide_mod                          隐藏内核模块（ioctl 通道不受影响）
            unhide_mod                        恢复内核模块可见

    comm <ACTION> [参数...]
        测试通信通道（Unix Socket/Stdio）

        操作:
            demo         运行完整的通道通信演示
            encrypted    运行加密通道演示

        参数:
            [SOCKET_PATH]  可选的 Unix Socket 路径

示例:
    frida-rust inject 1234
    frida-rust inject 1234 /path/to/custom_agent.so
    frida-rust attach com.example.app
    frida-rust script hook.js --pid 1234 --anti-detect
    frida-rust -v script analyze.rs
    frida-rust kernel ping
    frida-rust kernel status
    frida-rust kernel read 1 0x55579f8000 16
    frida-rust kernel write 1088 0x71c947a000 deadbeefcafebabe
    frida-rust kernel hide 1234
    frida-rust kernel-ioctl ping
    frida-rust kernel-ioctl status
    frida-rust kernel-ioctl hide_mod
    frida-rust kernel-ioctl unhide_mod
    frida-rust comm demo
    frida-rust comm encrypted
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
        "kernel" => {
            if command_args.len() < 2 {
                anyhow::bail!("kernel 子命令需要指定操作类型。用法: kernel <ping|version|status|read|write|hide|unhide> [参数]");
            }
            let action = command_args[1].clone();
            let args = command_args[2..].to_vec();
            SubCommand::Kernel { action, args }
        }
        "kernel-ioctl" => {
            if command_args.len() < 2 {
                anyhow::bail!("kernel-ioctl 子命令需要指定操作类型。用法: kernel-ioctl <ping|version|status|read|write|hide|unhide|hide_mod|unhide_mod> [参数]");
            }
            let action = command_args[1].clone();
            let args = command_args[2..].to_vec();
            SubCommand::KernelIoctl { action, args }
        }
        "hwbp" => {
            if command_args.len() < 3 {
                anyhow::bail!("hwbp 子命令用法: hwbp <netlink|ioctl> <set|clear|list|clear_all> [参数]");
            }
            let channel = command_args[1].clone();
            let action = command_args[2].clone();
            let args = command_args[3..].to_vec();
            if channel != "netlink" && channel != "ioctl" {
                anyhow::bail!("hwbp 通道必须是 netlink 或 ioctl");
            }
            SubCommand::Hwbp { channel, action, args }
        }
        "comm" => {
            if command_args.len() < 2 {
                anyhow::bail!("comm 子命令需要指定操作类型。用法: comm <demo|encrypted> [socket_path]");
            }
            let action = command_args[1].clone();
            let args = command_args[2..].to_vec();
            if action != "demo" && action != "encrypted" {
                anyhow::bail!("comm 操作必须是 demo 或 encrypted");
            }
            SubCommand::Comm { action, args }
        }
        other => {
            anyhow::bail!("未知子命令: {}。支持: inject, attach, script, kernel, kernel-ioctl, hwbp, comm", other);
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

// ======================== 内核通道子命令 ========================

/// 执行 kernel 子命令：与 nova_stealth 内核模块通信
#[cfg(any(target_os = "linux", target_os = "android"))]
fn run_kernel(action: &str, args: &[String]) -> Result<()> {
    use frida_rust::communication::kernel_channel::KernelChannel;

    log::info!("进入内核通道模式");
    log::info!("操作: {}", action);

    let channel = KernelChannel::new().map_err(|e| anyhow::anyhow!("创建内核通道失败: {}", e))?;

    match action {
        "ping" => {
            let resp = channel.ping().map_err(|e| anyhow::anyhow!("PING 失败: {}", e))?;
            println!("✓ PING 成功: {}", resp);
        }
        "version" => {
            let ver = channel.get_version().map_err(|e| anyhow::anyhow!("获取版本失败: {}", e))?;
            println!("✓ 版本: {}", ver);
        }
        "status" => {
            let data = channel.get_status().map_err(|e| anyhow::anyhow!("获取状态失败: {}", e))?;
            if data.len() >= 36 {
                let version = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                let hidden = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
                let hooked = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
                let rx = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
                let tx = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
                let mr = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
                let mw = u32::from_le_bytes([data[24], data[25], data[26], data[27]]);
                let inj = u32::from_le_bytes([data[28], data[29], data[30], data[31]]);
                let err = u32::from_le_bytes([data[32], data[33], data[34], data[35]]);
                println!("✓ 状态:");
                println!("  version:           {}", version);
                println!("  hidden_proc_count: {}", hidden);
                println!("  hooked_region:     {}", hooked);
                println!("  nl_pkts_rx:        {}", rx);
                println!("  nl_pkts_tx:        {}", tx);
                println!("  mem_read:          {}", mr);
                println!("  mem_write:         {}", mw);
                println!("  inject:            {}", inj);
                println!("  errors:            {}", err);
            } else {
                println!("✓ 状态数据 ({} 字节): {:02x?}", data.len(), data);
            }
        }
        "read" => {
            if args.len() < 3 {
                anyhow::bail!("用法: kernel read <pid> <hex_addr> <size>");
            }
            let pid: i32 = args[0].parse().map_err(|_| anyhow::anyhow!("无效的 PID"))?;
            let addr = u64::from_str_radix(args[1].trim_start_matches("0x"), 16)
                .map_err(|_| anyhow::anyhow!("无效的地址"))?;
            let size: usize = args[2].parse().map_err(|_| anyhow::anyhow!("无效的大小"))?;
            let data = channel.read_mem(pid, addr as usize, size)
                .map_err(|e| anyhow::anyhow!("读取内存失败: {}", e))?;
            print!("✓ 读取成功 ({} 字节):", data.len());
            for (i, b) in data.iter().enumerate() {
                if i % 16 == 0 { println!(); print!("  "); }
                print!("{:02x} ", b);
            }
            println!();
        }
        "write" => {
            if args.len() < 3 {
                anyhow::bail!("用法: kernel write <pid> <hex_addr> <hex_bytes>");
            }
            let pid: i32 = args[0].parse().map_err(|_| anyhow::anyhow!("无效的 PID"))?;
            let addr = u64::from_str_radix(args[1].trim_start_matches("0x"), 16)
                .map_err(|_| anyhow::anyhow!("无效的地址"))?;
            let hex_str = args[2].trim_start_matches("0x");
            let data = parse_hex_bytes(hex_str)?;
            channel.write_mem(pid, addr as usize, &data)
                .map_err(|e| anyhow::anyhow!("写入内存失败: {}", e))?;
            println!("✓ 写入成功 ({} 字节)", data.len());
        }
        "hide" => {
            if args.is_empty() {
                anyhow::bail!("用法: kernel hide <pid>");
            }
            let pid: i32 = args[0].parse().map_err(|_| anyhow::anyhow!("无效的 PID"))?;
            channel.hide_process(pid).map_err(|e| anyhow::anyhow!("隐藏进程失败: {}", e))?;
            println!("✓ 隐藏进程成功: PID={}", pid);
        }
        "unhide" => {
            if args.is_empty() {
                anyhow::bail!("用法: kernel unhide <pid>");
            }
            let pid: i32 = args[0].parse().map_err(|_| anyhow::anyhow!("无效的 PID"))?;
            channel.unhide_process(pid).map_err(|e| anyhow::anyhow!("取消隐藏进程失败: {}", e))?;
            println!("✓ 取消隐藏进程成功: PID={}", pid);
        }
        "hide_mod" => {
            println!("⚠ 警告: 隐藏模块后 Netlink 通信将失效，无法通过内核通道恢复！");
            channel.hide_module().map_err(|e| anyhow::anyhow!("隐藏模块失败: {}", e))?;
            println!("✓ 模块已隐藏（注意：Netlink 通信现已失效，需重启设备恢复）");
        }
        "unhide_mod" => {
            channel.unhide_module().map_err(|e| anyhow::anyhow!("恢复模块可见失败: {}", e))?;
            println!("✓ 模块已恢复可见");
        }
        "tap" => {
            if args.len() < 2 {
                anyhow::bail!("用法: kernel tap <x> <y> [duration_ms] [jitter]");
            }
            let x: u32 = args[0].parse().map_err(|_| anyhow::anyhow!("无效的 x 坐标"))?;
            let y: u32 = args[1].parse().map_err(|_| anyhow::anyhow!("无效的 y 坐标"))?;
            let duration_ms: u32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
            let jitter: u32 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(5);
            channel.input_tap(x, y, duration_ms, jitter).map_err(|e| anyhow::anyhow!("内核 tap 失败: {}", e))?;
            println!("✓ 内核 tap 注入成功: ({},{}) dur={}ms jitter={}", x, y, duration_ms, jitter);
        }
        "swipe" => {
            if args.len() < 4 {
                anyhow::bail!("用法: kernel swipe <x1> <y1> <x2> <y2> [duration_ms] [steps]");
            }
            let x1: u32 = args[0].parse().map_err(|_| anyhow::anyhow!("无效的 x1"))?;
            let y1: u32 = args[1].parse().map_err(|_| anyhow::anyhow!("无效的 y1"))?;
            let x2: u32 = args[2].parse().map_err(|_| anyhow::anyhow!("无效的 x2"))?;
            let y2: u32 = args[3].parse().map_err(|_| anyhow::anyhow!("无效的 y2"))?;
            let duration_ms: u32 = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(300);
            let steps: u32 = args.get(5).and_then(|s| s.parse().ok()).unwrap_or(0);
            channel.input_swipe(x1, y1, x2, y2, duration_ms, steps).map_err(|e| anyhow::anyhow!("内核 swipe 失败: {}", e))?;
            println!("✓ 内核 swipe 注入成功: ({},{})->({},{}) dur={}ms", x1, y1, x2, y2, duration_ms);
        }
        "key" => {
            if args.is_empty() {
                anyhow::bail!("用法: kernel key <keycode> [repeat]\n常用: 28=ENTER, 158=BACK, 172=HOME, 14=DELETE");
            }
            let keycode: u32 = args[0].parse().map_err(|_| anyhow::anyhow!("无效的 keycode"))?;
            let repeat: u32 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(1);
            channel.input_key(keycode, repeat).map_err(|e| anyhow::anyhow!("内核 key 失败: {}", e))?;
            println!("✓ 内核 key 注入成功: code={} repeat={}", keycode, repeat);
        }
        other => {
            anyhow::bail!("未知 kernel 操作: {}。支持: ping, version, status, read, write, hide, unhide, hide_mod, unhide_mod, tap, swipe, key", other);
        }
    }

    Ok(())
}

/// 解析十六进制字节字符串
#[cfg(any(target_os = "linux", target_os = "android"))]
fn parse_hex_bytes(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        anyhow::bail!("十六进制字符串长度必须为偶数");
    }
    let mut result = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let high = (bytes[i] as char).to_digit(16)
            .ok_or_else(|| anyhow::anyhow!("无效的十六进制字符: {}", bytes[i] as char))?;
        let low = (bytes[i + 1] as char).to_digit(16)
            .ok_or_else(|| anyhow::anyhow!("无效的十六进制字符: {}", bytes[i + 1] as char))?;
        result.push((high * 16 + low) as u8);
        i += 2;
    }
    Ok(result)
}

/// kernel 子命令的 Windows fallback（内核通道仅在 Linux/Android 可用）
#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn run_kernel(_action: &str, _args: &[String]) -> Result<()> {
    anyhow::bail!("kernel 子命令仅在 Linux/Android 平台可用");
}

/// 执行 kernel-ioctl 子命令：通过 /dev/nova_stealth 字符设备通信
/// 优势：模块从 module_list 隐藏后仍可用（不依赖 try_module_get）
#[cfg(any(target_os = "linux", target_os = "android"))]
fn run_kernel_ioctl(action: &str, args: &[String]) -> Result<()> {
    use frida_rust::communication::kernel_channel::IoctlChannel;

    log::info!("进入 ioctl 内核通道模式（/dev/nova_stealth）");
    log::info!("操作: {}", action);

    let channel = IoctlChannel::new().map_err(|e| anyhow::anyhow!("创建 ioctl 通道失败: {}", e))?;

    match action {
        "ping" => {
            channel.ping().map_err(|e| anyhow::anyhow!("PING 失败: {}", e))?;
            println!("✓ ioctl PING 成功");
        }
        "version" => {
            let ver = channel.get_version().map_err(|e| anyhow::anyhow!("获取版本失败: {}", e))?;
            println!("✓ 版本: v{}", ver);
        }
        "status" => {
            let s = channel.get_status().map_err(|e| anyhow::anyhow!("获取状态失败: {}", e))?;
            println!("✓ ioctl 状态:");
            println!("  version:           {}", s.version);
            println!("  hidden_proc_count: {}", s.hidden_proc_count);
            println!("  hooked_region:     {}", s.hooked_region_count);
            println!("  nl_pkts_rx:        {}", s.netlink_packets_rx);
            println!("  nl_pkts_tx:        {}", s.netlink_packets_tx);
            println!("  mem_read:          {}", s.mem_read_count);
            println!("  mem_write:         {}", s.mem_write_count);
            println!("  inject:            {}", s.inject_count);
            println!("  errors:            {}", s.errors);
        }
        "read" => {
            if args.len() < 3 {
                anyhow::bail!("用法: kernel-ioctl read <pid> <hex_addr> <size>");
            }
            let pid: i32 = args[0].parse().map_err(|_| anyhow::anyhow!("无效的 PID"))?;
            let addr = u64::from_str_radix(args[1].trim_start_matches("0x"), 16)
                .map_err(|_| anyhow::anyhow!("无效的地址"))?;
            let size: usize = args[2].parse().map_err(|_| anyhow::anyhow!("无效的大小"))?;
            let data = channel.read_mem(pid, addr as usize, size)
                .map_err(|e| anyhow::anyhow!("读取内存失败: {}", e))?;
            print!("✓ 读取成功 ({} 字节):", data.len());
            for (i, b) in data.iter().enumerate() {
                if i % 16 == 0 { println!(); print!("  "); }
                print!("{:02x} ", b);
            }
            println!();
        }
        "write" => {
            if args.len() < 3 {
                anyhow::bail!("用法: kernel-ioctl write <pid> <hex_addr> <hex_bytes>");
            }
            let pid: i32 = args[0].parse().map_err(|_| anyhow::anyhow!("无效的 PID"))?;
            let addr = u64::from_str_radix(args[1].trim_start_matches("0x"), 16)
                .map_err(|_| anyhow::anyhow!("无效的地址"))?;
            let hex_str = args[2].trim_start_matches("0x");
            let data = parse_hex_bytes(hex_str)?;
            channel.write_mem(pid, addr as usize, &data)
                .map_err(|e| anyhow::anyhow!("写入内存失败: {}", e))?;
            println!("✓ 写入成功 ({} 字节)", data.len());
        }
        "hide" => {
            if args.is_empty() {
                anyhow::bail!("用法: kernel-ioctl hide <pid>");
            }
            let pid: i32 = args[0].parse().map_err(|_| anyhow::anyhow!("无效的 PID"))?;
            channel.hide_process(pid).map_err(|e| anyhow::anyhow!("隐藏进程失败: {}", e))?;
            println!("✓ 隐藏进程成功: PID={}", pid);
        }
        "unhide" => {
            if args.is_empty() {
                anyhow::bail!("用法: kernel-ioctl unhide <pid>");
            }
            let pid: i32 = args[0].parse().map_err(|_| anyhow::anyhow!("无效的 PID"))?;
            channel.unhide_process(pid).map_err(|e| anyhow::anyhow!("取消隐藏进程失败: {}", e))?;
            println!("✓ 取消隐藏进程成功: PID={}", pid);
        }
        "hide_mod" => {
            println!("ℹ 通过 ioctl 隐藏模块（通信通道不受影响）");
            channel.hide_module().map_err(|e| anyhow::anyhow!("隐藏模块失败: {}", e))?;
            println!("✓ 模块已隐藏（ioctl 通道仍可用，可用 unhide_mod 恢复）");
        }
        "unhide_mod" => {
            channel.unhide_module().map_err(|e| anyhow::anyhow!("恢复模块可见失败: {}", e))?;
            println!("✓ 模块已恢复可见");
        }
        "tap" => {
            if args.len() < 2 {
                anyhow::bail!("用法: kernel-ioctl tap <x> <y> [duration_ms] [jitter]");
            }
            let x: u32 = args[0].parse().map_err(|_| anyhow::anyhow!("无效的 x 坐标"))?;
            let y: u32 = args[1].parse().map_err(|_| anyhow::anyhow!("无效的 y 坐标"))?;
            let duration_ms: u32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
            let jitter: u32 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(5);
            channel.input_tap(x, y, duration_ms, jitter).map_err(|e| anyhow::anyhow!("ioctl tap 失败: {}", e))?;
            println!("✓ ioctl tap 注入成功: ({},{}) dur={}ms jitter={}", x, y, duration_ms, jitter);
        }
        "swipe" => {
            if args.len() < 4 {
                anyhow::bail!("用法: kernel-ioctl swipe <x1> <y1> <x2> <y2> [duration_ms] [steps]");
            }
            let x1: u32 = args[0].parse().map_err(|_| anyhow::anyhow!("无效的 x1"))?;
            let y1: u32 = args[1].parse().map_err(|_| anyhow::anyhow!("无效的 y1"))?;
            let x2: u32 = args[2].parse().map_err(|_| anyhow::anyhow!("无效的 x2"))?;
            let y2: u32 = args[3].parse().map_err(|_| anyhow::anyhow!("无效的 y2"))?;
            let duration_ms: u32 = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(300);
            let steps: u32 = args.get(5).and_then(|s| s.parse().ok()).unwrap_or(0);
            channel.input_swipe(x1, y1, x2, y2, duration_ms, steps).map_err(|e| anyhow::anyhow!("ioctl swipe 失败: {}", e))?;
            println!("✓ ioctl swipe 注入成功: ({},{})->({},{}) dur={}ms", x1, y1, x2, y2, duration_ms);
        }
        "key" => {
            if args.is_empty() {
                anyhow::bail!("用法: kernel-ioctl key <keycode> [repeat]");
            }
            let keycode: u32 = args[0].parse().map_err(|_| anyhow::anyhow!("无效的 keycode"))?;
            let repeat: u32 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(1);
            channel.input_key(keycode, repeat).map_err(|e| anyhow::anyhow!("ioctl key 失败: {}", e))?;
            println!("✓ ioctl key 注入成功: code={} repeat={}", keycode, repeat);
        }
        other => {
            anyhow::bail!("未知 kernel-ioctl 操作: {}。支持: ping, version, status, read, write, hide, unhide, hide_mod, unhide_mod, tap, swipe, key", other);
        }
    }

    Ok(())
}

/// kernel-ioctl 子命令的 Windows fallback
#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn run_kernel_ioctl(_action: &str, _args: &[String]) -> Result<()> {
    anyhow::bail!("kernel-ioctl 子命令仅在 Linux/Android 平台可用");
}

/// 执行 hwbp 子命令：设置/清除/列出 ARM64 硬件断点
#[cfg(any(target_os = "linux", target_os = "android"))]
fn run_hwbp(channel: &str, action: &str, args: &[String]) -> Result<()> {
    use frida_rust::communication::kernel_channel::{KernelChannel, IoctlChannel};

    log::info!("进入硬件断点模式 (通道={}, 操作={})", channel, action);

    match action {
        "set" => {
            if args.len() < 4 {
                anyhow::bail!("用法: hwbp <channel> set <pid> <hex_addr> <type> [len]\n  type: 1=执行, 2=读, 3=写, 4=读写\n  len: 访问长度1-8（执行断点忽略）");
            }
            let pid: u32 = args[0].parse().map_err(|_| anyhow::anyhow!("无效的 PID"))?;
            let addr = u64::from_str_radix(args[1].trim_start_matches("0x"), 16)
                .map_err(|_| anyhow::anyhow!("无效的地址"))?;
            let type_: u32 = args[2].parse().map_err(|_| anyhow::anyhow!("无效的断点类型"))?;
            let len: u32 = if args.len() >= 4 {
                args[3].parse().map_err(|_| anyhow::anyhow!("无效的长度"))?
            } else {
                4
            };

            let bp_id = if channel == "netlink" {
                let ch = KernelChannel::new().map_err(|e| anyhow::anyhow!("创建 Netlink 通道失败: {}", e))?;
                ch.hwbp_set(pid, addr, type_, len).map_err(|e| anyhow::anyhow!("设置硬件断点失败: {}", e))?
            } else {
                let ch = IoctlChannel::new().map_err(|e| anyhow::anyhow!("创建 ioctl 通道失败: {}", e))?;
                ch.hwbp_set(pid, addr, type_, len).map_err(|e| anyhow::anyhow!("设置硬件断点失败: {}", e))?
            };
            println!("✓ 硬件断点已设置: id={}, pid={}, addr={:#x}, type={}, len={}", bp_id, pid, addr, type_, len);
        }
        "clear" => {
            if args.is_empty() {
                anyhow::bail!("用法: hwbp <channel> clear <bp_id>");
            }
            let bp_id: i32 = args[0].parse().map_err(|_| anyhow::anyhow!("无效的断点 ID"))?;
            if channel == "netlink" {
                let ch = KernelChannel::new().map_err(|e| anyhow::anyhow!("创建 Netlink 通道失败: {}", e))?;
                ch.hwbp_clear(bp_id).map_err(|e| anyhow::anyhow!("清除硬件断点失败: {}", e))?;
            } else {
                let ch = IoctlChannel::new().map_err(|e| anyhow::anyhow!("创建 ioctl 通道失败: {}", e))?;
                ch.hwbp_clear(bp_id).map_err(|e| anyhow::anyhow!("清除硬件断点失败: {}", e))?;
            }
            println!("✓ 硬件断点已清除: id={}", bp_id);
        }
        "list" => {
            let infos = if channel == "netlink" {
                let ch = KernelChannel::new().map_err(|e| anyhow::anyhow!("创建 Netlink 通道失败: {}", e))?;
                ch.hwbp_list().map_err(|e| anyhow::anyhow!("列出硬件断点失败: {}", e))?
            } else {
                let ch = IoctlChannel::new().map_err(|e| anyhow::anyhow!("创建 ioctl 通道失败: {}", e))?;
                ch.hwbp_list().map_err(|e| anyhow::anyhow!("列出硬件断点失败: {}", e))?
            };
            if infos.is_empty() {
                println!("（无硬件断点）");
            } else {
                println!("✓ 硬件断点列表 ({} 个):", infos.len());
                println!("  {:<6} {:<8} {:<18} {:<6} {:<6} {:<10}", "ID", "PID", "ADDR", "TYPE", "LEN", "HITS");
                let type_str = |t: u32| match t { 1 => "X", 2 => "R", 3 => "W", 4 => "RW", _ => "?" };
                for info in &infos {
                    println!("  {:<6} {:<8} {:#018x} {:<6} {:<6} {:<10}",
                        info.id, info.pid, info.addr, type_str(info.type_), info.len, info.hit_count);
                }
            }
        }
        "clear_all" => {
            let count = if channel == "netlink" {
                let ch = KernelChannel::new().map_err(|e| anyhow::anyhow!("创建 Netlink 通道失败: {}", e))?;
                ch.hwbp_clear_all().map_err(|e| anyhow::anyhow!("清除所有硬件断点失败: {}", e))?
            } else {
                let ch = IoctlChannel::new().map_err(|e| anyhow::anyhow!("创建 ioctl 通道失败: {}", e))?;
                ch.hwbp_clear_all().map_err(|e| anyhow::anyhow!("清除所有硬件断点失败: {}", e))?
            };
            println!("✓ 已清除所有硬件断点 (共 {} 个)", count);
        }
        other => {
            anyhow::bail!("未知 hwbp 操作: {}。支持: set, clear, list, clear_all", other);
        }
    }

    Ok(())
}

/// hwbp 子命令的 Windows fallback
#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn run_hwbp(_channel: &str, _action: &str, _args: &[String]) -> Result<()> {
    anyhow::bail!("hwbp 子命令仅在 Linux/Android 平台可用");
}

/// 执行 comm 子命令：测试通信通道
fn run_comm(action: &str, args: &[String]) -> Result<()> {
    log::info!("进入通信测试模式");
    log::info!("操作: {}", action);

    match action {
        "demo" => {
            let socket_path = args.get(0).map(|s| s.as_str());
            frida_rust::communication::run_channel_demo(socket_path)?;
            println!("✓ 通信演示完成");
        }
        "encrypted" => {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            {
                frida_rust::communication::run_encrypted_channel_demo()?;
                println!("✓ 加密通道演示完成");
            }
            #[cfg(not(any(target_os = "linux", target_os = "android")))]
            {
                anyhow::bail!("加密通道演示仅在 Linux/Android 平台可用");
            }
        }
        other => {
            anyhow::bail!("未知 comm 操作: {}。支持: demo, encrypted", other);
        }
    }

    Ok(())
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
        SubCommand::Kernel { action, args } => run_kernel(&action, &args),
        SubCommand::KernelIoctl { action, args } => run_kernel_ioctl(&action, &args),
        SubCommand::Hwbp { channel, action, args } => run_hwbp(&channel, &action, &args),
        SubCommand::Comm { action, args } => run_comm(&action, &args),
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
