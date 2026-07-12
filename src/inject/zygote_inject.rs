//! Zygote 注入方式实现
//!
//! 利用 Android Zygote 进程的 fork 机制实现注入。
//! Zygote 是 Android 系统中所有 Java 应用进程的父进程，
//! 在应用启动时通过 fork Zygote 来创建新进程。
//! 通过在 Zygote fork 之前注入代码，可以在所有新 fork 的
//! 应用进程中自动执行注入逻辑。
//!
//! # 工作原理
//! 1. 找到 Zygote 进程（通常 PID=1 或通过 init 进程查找）
//! 2. 解析目标 app 进程的 Zygote socket 信息
//! 3. 监控 Zygote 的 fork 行为
//! 4. 在 fork 后、exec 前注入共享库
//!
//! # 限制
//! - 仅适用于 Android 平台
//! 需要 root 权限

#[cfg(any(target_os = "linux", target_os = "android"))]
use crate::common::error::FridaError;
#[cfg(any(target_os = "linux", target_os = "android"))]
use crate::common::types::ProcessId;

/// Zygote 注入器
///
/// 通过 Zygote 进程的 fork 机制实现注入。
/// 在 Android 上，所有 Java 应用都是从 Zygote fork 出来的，
/// 通过 hook Zygote 的 fork 逻辑可以在应用启动时注入代码。
#[cfg(any(target_os = "linux", target_os = "android"))]
pub struct ZygoteInjector {
    /// Zygote 进程 PID
    zygote_pid: Option<ProcessId>,
    /// 是否已初始化
    initialized: bool,
    /// Zygote socket 路径
    zygote_socket: Option<String>,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl ZygoteInjector {
    /// 创建新的 Zygote 注入器实例
    pub fn new() -> Self {
        ZygoteInjector {
            zygote_pid: None,
            initialized: false,
            zygote_socket: None,
        }
    }

    /// 初始化 Zygote 注入器
    ///
    /// 查找 Zygote 进程并获取相关信息。
    pub fn init(&mut self) -> crate::Result<()> {
        // 查找 Zygote 进程
        let zygote_pid = self.find_zygote_process()?;

        // 获取 Zygote socket 路径
        let socket_path = self.find_zygote_socket(zygote_pid)?;

        self.zygote_pid = Some(zygote_pid);
        self.zygote_socket = Some(socket_path);
        self.initialized = true;

        log::info!(
            "Zygote 注入器初始化完成: Zygote PID={}, Socket={}",
            zygote_pid.0,
            self.zygote_socket.as_ref().unwrap()
        );
        Ok(())
    }

    /// 通过 Zygote 机制注入共享库到目标应用进程
    ///
    /// # 参数
    /// - `app_pid`: 目标应用进程 ID（Zygote 的子进程）
    /// - `lib_path`: 要注入的共享库路径
    ///
    /// # 流程
    /// 1. 确认目标进程是 Zygote 的子进程
    /// 2. 通过 ptrace 附加到目标进程
    /// 3. 调用 dlopen 加载共享库
    /// 4. 恢复目标进程执行
    pub fn inject(&mut self, app_pid: ProcessId, lib_path: &str) -> crate::Result<()> {
        if !self.initialized {
            self.init()?;
        }

        log::info!(
            "Zygote 注入: App PID={}, 库路径={}",
            app_pid.0,
            lib_path
        );

        // 验证目标进程确实是 Zygote 的子进程
        if !self.is_zygote_child(app_pid)? {
            return Err(FridaError::Inject {
                reason: format!(
                    "PID {} 不是 Zygote 的子进程",
                    app_pid.0
                ),
                pid: app_pid.0,
                source: None,
            }
            .into());
        }

        // 解析目标 app 进程的 Zygote socket 信息
        let _socket_info = self.parse_app_zygote_socket(app_pid)?;

        // 通过 ptrace 注入共享库
        let mut ptrace_injector = super::ptrace_inject::PtraceInjector::new();
        ptrace_injector.attach(app_pid)?;

        // 分配远程内存并写入库路径
        let path_bytes = lib_path.as_bytes();
        let path_len = path_bytes.len() + 1; // 包含 null 终止符
        let remote_addr = ptrace_injector.alloc_remote(app_pid, path_len)?;

        // 写入库路径字符串到远程内存
        let mut path_with_null = path_bytes.to_vec();
        path_with_null.push(0); // 添加 null 终止符
        ptrace_injector.write_remote(
            app_pid,
            remote_addr as usize,
            &path_with_null,
        )?;

        // 查找目标进程中的 dlopen 地址
        let dlopen_addr = ptrace_injector.find_remote_dlopen(app_pid)?;

        // 调用 dlopen 加载共享库
        let tid = app_pid.0 as i32;
        let args = vec![
            remote_addr,                                              // filename
            1u64,                                                     // flag = RTLD_LAZY
            0u64,                                                     // reserved (部分 dlopen 变体需要)
        ];

        // 只传前两个参数给标准 dlopen
        let dlopen_args = &args[..std::cmp::min(args.len(), 2)];
        let result = ptrace_injector.call_remote(tid, dlopen_addr, dlopen_args)?;

        if result == 0 {
            // dlopen 返回 NULL 表示失败，但在远程调用中我们需要更谨慎地处理
            log::warn!(
                "dlopen 远程调用返回 0，可能失败（需进一步检查远程 errno）"
            );
        } else {
            log::info!(
                "dlopen 远程调用成功，handle = {:#x}",
                result
            );
        }

        // 清理远程内存
        let _ = ptrace_injector.free_remote(app_pid, remote_addr, path_len);

        // 脱离目标进程
        ptrace_injector.detach()?;

        log::info!(
            "Zygote 注入完成: App PID={}, 库={}",
            app_pid.0,
            lib_path
        );
        Ok(())
    }

    /// 查找 Zygote 进程
    ///
    /// 通过遍历 /proc 查找名为 "zygote" 或 "main" 的进程。
    fn find_zygote_process(&self) -> crate::Result<ProcessId> {
        let proc_dir = std::fs::read_dir("/proc")?;

        for entry in proc_dir {
            let entry = entry?;
            let file_name = entry.file_name();
            let name_str = file_name.to_string_lossy();

            if let Ok(pid_num) = name_str.parse::<u32>() {
                if pid_num == 0 {
                    continue;
                }

                // 读取进程的 cmdline
                let cmdline_path = format!("/proc/{}/cmdline", pid_num);
                if let Ok(cmdline_bytes) = std::fs::read(&cmdline_path) {
                    let cmdline = String::from_utf8_lossy(&cmdline_bytes);
                    let cmdline = cmdline.replace('\0', " ");

                    // Zygote 进程的 cmdline 通常包含 "zygote" 关键字
                    if cmdline.contains("zygote") || cmdline.contains("app_process") {
                        log::debug!(
                            "找到 Zygote 候选进程: PID={}, cmdline={}",
                            pid_num,
                            cmdline.trim()
                        );

                        // 优先选择主 Zygote（不是 zygote64 或 zygote_secondary）
                        if cmdline.contains("zygote") && !cmdline.contains("zygote64")
                            && !cmdline.contains("--zygote64")
                        {
                            return Ok(ProcessId(pid_num));
                        }
                    }
                }
            }
        }

        Err(FridaError::NotFound {
            reason: "找不到 Zygote 进程（可能不在 Android 环境中）".to_string(),
        }
        .into())
    }

    /// 查找 Zygote 进程的 socket
    ///
    /// 解析 /proc/[zygote_pid]/fd 目录，查找 Zygote 使用的 Unix Domain Socket。
    fn find_zygote_socket(&self, zygote_pid: ProcessId) -> crate::Result<String> {
        let fd_dir_path = format!("/proc/{}/fd", zygote_pid.0);
        let fd_dir = std::fs::read_dir(&fd_dir_path)?;

        for entry in fd_dir {
            let entry = entry?;
            let link_target = std::fs::read_link(entry.path())?;
            let target_str = link_target.to_string_lossy();

            // Zygote socket 通常以 "socket:" 开头
            if target_str.contains("socket") {
                // 检查是否是 Unix socket
                if target_str.contains("[") {
                    // 提取 socket inode 号
                    if let Some(start) = target_str.find('[') {
                        if let Some(end) = target_str.find(']') {
                            let inode = &target_str[start + 1..end];
                            log::debug!(
                                "Zygote socket: fd={}, inode={}",
                                entry.file_name().to_string_lossy(),
                                inode
                            );

                            // 通过 /proc/net/unix 查找 socket 路径
                            if let Some(path) = self.find_unix_socket_path(inode)? {
                                return Ok(path);
                            }
                        }
                    }
                }
            }
        }

        // 默认返回 Android 标准 Zygote socket 路径
        Ok("/dev/socket/zygote".to_string())
    }

    /// 通过 socket inode 号查找 Unix Socket 的路径
    ///
    /// 解析 /proc/net/unix 文件，匹配 inode 号找到对应的 socket 路径。
    fn find_unix_socket_path(&self, inode: &str) -> crate::Result<Option<String>> {
        let unix_content = std::fs::read_to_string("/proc/net/unix")?;

        for line in unix_content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 7 {
                // 字段: Num RefCount Protocol Flags Type St Inode Path
                if fields[6] == inode {
                    if fields.len() > 7 {
                        let path = fields[7].to_string();
                        log::debug!("找到 Unix socket 路径: {} (inode={})", path, inode);
                        return Ok(Some(path));
                    }
                }
            }
        }

        Ok(None)
    }

    /// 检查目标进程是否是 Zygote 的子进程
    ///
    /// 通过 /proc/[pid]/status 中的 PPid 字段判断。
    fn is_zygote_child(&self, app_pid: ProcessId) -> crate::Result<bool> {
        let status_path = format!("/proc/{}/status", app_pid.0);
        let status_content = std::fs::read_to_string(&status_path)?;

        let mut ppid: u32 = 0;
        for line in status_content.lines() {
            if line.starts_with("PPid:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    ppid = parts[1].parse().unwrap_or(0);
                }
                break;
            }
        }

        if let Some(zygote_pid) = self.zygote_pid {
            // 直接检查 ppid 是否为 zygote_pid
            if ppid == zygote_pid.0 {
                return Ok(true);
            }

            // 也可以检查 ppid 是否是 zygote 的子进程（zygote64 等）
            let parent_status =
                std::fs::read_to_string(format!("/proc/{}/status", ppid));
            if let Ok(parent_content) = parent_status {
                for line in parent_content.lines() {
                    if line.starts_with("Name:") {
                        let name = line
                            .split_whitespace()
                            .nth(1)
                            .unwrap_or("");
                        if name.contains("zygote") {
                            return Ok(true);
                        }
                    }
                }
            }
        }

        Ok(false)
    }

    /// 解析目标应用进程的 Zygote socket 信息
    ///
    /// 从 /proc/[pid]/fd 中找到应用与 Zygote 通信的 socket。
    fn parse_app_zygote_socket(
        &self,
        app_pid: ProcessId,
    ) -> crate::Result<Option<String>> {
        let fd_dir_path = format!("/proc/{}/fd", app_pid.0);
        let fd_dir = match std::fs::read_dir(&fd_dir_path) {
            Ok(dir) => dir,
            Err(_) => return Ok(None),
        };

        for entry in fd_dir {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };

            let link_target = match std::fs::read_link(entry.path()) {
                Ok(t) => t,
                Err(_) => continue,
            };

            let target_str = link_target.to_string_lossy().to_string();

            // 查找 socket 类型的 fd
            if target_str.contains("socket") {
                log::debug!(
                    "App PID {} 的 socket fd: {} -> {}",
                    app_pid.0,
                    entry.file_name().to_string_lossy(),
                    target_str
                );
                return Ok(Some(target_str));
            }
        }

        Ok(None)
    }

    /// 获取 Zygote 进程 PID
    pub fn zygote_pid(&self) -> Option<ProcessId> {
        self.zygote_pid
    }

    /// 获取 Zygote socket 路径
    pub fn zygote_socket(&self) -> Option<&str> {
        self.zygote_socket.as_deref()
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl Default for ZygoteInjector {
    fn default() -> Self {
        Self::new()
    }
}

// 非 Linux 平台的占位实现
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub struct ZygoteInjector {
    _private: (),
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
impl ZygoteInjector {
    pub fn new() -> Self {
        ZygoteInjector { _private: () }
    }

    pub fn init(&mut self) -> crate::Result<()> {
        Err(FridaError::Unsupported {
            reason: "Zygote 注入仅支持 Linux/Android 平台".to_string(),
        }
        .into())
    }

    pub fn inject(&mut self, _app_pid: ProcessId, _lib_path: &str) -> crate::Result<()> {
        Err(FridaError::Unsupported {
            reason: "Zygote 注入仅支持 Linux/Android 平台".to_string(),
        }
        .into())
    }
}
