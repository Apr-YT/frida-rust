//! 核心注入器实现
//!
//! 提供统一的进程注入接口，封装了完整的 ptrace 注入流程。
//! 支持通过 dlopen 加载共享库到目标进程。
//!
//! # 使用方式
//! ```no_run
//! use frida_rust::inject::Injector;
//!
//! let mut injector = Injector::new(target_pid);
//! injector.inject_library("/path/to/libhook.so")?;
//! ```

use crate::common::error::FridaError;
use crate::common::types::ProcessId;
use crate::common::util;
use std::path::Path;

/// 注入器
///
/// 持有目标进程的 PID，封装了完整的共享库注入流程。
/// 通过 ptrace 附加目标进程，在目标进程中调用 dlopen 加载指定共享库。
///
/// # 生命周期
/// 1. 创建 Injector 指定目标 PID
/// 2. 调用 `inject_library()` 执行注入
/// 3. 析构时自动清理（脱离 ptrace、释放远程内存）
pub struct Injector {
    /// 目标进程 ID
    target_pid: ProcessId,
    /// 底层 ptrace 操作器
    ptrace: super::ptrace_inject::PtraceInjector,
    /// 注入过程中分配的远程资源地址（用于自动清理）
    remote_allocs: Vec<RemoteAlloc>,
}

/// 远程分配资源记录
#[derive(Debug)]
struct RemoteAlloc {
    /// 远程地址
    addr: u64,
    /// 分配大小
    size: usize,
}

impl Injector {
    /// 创建新的注入器
    ///
    /// # 参数
    /// - `target_pid`: 目标进程 ID
    ///
    /// # 注意
    /// 不会立即附加到目标进程，只在注入时才附加。
    pub fn new(target_pid: ProcessId) -> Self {
        Injector {
            target_pid,
            ptrace: super::ptrace_inject::PtraceInjector::new(),
            remote_allocs: Vec::new(),
        }
    }

    /// 将共享库注入到目标进程
    ///
    /// 完整的 ptrace 注入流程：
    /// 1. 验证目标进程存活
    /// 2. 检查共享库文件存在
    /// 3. ptrace 附加目标进程（静默附着）
    /// 4. 查找目标进程中的 dlopen 地址
    /// 5. 在目标进程中分配远程内存
    /// 6. 将 so 路径写入远程内存
    /// 7. 保存目标线程原始寄存器
    /// 8. 执行远程 dlopen 调用
    /// 9. 恢复原始寄存器
    /// 10. 释放远程内存并脱离 ptrace
    ///
    /// # 参数
    /// - `lib_path`: 要注入的共享库的绝对路径
    ///
    /// # 错误
    /// - 目标进程不存在
    /// - 共享库文件不存在
    /// - ptrace 附加失败（权限不足或进程已被 trace）
    /// - 远程内存分配失败
    /// - dlopen 远程调用失败
    pub fn inject_library(&mut self, lib_path: &str) -> crate::Result<()> {
        let pid = self.target_pid;
        log::info!("开始注入: PID={}, 库={}", pid.0, lib_path);

        // 1. 验证目标进程存活
        if !util::is_process_alive(pid) {
            return Err(FridaError::Inject {
                reason: format!("目标进程 {} 不存在或已终止", pid.0),
                pid: pid.0,
                source: None,
            }
            .into());
        }

        // 2. 检查共享库文件存在
        if !Path::new(lib_path).exists() {
            return Err(FridaError::NotFound {
                reason: format!("共享库文件不存在: {}", lib_path),
            }
            .into());
        }

        // 3. ptrace 附加目标进程
        self.attach_process()?;

        // 使用 scopeguard 确保异常时也能清理
        let result = self.inject_library_inner(lib_path);

        // 无论成功失败都尝试脱离
        if let Err(e) = self.detach_process() {
            log::warn!("脱离目标进程失败: {}", e);
        }

        // 清理远程分配的内存
        self.cleanup_allocs();

        match result {
            Ok(()) => {
                log::info!("注入完成: PID={}, 库={}", pid.0, lib_path);
                Ok(())
            }
            Err(e) => {
                log::error!("注入失败: PID={}, 库={}, 错误: {}", pid.0, lib_path, e);
                Err(e)
            }
        }
    }

    /// 内部注入实现（假设已附加到目标进程）
    fn inject_library_inner(&mut self, lib_path: &str) -> crate::Result<()> {
        let pid = self.target_pid;

        // 4. 查找目标进程中的 dlopen 地址
        let dlopen_addr = self
            .ptrace
            .find_remote_dlopen(pid)
            .map_err(|_| FridaError::Inject {
                reason: format!("找不到 dlopen 地址"),
                pid: pid.0,
                source: None,
            })?;

        log::debug!("目标进程中 dlopen 地址: {:#x}", dlopen_addr);

        // 5. 在目标进程中分配远程内存
        let path_bytes = lib_path.as_bytes();
        let path_len = path_bytes.len() + 1; // 包含 null 终止符
        let remote_path_addr = self.ptrace.alloc_remote(pid, path_len)?;

        // 记录分配（用于后续清理）
        self.remote_allocs.push(RemoteAlloc {
            addr: remote_path_addr,
            size: path_len,
        });

        // 6. 将 so 路径写入远程内存
        let mut path_with_null = path_bytes.to_vec();
        path_with_null.push(0); // 添加 null 终止符

        self.ptrace.write_remote(
            pid,
            remote_path_addr as usize,
            &path_with_null,
        )?;

        log::debug!(
            "库路径已写入远程地址 {:#x}: {}",
            remote_path_addr,
            lib_path
        );

        // 7. 保存目标线程原始寄存器
        let tid = pid.0 as i32;
        let _orig_regs = self.ptrace.save_regs(tid)?;

        // 8. 执行远程 dlopen 调用
        // dlopen(filename, flag)
        // flag = RTLD_LAZY (1) 表示延迟绑定
        let dlopen_args = vec![
            remote_path_addr, // filename
            1u64,             // flag = RTLD_LAZY
        ];

        log::debug!("调用远程 dlopen({:#x}, RTLD_LAZY)", remote_path_addr);

        // 在目标进程分配 BKPT 跳板页（需要 RWX，SIGTRAP 不会触发动态链接器清理）
        let trap_page = self.ptrace.alloc_remote_rwx(pid, 0x1000)?;
        let bkpt_insn: u32 = 0xD4200000u32; // BKPT #0
        self.ptrace.write_remote(pid, trap_page as usize, &bkpt_insn.to_ne_bytes())?;
        log::debug!("BKPT 跳板分配于 {:#x}", trap_page);

        let handle = self.ptrace.call_remote_trap(tid, dlopen_addr, &dlopen_args, trap_page)?;

        if handle == 0 {
            // dlopen 返回 NULL 表示加载失败
            log::error!("远程 dlopen 返回 NULL，库加载失败");
            return Err(FridaError::Inject {
                reason: format!(
                    "远程 dlopen 返回 NULL，库 {} 加载失败",
                    lib_path
                ),
                pid: pid.0,
                source: None,
            }
            .into());
        }

        // 9. 恢复原始寄存器
        self.ptrace.restore_regs(tid)?;

        log::info!(
            "远程 dlopen 成功，handle = {:#x}",
            handle
        );

        // 10. 脱离和清理在 inject_library 中处理

        Ok(())
    }

    /// 静默附着到目标进程
    ///
    /// 使用 ptrace(PTRACE_ATTACH) 暂停目标进程。
    /// 调用后目标进程将处于 stopped 状态，
    /// 直到调用 `detach_process()` 或 `PTRACE_CONT`。
    ///
    /// # 错误
    /// - 进程不存在
    /// - 权限不足
    /// - 进程已被其他进程 ptrace
    pub fn attach_process(&mut self) -> crate::Result<()> {
        self.ptrace.attach(self.target_pid)
    }

    /// 脱离目标进程
    ///
    /// 使用 ptrace(PTRACE_DETACH) 恢复目标进程正常执行。
    /// 同时恢复所有已保存的寄存器状态。
    pub fn detach_process(&mut self) -> crate::Result<()> {
        if self.ptrace.is_attached() {
            self.ptrace.detach()?;
        }
        Ok(())
    }

    /// 获取目标 PID
    pub fn target_pid(&self) -> ProcessId {
        self.target_pid
    }

    /// 检查是否已附加到目标进程
    pub fn is_attached(&self) -> bool {
        self.ptrace.is_attached()
    }

    /// 获取底层 ptrace 操作器的引用
    ///
    /// 用于高级操作，如直接读写远程内存等。
    pub fn ptrace(&self) -> &super::ptrace_inject::PtraceInjector {
        &self.ptrace
    }

    /// 获取底层 ptrace 操作器的可变引用
    pub fn ptrace_mut(&mut self) -> &mut super::ptrace_inject::PtraceInjector {
        &mut self.ptrace
    }

    /// 清理所有远程分配的资源
    ///
    /// 释放注入过程中分配的远程内存。
    /// 通常在注入完成或失败后调用。
    fn cleanup_allocs(&mut self) {
        for alloc in &self.remote_allocs {
            if let Err(e) = self.ptrace.free_remote(
                self.target_pid,
                alloc.addr,
                alloc.size,
            ) {
                log::warn!(
                    "释放远程内存失败: addr={:#x}, size={}, error={}",
                    alloc.addr,
                    alloc.size,
                    e
                );
            }
        }
        self.remote_allocs.clear();
        log::debug!("远程内存清理完成");
    }
}

impl Drop for Injector {
    /// 析构时自动脱离并清理
    fn drop(&mut self) {
        if self.ptrace.is_attached() {
            log::debug!("Injector drop: 自动脱离目标进程");
            let _ = self.detach_process();
        }
        self.cleanup_allocs();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_injector_creation() {
        let injector = Injector::new(ProcessId(1));
        assert_eq!(injector.target_pid().0, 1);
        assert!(!injector.is_attached());
    }
}
