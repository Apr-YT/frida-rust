//! ptrace 注入方式完整实现
//!
//! 提供 ptrace 底层操作的完整封装，包括：
//! - 附加/脱离目标进程或线程
//! - 读写目标进程寄存器
//! - 远程内存分配与数据读写
//! - 远程函数调用
//!
//! # 使用方式
//! ```no_run
//! use frida_rust::inject::ptrace_inject::PtraceInjector;
//!
//! let mut injector = PtraceInjector::new();
//! injector.attach(target_pid)?;
//! let regs = injector.get_regs(target_tid)?;
//! injector.detach()?;
//! ```

use crate::common::constants::{
    PTRACE_MAX_RETRIES, PTRACE_RETRY_INTERVAL_MS,
};
use crate::common::error::FridaError;
use crate::common::types::ProcessId;
use crate::common::util;

// ======================== 架构相关的寄存器类型与常量 ========================

/// AArch64 使用自定义的 user_pt_regs（libc 0.2 未暴露该类型）
#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct user_pt_regs {
    regs: [u64; 31],
    sp: u64,
    pc: u64,
    pstate: u64,
}

#[cfg(target_arch = "x86_64")]
pub type UserRegs = libc::user_regs_struct;

#[cfg(target_arch = "aarch64")]
pub type UserRegs = user_pt_regs;

#[cfg(all(target_arch = "aarch64", target_os = "android"))]
const PTRACE_GETREGSET: libc::c_int = 0x4204;
#[cfg(all(target_arch = "aarch64", not(target_os = "android")))]
const PTRACE_GETREGSET: libc::c_uint = 0x4204;
#[cfg(all(target_arch = "aarch64", target_os = "android"))]
const PTRACE_SETREGSET: libc::c_int = 0x4205;
#[cfg(all(target_arch = "aarch64", not(target_os = "android")))]
const PTRACE_SETREGSET: libc::c_uint = 0x4205;
#[cfg(target_arch = "aarch64")]
const NT_PRSTATUS: libc::c_int = 1;

#[cfg(target_arch = "aarch64")]
const PTRACE_INTERRUPT_VAL: libc::c_int = 0x4207;

/// ptrace 注入器
///
/// 封装了 ptrace 系统调用的所有底层操作，提供安全的高级接口。
/// 通过 PtraceInjector 可以：
/// 1. 附加到目标进程
/// 2. 读取/修改目标进程寄存器
/// 3. 在目标进程中分配/释放内存
/// 4. 读写目标进程内存
/// 5. 在目标进程中执行远程函数调用
pub struct PtraceInjector {
    /// 是否已附加到目标进程
    attached: bool,
    /// 目标进程 ID
    target_pid: Option<ProcessId>,
    /// 保存的原始寄存器状态（按线程 ID 索引）
    saved_regs: std::collections::HashMap<u32, UserRegs>,
    /// 分配的远程内存地址（用于清理）
    allocated_addrs: Vec<usize>,
}

impl PtraceInjector {
    /// 创建新的 ptrace 注入器实例
    pub fn new() -> Self {
        PtraceInjector {
            attached: false,
            target_pid: None,
            saved_regs: std::collections::HashMap::new(),
            allocated_addrs: Vec::new(),
        }
    }

    /// 附加到目标进程
    ///
    /// 使用 `ptrace(PTRACE_ATTACH)` 静默附着到目标进程，
    /// 使目标进程暂停执行并等待其停止。
    ///
    /// # 参数
    /// - `pid`: 目标进程 ID
    ///
    /// # 错误
    /// - 目标进程不存在
    /// - 权限不足（需要 root 或相同 uid）
    /// - 目标进程已被其他进程 ptrace
    pub fn attach(&mut self, pid: ProcessId) -> crate::Result<()> {
        log::info!("ptrace attach 到 PID {}", pid.0);

        if !util::is_process_alive(pid) {
            return Err(FridaError::Inject {
                reason: format!("目标进程 {} 不存在", pid.0),
                pid: pid.0,
                source: None,
            }.into());
        }

        let pid_i32 = pid.0 as libc::pid_t;

        // 优先尝试 PTRACE_SEIZE（不发送 SIGSTOP，适合有反调试的进程如微信）
        // PTRACE_SEIZE = 0x4206, PTRACE_O_TRACESYSGOOD = 0x00000001
        #[cfg(target_os = "android")]
        {
            const PTRACE_SEIZE: libc::c_int = 0x4206;
            let ret = unsafe { libc::ptrace(PTRACE_SEIZE, pid_i32, 0, 0x00000001usize) };
            if ret == 0 {
                log::info!("ptrace SEIZE 到 PID {} 成功 (无 SIGSTOP)", pid.0);
                // SEIZE 后立即用 INTERRUPT 停止主线程
                let _ = unsafe { libc::ptrace(PTRACE_INTERRUPT_VAL, pid_i32, 0, 0) };
                self.wait_for_stop(pid)?;
                self.attached = true;
                self.target_pid = Some(pid);
                log::info!("ptrace attach 到 PID {} 成功 (SEIZE+INTERRUPT)", pid.0);
                return Ok(());
            }
            log::debug!("PTRACE_SEIZE 失败 (errno={}), 回退 PTRACE_ATTACH", std::io::Error::last_os_error());
        }

        // 回退：传统 PTRACE_ATTACH
        let mut retry_count = 0;
        loop {
            let ret = unsafe { libc::ptrace(libc::PTRACE_ATTACH, pid_i32, 0, 0) };
            if ret == 0 {
                break;
            }
            let errno = std::io::Error::last_os_error();
            let errno_raw = errno.raw_os_error().unwrap_or(0);
            if errno_raw == libc::ESRCH {
                return Err(FridaError::Ptrace {
                    op: "ATTACH".to_string(), pid: pid.0,
                    detail: format!("进程不存在: {}", errno),
                }.into());
            }
            if errno_raw == libc::EPERM {
                return Err(FridaError::Ptrace {
                    op: "ATTACH".to_string(), pid: pid.0,
                    detail: format!("权限不足或进程已被 trace: {}", errno),
                }.into());
            }
            retry_count += 1;
            if retry_count >= PTRACE_MAX_RETRIES {
                return Err(FridaError::Ptrace {
                    op: "ATTACH".to_string(), pid: pid.0,
                    detail: format!("重试 {} 次后仍失败: {}", PTRACE_MAX_RETRIES, errno),
                }.into());
            }
            log::debug!("ptrace attach 失败 ({}), 第 {} 次重试...", errno, retry_count);
            std::thread::sleep(std::time::Duration::from_millis(PTRACE_RETRY_INTERVAL_MS));
        }

        self.wait_for_stop(pid)?;
        self.attached = true;
        self.target_pid = Some(pid);
        log::info!("ptrace attach 到 PID {} 成功", pid.0);
        Ok(())
    }

    /// 脱离目标进程并清理痕迹
    ///
    /// 使用 `ptrace(PTRACE_DETACH)` 脱离目标进程，
    /// 恢复其正常执行。同时清理所有已分配的远程内存。
    pub fn detach(&mut self) -> crate::Result<()> {
        if let Some(pid) = self.target_pid {
            log::info!("ptrace detach 从 PID {}", pid.0);
            let pid_i32 = pid.0 as libc::pid_t;

            // 先恢复所有保存的寄存器
            for (&tid, &regs) in &self.saved_regs {
                if tid == pid.0 {
                    let _ = self.set_regs(tid as libc::pid_t, regs);
                }
            }

            // 使用 PTRACE_DETACH 脱离进程
            // SAFETY: ptrace(PTRACE_DETACH) 在已附加的进程上调用是安全的
            let ret = unsafe { libc::ptrace(libc::PTRACE_DETACH, pid_i32, 0, 0) };
            if ret != 0 {
                let errno = std::io::Error::last_os_error();
                log::warn!("ptrace detach 失败: {}", errno);
                // 继续清理，不因此失败
            }

            self.attached = false;
            self.target_pid = None;
            self.saved_regs.clear();
            self.allocated_addrs.clear();

            log::info!("ptrace detach 成功");
        }
        Ok(())
    }

    /// 获取目标线程的寄存器状态
    ///
    /// x86_64 使用 `ptrace(PTRACE_GETREGS)`，AArch64 使用 `ptrace(PTRACE_GETREGSET)`。
    ///
    /// # 参数
    /// - `tid`: 目标线程 ID（对于单线程进程，tid == pid）
    ///
    /// # 返回值
    /// 返回包含所有寄存器值的架构相关寄存器结构体。
    #[cfg(target_arch = "x86_64")]
    pub fn get_regs(&self, tid: i32) -> crate::Result<UserRegs> {
        let mut regs: UserRegs = unsafe { std::mem::zeroed() };

        // SAFETY: ptrace(PTRACE_GETREGS) 需要在已附加的线程上调用
        let ret = unsafe {
            libc::ptrace(
                libc::PTRACE_GETREGS,
                tid,
                std::ptr::null_mut::<libc::c_void>(),
                &mut regs as *mut _ as *mut libc::c_void,
            )
        };

        if ret != 0 {
            let errno = std::io::Error::last_os_error();
            return Err(FridaError::Ptrace {
                op: "GETREGS".to_string(),
                pid: tid as u32,
                detail: format!("读取寄存器失败: {}", errno),
            }
            .into());
        }

        Ok(regs)
    }

    #[cfg(target_arch = "aarch64")]
    pub fn get_regs(&self, tid: i32) -> crate::Result<UserRegs> {
        let mut regs: UserRegs = unsafe { std::mem::zeroed() };
        let mut iov = libc::iovec {
            iov_base: &mut regs as *mut _ as *mut libc::c_void,
            iov_len: std::mem::size_of::<UserRegs>(),
        };

        // SAFETY: ptrace(PTRACE_GETREGSET) 需要在已附加的线程上调用
        let ret = unsafe {
            libc::ptrace(
                PTRACE_GETREGSET,
                tid,
                NT_PRSTATUS as *mut libc::c_void,
                &mut iov as *mut _ as *mut libc::c_void,
            )
        };

        if ret != 0 {
            let errno = std::io::Error::last_os_error();
            return Err(FridaError::Ptrace {
                op: "GETREGSET".to_string(),
                pid: tid as u32,
                detail: format!("读取寄存器失败: {}", errno),
            }
            .into());
        }

        Ok(regs)
    }

    /// 设置目标线程的寄存器状态
    ///
    /// x86_64 使用 `ptrace(PTRACE_SETREGS)`，AArch64 使用 `ptrace(PTRACE_SETREGSET)`。
    ///
    /// # 参数
    /// - `tid`: 目标线程 ID
    /// - `regs`: 要设置的寄存器值
    #[cfg(target_arch = "x86_64")]
    pub fn set_regs(&self, tid: libc::pid_t, regs: UserRegs) -> crate::Result<()> {
        // SAFETY: ptrace(PTRACE_SETREGS) 需要在已附加的线程上调用
        let ret = unsafe {
            libc::ptrace(
                libc::PTRACE_SETREGS,
                tid,
                std::ptr::null_mut::<libc::c_void>(),
                &regs as *const _ as *mut libc::c_void,
            )
        };

        if ret != 0 {
            let errno = std::io::Error::last_os_error();
            return Err(FridaError::Ptrace {
                op: "SETREGS".to_string(),
                pid: tid as u32,
                detail: format!("设置寄存器失败: {}", errno),
            }
            .into());
        }

        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    pub fn set_regs(&self, tid: libc::pid_t, regs: UserRegs) -> crate::Result<()> {
        let mut iov = libc::iovec {
            iov_base: &regs as *const _ as *mut libc::c_void,
            iov_len: std::mem::size_of::<UserRegs>(),
        };

        // SAFETY: ptrace(PTRACE_SETREGSET) 需要在已附加的线程上调用
        let ret = unsafe {
            libc::ptrace(
                PTRACE_SETREGSET,
                tid,
                NT_PRSTATUS as *mut libc::c_void,
                &mut iov as *mut _ as *mut libc::c_void,
            )
        };

        if ret != 0 {
            let errno = std::io::Error::last_os_error();
            return Err(FridaError::Ptrace {
                op: "SETREGSET".to_string(),
                pid: tid as u32,
                detail: format!("设置寄存器失败: {}", errno),
            }
            .into());
        }

        Ok(())
    }

    /// 保存并返回指定线程的原始寄存器状态
    ///
    /// 在修改寄存器前调用此方法保存原始状态，
    /// 后续可通过 `restore_regs()` 恢复。
    ///
    /// # 参数
    /// - `tid`: 目标线程 ID
    pub fn save_regs(&mut self, tid: i32) -> crate::Result<UserRegs> {
        let regs = self.get_regs(tid)?;
        self.saved_regs.insert(tid as u32, regs);
        log::debug!("已保存 TID {} 的寄存器状态", tid);
        Ok(regs)
    }

    /// 恢复指定线程的原始寄存器状态
    ///
    /// 使用之前 `save_regs()` 保存的寄存器值恢复线程状态。
    ///
    /// # 参数
    /// - `tid`: 目标线程 ID
    pub fn restore_regs(&mut self, tid: i32) -> crate::Result<()> {
        if let Some(&saved) = self.saved_regs.get(&(tid as u32)) {
            self.set_regs(tid, saved)?;
            self.saved_regs.remove(&(tid as u32));
            log::debug!("已恢复 TID {} 的寄存器状态", tid);
        }
        Ok(())
    }

    /// 在目标进程中执行远程函数调用
    ///
    /// 通过修改目标线程的寄存器（将 PC 设置为函数地址，设置参数寄存器），
    /// 然后单步执行直到函数返回，获取返回值。
    ///
    /// # 参数
    /// - `tid`: 要执行函数的线程 ID
    /// - `func_addr`: 函数在目标进程中的地址
    /// - `args`: 函数参数（最多 6 个，对应 x86_64 的 rdi/rsi/rdx/rcx/r8/r9）
    ///
    /// # 返回值
    /// 返回函数的返回值（在 rax 寄存器中）。
    ///
    /// # 注意
    /// 此方法在 x86_64 上通过设置 rip 和参数寄存器来实现远程调用，
    /// 使用 PTRACE_SINGLESTEP 逐步执行直到 rip 到达返回后的地址。
    #[cfg(target_arch = "x86_64")]
    pub fn call_remote(
        &mut self,
        tid: i32,
        func_addr: u64,
        args: &[u64],
    ) -> crate::Result<u64> {
        // 保存原始寄存器
        let orig_regs = self.save_regs(tid)?;

        // 设置参数寄存器
        let mut regs = orig_regs;
        regs.rip = func_addr; // 设置指令指针到目标函数

        // x86_64 System V ABI 参数传递顺序: rdi/rsi/rdx/rcx/r8/r9
        if args.len() > 0 {
            regs.rdi = args[0];
        }
        if args.len() > 1 {
            regs.rsi = args[1];
        }
        if args.len() > 2 {
            regs.rdx = args[2];
        }
        if args.len() > 3 {
            regs.rcx = args[3];
        }
        if args.len() > 4 {
            regs.r8 = args[4];
        }
        if args.len() > 5 {
            regs.r9 = args[5];
        }

        // 设置栈帧（rsp 对齐到 16 字节）并写入一个虚假的返回地址
        // 我们在目标进程中分配一个小区域作为 "返回陷阱"
        let _pid = self.target_pid.ok_or_else(|| FridaError::Other(
            "未附加到任何进程".to_string(),
        ))?;

        // 使用 PTRACE_CONT 让线程执行，然后通过信号停止
        // 先设置修改后的寄存器
        self.set_regs(tid, regs)?;

        // 记录一个哨兵值到栈上作为返回检测
        // 这里简化处理：使用 PTRACE_CONT 后等待 SIGTRAP
        // SAFETY: PTRACE_CONT 在已附加的线程上调用
        let ret = unsafe {
            libc::ptrace(libc::PTRACE_CONT, tid, 0, 0)
        };
        if ret != 0 {
            return Err(FridaError::Ptrace {
                op: "CONT".to_string(),
                pid: tid as u32,
                detail: format!("继续执行失败: {}", std::io::Error::last_os_error()),
            }
            .into());
        }

        // 等待线程停止
        self.wait_for_stop_by_tid(tid as u32)?;

        // 读取返回值（rax 寄存器）
        let final_regs = self.get_regs(tid)?;

        // 恢复原始寄存器
        self.restore_regs(tid)?;

        log::debug!(
            "远程调用完成，返回值 rax = {:#x}",
            final_regs.rax
        );

        Ok(final_regs.rax)
    }

    /// 在目标进程中执行远程函数调用（AArch64 版本）
    #[cfg(target_arch = "aarch64")]
    pub fn call_remote(
        &mut self,
        tid: i32,
        func_addr: u64,
        args: &[u64],
    ) -> crate::Result<u64> {
        self.call_remote_inner(tid, func_addr, args, 0 /* LR=0 → SIGSEGV */)
    }

    /// call_remote variant: sets LR to a BKPT page → SIGTRAP (cleaner, doesn't crash process)
    #[cfg(target_arch = "aarch64")]
    pub fn call_remote_trap(
        &mut self,
        tid: i32,
        func_addr: u64,
        args: &[u64],
        trap_addr: u64,
    ) -> crate::Result<u64> {
        self.call_remote_inner(tid, func_addr, args, trap_addr)
    }

    #[cfg(target_arch = "aarch64")]
    fn call_remote_inner(
        &mut self,
        tid: i32,
        func_addr: u64,
        args: &[u64],
        return_trap: u64,
    ) -> crate::Result<u64> {
        // 保存原始寄存器
        let orig_regs = self.save_regs(tid)?;

        let mut regs = orig_regs;
        // AArch64 user_regs_struct 中的 pc 字段
        regs.pc = func_addr;

        // AArch64 参数传递使用 x0-x7
        for (i, arg) in args.iter().enumerate() {
            if i < 8 {
                regs.regs[i] = *arg;
            }
        }

        // LR = trap address: 0→SIGSEGV for syscalls, BKPT page→SIGTRAP for dlopen
        regs.regs[30] = return_trap;

        // 设置栈指针对齐
        regs.sp &= !0xFu64; // 16 字节对齐

        self.set_regs(tid, regs)?;

        // 继续执行
        // SAFETY: PTRACE_CONT 在已附加的线程上调用
        let ret = unsafe {
            libc::ptrace(libc::PTRACE_CONT, tid, 0, 0)
        };
        if ret != 0 {
            return Err(FridaError::Ptrace {
                op: "CONT".to_string(),
                pid: tid as u32,
                detail: format!("继续执行失败: {}", std::io::Error::last_os_error()),
            }
            .into());
        }

        // 等待远程函数执行完毕（返回后因 LR=0 导致 SIGSEGV）
        let start = std::time::Instant::now();
        let max_wait = std::time::Duration::from_secs(3);
        let mut status: libc::c_int = 0;
        let mut first_wait = true;
        loop {
            if start.elapsed() > max_wait {
                // 超时：尝试用 PTRACE_INTERRUPT 强制停止
                let _ = unsafe { libc::ptrace(PTRACE_INTERRUPT_VAL, tid, 0, 0) };
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            // 第一次尝试阻塞，之后丢轮询
            let flags = if first_wait { 0 } else { libc::WNOHANG };
            first_wait = false;
            let wret = unsafe { libc::waitpid(tid, &mut status, flags) };
            if wret < 0 {
                let errno = std::io::Error::last_os_error();
                if errno.raw_os_error() == Some(libc::EINTR) {
                    continue; // 被信号中断，重试
                }
                return Err(FridaError::Ptrace {
                    op: "WAIT".to_string(),
                    pid: tid as u32,
                    detail: format!("waitpid 失败: {}", errno),
                }
                .into());
            }

            if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                return Err(FridaError::Ptrace {
                    op: "CALL".to_string(),
                    pid: tid as u32,
                    detail: format!(
                        "目标线程在执行远程调用时终止，退出码: {}",
                        if libc::WIFEXITED(status) { libc::WEXITSTATUS(status) } else { -1 }
                    ),
                }
                .into());
            }

            if libc::WIFSTOPPED(status) {
                let sig = libc::WSTOPSIG(status);
                // SIGSEGV from LR=0, SIGTRAP from BKPT trap page, SIGILL from invalid code
                if sig == libc::SIGSEGV || sig == libc::SIGTRAP || sig == libc::SIGILL {
                    break; // 预期信号：远程函数执行完毕
                }
                if sig == libc::SIGSTOP {
                    // 额外的 SIGSTOP（多线程 ptrace 行为），继续执行
                    let _ = unsafe { libc::ptrace(libc::PTRACE_CONT, tid, 0, 0) };
                    continue;
                }
                // 其他信号：转发给目标线程
                log::debug!("远程调用期间收到信号 {}，转发", sig);
                let _ = unsafe {
                    libc::ptrace(libc::PTRACE_CONT, tid, 0, sig as libc::c_ulong)
                };
                continue;
            }
        }

        // 读取返回值（x0 寄存器）
        let final_regs = self.get_regs(tid)?;

        // 恢复原始寄存器（让线程在原来的位置继续执行）
        self.set_regs(tid, orig_regs)?;
        // 清理 saved_regs 中的记录（由 save_regs 添加的）
        self.saved_regs.remove(&(tid as u32));

        let return_val = final_regs.regs[0];
        log::debug!(
            "远程调用完成，返回值 x0 = {:#x}",
            return_val
        );

        Ok(return_val)
    }

    /// 在非 x86_64/aarch64 平台的 call_remote 占位
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    pub fn call_remote(
        &mut self,
        _tid: i32,
        _func_addr: u64,
        _args: &[u64],
    ) -> crate::Result<u64> {
        Err(FridaError::Unsupported {
            reason: "远程调用仅支持 x86_64 和 aarch64 架构".to_string(),
        }
        .into())
    }

    /// 在目标进程中分配远程内存
    ///
    /// 通过让目标进程调用 `mmap` 系统调用来分配内存。
    /// 先找到目标进程中 mmap 的地址，然后通过远程调用执行 mmap。
    ///
    /// # 参数
    /// - `pid`: 目标进程 ID
    /// - `size`: 要分配的内存大小（字节）
    ///
    /// # 返回值
    /// 返回分配的远程内存地址。
    pub fn alloc_remote(&mut self, pid: ProcessId, size: usize) -> crate::Result<u64> {
        self.alloc_remote_with_prot(pid, size, (libc::PROT_READ | libc::PROT_WRITE) as u64)
    }

    /// 在目标进程中分配可执行远程内存（RWX）——用于跳板/BKPT 页
    pub fn alloc_remote_rwx(&mut self, pid: ProcessId, size: usize) -> crate::Result<u64> {
        self.alloc_remote_with_prot(pid, size, (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) as u64)
    }

    fn alloc_remote_with_prot(&mut self, pid: ProcessId, size: usize, prot: u64) -> crate::Result<u64> {
        let page_size = util::page_size();
        let aligned_size = (size + page_size - 1) & !(page_size - 1);
        let mmap_addr = self.find_remote_mmap(pid)?;
        let tid = pid.0 as i32;
        let args = vec![
            0, aligned_size as u64, prot,
            (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64,
            !0u64, 0,
        ];

        let result = self.call_remote(tid, mmap_addr, &args)?;

        if result == !0u64 || result == 0 {
            return Err(FridaError::MemoryWrite {
                address: 0,
                size,
                reason: format!("远程 mmap 返回无效地址: {:#x}", result),
            }
            .into());
        }

        self.allocated_addrs.push(result as usize);
        log::debug!("远程内存分配成功，地址: {:#x}，大小: {}", result, aligned_size);
        Ok(result)
    }

    /// 释放之前分配的远程内存
    ///
    /// 通过远程调用 munmap 来释放内存。
    ///
    /// # 参数
    /// - `pid`: 目标进程 ID
    /// - `addr`: 要释放的内存地址
    /// - `size`: 内存大小
    pub fn free_remote(&mut self, pid: ProcessId, addr: u64, size: usize) -> crate::Result<()> {
        log::debug!("释放 PID {} 地址 {:#x} 的远程内存", pid.0, addr);

        let page_size = util::page_size();
        let aligned_size = (size + page_size - 1) & !(page_size - 1);

        // 查找 munmap 地址
        let munmap_addr = self.find_remote_munmap(pid)?;

        let tid = pid.0 as i32;
        let args = vec![addr, aligned_size as u64];
        self.call_remote(tid, munmap_addr, &args)?;

        self.allocated_addrs.retain(|&a| a != addr as usize);
        log::debug!("远程内存释放成功");
        Ok(())
    }

    /// 向目标进程内存写入数据
    ///
    /// 优先使用 `process_vm_writev` 系统调用（高效），
    /// 如果失败则回退到 `ptrace(PTRACE_POKEDATA)` 方式。
    ///
    /// # 参数
    /// - `pid`: 目标进程 ID
    /// - `addr`: 目标虚拟地址
    /// - `data`: 要写入的数据
    pub fn write_remote(&self, pid: ProcessId, addr: usize, data: &[u8]) -> crate::Result<()> {
        // 优先尝试 process_vm_writev（更高效）
        match util::safe_write_bytes(pid, addr, data) {
            Ok(()) => return Ok(()),
            Err(e) => {
                log::debug!("process_vm_writev 失败，回退到 PTRACE_POKEDATA: {}", e);
            }
        }

        // 回退到 ptrace POKEDATA 方式
        self.write_remote_ptrace(pid, addr, data)
    }

    /// 通过 ptrace POKEDATA 向目标进程写入数据
    ///
    /// 以 sizeof(long) 为单位逐字写入目标进程内存。
    fn write_remote_ptrace(&self, pid: ProcessId, addr: usize, data: &[u8]) -> crate::Result<()> {
        let pid_i32 = pid.0 as libc::pid_t;
        let word_size = std::mem::size_of::<libc::c_long>();

        // 逐字写入
        let mut offset = 0;
        while offset < data.len() {
            let remaining = data.len() - offset;
            let chunk_size = std::cmp::min(remaining, word_size);

            // 读取原始数据（用于部分写入时保持未修改字节不变）
            let orig_word = self.peek_data(pid_i32, (addr + offset) as *mut libc::c_void)?;
            let orig_word = orig_word as u64; // 转为 u64 进行位运算

            // 构建新数据：保持高位不变，只写入需要的字节
            let mut new_word = orig_word;
            let bytes = &data[offset..offset + chunk_size];
            for (i, &byte) in bytes.iter().enumerate() {
                let shift = (i * 8) as u32; // 小端序
                new_word = (new_word & !(0xFFu64 << shift)) | ((byte as u64) << shift);
            }

            // SAFETY: PTRACE_POKEDATA 写入已附加进程的内存
            let ret = unsafe {
                libc::ptrace(
                    libc::PTRACE_POKEDATA,
                    pid_i32,
                    (addr + offset) as *mut libc::c_void,
                    new_word as *mut libc::c_void,
                )
            };

            if ret != 0 {
                return Err(FridaError::MemoryWrite {
                    address: addr + offset,
                    size: chunk_size,
                    reason: format!(
                        "PTRACE_POKEDATA 失败: {}",
                        std::io::Error::last_os_error()
                    ),
                }
                .into());
            }

            offset += word_size;
        }

        log::debug!(
            "通过 PTRACE_POKEDATA 写入 {} 字节到 PID {} 地址 {:#x}",
            data.len(),
            pid.0,
            addr
        );
        Ok(())
    }

    /// 从目标进程内存读取数据
    ///
    /// 优先使用 `process_vm_readv` 系统调用（高效），
    /// 如果失败则回退到 `ptrace(PTRACE_PEEKDATA)` 方式。
    ///
    /// # 参数
    /// - `pid`: 目标进程 ID
    /// - `addr`: 目标虚拟地址
    /// - `size`: 要读取的字节数
    ///
    /// # 返回值
    /// 返回读取到的数据。
    pub fn read_remote(&self, pid: ProcessId, addr: usize, size: usize) -> crate::Result<Vec<u8>> {
        // 优先尝试 process_vm_readv（更高效）
        match util::safe_read_bytes(pid, addr, size) {
            Ok(data) => return Ok(data),
            Err(e) => {
                log::debug!("process_vm_readv 失败，回退到 PTRACE_PEEKDATA: {}", e);
            }
        }

        // 回退到 ptrace PEEKDATA 方式
        self.read_remote_ptrace(pid, addr, size)
    }

    /// 通过 ptrace PEEKDATA 从目标进程读取数据
    ///
    /// 以 sizeof(long) 为单位逐字读取目标进程内存。
    fn read_remote_ptrace(
        &self,
        pid: ProcessId,
        addr: usize,
        size: usize,
    ) -> crate::Result<Vec<u8>> {
        let pid_i32 = pid.0 as libc::pid_t;
        let word_size = std::mem::size_of::<libc::c_long>();

        let mut result = Vec::with_capacity(size);
        let mut offset = 0;

        while offset < size {
            let word = self.peek_data(pid_i32, (addr + offset) as *mut libc::c_void)?;
            let bytes = word.to_ne_bytes();
            let remaining = size - offset;
            let chunk_size = std::cmp::min(remaining, word_size);
            result.extend_from_slice(&bytes[..chunk_size]);
            offset += word_size;
        }

        log::debug!(
            "通过 PTRACE_PEEKDATA 读取 {} 字节从 PID {} 地址 {:#x}",
            result.len(),
            pid.0,
            addr
        );
        Ok(result)
    }

    /// 读取目标进程中的一个机器字（sizeof(long)）
    ///
    /// 使用 `ptrace(PTRACE_PEEKDATA)` 读取。
    fn peek_data(
        &self,
        pid: libc::pid_t,
        addr: *mut libc::c_void,
    ) -> crate::Result<libc::c_long> {
        // SAFETY: PTRACE_PEEKDATA 读取已附加进程的内存
        let ret = unsafe { libc::ptrace(libc::PTRACE_PEEKDATA, pid, addr, 0) };

        // 注意: PTRACE_PEEKDATA 返回值直接就是读取到的数据（嵌入在 errno 之前）
        // 当 ret == -1 时需要判断是真实的错误还是读取到了 -1
        if ret == -1 {
            let errno = std::io::Error::last_os_error();
            if errno.raw_os_error() != Some(0) {
                return Err(FridaError::MemoryRead {
                    address: addr as usize,
                    size: std::mem::size_of::<libc::c_long>(),
                    reason: format!("PTRACE_PEEKDATA 失败: {}", errno),
                }
                .into());
            }
        }

        Ok(ret)
    }

    /// 查找目标进程中 mmap 函数的地址
    ///
    /// 通过解析 /proc/pid/maps 找到 libc 的基址，
    /// 然后计算 mmap 的偏移量得到远程地址。
    fn find_remote_mmap(&self, pid: ProcessId) -> crate::Result<u64> {
        self.find_remote_symbol(pid, "mmap")
    }

    /// 查找目标进程中 munmap 函数的地址
    fn find_remote_munmap(&self, pid: ProcessId) -> crate::Result<u64> {
        self.find_remote_symbol(pid, "munmap")
    }

    /// 查找目标进程中 dlopen 函数的地址
    pub fn find_remote_dlopen(&self, pid: ProcessId) -> crate::Result<u64> {
        self.find_remote_symbol(pid, "__libc_dlopen_mode")
            .or_else(|_| self.find_remote_symbol(pid, "dlopen"))
    }

    /// 查找目标进程中 dlsym 函数的地址
    pub fn find_remote_dlsym(&self, pid: ProcessId) -> crate::Result<u64> {
        self.find_remote_symbol(pid, "__libc_dlsym")
            .or_else(|_| self.find_remote_symbol(pid, "dlsym"))
    }

    /// 查找目标进程中 dlclose 函数的地址
    pub fn find_remote_dlclose(&self, pid: ProcessId) -> crate::Result<u64> {
        self.find_remote_symbol(pid, "__libc_dlclose")
            .or_else(|_| self.find_remote_symbol(pid, "dlclose"))
    }

    /// 查找目标进程中指定符号的地址
    ///
    /// 通过解析 /proc/pid/maps 找到包含该符号的库，
    /// 然后在本地查找对应库的符号偏移量，计算远程地址。
    fn find_remote_symbol(&self, pid: ProcessId, symbol_name: &str) -> crate::Result<u64> {
        use crate::inject::process;

        let modules = process::enum_modules(pid)?;

        // 搜索 libc 和 libdl 等核心库
        for module in &modules {
            if module.name.contains("libc.so")
                || module.name.contains("libc-")
                || module.name.contains("libdl")
                || module.name.contains("linker")
            {
                // 尝试在本地找到对应的库文件
                if let Some(offset) = self.find_local_symbol_offset(&module.name, symbol_name)? {
                    let remote_addr = (module.base_addr + offset) as u64;
                    log::debug!(
                        "符号 {} 在 {} 中: base={:#x}, offset={:#x}, remote={:#x}",
                        symbol_name,
                        module.name,
                        module.base_addr,
                        offset,
                        remote_addr
                    );
                    return Ok(remote_addr);
                }
            }
        }

        Err(FridaError::NotFound {
            reason: format!(
                "在 PID {} 中找不到符号 {}",
                pid.0, symbol_name
            ),
        }
        .into())
    }

    /// 在本地库中查找符号偏移量
    ///
    /// 在本地的共享库文件中解析 ELF 符号表，
    /// 返回指定符号在库中的偏移量。
    fn find_local_symbol_offset(
        &self,
        lib_name: &str,
        symbol_name: &str,
    ) -> crate::Result<Option<usize>> {
        // 常见的搜索路径
        let search_paths = [
            "/lib/x86_64-linux-gnu",
            "/lib/aarch64-linux-gnu",
            "/usr/lib/x86_64-linux-gnu",
            "/usr/lib/aarch64-linux-gnu",
            "/lib",
            "/usr/lib",
            "/system/lib64",
            "/system/lib",
        ];

        for dir in &search_paths {
            let path = std::path::Path::new(dir).join(lib_name);
            if path.exists() {
                let data = std::fs::read(&path)?;
                if let Some(offset) = parse_elf_symbol(&data, symbol_name) {
                    return Ok(Some(offset));
                }
            }
        }

        Ok(None)
    }

    /// 等待目标进程停止
    ///
    /// 使用 waitpid() 等待 PTRACE_ATTACH 后所有线程停止。
    /// 二阶段：先阻塞等待首个 SIGSTOP，再 WNOHANG 排空剩余线程。
    fn wait_for_stop(&self, pid: ProcessId) -> crate::Result<()> {
        let pid_i32 = pid.0 as libc::pid_t;

        // __WALL: 在 Android/Linux 上等待 clone() 出的线程（没有此标志 waitpid 可能只返回主线程）
        #[cfg(target_os = "android")]
        let wall_flag: libc::c_int = 0x40000000;
        #[cfg(not(target_os = "android"))]
        let wall_flag: libc::c_int = 0;

        // 阶段 1：阻塞等待第一个停止事件（可能是任意线程）
        let mut status: libc::c_int = 0;
        loop {
            let ret = unsafe { libc::waitpid(pid_i32, &mut status, wall_flag) };
            if ret < 0 {
                let errno = std::io::Error::last_os_error();
                if errno.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(FridaError::Ptrace {
                    op: "WAIT".to_string(),
                    pid: pid.0,
                    detail: format!("首个 waitpid 失败: {}", errno),
                }.into());
            }
            if libc::WIFSTOPPED(status) {
                log::debug!("首个线程 {} 已停止，信号: {}", ret, libc::WSTOPSIG(status));
                break;
            }
            if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                return Err(FridaError::Ptrace {
                    op: "WAIT".to_string(), pid: pid.0,
                    detail: "进程在 attach 等待期间终止".to_string(),
                }.into());
            }
        }

        // 阶段 2：非阻塞排空剩余线程的停止事件（多轮）
        let mut drained = 1;
        let max_rounds = 8;
        for _round in 0..max_rounds {
            let mut round_had_events = false;
            loop {
                let ret = unsafe { libc::waitpid(pid_i32, &mut status, libc::WNOHANG | wall_flag) };
                if ret <= 0 {
                    break;
                }
                round_had_events = true;
                if libc::WIFSTOPPED(status) {
                    let sig = libc::WSTOPSIG(status);
                    if sig == libc::SIGSTOP || sig == (libc::SIGSTOP | 0x80) {
                        drained += 1;
                    } else {
                        let _ = unsafe { libc::ptrace(libc::PTRACE_CONT, ret, 0, sig as libc::c_ulong) };
                    }
                }
            }
            if !round_had_events {
                break; // 本轮无事件，停止
            }
            // 暂停一下，让更多线程收到 SIGSTOP
            std::thread::sleep(std::time::Duration::from_millis(2));
        }

        log::debug!("目标进程 {} 已就绪 (收集了 {} 个停止线程)", pid.0, drained);
        Ok(())
    }

    /// 等待指定线程停止
    fn wait_for_stop_by_tid(&self, tid: u32) -> crate::Result<()> {
        let tid_i32 = tid as libc::pid_t;
        let mut status: libc::c_int = 0;

        // SAFETY: waitpid 用于等待线程停止
        let ret = unsafe { libc::waitpid(tid_i32, &mut status, 0) };

        if ret < 0 {
            let errno = std::io::Error::last_os_error();
            return Err(FridaError::Ptrace {
                op: "WAIT".to_string(),
                pid: tid,
                detail: format!("waitpid(tid={}) 失败: {}", tid, errno),
            }
            .into());
        }

        if !libc::WIFSTOPPED(status) {
            return Err(FridaError::Ptrace {
                op: "WAIT".to_string(),
                pid: tid,
                detail: format!("线程 {} 未按预期停止", tid),
            }
            .into());
        }

        Ok(())
    }

    /// 继续执行目标进程
    ///
    /// 使用 `ptrace(PTRACE_CONT)` 让停止的进程继续执行。
    pub fn cont(&self, pid: ProcessId) -> crate::Result<()> {
        let pid_i32 = pid.0 as libc::pid_t;
        // SAFETY: PTRACE_CONT 在已附加的停止进程上调用
        let ret = unsafe { libc::ptrace(libc::PTRACE_CONT, pid_i32, 0, 0) };
        if ret != 0 {
            return Err(FridaError::Ptrace {
                op: "CONT".to_string(),
                pid: pid.0,
                detail: format!("PTRACE_CONT 失败: {}", std::io::Error::last_os_error()),
            }
            .into());
        }
        Ok(())
    }

    /// 单步执行目标线程
    ///
    /// 使用 `ptrace(PTRACE_SINGLESTEP)` 让目标线程执行一条指令后停止。
    pub fn single_step(&self, tid: i32) -> crate::Result<()> {
        // SAFETY: PTRACE_SINGLESTEP 在已附加的停止线程上调用
        let ret = unsafe { libc::ptrace(libc::PTRACE_SINGLESTEP, tid, 0, 0) };
        if ret != 0 {
            return Err(FridaError::Ptrace {
                op: "SINGLESTEP".to_string(),
                pid: tid as u32,
                detail: format!(
                    "PTRACE_SINGLESTEP 失败: {}",
                    std::io::Error::last_os_error()
                ),
            }
            .into());
        }

        // 等待单步执行完成
        self.wait_for_stop_by_tid(tid as u32)?;
        Ok(())
    }

    /// 检查注入器是否已附加到目标进程
    pub fn is_attached(&self) -> bool {
        self.attached
    }

    /// 获取已附加的目标进程 ID
    pub fn target_pid(&self) -> Option<ProcessId> {
        self.target_pid
    }
}

impl Drop for PtraceInjector {
    /// 析构时自动脱离并清理
    fn drop(&mut self) {
        if self.attached {
            if let Err(e) = self.detach() {
                log::error!("PtraceInjector drop 时清理失败: {}", e);
            }
        }
    }
}

impl Default for PtraceInjector {
    fn default() -> Self {
        Self::new()
    }
}

/// 解析 ELF 文件中的符号偏移量
///
/// 使用 goblin 库解析 ELF 格式的共享库文件，
/// 在动态符号表和常规符号表中查找指定符号。
fn parse_elf_symbol(data: &[u8], symbol_name: &str) -> Option<usize> {
    match goblin::Object::parse(data) {
        Ok(goblin::Object::Elf(elf)) => {
            // 优先在动态符号表中查找（运行时可见的符号）
            for sym in &elf.dynsyms {
                if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                    if name == symbol_name {
                        return Some(sym.st_value as usize);
                    }
                }
            }
            // 也在常规符号表中查找
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
