//! 远程内存分配器 - 在目标进程中分配和管理内存
//!
//! 通过 ptrace 在目标进程中执行 mmap/munmap 系统调用，
//! 实现跨进程的内存分配和释放。
//!
//! ## 使用场景
//! - 注入代码/数据到目标进程
//! - 在目标进程中分配可执行内存用于 shellcode
//! - 读写目标进程的数据区域

use crate::common::types::ProcessId;
use crate::common::util::align_to_page_up;
use crate::Result;

use std::collections::HashMap;

// ======================== 架构相关的寄存器类型与常量 ========================

#[cfg(target_arch = "x86_64")]
type UserRegs = libc::user_regs_struct;

#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Clone, Copy)]
struct user_pt_regs {
    regs: [u64; 31],
    sp: u64,
    pc: u64,
    pstate: u64,
}

#[cfg(target_arch = "aarch64")]
type UserRegs = user_pt_regs;

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

// ======================== 分配记录 ========================

/// 已分配的内存区域记录
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct AllocatedRegion {
    /// 起始地址
    addr: u64,
    /// 分配大小
    size: usize,
    /// 是否可执行
    executable: bool,
    /// 分配时间戳
    #[allow(dead_code)]
    timestamp: std::time::Instant,
}

// ======================== 远程内存分配器 ========================

/// 远程内存分配器
///
/// 通过在目标进程中执行 mmap/munmap 系统调用来分配和释放内存。
/// 支持 ptrace 远程调用和 process_vm_readv/writev 数据传输。
pub struct RemoteAllocator {
    /// 目标进程 ID
    pid: ProcessId,
    /// 已分配的内存区域列表
    allocations: HashMap<u64, AllocatedRegion>,
    /// ptrace 是否已附加
    attached: bool,
    /// 保存的寄存器上下文（用于 ptrace 调用）
    saved_regs: Option<UserRegs>,
}

impl RemoteAllocator {
    /// 创建远程内存分配器
    ///
    /// # 参数
    /// - `pid`: 目标进程 ID
    pub fn new(pid: ProcessId) -> Self {
        RemoteAllocator {
            pid,
            allocations: HashMap::new(),
            attached: false,
            saved_regs: None,
        }
    }

    /// 在目标进程中分配内存
    ///
    /// 通过 ptrace 在目标进程中执行 mmap 系统调用。
    ///
    /// # 参数
    /// - `size`: 分配大小（字节），自动向上对齐到页面大小
    /// - `executable`: 是否需要可执行权限
    ///
    /// # 返回值
    /// 返回分配到的远程内存地址
    ///
    /// # 系统调用参数 (x86_64)
    /// - syscall 号: __NR_mmap (9)
    /// - rdi: addr (0 = 内核选择)
    /// - rsi: length
    /// - rdx: prot (PROT_READ | PROT_WRITE [| PROT_EXEC])
    /// - r10: flags (MAP_PRIVATE | MAP_ANONYMOUS)
    /// - r8: fd (-1)
    /// - r9: offset (0)
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn alloc(&mut self, size: usize, executable: bool) -> Result<u64> {
        let aligned_size = align_to_page_up(size);

        log::debug!(
            "在 PID {} 中分配 {} 字节内存 (对齐后: {}, exec={})",
            self.pid.0,
            size,
            aligned_size,
            executable
        );

        let prot = libc::PROT_READ | libc::PROT_WRITE
            | if executable { libc::PROT_EXEC } else { 0 };
        let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;

        let addr = self.remote_mmap(0, aligned_size, prot, flags)?;

        log::info!(
            "远程内存分配成功: PID {}, 地址={:#x}, 大小={}",
            self.pid.0,
            addr,
            aligned_size
        );

        // 记录分配
        self.allocations.insert(
            addr,
            AllocatedRegion {
                addr,
                size: aligned_size,
                executable,
                timestamp: std::time::Instant::now(),
            },
        );

        Ok(addr)
    }

    /// 释放已分配的远程内存
    ///
    /// 通过 ptrace 在目标进程中执行 munmap 系统调用。
    ///
    /// # 参数
    /// - `addr`: 之前分配的内存地址
    pub fn free(&mut self, addr: u64) -> Result<()> {
        let region = self.allocations.remove(&addr).ok_or_else(|| {
            crate::FridaError::MemoryWrite {
                address: addr as usize,
                size: 0,
                reason: format!("地址 {:#x} 不在已分配列表中", addr),
            }
        })?;

        log::debug!(
            "释放远程内存: PID {}, 地址={:#x}, 大小={}",
            self.pid.0,
            addr,
            region.size
        );

        self.remote_munmap(addr, region.size)?;

        log::info!(
            "远程内存已释放: PID {}, 地址={:#x}",
            self.pid.0,
            addr
        );

        Ok(())
    }

    /// 向远程进程的内存写入数据
    ///
    /// 使用 process_vm_writev 系统调用进行高效的跨进程写入。
    ///
    /// # 参数
    /// - `addr`: 目标地址
    /// - `data`: 要写入的数据
    pub fn write(&self, addr: u64, data: &[u8]) -> Result<()> {
        log::debug!(
            "写入远程内存: PID {}, 地址={:#x}, 大小={}",
            self.pid.0,
            addr,
            data.len()
        );

        // 验证地址在已分配区域内
        if let Some((start, region)) = self.find_region(addr) {
            let end = addr + data.len() as u64;
            let region_end = region.addr + region.size as u64;
            if end > region_end {
                log::warn!(
                    "写入超出区域边界: {:#x}..{:#x}, 区域: {:#x}..{:#x}",
                    addr,
                    end,
                    start,
                    region_end
                );
            }
        }

        // 如果是当前进程，直接写入
        if self.pid.0 == 0 {
            unsafe {
                libc::memcpy(
                    addr as *mut libc::c_void,
                    data.as_ptr() as *const libc::c_void,
                    data.len(),
                );
            }
            return Ok(());
        }

        // 远程进程：使用 process_vm_writev
        let local_iovec = libc::iovec {
            iov_base: data.as_ptr() as *mut libc::c_void,
            iov_len: data.len(),
        };

        let remote_iovec = libc::iovec {
            iov_base: addr as *mut libc::c_void,
            iov_len: data.len(),
        };

        // SAFETY: process_vm_writev 需要调用者确保目标地址合法
        let ret = unsafe {
            crate::common::syscall_wrapper::process_vm_writev(
                self.pid.0 as libc::pid_t,
                &local_iovec,
                1,
                &remote_iovec,
                1,
                0,
            )
        };

        if ret < 0 {
            return Err(crate::FridaError::MemoryWrite {
                address: addr as usize,
                size: data.len(),
                reason: format!("process_vm_writev 失败: {}", std::io::Error::last_os_error()),
            }
            .into());
        }

        if ret as usize != data.len() {
            log::warn!(
                "部分写入: 期望 {} 字节, 实际 {} 字节",
                data.len(),
                ret
            );
        }

        Ok(())
    }

    /// 从远程进程的内存读取数据
    ///
    /// 使用 process_vm_readv 系统调用进行高效的跨进程读取。
    ///
    /// # 参数
    /// - `addr`: 目标地址
    /// - `size`: 读取大小
    ///
    /// # 返回值
    /// 返回读取到的数据
    pub fn read(&self, addr: u64, size: usize) -> Result<Vec<u8>> {
        log::debug!(
            "读取远程内存: PID {}, 地址={:#x}, 大小={}",
            self.pid.0,
            addr,
            size
        );

        let mut buf = vec![0u8; size];

        // 如果是当前进程，直接读取
        if self.pid.0 == 0 {
            unsafe {
                libc::memcpy(
                    buf.as_mut_ptr() as *mut libc::c_void,
                    addr as *const libc::c_void,
                    size,
                );
            }
            return Ok(buf);
        }

        // 远程进程：使用 process_vm_readv
        let local_iovec = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: size,
        };

        let remote_iovec = libc::iovec {
            iov_base: addr as *mut libc::c_void,
            iov_len: size,
        };

        let ret = unsafe {
            crate::common::syscall_wrapper::process_vm_readv(
                self.pid.0 as libc::pid_t,
                &local_iovec,
                1,
                &remote_iovec,
                1,
                0,
            )
        };

        if ret < 0 {
            return Err(crate::FridaError::MemoryRead {
                address: addr as usize,
                size,
                reason: format!("process_vm_readv 失败: {}", std::io::Error::last_os_error()),
            }
            .into());
        }

        if ret as usize != size {
            buf.truncate(ret as usize);
            log::warn!(
                "部分读取: 期望 {} 字节, 实际 {} 字节",
                size,
                ret
            );
        }

        Ok(buf)
    }

    /// 修改远程内存的保护属性
    ///
    /// # 参数
    /// - `addr`: 内存地址
    /// - `size`: 大小
    /// - `prot`: 新的保护属性（libc::PROT_* 标志组合）
    pub fn protect(&self, addr: u64, size: usize, prot: libc::c_int) -> Result<()> {
        log::debug!(
            "修改远程内存保护: PID {}, 地址={:#x}, 大小={}, prot={}",
            self.pid.0,
            addr,
            size,
            prot
        );

        if self.pid.0 == 0 {
            // 当前进程：直接调用 mprotect
            let ret = unsafe {
                libc::mprotect(
                    align_to_page_up(addr as usize) as *mut libc::c_void,
                    align_to_page_up(size),
                    prot,
                )
            };
            if ret != 0 {
                return Err(crate::FridaError::MemoryProtect {
                    address: addr as usize,
                    reason: format!("mprotect 失败: {}", std::io::Error::last_os_error()),
                }
                .into());
            }
            return Ok(());
        }

        // 远程进程：通过 ptrace 调用 mprotect
        self.remote_mprotect(addr, size, prot)?;

        Ok(())
    }

    /// 释放所有已分配的远程内存
    pub fn free_all(&mut self) -> Result<()> {
        let addrs: Vec<u64> = self.allocations.keys().copied().collect();
        let errors: Vec<String> = addrs
            .into_iter()
            .filter_map(|addr| match self.free(addr) {
                Ok(()) => None,
                Err(e) => Some(format!("{:#x}: {}", addr, e)),
            })
            .collect();

        if !errors.is_empty() {
            log::warn!("部分内存释放失败: {}", errors.join("; "));
        }

        Ok(())
    }

    /// 获取已分配的内存区域数量
    pub fn allocation_count(&self) -> usize {
        self.allocations.len()
    }

    /// 查找包含指定地址的分配区域
    fn find_region(&self, addr: u64) -> Option<(u64, &AllocatedRegion)> {
        for (_, region) in &self.allocations {
            if addr >= region.addr && addr < region.addr + region.size as u64 {
                return Some((region.addr, region));
            }
        }
        None
    }

    // ======================== ptrace 远程调用 ========================

    /// 通过 ptrace 在目标进程中执行 mmap 系统调用
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn remote_mmap(
        &mut self,
        addr: u64,
        size: usize,
        prot: libc::c_int,
        flags: libc::c_int,
    ) -> Result<u64> {
        // 如果是当前进程，直接调用 mmap
        if self.pid.0 == 0 {
            let result = unsafe {
                libc::mmap(
                    if addr == 0 { std::ptr::null_mut() } else { addr as *mut libc::c_void },
                    size,
                    prot,
                    flags,
                    -1,
                    0,
                )
            };

            if result == libc::MAP_FAILED {
                return Err(crate::FridaError::MemoryWrite {
                    address: 0,
                    size,
                    reason: format!("mmap 失败: {}", std::io::Error::last_os_error()),
                }
                .into());
            }

            return Ok(result as u64);
        }

        // 远程进程：通过 ptrace call_remote
        // 1. 附加到目标进程
        self.ptrace_attach()?;

        // 2. 保存寄存器状态
        self.save_registers()?;

        // 3. 设置系统调用参数
        // x86_64: syscall(__NR_mmap, addr, length, prot, flags, fd, offset)
        #[cfg(target_arch = "x86_64")]
        {
            let nr_mmap: u64 = 9; // __NR_mmap on x86_64
            self.set_registers_for_syscall(
                nr_mmap,
                &[addr, size as u64, prot as u64, flags as u64, 0xFFFF_FFFF_FFFF_FFFF_u64, 0],
            )?;
        }

        // AArch64: syscall(__NR_mmap, addr, length, prot, flags, fd, offset)
        #[cfg(target_arch = "aarch64")]
        {
            let nr_mmap: u64 = 222; // __NR_mmap on AArch64
            self.set_registers_for_syscall(
                nr_mmap,
                &[
                    addr,
                    size as u64,
                    prot as u64,
                    flags as u64,
                    0xFFFF_FFFF_FFFF_FFFF_u64,
                    0,
                ],
            )?;
        }

        // 4. 执行系统调用
        self.execute_syscall()?;

        // 5. 读取返回值
        let result = self.read_syscall_result()?;

        // 6. 恢复寄存器
        self.restore_registers()?;

        // 7. 分离 ptrace
        self.ptrace_detach()?;

        // 检查 mmap 返回值（MAP_FAILED = (void*)-1）
        if result == 0xFFFF_FFFF_FFFF_FFFF_u64 {
            return Err(crate::FridaError::MemoryWrite {
                address: 0,
                size,
                reason: "远程 mmap 返回 MAP_FAILED".to_string(),
            }
            .into());
        }

        Ok(result)
    }

    /// 通过 ptrace 在目标进程中执行 munmap 系统调用
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn remote_munmap(&mut self, addr: u64, size: usize) -> Result<()> {
        if self.pid.0 == 0 {
            let ret = unsafe { libc::munmap(addr as *mut libc::c_void, size) };
            if ret != 0 {
                return Err(crate::FridaError::MemoryWrite {
                    address: addr as usize,
                    size,
                    reason: format!("munmap 失败: {}", std::io::Error::last_os_error()),
                }
                .into());
            }
            return Ok(());
        }

        self.ptrace_attach()?;
        self.save_registers()?;

        #[cfg(target_arch = "x86_64")]
        {
            let nr_munmap: u64 = 11; // __NR_munmap on x86_64
            self.set_registers_for_syscall(nr_munmap, &[addr, size as u64, 0, 0, 0, 0])?;
        }

        #[cfg(target_arch = "aarch64")]
        {
            let nr_munmap: u64 = 215; // __NR_munmap on AArch64
            self.set_registers_for_syscall(nr_munmap, &[addr, size as u64, 0, 0, 0, 0])?;
        }

        self.execute_syscall()?;
        self.restore_registers()?;
        self.ptrace_detach()?;

        Ok(())
    }

    /// 通过 ptrace 在目标进程中执行 mprotect 系统调用
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn remote_mprotect(&self, addr: u64, size: usize, prot: libc::c_int) -> Result<()> {
        if self.pid.0 == 0 {
            let ret = unsafe {
                libc::mprotect(
                    align_to_page_up(addr as usize) as *mut libc::c_void,
                    align_to_page_up(size),
                    prot,
                )
            };
            if ret != 0 {
                return Err(crate::FridaError::MemoryProtect {
                    address: addr as usize,
                    reason: format!("mprotect 失败: {}", std::io::Error::last_os_error()),
                }
                .into());
            }
            return Ok(());
        }

        // 远程进程 mprotect 需要先 attach
        // 简化实现：返回错误，提示需要先调用者处理 ptrace attach
        log::warn!("远程 mprotect 需要目标进程处于 ptrace 停止状态");

        Err(crate::FridaError::Unsupported {
            reason: "远程 mprotect 需要 ptrace 附加，请确保目标进程已暂停".to_string(),
        }
        .into())
    }

    // ---- ptrace 辅助方法 ----

    /// ptrace 附加到目标进程
    fn ptrace_attach(&mut self) -> Result<()> {
        if self.attached {
            return Ok(());
        }

        let ret = unsafe { libc::ptrace(libc::PTRACE_ATTACH, self.pid.0 as libc::pid_t, std::ptr::null_mut::<libc::c_void>(), std::ptr::null_mut::<libc::c_void>()) };
        if ret != 0 {
            return Err(crate::FridaError::Ptrace {
                op: "attach".to_string(),
                pid: self.pid.0,
                detail: format!("ptrace attach 失败: {}", std::io::Error::last_os_error()),
            }
            .into());
        }

        // 等待目标进程停止
        let mut status: libc::c_int = 0;
        let _ = unsafe { libc::waitpid(self.pid.0 as libc::pid_t, &mut status, 0) };

        self.attached = true;
        log::debug!("ptrace 已附加到 PID {}", self.pid.0);
        Ok(())
    }

    /// ptrace 分离目标进程
    fn ptrace_detach(&mut self) -> Result<()> {
        if !self.attached {
            return Ok(());
        }

        let ret = unsafe { libc::ptrace(libc::PTRACE_DETACH, self.pid.0 as libc::pid_t, std::ptr::null_mut::<libc::c_void>(), std::ptr::null_mut::<libc::c_void>()) };
        if ret != 0 {
            log::warn!(
                "ptrace detach 失败: {}",
                std::io::Error::last_os_error()
            );
        }

        self.attached = false;
        log::debug!("ptrace 已从 PID {} 分离", self.pid.0);
        Ok(())
    }

    /// 保存当前寄存器状态
    #[cfg(target_arch = "x86_64")]
    fn save_registers(&mut self) -> Result<()> {
        let mut regs: UserRegs = unsafe { std::mem::zeroed() };
        let ret = unsafe {
            libc::ptrace(
                libc::PTRACE_GETREGS,
                self.pid.0 as libc::pid_t,
                std::ptr::null_mut::<libc::c_void>(),
                &mut regs as *mut _ as *mut libc::c_void,
            )
        };
        if ret != 0 {
            return Err(crate::FridaError::Ptrace {
                op: "GETREGS".to_string(),
                pid: self.pid.0,
                detail: format!("获取寄存器失败: {}", std::io::Error::last_os_error()),
            }
            .into());
        }

        self.saved_regs = Some(regs);
        log::debug!("寄存器状态已保存");
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    fn save_registers(&mut self) -> Result<()> {
        let mut regs: UserRegs = unsafe { std::mem::zeroed() };
        let mut iov = libc::iovec {
            iov_base: &mut regs as *mut _ as *mut libc::c_void,
            iov_len: std::mem::size_of::<UserRegs>(),
        };
        let ret = unsafe {
            libc::ptrace(
                PTRACE_GETREGSET,
                self.pid.0 as libc::pid_t,
                NT_PRSTATUS as *mut libc::c_void,
                &mut iov as *mut _ as *mut libc::c_void,
            )
        };
        if ret != 0 {
            return Err(crate::FridaError::Ptrace {
                op: "GETREGSET".to_string(),
                pid: self.pid.0,
                detail: format!("获取寄存器失败: {}", std::io::Error::last_os_error()),
            }
            .into());
        }

        self.saved_regs = Some(regs);
        log::debug!("寄存器状态已保存");
        Ok(())
    }

    /// 恢复寄存器状态
    #[cfg(target_arch = "x86_64")]
    fn restore_registers(&self) -> Result<()> {
        if let Some(ref regs) = self.saved_regs {
            let ret = unsafe {
                libc::ptrace(
                    libc::PTRACE_SETREGS,
                    self.pid.0 as libc::pid_t,
                    std::ptr::null_mut::<libc::c_void>(),
                    regs as *const _ as *const libc::c_void,
                )
            };
            if ret != 0 {
                return Err(crate::FridaError::Ptrace {
                    op: "SETREGS".to_string(),
                    pid: self.pid.0,
                    detail: format!("恢复寄存器失败: {}", std::io::Error::last_os_error()),
                }
                .into());
            }
            log::debug!("寄存器状态已恢复");
        }
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    fn restore_registers(&self) -> Result<()> {
        if let Some(ref regs) = self.saved_regs {
            let mut iov = libc::iovec {
                iov_base: regs as *const _ as *mut libc::c_void,
                iov_len: std::mem::size_of::<UserRegs>(),
            };
            let ret = unsafe {
                libc::ptrace(
                    PTRACE_SETREGSET,
                    self.pid.0 as libc::pid_t,
                    NT_PRSTATUS as *mut libc::c_void,
                    &mut iov as *mut _ as *mut libc::c_void,
                )
            };
            if ret != 0 {
                return Err(crate::FridaError::Ptrace {
                    op: "SETREGSET".to_string(),
                    pid: self.pid.0,
                    detail: format!("恢复寄存器失败: {}", std::io::Error::last_os_error()),
                }
                .into());
            }
            log::debug!("寄存器状态已恢复");
        }
        Ok(())
    }

    /// 设置寄存器用于系统调用
    #[cfg(target_arch = "x86_64")]
    fn set_registers_for_syscall(
        &self,
        syscall_nr: u64,
        args: &[u64; 6],
    ) -> Result<()> {
        let mut regs: UserRegs = match &self.saved_regs {
            Some(r) => *r,
            None => unsafe { std::mem::zeroed() },
        };

        // x86_64 系统调用约定:
        // rax = syscall number
        // rdi, rsi, rdx, r10, r8, r9 = 参数
        regs.rax = syscall_nr;
        regs.rdi = args[0];
        regs.rsi = args[1];
        regs.rdx = args[2];
        regs.r10 = args[3];
        regs.r8 = args[4];
        regs.r9 = args[5];

        // 设置 orig_rax 以便 ptrace 正确处理系统调用
        regs.orig_rax = syscall_nr;

        let ret = unsafe {
            libc::ptrace(
                libc::PTRACE_SETREGS,
                self.pid.0 as libc::pid_t,
                std::ptr::null_mut::<libc::c_void>(),
                &regs as *const _ as *const libc::c_void,
            )
        };
        if ret != 0 {
            return Err(crate::FridaError::Ptrace {
                op: "SETREGS".to_string(),
                pid: self.pid.0,
                detail: format!("设置系统调用寄存器失败: {}", std::io::Error::last_os_error()),
            }
            .into());
        }

        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    fn set_registers_for_syscall(
        &self,
        syscall_nr: u64,
        args: &[u64; 6],
    ) -> Result<()> {
        // AArch64 系统调用约定:
        // x8 = syscall number
        // x0-x5 = 参数
        let mut regs: UserRegs = match &self.saved_regs {
            Some(r) => *r,
            None => unsafe { std::mem::zeroed() },
        };

        regs.regs[8] = syscall_nr;
        for (i, &arg) in args.iter().enumerate() {
            regs.regs[i] = arg;
        }

        let mut iov = libc::iovec {
            iov_base: &mut regs as *mut _ as *mut libc::c_void,
            iov_len: std::mem::size_of::<UserRegs>(),
        };

        let ret = unsafe {
            libc::ptrace(
                PTRACE_SETREGSET,
                self.pid.0 as libc::pid_t,
                NT_PRSTATUS as *mut libc::c_void,
                &mut iov as *mut _ as *mut libc::c_void,
            )
        };
        if ret != 0 {
            return Err(crate::FridaError::Ptrace {
                op: "SETREGSET".to_string(),
                pid: self.pid.0,
                detail: format!("设置系统调用寄存器失败: {}", std::io::Error::last_os_error()),
            }
            .into());
        }

        Ok(())
    }

    /// 执行系统调用并等待完成
    fn execute_syscall(&self) -> Result<()> {
        // 单步执行到 syscall 指令
        // 使用 PTRACE_SYSCALL 让进程执行到下一个系统调用入口/出口
        loop {
            let ret = unsafe {
                libc::ptrace(
                    libc::PTRACE_SYSCALL,
                    self.pid.0 as libc::pid_t,
                    std::ptr::null_mut::<libc::c_void>(),
                    std::ptr::null_mut::<libc::c_void>(),
                )
            };
            if ret != 0 {
                return Err(crate::FridaError::Ptrace {
                    op: "SYSCALL".to_string(),
                    pid: self.pid.0,
                    detail: format!("ptrace syscall 失败: {}", std::io::Error::last_os_error()),
                }
                .into());
            }

            let mut status: libc::c_int = 0;
            let _ = unsafe { libc::waitpid(self.pid.0 as libc::pid_t, &mut status, 0) };

            // 检查是否到达 syscall 入口 (WIFSTOPPED && (status >> 8 == (SIGTRAP | PTRACE_SYSCALL))
            if libc::WIFSTOPPED(status) {
                let sig = libc::WSTOPSIG(status);
                if sig == (libc::SIGTRAP | 0x80) {
                    // 到达 syscall 入口
                    break;
                }
            }
        }
        Ok(())
    }

    /// 读取系统调用返回值
    #[cfg(target_arch = "x86_64")]
    fn read_syscall_result(&self) -> Result<u64> {
        let mut regs: UserRegs = unsafe { std::mem::zeroed() };
        let ret = unsafe {
            libc::ptrace(
                libc::PTRACE_GETREGS,
                self.pid.0 as libc::pid_t,
                std::ptr::null_mut::<libc::c_void>(),
                &mut regs as *mut _ as *mut libc::c_void,
            )
        };
        if ret != 0 {
            return Err(crate::FridaError::Ptrace {
                op: "GETREGS".to_string(),
                pid: self.pid.0,
                detail: "读取系统调用返回值失败".to_string(),
            }
            .into());
        }

        // x86_64: 返回值在 rax
        Ok(regs.rax)
    }

    #[cfg(target_arch = "aarch64")]
    fn read_syscall_result(&self) -> Result<u64> {
        let mut regs: UserRegs = unsafe { std::mem::zeroed() };
        let mut iov = libc::iovec {
            iov_base: &mut regs as *mut _ as *mut libc::c_void,
            iov_len: std::mem::size_of::<UserRegs>(),
        };
        let ret = unsafe {
            libc::ptrace(
                PTRACE_GETREGSET,
                self.pid.0 as libc::pid_t,
                NT_PRSTATUS as *mut libc::c_void,
                &mut iov as *mut _ as *mut libc::c_void,
            )
        };
        if ret != 0 {
            return Err(crate::FridaError::Ptrace {
                op: "GETREGSET".to_string(),
                pid: self.pid.0,
                detail: "读取系统调用返回值失败".to_string(),
            }
            .into());
        }

        // AArch64: 返回值在 x0 (regs[0])
        Ok(regs.regs[0])
    }
}

impl Default for RemoteAllocator {
    fn default() -> Self {
        Self::new(ProcessId(0))
    }
}

impl Drop for RemoteAllocator {
    fn drop(&mut self) {
        // 分离 ptrace（如果仍然附加）
        if self.attached {
            let _ = self.ptrace_detach();
        }

        // 释放所有分配（最佳努力）
        if !self.allocations.is_empty() {
            log::warn!(
                "RemoteAllocator 析构时仍有 {} 个未释放的内存分配",
                self.allocations.len()
            );
        }
    }
}
