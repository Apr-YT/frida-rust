use crate::common::types::ProcessId;
use crate::common::util::align_to_page_up;
use crate::Result;

#[cfg(any(target_os = "linux", target_os = "android"))]
use crate::communication::kernel_channel::KernelChannel;

use std::collections::HashMap;

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

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct AllocatedRegion {
    addr: u64,
    size: usize,
    executable: bool,
    #[allow(dead_code)]
    timestamp: std::time::Instant,
}

pub struct RemoteAllocator {
    pid: ProcessId,
    allocations: HashMap<u64, AllocatedRegion>,
    attached: bool,
    saved_regs: Option<UserRegs>,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    kernel_channel: Option<KernelChannel>,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    kernel_available: bool,
}

impl RemoteAllocator {
    pub fn new(pid: ProcessId) -> Self {
        RemoteAllocator {
            pid,
            allocations: HashMap::new(),
            attached: false,
            saved_regs: None,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            kernel_channel: None,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            kernel_available: true,
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn ensure_kernel_channel(&mut self) -> Option<&KernelChannel> {
        if !self.kernel_available {
            return None;
        }

        if self.kernel_channel.is_none() {
            match KernelChannel::new() {
                Ok(channel) => {
                    match channel.ping() {
                        Ok(_) => {
                            log::info!("内核通道已连接，优先使用内核内存读写");
                            self.kernel_channel = Some(channel);
                        }
                        Err(e) => {
                            log::warn!("内核通道不可用，回退到用户态: {}", e);
                            self.kernel_available = false;
                            return None;
                        }
                    }
                }
                Err(e) => {
                    log::warn!("创建内核通道失败，回退到用户态: {}", e);
                    self.kernel_available = false;
                    return None;
                }
            }
        }

        self.kernel_channel.as_ref()
    }

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

    pub fn write(&self, addr: u64, data: &[u8]) -> Result<()> {
        log::debug!(
            "写入远程内存: PID {}, 地址={:#x}, 大小={}",
            self.pid.0,
            addr,
            data.len()
        );

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

        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            if let Some(channel) = self.kernel_channel.as_ref() {
                match channel.write_mem(self.pid.0 as i32, addr as usize, data) {
                    Ok(()) => {
                        log::trace!("内核通道写入成功: addr={:#x}, size={}", addr, data.len());
                        return Ok(());
                    }
                    Err(e) => {
                        log::debug!("内核通道写入失败，回退到用户态: {}", e);
                    }
                }
            }
        }

        let local_iovec = libc::iovec {
            iov_base: data.as_ptr() as *mut libc::c_void,
            iov_len: data.len(),
        };

        let remote_iovec = libc::iovec {
            iov_base: addr as *mut libc::c_void,
            iov_len: data.len(),
        };

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

    pub fn read(&self, addr: u64, size: usize) -> Result<Vec<u8>> {
        log::debug!(
            "读取远程内存: PID {}, 地址={:#x}, 大小={}",
            self.pid.0,
            addr,
            size
        );

        if self.pid.0 == 0 {
            let mut buf = vec![0u8; size];
            unsafe {
                libc::memcpy(
                    buf.as_mut_ptr() as *mut libc::c_void,
                    addr as *const libc::c_void,
                    size,
                );
            }
            return Ok(buf);
        }

        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            if let Some(channel) = self.kernel_channel.as_ref() {
                match channel.read_mem(self.pid.0 as i32, addr as usize, size) {
                    Ok(data) => {
                        log::trace!("内核通道读取成功: addr={:#x}, size={}", addr, size);
                        return Ok(data);
                    }
                    Err(e) => {
                        log::debug!("内核通道读取失败，回退到用户态: {}", e);
                    }
                }
            }
        }

        let mut buf = vec![0u8; size];

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

    pub fn protect(&self, addr: u64, size: usize, prot: libc::c_int) -> Result<()> {
        log::debug!(
            "修改远程内存保护: PID {}, 地址={:#x}, 大小={}, prot={}",
            self.pid.0,
            addr,
            size,
            prot
        );

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

        self.remote_mprotect(addr, size, prot)?;

        Ok(())
    }

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

    pub fn allocation_count(&self) -> usize {
        self.allocations.len()
    }

    fn find_region(&self, addr: u64) -> Option<(u64, &AllocatedRegion)> {
        for (_, region) in &self.allocations {
            if addr >= region.addr && addr < region.addr + region.size as u64 {
                return Some((region.addr, region));
            }
        }
        None
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn remote_mmap(
        &mut self,
        addr: u64,
        size: usize,
        prot: libc::c_int,
        flags: libc::c_int,
    ) -> Result<u64> {
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

        self.ptrace_attach()?;
        self.save_registers()?;

        #[cfg(target_arch = "x86_64")]
        {
            let nr_mmap: u64 = 9;
            self.set_registers_for_syscall(
                nr_mmap,
                &[addr, size as u64, prot as u64, flags as u64, 0xFFFF_FFFF_FFFF_FFFF_u64, 0],
            )?;
        }

        #[cfg(target_arch = "aarch64")]
        {
            let nr_mmap: u64 = 222;
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

        self.execute_syscall()?;
        let result = self.read_syscall_result()?;
        self.restore_registers()?;
        self.ptrace_detach()?;

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
            let nr_munmap: u64 = 11;
            self.set_registers_for_syscall(nr_munmap, &[addr, size as u64, 0, 0, 0, 0])?;
        }

        #[cfg(target_arch = "aarch64")]
        {
            let nr_munmap: u64 = 215;
            self.set_registers_for_syscall(nr_munmap, &[addr, size as u64, 0, 0, 0, 0])?;
        }

        self.execute_syscall()?;
        self.restore_registers()?;
        self.ptrace_detach()?;

        Ok(())
    }

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

        log::warn!("远程 mprotect 需要目标进程处于 ptrace 停止状态");

        Err(crate::FridaError::Unsupported {
            reason: "远程 mprotect 需要 ptrace 附加，请确保目标进程已暂停".to_string(),
        }
        .into())
    }

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

        let mut status: libc::c_int = 0;
        let _ = unsafe { libc::waitpid(self.pid.0 as libc::pid_t, &mut status, 0) };

        self.attached = true;
        log::debug!("ptrace 已附加到 PID {}", self.pid.0);
        Ok(())
    }

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

        regs.rax = syscall_nr;
        regs.rdi = args[0];
        regs.rsi = args[1];
        regs.rdx = args[2];
        regs.r10 = args[3];
        regs.r8 = args[4];
        regs.r9 = args[5];
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

    fn execute_syscall(&self) -> Result<()> {
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

            if libc::WIFSTOPPED(status) {
                let sig = libc::WSTOPSIG(status);
                if sig == (libc::SIGTRAP | 0x80) {
                    break;
                }
            }
        }
        Ok(())
    }

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
        if self.attached {
            let _ = self.ptrace_detach();
        }

        if !self.allocations.is_empty() {
            log::warn!(
                "RemoteAllocator 析构时仍有 {} 个未释放的内存分配",
                self.allocations.len()
            );
        }
    }
}