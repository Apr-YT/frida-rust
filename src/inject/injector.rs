use crate::common::error::FridaError;
use crate::common::types::ProcessId;
use crate::common::util;
use std::path::Path;

#[cfg(any(target_os = "linux", target_os = "android"))]
use crate::communication::kernel_channel::KernelChannel;

pub struct Injector {
    target_pid: ProcessId,
    ptrace: super::ptrace_inject::PtraceInjector,
    remote_allocs: Vec<RemoteAlloc>,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    kernel_channel: Option<KernelChannel>,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    kernel_available: bool,
}

#[derive(Debug)]
struct RemoteAlloc {
    addr: u64,
    size: usize,
}

impl Injector {
    pub fn new(target_pid: ProcessId) -> Self {
        Injector {
            target_pid,
            ptrace: super::ptrace_inject::PtraceInjector::new(),
            remote_allocs: Vec::new(),
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
                            log::info!("内核通道已连接，优先使用内核注入");
                            self.kernel_channel = Some(channel);
                        }
                        Err(e) => {
                            log::warn!("内核通道不可用，回退到 ptrace: {}", e);
                            self.kernel_available = false;
                            return None;
                        }
                    }
                }
                Err(e) => {
                    log::warn!("创建内核通道失败，回退到 ptrace: {}", e);
                    self.kernel_available = false;
                    return None;
                }
            }
        }

        self.kernel_channel.as_ref()
    }

    pub fn inject_library(&mut self, lib_path: &str) -> crate::Result<()> {
        let pid = self.target_pid;
        log::info!("开始注入: PID={}, 库={}", pid.0, lib_path);

        if !util::is_process_alive(pid) {
            return Err(FridaError::Inject {
                reason: format!("目标进程 {} 不存在或已终止", pid.0),
                pid: pid.0,
                source: None,
            }
            .into());
        }

        if !Path::new(lib_path).exists() {
            return Err(FridaError::NotFound {
                reason: format!("共享库文件不存在: {}", lib_path),
            }
            .into());
        }

        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            if let Some(channel) = self.ensure_kernel_channel() {
                match channel.inject(pid.0 as i32, lib_path) {
                    Ok(()) => {
                        log::info!("内核注入成功: PID={}, 库={}", pid.0, lib_path);
                        return Ok(());
                    }
                    Err(e) => {
                        log::warn!("内核注入失败，回退到 ptrace: {}", e);
                        self.kernel_available = false;
                    }
                }
            }
        }

        self.attach_process()?;
        let result = self.inject_library_inner(lib_path);

        if let Err(e) = self.detach_process() {
            log::warn!("脱离目标进程失败: {}", e);
        }

        self.cleanup_allocs();

        match result {
            Ok(()) => {
                log::info!("ptrace注入完成: PID={}, 库={}", pid.0, lib_path);
                Ok(())
            }
            Err(e) => {
                log::error!("注入失败: PID={}, 库={}, 错误: {}", pid.0, lib_path, e);
                Err(e)
            }
        }
    }

    fn inject_library_inner(&mut self, lib_path: &str) -> crate::Result<()> {
        let pid = self.target_pid;

        let path_bytes = lib_path.as_bytes();
        let path_len = path_bytes.len() + 1;
        let remote_path_addr = self.ptrace.alloc_remote(pid, path_len)?;

        self.remote_allocs.push(RemoteAlloc {
            addr: remote_path_addr,
            size: path_len,
        });

        let mut path_with_null = path_bytes.to_vec();
        path_with_null.push(0);

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

        let tid = pid.0 as i32;
        let _orig_regs = self.ptrace.save_regs(tid)?;

        let trap_page = self.ptrace.alloc_remote_rwx(pid, 0x1000)?;
        let bkpt_insn: u32 = 0xD4200000u32;
        self.ptrace.write_remote(pid, trap_page as usize, &bkpt_insn.to_ne_bytes())?;
        log::debug!("BKPT 跳板分配于 {:#x}", trap_page);

        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            if let Ok(dlopen_ext_addr) = self.ptrace.find_remote_android_dlopen_ext(pid) {
                log::debug!("使用 android_dlopen_ext 绕过 linker namespace，地址: {:#x}", dlopen_ext_addr);
                
                let dlopen_ext_args = vec![
                    remote_path_addr,
                    1u64,
                    0u64,
                    0u64,
                ];

                let handle = self.ptrace.call_remote_trap(tid, dlopen_ext_addr, &dlopen_ext_args, trap_page)?;
                if handle != 0 {
                    self.ptrace.restore_regs(tid)?;
                    log::info!("远程 android_dlopen_ext 成功，handle = {:#x}", handle);
                    return Ok(());
                }
                log::warn!("android_dlopen_ext 返回 NULL，尝试普通 dlopen");
            }
        }

        let dlopen_addr = self
            .ptrace
            .find_remote_dlopen(pid)
            .map_err(|_| FridaError::Inject {
                reason: format!("找不到 dlopen 地址"),
                pid: pid.0,
                source: None,
            })?;

        log::debug!("目标进程中 dlopen 地址: {:#x}", dlopen_addr);

        let dlopen_args = vec![
            remote_path_addr,
            1u64,
        ];

        log::debug!("调用远程 dlopen({:#x}, RTLD_LAZY)", remote_path_addr);

        let handle = self.ptrace.call_remote_trap(tid, dlopen_addr, &dlopen_args, trap_page)?;

        if handle == 0 {
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

        self.ptrace.restore_regs(tid)?;

        log::info!(
            "远程 dlopen 成功，handle = {:#x}",
            handle
        );

        Ok(())
    }

    pub fn attach_process(&mut self) -> crate::Result<()> {
        self.ptrace.attach(self.target_pid)
    }

    pub fn detach_process(&mut self) -> crate::Result<()> {
        if self.ptrace.is_attached() {
            self.ptrace.detach()?;
        }
        Ok(())
    }

    pub fn target_pid(&self) -> ProcessId {
        self.target_pid
    }

    pub fn is_attached(&self) -> bool {
        self.ptrace.is_attached()
    }

    pub fn ptrace(&self) -> &super::ptrace_inject::PtraceInjector {
        &self.ptrace
    }

    pub fn ptrace_mut(&mut self) -> &mut super::ptrace_inject::PtraceInjector {
        &mut self.ptrace
    }

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