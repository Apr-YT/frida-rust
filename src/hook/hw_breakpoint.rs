//! 硬件断点模块
//!
//! 通过处理器的调试寄存器实现硬件级断点，无需修改目标指令。
//!
//! x86_64: 通过 PTRACE_POKEUSER 写 DR0-DR3（地址寄存器）+ DR7（控制寄存器），最多 4 个断点
//! ARM64: 通过 nova_stealth.ko 的 ioctl 通道由内核设置硬件调试寄存器（DBGBCR/DBGWCR）。
//!        原因：nix 0.29 在 aarch64 未暴露 ptrace::RegSet/setregset，且内核模块已封装正确的
//!        硬件断点/监视点编码，用户态直接操作 ptrace 反而需自行拼 user_hw_breakpoint。

use crate::common::types::ProcessId;
use crate::Result;
use nix::sys::ptrace;
use nix::unistd::Pid;
use std::collections::HashMap;

// ======================== 断点类型 ========================

/// 硬件断点类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakpointType {
    Execute,
    Read,
    Write,
    ReadWrite,
}

/// 断点长度
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakpointLength {
    OneByte,
    TwoBytes,
    FourBytes,
    EightBytes,
}

// ======================== 硬件断点配置 ========================

/// 硬件断点配置
#[derive(Debug, Clone)]
pub struct HardwareBreakpointConfig {
    pub target_pid: ProcessId,
    pub target_tid: Option<u32>,
    pub address: u64,
    pub bp_type: BreakpointType,
    pub length: BreakpointLength,
    pub enabled: bool,
}

/// 硬件断点句柄
pub struct HardwareBreakpointHandle {
    pub bp_id: u64,
    /// 内核模块（nova_stealth.ko）返回的硬件断点 ID，用于清除
    pub ko_bp_id: i32,
    pub config: HardwareBreakpointConfig,
    pub register_index: usize,
    pub enabled: bool,
}

/// 硬件断点管理器
pub struct HardwareBreakpointManager {
    breakpoints: HashMap<u64, HardwareBreakpointHandle>,
    next_id: u64,
    available_registers: Vec<bool>,
    max_breakpoints: usize,
}

impl HardwareBreakpointManager {
    /// 创建新的硬件断点管理器
    pub fn new(target_pid: ProcessId) -> Result<Self> {
        let max_bp = Self::get_max_breakpoints();

        Ok(HardwareBreakpointManager {
            breakpoints: HashMap::new(),
            next_id: 1,
            available_registers: vec![true; max_bp],
            max_breakpoints: max_bp,
        })
    }

    /// 获取系统支持的最大硬件断点数量
    pub fn get_max_breakpoints() -> usize {
        #[cfg(target_arch = "x86_64")]
        {
            4
        }
        #[cfg(target_arch = "aarch64")]
        {
            6
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            0
        }
    }

    /// 添加硬件断点
    pub fn add_breakpoint(&mut self, config: HardwareBreakpointConfig) -> Result<u64> {
        if self.breakpoints.len() >= self.max_breakpoints {
            return Err(crate::FridaError::LimitExceeded {
                reason: format!("已达到最大硬件断点数量 ({})", self.max_breakpoints),
            }.into());
        }

        let register_idx = self.available_registers.iter()
            .position(|&available| available)
            .ok_or_else(|| crate::FridaError::LimitExceeded {
                reason: "无可用的调试寄存器".to_string(),
            })?;

        let bp_id = self.next_id;
        self.next_id += 1;

        let ko_bp_id = set_hw_breakpoint(&config, register_idx)?;

        self.available_registers[register_idx] = false;

        let handle = HardwareBreakpointHandle {
            bp_id,
            ko_bp_id,
            config: config.clone(),
            register_index: register_idx,
            enabled: true,
        };

        self.breakpoints.insert(bp_id, handle);
        log::info!("硬件断点 #{} 已设置: 0x{:x}", bp_id, config.address);

        Ok(bp_id)
    }

    /// 移除硬件断点
    pub fn remove_breakpoint(&mut self, bp_id: u64) -> Result<()> {
        if let Some(handle) = self.breakpoints.remove(&bp_id) {
            clear_hw_breakpoint(&handle.config, handle.register_index, handle.ko_bp_id)?;
            self.available_registers[handle.register_index] = true;
            log::info!("硬件断点 #{} 已移除", bp_id);
        } else {
            return Err(crate::FridaError::NotFound {
                reason: format!("未找到硬件断点 #{}", bp_id),
            }.into());
        }
        Ok(())
    }

    /// 启用断点
    pub fn enable_breakpoint(&mut self, bp_id: u64) -> Result<()> {
        if let Some(handle) = self.breakpoints.get_mut(&bp_id) {
            if !handle.enabled {
                let ko_bp_id = set_hw_breakpoint(&handle.config, handle.register_index)?;
                handle.ko_bp_id = ko_bp_id;
                handle.enabled = true;
                log::info!("硬件断点 #{} 已启用", bp_id);
            }
        } else {
            return Err(crate::FridaError::NotFound {
                reason: format!("未找到硬件断点 #{}", bp_id),
            }.into());
        }
        Ok(())
    }

    /// 禁用断点
    pub fn disable_breakpoint(&mut self, bp_id: u64) -> Result<()> {
        if let Some(handle) = self.breakpoints.get_mut(&bp_id) {
            if handle.enabled {
                clear_hw_breakpoint(&handle.config, handle.register_index, handle.ko_bp_id)?;
                handle.enabled = false;
                log::info!("硬件断点 #{} 已禁用", bp_id);
            }
        } else {
            return Err(crate::FridaError::NotFound {
                reason: format!("未找到硬件断点 #{}", bp_id),
            }.into());
        }
        Ok(())
    }

    /// 设置硬件写监视点（ARM64）—— 通过内核模块 ioctl 通道
    #[cfg(target_arch = "aarch64")]
    pub fn add_watchpoint(&mut self, config: HardwareBreakpointConfig) -> Result<u64> {
        use crate::communication::kernel_channel::IoctlChannel;
        let bp_id = self.next_id;
        self.next_id += 1;

        let type_: u32 = match config.bp_type {
            BreakpointType::Execute => 0,
            BreakpointType::Read => 1,
            BreakpointType::Write => 2,
            BreakpointType::ReadWrite => 3,
        };
        let len: u32 = match config.length {
            BreakpointLength::OneByte => 1,
            BreakpointLength::TwoBytes => 2,
            BreakpointLength::FourBytes => 4,
            BreakpointLength::EightBytes => 8,
        };
        let ch = IoctlChannel::new()?;
        let ko_bp_id = ch.hwbp_set(config.target_pid.0, config.address, type_, len)?;
        let bp_addr = config.address;

        let handle = HardwareBreakpointHandle {
            bp_id,
            ko_bp_id,
            config,
            register_index: 0,
            enabled: true,
        };

        self.breakpoints.insert(bp_id, handle);
        log::info!("硬件监视点 #{} 已设置: 0x{:x}", bp_id, bp_addr);

        Ok(bp_id)
    }

    /// 获取断点数量
    pub fn breakpoint_count(&self) -> usize {
        self.breakpoints.len()
    }

    /// 获取可用断点数量
    pub fn available_count(&self) -> usize {
        self.available_registers.iter().filter(|&&v| v).count()
    }
}

// ======================== 平台相关的硬件断点实现（free function，避免 &self 借用冲突） ========================

#[cfg(target_arch = "x86_64")]
fn set_hw_breakpoint(config: &HardwareBreakpointConfig, register_idx: usize) -> Result<i32> {
    let pid = Pid::from_raw(config.target_pid.0 as i32);
    let dr_registers = [libc::DR0, libc::DR1, libc::DR2, libc::DR3];
    let dr7_bits = [(0, 1), (2, 3), (4, 5), (6, 7)];
    if register_idx >= 4 {
        return Err(crate::FridaError::LimitExceeded {
            reason: "x86_64 最多支持 4 个硬件断点".to_string(),
        }.into());
    }
    unsafe {
        ptrace::pokeuser(pid, dr_registers[register_idx] as i32, config.address as *mut libc::c_void)
            .map_err(|e| crate::FridaError::Inject {
                reason: format!("写入 DR{} 失败: {}", register_idx, e),
                pid: config.target_pid.0,
                source: None,
            })?;
        let mut dr7: u64 = ptrace::peekuser(pid, libc::DR7 as i32)
            .map_err(|e| crate::FridaError::Inject {
                reason: format!("读取 DR7 失败: {}", e),
                pid: config.target_pid.0,
                source: None,
            })? as u64;
        let (len_low, _len_high) = match config.length {
            BreakpointLength::OneByte => (0b00, 0b00),
            BreakpointLength::TwoBytes => (0b01, 0b01),
            BreakpointLength::FourBytes => (0b11, 0b11),
            BreakpointLength::EightBytes => (0b10, 0b10),
        };
        let (rwx_low, _rwx_high) = match config.bp_type {
            BreakpointType::Execute => (0b00, 0b00),
            BreakpointType::Write => (0b01, 0b00),
            BreakpointType::Read => (0b11, 0b00),
            BreakpointType::ReadWrite => (0b11, 0b00),
        };
        let (low_bit, _high_bit) = dr7_bits[register_idx];
        dr7 |= 1u64 << low_bit;
        dr7 &= !(0b11u64 << (16 + register_idx * 2));
        dr7 |= (len_low as u64) << (16 + register_idx * 2);
        dr7 &= !(0b11u64 << (24 + register_idx * 2));
        dr7 |= (rwx_low as u64) << (24 + register_idx * 2);
        ptrace::pokeuser(pid, libc::DR7 as i32, dr7 as *mut libc::c_void)
            .map_err(|e| crate::FridaError::Inject {
                reason: format!("写入 DR7 失败: {}", e),
                pid: config.target_pid.0,
                source: None,
            })?;
    }
    Ok(register_idx as i32)
}

#[cfg(target_arch = "x86_64")]
fn clear_hw_breakpoint(config: &HardwareBreakpointConfig, register_idx: usize, _ko_bp_id: i32) -> Result<()> {
    let pid = Pid::from_raw(config.target_pid.0 as i32);
    let dr_registers = [libc::DR0, libc::DR1, libc::DR2, libc::DR3];
    let dr7_bits = [(0, 1), (2, 3), (4, 5), (6, 7)];
    unsafe {
        ptrace::pokeuser(pid, dr_registers[register_idx] as i32, 0u64 as *mut libc::c_void)
            .map_err(|e| crate::FridaError::Inject {
                reason: format!("清除 DR{} 失败: {}", register_idx, e),
                pid: config.target_pid.0,
                source: None,
            })?;
        let mut dr7: u64 = ptrace::peekuser(pid, libc::DR7 as i32)
            .map_err(|e| crate::FridaError::Inject {
                reason: format!("读取 DR7 失败: {}", e),
                pid: config.target_pid.0,
                source: None,
            })? as u64;
        let (low_bit, _) = dr7_bits[register_idx];
        dr7 &= !(1u64 << low_bit);
        ptrace::pokeuser(pid, libc::DR7 as i32, dr7 as *mut libc::c_void)
            .map_err(|e| crate::FridaError::Inject {
                reason: format!("更新 DR7 失败: {}", e),
                pid: config.target_pid.0,
                source: None,
            })?;
    }
    Ok(())
}

#[cfg(target_arch = "aarch64")]
fn set_hw_breakpoint(config: &HardwareBreakpointConfig, _register_idx: usize) -> Result<i32> {
    use crate::communication::kernel_channel::IoctlChannel;
    if config.target_pid.0 == 0 {
        return Err(crate::FridaError::Unsupported {
            reason: "target_pid 无效".to_string(),
        }.into());
    }
    let type_: u32 = match config.bp_type {
        BreakpointType::Execute => 0,
        BreakpointType::Read => 1,
        BreakpointType::Write => 2,
        BreakpointType::ReadWrite => 3,
    };
    let len: u32 = match config.length {
        BreakpointLength::OneByte => 1,
        BreakpointLength::TwoBytes => 2,
        BreakpointLength::FourBytes => 4,
        BreakpointLength::EightBytes => 8,
    };
    let ch = IoctlChannel::new()?;
    let ko_id = ch.hwbp_set(config.target_pid.0, config.address, type_, len)?;
    Ok(ko_id)
}

#[cfg(target_arch = "aarch64")]
fn clear_hw_breakpoint(_config: &HardwareBreakpointConfig, _register_idx: usize, ko_bp_id: i32) -> Result<()> {
    use crate::communication::kernel_channel::IoctlChannel;
    let ch = IoctlChannel::new()?;
    ch.hwbp_clear(ko_bp_id)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_max_breakpoints() {
        let max = HardwareBreakpointManager::get_max_breakpoints();
        assert!(max > 0);
    }

    #[test]
    fn test_manager_creation() {
        let manager = HardwareBreakpointManager::new(ProcessId(1234));
        assert!(manager.is_ok());
    }

    #[test]
    fn test_breakpoint_config() {
        let config = HardwareBreakpointConfig {
            target_pid: ProcessId(1234),
            target_tid: None,
            address: 0x12345678,
            bp_type: BreakpointType::Execute,
            length: BreakpointLength::FourBytes,
            enabled: true,
        };
        assert_eq!(config.address, 0x12345678);
        assert_eq!(config.bp_type, BreakpointType::Execute);
    }
}
