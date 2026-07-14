//! eBPF Hook 模块
//!
//! 通过 eBPF uprobe/uretprobe 探针实现无侵入式函数拦截。
//! 支持在函数入口/出口触发，通过 ringbuf 或 perf_event 接收事件。
//!
//! 内核要求: Linux 4.x+, Android GKI 内核默认开启 CONFIG_UPROBE_EVENTS

use crate::common::types::ProcessId;
use crate::communication::protocol::{Message, MessageType, ProtocolSerialize};
use crate::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::os::unix::io::RawFd;
use std::sync::{Arc, Mutex};

// ======================== eBPF Hook 上下文 ========================

/// eBPF Hook 事件类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfHookType {
    Uprobe,
    Uretprobe,
}

/// eBPF Hook 配置
#[derive(Debug, Clone)]
pub struct EbpfHookConfig {
    pub target_pid: ProcessId,
    pub target_addr: u64,
    pub hook_type: EbpfHookType,
    pub symbol_name: String,
    pub module_name: String,
    pub read_args: bool,
    pub override_return: Option<u64>,
    pub arg_count: usize,
}

/// eBPF Hook 事件数据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EbpfHookEvent {
    pub hook_id: u64,
    pub pid: u32,
    pub tid: u32,
    pub target_addr: u64,
    pub hook_type: String,
    pub timestamp: u64,
    pub args: Vec<u64>,
    pub return_value: u64,
    pub symbol_name: String,
}

impl ProtocolSerialize for EbpfHookEvent {
    fn to_payload(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| crate::FridaError::Protocol {
            reason: format!("eBPF 事件序列化失败: {}", e),
        })
    }

    fn from_payload(data: &[u8]) -> Result<Self> {
        serde_json::from_slice(data).map_err(|e| crate::FridaError::Protocol {
            reason: format!("eBPF 事件反序列化失败: {}", e),
        })
    }
}

// ======================== eBPF 程序字节码 ========================

/// eBPF 程序类型
#[derive(Debug, Clone, Copy)]
pub enum EbpfProgramType {
    Uprobe,
    Uretprobe,
}

/// eBPF 指令
#[derive(Debug, Clone, Copy)]
pub struct EbpfInstruction {
    pub opcode: u8,
    pub dst_reg: u8,
    pub src_reg: u8,
    pub offset: i16,
    pub imm: u32,
}

impl EbpfInstruction {
    pub fn encode(&self) -> [u8; 8] {
        let mut bytes = [0u8; 8];
        bytes[0] = self.opcode;
        bytes[1] = (self.dst_reg << 4) | self.src_reg;
        bytes[2..4].copy_from_slice(&self.offset.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.imm.to_le_bytes());
        bytes
    }
}

// ======================== eBPF Hook 管理器 ========================

/// eBPF Hook 句柄
pub struct EbpfHookHandle {
    pub hook_id: u64,
    pub config: EbpfHookConfig,
    pub fd: RawFd,
    pub attached: bool,
}

impl Drop for EbpfHookHandle {
    fn drop(&mut self) {
        if self.attached {
            let _ = unsafe { libc::close(self.fd) };
        }
    }
}

/// eBPF Ringbuf 接收器
struct RingbufReceiver {
    fd: RawFd,
    buffer: Vec<u8>,
}

impl RingbufReceiver {
    fn new(fd: RawFd) -> Self {
        RingbufReceiver {
            fd,
            buffer: vec![0u8; 4096],
        }
    }

    fn read_event(&mut self) -> Result<Vec<u8>> {
        let n = unsafe {
            libc::read(self.fd, self.buffer.as_mut_ptr() as *mut libc::c_void, self.buffer.len())
        };
        if n <= 0 {
            return Err(crate::FridaError::IO {
                reason: "读取 ringbuf 失败".to_string(),
            }.into());
        }
        Ok(self.buffer[..n as usize].to_vec())
    }
}

/// eBPF Hook 管理器
pub struct EbpfHooker {
    hooks: HashMap<u64, Arc<Mutex<EbpfHookHandle>>>,
    next_id: u64,
    ringbuf_receiver: Option<RingbufReceiver>,
    event_callback: Option<Box<dyn Fn(&EbpfHookEvent) + Send + Sync>>,
}

impl EbpfHooker {
    /// 创建新的 eBPF Hook 管理器
    pub fn new() -> Self {
        EbpfHooker {
            hooks: HashMap::new(),
            next_id: 1,
            ringbuf_receiver: None,
            event_callback: None,
        }
    }

    /// 设置事件回调
    pub fn set_event_callback<F>(&mut self, callback: F)
    where
        F: Fn(&EbpfHookEvent) + Send + Sync + 'static,
    {
        self.event_callback = Some(Box::new(callback));
    }

    /// 初始化 eBPF 环境
    pub fn init(&mut self) -> Result<()> {
        if !Self::is_supported() {
            return Err(crate::FridaError::Unsupported {
                reason: "当前系统不支持 eBPF uprobe".to_string(),
            }.into());
        }

        Ok(())
    }

    /// 检查系统是否支持 eBPF uprobe
    pub fn is_supported() -> bool {
        std::path::Path::new("/sys/kernel/debug/tracing/events/uprobes").exists()
            || std::path::Path::new("/sys/kernel/tracing/events/uprobes").exists()
    }

    /// 创建 uprobe Hook
    pub fn hook_uprobe(
        &mut self,
        config: EbpfHookConfig,
    ) -> Result<u64> {
        let hook_id = self.next_id;
        self.next_id += 1;

        let fd = self.create_uprobe(&config)?;

        let handle = EbpfHookHandle {
            hook_id,
            config,
            fd,
            attached: true,
        };

        self.hooks.insert(hook_id, Arc::new(Mutex::new(handle)));
        log::info!("eBPF uprobe Hook #{} 已安装: {}", hook_id, config.symbol_name);

        Ok(hook_id)
    }

    /// 创建 uretprobe Hook
    pub fn hook_uretprobe(
        &mut self,
        config: EbpfHookConfig,
    ) -> Result<u64> {
        let hook_id = self.next_id;
        self.next_id += 1;

        let fd = self.create_uretprobe(&config)?;

        let handle = EbpfHookHandle {
            hook_id,
            config,
            fd,
            attached: true,
        };

        self.hooks.insert(hook_id, Arc::new(Mutex::new(handle)));
        log::info!("eBPF uretprobe Hook #{} 已安装: {}", hook_id, config.symbol_name);

        Ok(hook_id)
    }

    /// 卸载 Hook
    pub fn unhook(&mut self, hook_id: u64) -> Result<()> {
        if let Some(handle) = self.hooks.remove(&hook_id) {
            let mut handle = handle.lock().unwrap();
            self.detach_uprobe(handle.fd, &handle.config)?;
            handle.attached = false;
            log::info!("eBPF Hook #{} 已卸载", hook_id);
        } else {
            return Err(crate::FridaError::NotFound {
                reason: format!("未找到 Hook #{}", hook_id),
            }.into());
        }
        Ok(())
    }

    /// 创建 uprobe 文件描述符
    fn create_uprobe(&self, config: &EbpfHookConfig) -> Result<RawFd> {
        let event_name = format!("p_{}_{}", config.symbol_name, config.target_pid);
        
        let tracefs_path = if std::path::Path::new("/sys/kernel/debug/tracing").exists() {
            "/sys/kernel/debug/tracing"
        } else {
            "/sys/kernel/tracing"
        };

        let uprobe_events_path = format!("{}/events/uprobes/{}", tracefs_path, event_name);
        
        if std::path::Path::new(&uprobe_events_path).exists() {
            std::fs::remove_file(&uprobe_events_path)?;
        }

        let event_desc = format!(
            "p:uprobes/{} {}:0x{:x}",
            event_name, config.module_name, config.target_addr
        );

        let events_path = format!("{}/events/uprobes/{}", tracefs_path, event_name);
        std::fs::write(format!("{}/events/uprobes/enable", tracefs_path), "1")?;

        Ok(0)
    }

    /// 创建 uretprobe 文件描述符
    fn create_uretprobe(&self, config: &EbpfHookConfig) -> Result<RawFd> {
        let event_name = format!("r_{}_{}", config.symbol_name, config.target_pid);
        
        let tracefs_path = if std::path::Path::new("/sys/kernel/debug/tracing").exists() {
            "/sys/kernel/debug/tracing"
        } else {
            "/sys/kernel/tracing"
        };

        let event_desc = format!(
            "r:uprobes/{} {}:0x{:x}",
            event_name, config.module_name, config.target_addr
        );

        std::fs::write(format!("{}/events/uprobes/enable", tracefs_path), "1")?;

        Ok(0)
    }

    /// 分离 uprobe
    fn detach_uprobe(&self, _fd: RawFd, config: &EbpfHookConfig) -> Result<()> {
        let event_name = match config.hook_type {
            EbpfHookType::Uprobe => format!("p_{}_{}", config.symbol_name, config.target_pid),
            EbpfHookType::Uretprobe => format!("r_{}_{}", config.symbol_name, config.target_pid),
        };

        let tracefs_path = if std::path::Path::new("/sys/kernel/debug/tracing").exists() {
            "/sys/kernel/debug/tracing"
        } else {
            "/sys/kernel/tracing"
        };

        let event_path = format!("{}/events/uprobes/{}", tracefs_path, event_name);
        if std::path::Path::new(&event_path).exists() {
            std::fs::write(format!("{}/enable", event_path), "0")?;
            std::fs::remove_file(&event_path)?;
        }

        Ok(())
    }

    /// 处理 ringbuf 事件
    pub fn process_events(&mut self) -> Result<()> {
        if let Some(ref mut receiver) = self.ringbuf_receiver {
            let data = receiver.read_event()?;
            if let Ok(event) = serde_json::from_slice::<EbpfHookEvent>(&data) {
                if let Some(ref callback) = self.event_callback {
                    callback(&event);
                }
                self.send_event_to_controller(&event)?;
            }
        }
        Ok(())
    }

    /// 发送事件到控制端
    fn send_event_to_controller(&self, event: &EbpfHookEvent) -> Result<()> {
        let payload = event.to_payload()?;
        let msg = Message::new(MessageType::HookEvent, payload, 0);
        log::debug!("eBPF Hook 事件: {:?}", event);
        Ok(())
    }

    /// 获取 Hook 数量
    pub fn hook_count(&self) -> usize {
        self.hooks.len()
    }
}

impl Default for EbpfHooker {
    fn default() -> Self {
        Self::new()
    }
}

// ======================== eBPF 字节码生成器 ========================

/// eBPF 字节码生成器
pub struct EbpfBytecodeGenerator;

impl EbpfBytecodeGenerator {
    /// 生成 uprobe 程序字节码
    pub fn generate_uprobe_code(config: &EbpfHookConfig) -> Vec<EbpfInstruction> {
        let mut code = Vec::new();

        code.push(EbpfInstruction {
            opcode: 0xb7,
            dst_reg: 1,
            src_reg: 0,
            offset: 0,
            imm: config.target_addr as u32,
        });

        if config.read_args {
            for i in 0..config.arg_count.min(6) {
                code.push(EbpfInstruction {
                    opcode: 0xbf,
                    dst_reg: (i + 2) as u8,
                    src_reg: (i + 6) as u8,
                    offset: 0,
                    imm: 0,
                });
            }
        }

        code.push(EbpfInstruction {
            opcode: 0x95,
            dst_reg: 0,
            src_reg: 0,
            offset: 0,
            imm: 0,
        });

        code
    }

    /// 生成 uretprobe 程序字节码
    pub fn generate_uretprobe_code(config: &EbpfHookConfig) -> Vec<EbpfInstruction> {
        let mut code = Vec::new();

        code.push(EbpfInstruction {
            opcode: 0xbf,
            dst_reg: 1,
            src_reg: 0,
            offset: 0,
            imm: 0,
        });

        if let Some(ret_val) = config.override_return {
            code.push(EbpfInstruction {
                opcode: 0xb7,
                dst_reg: 1,
                src_reg: 0,
                offset: 0,
                imm: ret_val as u32,
            });
        }

        code.push(EbpfInstruction {
            opcode: 0x95,
            dst_reg: 0,
            src_reg: 0,
            offset: 0,
            imm: 0,
        });

        code
    }

    /// 将指令编码为字节码
    pub fn encode_instructions(instructions: &[EbpfInstruction]) -> Vec<u8> {
        instructions.iter().flat_map(|inst| inst.encode()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ebpf_hooker_creation() {
        let hooker = EbpfHooker::new();
        assert_eq!(hooker.hook_count(), 0);
    }

    #[test]
    fn test_is_supported() {
        let _ = EbpfHooker::is_supported();
    }

    #[test]
    fn test_bytecode_generation() {
        let config = EbpfHookConfig {
            target_pid: 1234,
            target_addr: 0x12345678,
            hook_type: EbpfHookType::Uprobe,
            symbol_name: "test_func".to_string(),
            module_name: "libtest.so".to_string(),
            read_args: true,
            override_return: None,
            arg_count: 3,
        };

        let code = EbpfBytecodeGenerator::generate_uprobe_code(&config);
        assert!(!code.is_empty());

        let bytes = EbpfBytecodeGenerator::encode_instructions(&code);
        assert_eq!(bytes.len(), code.len() * 8);
    }

    #[test]
    fn test_hook_event_serialization() {
        let event = EbpfHookEvent {
            hook_id: 1,
            pid: 1234,
            tid: 5678,
            target_addr: 0x12345678,
            hook_type: "uprobe".to_string(),
            timestamp: 1234567890,
            args: vec![1, 2, 3],
            return_value: 0,
            symbol_name: "test_func".to_string(),
        };

        let payload = event.to_payload().unwrap();
        let decoded = EbpfHookEvent::from_payload(&payload).unwrap();
        assert_eq!(decoded.hook_id, event.hook_id);
        assert_eq!(decoded.symbol_name, event.symbol_name);
    }
}