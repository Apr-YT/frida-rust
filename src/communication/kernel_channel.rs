use crate::FridaError;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicU32, AtomicBool, Ordering};
use std::time::Duration;

const NOVA_MAX_DATA_SIZE: usize = 65536;
const NOVA_RECV_TIMEOUT_MS: i32 = 5000;
const NOVA_MAX_RETRY: usize = 3;
const NOVA_RETRY_DELAY_MS: u64 = 100;

const NLMSG_HDRLEN: usize = 16;
const NLMSG_DONE: u16 = 0;

#[repr(C)]
struct NlMsgHdr {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum NovaCmd {
    None = 0,
    Inject = 1,
    MemRead = 2,
    MemWrite = 3,
    HideProc = 4,
    UnhideProc = 5,
    HideThread = 6,
    HideMod = 7,
    UnhideMod = 8,
    InstallHook = 9,
    EventNotify = 10,
    Ping = 11,
    Version = 12,
    RegisterHook = 13,
    UnregisterHook = 14,
    SetConfig = 15,
    GetStatus = 16,
    HwbpSet = 17,
    HwbpClear = 18,
    HwbpList = 19,
    HwbpClearAll = 20,
    InputTap = 21,
    InputSwipe = 22,
    InputKey = 23,
    InputText = 24,
}

#[repr(C)]
#[derive(Debug)]
pub struct NovaRequest {
    pub cmd: u32,
    pub seq: u32,
    pub target_pid: u32,
    pub data_len: u32,
    pub data: [u8; 0],
}

#[repr(C)]
#[derive(Debug)]
pub struct NovaResponse {
    pub seq: u32,
    pub result: i32,
    pub data_len: u32,
    pub data: [u8; 0],
}

#[repr(C)]
#[derive(Debug)]
pub struct NovaInjectData {
    pub flags: u32,
    pub path: [u8; 0],
}

#[repr(C)]
#[derive(Debug)]
pub struct NovaMemData {
    pub addr: u64,
    pub size: u32,
    pub data: [u8; 0],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct NovaHwbpConfig {
    pub pid: u32,
    pub type_: u32,
    pub addr: u64,
    pub len: u32,
    pub bp_id: i32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct NovaHwbpInfo {
    pub id: i32,
    pub pid: u32,
    pub addr: u64,
    pub type_: u32,
    pub len: u32,
    pub hit_count: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct NovaInputTap {
    pub x: u32,
    pub y: u32,
    pub duration_ms: u32,
    pub jitter: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct NovaInputSwipe {
    pub x1: u32,
    pub y1: u32,
    pub x2: u32,
    pub y2: u32,
    pub duration_ms: u32,
    pub steps: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct NovaInputKey {
    pub keycode: u32,
    pub repeat: u32,
}

const NOVA_REQUEST_HEADER_SIZE: usize = std::mem::size_of::<NovaRequest>();
const NOVA_RESPONSE_HEADER_SIZE: usize = std::mem::size_of::<NovaResponse>();
const NOVA_INJECT_DATA_HEADER_SIZE: usize = std::mem::size_of::<NovaInjectData>();
const NOVA_MEM_DATA_HEADER_SIZE: usize = std::mem::size_of::<NovaMemData>();

pub struct KernelChannel {
    fd: RawFd,
    seq_counter: AtomicU32,
    available: AtomicBool,
    pid: u32,
}

impl KernelChannel {
    pub fn new() -> Result<Self, FridaError> {
        unsafe {
            let fd = libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_DGRAM,
                libc::NETLINK_FIREWALL,
            );

            if fd < 0 {
                return Err(FridaError::Communication {
                    reason: format!("创建 Netlink socket 失败: {}", std::io::Error::last_os_error()),
                    source: None,
                });
            }

            let timeout = libc::timeval {
                tv_sec: (NOVA_RECV_TIMEOUT_MS / 1000) as libc::time_t,
                tv_usec: ((NOVA_RECV_TIMEOUT_MS % 1000) * 1000) as libc::suseconds_t,
            };

            let ret = libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &timeout as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );

            if ret < 0 {
                libc::close(fd);
                return Err(FridaError::Communication {
                    reason: format!("设置接收超时失败: {}", std::io::Error::last_os_error()),
                    source: None,
                });
            }

            let mut addr = std::mem::zeroed::<libc::sockaddr_nl>();
            addr.nl_family = libc::AF_NETLINK as u16;
            addr.nl_pid = 0;
            addr.nl_groups = 0;

            let ret = libc::bind(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            );

            if ret < 0 {
                libc::close(fd);
                return Err(FridaError::Communication {
                    reason: format!("绑定 Netlink socket 失败: {}", std::io::Error::last_os_error()),
                    source: None,
                });
            }

            let pid = libc::getpid() as u32;

            Ok(KernelChannel {
                fd,
                seq_counter: AtomicU32::new(1),
                available: AtomicBool::new(true),
                pid,
            })
        }
    }

    pub fn is_available(&self) -> bool {
        self.available.load(Ordering::Relaxed)
    }

    pub fn reset_available(&self) {
        self.available.store(true, Ordering::Relaxed);
    }

    fn next_seq(&self) -> u32 {
        self.seq_counter.fetch_add(1, Ordering::Relaxed)
    }

    fn send_request(&self, cmd: NovaCmd, target_pid: u32, data: &[u8]) -> Result<u32, FridaError> {
        let seq = self.next_seq();
        let request_header_size = NOVA_REQUEST_HEADER_SIZE;
        let data_len = data.len();
        let total_size = NLMSG_HDRLEN + request_header_size + data_len;

        if total_size > NOVA_MAX_DATA_SIZE {
            return Err(FridaError::Communication {
                reason: "数据大小超出限制".to_string(),
                source: None,
            });
        }

        let mut buf = vec![0u8; total_size];

        let nlmsghdr = unsafe { &mut *(buf.as_mut_ptr() as *mut NlMsgHdr) };
        nlmsghdr.nlmsg_len = total_size as u32;
        nlmsghdr.nlmsg_type = NLMSG_DONE;
        nlmsghdr.nlmsg_flags = 0;
        nlmsghdr.nlmsg_seq = seq;
        nlmsghdr.nlmsg_pid = self.pid;

        let req = unsafe { &mut *((buf.as_mut_ptr().wrapping_add(NLMSG_HDRLEN)) as *mut NovaRequest) };
        req.cmd = cmd as u32;
        req.seq = seq;
        req.target_pid = target_pid;
        req.data_len = data_len as u32;

        if !data.is_empty() {
            buf[NLMSG_HDRLEN + request_header_size..NLMSG_HDRLEN + request_header_size + data_len]
                .copy_from_slice(data);
        }

        unsafe {
            let mut dest_addr = std::mem::zeroed::<libc::sockaddr_nl>();
            dest_addr.nl_family = libc::AF_NETLINK as u16;
            dest_addr.nl_pid = 0;
            dest_addr.nl_groups = 0;

            let len = libc::sendto(
                self.fd,
                buf.as_ptr() as *const libc::c_void,
                total_size,
                0,
                &dest_addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            );

            if len < 0 {
                return Err(FridaError::Communication {
                    reason: format!("发送 Netlink 请求失败: {}", std::io::Error::last_os_error()),
                    source: None,
                });
            }

            if len != total_size as isize {
                return Err(FridaError::Communication {
                    reason: "发送不完整".to_string(),
                    source: None,
                });
            }
        }

        Ok(seq)
    }

    fn recv_response(&self, expected_seq: u32) -> Result<(i32, Vec<u8>), FridaError> {
        let mut buf = vec![0u8; NOVA_MAX_DATA_SIZE];
        let mut addr = unsafe { std::mem::zeroed::<libc::sockaddr_nl>() };
        let mut addr_len = std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;

        unsafe {
            let len = libc::recvfrom(
                self.fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                NOVA_MAX_DATA_SIZE,
                0,
                &mut addr as *mut _ as *mut libc::sockaddr,
                &mut addr_len,
            );

            if len < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::TimedOut {
                    return Err(FridaError::Communication {
                        reason: "接收响应超时".to_string(),
                        source: None,
                    });
                }
                return Err(FridaError::Communication {
                    reason: format!("接收 Netlink 响应失败: {}", err),
                    source: None,
                });
            }

            if (len as usize) < NLMSG_HDRLEN + NOVA_RESPONSE_HEADER_SIZE {
                return Err(FridaError::Communication {
                    reason: "响应数据过短".to_string(),
                    source: None,
                });
            }

            let nlh = &*(buf.as_ptr() as *const NlMsgHdr);
            if nlh.nlmsg_seq != expected_seq {
                return Err(FridaError::Communication {
                    reason: format!("序列号不匹配: 期望 {}, 实际 {}", expected_seq, nlh.nlmsg_seq),
                    source: None,
                });
            }

            let resp = &*((buf.as_ptr().wrapping_add(NLMSG_HDRLEN)) as *const NovaResponse);

            let data_len = resp.data_len as usize;
            let mut data = Vec::new();
            let total_response_len = NLMSG_HDRLEN + NOVA_RESPONSE_HEADER_SIZE + data_len;
            if data_len > 0 && len as usize >= total_response_len {
                data.extend_from_slice(
                    &buf[NLMSG_HDRLEN + NOVA_RESPONSE_HEADER_SIZE
                        ..NLMSG_HDRLEN + NOVA_RESPONSE_HEADER_SIZE + data_len],
                );
            }

            Ok((resp.result, data))
        }
    }

    fn send_request_with_retry(
        &self,
        cmd: NovaCmd,
        target_pid: u32,
        data: &[u8],
    ) -> Result<(i32, Vec<u8>), FridaError> {
        let mut last_err: Option<FridaError> = None;

        for attempt in 0..NOVA_MAX_RETRY {
            match self.send_request(cmd, target_pid, data) {
                Ok(seq) => {
                    match self.recv_response(seq) {
                        Ok(result) => return Ok(result),
                        Err(e) => {
                            last_err = Some(e);
                            if attempt < NOVA_MAX_RETRY - 1 {
                                std::thread::sleep(Duration::from_millis(NOVA_RETRY_DELAY_MS * (1 << attempt)));
                            }
                        }
                    }
                }
                Err(e) => {
                    last_err = Some(e);
                    if attempt < NOVA_MAX_RETRY - 1 {
                        std::thread::sleep(Duration::from_millis(NOVA_RETRY_DELAY_MS * (1 << attempt)));
                    }
                }
            }
        }

        self.available.store(false, Ordering::Relaxed);

        Err(last_err.unwrap_or(FridaError::Communication {
            reason: "请求失败，已达到最大重试次数".to_string(),
            source: None,
        }))
    }

    pub fn ping(&self) -> Result<String, FridaError> {
        let (result, data) = self.send_request_with_retry(NovaCmd::Ping, 0, &[])?;

        if result != 0 {
            return Err(FridaError::Communication {
                reason: format!("Ping 失败: {}", result),
                source: None,
            });
        }

        Ok(String::from_utf8_lossy(&data).trim().to_string())
    }

    pub fn get_version(&self) -> Result<String, FridaError> {
        let (result, data) = self.send_request_with_retry(NovaCmd::Version, 0, &[])?;

        if result != 0 {
            return Err(FridaError::Communication {
                reason: format!("获取版本失败: {}", result),
                source: None,
            });
        }

        Ok(String::from_utf8_lossy(&data).trim().to_string())
    }

    pub fn inject(&self, pid: i32, so_path: &str) -> Result<(), FridaError> {
        let path_bytes = so_path.as_bytes();
        let total_data_len = NOVA_INJECT_DATA_HEADER_SIZE + path_bytes.len();

        if total_data_len > NOVA_MAX_DATA_SIZE {
            return Err(FridaError::Communication {
                reason: "注入路径过长".to_string(),
                source: None,
            });
        }

        let mut data = vec![0u8; total_data_len];
        let inject_data = unsafe { &mut *(data.as_mut_ptr() as *mut NovaInjectData) };
        inject_data.flags = 0;

        data[NOVA_INJECT_DATA_HEADER_SIZE..total_data_len].copy_from_slice(path_bytes);

        let (result, _) = self.send_request_with_retry(NovaCmd::Inject, pid as u32, &data)?;

        if result != 0 {
            return Err(FridaError::Communication {
                reason: format!("注入失败: {}", result),
                source: None,
            });
        }

        Ok(())
    }

    pub fn read_mem(&self, pid: i32, addr: usize, size: usize) -> Result<Vec<u8>, FridaError> {
        let mut data = vec![0u8; NOVA_MEM_DATA_HEADER_SIZE];
        let mem_data = unsafe { &mut *(data.as_mut_ptr() as *mut NovaMemData) };
        mem_data.addr = addr as u64;
        mem_data.size = size as u32;

        let (result, response_data) =
            self.send_request_with_retry(NovaCmd::MemRead, pid as u32, &data)?;

        if result != 0 {
            return Err(FridaError::Communication {
                reason: format!("内存读取失败: {}", result),
                source: None,
            });
        }

        Ok(response_data)
    }

    pub fn write_mem(&self, pid: i32, addr: usize, data: &[u8]) -> Result<(), FridaError> {
        let total_data_len = NOVA_MEM_DATA_HEADER_SIZE + data.len();

        if total_data_len > NOVA_MAX_DATA_SIZE {
            return Err(FridaError::Communication {
                reason: "写入数据过长".to_string(),
                source: None,
            });
        }

        let mut req_data = vec![0u8; total_data_len];
        let mem_data = unsafe { &mut *(req_data.as_mut_ptr() as *mut NovaMemData) };
        mem_data.addr = addr as u64;
        mem_data.size = data.len() as u32;

        req_data[NOVA_MEM_DATA_HEADER_SIZE..total_data_len].copy_from_slice(data);

        let (result, _) = self.send_request_with_retry(NovaCmd::MemWrite, pid as u32, &req_data)?;

        if result != 0 {
            return Err(FridaError::Communication {
                reason: format!("内存写入失败: {}", result),
                source: None,
            });
        }

        Ok(())
    }

    pub fn hide_process(&self, pid: i32) -> Result<(), FridaError> {
        let (result, _) = self.send_request_with_retry(NovaCmd::HideProc, pid as u32, &[])?;

        if result != 0 {
            return Err(FridaError::Communication {
                reason: format!("隐藏进程失败: {}", result),
                source: None,
            });
        }

        Ok(())
    }

    pub fn unhide_process(&self, pid: i32) -> Result<(), FridaError> {
        let (result, _) = self.send_request_with_retry(NovaCmd::UnhideProc, pid as u32, &[])?;

        if result != 0 {
            return Err(FridaError::Communication {
                reason: format!("取消隐藏进程失败: {}", result),
                source: None,
            });
        }

        Ok(())
    }

    /// 隐藏内核模块自身（注意：隐藏后 Netlink 通信将失效，无法恢复）
    pub fn hide_module(&self) -> Result<(), FridaError> {
        let (result, _) = self.send_request_with_retry(NovaCmd::HideMod, 0, &[])?;

        if result != 0 {
            return Err(FridaError::Communication {
                reason: format!("隐藏模块失败: {}", result),
                source: None,
            });
        }

        Ok(())
    }

    /// 恢复内核模块可见（仅在模块未隐藏时有效）
    pub fn unhide_module(&self) -> Result<(), FridaError> {
        let (result, _) = self.send_request_with_retry(NovaCmd::UnhideMod, 0, &[])?;

        if result != 0 {
            return Err(FridaError::Communication {
                reason: format!("恢复模块可见失败: {}", result),
                source: None,
            });
        }

        Ok(())
    }

    /// 内核级触摸点击注入（绕过 adb input，source 为 SOURCE_TOUCHSCREEN）
    pub fn input_tap(&self, x: u32, y: u32, duration_ms: u32, jitter: u32) -> Result<(), FridaError> {
        let tap = NovaInputTap { x, y, duration_ms, jitter };
        let data = unsafe {
            std::slice::from_raw_parts(
                &tap as *const NovaInputTap as *const u8,
                std::mem::size_of::<NovaInputTap>(),
            )
        };

        let (result, _) = self.send_request_with_retry(NovaCmd::InputTap, 0, data)?;

        if result != 0 {
            return Err(FridaError::Communication {
                reason: format!("输入注入 tap 失败: {}", result),
                source: None,
            });
        }

        Ok(())
    }

    /// 内核级滑动注入（带插值采样和随机抖动）
    pub fn input_swipe(&self, x1: u32, y1: u32, x2: u32, y2: u32, duration_ms: u32, steps: u32) -> Result<(), FridaError> {
        let swipe = NovaInputSwipe { x1, y1, x2, y2, duration_ms, steps };
        let data = unsafe {
            std::slice::from_raw_parts(
                &swipe as *const NovaInputSwipe as *const u8,
                std::mem::size_of::<NovaInputSwipe>(),
            )
        };

        let (result, _) = self.send_request_with_retry(NovaCmd::InputSwipe, 0, data)?;

        if result != 0 {
            return Err(FridaError::Communication {
                reason: format!("输入注入 swipe 失败: {}", result),
                source: None,
            });
        }

        Ok(())
    }

    /// 内核级按键注入（如 ENTER/BACK/HOME）
    pub fn input_key(&self, keycode: u32, repeat: u32) -> Result<(), FridaError> {
        let key = NovaInputKey { keycode, repeat };
        let data = unsafe {
            std::slice::from_raw_parts(
                &key as *const NovaInputKey as *const u8,
                std::mem::size_of::<NovaInputKey>(),
            )
        };

        let (result, _) = self.send_request_with_retry(NovaCmd::InputKey, 0, data)?;

        if result != 0 {
            return Err(FridaError::Communication {
                reason: format!("输入注入 key 失败: {}", result),
                source: None,
            });
        }

        Ok(())
    }

    pub fn hide_thread(&self, pid: i32, tid: i32) -> Result<(), FridaError> {
        let mut data = vec![0u8; 4];
        let tid_bytes = tid.to_le_bytes();
        data[0..4].copy_from_slice(&tid_bytes[0..4]);

        let (result, _) = self.send_request_with_retry(NovaCmd::HideThread, pid as u32, &data)?;

        if result != 0 {
            return Err(FridaError::Communication {
                reason: format!("隐藏线程失败: {}", result),
                source: None,
            });
        }

        Ok(())
    }

    pub fn register_hook(&self, addr: usize, original_bytes: &[u8]) -> Result<(), FridaError> {
        if original_bytes.is_empty() || original_bytes.len() > 32 {
            return Err(FridaError::Communication {
                reason: "hook 原始字节长度无效".to_string(),
                source: None,
            });
        }

        let total_data_len = 16 + original_bytes.len();
        let mut data = vec![0u8; total_data_len];
        let addr_bytes = addr.to_le_bytes();
        let size_bytes = original_bytes.len().to_le_bytes();
        data[0..8].copy_from_slice(&addr_bytes);
        data[8..16].copy_from_slice(&size_bytes);
        data[16..total_data_len].copy_from_slice(original_bytes);

        let (result, _) = self.send_request_with_retry(NovaCmd::RegisterHook, 0, &data)?;

        if result != 0 {
            return Err(FridaError::Communication {
                reason: format!("注册 hook 失败: {}", result),
                source: None,
            });
        }

        Ok(())
    }

    pub fn unregister_hook(&self, addr: usize) -> Result<(), FridaError> {
        let addr_bytes = addr.to_le_bytes();
        let (result, _) = self.send_request_with_retry(NovaCmd::UnregisterHook, 0, &addr_bytes)?;

        if result != 0 {
            return Err(FridaError::Communication {
                reason: format!("注销 hook 失败: {}", result),
                source: None,
            });
        }

        Ok(())
    }

    pub fn get_status(&self) -> Result<Vec<u8>, FridaError> {
        let (result, data) = self.send_request_with_retry(NovaCmd::GetStatus, 0, &[])?;

        if result != 0 {
            return Err(FridaError::Communication {
                reason: format!("获取状态失败: {}", result),
                source: None,
            });
        }

        Ok(data)
    }

    /// 设置硬件断点
    /// type_: 1=执行, 2=读, 3=写, 4=读写
    /// len: 访问长度（1-8，执行断点忽略）
    /// 返回断点 ID
    pub fn hwbp_set(&self, pid: u32, addr: u64, type_: u32, len: u32) -> Result<i32, FridaError> {
        let cfg = NovaHwbpConfig {
            pid,
            type_,
            addr,
            len,
            bp_id: 0,
            reserved: 0,
        };
        let data_bytes = unsafe {
            std::slice::from_raw_parts(&cfg as *const NovaHwbpConfig as *const u8, std::mem::size_of::<NovaHwbpConfig>())
        };
        let (result, resp) = self.send_request_with_retry(NovaCmd::HwbpSet, 0, data_bytes)?;
        if result != 0 {
            return Err(FridaError::Communication {
                reason: format!("设置硬件断点失败: {}", result),
                source: None,
            });
        }
        if resp.len() >= std::mem::size_of::<NovaHwbpConfig>() {
            let resp_cfg = unsafe { *(resp.as_ptr() as *const NovaHwbpConfig) };
            Ok(resp_cfg.bp_id)
        } else {
            Err(FridaError::Communication {
                reason: "hwbp_set 响应数据不足".to_string(),
                source: None,
            })
        }
    }

    /// 清除指定硬件断点
    pub fn hwbp_clear(&self, bp_id: i32) -> Result<(), FridaError> {
        let data = bp_id.to_le_bytes();
        let (result, _) = self.send_request_with_retry(NovaCmd::HwbpClear, 0, &data)?;
        if result != 0 {
            return Err(FridaError::Communication {
                reason: format!("清除硬件断点失败: {}", result),
                source: None,
            });
        }
        Ok(())
    }

    /// 列出所有硬件断点
    pub fn hwbp_list(&self) -> Result<Vec<NovaHwbpInfo>, FridaError> {
        let (result, data) = self.send_request_with_retry(NovaCmd::HwbpList, 0, &[])?;
        if result < 0 {
            return Err(FridaError::Communication {
                reason: format!("列出硬件断点失败: {}", result),
                source: None,
            });
        }
        let entry_size = std::mem::size_of::<NovaHwbpInfo>();
        let count = data.len() / entry_size;
        let mut infos = Vec::with_capacity(count);
        for i in 0..count {
            let offset = i * entry_size;
            if offset + entry_size <= data.len() {
                let info = unsafe { *(data.as_ptr().add(offset) as *const NovaHwbpInfo) };
                infos.push(info);
            }
        }
        Ok(infos)
    }

    /// 清除所有硬件断点
    pub fn hwbp_clear_all(&self) -> Result<i32, FridaError> {
        let (result, _) = self.send_request_with_retry(NovaCmd::HwbpClearAll, 0, &[])?;
        Ok(result)
    }
}

impl Drop for KernelChannel {
    fn drop(&mut self) {
        unsafe {
            let _ = libc::close(self.fd);
        }
    }
}

// ==================== Ioctl 备份通道 ====================
// 字符设备 /dev/nova_stealth，作为 Netlink 的备份通信通道
// 优势：模块从 module_list 隐藏后仍可用（不依赖 try_module_get）

/// ioctl 宏计算（与 Linux 内核 _IOC 宏一致，ARM64）
const fn _ioc(dir: u32, type_: u32, nr: u32, size: u32) -> u32 {
    (dir << 30) | (size << 16) | (type_ << 8) | nr
}
const fn _io(type_: u32, nr: u32) -> u32 { _ioc(0, type_, nr, 0) }
const fn _ior(type_: u32, nr: u32, size: u32) -> u32 { _ioc(2, type_, nr, size) }
const fn _iow(type_: u32, nr: u32, size: u32) -> u32 { _ioc(1, type_, nr, size) }
const fn _iowr(type_: u32, nr: u32, size: u32) -> u32 { _ioc(3, type_, nr, size) }

const NOVA_IOC_TYPE: u32 = b'N' as u32;

/// ioctl 内存操作请求结构（与内核 nova_ioctl.c 一致）
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NovaIoctlMemReq {
    pub pid: u32,
    pub reserved: u32,
    pub addr: u64,
    pub size: u32,
    pub result: i32,
    pub data: [u8; 4096],
}

/// NovaStatus 结构（与内核 nova_stealth.h 一致）
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct NovaStatusRaw {
    pub version: u32,
    pub hidden_proc_count: u32,
    pub hooked_region_count: u32,
    pub netlink_packets_rx: u32,
    pub netlink_packets_tx: u32,
    pub mem_read_count: u32,
    pub mem_write_count: u32,
    pub inject_count: u32,
    pub errors: u32,
}

/// ioctl 命令编号
const IOC_PING: u32 = _io(NOVA_IOC_TYPE, 0x01);
const IOC_VERSION: u32 = _ior(NOVA_IOC_TYPE, 0x02, std::mem::size_of::<u32>() as u32);
const IOC_STATUS: u32 = _ior(NOVA_IOC_TYPE, 0x03, std::mem::size_of::<NovaStatusRaw>() as u32);
const IOC_MEM_READ: u32 = _iowr(NOVA_IOC_TYPE, 0x04, std::mem::size_of::<NovaIoctlMemReq>() as u32);
const IOC_MEM_WRITE: u32 = _iow(NOVA_IOC_TYPE, 0x05, std::mem::size_of::<NovaIoctlMemReq>() as u32);
const IOC_HIDE_PROC: u32 = _iow(NOVA_IOC_TYPE, 0x06, std::mem::size_of::<u32>() as u32);
const IOC_UNHIDE_PROC: u32 = _iow(NOVA_IOC_TYPE, 0x07, std::mem::size_of::<u32>() as u32);
const IOC_HIDE_MOD: u32 = _io(NOVA_IOC_TYPE, 0x08);
const IOC_UNHIDE_MOD: u32 = _io(NOVA_IOC_TYPE, 0x09);
const IOC_HWBP_SET: u32 = _iowr(NOVA_IOC_TYPE, 0x0A, std::mem::size_of::<NovaHwbpConfig>() as u32);
const IOC_HWBP_CLEAR: u32 = _iow(NOVA_IOC_TYPE, 0x0B, 4);
const IOC_HWBP_LIST: u32 = _ior(NOVA_IOC_TYPE, 0x0C, (std::mem::size_of::<NovaHwbpInfo>() * 16) as u32);
const IOC_HWBP_CLEAR_ALL: u32 = _io(NOVA_IOC_TYPE, 0x0D);
const IOC_INPUT_TAP: u32 = _iow(NOVA_IOC_TYPE, 0x0E, std::mem::size_of::<NovaInputTap>() as u32);
const IOC_INPUT_SWIPE: u32 = _iow(NOVA_IOC_TYPE, 0x0F, std::mem::size_of::<NovaInputSwipe>() as u32);
const IOC_INPUT_KEY: u32 = _iow(NOVA_IOC_TYPE, 0x10, std::mem::size_of::<NovaInputKey>() as u32);

const NOVA_IOCTL_DEVICE: &str = "/dev/nova_stealth";

/// ioctl 字符设备通道：作为 Netlink 的备份通信
pub struct IoctlChannel {
    fd: RawFd,
}

impl IoctlChannel {
    pub fn new() -> Result<Self, FridaError> {
        let c_path = std::ffi::CString::new(NOVA_IOCTL_DEVICE)
            .map_err(|_| FridaError::Other("路径包含 NUL 字节".to_string()))?;
        let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDWR) };
        if fd < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            return Err(FridaError::Communication {
                reason: format!("打开 {} 失败 (errno={})", NOVA_IOCTL_DEVICE, errno),
                source: None,
            });
        }
        log::info!("ioctl 通道已打开: fd={}", fd);
        Ok(Self { fd })
    }

    pub fn ping(&self) -> Result<(), FridaError> {
        let ret = unsafe { libc::ioctl(self.fd, IOC_PING as libc::Ioctl) };
        if ret < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            return Err(FridaError::Communication {
                reason: format!("ioctl PING 失败 (ret={}, errno={})", ret, errno),
                source: None,
            });
        }
        Ok(())
    }

    pub fn get_version(&self) -> Result<u32, FridaError> {
        let mut ver: u32 = 0;
        let ret = unsafe { libc::ioctl(self.fd, IOC_VERSION as libc::Ioctl, &mut ver as *mut u32) };
        if ret < 0 {
            return Err(FridaError::Communication {
                reason: format!("ioctl VERSION 失败 (ret={})", ret),
                source: None,
            });
        }
        Ok(ver)
    }

    pub fn get_status(&self) -> Result<NovaStatusRaw, FridaError> {
        let mut status = NovaStatusRaw::default();
        let ret = unsafe { libc::ioctl(self.fd, IOC_STATUS as libc::Ioctl, &mut status as *mut NovaStatusRaw) };
        if ret < 0 {
            return Err(FridaError::Communication {
                reason: format!("ioctl STATUS 失败 (ret={})", ret),
                source: None,
            });
        }
        Ok(status)
    }

    pub fn read_mem(&self, pid: i32, addr: usize, size: usize) -> Result<Vec<u8>, FridaError> {
        if size > 4096 {
            return Err(FridaError::Other("ioctl 读取大小不能超过 4096 字节".to_string()));
        }
        let mut req = NovaIoctlMemReq {
            pid: pid as u32,
            reserved: 0,
            addr: addr as u64,
            size: size as u32,
            result: 0,
            data: [0u8; 4096],
        };
        let ret = unsafe { libc::ioctl(self.fd, IOC_MEM_READ as libc::Ioctl, &mut req as *mut NovaIoctlMemReq) };
        if ret < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            return Err(FridaError::Communication {
                reason: format!("ioctl MEM_READ 失败 (ret={}, errno={})", ret, errno),
                source: None,
            });
        }
        if req.result != 0 {
            return Err(FridaError::Communication {
                reason: format!("ioctl MEM_READ 内核错误: {}", req.result),
                source: None,
            });
        }
        Ok(req.data[..size].to_vec())
    }

    pub fn write_mem(&self, pid: i32, addr: usize, data: &[u8]) -> Result<(), FridaError> {
        if data.len() > 4096 {
            return Err(FridaError::Other("ioctl 写入大小不能超过 4096 字节".to_string()));
        }
        let mut req = NovaIoctlMemReq {
            pid: pid as u32,
            reserved: 0,
            addr: addr as u64,
            size: data.len() as u32,
            result: 0,
            data: [0u8; 4096],
        };
        req.data[..data.len()].copy_from_slice(data);
        let ret = unsafe { libc::ioctl(self.fd, IOC_MEM_WRITE as libc::Ioctl, &mut req as *mut NovaIoctlMemReq) };
        if ret < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            return Err(FridaError::Communication {
                reason: format!("ioctl MEM_WRITE 失败 (ret={}, errno={})", ret, errno),
                source: None,
            });
        }
        if req.result != 0 {
            return Err(FridaError::Communication {
                reason: format!("ioctl MEM_WRITE 内核错误: {}", req.result),
                source: None,
            });
        }
        Ok(())
    }

    pub fn hide_process(&self, pid: i32) -> Result<(), FridaError> {
        let mut pid_val: u32 = pid as u32;
        let ret = unsafe { libc::ioctl(self.fd, IOC_HIDE_PROC as libc::Ioctl, &mut pid_val as *mut u32) };
        if ret < 0 {
            return Err(FridaError::Communication {
                reason: format!("ioctl HIDE_PROC 失败 (ret={})", ret),
                source: None,
            });
        }
        Ok(())
    }

    pub fn unhide_process(&self, pid: i32) -> Result<(), FridaError> {
        let mut pid_val: u32 = pid as u32;
        let ret = unsafe { libc::ioctl(self.fd, IOC_UNHIDE_PROC as libc::Ioctl, &mut pid_val as *mut u32) };
        if ret < 0 {
            return Err(FridaError::Communication {
                reason: format!("ioctl UNHIDE_PROC 失败 (ret={})", ret),
                source: None,
            });
        }
        Ok(())
    }

    pub fn hide_module(&self) -> Result<(), FridaError> {
        let ret = unsafe { libc::ioctl(self.fd, IOC_HIDE_MOD as libc::Ioctl) };
        if ret < 0 {
            return Err(FridaError::Communication {
                reason: format!("ioctl HIDE_MOD 失败 (ret={})", ret),
                source: None,
            });
        }
        Ok(())
    }

    pub fn unhide_module(&self) -> Result<(), FridaError> {
        let ret = unsafe { libc::ioctl(self.fd, IOC_UNHIDE_MOD as libc::Ioctl) };
        if ret < 0 {
            return Err(FridaError::Communication {
                reason: format!("ioctl UNHIDE_MOD 失败 (ret={})", ret),
                source: None,
            });
        }
        Ok(())
    }

    /// 内核级触摸点击注入（ioctl 通道）
    pub fn input_tap(&self, x: u32, y: u32, duration_ms: u32, jitter: u32) -> Result<(), FridaError> {
        let tap = NovaInputTap { x, y, duration_ms, jitter };
        let ret = unsafe { libc::ioctl(self.fd, IOC_INPUT_TAP as libc::Ioctl, &tap as *const NovaInputTap) };
        if ret < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            return Err(FridaError::Communication {
                reason: format!("ioctl INPUT_TAP 失败 (ret={}, errno={})", ret, errno),
                source: None,
            });
        }
        Ok(())
    }

    /// 内核级滑动注入（ioctl 通道）
    pub fn input_swipe(&self, x1: u32, y1: u32, x2: u32, y2: u32, duration_ms: u32, steps: u32) -> Result<(), FridaError> {
        let swipe = NovaInputSwipe { x1, y1, x2, y2, duration_ms, steps };
        let ret = unsafe { libc::ioctl(self.fd, IOC_INPUT_SWIPE as libc::Ioctl, &swipe as *const NovaInputSwipe) };
        if ret < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            return Err(FridaError::Communication {
                reason: format!("ioctl INPUT_SWIPE 失败 (ret={}, errno={})", ret, errno),
                source: None,
            });
        }
        Ok(())
    }

    /// 内核级按键注入（ioctl 通道）
    pub fn input_key(&self, keycode: u32, repeat: u32) -> Result<(), FridaError> {
        let key = NovaInputKey { keycode, repeat };
        let ret = unsafe { libc::ioctl(self.fd, IOC_INPUT_KEY as libc::Ioctl, &key as *const NovaInputKey) };
        if ret < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            return Err(FridaError::Communication {
                reason: format!("ioctl INPUT_KEY 失败 (ret={}, errno={})", ret, errno),
                source: None,
            });
        }
        Ok(())
    }

    /// 设置硬件断点，返回断点 ID
    pub fn hwbp_set(&self, pid: u32, addr: u64, type_: u32, len: u32) -> Result<i32, FridaError> {
        let mut cfg = NovaHwbpConfig { pid, type_, addr, len, bp_id: 0, reserved: 0 };
        let ret = unsafe { libc::ioctl(self.fd, IOC_HWBP_SET as libc::Ioctl, &mut cfg as *mut NovaHwbpConfig) };
        if ret < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            return Err(FridaError::Communication {
                reason: format!("ioctl HWBP_SET 失败 (ret={}, errno={})", ret, errno),
                source: None,
            });
        }
        if ret != 0 {
            return Err(FridaError::Communication {
                reason: format!("HWBP_SET 内核错误: {}", ret),
                source: None,
            });
        }
        Ok(cfg.bp_id)
    }

    /// 清除指定硬件断点
    pub fn hwbp_clear(&self, bp_id: i32) -> Result<(), FridaError> {
        let ret = unsafe { libc::ioctl(self.fd, IOC_HWBP_CLEAR as libc::Ioctl, &bp_id as *const i32) };
        if ret < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            return Err(FridaError::Communication {
                reason: format!("ioctl HWBP_CLEAR 失败 (ret={}, errno={})", ret, errno),
                source: None,
            });
        }
        Ok(())
    }

    /// 列出所有硬件断点
    pub fn hwbp_list(&self) -> Result<Vec<NovaHwbpInfo>, FridaError> {
        let mut infos = [NovaHwbpInfo::default(); 16];
        let ret = unsafe { libc::ioctl(self.fd, IOC_HWBP_LIST as libc::Ioctl, infos.as_mut_ptr() as *mut [NovaHwbpInfo; 16]) };
        if ret < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            return Err(FridaError::Communication {
                reason: format!("ioctl HWBP_LIST 失败 (ret={}, errno={})", ret, errno),
                source: None,
            });
        }
        let count = ret as usize;
        Ok(infos[..count.min(16)].to_vec())
    }

    /// 清除所有硬件断点，返回清除的数量
    pub fn hwbp_clear_all(&self) -> Result<i32, FridaError> {
        let ret = unsafe { libc::ioctl(self.fd, IOC_HWBP_CLEAR_ALL as libc::Ioctl) };
        if ret < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            return Err(FridaError::Communication {
                reason: format!("ioctl HWBP_CLEAR_ALL 失败 (ret={}, errno={})", ret, errno),
                source: None,
            });
        }
        Ok(ret)
    }
}

impl Drop for IoctlChannel {
    fn drop(&mut self) {
        unsafe {
            let _ = libc::close(self.fd);
        }
    }
}