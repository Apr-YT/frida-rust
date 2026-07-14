use crate::FridaError;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicU32, AtomicBool, Ordering};
use std::time::Duration;

const NOVA_MAX_DATA_SIZE: usize = 65536;
const NOVA_RECV_TIMEOUT_MS: i32 = 5000;
const NOVA_MAX_RETRY: usize = 3;
const NOVA_RETRY_DELAY_MS: u64 = 100;

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum NovaCmd {
    None = 0,
    Inject = 1,
    MemRead = 2,
    MemWrite = 3,
    HideProc = 4,
    HideThread = 5,
    InstallHook = 6,
    EventNotify = 7,
    Ping = 8,
    Version = 9,
    RegisterHook = 10,
    UnregisterHook = 11,
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

const NOVA_REQUEST_HEADER_SIZE: usize = std::mem::size_of::<NovaRequest>();
const NOVA_RESPONSE_HEADER_SIZE: usize = std::mem::size_of::<NovaResponse>();

pub struct KernelChannel {
    fd: RawFd,
    seq_counter: AtomicU32,
    available: AtomicBool,
}

impl KernelChannel {
    pub fn new() -> Result<Self, FridaError> {
        unsafe {
            let fd = libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_DGRAM,
                libc::NETLINK_USERSOCK,
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

            Ok(KernelChannel {
                fd,
                seq_counter: AtomicU32::new(1),
                available: AtomicBool::new(true),
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
        let header_size = NOVA_REQUEST_HEADER_SIZE;
        let total_size = header_size + data.len();

        if total_size > NOVA_MAX_DATA_SIZE {
            return Err(FridaError::Communication {
                reason: "数据大小超出限制".to_string(),
                source: None,
            });
        }

        let mut buf = vec![0u8; total_size];
        let req = unsafe { &mut *(buf.as_mut_ptr() as *mut NovaRequest) };
        req.cmd = cmd as u32;
        req.seq = seq;
        req.target_pid = target_pid;
        req.data_len = data.len() as u32;

        if !data.is_empty() {
            buf[header_size..header_size + data.len()].copy_from_slice(data);
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

            if (len as usize) < NOVA_RESPONSE_HEADER_SIZE {
                return Err(FridaError::Communication {
                    reason: "响应数据过短".to_string(),
                    source: None,
                });
            }

            let resp = &*(buf.as_ptr() as *const NovaResponse);
            if resp.seq != expected_seq {
                return Err(FridaError::Communication {
                    reason: format!("序列号不匹配: 期望 {}, 实际 {}", expected_seq, resp.seq),
                    source: None,
                });
            }

            let data_len = resp.data_len as usize;
            let mut data = Vec::new();
            if data_len > 0 && len as usize >= NOVA_RESPONSE_HEADER_SIZE + data_len {
                data.extend_from_slice(&buf[NOVA_RESPONSE_HEADER_SIZE..NOVA_RESPONSE_HEADER_SIZE + data_len]);
            }

            Ok((resp.result, data))
        }
    }

    fn send_request_with_retry(&self, cmd: NovaCmd, target_pid: u32, data: &[u8]) -> Result<(i32, Vec<u8>), FridaError> {
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
        let (result, _) = self.send_request_with_retry(NovaCmd::Inject, pid as u32, path_bytes)?;

        if result != 0 {
            return Err(FridaError::Communication {
                reason: format!("注入失败: {}", result),
                source: None,
            });
        }

        Ok(())
    }

    pub fn read_mem(&self, pid: i32, addr: usize, size: usize) -> Result<Vec<u8>, FridaError> {
        let mut data = vec![0u8; 12];
        let addr_bytes = addr.to_le_bytes();
        let size_bytes = size.to_le_bytes();
        data[0..8].copy_from_slice(&addr_bytes);
        data[8..12].copy_from_slice(&size_bytes);

        let (result, response_data) = self.send_request_with_retry(NovaCmd::MemRead, pid as u32, &data)?;

        if result != 0 {
            return Err(FridaError::Communication {
                reason: format!("内存读取失败: {}", result),
                source: None,
            });
        }

        Ok(response_data)
    }

    pub fn write_mem(&self, pid: i32, addr: usize, data: &[u8]) -> Result<(), FridaError> {
        let mut req_data = vec![0u8; 12 + data.len()];
        let addr_bytes = addr.to_le_bytes();
        let size_bytes = data.len().to_le_bytes();
        req_data[0..8].copy_from_slice(&addr_bytes);
        req_data[8..12].copy_from_slice(&size_bytes);
        req_data[12..12 + data.len()].copy_from_slice(data);

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

    pub fn hide_thread(&self, pid: i32, tid: i32) -> Result<(), FridaError> {
        let tid_bytes = tid.to_le_bytes();
        let (result, _) = self.send_request_with_retry(NovaCmd::HideThread, pid as u32, &tid_bytes)?;

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

        let mut data = vec![0u8; 16 + original_bytes.len()];
        let addr_bytes = addr.to_le_bytes();
        let size_bytes = original_bytes.len().to_le_bytes();
        data[0..8].copy_from_slice(&addr_bytes);
        data[8..16].copy_from_slice(&size_bytes);
        data[16..16 + original_bytes.len()].copy_from_slice(original_bytes);

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
}

impl Drop for KernelChannel {
    fn drop(&mut self) {
        unsafe {
            let _ = libc::close(self.fd);
        }
    }
}