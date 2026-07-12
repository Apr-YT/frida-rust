//! 通信通道 Trait 和实现
//!
//! 定义统一的通信接口，提供三种传输通道实现：
//! - **UnixSocketChannel**: 本地 Unix Domain Socket（性能最好）
//! - **StdioChannel**: 标准输入/输出管道（兼容性最好）
//! - **SharedMemChannel**: 共享内存通道（延迟最低）
//!
//! 在传输通道之上提供 **EncryptedChannel** 加密包装层。

use crate::communication::protocol::{Message, MessageHeader};
#[cfg(unix)]
use crate::common::constants::COMM_BUFFER_SIZE;
use crate::FridaError;
use std::io::{Read, Write};

// ======================== Channel Trait ========================

/// 通信通道 trait
///
/// 定义双向消息传输的统一接口。
pub trait Channel: Send + Sync {
    /// 发送消息
    ///
    /// # 参数
    /// - `msg`: 要发送的消息
    fn send(&mut self, msg: &Message) -> Result<(), FridaError>;

    /// 接收消息
    ///
    /// # 返回值
    /// 接收到的完整消息
    fn recv(&mut self) -> Result<Message, FridaError>;

    /// 关闭通道
    fn close(&mut self) -> Result<(), FridaError>;

    /// 检查通道是否仍然连接
    fn is_connected(&self) -> bool;
}

// ======================== Unix Socket 通道 ========================

/// Unix Domain Socket 通信通道
///
/// 使用 AF_UNIX/AF_LOCAL 套接字进行本地进程间通信。
/// 适用于同一设备上的控制端与 agent 之间的通信。
#[cfg(any(target_os = "linux", target_os = "android"))]
pub struct UnixSocketChannel {
    /// 内部流（已连接的 UnixStream）
    stream: Option<std::os::unix::net::UnixStream>,
    /// 接收缓冲区
    #[allow(dead_code)]
    recv_buffer: Vec<u8>,
    /// 是否已连接
    connected: bool,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl UnixSocketChannel {
    /// 连接到指定的 Unix Socket 路径
    pub fn connect(path: &str) -> Result<Self, FridaError> {
        let stream = std::os::unix::net::UnixStream::connect(path).map_err(|e| {
            FridaError::Communication {
                reason: format!("连接 Unix Socket '{}' 失败", path),
                source: Some(e),
            }
        })?;

        // 设置非阻塞超时（可选）
        stream
            .set_nonblocking(false)
            .map_err(|e| FridaError::Communication {
                reason: "设置 socket 模式失败".to_string(),
                source: Some(e),
            })?;

        log::info!("已连接到 Unix Socket: {}", path);
        Ok(UnixSocketChannel {
            stream: Some(stream),
            recv_buffer: Vec::with_capacity(COMM_BUFFER_SIZE),
            connected: true,
        })
    }

    /// 创建一对已连接的 Unix Socket（用于测试）
    pub fn pair() -> Result<(Self, Self), FridaError> {
        let (sock1, sock2) = std::os::unix::net::UnixStream::pair().map_err(|e| {
            FridaError::Communication {
                reason: "创建 socket 对失败".to_string(),
                source: Some(e),
            }
        })?;

        let ch1 = UnixSocketChannel {
            stream: Some(sock1),
            recv_buffer: Vec::with_capacity(COMM_BUFFER_SIZE),
            connected: true,
        };

        let ch2 = UnixSocketChannel {
            stream: Some(sock2),
            recv_buffer: Vec::with_capacity(COMM_BUFFER_SIZE),
            connected: true,
        };

        Ok((ch1, ch2))
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl Channel for UnixSocketChannel {
    fn send(&mut self, msg: &Message) -> Result<(), FridaError> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| FridaError::Communication {
                reason: "通道未连接".to_string(),
                source: None,
            })?;

        let data = msg.encode();
        stream
            .write_all(&data)
            .map_err(|e| FridaError::Communication {
                reason: "发送消息失败".to_string(),
                source: Some(e),
            })?;

        log::trace!("发送消息: type={:?}, len={}", msg.header.msg_type, data.len());
        Ok(())
    }

    fn recv(&mut self) -> Result<Message, FridaError> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| FridaError::Communication {
                reason: "通道未连接".to_string(),
                source: None,
            })?;

        // 先读取消息头
        let mut header_buf = [0u8; crate::common::constants::MESSAGE_HEADER_SIZE];
        stream
            .read_exact(&mut header_buf)
            .map_err(|e| FridaError::Communication {
                reason: "读取消息头失败".to_string(),
                source: Some(e),
            })?;

        // 解码消息头获取负载长度
        let mut cursor = std::io::Cursor::new(header_buf);
        let header = MessageHeader::decode(&mut cursor)?;

        // 读取负载
        let mut payload = vec![0u8; header.length as usize];
        if header.length > 0 {
            stream
                .read_exact(&mut payload)
                .map_err(|e| FridaError::Communication {
                    reason: format!("读取负载失败 ({} 字节)", header.length),
                    source: Some(e),
                })?;
        }

        let msg = Message {
            header,
            payload,
        };
        log::trace!(
            "接收消息: type={:?}, len={}",
            msg.header.msg_type,
            msg.payload.len()
        );
        Ok(msg)
    }

    fn close(&mut self) -> Result<(), FridaError> {
        if let Some(stream) = self.stream.take() {
            stream
                .shutdown(std::net::Shutdown::Both)
                .map_err(|e| FridaError::Communication {
                    reason: "关闭 socket 失败".to_string(),
                    source: Some(e),
                })?;
        }
        self.connected = false;
        log::info!("Unix Socket 通道已关闭");
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected
    }
}

// ======================== Stdio 通道 ========================

/// 标准输入/输出通信通道
///
/// 通过 stdin/stdout 进行通信，适用于管道模式和子进程场景。
pub struct StdioChannel {
    /// 输入流
    reader: Option<std::io::BufReader<std::io::Stdin>>,
    /// 输出流
    writer: Option<std::io::BufWriter<std::io::Stdout>>,
    /// 是否已连接
    connected: bool,
}

impl StdioChannel {
    /// 创建绑定到 stdin/stdout 的通道
    pub fn new() -> Self {
        StdioChannel {
            reader: None,
            writer: None,
            connected: true,
        }
    }

    /// 使用自定义的输入/输出流创建通道
    pub fn with_streams<R: Read + Send + Sync + 'static, W: Write + Send + Sync + 'static>(
        reader: R,
        writer: W,
    ) -> StdioChannelWrapper<R, W> {
        StdioChannelWrapper {
            reader: Some(std::io::BufReader::new(reader)),
            writer: Some(std::io::BufWriter::new(writer)),
            connected: true,
        }
    }
}

impl Default for StdioChannel {
    fn default() -> Self {
        Self::new()
    }
}

impl Channel for StdioChannel {
    fn send(&mut self, msg: &Message) -> Result<(), FridaError> {
        let writer = self.writer.get_or_insert_with(|| {
            std::io::BufWriter::new(std::io::stdout())
        });

        let data = msg.encode();
        writer
            .write_all(&data)
            .map_err(|e| FridaError::Communication {
                reason: "stdout 写入失败".to_string(),
                source: Some(e),
            })?;
        writer
            .flush()
            .map_err(|e| FridaError::Communication {
                reason: "stdout 刷新失败".to_string(),
                source: Some(e),
            })?;

        log::trace!("Stdio 发送消息: type={:?}", msg.header.msg_type);
        Ok(())
    }

    fn recv(&mut self) -> Result<Message, FridaError> {
        let reader = self.reader.get_or_insert_with(|| {
            std::io::BufReader::new(std::io::stdin())
        });

        let mut header_buf = [0u8; crate::common::constants::MESSAGE_HEADER_SIZE];
        reader
            .read_exact(&mut header_buf)
            .map_err(|e| FridaError::Communication {
                reason: "stdin 读取失败".to_string(),
                source: Some(e),
            })?;

        let mut cursor = std::io::Cursor::new(header_buf);
        let header = MessageHeader::decode(&mut cursor)?;

        let mut payload = vec![0u8; header.length as usize];
        if header.length > 0 {
            reader
                .read_exact(&mut payload)
                .map_err(|e| FridaError::Communication {
                    reason: "stdin 负载读取失败".to_string(),
                    source: Some(e),
                })?;
        }

        Ok(Message {
            header,
            payload,
        })
    }

    fn close(&mut self) -> Result<(), FridaError> {
        self.connected = false;
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected
    }
}

/// 泛型 Stdio 通道包装器（支持自定义输入/输出流）
pub struct StdioChannelWrapper<R: Read, W: Write> {
    reader: Option<std::io::BufReader<R>>,
    writer: Option<std::io::BufWriter<W>>,
    connected: bool,
}

impl<R: Read + Send + Sync, W: Write + Send + Sync> Channel for StdioChannelWrapper<R, W> {
    fn send(&mut self, msg: &Message) -> Result<(), FridaError> {
        let writer = self.writer.as_mut().ok_or_else(|| FridaError::Communication {
            reason: "写入通道已关闭".to_string(),
            source: None,
        })?;

        let data = msg.encode();
        writer
            .write_all(&data)
            .map_err(|e| FridaError::Communication {
                reason: "写入失败".to_string(),
                source: Some(e),
            })?;
        writer.flush().map_err(|e| FridaError::Communication {
            reason: "刷新失败".to_string(),
            source: Some(e),
        })?;
        Ok(())
    }

    fn recv(&mut self) -> Result<Message, FridaError> {
        let reader = self.reader.as_mut().ok_or_else(|| FridaError::Communication {
            reason: "读取通道已关闭".to_string(),
            source: None,
        })?;

        let mut header_buf = [0u8; crate::common::constants::MESSAGE_HEADER_SIZE];
        reader.read_exact(&mut header_buf).map_err(|e| FridaError::Communication {
            reason: "读取消息头失败".to_string(),
            source: Some(e),
        })?;

        let mut cursor = std::io::Cursor::new(header_buf);
        let header = MessageHeader::decode(&mut cursor)?;

        let mut payload = vec![0u8; header.length as usize];
        if header.length > 0 {
            reader.read_exact(&mut payload).map_err(|e| FridaError::Communication {
                reason: "读取负载失败".to_string(),
                source: Some(e),
            })?;
        }

        Ok(Message { header, payload })
    }

    fn close(&mut self) -> Result<(), FridaError> {
        self.writer = None;
        self.reader = None;
        self.connected = false;
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected
    }
}

// ======================== 共享内存通道 ========================

/// 共享内存通信通道
///
/// 使用 POSIX 共享内存实现低延迟的双向通信。
/// 通过环形缓冲区和信号量/原子变量进行同步。
#[cfg(any(target_os = "linux", target_os = "android"))]
pub struct SharedMemChannel {
    /// 共享内存名称
    shm_name: String,
    /// 共享内存文件描述符
    fd: Option<i32>,
    /// 映射的内存区域指针
    mapped_addr: Option<usize>,
    /// 映射大小
    map_size: usize,
    /// 是否已连接
    connected: bool,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl SharedMemChannel {
    /// 共享内存头部大小：mutex(8B) + data_len(8B) = 16 字节
    const SHM_HEADER_SIZE: usize = 16;

    /// 自旋锁最大自旋次数（避免无限循环）
    const MAX_SPIN_COUNT: u32 = 1_000_000;

    /// 创建或打开共享内存通道
    ///
    /// 打开 POSIX 共享内存对象并 mmap 到进程地址空间。
    /// 共享内存布局: `[mutex(8B)] [data_len(8B)] [data(NB)]`
    pub fn open(name: &str, size: usize) -> Result<Self, FridaError> {
        #[cfg(target_os = "android")]
        {
            let _ = name;
            let _ = size;
            return Err(FridaError::Communication {
                reason: "Android 不支持 POSIX 共享内存".to_string(),
                source: None,
            });
        }

        #[cfg(not(target_os = "android"))]
        {
            use std::ffi::CString;

            let shm_name = if name.starts_with('/') {
                name.to_string()
            } else {
                format!("/frida-rust-{}", name)
            };

            let c_name = CString::new(shm_name.as_str()).map_err(|e| FridaError::Communication {
                reason: format!("共享内存名称无效: {}", e),
                source: None,
            })?;

            // 打开或创建共享内存
            // SAFETY: shm_open 是标准的 POSIX API
            let fd = unsafe {
                libc::shm_open(
                    c_name.as_ptr(),
                    libc::O_CREAT | libc::O_RDWR,
                    0o600, // 仅所有者可读写
                )
            };

            if fd < 0 {
                return Err(FridaError::Communication {
                    reason: format!(
                        "shm_open 失败: {}",
                        std::io::Error::last_os_error()
                    ),
                    source: None,
                });
            }

            // 设置共享内存大小
            // SAFETY: ftruncate 用于调整共享内存大小
            let ret = unsafe { libc::ftruncate(fd, size as libc::off_t) };
            if ret < 0 {
                unsafe { libc::close(fd) };
                return Err(FridaError::Communication {
                    reason: format!(
                        "ftruncate 失败: {}",
                        std::io::Error::last_os_error()
                    ),
                    source: None,
                });
            }

            // 将共享内存映射到进程地址空间
            // SAFETY: mmap 使用有效的 fd 和 size，MAP_SHARED 允许跨进程共享
            let mapped_addr = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),       // 由内核选择地址
                    size,                        // 映射大小
                    libc::PROT_READ | libc::PROT_WRITE, // 读写权限
                    libc::MAP_SHARED,            // 跨进程共享
                    fd,                          // 共享内存文件描述符
                    0,                           // 偏移量为 0
                )
            };

            if mapped_addr == libc::MAP_FAILED {
                unsafe { libc::close(fd) };
                return Err(FridaError::Communication {
                    reason: format!(
                        "mmap 失败: {}",
                        std::io::Error::last_os_error()
                    ),
                    source: None,
                });
            }

            log::info!(
                "共享内存通道已打开: {}, fd={}, size={}, mapped_addr={:#x}",
                shm_name,
                fd,
                size,
                mapped_addr as usize
            );

            Ok(SharedMemChannel {
                shm_name,
                fd: Some(fd),
                mapped_addr: Some(mapped_addr as usize),
                map_size: size,
                connected: true,
            })
        }
    }

    /// 确保 mmap 已完成，返回映射后的内存指针
    #[allow(dead_code)]
    fn ensure_mapped(&mut self) -> Result<*mut u8, FridaError> {
        match self.mapped_addr {
            Some(addr) => Ok(addr as *mut u8),
            None => Err(FridaError::Communication {
                reason: "共享内存尚未映射，请先调用 open()".to_string(),
                source: None,
            }),
        }
    }

    /// 获取共享内存中 mutex 的原子引用
    ///
    /// 布局: 偏移 0 处是 8 字节的 mutex（0=未锁定, 1=已锁定）
    fn mutex_ptr(&self) -> *mut std::sync::atomic::AtomicU64 {
        self.mapped_addr.unwrap() as *mut std::sync::atomic::AtomicU64
    }

    /// 获取共享内存中 data_len 的原子引用
    ///
    /// 布局: 偏移 8 处是 8 字节的数据长度
    fn data_len_ptr(&self) -> *mut std::sync::atomic::AtomicU64 {
        (self.mapped_addr.unwrap() + 8) as *mut std::sync::atomic::AtomicU64
    }

    /// 获取数据区域的起始指针
    ///
    /// 布局: 偏移 16 处开始是实际数据
    fn data_ptr(&self) -> *mut u8 {
        (self.mapped_addr.unwrap() + Self::SHM_HEADER_SIZE) as *mut u8
    }

    /// 数据区域可用大小
    fn data_capacity(&self) -> usize {
        self.map_size.saturating_sub(Self::SHM_HEADER_SIZE)
    }

    /// 通过 CAS 自旋锁获取互斥锁
    fn spin_lock(&self) -> Result<(), FridaError> {
        let mutex = self.mutex_ptr();
        // SAFETY: mutex_ptr 指向 mmap 共享内存中的有效 8 字节区域
        let atomic = unsafe { &*mutex };

        for _ in 0..Self::MAX_SPIN_COUNT {
            // 尝试 CAS: 期望 0（未锁定），写入 1（已锁定）
            match atomic.compare_exchange_weak(
                0,
                1,
                std::sync::atomic::Ordering::Acquire,
                std::sync::atomic::Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(()), // 成功获取锁
                Err(_) => {
                    // 锁被占用，使用 CPU pause 指令让出执行单元减少总线争用
                    std::hint::spin_loop();
                }
            }
        }

        Err(FridaError::Communication {
            reason: "获取共享内存锁超时（自旋次数超限）".to_string(),
            source: None,
        })
    }

    /// 释放互斥锁（写入 0）
    fn spin_unlock(&self) {
        let mutex = self.mutex_ptr();
        // SAFETY: mutex_ptr 指向 mmap 共享内存中的有效 8 字节区域
        let atomic = unsafe { &*mutex };
        atomic.store(0, std::sync::atomic::Ordering::Release);
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl Channel for SharedMemChannel {
    fn send(&mut self, msg: &Message) -> Result<(), FridaError> {
        if !self.is_connected() {
            return Err(FridaError::Communication {
                reason: "共享内存通道未连接".to_string(),
                source: None,
            });
        }

        // 1. 将 Message 编码为字节数组（头 + 负载）
        let encoded = msg.encode();
        let data_len = encoded.len();

        // 检查数据是否超出共享内存容量
        if data_len > self.data_capacity() {
            return Err(FridaError::Communication {
                reason: format!(
                    "消息大小 ({}) 超出共享内存数据区容量 ({})",
                    data_len,
                    self.data_capacity()
                ),
                source: None,
            });
        }

        // 2. 获取自旋锁（CAS 自旋等待）
        self.spin_lock()?;

        // 3. 写入数据长度到头部区域
        // SAFETY: data_len_ptr 指向 mmap 共享内存中的有效 8 字节区域
        let len_atomic = unsafe { &*self.data_len_ptr() };
        len_atomic.store(data_len as u64, std::sync::atomic::Ordering::Release);

        // 4. 写入编码后的消息数据到数据区域
        // SAFETY: data_ptr 指向 mmap 共享内存中的有效数据区域，
        // 大小已通过 data_capacity() 验证
        let data_ptr = self.data_ptr();
        unsafe {
            std::ptr::copy_nonoverlapping(encoded.as_ptr(), data_ptr, data_len);
        }

        // 5. 释放自旋锁（Release 语义确保上面的写入对其他进程可见）
        self.spin_unlock();

        log::trace!(
            "共享内存发送完成: type={:?}, len={}",
            msg.header.msg_type,
            data_len
        );
        Ok(())
    }

    fn recv(&mut self) -> Result<Message, FridaError> {
        if !self.is_connected() {
            return Err(FridaError::Communication {
                reason: "共享内存通道未连接".to_string(),
                source: None,
            });
        }

        // 1. 获取自旋锁
        self.spin_lock()?;

        // 2. 读取数据长度
        // SAFETY: data_len_ptr 指向 mmap 共享内存中的有效 8 字节区域
        let len_atomic = unsafe { &*self.data_len_ptr() };
        let data_len = len_atomic.load(std::sync::atomic::Ordering::Acquire) as usize;

        // 3. 长度为 0 表示暂无数据，释放锁后返回占位消息
        if data_len == 0 {
            self.spin_unlock();
            let header = crate::communication::protocol::MessageHeader::new(
                crate::communication::protocol::MessageType::Ping,
                0,
                0,
            );
            return Ok(Message {
                header,
                payload: Vec::new(),
            });
        }

        // 4. 从数据区域读取消息字节
        if data_len > self.data_capacity() {
            self.spin_unlock();
            return Err(FridaError::Communication {
                reason: format!(
                    "共享内存中的数据长度 ({}) 超出数据区容量 ({})",
                    data_len,
                    self.data_capacity()
                ),
                source: None,
            });
        }

        let mut buf = vec![0u8; data_len];
        let data_ptr = self.data_ptr();
        // SAFETY: data_ptr 指向 mmap 共享内存中的有效数据区域，
        // data_len 已通过 data_capacity() 验证
        unsafe {
            std::ptr::copy_nonoverlapping(data_ptr, buf.as_mut_ptr(), data_len);
        }

        // 5. 读取完毕后将长度清零，表示消息已被消费
        len_atomic.store(0, std::sync::atomic::Ordering::Release);

        // 6. 释放自旋锁
        self.spin_unlock();

        // 7. 使用 protocol::decode 解码为 Message
        let mut cursor = std::io::Cursor::new(buf);
        let msg = Message::decode(&mut cursor)?;

        log::trace!(
            "共享内存接收完成: type={:?}, len={}",
            msg.header.msg_type,
            msg.payload.len()
        );
        Ok(msg)
    }

    fn close(&mut self) -> Result<(), FridaError> {
        // 取消映射
        if let Some(addr) = self.mapped_addr.take() {
            // SAFETY: munmap 与 mmap 配对使用
            unsafe {
                libc::munmap(addr as *mut libc::c_void, self.map_size);
            }
        }

        // 关闭文件描述符并删除共享内存
        if let Some(fd) = self.fd.take() {
            // SAFETY: close 是标准的资源释放操作
            unsafe { libc::close(fd) };
        }

        // 删除共享内存对象
        #[cfg(not(target_os = "android"))]
        {
            let c_name = std::ffi::CString::new(self.shm_name.as_str())
                .map_err(|e| FridaError::Communication {
                    reason: format!("共享内存名称包含无效字符: {}", e),
                    source: None,
                })?;
            // SAFETY: shm_unlink 删除共享内存对象
            unsafe {
                libc::shm_unlink(c_name.as_ptr());
            }
        }

        self.connected = false;
        log::info!("共享内存通道已关闭: {}", self.shm_name);
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected && self.fd.is_some()
    }
}

// ======================== 加密包装通道 ========================

/// 加密通信通道
///
/// 对底层通道的消息进行 AES-256-GCM 加密/解密。
/// 每个消息使用独立的 nonce 和认证标签，确保机密性和完整性。
pub struct EncryptedChannel<T: Channel> {
    /// 底层传输通道
    inner: T,
    /// AES-256-GCM 加密密钥
    key: [u8; 32],
    /// 发送计数器（用于生成 nonce）
    send_counter: u64,
    /// 接收计数器（用于验证 nonce）
    recv_counter: u64,
}

impl<T: Channel> EncryptedChannel<T> {
    /// 创建加密通道
    ///
    /// # 参数
    /// - `inner`: 底层传输通道
    /// - `key`: 256 位加密密钥
    pub fn new(inner: T, key: [u8; 32]) -> Self {
        log::info!("加密通道已创建");
        EncryptedChannel {
            inner,
            key,
            send_counter: 0,
            recv_counter: 0,
        }
    }

    /// 生成随机密钥
    pub fn generate_key() -> [u8; 32] {
        use rand::RngCore;
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        key
    }

    /// 加密数据
    ///
    /// 使用 AES-256-GCM 对数据进行加密，生成 nonce + ciphertext + tag。
    fn encrypt_data(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, FridaError> {
        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::{Aes256Gcm, Nonce};

        let cipher = Aes256Gcm::new_from_slice(&self.key).map_err(|e| {
            FridaError::Crypto {
                reason: format!("创建加密上下文失败: {:?}", e),
            }
        })?;

        // 从计数器生成 nonce (12 字节)
        let nonce_bytes = self.send_counter.to_le_bytes();
        let mut nonce_data = [0u8; 12];
        nonce_data[4..].copy_from_slice(&nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_data);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| FridaError::Crypto {
                reason: format!("加密失败: {:?}", e),
            })?;

        self.send_counter += 1;

        // 前缀: 8 字节计数器 + 密文（含 tag）
        let mut result = Vec::with_capacity(8 + ciphertext.len());
        result.extend_from_slice(&self.send_counter.to_le_bytes());
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// 解密数据
    fn decrypt_data(&mut self, data: &[u8]) -> Result<Vec<u8>, FridaError> {
        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::{Aes256Gcm, Nonce};

        if data.len() < 8 {
            return Err(FridaError::Crypto {
                reason: "加密数据过短".to_string(),
            });
        }

        // 提取计数器和密文
        let mut counter_bytes = [0u8; 8];
        counter_bytes.copy_from_slice(&data[..8]);
        let counter = u64::from_le_bytes(counter_bytes);
        let ciphertext = &data[8..];

        // 验证计数器顺序
        if counter <= self.recv_counter {
            return Err(FridaError::Crypto {
                reason: format!(
                    "Nonce 计数器回退: 期望 > {}, 实际 {}",
                    self.recv_counter, counter
                ),
            });
        }
        self.recv_counter = counter;

        let cipher = Aes256Gcm::new_from_slice(&self.key).map_err(|e| {
            FridaError::Crypto {
                reason: format!("创建解密上下文失败: {:?}", e),
            }
        })?;

        // 从计数器生成 nonce
        let nonce_bytes = counter.to_le_bytes();
        let mut nonce_data = [0u8; 12];
        nonce_data[4..].copy_from_slice(&nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_data);

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| FridaError::Crypto {
                reason: format!("解密失败（可能被篡改）: {:?}", e),
            })?;

        Ok(plaintext)
    }
}

impl<T: Channel> Channel for EncryptedChannel<T> {
    fn send(&mut self, msg: &Message) -> Result<(), FridaError> {
        let plaintext = msg.encode();
        let encrypted = self.encrypt_data(&plaintext)?;

        // 创建包装消息（类型为 Notification，负载为加密数据）
        let wrapper = Message::new(
            crate::communication::protocol::MessageType::Notification,
            encrypted,
            msg.header.seq,
        );

        self.inner.send(&wrapper)
    }

    fn recv(&mut self) -> Result<Message, FridaError> {
        let wrapper = self.inner.recv()?;
        let plaintext = self.decrypt_data(&wrapper.payload)?;

        // 从解密后的字节中解析原始消息
        let mut cursor = std::io::Cursor::new(plaintext);
        Message::decode(&mut cursor)
    }

    fn close(&mut self) -> Result<(), FridaError> {
        // 发送断开连接消息
        let _ = self.inner.send(&Message::disconnect(0));
        self.inner.close()
    }

    fn is_connected(&self) -> bool {
        self.inner.is_connected()
    }
}
