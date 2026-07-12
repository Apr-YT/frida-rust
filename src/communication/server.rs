//! 通信服务端
//!
//! 在 agent 端运行的通信服务，负责：
//! - 监听来自控制端的连接
//! - 接受新连接
//! - 消息路由分发到对应的处理函数

use crate::communication::protocol::{Message, MessageType};
#[cfg(unix)]
use crate::common::constants::UNIX_SOCKET_PATH_TEMPLATE;
use crate::FridaError;
use std::collections::HashMap;
#[cfg(unix)]
use std::io::Write;

// ======================== 消息处理器类型 ========================

/// 消息处理回调函数类型
pub type MessageHandler = Box<dyn Fn(&Message) -> Result<Message, FridaError> + Send + Sync>;

// ======================== 通信服务端 ========================

/// 通信服务端
///
/// 在注入 agent 的进程内运行，监听控制端的连接请求。
pub struct CommServer {
    /// 消息路由表：消息类型 -> 处理函数
    handlers: HashMap<MessageType, MessageHandler>,
    /// 监听套接字路径
    socket_path: String,
    /// 是否正在运行
    running: bool,
    /// 消息序列号计数器
    #[allow(dead_code)]
    seq_counter: u32,
}

impl CommServer {
    /// 创建通信服务端
    ///
    /// # 参数
    /// - `socket_path`: Unix Socket 监听路径（可选，自动生成）
    pub fn new(socket_path: Option<String>) -> Self {
        let path = socket_path.unwrap_or_else(|| {
            #[cfg(windows)]
            {
                format!(r"\\.\pipe\frida-rust-{}", std::process::id())
            }
            #[cfg(not(windows))]
            {
                UNIX_SOCKET_PATH_TEMPLATE.replace("{}", &format!("{}", std::process::id()))
            }
        });

        log::info!("创建通信服务端: socket={}", path);

        CommServer {
            handlers: HashMap::new(),
            socket_path: path,
            running: false,
            seq_counter: 0,
        }
    }

    /// 注册消息处理函数
    ///
    /// # 参数
    /// - `msg_type`: 要处理的消息类型
    /// - `handler`: 处理回调函数
    pub fn register_handler<F>(&mut self, msg_type: MessageType, handler: F)
    where
        F: Fn(&Message) -> Result<Message, FridaError> + Send + Sync + 'static,
    {
        self.handlers.insert(msg_type, Box::new(handler));
        log::debug!("注册消息处理器: {:?}", msg_type);
    }

    /// 生成下一个序列号
    #[allow(dead_code)]
    fn next_seq(&mut self) -> u32 {
        self.seq_counter = self.seq_counter.wrapping_add(1);
        self.seq_counter
    }

    /// 启动服务端，开始监听
    ///
    /// 阻塞当前线程，接受连接并处理消息。
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn start(&mut self) -> Result<(), FridaError> {
        use std::os::unix::net::UnixListener;

        self.running = true;

        // 确保旧的 socket 文件被清理
        let _ = std::fs::remove_file(&self.socket_path);

        // 创建监听套接字
        let listener = UnixListener::bind(&self.socket_path).map_err(|e| {
            FridaError::Communication {
                reason: format!("绑定 socket '{}' 失败", self.socket_path),
                source: Some(e),
            }
        })?;

        log::info!(
            "通信服务端已启动，监听: {}",
            self.socket_path
        );

        // 设置监听超时
        listener
            .set_nonblocking(false)
            .map_err(|e| FridaError::Communication {
                reason: "设置监听模式失败".to_string(),
                source: Some(e),
            })?;

        // 注册默认处理器
        self.register_default_handlers();

        // 主循环：接受连接并处理消息
        for stream_result in listener.incoming() {
            if !self.running {
                break;
            }

            let stream = match stream_result {
                Ok(s) => s,
                Err(e) => {
                    log::warn!("接受连接失败: {}", e);
                    continue;
                }
            };

            let peer = stream.peer_addr().ok();
            log::info!("新连接来自: {:?}", peer);

            // 处理客户端消息
            if let Err(e) = self.handle_client(stream) {
                log::error!("处理客户端错误: {}", e);
            }
        }

        // 清理 socket 文件
        let _ = std::fs::remove_file(&self.socket_path);
        log::info!("通信服务端已停止");
        Ok(())
    }

    /// 处理单个客户端连接
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn handle_client(
        &mut self,
        stream: std::os::unix::net::UnixStream,
    ) -> Result<(), FridaError> {
        use std::io::{BufReader, BufWriter};

        stream
            .set_nonblocking(false)
            .map_err(|e| FridaError::Communication {
                reason: "设置客户端 socket 模式失败".to_string(),
                source: Some(e),
            })?;

        let mut reader = BufReader::new(&stream);
        let mut writer = BufWriter::new(&stream);

        // 消息处理循环
        loop {
            // 读取消息头
            let mut header_buf = [0u8; crate::common::constants::MESSAGE_HEADER_SIZE];
            match std::io::Read::read_exact(&mut reader, &mut header_buf) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    log::info!("客户端断开连接");
                    break;
                }
                Err(e) => {
                    return Err(FridaError::Communication {
                        reason: format!("读取消息头失败: {}", e),
                        source: Some(e),
                    });
                }
            }

            // 解码消息
            let request = {
                let mut cursor = std::io::Cursor::new(header_buf);
                let header = crate::communication::protocol::MessageHeader::decode(&mut cursor)?;
                let mut payload = vec![0u8; header.length as usize];
                if header.length > 0 {
                    std::io::Read::read_exact(&mut reader, &mut payload).map_err(|e| {
                        FridaError::Communication {
                            reason: format!("读取负载失败: {}", e),
                            source: Some(e),
                        }
                    })?;
                }
                Message { header, payload }
            };

            log::trace!("收到消息: {:?}", request.header.msg_type);

            // 检查是否为断开连接消息
            if request.header.msg_type == MessageType::Disconnect {
                log::info!("客户端请求断开");
                break;
            }

            // 路由到对应的处理器
            let response = self.route_message(&request);

            // 发送响应
            let response_data = response.encode();
            std::io::Write::write_all(&mut writer, &response_data).map_err(|e| {
                FridaError::Communication {
                    reason: format!("发送响应失败: {}", e),
                    source: Some(e),
                }
            })?;
            writer.flush().map_err(|e| FridaError::Communication {
                reason: format!("刷新输出失败: {}", e),
                source: Some(e),
            })?;
        }

        Ok(())
    }

    /// 路由消息到对应的处理函数
    fn route_message(&self, msg: &Message) -> Message {
        if let Some(handler) = self.handlers.get(&msg.header.msg_type) {
            match handler(msg) {
                Ok(response) => response,
                Err(e) => {
                    log::error!("消息处理错误: {}", e);
                    Message::error(&format!("处理失败: {}", e), msg.header.seq)
                }
            }
        } else {
            log::warn!("未注册的消息类型: {:?}", msg.header.msg_type);
            Message::error(
                &format!("未知消息类型: {:?}", msg.header.msg_type),
                msg.header.seq,
            )
        }
    }

    /// 注册默认的内置处理器
    fn register_default_handlers(&mut self) {
        // Ping-Pong 处理器
        self.register_handler(MessageType::Ping, |_msg: &Message| {
            Ok(Message::pong(_msg.header.seq))
        });

        log::debug!("已注册默认处理器");
    }

    /// 停止服务端
    pub fn stop(&mut self) {
        self.running = false;
        log::info!("通信服务端停止请求");
    }

    /// 获取 Socket 路径（供控制端连接使用）
    pub fn socket_path(&self) -> &str {
        &self.socket_path
    }
}

impl Default for CommServer {
    fn default() -> Self {
        Self::new(None)
    }
}

// ======================== Windows NamedPipe 实现 ========================

#[cfg(target_os = "windows")]
impl CommServer {
    /// 启动服务端，开始监听（Windows NamedPipe）
    ///
    /// 阻塞当前线程，接受连接并处理消息。
    pub fn start(&mut self) -> Result<(), FridaError> {
        use crate::communication::win_channel::NamedPipeServerChannel;

        self.running = true;

        log::info!(
            "通信服务端已启动 (Windows)，监听管道: {}",
            self.socket_path
        );

        // 注册默认处理器
        self.register_default_handlers();

        // 主循环：接受连接并处理消息
        while self.running {
            let channel = match NamedPipeServerChannel::new(&self.socket_path) {
                Ok(ch) => ch,
                Err(e) => {
                    log::warn!("创建命名管道失败: {}", e);
                    continue;
                }
            };

            if let Err(e) = channel.accept() {
                log::warn!("接受连接失败: {}", e);
                continue;
            }

            log::info!("新管道连接");

            // 处理客户端消息
            if let Err(e) = self.handle_client(&channel) {
                log::error!("处理客户端错误: {}", e);
            }

            channel.close();
        }

        log::info!("通信服务端已停止");
        Ok(())
    }

    /// 处理单个客户端连接（Windows NamedPipe）
    fn handle_client(
        &mut self,
        channel: &crate::communication::win_channel::NamedPipeServerChannel,
    ) -> Result<(), FridaError> {
        // 消息处理循环
        loop {
            // 读取消息头
            let mut header_buf = [0u8; crate::common::constants::MESSAGE_HEADER_SIZE];
            let mut total_read = 0usize;
            while total_read < header_buf.len() {
                match channel.recv(&mut header_buf[total_read..]) {
                    Ok(n) => {
                        if n == 0 {
                            log::info!("客户端断开连接");
                            return Ok(());
                        }
                        total_read += n;
                    }
                    Err(e) => {
                        return Err(FridaError::Communication {
                            reason: format!("读取消息头失败: {}", e),
                            source: None,
                        });
                    }
                }
            }

            // 解码消息
            let request = {
                let mut cursor = std::io::Cursor::new(header_buf);
                let header = crate::communication::protocol::MessageHeader::decode(&mut cursor)?;
                let mut payload = vec![0u8; header.length as usize];
                if header.length > 0 {
                    let mut total_read = 0usize;
                    while total_read < payload.len() {
                        match channel.recv(&mut payload[total_read..]) {
                            Ok(n) => {
                                if n == 0 {
                                    log::info!("客户端断开连接");
                                    return Ok(());
                                }
                                total_read += n;
                            }
                            Err(e) => {
                                return Err(FridaError::Communication {
                                    reason: format!("读取负载失败: {}", e),
                                    source: None,
                                });
                            }
                        }
                    }
                }
                Message { header, payload }
            };

            log::trace!("收到消息: {:?}", request.header.msg_type);

            // 检查是否为断开连接消息
            if request.header.msg_type == MessageType::Disconnect {
                log::info!("客户端请求断开");
                break;
            }

            // 路由到对应的处理器
            let response = self.route_message(&request);

            // 发送响应
            let response_data = response.encode();
            channel.send(&response_data)?;
        }

        Ok(())
    }
}

// ======================== 其他平台桩 ========================

#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "windows")))]
impl CommServer {
    pub fn start(&mut self) -> Result<(), FridaError> {
        Err(FridaError::Unsupported {
            reason: "通信服务端仅支持 Linux/Android/Windows".to_string(),
        }
        .into())
    }
}
