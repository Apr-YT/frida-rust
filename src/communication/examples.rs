use crate::communication::{
    channel::{Channel, StdioChannel},
    protocol::{Message, MessageType},
};
#[cfg(any(target_os = "linux", target_os = "android"))]
use crate::communication::{
    channel::{EncryptedChannel, UnixSocketChannel},
    CommServer,
};
#[cfg(any(target_os = "linux", target_os = "android"))]
use crate::FridaError;
use serde_json::json;
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::thread;
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::time::Duration;

pub fn run_channel_demo(socket_path: Option<&str>) -> crate::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        run_unix_socket_demo(socket_path)?;
    }
    #[cfg(windows)]
    {
        let _ = socket_path;
        run_stdio_demo()?;
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn run_unix_socket_demo(socket_path: Option<&str>) -> crate::Result<()> {
    let path: String = socket_path
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("/tmp/frida-rust-demo-{}.sock", std::process::id()));
    let server_path = path.clone();
    thread::spawn(move || {
        let mut server = CommServer::new(Some(server_path));
        
        server.register_handler(MessageType::Ping, |msg: &Message| {
            log::info!("服务端收到 Ping 消息, seq={}", msg.header.seq);
            Ok(Message::pong(msg.header.seq))
        });

        server.register_handler(MessageType::MemoryReadRequest, |msg: &Message| {
            log::info!("服务端收到内存读取请求, seq={}", msg.header.seq);
            
            let response_data = json!({
                "pid": 1234,
                "address": "0x7f1234567890",
                "data": "deadbeefcafebabe",
                "size": 16
            });
            
            let payload = serde_json::to_vec(&response_data).map_err(|e| {
                FridaError::Protocol {
                    reason: format!("序列化失败: {}", e),
                }
            })?;
            
            Ok(Message::new(MessageType::MemoryReadResponse, payload, msg.header.seq))
        });

        server.register_handler(MessageType::HookInstallRequest, |msg: &Message| {
            log::info!("服务端收到 Hook 安装请求, seq={}", msg.header.seq);
            
            let response_data = json!({
                "status": "success",
                "hook_id": 1,
                "symbol": "target_function"
            });
            
            let payload = serde_json::to_vec(&response_data).map_err(|e| {
                FridaError::Protocol {
                    reason: format!("序列化失败: {}", e),
                }
            })?;
            
            Ok(Message::new(MessageType::HookInstallResponse, payload, msg.header.seq))
        });

        if let Err(e) = server.start() {
            log::error!("服务端启动失败: {}", e);
        }
    });

    thread::sleep(Duration::from_millis(500));

    let mut client = UnixSocketChannel::connect(&path)?;
    log::info!("客户端已连接到 Unix Socket: {}", path);

    let mut seq: u32 = 0;

    seq += 1;
    let ping_msg = Message::ping(seq);
    client.send(&ping_msg)?;
    log::info!("客户端发送 Ping 消息, seq={}", seq);

    let pong_msg = client.recv()?;
    log::info!("客户端收到 Pong 消息, seq={}", pong_msg.header.seq);

    seq += 1;
    let read_request = json!({
        "pid": 1234,
        "address": "0x7f1234567890",
        "size": 16
    });
    let read_payload = serde_json::to_vec(&read_request)?;
    let read_msg = Message::new(MessageType::MemoryReadRequest, read_payload, seq);
    client.send(&read_msg)?;
    log::info!("客户端发送内存读取请求, seq={}", seq);

    let read_response = client.recv()?;
    if let Some(json_data) = read_response.payload_as_json() {
        log::info!("客户端收到内存读取响应: {}", json_data);
    }

    seq += 1;
    let hook_request = json!({
        "pid": 1234,
        "module": "libtarget.so",
        "symbol": "target_function",
        "hook_type": "inline"
    });
    let hook_payload = serde_json::to_vec(&hook_request)?;
    let hook_msg = Message::new(MessageType::HookInstallRequest, hook_payload, seq);
    client.send(&hook_msg)?;
    log::info!("客户端发送 Hook 安装请求, seq={}", seq);

    let hook_response = client.recv()?;
    if let Some(json_data) = hook_response.payload_as_json() {
        log::info!("客户端收到 Hook 安装响应: {}", json_data);
    }

    seq += 1;
    let disconnect_msg = Message::disconnect(seq);
    client.send(&disconnect_msg)?;
    log::info!("客户端发送断开连接消息");

    client.close()?;
    log::info!("Unix Socket 通道演示完成");

    Ok(())
}

pub fn run_stdio_demo() -> crate::Result<()> {
    let mut channel = StdioChannel::new();
    
    let mut seq: u32 = 0;

    seq += 1;
    let data = json!({
        "type": "process_info",
        "pid": 1234,
        "timestamp": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    });
    let payload = serde_json::to_vec(&data)?;
    let msg = Message::new(MessageType::Notification, payload, seq);
    
    channel.send(&msg)?;
    log::info!("Stdio 通道发送消息, seq={}", seq);

    Ok(())
}

pub fn run_encrypted_channel_demo() -> crate::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let path = format!("/tmp/frida-rust-encrypted-{}.sock", std::process::id());

        let key = EncryptedChannel::<UnixSocketChannel>::generate_key();
        log::info!("生成加密密钥: {:02x?}", key);

        let server_path = path.clone();
        let server_key = key;
        thread::spawn(move || {
            let mut server = CommServer::new(Some(server_path));
            
            server.register_handler(MessageType::Ping, |msg: &Message| {
                log::info!("加密通道服务端收到 Ping, seq={}", msg.header.seq);
                Ok(Message::pong(msg.header.seq))
            });

            if let Err(e) = server.start() {
                log::error!("加密通道服务端启动失败: {}", e);
            }
        });

        thread::sleep(Duration::from_millis(500));

        let inner = UnixSocketChannel::connect(&path).unwrap();
        let mut encrypted = EncryptedChannel::new(inner, server_key);

        let mut seq: u32 = 0;
        seq += 1;
        let ping_msg = Message::ping(seq);
        encrypted.send(&ping_msg)?;
        log::info!("加密通道发送 Ping");

        let response = encrypted.recv()?;
        log::info!("加密通道收到响应, type={:?}", response.header.msg_type);

        encrypted.close()?;
        log::info!("加密通道演示完成");
    }

    Ok(())
}

pub fn create_message_example() -> Message {
    let payload = b"Hello, Frida-Rust!".to_vec();
    Message::new(MessageType::Notification, payload, 1)
}

pub fn parse_message_example(msg: &Message) -> Option<serde_json::Value> {
    msg.payload_as_json()
}

pub fn build_memory_read_request(pid: u32, address: &str, size: usize) -> crate::Result<Message> {
    let data = json!({
        "pid": pid,
        "address": address,
        "size": size
    });
    let payload = serde_json::to_vec(&data)?;
    Ok(Message::new(MessageType::MemoryReadRequest, payload, 0))
}

pub fn build_hook_install_request(
    pid: u32,
    module: &str,
    symbol: &str,
    hook_type: &str,
) -> crate::Result<Message> {
    let data = json!({
        "pid": pid,
        "module": module,
        "symbol": symbol,
        "hook_type": hook_type
    });
    let payload = serde_json::to_vec(&data)?;
    Ok(Message::new(MessageType::HookInstallRequest, payload, 0))
}

pub fn build_inject_request(pid: u32, lib_path: &str) -> crate::Result<Message> {
    let data = json!({
        "pid": pid,
        "lib_path": lib_path,
        "flags": 1
    });
    let payload = serde_json::to_vec(&data)?;
    Ok(Message::new(MessageType::InjectRequest, payload, 0))
}