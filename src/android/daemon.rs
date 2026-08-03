//! 设备端 frida-server 守护进程通信(主机侧客户端)
//!
//! 通过 adb forward 连接设备端 Unix socket,使用长度前缀 JSON 帧通信。
//! P0 提供 ping 验证;后续注入/hook/脚本命令在此扩展。

use crate::Result;
use std::io::{Read, Write};
use std::net::TcpStream;

/// 设备端守护进程 socket(经 adb forward 映射)
pub const DAEMON_SOCKET: &str = "localabstract:frida";

/// 向设备端守护进程发送 ping,返回响应 JSON(自动建/拆 adb forward)
pub fn ping(serial: &str, local_port: u16) -> Result<serde_json::Value> {
    super::adb::forward(serial, local_port, DAEMON_SOCKET)?;
    let r = request(local_port, &serde_json::json!({ "type": "ping" }));
    let _ = super::adb::forward_remove(serial, local_port);
    r
}

/// 向设备端守护进程发送任意命令
pub fn request(port: u16, req: &serde_json::Value) -> Result<serde_json::Value> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    let body = serde_json::to_vec(req)?;
    let mut frame = (body.len() as u32).to_le_bytes().to_vec();
    frame.extend_from_slice(&body);
    stream.write_all(&frame)?;
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > 16 * 1024 * 1024 {
        return Err(anyhow::anyhow!("守护进程返回非法帧长度: {}", len));
    }
    let mut resp = vec![0u8; len];
    stream.read_exact(&mut resp)?;
    Ok(serde_json::from_slice(&resp)?)
}
