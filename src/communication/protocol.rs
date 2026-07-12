//! 自定义二进制协议
//!
//! 定义 frida-rust 控制端与 agent 之间的消息格式。
//! 采用固定长度的消息头 + 变长负载的二进制协议，
//! 使用小端字节序（Little Endian）。

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use crate::common::constants::{
    MESSAGE_HEADER_SIZE, PROTOCOL_MAGIC, PROTOCOL_VERSION,
};
use crate::FridaError;
use std::io::Read;

// ======================== 消息头 ========================

/// 消息头（固定 20 字节）
///
/// ```text
/// | 字段       | 偏移 | 大小 | 说明                     |
/// |-----------|------|------|-------------------------|
/// | magic     | 0    | 4    | 魔数 (0xF1D40001)       |
/// | version   | 4    | 2    | 协议版本                  |
/// | msg_type  | 6    | 2    | 消息类型                  |
/// | length    | 8    | 4    | 负载长度（字节）          |
/// | seq       | 12   | 4    | 序列号（用于匹配请求/响应）|
/// | reserved  | 16   | 4    | 保留字段                  |
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageHeader {
    /// 协议魔数
    pub magic: u32,
    /// 协议版本
    pub version: u16,
    /// 消息类型
    pub msg_type: MessageType,
    /// 负载长度
    pub length: u32,
    /// 序列号
    pub seq: u32,
    /// 保留字段
    pub reserved: u32,
}

impl MessageHeader {
    /// 创建新的消息头
    pub fn new(msg_type: MessageType, length: u32, seq: u32) -> Self {
        MessageHeader {
            magic: PROTOCOL_MAGIC,
            version: PROTOCOL_VERSION,
            msg_type,
            length,
            seq,
            reserved: 0,
        }
    }

    /// 从字节流解码消息头
    ///
    /// # 错误
    /// 字节不足或魔数不匹配时返回错误
    pub fn decode<R: Read>(reader: &mut R) -> Result<Self, FridaError> {
        let magic = reader
            .read_u32::<LittleEndian>()
            .map_err(|e| FridaError::Protocol {
                reason: format!("读取魔数失败: {}", e),
            })?;

        // 验证魔数
        if magic != PROTOCOL_MAGIC {
            return Err(FridaError::Protocol {
                reason: format!(
                    "魔数不匹配: 期望 {:#x}, 实际 {:#x}",
                    PROTOCOL_MAGIC, magic
                ),
            });
        }

        let version = reader
            .read_u16::<LittleEndian>()
            .map_err(|e| FridaError::Protocol {
                reason: format!("读取版本号失败: {}", e),
            })?;

        // 验证版本
        if version != PROTOCOL_VERSION {
            log::warn!(
                "协议版本不匹配: 期望 {}, 实际 {}",
                PROTOCOL_VERSION,
                version
            );
        }

        let msg_type_raw = reader
            .read_u16::<LittleEndian>()
            .map_err(|e| FridaError::Protocol {
                reason: format!("读取消息类型失败: {}", e),
            })?;
        let msg_type = MessageType::from_u16(msg_type_raw);

        let length = reader
            .read_u32::<LittleEndian>()
            .map_err(|e| FridaError::Protocol {
                reason: format!("读取负载长度失败: {}", e),
            })?;

        let seq = reader
            .read_u32::<LittleEndian>()
            .map_err(|e| FridaError::Protocol {
                reason: format!("读取序列号失败: {}", e),
            })?;

        let reserved = reader
            .read_u32::<LittleEndian>()
            .map_err(|e| FridaError::Protocol {
                reason: format!("读取保留字段失败: {}", e),
            })?;

        Ok(MessageHeader {
            magic,
            version,
            msg_type,
            length,
            seq,
            reserved,
        })
    }

    /// 将消息头编码为字节
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(MESSAGE_HEADER_SIZE);
        buf.write_u32::<LittleEndian>(self.magic).unwrap();
        buf.write_u16::<LittleEndian>(self.version).unwrap();
        buf.write_u16::<LittleEndian>(self.msg_type.to_u16()).unwrap();
        buf.write_u32::<LittleEndian>(self.length).unwrap();
        buf.write_u32::<LittleEndian>(self.seq).unwrap();
        buf.write_u32::<LittleEndian>(self.reserved).unwrap();
        buf
    }
}

// ======================== 消息类型 ========================

/// 消息类型枚举
///
/// 定义控制端与 agent 之间所有可能的消息类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageType {
    // ========== 控制类消息 ==========
    /// 心跳请求（Ping）
    Ping,
    /// 心跳响应（Pong）
    Pong,

    // ========== 注入类消息 ==========
    /// 注入请求
    InjectRequest,
    /// 注入响应
    InjectResponse,

    // ========== Hook 类消息 ==========
    /// 安装 Hook 请求
    HookInstallRequest,
    /// 安装 Hook 响应
    HookInstallResponse,
    /// 卸载 Hook 请求
    HookUninstallRequest,
    /// 卸载 Hook 响应
    HookUninstallResponse,
    /// Hook 触发事件（agent -> 控制端）
    HookEvent,

    // ========== 内存类消息 ==========
    /// 内存读取请求
    MemoryReadRequest,
    /// 内存读取响应
    MemoryReadResponse,
    /// 内存写入请求
    MemoryWriteRequest,
    /// 内存写入响应
    MemoryWriteResponse,
    /// 内存搜索请求
    MemorySearchRequest,
    /// 内存搜索响应
    MemorySearchResponse,

    // ========== 脚本类消息 ==========
    /// 脚本执行请求
    ScriptExecRequest,
    /// 脚本执行响应
    ScriptExecResponse,
    /// 脚本日志输出（agent -> 控制端）
    ScriptLog,

    // ========== 反检测类消息 ==========
    /// 反检测配置请求
    AntiDetectRequest,
    /// 反检测响应
    AntiDetectResponse,

    // ========== 系统类消息 ==========
    /// 错误消息
    Error,
    /// 通知消息
    Notification,
    /// 断开连接
    Disconnect,
    /// 未知消息类型（用于向前兼容）
    Unknown(u16),
}

impl MessageType {
    /// 将消息类型转换为 u16
    pub fn to_u16(self) -> u16 {
        match self {
            MessageType::Ping => 0x0001,
            MessageType::Pong => 0x0002,
            MessageType::InjectRequest => 0x0101,
            MessageType::InjectResponse => 0x0102,
            MessageType::HookInstallRequest => 0x0201,
            MessageType::HookInstallResponse => 0x0202,
            MessageType::HookUninstallRequest => 0x0203,
            MessageType::HookUninstallResponse => 0x0204,
            MessageType::HookEvent => 0x0205,
            MessageType::MemoryReadRequest => 0x0301,
            MessageType::MemoryReadResponse => 0x0302,
            MessageType::MemoryWriteRequest => 0x0303,
            MessageType::MemoryWriteResponse => 0x0304,
            MessageType::MemorySearchRequest => 0x0305,
            MessageType::MemorySearchResponse => 0x0306,
            MessageType::ScriptExecRequest => 0x0401,
            MessageType::ScriptExecResponse => 0x0402,
            MessageType::ScriptLog => 0x0403,
            MessageType::AntiDetectRequest => 0x0501,
            MessageType::AntiDetectResponse => 0x0502,
            MessageType::Error => 0xFF01,
            MessageType::Notification => 0xFF02,
            MessageType::Disconnect => 0xFFFF,
            MessageType::Unknown(v) => v,
        }
    }

    /// 从 u16 转换为消息类型
    pub fn from_u16(val: u16) -> Self {
        match val {
            0x0001 => MessageType::Ping,
            0x0002 => MessageType::Pong,
            0x0101 => MessageType::InjectRequest,
            0x0102 => MessageType::InjectResponse,
            0x0201 => MessageType::HookInstallRequest,
            0x0202 => MessageType::HookInstallResponse,
            0x0203 => MessageType::HookUninstallRequest,
            0x0204 => MessageType::HookUninstallResponse,
            0x0205 => MessageType::HookEvent,
            0x0301 => MessageType::MemoryReadRequest,
            0x0302 => MessageType::MemoryReadResponse,
            0x0303 => MessageType::MemoryWriteRequest,
            0x0304 => MessageType::MemoryWriteResponse,
            0x0305 => MessageType::MemorySearchRequest,
            0x0306 => MessageType::MemorySearchResponse,
            0x0401 => MessageType::ScriptExecRequest,
            0x0402 => MessageType::ScriptExecResponse,
            0x0403 => MessageType::ScriptLog,
            0x0501 => MessageType::AntiDetectRequest,
            0x0502 => MessageType::AntiDetectResponse,
            0xFF01 => MessageType::Error,
            0xFF02 => MessageType::Notification,
            0xFFFF => MessageType::Disconnect,
            v => MessageType::Unknown(v),
        }
    }
}

// ======================== 完整消息 ========================

/// 完整的消息（头 + 负载）
#[derive(Debug, Clone)]
pub struct Message {
    /// 消息头
    pub header: MessageHeader,
    /// 消息负载（原始字节）
    pub payload: Vec<u8>,
}

impl Message {
    /// 创建新消息
    pub fn new(msg_type: MessageType, payload: Vec<u8>, seq: u32) -> Self {
        let length = payload.len() as u32;
        let header = MessageHeader::new(msg_type, length, seq);
        Message { header, payload }
    }

    /// 创建无负载的消息
    pub fn empty(msg_type: MessageType, seq: u32) -> Self {
        Self::new(msg_type, Vec::new(), seq)
    }

    /// 创建 Ping 消息
    pub fn ping(seq: u32) -> Self {
        Self::empty(MessageType::Ping, seq)
    }

    /// 创建 Pong 消息
    pub fn pong(seq: u32) -> Self {
        Self::empty(MessageType::Pong, seq)
    }

    /// 创建错误消息
    pub fn error(error_msg: &str, seq: u32) -> Self {
        Self::new(MessageType::Error, error_msg.as_bytes().to_vec(), seq)
    }

    /// 创建断开连接消息
    pub fn disconnect(seq: u32) -> Self {
        Self::empty(MessageType::Disconnect, seq)
    }

    /// 将消息序列化为字节
    ///
    /// 格式: [消息头 (20 字节)] + [负载 (N 字节)]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = self.header.encode();
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// 从字节流解码消息
    ///
    /// # 错误
    /// 字节不足、魔数不匹配或负载长度不一致时返回错误
    pub fn decode<R: Read>(reader: &mut R) -> Result<Self, FridaError> {
        // 解码消息头
        let header = MessageHeader::decode(reader)?;

        // 读取负载
        let mut payload = vec![0u8; header.length as usize];
        if header.length > 0 {
            reader
                .read_exact(&mut payload)
                .map_err(|e| FridaError::Protocol {
                    reason: format!("读取负载失败 (预期 {} 字节): {}", header.length, e),
                })?;
        }

        Ok(Message { header, payload })
    }

    /// 将负载解析为字符串
    pub fn payload_as_string(&self) -> Option<String> {
        String::from_utf8(self.payload.clone()).ok()
    }

    /// 将负载解析为 JSON 值
    pub fn payload_as_json(&self) -> Option<serde_json::Value> {
        serde_json::from_slice(&self.payload).ok()
    }
}

// ======================== 序列化/反序列化 Trait ========================

/// 可序列化为协议消息负载的 trait
pub trait ProtocolSerialize: Sized {
    /// 序列化为字节向量
    fn to_payload(&self) -> Result<Vec<u8>, FridaError>;

    /// 从字节向量反序列化
    fn from_payload(data: &[u8]) -> Result<Self, FridaError>;
}

/// 为 String 类型实现协议序列化
impl ProtocolSerialize for String {
    fn to_payload(&self) -> Result<Vec<u8>, FridaError> {
        Ok(self.as_bytes().to_vec())
    }

    fn from_payload(data: &[u8]) -> Result<Self, FridaError> {
        String::from_utf8(data.to_vec()).map_err(|e| FridaError::Protocol {
            reason: format!("字符串解码失败: {}", e),
        })
    }
}

/// 为 JSON Value 实现协议序列化
impl ProtocolSerialize for serde_json::Value {
    fn to_payload(&self) -> Result<Vec<u8>, FridaError> {
        serde_json::to_vec(self).map_err(|e| FridaError::Protocol {
            reason: format!("JSON 序列化失败: {}", e),
        })
    }

    fn from_payload(data: &[u8]) -> Result<Self, FridaError> {
        serde_json::from_slice(data).map_err(|e| FridaError::Protocol {
            reason: format!("JSON 反序列化失败: {}", e),
        })
    }
}

// ======================== 测试 ========================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_message_header_encode_decode() {
        let header = MessageHeader::new(MessageType::Ping, 0, 42);
        let encoded = header.encode();
        assert_eq!(encoded.len(), MESSAGE_HEADER_SIZE);

        let mut cursor = Cursor::new(encoded);
        let decoded = MessageHeader::decode(&mut cursor).unwrap();
        assert_eq!(decoded.magic, PROTOCOL_MAGIC);
        assert_eq!(decoded.version, PROTOCOL_VERSION);
        assert_eq!(decoded.msg_type, MessageType::Ping);
        assert_eq!(decoded.length, 0);
        assert_eq!(decoded.seq, 42);
    }

    #[test]
    fn test_message_roundtrip() {
        let msg = Message::new(
            MessageType::HookInstallRequest,
            b"test_payload".to_vec(),
            1,
        );
        let encoded = msg.encode();

        let mut cursor = Cursor::new(encoded);
        let decoded = Message::decode(&mut cursor).unwrap();

        assert_eq!(decoded.header.msg_type, MessageType::HookInstallRequest);
        assert_eq!(decoded.header.seq, 1);
        assert_eq!(decoded.payload, b"test_payload");
    }

    #[test]
    fn test_message_type_conversion() {
        assert_eq!(MessageType::Ping.to_u16(), 0x0001);
        assert_eq!(MessageType::from_u16(0x0001), MessageType::Ping);
        assert_eq!(MessageType::from_u16(0x9999), MessageType::Unknown(0x9999));
    }

    #[test]
    fn test_invalid_magic() {
        let mut data = vec![0u8; MESSAGE_HEADER_SIZE];
        // 写入无效魔数
        data[0..4].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());

        let mut cursor = Cursor::new(data);
        let result = MessageHeader::decode(&mut cursor);
        assert!(result.is_err());
    }
}
