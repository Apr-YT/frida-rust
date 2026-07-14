//! 通信模块
//!
//! 提供 frida-rust 控制端与注入 agent 之间的双向通信框架。
//! 支持多种传输通道和安全加密层。
//!
//! ## 架构
//! ```text
//! 控制端                          Agent 端
//!  |                               |
//!  +--- Channel (Unix Socket) ------+
//!  |     |                         |
//!  |     +--- Encryption Layer ---+ |
//!  |     |                         |
//!  |     +--- Protocol Layer ------+ |
//!  |
//!  +--- KernelChannel (Netlink) ---+
//!        |
//!        +--- nova_stealth.ko
//! ```

pub mod protocol;
pub mod channel;
pub mod server;

#[cfg(windows)]
pub mod win_channel;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod kernel_channel;

// 重新导出主要接口
pub use channel::{Channel, EncryptedChannel, StdioChannel, StdioChannelWrapper};
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use channel::{SharedMemChannel, UnixSocketChannel};
#[cfg(windows)]
pub use win_channel::{NamedPipeClientChannel, NamedPipeServerChannel};
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use kernel_channel::{KernelChannel, NovaCmd, NovaRequest, NovaResponse};
pub use protocol::{Message, MessageHeader, MessageType};
pub use server::CommServer;
