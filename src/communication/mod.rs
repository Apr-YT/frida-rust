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
pub mod examples;

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
pub use kernel_channel::{KernelChannel, NovaCmd, NovaRequest, NovaResponse, IoctlChannel, NovaStatusRaw, NovaIoctlMemReq, NovaHwbpConfig, NovaHwbpInfo};
pub use protocol::{Message, MessageHeader, MessageType};
pub use server::CommServer;
pub use examples::{
    run_channel_demo, run_stdio_demo,
    create_message_example, parse_message_example, build_memory_read_request,
    build_hook_install_request, build_inject_request,
};
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use examples::{run_unix_socket_demo, run_encrypted_channel_demo};
