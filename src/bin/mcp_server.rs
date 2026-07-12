//! frida-rust MCP 服务器入口
//!
//! 通过 stdio 传输层运行 MCP 服务器，供 Codex 等 AI 助手调用。
//!
//! 使用方式:
//!   frida-rust-mcp
//!
//! 配置到 Codex MCP:
//!   在 .codex/config 中添加:
//!   {
//!     "mcpServers": {
//!       "frida-rust": {
//!         "command": "frida-rust-mcp",
//!         "args": []
//!       }
//!     }
//!   }

use frida_rust::mcp::FridaMcpServer;
use rmcp::{ServiceExt, transport::stdio};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 初始化日志 (输出到 stderr，不干扰 stdio 通信)
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Info)
        .target(env_logger::Target::Stderr)
        .init();

    log::info!("frida-rust MCP server 启动");

    let server = FridaMcpServer;

    // 使用 stdio 传输层，通过 stdin/stdout 与客户端通信
    let service = server.serve(stdio()).await?;

    // 等待服务结束
    service.waiting().await?;

    log::info!("frida-rust MCP server 已停止");
    Ok(())
}
