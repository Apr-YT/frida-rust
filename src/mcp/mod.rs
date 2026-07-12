//! MCP (Model Context Protocol) 服务器模块
//!
//! 将 frida-rust 的核心能力暴露为 MCP tools，
//! 让 AI 助手可以直接调用进程注入、Hook、内存操作、反检测等功能。

pub mod handler;

pub use handler::FridaMcpServer;
