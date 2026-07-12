//! 内存操作模块
//!
//! 提供跨进程内存读写、内存搜索、内存保护属性修改等功能。
//!
//! 子模块：
//! - **scanner**: 内存扫描器 - 在进程内存中搜索字节模式和字符串
//! - **allocator**: 远程内存分配器 - 在目标进程中分配和释放内存
//! - **elf_parser**: ELF 解析器 - 解析 ELF 文件的段、节、符号表等

#[cfg(unix)]
pub mod scanner;
#[cfg(unix)]
pub mod allocator;
pub mod elf_parser;

#[cfg(windows)]
pub mod win_allocator;
#[cfg(windows)]
pub mod win_scanner;

// 重新导出主要接口
#[cfg(unix)]
pub use scanner::MemoryScanner;
#[cfg(unix)]
pub use allocator::RemoteAllocator;
pub use elf_parser::{ElfInfo, SectionInfo, SymbolEntry, parse_elf, find_symbol, find_section};

#[cfg(windows)]
pub use win_allocator::WinRemoteAllocator;
#[cfg(windows)]
pub use win_scanner::WinMemoryScanner;
