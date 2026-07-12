//! Windows 命名管道通信实现
//!
//! 使用 Windows NamedPipe 实现本地进程间通信。
//! 提供服务端和客户端两种角色，支持双向字节流传输。

use crate::FridaError;

use winapi::um::fileapi::{CreateFileW, ReadFile, WriteFile, OPEN_EXISTING};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::namedpipeapi::{ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe};
use winapi::um::winbase::{
    PIPE_ACCESS_DUPLEX, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use winapi::um::winnt::{FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ, GENERIC_WRITE};

/// NamedPipe 服务端通道
///
/// 创建命名管道并等待客户端连接，连接成功后可以进行读写操作。
pub struct NamedPipeServerChannel {
    handle: *mut winapi::ctypes::c_void,
}

/// NamedPipe 客户端通道
///
/// 连接到已存在的命名管道服务端。
pub struct NamedPipeClientChannel {
    handle: *mut winapi::ctypes::c_void,
}

/// 将 Rust 字符串转为 Windows 宽字符以 \0 结尾的 Vec<u16>
fn to_wide_string(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

impl NamedPipeServerChannel {
    /// 创建新的命名管道服务端
    ///
    /// # 参数
    /// - `pipe_name`: 管道名称（如 "\\.\pipe\frida-rust"）
    pub fn new(pipe_name: &str) -> Result<Self, FridaError> {
        let name_w = to_wide_string(pipe_name);

        let handle = unsafe {
            CreateNamedPipeW(
                name_w.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                65536,
                65536,
                0,
                std::ptr::null_mut(),
            )
        };

        if handle == INVALID_HANDLE_VALUE {
            return Err(FridaError::Communication {
                reason: format!("创建命名管道失败: {}", std::io::Error::last_os_error()),
                source: None,
            });
        }

        Ok(NamedPipeServerChannel { handle })
    }

    /// 等待客户端连接
    ///
    /// 阻塞当前线程直到有客户端连接到该命名管道。
    pub fn accept(&self) -> Result<(), FridaError> {
        let ret = unsafe { ConnectNamedPipe(self.handle, std::ptr::null_mut()) };
        if ret == 0 {
            let err = std::io::Error::last_os_error();
            // ERROR_PIPE_CONNECTED (535) 表示已经有客户端连接，不算错误
            if err.raw_os_error() != Some(535) {
                return Err(FridaError::Communication {
                    reason: format!("等待客户端连接失败: {}", err),
                    source: Some(err),
                });
            }
        }
        Ok(())
    }

    /// 发送原始数据
    ///
    /// # 参数
    /// - `data`: 要发送的字节数据
    pub fn send(&self, data: &[u8]) -> Result<(), FridaError> {
        let mut written = 0u32;
        let ret = unsafe {
            WriteFile(
                self.handle,
                data.as_ptr() as *const _,
                data.len() as u32,
                &mut written,
                std::ptr::null_mut(),
            )
        };
        if ret == 0 {
            return Err(FridaError::Communication {
                reason: format!("命名管道写入失败: {}", std::io::Error::last_os_error()),
                source: None,
            });
        }
        Ok(())
    }

    /// 接收原始数据
    ///
    /// # 参数
    /// - `buf`: 接收缓冲区
    ///
    /// # 返回值
    /// 实际读取到的字节数
    pub fn recv(&self, buf: &mut [u8]) -> Result<usize, FridaError> {
        let mut read = 0u32;
        let ret = unsafe {
            ReadFile(
                self.handle,
                buf.as_mut_ptr() as *mut _,
                buf.len() as u32,
                &mut read,
                std::ptr::null_mut(),
            )
        };
        if ret == 0 {
            return Err(FridaError::Communication {
                reason: format!("命名管道读取失败: {}", std::io::Error::last_os_error()),
                source: None,
            });
        }
        Ok(read as usize)
    }

    /// 关闭管道
    ///
    /// 断开与客户端的连接并关闭句柄。
    pub fn close(&self) {
        unsafe {
            let _ = DisconnectNamedPipe(self.handle);
            CloseHandle(self.handle);
        }
    }
}

impl Drop for NamedPipeServerChannel {
    fn drop(&mut self) {
        self.close();
    }
}

impl NamedPipeClientChannel {
    /// 连接到命名管道服务端
    ///
    /// # 参数
    /// - `pipe_name`: 管道名称（如 "\\.\pipe\frida-rust"）
    pub fn connect(pipe_name: &str) -> Result<Self, FridaError> {
        let name_w = to_wide_string(pipe_name);

        let handle = unsafe {
            CreateFileW(
                name_w.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };

        if handle == INVALID_HANDLE_VALUE {
            return Err(FridaError::Communication {
                reason: format!("连接命名管道失败: {}", std::io::Error::last_os_error()),
                source: None,
            });
        }

        Ok(NamedPipeClientChannel { handle })
    }

    /// 发送原始数据
    ///
    /// # 参数
    /// - `data`: 要发送的字节数据
    pub fn send(&self, data: &[u8]) -> Result<(), FridaError> {
        let mut written = 0u32;
        let ret = unsafe {
            WriteFile(
                self.handle,
                data.as_ptr() as *const _,
                data.len() as u32,
                &mut written,
                std::ptr::null_mut(),
            )
        };
        if ret == 0 {
            return Err(FridaError::Communication {
                reason: format!("命名管道写入失败: {}", std::io::Error::last_os_error()),
                source: None,
            });
        }
        Ok(())
    }

    /// 接收原始数据
    ///
    /// # 参数
    /// - `buf`: 接收缓冲区
    ///
    /// # 返回值
    /// 实际读取到的字节数
    pub fn recv(&self, buf: &mut [u8]) -> Result<usize, FridaError> {
        let mut read = 0u32;
        let ret = unsafe {
            ReadFile(
                self.handle,
                buf.as_mut_ptr() as *mut _,
                buf.len() as u32,
                &mut read,
                std::ptr::null_mut(),
            )
        };
        if ret == 0 {
            return Err(FridaError::Communication {
                reason: format!("命名管道读取失败: {}", std::io::Error::last_os_error()),
                source: None,
            });
        }
        Ok(read as usize)
    }

    /// 关闭管道
    pub fn close(&self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

impl Drop for NamedPipeClientChannel {
    fn drop(&mut self) {
        self.close();
    }
}
