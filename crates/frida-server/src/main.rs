//! 设备端 frida-server 守护进程(Android)
//!
//! 运行在 Android 设备上(root),监听 Unix socket,通过长度前缀 JSON 帧
//! 与主机侧通信(adb forward 映射)。P0 提供:ping / process_list / package_list。
//!
//! 协议:4 字节小端长度 + JSON 负载。
//! 请求 {"type": "..."};响应 {"type": "...", ...};错误 {"type": "error", "error": "..."}。

#[cfg(unix)]
mod server {
    use std::io::{Read, Write};
    use std::os::unix::io::FromRawFd;
    use std::os::unix::net::{UnixListener, UnixStream};
    use serde_json::json;

    /// 抽象 socket 名称(与主机侧 adb forward localabstract:frida 对应)
    pub const SOCKET_NAME: &str = "frida";

    /// 绑定抽象命名空间 Unix socket(AF_UNIX, sun_path[0] = 0)
    ///
    /// 使用抽象 socket 而非文件系统路径,以绕开 Android SELinux 对
    /// /data/local/tmp 下 socket 文件的访问限制(adbd shell 域连接会被拦截)。
    fn bind_abstract(name: &str) -> std::io::Result<UnixListener> {
        let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let name_bytes = name.as_bytes();
        let name_len = std::cmp::min(name_bytes.len(), 107);
        unsafe {
            std::ptr::copy_nonoverlapping(
                name_bytes.as_ptr(),
                addr.sun_path.as_mut_ptr().add(1),
                name_len,
            );
        }
        let addr_len = (std::mem::offset_of!(libc::sockaddr_un, sun_path) + 1 + name_len)
            as libc::socklen_t;
        if unsafe { libc::bind(fd, &addr as *const _ as *const libc::sockaddr, addr_len) } != 0 {
            let e = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(e);
        }
        if unsafe { libc::listen(fd, 16) } != 0 {
            let e = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(e);
        }
        Ok(unsafe { UnixListener::from_raw_fd(fd) })
    }

    /// 启动守护进程:监听 socket,逐连接处理命令
    pub fn run() {
        let listener = match bind_abstract(SOCKET_NAME) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("frida-server: 绑定 abstract:{} 失败: {}", SOCKET_NAME, e);
                std::process::exit(1);
            }
        };
        eprintln!("frida-server: 监听 abstract:{} (pid={})", SOCKET_NAME, std::process::id());

        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    if let Err(e) = handle_client(stream) {
                        eprintln!("frida-server: 连接处理失败: {}", e);
                    }
                }
                Err(e) => eprintln!("frida-server: accept 失败: {}", e),
            }
        }
    }

    fn handle_client(mut stream: UnixStream) -> std::io::Result<()> {
        loop {
            let mut len_buf = [0u8; 4];
            if read_exact_or_eof(&mut stream, &mut len_buf)? {
                return Ok(()); // 客户端关闭连接
            }
            let len = u32::from_le_bytes(len_buf) as usize;
            if len == 0 || len > 16 * 1024 * 1024 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("非法帧长度: {}", len),
                ));
            }
            let mut payload = vec![0u8; len];
            stream.read_exact(&mut payload)?;
            let req: serde_json::Value = match serde_json::from_slice(&payload) {
                Ok(v) => v,
                Err(e) => {
                    write_frame(&mut stream, &json!({"type": "error", "error": format!("JSON 解析失败: {}", e)}))?;
                    continue;
                }
            };
            let resp = dispatch(&req);
            write_frame(&mut stream, &resp)?;
        }
    }

    fn read_exact_or_eof(stream: &mut UnixStream, buf: &mut [u8]) -> std::io::Result<bool> {
        let mut read = 0;
        while read < buf.len() {
            match stream.read(&mut buf[read..]) {
                Ok(0) => return Ok(true),
                Ok(n) => read += n,
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(false)
    }

    fn write_frame(stream: &mut UnixStream, resp: &serde_json::Value) -> std::io::Result<()> {
        let bytes = serde_json::to_vec(resp).unwrap_or_else(|_| b"{}".to_vec());
        let mut out = (bytes.len() as u32).to_le_bytes().to_vec();
        out.extend_from_slice(&bytes);
        stream.write_all(&out)
    }

    fn dispatch(req: &serde_json::Value) -> serde_json::Value {
        let cmd = req.get("type").and_then(|v| v.as_str()).unwrap_or("");
        match cmd {
            "ping" => json!({
                "type": "pong",
                "pid": std::process::id(),
                "arch": std::env::consts::ARCH,
                "version": env!("CARGO_PKG_VERSION"),
            }),
            "process_list" => json!({"type": "process_list", "processes": process_list()}),
            "package_list" => json!({"type": "package_list", "packages": package_list()}),
            _ => json!({"type": "error", "error": format!("未知命令: {}", cmd)}),
        }
    }

    fn process_list() -> Vec<serde_json::Value> {
        let mut out = Vec::new();
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let Some(name) = name.to_str() else { continue };
                let Ok(pid) = name.parse::<u32>() else { continue };
                let cmdline = std::fs::read(format!("/proc/{}/cmdline", pid))
                    .map(|b| String::from_utf8_lossy(&b).replace('\0', " ").trim().to_string())
                    .unwrap_or_default();
                out.push(json!({"pid": pid, "name": cmdline}));
            }
        }
        out.sort_by_key(|v| v["pid"].as_u64().unwrap_or(0));
        out
    }

    fn package_list() -> Vec<String> {
        match std::process::Command::new("pm")
            .args(["list", "packages", "-3"])
            .output()
        {
            Ok(o) => String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter_map(|l| l.trim().strip_prefix("package:"))
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            Err(_) => Vec::new(),
        }
    }
}

fn main() {
    #[cfg(unix)]
    {
        server::run();
    }
    #[cfg(not(unix))]
    {
        eprintln!("frida-server 仅支持 Android/Unix 目标平台");
        std::process::exit(1);
    }
}
