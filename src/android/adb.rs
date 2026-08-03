//! 主机侧 adb 封装
//!
//! 纯主机侧工具:通过 adb 命令行与 Android 设备交互,不依赖设备端组件。
//! 主机可以是 Windows / Linux / macOS,只要 PATH 上有 adb
//! (或通过 ADB 环境变量指定 adb 可执行文件路径)。

use crate::Result;

/// 已连接的 adb 设备(adb devices -l 解析结果)
#[derive(Debug, Clone)]
pub struct AdbDevice {
    pub serial: String,
    pub state: String,
    pub product: String,
    pub model: String,
    pub device: String,
    pub transport_id: u32,
}

impl AdbDevice {
    /// 展示名:优先型号,回退序列号
    pub fn display_name(&self) -> String {
        if !self.model.is_empty() {
            self.model.clone()
        } else {
            self.serial.clone()
        }
    }

    /// 是否处于可用状态(device)
    pub fn is_online(&self) -> bool {
        self.state == "device"
    }
}

/// adb 可执行文件路径(ADB 环境变量可覆盖)
pub fn adb_bin() -> String {
    std::env::var("ADB").unwrap_or_else(|_| "adb".to_string())
}

/// 执行 adb 命令,返回 stdout(失败返回错误)
pub fn run(args: &[&str]) -> Result<String> {
    let out = std::process::Command::new(adb_bin()).args(args).output()?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(anyhow::anyhow!("adb {} 失败: {}", args.join(" "), err.trim()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// 解析 `adb devices -l` 输出(纯函数,便于测试)
pub fn parse_devices_output(out: &str) -> Vec<AdbDevice> {
    let mut devices = Vec::new();
    for line in out.lines().skip(1) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut it = line.split_whitespace();
        let (Some(serial), Some(state)) = (it.next(), it.next()) else {
            continue;
        };
        let mut dev = AdbDevice {
            serial: serial.to_string(),
            state: state.to_string(),
            product: String::new(),
            model: String::new(),
            device: String::new(),
            transport_id: 0,
        };
        for kv in it {
            if let Some((k, v)) = kv.split_once(':') {
                match k {
                    "product" => dev.product = v.to_string(),
                    "model" => dev.model = v.to_string(),
                    "device" => dev.device = v.to_string(),
                    "transport_id" => dev.transport_id = v.parse().unwrap_or(0),
                    _ => {}
                }
            }
        }
        devices.push(dev);
    }
    devices
}

/// 列出已连接设备
pub fn list_devices() -> Result<Vec<AdbDevice>> {
    let out = run(&["devices", "-l"])?;
    Ok(parse_devices_output(&out))
}

/// 选择第一台在线设备
pub fn first_online() -> Result<AdbDevice> {
    list_devices()?
        .into_iter()
        .find(|d| d.is_online())
        .ok_or_else(|| anyhow::anyhow!("未找到在线 adb 设备(请检查 USB 调试连接)"))
}

/// 在指定设备上执行 shell 命令,返回 stdout
pub fn shell(serial: &str, cmd: &str) -> Result<String> {
    run(&["-s", serial, "shell", cmd])
}

/// 以 root 执行命令(需要已 root 设备)
pub fn shell_su(serial: &str, cmd: &str) -> Result<String> {
    shell(serial, &format!("su -c \"{}\"", cmd.replace('"', "\\\"")))
}

/// 查询设备属性
pub fn getprop(serial: &str, key: &str) -> Result<String> {
    Ok(shell(serial, &format!("getprop {}", key))?.trim().to_string())
}

/// 推送本地文件到设备
pub fn push(serial: &str, local: &str, remote: &str) -> Result<()> {
    run(&["-s", serial, "push", local, remote])?;
    Ok(())
}

/// 建立端口转发:本地 tcp 端口 -> 设备端 socket 地址
/// remote 形如 "localabstract:frida" / "tcp:27042" / "localfilesystem:/data/.../x.sock"
pub fn forward(serial: &str, local_port: u16, remote: &str) -> Result<()> {
    run(&[
        "-s",
        serial,
        "forward",
        &format!("tcp:{}", local_port),
        remote,
    ])?;
    Ok(())
}

/// 移除指定转发
pub fn forward_remove(serial: &str, local_port: u16) -> Result<()> {
    run(&["-s", serial, "forward", "--remove", &format!("tcp:{}", local_port)])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_devices_output() {
        let out = "List of devices attached\n134d2f8\tdevice product:myron model:25102RKBEC device:myron transport_id:23\n\n";
        let devices = parse_devices_output(out);
        assert_eq!(devices.len(), 1);
        let d = &devices[0];
        assert_eq!(d.serial, "134d2f8");
        assert_eq!(d.state, "device");
        assert_eq!(d.model, "25102RKBEC");
        assert_eq!(d.product, "myron");
        assert_eq!(d.transport_id, 23);
        assert!(d.is_online());
        assert_eq!(d.display_name(), "25102RKBEC");
    }

    #[test]
    fn test_parse_devices_empty_and_offline() {
        assert!(parse_devices_output("List of devices attached\n").is_empty());

        let out = "List of devices attached\na1b2c3\toffline\n";
        let devices = parse_devices_output(out);
        assert_eq!(devices.len(), 1);
        assert!(!devices[0].is_online());
    }
}
