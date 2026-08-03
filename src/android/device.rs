//! 主机侧设备客户端(P0:adb 直连模式)
//!
//! P0 阶段进程/包列表/日志直接通过 adb shell 获取,不依赖设备端组件;
//! 注入/hook 能力将通过 adb forward + 设备端 frida-server 守护进程提供。

use crate::Result;
use super::adb;

/// 设备基本信息
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub serial: String,
    pub model: String,
    pub android_version: String,
    pub api_level: String,
    pub abi: String,
    pub root: bool,
}

/// 设备进程(ps -A -o PID,PPID,ARGS)
#[derive(Debug, Clone)]
pub struct DeviceProcess {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
}

/// 目标设备客户端
#[derive(Debug, Clone)]
pub struct DeviceClient {
    pub serial: String,
}

impl DeviceClient {
    /// 指定序列号
    pub fn new(serial: impl Into<String>) -> Self {
        DeviceClient { serial: serial.into() }
    }

    /// 自动选择第一台在线设备
    pub fn auto() -> Result<Self> {
        Ok(Self::new(adb::first_online()?.serial))
    }

    /// 设备信息(型号/系统版本/ABI/root)
    pub fn info(&self) -> Result<DeviceInfo> {
        let model = adb::getprop(&self.serial, "ro.product.model").unwrap_or_default();
        let android_version =
            adb::getprop(&self.serial, "ro.build.version.release").unwrap_or_default();
        let api_level = adb::getprop(&self.serial, "ro.build.version.sdk").unwrap_or_default();
        let abi = adb::getprop(&self.serial, "ro.product.cpu.abi").unwrap_or_default();
        let root = adb::shell_su(&self.serial, "id")
            .map(|o| o.contains("uid=0"))
            .unwrap_or(false);
        Ok(DeviceInfo {
            serial: self.serial.clone(),
            model,
            android_version,
            api_level,
            abi,
            root,
        })
    }

    /// 进程列表
    pub fn process_list(&self) -> Result<Vec<DeviceProcess>> {
        let out = adb::shell(&self.serial, "ps -A -o PID,PPID,ARGS")?;
        Ok(parse_process_output(&out))
    }

    /// 按包名/进程名查找 PID
    pub fn find_pid(&self, name: &str) -> Result<Vec<u32>> {
        let procs = self.process_list()?;
        Ok(procs
            .iter()
            .filter(|p| p.name.contains(name))
            .map(|p| p.pid)
            .collect())
    }

    /// 已安装的第三方包列表(pm list packages -3)
    pub fn package_list(&self) -> Result<Vec<String>> {
        let out = adb::shell(&self.serial, "pm list packages -3")?;
        Ok(parse_package_output(&out))
    }

    /// logcat 快照(可选 tag/level/pid 过滤)
    pub fn logcat_snapshot(
        &self,
        tag: Option<&str>,
        level: Option<&str>,
        pid: Option<u32>,
    ) -> Result<Vec<String>> {
        let mut cmd = String::from("logcat -d -t 200");
        if let Some(pid) = pid {
            cmd.push_str(&format!(" --pid={}", pid));
        }
        if let Some(tag) = tag {
            cmd.push_str(&format!(" -s {}:{}", tag, level.unwrap_or("I")));
        }
        let out = adb::shell(&self.serial, &cmd)?;
        Ok(out.lines().map(|l| l.to_string()).collect())
    }
}

/// 解析 ps 输出(纯函数,便于测试)
pub fn parse_process_output(out: &str) -> Vec<DeviceProcess> {
    let mut list = Vec::new();
    for line in out.lines().skip(1) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut it = line.split_whitespace();
        let (Some(pid), Some(ppid)) = (it.next(), it.next()) else {
            continue;
        };
        let name = it.collect::<Vec<_>>().join(" ");
        if name.is_empty() {
            continue;
        }
        let Ok(pid) = pid.parse::<u32>() else { continue };
        let Ok(ppid) = ppid.parse::<u32>() else { continue };
        list.push(DeviceProcess { pid, ppid, name });
    }
    list
}

/// 解析 pm list packages 输出
pub fn parse_package_output(out: &str) -> Vec<String> {
    out.lines()
        .filter_map(|l| l.trim().strip_prefix("package:"))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_process_output() {
        let out = "  PID  PPID ARGS\n    1     0 init second_stage\n  123   456 com.example.app\n";
        let list = parse_process_output(out);
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].pid, 1);
        assert_eq!(list[0].ppid, 0);
        assert_eq!(list[0].name, "init second_stage");
        assert_eq!(list[1].pid, 123);
        assert_eq!(list[1].ppid, 456);
        assert_eq!(list[1].name, "com.example.app");
    }

    #[test]
    fn test_parse_process_output_ignores_header_and_empty() {
        assert!(parse_process_output("  PID  PPID ARGS\n").is_empty());
        let out = "  PID  PPID ARGS\n\n  1 0 \n";
        assert!(parse_process_output(out).is_empty());
    }

    #[test]
    fn test_parse_package_output() {
        let out = "package:com.tencent.mm\npackage:com.qq.reader\n\n";
        let pkgs = parse_package_output(out);
        assert_eq!(pkgs, vec!["com.tencent.mm", "com.qq.reader"]);
        assert!(parse_package_output("").is_empty());
    }
}
