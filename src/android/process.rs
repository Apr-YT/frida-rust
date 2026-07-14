//! Android 进程管理模块
//!
//! 提供按包名查找进程、列出运行中的 APK、获取 SELinux 上下文等功能。

use crate::common::types::ProcessId;
use crate::Result;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct AndroidProcessInfo {
    pub pid: ProcessId,
    pub package_name: String,
    pub process_name: String,
    pub uid: u32,
    pub selinux_context: String,
    pub cmdline: String,
}

#[derive(Debug, Clone)]
pub struct AndroidPackageInfo {
    pub package_name: String,
    pub app_name: String,
    pub version_name: String,
    pub version_code: String,
    pub apk_path: String,
    pub uid: u32,
    pub installed: bool,
}

pub fn get_pid_by_package(package_name: &str) -> Result<Vec<ProcessId>> {
    let mut result = Vec::new();
    let proc_dir = std::fs::read_dir("/proc")?;

    for entry in proc_dir {
        let entry = entry?;
        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();

        if let Ok(pid_num) = name_str.parse::<u32>() {
            if pid_num == 0 {
                continue;
            }

            let cmdline_path = format!("/proc/{}/cmdline", pid_num);
            if let Ok(cmdline_bytes) = std::fs::read(&cmdline_path) {
                let cmdline = String::from_utf8_lossy(&cmdline_bytes);
                let cmdline = cmdline.replace('\0', " ");

                if cmdline.contains(package_name) {
                    result.push(ProcessId(pid_num));
                }
            }
        }
    }

    Ok(result)
}

pub fn list_running_packages() -> Result<Vec<AndroidProcessInfo>> {
    let mut result = Vec::new();
    let proc_dir = std::fs::read_dir("/proc")?;

    for entry in proc_dir {
        let entry = entry?;
        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();

        if let Ok(pid_num) = name_str.parse::<u32>() {
            if pid_num == 0 {
                continue;
            }

            let pid = ProcessId(pid_num);
            if let Ok(info) = get_process_info(pid) {
                if !info.package_name.is_empty() && info.package_name != "system" {
                    result.push(info);
                }
            }
        }
    }

    result.sort_by(|a, b| a.package_name.cmp(&b.package_name));
    Ok(result)
}

pub fn get_process_info(pid: ProcessId) -> Result<AndroidProcessInfo> {
    let cmdline_path = format!("/proc/{}/cmdline", pid.0);
    let cmdline_bytes = std::fs::read(&cmdline_path)?;
    let cmdline = String::from_utf8_lossy(&cmdline_bytes).replace('\0', " ");

    let status_path = format!("/proc/{}/status", pid.0);
    let status_content = std::fs::read_to_string(&status_path)?;

    let mut uid: u32 = 0;
    let mut process_name = String::new();

    for line in status_content.lines() {
        if line.starts_with("Uid:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                uid = parts[1].parse().unwrap_or(0);
            }
        }
        if line.starts_with("Name:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                process_name = parts[1].to_string();
            }
        }
    }

    let selinux_context = get_selinux_context(pid)?;

    let package_name = extract_package_name(&cmdline, &process_name);

    Ok(AndroidProcessInfo {
        pid,
        package_name,
        process_name,
        uid,
        selinux_context,
        cmdline: cmdline.trim().to_string(),
    })
}

pub fn get_selinux_context(pid: ProcessId) -> Result<String> {
    let attr_path = format!("/proc/{}/attr/current", pid.0);
    if let Ok(content) = std::fs::read_to_string(&attr_path) {
        return Ok(content.trim().to_string());
    }

    Ok("unknown".to_string())
}

pub fn list_installed_packages() -> Result<Vec<AndroidPackageInfo>> {
    let mut result = Vec::new();
    let pm_output = std::process::Command::new("pm")
        .arg("list")
        .arg("packages")
        .arg("-f")
        .output()?;

    let output = String::from_utf8_lossy(&pm_output.stdout);
    for line in output.lines() {
        if let Some(info) = parse_pm_package_line(line) {
            result.push(info);
        }
    }

    result.sort_by(|a, b| a.package_name.cmp(&b.package_name));
    Ok(result)
}

fn extract_package_name(cmdline: &str, process_name: &str) -> String {
    let parts: Vec<&str> = cmdline.split_whitespace().collect();
    
    for part in parts {
        if part.starts_with("--") {
            continue;
        }
        
        if part.contains('/') {
            let path_parts: Vec<&str> = part.split('/').collect();
            if let Some(last) = path_parts.last() {
                if last.starts_with("lib") || last.contains(".so") {
                    continue;
                }
            }
            
            if let Some(idx) = part.find("=") {
                let candidate = &part[idx + 1..];
                if is_valid_package_name(candidate) {
                    return candidate.to_string();
                }
            }
            
            let file_name = std::path::Path::new(part).file_name().and_then(|s| s.to_str());
            if let Some(name) = file_name {
                if is_valid_package_name(name) {
                    return name.to_string();
                }
            }
        } else {
            if is_valid_package_name(part) {
                return part.to_string();
            }
        }
    }

    if is_valid_package_name(process_name) {
        return process_name.to_string();
    }

    String::new()
}

fn is_valid_package_name(name: &str) -> bool {
    if name.is_empty() || name.len() < 5 {
        return false;
    }
    if name.starts_with('.') || name.ends_with('.') {
        return false;
    }
    if name.contains("..") {
        return false;
    }
    
    let parts: Vec<&str> = name.split('.').collect();
    parts.len() >= 2 && parts.iter().all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
}

fn parse_pm_package_line(line: &str) -> Option<AndroidPackageInfo> {
    let line = line.trim_start_matches("package:");
    let parts: Vec<&str> = line.split("=").collect();
    
    if parts.len() != 2 {
        return None;
    }
    
    let apk_path = parts[0].trim();
    let package_name = parts[1].trim();
    
    let pm_dump = std::process::Command::new("pm")
        .arg("dump")
        .arg(package_name)
        .output()
        .ok()?;
    
    let dump_output = String::from_utf8_lossy(&pm_dump.stdout);
    
    let mut app_name = String::new();
    let mut version_name = String::new();
    let mut version_code = String::new();
    let mut uid: u32 = 0;
    
    for dump_line in dump_output.lines() {
        if dump_line.contains("Application Label:") {
            app_name = dump_line.split(":").nth(1).unwrap_or("").trim().to_string();
        }
        if dump_line.contains("versionName=") {
            version_name = dump_line.split("=").nth(1).unwrap_or("").trim().to_string();
        }
        if dump_line.contains("versionCode=") {
            version_code = dump_line.split("=").nth(1).unwrap_or("").trim().to_string();
        }
        if dump_line.contains("userId=") {
            uid = dump_line.split("=").nth(1).unwrap_or("0").trim().parse().unwrap_or(0);
        }
    }
    
    if app_name.is_empty() {
        app_name = package_name.split('.').last().unwrap_or(package_name).to_string();
    }
    
    Some(AndroidPackageInfo {
        package_name: package_name.to_string(),
        app_name,
        version_name,
        version_code,
        apk_path: apk_path.to_string(),
        uid,
        installed: true,
    })
}