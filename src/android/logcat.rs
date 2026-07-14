//! Android logcat 日志模块
//!
//! 提供 logcat 日志捕获和过滤功能。

use crate::Result;
use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogLevel {
    Verbose,
    Debug,
    Info,
    Warn,
    Error,
    Assert,
}

impl From<char> for LogLevel {
    fn from(c: char) -> Self {
        match c {
            'V' | 'v' => LogLevel::Verbose,
            'D' | 'd' => LogLevel::Debug,
            'I' | 'i' => LogLevel::Info,
            'W' | 'w' => LogLevel::Warn,
            'E' | 'e' => LogLevel::Error,
            'A' | 'a' => LogLevel::Assert,
            _ => LogLevel::Info,
        }
    }
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self {
            LogLevel::Verbose => "V",
            LogLevel::Debug => "D",
            LogLevel::Info => "I",
            LogLevel::Warn => "W",
            LogLevel::Error => "E",
            LogLevel::Assert => "A",
        })
    }
}

#[derive(Debug, Clone)]
pub struct LogcatEntry {
    pub pid: u32,
    pub tid: u32,
    pub level: LogLevel,
    pub tag: String,
    pub message: String,
    pub time: String,
}

pub struct LogcatReader {
    running: Arc<Mutex<bool>>,
    output: Arc<Mutex<Vec<LogcatEntry>>>,
    handle: Option<thread::JoinHandle<()>>,
}

impl LogcatReader {
    pub fn new() -> Self {
        LogcatReader {
            running: Arc::new(Mutex::new(false)),
            output: Arc::new(Mutex::new(Vec::new())),
            handle: None,
        }
    }

    pub fn start(&mut self, tag_filter: Option<&str>, level_filter: Option<LogLevel>, pid_filter: Option<u32>) -> Result<()> {
        if *self.running.lock().unwrap() {
            return Ok(());
        }

        *self.running.lock().unwrap() = true;
        let running_clone = Arc::clone(&self.running);
        let output_clone = Arc::clone(&self.output);
        
        let tag = tag_filter.map(|s| s.to_string());
        let level = level_filter;
        let pid = pid_filter;

        self.handle = Some(thread::spawn(move || {
            let mut cmd = Command::new("logcat");
            
            if let Some(ref level) = level {
                cmd.arg(format!("-s"));
                cmd.arg(format!("*:{}", level));
            }
            
            if let Some(ref tag) = tag {
                cmd.arg(format!("{}:V", tag));
            }
            
            if let Some(pid) = pid {
                cmd.arg("--pid").arg(pid.to_string());
            }

            cmd.arg("-v").arg("brief");
            cmd.stdout(Stdio::piped());
            
            if let Ok(mut child) = cmd.spawn() {
                if let Ok(mut stdout) = child.stdout.take() {
                    let mut buf = String::new();
                    while *running_clone.lock().unwrap() {
                        let mut tmp = [0u8; 1024];
                        match stdout.read(&mut tmp) {
                            Ok(0) => break,
                            Ok(n) => {
                                buf.push_str(&String::from_utf8_lossy(&tmp[..n]));
                                while let Some(pos) = buf.find('\n') {
                                    let line = buf[..pos].to_string();
                                    buf.drain(..pos + 1);
                                    
                                    if let Ok(entry) = parse_logcat_line(&line) {
                                        let mut output = output_clone.lock().unwrap();
                                        output.push(entry);
                                        if output.len() > 10000 {
                                            output.drain(..5000);
                                        }
                                    }
                                }
                            }
                            Err(_) => break,
                        }
                    }
                }
                let _ = child.kill();
            }
        }));

        Ok(())
    }

    pub fn stop(&mut self) {
        *self.running.lock().unwrap() = false;
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }

    pub fn get_entries(&self) -> Vec<LogcatEntry> {
        self.output.lock().unwrap().clone()
    }

    pub fn get_entries_since(&self, count: usize) -> Vec<LogcatEntry> {
        let output = self.output.lock().unwrap();
        let start = output.len().saturating_sub(count);
        output[start..].to_vec()
    }

    pub fn clear(&self) {
        let _ = Command::new("logcat").arg("-c").output();
        self.output.lock().unwrap().clear();
    }

    pub fn get_last_n(&self, n: usize) -> Vec<LogcatEntry> {
        let output = self.output.lock().unwrap();
        let start = output.len().saturating_sub(n);
        output[start..].to_vec()
    }
}

impl Drop for LogcatReader {
    fn drop(&mut self) {
        self.stop();
    }
}

pub fn capture_logcat(tag_filter: Option<&str>, level_filter: Option<LogLevel>, pid_filter: Option<u32>, duration: Duration) -> Result<Vec<LogcatEntry>> {
    let mut reader = LogcatReader::new();
    reader.start(tag_filter, level_filter, pid_filter)?;
    
    thread::sleep(duration);
    
    let entries = reader.get_entries();
    reader.stop();
    
    Ok(entries)
}

fn parse_logcat_line(line: &str) -> Result<LogcatEntry> {
    let line = line.trim();
    if line.is_empty() {
        return Err(crate::FridaError::Other("空行".to_string()).into());
    }

    let parts: Vec<&str> = line.splitn(5, ' ').collect();
    
    if parts.len() < 5 {
        return Err(crate::FridaError::Other(format!("格式错误: {}", line)).into());
    }

    let time = parts[0].to_string();
    let level_char = parts[1].chars().next().unwrap_or('I');
    let tag = parts[2].to_string();
    let pid_tid = parts[3];
    let message = parts[4..].join(" ").trim().to_string();

    let pid_tid_parts: Vec<&str> = pid_tid.split('-').collect();
    let pid = pid_tid_parts[0].parse().unwrap_or(0);
    let tid = if pid_tid_parts.len() > 1 {
        pid_tid_parts[1].parse().unwrap_or(0)
    } else {
        pid
    };

    Ok(LogcatEntry {
        pid,
        tid,
        level: level_char.into(),
        tag,
        message,
        time,
    })
}

pub fn get_logcat_snapshot(tag_filter: Option<&str>, level_filter: Option<LogLevel>, pid_filter: Option<u32>) -> Result<Vec<LogcatEntry>> {
    let mut cmd = Command::new("logcat");
    
    if let Some(ref level) = level_filter {
        cmd.arg(format!("-s"));
        cmd.arg(format!("*:{}", level));
    }
    
    if let Some(ref tag) = tag_filter {
        cmd.arg(format!("{}:V", tag));
    }
    
    if let Some(pid) = pid_filter {
        cmd.arg("--pid").arg(pid.to_string());
    }

    cmd.arg("-v").arg("brief");
    cmd.arg("-d");

    let output = cmd.output()?;
    let output_str = String::from_utf8_lossy(&output.stdout);

    let mut entries = Vec::new();
    for line in output_str.lines() {
        if let Ok(entry) = parse_logcat_line(line) {
            entries.push(entry);
        }
    }

    Ok(entries)
}