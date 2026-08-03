//! 内核级内存扫描器（感知层）
//!
//! 通过内核驱动（Netlink/Ioctl通道）直接读取目标进程内存，
//! 绕过用户态检测，实现隐蔽的内存访问。
//!
//! 核心能力：
//! - 内核级进程内存读取（绕过 ptrace 检测）
//! - 消息结构识别与提取（支持多种协议格式）
//! - 内存快照对比与变更检测
//! - 智能数据过滤（只提取有意义的内容）

use crate::communication::kernel_channel::{KernelChannel, IoctlChannel};
use crate::common::types::{MemoryRegion, ProcessId};
use crate::Result;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

// ======================== 消息格式识别 ========================

/// 消息类型枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MessageFormat {
    Json,
    ProtoBuf,
    Binary,
    String,
    Unknown,
}

/// 消息结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedMessage {
    pub addr: u64,
    pub pid: u32,
    pub format: MessageFormat,
    pub content: String,
    pub timestamp: u64,
    pub confidence: f64,
    pub tags: Vec<String>,
}

/// 内存快照
#[derive(Debug, Clone)]
pub struct MemorySnapshot {
    pub pid: u32,
    pub timestamp: u64,
    pub regions: Vec<MemoryRegion>,
    pub content_hashes: HashMap<u64, u64>,
}

// ======================== 内核级内存扫描器 ========================

pub struct KernelMemoryScanner {
    pid: ProcessId,
    kernel_channel: Option<KernelChannel>,
    ioctl_channel: Option<IoctlChannel>,
    use_kernel_mode: bool,
    last_snapshot: Option<MemorySnapshot>,
    message_buffer: Vec<DetectedMessage>,
}

impl KernelMemoryScanner {
    /// 创建新的内核内存扫描器
    pub fn new(pid: ProcessId) -> Self {
        KernelMemoryScanner {
            pid,
            kernel_channel: None,
            ioctl_channel: None,
            use_kernel_mode: false,
            last_snapshot: None,
            message_buffer: Vec::new(),
        }
    }

    /// 初始化内核通道（优先 Netlink，失败回退 Ioctl）
    pub fn init_kernel_channel(&mut self) -> Result<bool> {
        match KernelChannel::new() {
            Ok(mut channel) => {
                match channel.ping() {
                    Ok(_) => {
                        log::info!("Netlink 内核通道已连接");
                        self.kernel_channel = Some(channel);
                        self.use_kernel_mode = true;
                        return Ok(true);
                    }
                    Err(e) => {
                        log::warn!("Netlink 通道不可用: {}", e);
                    }
                }
            }
            Err(e) => {
                log::warn!("创建 Netlink 通道失败: {}", e);
            }
        }

        match IoctlChannel::new() {
            Ok(channel) => {
                match channel.ping() {
                    Ok(_) => {
                        log::info!("Ioctl 内核通道已连接");
                        self.ioctl_channel = Some(channel);
                        self.use_kernel_mode = true;
                        return Ok(true);
                    }
                    Err(e) => {
                        log::warn!("Ioctl 通道不可用: {}", e);
                    }
                }
            }
            Err(e) => {
                log::warn!("创建 Ioctl 通道失败: {}", e);
            }
        }

        log::warn!("内核通道不可用，回退到用户态模式");
        Ok(false)
    }

    /// 检查是否启用内核模式
    pub fn is_kernel_mode(&self) -> bool {
        self.use_kernel_mode
    }

    /// 通过内核通道读取内存
    pub fn read_memory_kernel(&self, addr: u64, size: usize) -> Result<Vec<u8>> {
        if let Some(channel) = &self.kernel_channel {
            return channel.read_mem(self.pid.0 as i32, addr as usize, size).map_err(|e| anyhow::anyhow!("{}", e));
        }
        if let Some(channel) = &self.ioctl_channel {
            return channel.read_mem(self.pid.0 as i32, addr as usize, size).map_err(|e| anyhow::anyhow!("{}", e));
        }
        Err(anyhow::anyhow!("内核通道未初始化"))
    }

    /// 通过内核通道写入内存
    pub fn write_memory_kernel(&self, addr: u64, data: &[u8]) -> Result<()> {
        if let Some(channel) = &self.kernel_channel {
            return channel.write_mem(self.pid.0 as i32, addr as usize, data).map_err(|e| anyhow::anyhow!("{}", e));
        }
        if let Some(channel) = &self.ioctl_channel {
            return channel.write_mem(self.pid.0 as i32, addr as usize, data).map_err(|e| anyhow::anyhow!("{}", e));
        }
        Err(anyhow::anyhow!("内核通道未初始化"))
    }

    /// 扫描内存区域，检测消息结构
    pub fn scan_for_messages(
        &mut self,
        regions: Option<&[MemoryRegion]>,
        max_messages: usize,
    ) -> Result<Vec<DetectedMessage>> {
        let target_regions = match regions {
            Some(r) => r.to_vec(),
            None => self.get_readable_regions()?,
        };

        let mut messages = Vec::new();

        for region in target_regions {
            if region.size() == 0 || !region.perms.read {
                continue;
            }

            if messages.len() >= max_messages {
                break;
            }

            let detected = self.scan_region_for_messages(&region)?;
            messages.extend(detected);
        }

        self.message_buffer.extend_from_slice(&messages);
        while self.message_buffer.len() > 1000 {
            self.message_buffer.remove(0);
        }

        Ok(messages)
    }

    /// 扫描单个内存区域
    fn scan_region_for_messages(&self, region: &MemoryRegion) -> Result<Vec<DetectedMessage>> {
        let mut messages = Vec::new();
        let page_size = 4096;
        let mut addr = region.start;

        while addr < region.end {
            let remaining = region.end - addr;
            let read_size = remaining.min(page_size);

            let data = match self.read_memory_kernel(addr as u64, read_size) {
                Ok(d) => d,
                Err(e) => {
                    log::debug!("读取内存失败 ({:x}): {}", addr, e);
                    addr += page_size;
                    continue;
                }
            };

            let mut offset = 0;
            while offset < data.len() {
                if let Some(msg) = self.detect_message(&data[offset..], addr + offset) {
                    messages.push(msg);
                    offset += 64;
                } else {
                    offset += 16;
                }
            }

            addr += page_size;
        }

        Ok(messages)
    }

    /// 检测消息结构
    fn detect_message(&self, data: &[u8], addr: usize) -> Option<DetectedMessage> {
        if data.len() < 16 {
            return None;
        }

        let format = self.identify_format(data);
        let (content, confidence) = self.extract_content(data, format);

        if confidence < 0.5 {
            return None;
        }

        let tags = self.tag_message(&content, format);

        Some(DetectedMessage {
            addr: addr as u64,
            pid: self.pid.0,
            format,
            content,
            timestamp: self.get_timestamp(),
            confidence,
            tags,
        })
    }

    /// 识别数据格式
    fn identify_format(&self, data: &[u8]) -> MessageFormat {
        if data.starts_with(b"{") && data.ends_with(b"}") {
            if let Ok(json) = serde_json::from_slice::<serde_json::Value>(data) {
                if json.is_object() {
                    return MessageFormat::Json;
                }
            }
        }

        if data.starts_with(b"[") && data.ends_with(b"]") {
            if let Ok(_) = serde_json::from_slice::<Vec<serde_json::Value>>(data) {
                return MessageFormat::Json;
            }
        }

        if data[0] >= b' ' && data[0] <= b'~' {
            if data.iter().all(|&b| b == 0 || (b >= 0x20 && b <= 0x7E) || b == b'\n' || b == b'\r') {
                return MessageFormat::String;
            }
        }

        if data.len() >= 4 && u32::from_le_bytes([data[0], data[1], data[2], data[3]]) > 0 {
            if data.len() >= 12 {
                let len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
                if len < data.len() && len > 0 {
                    return MessageFormat::ProtoBuf;
                }
            }
        }

        MessageFormat::Unknown
    }

    /// 提取消息内容
    fn extract_content(&self, data: &[u8], format: MessageFormat) -> (String, f64) {
        match format {
            MessageFormat::Json => {
                if let Ok(json) = serde_json::from_slice::<serde_json::Value>(data) {
                    if let Ok(s) = serde_json::to_string(&json) {
                        return (s, 0.95);
                    }
                }
                let end = data.iter().position(|&b| b == b'}').unwrap_or(data.len().min(1024));
                (String::from_utf8_lossy(&data[..end + 1]).to_string(), 0.8)
            }
            MessageFormat::String => {
                let end = data.iter().position(|&b| b == 0).unwrap_or(data.len().min(512));
                let s = String::from_utf8_lossy(&data[..end]).to_string();
                if s.len() > 10 {
                    (s, 0.85)
                } else {
                    (s, 0.3)
                }
            }
            MessageFormat::ProtoBuf => {
                let len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
                let end = len.min(data.len());
                (format!("protobuf: {} bytes", end), 0.6)
            }
            MessageFormat::Binary => {
                let hex: Vec<String> = data.iter().take(32).map(|b| format!("{:02x}", b)).collect();
                (format!("binary: {}", hex.join(" ")), 0.4)
            }
            MessageFormat::Unknown => {
                ("unknown".to_string(), 0.1)
            }
        }
    }

    /// 为消息添加标签
    fn tag_message(&self, content: &str, format: MessageFormat) -> Vec<String> {
        let mut tags = Vec::new();

        if format == MessageFormat::Json {
            if content.contains("\"message\"") || content.contains("\"msg\"") {
                tags.push("chat".to_string());
            }
            if content.contains("\"error\"") || content.contains("\"err\"") {
                tags.push("error".to_string());
            }
            if content.contains("\"token\"") || content.contains("\"auth\"") {
                tags.push("security".to_string());
            }
            if content.contains("\"data\"") || content.contains("\"payload\"") {
                tags.push("data".to_string());
            }
        }

        if content.len() > 100 {
            tags.push("large".to_string());
        }

        tags
    }

    /// 获取可读内存区域
    fn get_readable_regions(&self) -> Result<Vec<MemoryRegion>> {
        use crate::common::util::parse_proc_maps;
        let regions = parse_proc_maps(self.pid)?;
        Ok(regions.into_iter()
            .filter(|r| r.perms.read && r.size() > 0)
            .collect())
    }

    /// 创建内存快照
    pub fn create_snapshot(&mut self) -> Result<MemorySnapshot> {
        let regions = self.get_readable_regions()?;
        let mut hashes = HashMap::new();

        for region in &regions {
            let addr = region.start;
            let size = region.size().min(4096);
            if let Ok(data) = self.read_memory_kernel(addr as u64, size) {
                let hash = self.hash_data(&data);
                hashes.insert(addr as u64, hash);
            }
        }

        let snapshot = MemorySnapshot {
            pid: self.pid.0,
            timestamp: self.get_timestamp(),
            regions,
            content_hashes: hashes,
        };

        self.last_snapshot = Some(snapshot.clone());
        Ok(snapshot)
    }

    /// 对比两个快照，找出变更区域
    pub fn compare_snapshots(
        &self,
        old: &MemorySnapshot,
        new: &MemorySnapshot,
    ) -> Result<Vec<u64>> {
        let mut changed_addrs = Vec::new();

        for (addr, old_hash) in &old.content_hashes {
            if let Some(new_hash) = new.content_hashes.get(addr) {
                if old_hash != new_hash {
                    changed_addrs.push(*addr);
                }
            }
        }

        Ok(changed_addrs)
    }

    /// 获取自上次快照以来的变更
    pub fn get_changes_since_last_snapshot(&mut self) -> Result<Vec<u64>> {
        if self.last_snapshot.is_none() {
            return Ok(Vec::new());
        }

        let new_snapshot = self.create_snapshot()?;
        let changes = self.compare_snapshots(
            self.last_snapshot.as_ref().unwrap(),
            &new_snapshot,
        )?;

        Ok(changes)
    }

    /// 简单哈希函数
    fn hash_data(&self, data: &[u8]) -> u64 {
        let mut hash: u64 = 0xcbf29ce484222325;
        let prime: u64 = 0x100000001b3;

        for &byte in data {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(prime);
        }

        hash
    }

    /// 获取时间戳
    fn get_timestamp(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// 获取检测到的消息缓冲区
    pub fn get_message_buffer(&self) -> &[DetectedMessage] {
        &self.message_buffer
    }

    /// 按标签过滤消息
    pub fn filter_messages_by_tag(&self, tag: &str) -> Vec<&DetectedMessage> {
        self.message_buffer
            .iter()
            .filter(|m| m.tags.contains(&tag.to_string()))
            .collect()
    }

    /// 获取消息数量
    pub fn message_count(&self) -> usize {
        self.message_buffer.len()
    }

    /// 清除消息缓冲区
    pub fn clear_messages(&mut self) {
        self.message_buffer.clear();
    }
}

// ======================== 智能消息分析器 ========================

/// 消息分析结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageAnalysis {
    pub total_messages: usize,
    pub by_format: HashMap<MessageFormat, usize>,
    pub by_tag: HashMap<String, usize>,
    pub keywords: Vec<(String, usize)>,
    pub suspicious_patterns: Vec<String>,
    pub timestamp: u64,
}

/// 智能消息分析器
pub struct MessageAnalyzer {
    scanner: KernelMemoryScanner,
    keyword_patterns: Vec<String>,
    suspicious_patterns: Vec<String>,
}

impl MessageAnalyzer {
    /// 创建新的消息分析器
    pub fn new(pid: ProcessId) -> Self {
        MessageAnalyzer {
            scanner: KernelMemoryScanner::new(pid),
            keyword_patterns: vec![
                "password".to_string(),
                "token".to_string(),
                "secret".to_string(),
                "key".to_string(),
                "auth".to_string(),
                "session".to_string(),
                "message".to_string(),
                "chat".to_string(),
                "send".to_string(),
                "recv".to_string(),
            ],
            suspicious_patterns: vec![
                "frida".to_string(),
                "gum-js".to_string(),
                "tracer".to_string(),
                "debugger".to_string(),
                "hook".to_string(),
            ],
        }
    }

    /// 初始化内核通道
    pub fn init_kernel_channel(&mut self) -> Result<bool> {
        self.scanner.init_kernel_channel()
    }

    /// 执行完整的消息扫描和分析
    pub fn analyze(&mut self, max_messages: usize) -> Result<MessageAnalysis> {
        let messages = self.scanner.scan_for_messages(None, max_messages)?;

        let mut by_format = HashMap::new();
        let mut by_tag = HashMap::new();
        let mut keyword_counts = HashMap::new();
        let mut suspicious_found = Vec::new();

        for msg in &messages {
            *by_format.entry(msg.format).or_insert(0) += 1;

            for tag in &msg.tags {
                *by_tag.entry(tag.clone()).or_insert(0) += 1;
            }

            for keyword in &self.keyword_patterns {
                if msg.content.to_lowercase().contains(&keyword.to_lowercase()) {
                    *keyword_counts.entry(keyword.clone()).or_insert(0) += 1;
                }
            }

            for pattern in &self.suspicious_patterns {
                if msg.content.to_lowercase().contains(&pattern.to_lowercase()) {
                    if !suspicious_found.contains(pattern) {
                        suspicious_found.push(pattern.clone());
                    }
                }
            }
        }

        let mut keywords: Vec<(String, usize)> = keyword_counts.into_iter().collect();
        keywords.sort_by(|a, b| b.1.cmp(&a.1));

        Ok(MessageAnalysis {
            total_messages: messages.len(),
            by_format,
            by_tag,
            keywords,
            suspicious_patterns: suspicious_found,
            timestamp: self.scanner.get_timestamp(),
        })
    }

    /// 获取内核扫描器引用
    pub fn scanner(&self) -> &KernelMemoryScanner {
        &self.scanner
    }

    /// 获取内核扫描器可变引用
    pub fn scanner_mut(&mut self) -> &mut KernelMemoryScanner {
        &mut self.scanner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_creation() {
        let scanner = KernelMemoryScanner::new(ProcessId(1234));
        assert!(!scanner.is_kernel_mode());
    }

    #[test]
    fn test_analyzer_creation() {
        let analyzer = MessageAnalyzer::new(ProcessId(1234));
        assert!(!analyzer.scanner().is_kernel_mode());
    }

    #[test]
    fn test_message_detection() {
        let scanner = KernelMemoryScanner::new(ProcessId(1234));
        
        let json_data = b"{\"message\": \"hello\", \"type\": \"text\"}";
        let format = scanner.identify_format(json_data);
        assert_eq!(format, MessageFormat::Json);

        let text_data = b"Hello world!";
        let format = scanner.identify_format(text_data);
        assert_eq!(format, MessageFormat::String);
    }

    #[test]
    fn test_hash_function() {
        let scanner = KernelMemoryScanner::new(ProcessId(1234));
        let data1 = b"test data";
        let data2 = b"test data";
        let data3 = b"different data";
        
        assert_eq!(scanner.hash_data(data1), scanner.hash_data(data2));
        assert_ne!(scanner.hash_data(data1), scanner.hash_data(data3));
    }
}