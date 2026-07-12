//! 智能反检测模块
//!
//! 自动检测目标进程使用的反调试/反作弊技术，
//! 并根据检测结果智能推荐和应用反检测策略。

use crate::common::types::{ProcessId, MemoryRegion};
use crate::Result;
use std::collections::{HashMap, HashSet};

// ======================== 检测到的反调试技术类型 ========================

/// 反调试/反作弊技术类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AntiDebugTechnique {
    /// 检查 TracerPid
    TracerPidCheck,
    /// 检查 /proc/self/status
    ProcStatusCheck,
    /// 检查 /proc/self/maps
    ProcMapsCheck,
    /// 检查 /proc/self/fd
    ProcFdCheck,
    /// ptrace 自检
    PtraceSelfAttach,
    /// 时间检测（检测调试器造成的延迟）
    TimingCheck,
    /// 信号检测
    SignalCheck,
    /// 文件描述符检测
    FdDetection,
    /// 端口扫描检测
    PortScan,
    /// 内存完整性检查
    MemoryIntegrity,
    /// PEB 检查（Windows）
    PEBCheck,
    /// 调试寄存器检查（Windows）
    DebugRegisterCheck,
    /// IsDebuggerPresent（Windows）
    IsDebuggerPresent,
    /// NtQueryInformationProcess（Windows）
    NtQueryInformationProcess,
    /// 游戏反作弊 - BattlEye
    BattlEye,
    /// 游戏反作弊 - EasyAntiCheat
    EasyAntiCheat,
    /// 游戏反作弊 - Vanguard
    Vanguard,
    /// 游戏反作弊 - XIGNCODE3
    XignCode3,
    /// 游戏反作弊 - nProtect
    NProtect,
    /// 游戏反作弊 - 自定义/未知
    UnknownAntiCheat(String),
    
    // ==================== 国内反作弊系统 ====================
    /// 腾讯 ACE (Anti-Cheat Expert)
    TencentACE,
    /// 腾讯 TP (TenProtect)
    TenProtect,
    /// 腾讯 MTP (Mobile TenProtect)
    MTP,
    /// 网易 UProtect
    NetEaseUProtect,
    /// 网易 YidaXun
    NetEaseYidaXun,
    /// 米哈游 Protect
    MiHoYoProtect,
    /// 米哈游 AntiCheat
    MiHoYoAntiCheat,
    /// 盛趣 GPProtect
    ShengquGPProtect,
    /// 完美世界 PWProtect
    PerfectWorldProtect,
    /// 莉莉丝 LilithProtect
    LilithProtect,
    /// 阿里云游戏盾
    AliGameShield,
    /// 360游戏保护
    Qihoo360GameProtect,
    /// 金山游戏保护
    KingsoftGameProtect,
    /// DRM - Denuvo
    Denuvo,
    /// DRM - Steam DRM
    SteamDRM,
    /// DRM - Epic保护
    EpicProtection,
    /// 游戏加固 - 网易易盾
    NetEaseYidun,
    /// 游戏加固 - 顶象
    DingXiang,
    /// 游戏加固 - 数美
    Shumei,
    /// 游戏加固 - 极验
    GeeTest,
    /// 内存保护 - 自定义
    MemoryProtection(String),
}

/// 检测结果
#[derive(Debug, Clone)]
pub struct DetectionResult {
    /// 检测到的技术
    pub technique: AntiDebugTechnique,
    /// 置信度 (0-100)
    pub confidence: u8,
    /// 证据描述
    pub evidence: String,
    /// 相关内存地址（如果有）
    pub address: Option<u64>,
}

/// 推荐的反检测策略
#[derive(Debug, Clone)]
pub struct StealthRecommendation {
    /// 策略名称
    pub name: String,
    /// 策略描述
    pub description: String,
    /// 优先级 (1-10, 10最高)
    pub priority: u8,
    /// 是否必须执行
    pub required: bool,
    /// 对应的反检测模块
    pub modules: Vec<String>,
}

/// 智能反检测分析器
pub struct SmartStealth {
    pid: ProcessId,
    detections: Vec<DetectionResult>,
    recommendations: Vec<StealthRecommendation>,
    applied_modules: HashSet<String>,
}

impl SmartStealth {
    /// 创建新的智能反检测分析器
    pub fn new(pid: ProcessId) -> Self {
        SmartStealth {
            pid,
            detections: Vec::new(),
            recommendations: Vec::new(),
            applied_modules: HashSet::new(),
        }
    }

    /// 执行全面扫描，检测目标进程使用的反调试技术
    #[cfg(unix)]
    pub fn scan(&mut self) -> Result<&[DetectionResult]> {
        log::info!("开始扫描进程 {} 的反调试技术...", self.pid.0);
        
        self.detections.clear();
        
        // 1. 检查常见反调试库
        self.detect_anti_cheat_libraries()?;
        
        // 2. 检查内存中的反调试特征
        self.detect_debug_signatures()?;
        
        // 3. 检查 /proc 监控行为
        self.detect_proc_monitoring()?;
        
        // 4. 检查 ptrace 使用
        self.detect_ptrace_usage()?;
        
        // 5. 检查时间检测
        self.detect_timing_checks()?;
        
        // 6. 检查端口监听（反作弊服务器通信）
        self.detect_anti_cheat_ports()?;
        
        log::info!("扫描完成，发现 {} 个反调试技术", self.detections.len());
        
        // 根据检测结果生成推荐
        self.generate_recommendations();
        
        Ok(&self.detections)
    }

    /// 检测反作弊库
    #[cfg(unix)]
    fn detect_anti_cheat_libraries(&mut self) -> Result<()> {
        use crate::common::util::parse_proc_maps;
        
        let regions = parse_proc_maps(self.pid)?;
        
        // 已知反作弊库特征（包含国内主流反作弊）
        let anti_cheat_signatures: Vec<(&str, AntiDebugTechnique)> = vec![
            // 国际反作弊
            ("libBattlEye", AntiDebugTechnique::BattlEye),
            ("BEDaisy", AntiDebugTechnique::BattlEye),
            ("EasyAntiCheat", AntiDebugTechnique::EasyAntiCheat),
            ("eac", AntiDebugTechnique::EasyAntiCheat),
            ("vgc.sys", AntiDebugTechnique::Vanguard),
            ("vgk.sys", AntiDebugTechnique::Vanguard),
            ("xigncode", AntiDebugTechnique::XignCode3),
            ("x3.xem", AntiDebugTechnique::XignCode3),
            ("npptools", AntiDebugTechnique::NProtect),
            ("npp", AntiDebugTechnique::NProtect),
            
            // ==================== 国内反作弊 ====================
            // 腾讯 ACE / TP
            ("ACE-Base", AntiDebugTechnique::TencentACE),
            ("ACE-Tracer", AntiDebugTechnique::TencentACE),
            ("ACE-Bin", AntiDebugTechnique::TencentACE),
            ("ace-", AntiDebugTechnique::TencentACE),
            ("libace", AntiDebugTechnique::TencentACE),
            ("TPHelper", AntiDebugTechnique::TenProtect),
            ("TenProtect", AntiDebugTechnique::TenProtect),
            ("tp2", AntiDebugTechnique::TenProtect),
            ("tp_sys", AntiDebugTechnique::TenProtect),
            ("SSOProtect", AntiDebugTechnique::TenProtect),
            ("MTPProtect", AntiDebugTechnique::MTP),
            ("libmtp", AntiDebugTechnique::MTP),
            ("mtp_", AntiDebugTechnique::MTP),
            
            // 网易
            ("UProtect", AntiDebugTechnique::NetEaseUProtect),
            ("upro", AntiDebugTechnique::NetEaseUProtect),
            ("NGuard", AntiDebugTechnique::NetEaseUProtect),
            ("YidaXun", AntiDebugTechnique::NetEaseYidaXun),
            ("ydx", AntiDebugTechnique::NetEaseYidaXun),
            ("Yidun", AntiDebugTechnique::NetEaseYidun),
            ("yidun", AntiDebugTechnique::NetEaseYidun),
            ("libyidun", AntiDebugTechnique::NetEaseYidun),
            
            // 米哈游
            ("MiHoYoProtect", AntiDebugTechnique::MiHoYoProtect),
            ("mhyprotect", AntiDebugTechnique::MiHoYoProtect),
            ("mhy_ac", AntiDebugTechnique::MiHoYoAntiCheat),
            ("MiHoYoAC", AntiDebugTechnique::MiHoYoAntiCheat),
            ("mihoyo", AntiDebugTechnique::MiHoYoProtect),
            ("GenshinImpact", AntiDebugTechnique::MiHoYoProtect),
            
            // 盛趣 / 完美 / 莉莉丝
            ("GPProtect", AntiDebugTechnique::ShengquGPProtect),
            ("gp_", AntiDebugTechnique::ShengquGPProtect),
            ("PWProtect", AntiDebugTechnique::PerfectWorldProtect),
            ("pwprotect", AntiDebugTechnique::PerfectWorldProtect),
            ("LilithProtect", AntiDebugTechnique::LilithProtect),
            ("lilith_", AntiDebugTechnique::LilithProtect),
            
            // 阿里 / 360 / 金山
            ("AliGameShield", AntiDebugTechnique::AliGameShield),
            ("gameshield", AntiDebugTechnique::AliGameShield),
            ("QHGameProtect", AntiDebugTechnique::Qihoo360GameProtect),
            ("360game", AntiDebugTechnique::Qihoo360GameProtect),
            ("KSProtect", AntiDebugTechnique::KingsoftGameProtect),
            
            // DRM
            ("denuvo", AntiDebugTechnique::Denuvo),
            ("Denuvo", AntiDebugTechnique::Denuvo),
            ("steam_api", AntiDebugTechnique::SteamDRM),
            ("steamclient", AntiDebugTechnique::SteamDRM),
            ("EOSSDK", AntiDebugTechnique::EpicProtection),
            
            // 游戏加固
            ("DingXiang", AntiDebugTechnique::DingXiang),
            ("dingxiang", AntiDebugTechnique::DingXiang),
            ("Shumei", AntiDebugTechnique::Shumei),
            ("shumei", AntiDebugTechnique::Shumei),
            ("GeeTest", AntiDebugTechnique::GeeTest),
            ("geetest", AntiDebugTechnique::GeeTest),
            ("gt_", AntiDebugTechnique::GeeTest),
            
            // 通用特征
            ("anti_cheat", AntiDebugTechnique::UnknownAntiCheat("custom".to_string())),
            ("anticheat", AntiDebugTechnique::UnknownAntiCheat("custom".to_string())),
            ("gameprotect", AntiDebugTechnique::UnknownAntiCheat("gameprotect".to_string())),
            ("game_protect", AntiDebugTechnique::UnknownAntiCheat("game_protect".to_string())),
            ("anti_debug", AntiDebugTechnique::UnknownAntiCheat("anti_debug".to_string())),
            ("anti_attach", AntiDebugTechnique::UnknownAntiCheat("anti_attach".to_string())),
        ];
        
        let mut found_techniques = HashSet::new();
        
        for region in &regions {
            let name_lower = region.name.to_lowercase();
            for (signature, technique) in &anti_cheat_signatures {
                if name_lower.contains(&signature.to_lowercase()) && !found_techniques.contains(technique) {
                    found_techniques.insert(*technique);
                    self.detections.push(DetectionResult {
                        technique: *technique,
                        confidence: 90,
                        evidence: format!("发现反作弊库: {}", region.name),
                        address: Some(region.start as u64),
                    });
                    log::info!("检测到反作弊: {:?} @ {}", technique, region.name);
                }
            }
        }
        
        Ok(())
    }

    /// 检测内存中的反调试特征
    #[cfg(unix)]
    fn detect_debug_signatures(&mut self) -> Result<()> {
        use crate::memory::MemoryScanner;
        
        let mut scanner = MemoryScanner::new(self.pid);
        
        // 常见反调试特征字符串（包含国内特色）
        let debug_signatures: Vec<(&str, AntiDebugTechnique, u8)> = vec![
            // 通用反调试
            ("TracerPid", AntiDebugTechnique::TracerPidCheck, 95),
            ("/proc/self/status", AntiDebugTechnique::ProcStatusCheck, 85),
            ("/proc/self/maps", AntiDebugTechnique::ProcMapsCheck, 85),
            ("/proc/self/fd", AntiDebugTechnique::ProcFdCheck, 80),
            ("PTRACE_TRACEME", AntiDebugTechnique::PtraceSelfAttach, 90),
            ("ptrace", AntiDebugTechnique::PtraceSelfAttach, 60),
            ("IsDebuggerPresent", AntiDebugTechnique::IsDebuggerPresent, 95),
            ("NtQueryInformationProcess", AntiDebugTechnique::NtQueryInformationProcess, 95),
            ("CheckRemoteDebuggerPresent", AntiDebugTechnique::IsDebuggerPresent, 95),
            ("OutputDebugString", AntiDebugTechnique::SignalCheck, 70),
            
            // 国内反作弊特征
            ("ACE", AntiDebugTechnique::TencentACE, 70),
            ("AntiCheatExpert", AntiDebugTechnique::TencentACE, 90),
            ("TenProtect", AntiDebugTechnique::TenProtect, 90),
            ("TPHelper", AntiDebugTechnique::TenProtect, 85),
            ("UProtect", AntiDebugTechnique::NetEaseUProtect, 90),
            ("NGuard", AntiDebugTechnique::NetEaseUProtect, 85),
            ("Yidun", AntiDebugTechnique::NetEaseYidun, 90),
            ("MiHoYo", AntiDebugTechnique::MiHoYoProtect, 90),
            ("mhyprotect", AntiDebugTechnique::MiHoYoProtect, 85),
            ("GPProtect", AntiDebugTechnique::ShengquGPProtect, 90),
            ("LilithProtect", AntiDebugTechnique::LilithProtect, 90),
        ];
        
        for (signature, technique, confidence) in &debug_signatures {
            match scanner.search_bytes(signature.as_bytes(), None) {
                Ok(addresses) if !addresses.is_empty() => {
                    self.detections.push(DetectionResult {
                        technique: *technique,
                        confidence: *confidence,
                        evidence: format!("发现反调试特征 '{}' ({} 处)", signature, addresses.len()),
                        address: addresses.first().copied(),
                    });
                    log::info!("检测到反调试特征: '{}' ({} 处)", signature, addresses.len());
                }
                _ => {}
            }
        }
        
        Ok(())
    }

    /// 检测 /proc 监控行为
    #[cfg(unix)]
    fn detect_proc_monitoring(&mut self) -> Result<()> {
        use std::fs;
        
        // 检查进程是否打开了 /proc 文件
        let fd_path = format!("/proc/{}/fd", self.pid.0);
        if let Ok(entries) = fs::read_dir(&fd_path) {
            let proc_files = entries
                .filter_map(|e| e.ok())
                .filter_map(|e| {
                    let link = fs::read_link(e.path()).ok()?;
                    let path = link.to_string_lossy().to_string();
                    if path.contains("/proc/") {
                        Some(path)
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();
            
            if !proc_files.is_empty() {
                self.detections.push(DetectionResult {
                    technique: AntiDebugTechnique::ProcStatusCheck,
                    confidence: 75,
                    evidence: format!("进程打开了 {} 个 /proc 文件: {:?}", proc_files.len(), 
                        proc_files.iter().take(3).collect::<Vec<_>>()),
                    address: None,
                });
            }
        }
        
        Ok(())
    }

    /// 检测 ptrace 使用
    #[cfg(unix)]
    fn detect_ptrace_usage(&mut self) -> Result<()> {
        use std::fs;
        
        // 检查 TracerPid
        let status_path = format!("/proc/{}/status", self.pid.0);
        if let Ok(status) = fs::read_to_string(&status_path) {
            for line in status.lines() {
                if line.starts_with("TracerPid:") {
                    let tracer_pid: u32 = line.split_whitespace()
                        .nth(1)
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0);
                    
                    if tracer_pid != 0 {
                        self.detections.push(DetectionResult {
                            technique: AntiDebugTechnique::TracerPidCheck,
                            confidence: 100,
                            evidence: format!("TracerPid = {} (正在被调试)", tracer_pid),
                            address: None,
                        });
                    }
                    break;
                }
            }
        }
        
        Ok(())
    }

    /// 检测时间检测
    #[cfg(unix)]
    fn detect_timing_checks(&mut self) -> Result<()> {
        use crate::memory::MemoryScanner;
        
        let mut scanner = MemoryScanner::new(self.pid);
        
        // 时间相关函数特征
        let timing_signatures = [
            "clock_gettime",
            "gettimeofday",
            "rdtsc",
            "QueryPerformanceCounter",
            "timeGetTime",
        ];
        
        let mut timing_count = 0;
        for sig in &timing_signatures {
            if let Ok(addrs) = scanner.search_bytes(sig.as_bytes(), None) {
                if !addrs.is_empty() {
                    timing_count += addrs.len();
                }
            }
        }
        
        // 如果发现大量时间函数使用，可能是时间检测
        if timing_count > 10 {
            self.detections.push(DetectionResult {
                technique: AntiDebugTechnique::TimingCheck,
                confidence: 60,
                evidence: format!("发现 {} 处时间相关函数调用", timing_count),
                address: None,
            });
        }
        
        Ok(())
    }

    /// 检测反作弊端口
    #[cfg(unix)]
    fn detect_anti_cheat_ports(&mut self) -> Result<()> {
        use std::fs;
        
        // 常见反作弊服务器端口
        let anti_cheat_ports: Vec<(u16, &str)> = vec![
            (27015, "Steam/Game Server"),
            (3724, "Battle.net"),
            (6112, "Battle.net"),
            (8080, "HTTP Proxy"),
            (443, "HTTPS"),
        ];
        
        let tcp_path = "/proc/net/tcp";
        if let Ok(tcp_content) = fs::read_to_string(tcp_path) {
            for line in tcp_content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() > 1 {
                    let local_addr = parts[1];
                    if let Some(colon_pos) = local_addr.rfind(':') {
                        if let Ok(port) = u16::from_str_radix(&local_addr[colon_pos + 1..], 16) {
                            for (known_port, service) in &anti_cheat_ports {
                                if port == *known_port {
                                    self.detections.push(DetectionResult {
                                        technique: AntiDebugTechnique::PortScan,
                                        confidence: 50,
                                        evidence: format!("监听端口 {} ({})", port, service),
                                        address: None,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        
        Ok(())
    }

    /// 根据检测结果生成推荐策略
    fn generate_recommendations(&mut self) {
        self.recommendations.clear();
        
        // 基础推荐（总是需要）
        self.recommendations.push(StealthRecommendation {
            name: "环境清理".to_string(),
            description: "清除 Frida 相关环境变量".to_string(),
            priority: 10,
            required: true,
            modules: vec!["env_clean".to_string()],
        });
        
        self.recommendations.push(StealthRecommendation {
            name: "特征擦除".to_string(),
            description: "擦除内存中的 Frida 特征字符串".to_string(),
            priority: 10,
            required: true,
            modules: vec!["signature".to_string()],
        });
        
        // 根据检测结果生成特定推荐
        let detected_techniques: HashSet<AntiDebugTechnique> = 
            self.detections.iter().map(|d| d.technique).collect();
        
        if detected_techniques.contains(&AntiDebugTechnique::TracerPidCheck) ||
           detected_techniques.contains(&AntiDebugTechnique::ProcStatusCheck) {
            self.recommendations.push(StealthRecommendation {
                name: "TracerPid 隐藏".to_string(),
                description: "清除 /proc/self/status 中的 TracerPid".to_string(),
                priority: 9,
                required: true,
                modules: vec!["tracer".to_string()],
            });
        }
        
        if detected_techniques.contains(&AntiDebugTechnique::ProcMapsCheck) {
            self.recommendations.push(StealthRecommendation {
                name: "Maps 隐藏".to_string(),
                description: "隐藏 /proc/self/maps 中的 Frida 条目".to_string(),
                priority: 9,
                required: true,
                modules: vec!["maps_hide".to_string()],
            });
        }
        
        if detected_techniques.contains(&AntiDebugTechnique::ProcFdCheck) ||
           detected_techniques.contains(&AntiDebugTechnique::FdDetection) {
            self.recommendations.push(StealthRecommendation {
                name: "文件描述符隐藏".to_string(),
                description: "隐藏 /proc/self/fd 中的 Frida 文件描述符".to_string(),
                priority: 8,
                required: true,
                modules: vec!["fd_hide".to_string()],
            });
        }
        
        if detected_techniques.contains(&AntiDebugTechnique::PortScan) {
            self.recommendations.push(StealthRecommendation {
                name: "端口隐藏".to_string(),
                description: "隐藏 /proc/net/tcp 中的 Frida 端口".to_string(),
                priority: 8,
                required: false,
                modules: vec!["port_hide".to_string(), "net_hide".to_string()],
            });
        }
        
        // 游戏反作弊特殊处理（包含国内反作弊）
        let has_game_anti_cheat = detected_techniques.iter().any(|t| matches!(
            t,
            // 国际反作弊
            AntiDebugTechnique::BattlEye |
            AntiDebugTechnique::EasyAntiCheat |
            AntiDebugTechnique::Vanguard |
            AntiDebugTechnique::XignCode3 |
            AntiDebugTechnique::NProtect |
            // 国内反作弊
            AntiDebugTechnique::TencentACE |
            AntiDebugTechnique::TenProtect |
            AntiDebugTechnique::MTP |
            AntiDebugTechnique::NetEaseUProtect |
            AntiDebugTechnique::NetEaseYidaXun |
            AntiDebugTechnique::NetEaseYidun |
            AntiDebugTechnique::MiHoYoProtect |
            AntiDebugTechnique::MiHoYoAntiCheat |
            AntiDebugTechnique::ShengquGPProtect |
            AntiDebugTechnique::PerfectWorldProtect |
            AntiDebugTechnique::LilithProtect |
            AntiDebugTechnique::AliGameShield |
            AntiDebugTechnique::Qihoo360GameProtect |
            AntiDebugTechnique::KingsoftGameProtect |
            AntiDebugTechnique::Denuvo |
            AntiDebugTechnique::SteamDRM |
            AntiDebugTechnique::EpicProtection |
            AntiDebugTechnique::DingXiang |
            AntiDebugTechnique::Shumei |
            AntiDebugTechnique::GeeTest |
            AntiDebugTechnique::UnknownAntiCheat(_)
        ));
        
        // 国内高强度反作弊需要更严格的防护
        let has_strong_chinese_ac = detected_techniques.iter().any(|t| matches!(
            t,
            AntiDebugTechnique::TencentACE |
            AntiDebugTechnique::TenProtect |
            AntiDebugTechnique::MTP |
            AntiDebugTechnique::MiHoYoProtect |
            AntiDebugTechnique::MiHoYoAntiCheat
        ));
        
        if has_game_anti_cheat {
            // 游戏反作弊通常需要全面防护
            self.recommendations.push(StealthRecommendation {
                name: "全面防护".to_string(),
                description: "游戏反作弊检测到，启用全面反检测措施".to_string(),
                priority: 10,
                required: true,
                modules: vec![
                    "tracer".to_string(),
                    "maps_hide".to_string(),
                    "fd_hide".to_string(),
                    "thread_hide".to_string(),
                    "port_hide".to_string(),
                    "net_hide".to_string(),
                    "stack_fake".to_string(),
                ],
            });
        }
        
        // 按优先级排序
        self.recommendations.sort_by(|a, b| b.priority.cmp(&a.priority));
        
        log::info!("生成 {} 条反检测推荐", self.recommendations.len());
    }

    /// 获取检测结果
    pub fn detections(&self) -> &[DetectionResult] {
        &self.detections
    }

    /// 获取推荐策略
    pub fn recommendations(&self) -> &[StealthRecommendation] {
        &self.recommendations
    }

    /// 获取推荐的隐蔽模式
    pub fn recommended_mode(&self) -> crate::anti_detect::StealthMode {
        let has_high_risk = self.detections.iter().any(|d| d.confidence >= 80);
        
        // 检测到的所有游戏反作弊
        let has_game_anti_cheat = self.detections.iter().any(|d| matches!(
            d.technique,
            // 国际反作弊
            AntiDebugTechnique::BattlEye |
            AntiDebugTechnique::EasyAntiCheat |
            AntiDebugTechnique::Vanguard |
            AntiDebugTechnique::XignCode3 |
            AntiDebugTechnique::NProtect |
            // 国内反作弊
            AntiDebugTechnique::TencentACE |
            AntiDebugTechnique::TenProtect |
            AntiDebugTechnique::MTP |
            AntiDebugTechnique::NetEaseUProtect |
            AntiDebugTechnique::NetEaseYidaXun |
            AntiDebugTechnique::NetEaseYidun |
            AntiDebugTechnique::MiHoYoProtect |
            AntiDebugTechnique::MiHoYoAntiCheat |
            AntiDebugTechnique::ShengquGPProtect |
            AntiDebugTechnique::PerfectWorldProtect |
            AntiDebugTechnique::LilithProtect |
            AntiDebugTechnique::AliGameShield |
            AntiDebugTechnique::Qihoo360GameProtect |
            AntiDebugTechnique::KingsoftGameProtect |
            AntiDebugTechnique::Denuvo |
            AntiDebugTechnique::SteamDRM |
            AntiDebugTechnique::EpicProtection |
            AntiDebugTechnique::DingXiang |
            AntiDebugTechnique::Shumei |
            AntiDebugTechnique::GeeTest |
            AntiDebugTechnique::UnknownAntiCheat(_)
        ));
        
        // 国内高强度反作弊（ACE/TP/米哈游）需要最高级别防护
        let has_strong_chinese_ac = self.detections.iter().any(|d| matches!(
            d.technique,
            AntiDebugTechnique::TencentACE |
            AntiDebugTechnique::TenProtect |
            AntiDebugTechnique::MTP |
            AntiDebugTechnique::MiHoYoProtect |
            AntiDebugTechnique::MiHoYoAntiCheat
        ));
        
        if has_strong_chinese_ac {
            // 国内高强度反作弊必须使用完整模式
            log::warn!("检测到国内高强度反作弊（ACE/TP/米哈游），必须使用完整模式");
            crate::anti_detect::StealthMode::Full
        } else if has_game_anti_cheat {
            crate::anti_detect::StealthMode::Full
        } else if has_high_risk {
            crate::anti_detect::StealthMode::Standard
        } else if !self.detections.is_empty() {
            crate::anti_detect::StealthMode::Minimal
        } else {
            crate::anti_detect::StealthMode::Minimal
        }
    }

    /// 应用推荐的反检测策略
    #[cfg(unix)]
    pub fn apply_recommended(&mut self) -> Result<()> {
        let mode = self.recommended_mode();
        log::info!("应用推荐的隐蔽模式: {:?}", mode);
        
        let mut manager = crate::anti_detect::StealthManager::new();
        manager.set_mode(mode);
        manager.apply_all()?;
        
        // 记录已应用的模块
        for rec in &self.recommendations {
            for module in &rec.modules {
                self.applied_modules.insert(module.clone());
            }
        }
        
        Ok(())
    }

    /// 获取格式化的分析报告
    pub fn report(&self) -> String {
        let mut report = String::new();
        
        report.push_str(&format!("=== 进程 {} 反调试分析报告 ===\n\n", self.pid.0));
        
        // 检测结果
        report.push_str("【检测结果】\n");
        if self.detections.is_empty() {
            report.push_str("  未发现明显的反调试技术\n");
        } else {
            for (i, det) in self.detections.iter().enumerate() {
                report.push_str(&format!(
                    "  {}. {:?} (置信度: {}%)\n     证据: {}\n",
                    i + 1, det.technique, det.confidence, det.evidence
                ));
                if let Some(addr) = det.address {
                    report.push_str(&format!("     地址: {:#x}\n", addr));
                }
            }
        }
        
        report.push_str("\n【推荐策略】\n");
        for (i, rec) in self.recommendations.iter().enumerate() {
            report.push_str(&format!(
                "  {}. [优先级{}] {} {}\n     {}\n     模块: {:?}\n",
                i + 1, rec.priority, 
                if rec.required { "【必须】" } else { "" },
                rec.name, rec.description, rec.modules
            ));
        }
        
        let mode = self.recommended_mode();
        report.push_str(&format!("\n【推荐模式】{:?}\n", mode));
        
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smart_stealth_creation() {
        let smart = SmartStealth::new(ProcessId(1));
        assert!(smart.detections().is_empty());
        assert!(smart.recommendations().is_empty());
    }

    #[test]
    fn test_report_generation() {
        let smart = SmartStealth::new(ProcessId(1));
        let report = smart.report();
        assert!(report.contains("反调试分析报告"));
    }
}
