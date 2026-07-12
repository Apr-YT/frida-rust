//! AI 自我学习系统
//!
//! 记录逆向分析过程中的问题和解决方案，
//! 让 AI 能够从经验中学习并自我升级。

use std::collections::HashMap;
use std::path::PathBuf;
use serde::{Serialize, Deserialize};
use crate::Result;

// ======================== 经验数据结构 ========================

/// 经验类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ExperienceType {
    /// 反作弊检测成功规避
    AntiCheatBypass,
    /// 反作弊检测失败被发现
    AntiCheatDetected,
    /// Hook 成功
    HookSuccess,
    /// Hook 失败
    HookFailed,
    /// 注入成功
    InjectSuccess,
    /// 注入失败
    InjectFailed,
    /// 内存读取成功
    MemoryReadSuccess,
    /// 内存读取失败
    MemoryReadFailed,
    /// 特征发现
    SignatureFound,
    /// 策略调整
    StrategyAdjustment,
}

/// 单条经验记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Experience {
    /// 经验ID
    pub id: String,
    /// 时间戳
    pub timestamp: u64,
    /// 经验类型
    pub exp_type: ExperienceType,
    /// 目标进程/游戏
    pub target: String,
    /// 反作弊系统（如果有）
    pub anti_cheat: Option<String>,
    /// 遇到的问题描述
    pub problem: String,
    /// 解决方案
    pub solution: String,
    /// 使用的策略
    pub strategy: Vec<String>,
    /// 成功/失败
    pub success: bool,
    /// 置信度 (0-100)
    pub confidence: u8,
    /// 附加标签
    pub tags: Vec<String>,
    /// 额外元数据
    pub metadata: HashMap<String, String>,
}

/// 策略模板
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategyTemplate {
    /// 策略名称
    pub name: String,
    /// 适用场景
    pub scenarios: Vec<String>,
    /// 适用的反作弊系统
    pub anti_cheats: Vec<String>,
    /// 执行步骤
    pub steps: Vec<StrategyStep>,
    /// 成功率
    pub success_rate: f32,
    /// 使用次数
    pub usage_count: u32,
    /// 最后使用时间
    pub last_used: u64,
}

/// 策略步骤
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategyStep {
    /// 步骤名称
    pub name: String,
    /// 步骤描述
    pub description: String,
    /// MCP 工具调用
    pub tool: String,
    /// 参数
    pub params: HashMap<String, String>,
    /// 是否必须
    pub required: bool,
    /// 失败时的回退步骤
    pub fallback: Option<Box<StrategyStep>>,
}

/// 知识库条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeEntry {
    /// 条目ID
    pub id: String,
    /// 反作弊系统名称
    pub anti_cheat: String,
    /// 特征描述
    pub signatures: Vec<String>,
    /// 已知的检测方法
    pub detection_methods: Vec<String>,
    /// 已知的绕过方法
    pub bypass_methods: Vec<String>,
    /// 注意事项
    pub notes: Vec<String>,
    /// 更新时间
    pub updated_at: u64,
    /// 来源
    pub source: String,
}

// ======================== AI 学习系统 ========================

/// AI 自我学习系统
pub struct AILearningSystem {
    /// 经验数据库
    experiences: Vec<Experience>,
    /// 策略库
    strategies: Vec<StrategyTemplate>,
    /// 知识库
    knowledge: HashMap<String, KnowledgeEntry>,
    /// 存储路径
    storage_path: PathBuf,
    /// 经验计数器
    exp_counter: u64,
}

impl AILearningSystem {
    /// 创建新的学习系统
    pub fn new(storage_path: Option<PathBuf>) -> Self {
        let path = storage_path.unwrap_or_else(|| {
            // 尝试获取用户数据目录
            if let Ok(data_dir) = std::env::var(if cfg!(windows) { "LOCALAPPDATA" } else { "HOME" }) {
                let mut path = PathBuf::from(data_dir);
                if !cfg!(windows) {
                    path.push(".local");
                    path.push("share");
                }
                path.push("frida-rust");
                path.push("ai_learning");
                path
            } else {
                PathBuf::from(".").join("frida-rust").join("ai_learning")
            }
        });
        
        let mut system = AILearningSystem {
            experiences: Vec::new(),
            strategies: Vec::new(),
            knowledge: HashMap::new(),
            storage_path: path,
            exp_counter: 0,
        };
        
        // 尝试加载已有数据
        let _ = system.load();
        
        // 加载内置知识库
        system.init_builtin_knowledge();
        
        system
    }

    /// 记录一条经验
    pub fn record_experience(
        &mut self,
        exp_type: ExperienceType,
        target: &str,
        anti_cheat: Option<&str>,
        problem: &str,
        solution: &str,
        strategy: Vec<String>,
        success: bool,
    ) -> String {
        self.exp_counter += 1;
        let id = format!("exp_{}", self.exp_counter);
        
        let exp = Experience {
            id: id.clone(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            exp_type,
            target: target.to_string(),
            anti_cheat: anti_cheat.map(|s| s.to_string()),
            problem: problem.to_string(),
            solution: solution.to_string(),
            strategy,
            success,
            confidence: if success { 80 } else { 30 },
            tags: Vec::new(),
            metadata: HashMap::new(),
        };
        
        self.experiences.push(exp.clone());
        
        // 自动保存
        let _ = self.save();
        
        // 如果是成功经验，可能生成新策略
        if success {
            self.learn_from_success(&exp);
        }
        
        log::info!("记录经验: {} - {}", id, problem);
        id
    }

    /// 从成功经验中学习
    fn learn_from_success(&mut self, exp: &Experience) {
        // 检查是否已有类似策略
        let existing = self.strategies.iter_mut().find(|s| {
            s.anti_cheats.contains(&exp.anti_cheat.clone().unwrap_or_default())
        });
        
        if let Some(strategy) = existing {
            // 更新现有策略的成功率
            strategy.usage_count += 1;
            strategy.success_rate = (strategy.success_rate * (strategy.usage_count - 1) as f32 + 1.0) 
                / strategy.usage_count as f32;
            strategy.last_used = exp.timestamp;
        } else if exp.anti_cheat.is_some() {
            // 创建新策略模板
            let new_strategy = StrategyTemplate {
                name: format!("{} 绕过策略", exp.anti_cheat.as_ref().unwrap()),
                scenarios: vec![exp.target.clone()],
                anti_cheats: vec![exp.anti_cheat.clone().unwrap()],
                steps: self.generate_strategy_steps(exp),
                success_rate: 1.0,
                usage_count: 1,
                last_used: exp.timestamp,
            };
            
            self.strategies.push(new_strategy);
            log::info!("生成新策略: {}", exp.anti_cheat.as_ref().unwrap());
        }
    }

    /// 根据经验生成策略步骤
    fn generate_strategy_steps(&self, exp: &Experience) -> Vec<StrategyStep> {
        let mut steps = Vec::new();
        
        // 基础步骤
        steps.push(StrategyStep {
            name: "环境清理".to_string(),
            description: "清除 Frida 环境变量".to_string(),
            tool: "apply_smart_stealth".to_string(),
            params: HashMap::new(),
            required: true,
            fallback: None,
        });
        
        // 根据反作弊类型添加特定步骤
        if let Some(ref ac) = exp.anti_cheat {
            match ac.as_str() {
                "TencentACE" | "TenProtect" | "MTP" => {
                    steps.push(StrategyStep {
                        name: "延迟注入".to_string(),
                        description: "腾讯反作弊检测严格，需要延迟注入".to_string(),
                        tool: "wait_and_inject".to_string(),
                        params: {
                            let mut p = HashMap::new();
                            p.insert("delay_ms".to_string(), "5000".to_string());
                            p
                        },
                        required: true,
                        fallback: None,
                    });
                }
                "MiHoYoProtect" | "MiHoYoAntiCheat" => {
                    steps.push(StrategyStep {
                        name: "内存特征清除".to_string(),
                        description: "米哈游会扫描内存特征".to_string(),
                        tool: "erase_frida_signatures".to_string(),
                        params: HashMap::new(),
                        required: true,
                        fallback: None,
                    });
                }
                _ => {}
            }
        }
        
        steps
    }

    /// 查询相关经验
    pub fn query_experiences(
        &self,
        target: Option<&str>,
        anti_cheat: Option<&str>,
        exp_type: Option<&ExperienceType>,
    ) -> Vec<&Experience> {
        self.experiences.iter().filter(|exp| {
            if let Some(t) = target {
                if !exp.target.contains(t) {
                    return false;
                }
            }
            if let Some(ac) = anti_cheat {
                if exp.anti_cheat.as_ref().map_or(true, |e| !e.contains(ac)) {
                    return false;
                }
            }
            if let Some(et) = exp_type {
                if exp.exp_type != *et {
                    return false;
                }
            }
            true
        }).collect()
    }

    /// 查询相关策略
    pub fn query_strategies(&self, anti_cheat: &str) -> Vec<&StrategyTemplate> {
        self.strategies.iter().filter(|s| {
            s.anti_cheats.iter().any(|ac| ac.contains(anti_cheat) || anti_cheat.contains(ac))
        }).collect()
    }

    /// 查询知识库
    pub fn query_knowledge(&self, anti_cheat: &str) -> Option<&KnowledgeEntry> {
        self.knowledge.get(anti_cheat)
    }

    /// 根据历史经验推荐策略
    pub fn recommend_strategy(&self, anti_cheat: &str, target: &str) -> Vec<String> {
        let mut recommendations = Vec::new();
        
        // 1. 查询知识库
        if let Some(knowledge) = self.query_knowledge(anti_cheat) {
            recommendations.push(format!("📚 知识库建议: {:?}", knowledge.bypass_methods));
        }
        
        // 2. 查询历史成功策略
        let strategies = self.query_strategies(anti_cheat);
        let successful: Vec<_> = strategies.iter()
            .filter(|s| s.success_rate > 0.5)
            .collect();
        
        if !successful.is_empty() {
            let best = successful.iter().max_by(|a, b| {
                a.success_rate.partial_cmp(&b.success_rate).unwrap()
            }).unwrap();
            recommendations.push(format!(
                "🎯 推荐策略: {} (成功率: {:.0}%, 使用次数: {})",
                best.name, best.success_rate * 100.0, best.usage_count
            ));
        }
        
        // 3. 查询历史经验
        let experiences = self.query_experiences(Some(target), Some(anti_cheat), None);
        let successful_exps: Vec<_> = experiences.iter()
            .filter(|e| e.success)
            .collect();
        
        if !successful_exps.is_empty() {
            let latest = successful_exps.last().unwrap();
            recommendations.push(format!(
                "💡 历史经验: {} (解决方案: {})",
                latest.problem, latest.solution
            ));
        }
        
        recommendations
    }

    /// 反馈循环 - AI 报告问题并学习
    pub fn feedback_loop(
        &mut self,
        problem: &str,
        context: &str,
        solution: Option<&str>,
        success: bool,
    ) -> String {
        let exp_type = if success {
            ExperienceType::AntiCheatBypass
        } else {
            ExperienceType::AntiCheatDetected
        };
        
        // 从上下文中提取反作弊信息
        let anti_cheat = self.extract_anti_cheat(context);
        let target = self.extract_target(context);
        
        let solution_str = solution.unwrap_or("待解决");
        
        let id = self.record_experience(
            exp_type,
            &target,
            anti_cheat.as_deref(),
            problem,
            solution_str,
            Vec::new(),
            success,
        );
        
        // 如果失败，尝试从知识库中找解决方案
        if !success {
            if let Some(ac) = &anti_cheat {
                if let Some(knowledge) = self.query_knowledge(ac) {
                    return format!(
                        "❌ 问题记录: {}\n\n\
                         📚 知识库中有以下绕过方法可以尝试:\n\
                         {}\n\n\
                         💡 建议尝试这些方法并反馈结果",
                        id,
                        knowledge.bypass_methods.iter()
                            .enumerate()
                            .map(|(i, m)| format!("  {}. {}", i + 1, m))
                            .collect::<Vec<_>>()
                            .join("\n")
                    );
                }
            }
        }
        
        id
    }

    /// 从上下文中提取反作弊名称（公开版本）
    pub fn extract_anti_cheat_from_context(&self, context: &str) -> Option<String> {
        self.extract_anti_cheat(context)
    }

    /// 获取可变知识库引用
    pub fn query_knowledge_mut(&mut self, anti_cheat: &str) -> Option<&mut KnowledgeEntry> {
        self.knowledge.get_mut(anti_cheat)
    }

    /// 从上下文中提取反作弊名称
    fn extract_anti_cheat(&self, context: &str) -> Option<String> {
        let known_anti_cheats = vec![
            "ACE", "TenProtect", "MTP", "UProtect", "Yidun",
            "MiHoYo", "GPProtect", "Lilith", "BattlEye", "EasyAntiCheat",
        ];
        
        for ac in known_anti_cheats {
            if context.contains(ac) {
                return Some(ac.to_string());
            }
        }
        
        None
    }

    /// 从上下文中提取目标名称
    fn extract_target(&self, context: &str) -> String {
        // 简单提取：如果包含 "PID" 则提取 PID
        if let Some(pid_start) = context.find("PID=") {
            let pid_str = &context[pid_start + 4..];
            if let Some(pid_end) = pid_str.find(|c: char| !c.is_ascii_digit()) {
                return format!("PID:{}", &pid_str[..pid_end]);
            }
        }
        
        "unknown".to_string()
    }

    /// 获取学习统计
    pub fn stats(&self) -> LearningStats {
        let total = self.experiences.len();
        let successful = self.experiences.iter().filter(|e| e.success).count();
        let failed = total - successful;
        
        let mut by_type = HashMap::new();
        for exp in &self.experiences {
            *by_type.entry(exp.exp_type.clone()).or_insert(0) += 1;
        }
        
        let mut by_anti_cheat = HashMap::new();
        for exp in &self.experiences {
            if let Some(ref ac) = exp.anti_cheat {
                *by_anti_cheat.entry(ac.clone()).or_insert(0) += 1;
            }
        }
        
        LearningStats {
            total_experiences: total,
            successful,
            failed,
            success_rate: if total > 0 { successful as f32 / total as f32 } else { 0.0 },
            strategies_count: self.strategies.len(),
            knowledge_count: self.knowledge.len(),
            by_type,
            by_anti_cheat,
        }
    }

    /// 生成学习报告
    pub fn report(&self) -> String {
        let stats = self.stats();
        
        let mut report = String::from("=== AI 学习系统报告 ===\n\n");
        
        report.push_str(&format!("📊 总体统计:\n"));
        report.push_str(&format!("  总经验数: {}\n", stats.total_experiences));
        report.push_str(&format!("  成功: {} ({:.0}%)\n", stats.successful, stats.success_rate * 100.0));
        report.push_str(&format!("  失败: {}\n", stats.failed));
        report.push_str(&format!("  策略库: {} 条\n", stats.strategies_count));
        report.push_str(&format!("  知识库: {} 条\n\n", stats.knowledge_count));
        
        report.push_str("📈 按类型统计:\n");
        for (exp_type, count) in &stats.by_type {
            report.push_str(&format!("  {:?}: {}\n", exp_type, count));
        }
        
        report.push_str("\n🎮 按反作弊统计:\n");
        for (ac, count) in &stats.by_anti_cheat {
            report.push_str(&format!("  {}: {}\n", ac, count));
        }
        
        report.push_str("\n📚 策略库:\n");
        for strategy in &self.strategies {
            report.push_str(&format!(
                "  {} (成功率: {:.0}, 使用: {}次)\n",
                strategy.name, strategy.success_rate * 100.0, strategy.usage_count
            ));
        }
        
        report
    }

    /// 初始化内置知识库
    fn init_builtin_knowledge(&mut self) {
        // 腾讯 ACE
        self.knowledge.insert("TencentACE".to_string(), KnowledgeEntry {
            id: "ac_ace".to_string(),
            anti_cheat: "TencentACE".to_string(),
            signatures: vec![
                "ACE-Base".to_string(),
                "ACE-Tracer".to_string(),
                "AntiCheatExpert".to_string(),
            ],
            detection_methods: vec![
                "内存完整性检查".to_string(),
                "调试器检测".to_string(),
                "进程注入检测".to_string(),
                "Hook 检测".to_string(),
                "模块完整性校验".to_string(),
            ],
            bypass_methods: vec![
                "延迟注入 - 等待游戏完全加载后再注入".to_string(),
                "内存伪装 - 修改内存特征避免扫描".to_string(),
                "线程隐藏 - 隐藏 Frida 相关线程".to_string(),
                "模块隐藏 - 隐藏 Frida 模块".to_string(),
                "调用栈伪造 - 伪造正常的调用栈".to_string(),
            ],
            notes: vec![
                "ACE 检测非常严格，需要多层防护".to_string(),
                "建议在游戏启动后等待 5-10 秒再注入".to_string(),
                "注入后立即应用所有反检测措施".to_string(),
            ],
            updated_at: 0,
            source: "builtin".to_string(),
        });
        
        // 米哈游
        self.knowledge.insert("MiHoYoProtect".to_string(), KnowledgeEntry {
            id: "ac_mihoyo".to_string(),
            anti_cheat: "MiHoYoProtect".to_string(),
            signatures: vec![
                "MiHoYoProtect".to_string(),
                "mhyprotect".to_string(),
                "mhy_ac".to_string(),
            ],
            detection_methods: vec![
                "内存扫描".to_string(),
                "模块校验".to_string(),
                "调试器检测".to_string(),
                "系统调用监控".to_string(),
            ],
            bypass_methods: vec![
                "特征擦除 - 清除内存中的 Frida 特征".to_string(),
                "模块隐藏 - 隐藏 /proc/self/maps 中的条目".to_string(),
                "环境清理 - 清除 FRIDA_* 环境变量".to_string(),
                "调用栈伪造 - 过滤敏感调用帧".to_string(),
            ],
            notes: vec![
                "米哈游会持续更新检测方法".to_string(),
                "建议使用最新版本的反检测模块".to_string(),
            ],
            updated_at: 0,
            source: "builtin".to_string(),
        });
        
        // 网易 Yidun
        self.knowledge.insert("NetEaseYidun".to_string(), KnowledgeEntry {
            id: "ac_yidun".to_string(),
            anti_cheat: "NetEaseYidun".to_string(),
            signatures: vec![
                "Yidun".to_string(),
                "yidun".to_string(),
                "libyidun".to_string(),
            ],
            detection_methods: vec![
                "内存保护".to_string(),
                "反调试检测".to_string(),
                "Hook 检测".to_string(),
            ],
            bypass_methods: vec![
                "内存特征清除".to_string(),
                "反调试绕过".to_string(),
                "Hook 伪装".to_string(),
            ],
            notes: vec!["网易易盾会根据游戏定制检测策略".to_string()],
            updated_at: 0,
            source: "builtin".to_string(),
        });
    }

    /// 保存到文件
    fn save(&self) -> Result<()> {
        std::fs::create_dir_all(&self.storage_path)?;
        
        let experiences_path = self.storage_path.join("experiences.json");
        let strategies_path = self.storage_path.join("strategies.json");
        let knowledge_path = self.storage_path.join("knowledge.json");
        
        std::fs::write(
            &experiences_path,
            serde_json::to_string_pretty(&self.experiences).unwrap_or_default(),
        )?;
        
        std::fs::write(
            &strategies_path,
            serde_json::to_string_pretty(&self.strategies).unwrap_or_default(),
        )?;
        
        std::fs::write(
            &knowledge_path,
            serde_json::to_string_pretty(&self.knowledge).unwrap_or_default(),
        )?;
        
        Ok(())
    }

    /// 从文件加载
    fn load(&mut self) -> Result<()> {
        let experiences_path = self.storage_path.join("experiences.json");
        let strategies_path = self.storage_path.join("strategies.json");
        let knowledge_path = self.storage_path.join("knowledge.json");
        
        if experiences_path.exists() {
            let data = std::fs::read_to_string(&experiences_path)?;
            self.experiences = serde_json::from_str(&data).unwrap_or_default();
        }
        
        if strategies_path.exists() {
            let data = std::fs::read_to_string(&strategies_path)?;
            self.strategies = serde_json::from_str(&data).unwrap_or_default();
        }
        
        if knowledge_path.exists() {
            let data = std::fs::read_to_string(&knowledge_path)?;
            self.knowledge = serde_json::from_str(&data).unwrap_or_default();
        }
        
        Ok(())
    }
}

/// 学习统计
#[derive(Debug)]
pub struct LearningStats {
    pub total_experiences: usize,
    pub successful: usize,
    pub failed: usize,
    pub success_rate: f32,
    pub strategies_count: usize,
    pub knowledge_count: usize,
    pub by_type: HashMap<ExperienceType, usize>,
    pub by_anti_cheat: HashMap<String, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_learning_system_creation() {
        let system = AILearningSystem::new(None);
        assert_eq!(system.experiences.len(), 0);
        assert!(system.knowledge.len() > 0); // 内置知识库
    }

    #[test]
    fn test_record_experience() {
        let mut system = AILearningSystem::new(None);
        let id = system.record_experience(
            ExperienceType::AntiCheatBypass,
            "test_game",
            Some("TestAC"),
            "检测到调试器",
            "使用延迟注入",
            vec!["delay_inject".to_string()],
            true,
        );
        assert!(!id.is_empty());
        assert_eq!(system.experiences.len(), 1);
    }

    #[test]
    fn test_query_knowledge() {
        let system = AILearningSystem::new(None);
        let knowledge = system.query_knowledge("TencentACE");
        assert!(knowledge.is_some());
        assert_eq!(knowledge.unwrap().anti_cheat, "TencentACE");
    }
}
