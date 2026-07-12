//! AI 全面自我学习系统
//!
//! 实现：
//! - 自动经验收集 - 每次操作自动记录
//! - 智能反馈循环 - 遇到问题自动分析
//! - 策略迭代优化 - 根据成功率调整
//! - 知识图谱构建 - 反作弊特征关系

use std::collections::HashMap;
use std::path::PathBuf;
use serde::{Serialize, Deserialize};
// use crate::Result; // 未使用

// ======================== 核心数据结构 ========================

/// 操作类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ActionType {
    /// 进程附着
    Attach,
    /// 库注入
    Inject,
    /// 函数Hook
    Hook,
    /// 内存读取
    MemoryRead,
    /// 内存写入
    MemoryWrite,
    /// 内存搜索
    MemorySearch,
    /// 反检测应用
    StealthApply,
    /// 反调试分析
    StealthAnalyze,
    /// ESP分析
    EspAnalyze,
    /// 符号查询
    SymbolQuery,
}

/// 操作结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationResult {
    /// 操作ID
    pub id: String,
    /// 时间戳
    pub timestamp: u64,
    /// 操作类型
    pub action: ActionType,
    /// 目标进程
    pub target_pid: u32,
    /// 目标名称
    pub target_name: String,
    /// 反作弊系统（如果有）
    pub anti_cheat: Option<String>,
    /// 是否成功
    pub success: bool,
    /// 错误信息（如果失败）
    pub error: Option<String>,
    /// 使用的策略
    pub strategy: Vec<String>,
    /// 执行时间（毫秒）
    pub duration_ms: u64,
    /// 附加数据
    pub metadata: HashMap<String, String>,
}

/// 策略模板
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Strategy {
    /// 策略ID
    pub id: String,
    /// 策略名称
    pub name: String,
    /// 适用的操作类型
    pub actions: Vec<ActionType>,
    /// 适用的反作弊系统
    pub anti_cheats: Vec<String>,
    /// 执行步骤
    pub steps: Vec<StrategyStep>,
    /// 成功率
    pub success_rate: f64,
    /// 使用次数
    pub usage_count: u32,
    /// 成功次数
    pub success_count: u32,
    /// 平均执行时间
    pub avg_duration_ms: u64,
    /// 最后使用时间
    pub last_used: u64,
    /// 优先级
    pub priority: u8,
}

/// 策略步骤
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategyStep {
    /// 步骤名称
    pub name: String,
    /// 步骤描述
    pub description: String,
    /// MCP工具名
    pub tool: String,
    /// 参数模板
    pub params: HashMap<String, String>,
    /// 是否必须
    pub required: bool,
    /// 失败时的回退
    pub fallback: Option<String>,
}

/// 知识节点
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeNode {
    /// 节点ID
    pub id: String,
    /// 节点类型
    pub node_type: KnowledgeNodeType,
    /// 名称
    pub name: String,
    /// 描述
    pub description: String,
    /// 关联节点
    pub connections: Vec<KnowledgeEdge>,
    /// 置信度
    pub confidence: f64,
    /// 更新时间
    pub updated_at: u64,
}

/// 知识节点类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum KnowledgeNodeType {
    /// 反作弊系统
    AntiCheat,
    /// 检测方法
    DetectionMethod,
    /// 绕过方法
    BypassMethod,
    /// 游戏引擎
    GameEngine,
    /// 游戏
    Game,
}

/// 知识边
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeEdge {
    /// 目标节点ID
    pub target_id: String,
    /// 关系类型
    pub relation: String,
    /// 权重
    pub weight: f64,
}

// ======================== AI 学习引擎 ========================

/// AI 学习引擎
#[allow(dead_code)]
pub struct AILearningEngine {
    /// 存储路径
    storage_path: PathBuf,
    /// 操作历史
    operations: Vec<OperationResult>,
    /// 策略库
    strategies: Vec<Strategy>,
    /// 知识图谱
    knowledge: HashMap<String, KnowledgeNode>,
    /// 操作计数器
    counter: u64,
    /// 统计信息
    stats: LearningStats,
}

/// 学习统计
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearningStats {
    /// 总操作次数
    pub total_operations: u32,
    /// 成功次数
    pub success_count: u32,
    /// 失败次数
    pub failure_count: u32,
    /// 按操作类型统计
    pub by_action: HashMap<ActionType, ActionStats>,
    /// 按反作弊统计
    pub by_anti_cheat: HashMap<String, ActionStats>,
    /// 学习曲线（最近10次成功率）
    pub learning_curve: Vec<f64>,
}

/// 操作统计
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionStats {
    pub total: u32,
    pub success: u32,
    pub failure: u32,
    pub success_rate: f64,
    pub avg_duration_ms: u64,
}

impl AILearningEngine {
    /// 创建新的学习引擎
    pub fn new(storage_path: Option<PathBuf>) -> Self {
        let path = storage_path.unwrap_or_else(|| {
            if let Ok(data_dir) = std::env::var(if cfg!(windows) { "LOCALAPPDATA" } else { "HOME" }) {
                let mut p = PathBuf::from(data_dir);
                if !cfg!(windows) { p.push(".local/share"); }
                p.push("frida-rust/ai_learning");
                p
            } else {
                PathBuf::from("./ai_learning")
            }
        });

        let mut engine = AILearningEngine {
            storage_path: path,
            operations: Vec::new(),
            strategies: Vec::new(),
            knowledge: HashMap::new(),
            counter: 0,
            stats: LearningStats::new(),
        };

        engine.load();
        engine.init_builtin_knowledge();
        engine
    }

    // ==================== 自动经验收集 ====================

    /// 记录操作（自动调用）
    pub fn record_operation(&mut self, mut op: OperationResult) {
        self.counter += 1;
        op.id = format!("op_{}", self.counter);
        op.timestamp = self.get_timestamp();

        // 更新统计
        self.update_stats(&op);

        // 学习：从成功/失败中提取经验
        if op.success {
            self.learn_from_success(&op);
        } else {
            self.learn_from_failure(&op);
        }

        self.operations.push(op);

        // 自动保存
        if self.operations.len() % 10 == 0 {
            self.save();
        }
    }

    /// 开始记录操作
    pub fn start_operation(&self, action: ActionType, pid: u32, name: &str) -> OperationTracker {
        OperationTracker {
            id: format!("op_{}", self.counter + 1),
            action,
            target_pid: pid,
            target_name: name.to_string(),
            anti_cheat: None,
            strategy: Vec::new(),
            start_time: std::time::Instant::now(),
            metadata: HashMap::new(),
        }
    }

    // ==================== 智能反馈循环 ====================

    /// 从成功中学习
    fn learn_from_success(&mut self, op: &OperationResult) {
        // 查找或创建策略
        let strategy_id = format!("{}_{}", 
            format!("{:?}", op.action).to_lowercase(),
            op.anti_cheat.as_deref().unwrap_or("default")
        );
        let timestamp = self.get_timestamp();
        let new_steps = self.generate_steps_from_success(op);

        if let Some(strategy) = self.strategies.iter_mut().find(|s| s.id == strategy_id) {
            strategy.success_count += 1;
            strategy.usage_count += 1;
            strategy.success_rate = strategy.success_count as f64 / strategy.usage_count as f64;
            strategy.last_used = op.timestamp;
            strategy.avg_duration_ms = (strategy.avg_duration_ms + op.duration_ms) / 2;
        } else {
            // 创建新策略
            self.strategies.push(Strategy {
                id: strategy_id,
                name: format!("{:?} - {}", op.action, op.anti_cheat.as_deref().unwrap_or("default")),
                actions: vec![op.action.clone()],
                anti_cheats: op.anti_cheat.iter().cloned().collect(),
                steps: new_steps,
                success_rate: 1.0,
                usage_count: 1,
                success_count: 1,
                avg_duration_ms: op.duration_ms,
                last_used: timestamp,
                priority: 5,
            });
        }

        // 更新知识图谱
        if let Some(ref ac) = op.anti_cheat {
            self.update_knowledge_for_success(ac, op);
        }
    }

    /// 从失败中学习
    fn learn_from_failure(&mut self, op: &OperationResult) {
        // 更新策略统计
        let strategy_id = format!("{}_{}", 
            format!("{:?}", op.action).to_lowercase(),
            op.anti_cheat.as_deref().unwrap_or("default")
        );

        if let Some(strategy) = self.strategies.iter_mut().find(|s| s.id == strategy_id) {
            strategy.usage_count += 1;
            strategy.success_rate = strategy.success_count as f64 / strategy.usage_count as f64;
            strategy.last_used = op.timestamp;
        }

        // 分析失败原因
        if let Some(ref error) = op.error {
            self.analyze_failure_reason(error, op);
        }

        // 更新知识图谱
        if let Some(ref ac) = op.anti_cheat {
            self.update_knowledge_for_failure(ac, op);
        }
    }

    /// 分析失败原因
    fn analyze_failure_reason(&mut self, error: &str, _op: &OperationResult) {
        let error_lower = error.to_lowercase();
        let timestamp = self.get_timestamp();

        // 常见失败模式
        let patterns = vec![
            ("permission denied", "权限不足", "需要 root 权限"),
            ("not found", "目标不存在", "检查进程/模块是否存在"),
            ("timeout", "超时", "增加超时时间或重试"),
            ("detected", "被检测", "应用反检测措施"),
            ("anti-cheat", "反作弊拦截", "使用更强的反检测"),
            ("crash", "崩溃", "检查参数是否正确"),
        ];

        for (pattern, reason, suggestion) in patterns {
            if error_lower.contains(pattern) {
                let node_id = format!("error_{}", pattern.replace(" ", "_"));
                if !self.knowledge.contains_key(&node_id) {
                    self.knowledge.insert(node_id.clone(), KnowledgeNode {
                        id: node_id,
                        node_type: KnowledgeNodeType::DetectionMethod,
                        name: reason.to_string(),
                        description: format!("错误模式: {} -> {}", error, suggestion),
                        connections: Vec::new(),
                        confidence: 0.8,
                        updated_at: timestamp,
                    });
                }
            }
        }
    }

    // ==================== 策略迭代优化 ====================

    /// 获取推荐策略
    pub fn recommend_strategy(&self, action: &ActionType, anti_cheat: Option<&str>) -> Vec<&Strategy> {
        let mut candidates: Vec<&Strategy> = self.strategies.iter()
            .filter(|s| s.actions.contains(action))
            .filter(|s| {
                if let Some(ac) = anti_cheat {
                    s.anti_cheats.is_empty() || s.anti_cheats.contains(&ac.to_string())
                } else {
                    true
                }
            })
            .collect();

        // 按成功率和优先级排序
        candidates.sort_by(|a, b| {
            let score_a = a.success_rate * 0.7 + (a.priority as f64 / 10.0) * 0.3;
            let score_b = b.success_rate * 0.7 + (b.priority as f64 / 10.0) * 0.3;
            score_b.partial_cmp(&score_a).unwrap_or(std::cmp::Ordering::Equal)
        });

        candidates
    }

    /// 优化策略（定期调用）
    pub fn optimize_strategies(&mut self) {
        let now = self.get_timestamp();

        for strategy in &mut self.strategies {
            // 降低长期未使用策略的优先级
            if now - strategy.last_used > 86400 * 7 {  // 7天
                strategy.priority = strategy.priority.saturating_sub(1);
            }

            // 提升高成功率策略的优先级
            if strategy.success_rate > 0.8 && strategy.usage_count >= 5 {
                strategy.priority = (strategy.priority + 1).min(10);
            }
        }
    }

    // ==================== 知识图谱 ====================

    /// 更新成功知识
    fn update_knowledge_for_success(&mut self, anti_cheat: &str, op: &OperationResult) {
        let ac_id = format!("ac_{}", anti_cheat.to_lowercase().replace(" ", "_"));
        let timestamp = self.get_timestamp();

        // 添加/更新反作弊节点
        if !self.knowledge.contains_key(&ac_id) {
            self.knowledge.insert(ac_id.clone(), KnowledgeNode {
                id: ac_id.clone(),
                node_type: KnowledgeNodeType::AntiCheat,
                name: anti_cheat.to_string(),
                description: String::new(),
                connections: Vec::new(),
                confidence: 0.5,
                updated_at: timestamp,
            });
        }

        // 添加绕过方法节点
        let bypass_id = format!("bypass_{:?}_{:?}", op.action, anti_cheat).to_lowercase();
        if !self.knowledge.contains_key(&bypass_id) {
            self.knowledge.insert(bypass_id.clone(), KnowledgeNode {
                id: bypass_id,
                node_type: KnowledgeNodeType::BypassMethod,
                name: format!("{:?} 绕过", op.action),
                description: format!("成功绕过 {} 的 {:?}", anti_cheat, op.action),
                connections: vec![KnowledgeEdge {
                    target_id: ac_id,
                    relation: "绕过".to_string(),
                    weight: 1.0,
                }],
                confidence: 0.9,
                updated_at: timestamp,
            });
        }
    }

    /// 更新失败知识
    fn update_knowledge_for_failure(&mut self, anti_cheat: &str, _op: &OperationResult) {
        let ac_id = format!("ac_{}", anti_cheat.to_lowercase().replace(" ", "_"));

        if let Some(node) = self.knowledge.get_mut(&ac_id) {
            node.confidence = (node.confidence + 0.1).min(1.0);
        }
    }

    /// 查询知识
    pub fn query_knowledge(&self, anti_cheat: &str) -> KnowledgeReport {
        let ac_id = format!("ac_{}", anti_cheat.to_lowercase().replace(" ", "_"));

        let mut report = KnowledgeReport {
            anti_cheat: anti_cheat.to_string(),
            detection_methods: Vec::new(),
            bypass_methods: Vec::new(),
            related_games: Vec::new(),
            confidence: 0.0,
        };

        if let Some(ac_node) = self.knowledge.get(&ac_id) {
            report.confidence = ac_node.confidence;

            // 查找关联的检测和绕过方法
            for (_id, node) in &self.knowledge {
                for edge in &node.connections {
                    if edge.target_id == ac_id {
                        match node.node_type {
                            KnowledgeNodeType::DetectionMethod => {
                                report.detection_methods.push(node.name.clone());
                            }
                            KnowledgeNodeType::BypassMethod => {
                                report.bypass_methods.push(node.name.clone());
                            }
                            KnowledgeNodeType::Game => {
                                report.related_games.push(node.name.clone());
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        report
    }

    // ==================== 辅助方法 ====================

    fn generate_steps_from_success(&self, op: &OperationResult) -> Vec<StrategyStep> {
        vec![StrategyStep {
            name: format!("{:?}", op.action),
            description: format!("执行 {:?}", op.action),
            tool: format!("{:?}_tool", op.action).to_lowercase(),
            params: HashMap::new(),
            required: true,
            fallback: None,
        }]
    }

    fn update_stats(&mut self, op: &OperationResult) {
        self.stats.total_operations += 1;

        if op.success {
            self.stats.success_count += 1;
        } else {
            self.stats.failure_count += 1;
        }

        // 更新学习曲线
        self.stats.learning_curve.push(if op.success { 1.0 } else { 0.0 });
        if self.stats.learning_curve.len() > 10 {
            self.stats.learning_curve.remove(0);
        }

        // 按操作类型统计
        let action_stats = self.stats.by_action.entry(op.action.clone()).or_insert_with(|| ActionStats {
            total: 0, success: 0, failure: 0, success_rate: 0.0, avg_duration_ms: 0,
        });
        action_stats.total += 1;
        if op.success { action_stats.success += 1; } else { action_stats.failure += 1; }
        action_stats.success_rate = action_stats.success as f64 / action_stats.total as f64;
        action_stats.avg_duration_ms = (action_stats.avg_duration_ms + op.duration_ms) / 2;

        // 按反作弊统计
        if let Some(ref ac) = op.anti_cheat {
            let ac_stats = self.stats.by_anti_cheat.entry(ac.clone()).or_insert_with(|| ActionStats {
                total: 0, success: 0, failure: 0, success_rate: 0.0, avg_duration_ms: 0,
            });
            ac_stats.total += 1;
            if op.success { ac_stats.success += 1; } else { ac_stats.failure += 1; }
            ac_stats.success_rate = ac_stats.success as f64 / ac_stats.total as f64;
        }
    }

    fn get_timestamp(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    // ==================== 报告生成 ====================

    /// 生成学习报告
    pub fn report(&self) -> String {
        let mut report = String::from("=== AI 学习报告 ===\n\n");

        report.push_str(&format!("📊 总体统计:\n"));
        report.push_str(&format!("  总操作: {}\n", self.stats.total_operations));
        report.push_str(&format!("  成功: {} ({:.0}%)\n", 
            self.stats.success_count,
            if self.stats.total_operations > 0 { 
                self.stats.success_count as f64 / self.stats.total_operations as f64 * 100.0 
            } else { 0.0 }
        ));
        report.push_str(&format!("  失败: {}\n", self.stats.failure_count));
        report.push_str(&format!("  策略数: {}\n", self.strategies.len()));
        report.push_str(&format!("  知识节点: {}\n\n", self.knowledge.len()));

        report.push_str("📈 学习曲线 (最近10次):\n  ");
        for &val in &self.stats.learning_curve {
            report.push_str(if val > 0.5 { "█" } else { "░" });
        }
        report.push_str("\n\n");

        report.push_str("🎯 按操作类型:\n");
        for (action, stats) in &self.stats.by_action {
            report.push_str(&format!("  {:?}: {}次, {:.0}%\n", action, stats.total, stats.success_rate * 100.0));
        }

        report.push_str("\n🛡️ 按反作弊:\n");
        for (ac, stats) in &self.stats.by_anti_cheat {
            report.push_str(&format!("  {}: {}次, {:.0}%\n", ac, stats.total, stats.success_rate * 100.0));
        }

        report
    }

    // ==================== 内置知识库 ====================

    fn init_builtin_knowledge(&mut self) {
        // 腾讯 ACE
        self.knowledge.insert("ac_tencent_ace".to_string(), KnowledgeNode {
            id: "ac_tencent_ace".to_string(),
            node_type: KnowledgeNodeType::AntiCheat,
            name: "腾讯 ACE".to_string(),
            description: "腾讯游戏反作弊专家".to_string(),
            connections: Vec::new(),
            confidence: 0.9,
            updated_at: self.get_timestamp(),
        });

        // 米哈游
        self.knowledge.insert("ac_mihoyo".to_string(), KnowledgeNode {
            id: "ac_mihoyo".to_string(),
            node_type: KnowledgeNodeType::AntiCheat,
            name: "米哈游 Protect".to_string(),
            description: "米哈游游戏保护".to_string(),
            connections: Vec::new(),
            confidence: 0.85,
            updated_at: self.get_timestamp(),
        });
    }

    // ==================== 持久化 ====================

    fn save(&self) {
        // TODO: 保存到文件
    }

    fn load(&mut self) {
        // TODO: 从文件加载
    }
}

/// 操作追踪器
pub struct OperationTracker {
    id: String,
    action: ActionType,
    target_pid: u32,
    target_name: String,
    anti_cheat: Option<String>,
    strategy: Vec<String>,
    start_time: std::time::Instant,
    metadata: HashMap<String, String>,
}

impl OperationTracker {
    /// 设置反作弊类型
    pub fn with_anti_cheat(mut self, anti_cheat: &str) -> Self {
        self.anti_cheat = Some(anti_cheat.to_string());
        self
    }

    /// 添加策略步骤
    pub fn with_strategy(mut self, step: &str) -> Self {
        self.strategy.push(step.to_string());
        self
    }

    /// 完成操作
    pub fn finish(self, success: bool, error: Option<String>) -> OperationResult {
        OperationResult {
            id: self.id,
            timestamp: 0,
            action: self.action,
            target_pid: self.target_pid,
            target_name: self.target_name,
            anti_cheat: self.anti_cheat,
            success,
            error,
            strategy: self.strategy,
            duration_ms: self.start_time.elapsed().as_millis() as u64,
            metadata: self.metadata,
        }
    }
}

/// 知识报告
#[derive(Debug)]
pub struct KnowledgeReport {
    pub anti_cheat: String,
    pub detection_methods: Vec<String>,
    pub bypass_methods: Vec<String>,
    pub related_games: Vec<String>,
    pub confidence: f64,
}

impl LearningStats {
    fn new() -> Self {
        LearningStats {
            total_operations: 0,
            success_count: 0,
            failure_count: 0,
            by_action: HashMap::new(),
            by_anti_cheat: HashMap::new(),
            learning_curve: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_learning_engine_creation() {
        let engine = AILearningEngine::new(None);
        assert_eq!(engine.stats.total_operations, 0);
    }

    #[test]
    fn test_record_operation() {
        let mut engine = AILearningEngine::new(None);
        engine.record_operation(OperationResult {
            id: "test".to_string(),
            timestamp: 0,
            action: ActionType::Hook,
            target_pid: 1234,
            target_name: "test.exe".to_string(),
            anti_cheat: None,
            success: true,
            error: None,
            strategy: Vec::new(),
            duration_ms: 100,
            metadata: HashMap::new(),
        });
        assert_eq!(engine.stats.total_operations, 1);
        assert_eq!(engine.stats.success_count, 1);
    }
}
