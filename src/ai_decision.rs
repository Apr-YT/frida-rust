//! 智能决策引擎（决策层）
//!
//! 基于大模型的智能决策系统，整合内核感知层数据，
//! 实现自主决策与行动能力。
//!
//! 核心能力：
//! - 大模型上下文管理（会话历史、消息队列）
//! - 智能决策引擎（策略推理、风险评估、行动规划）
//! - 上下文感知（实时状态监测、环境感知）
//! - 自适应学习（从经验中优化决策）

use crate::ai_learning::{ActionType, OperationResult, Strategy};
#[cfg(test)]
use crate::ai_learning::StrategyStep;
#[cfg(any(target_os = "linux", target_os = "android"))]
use crate::memory::kernel_scanner::{DetectedMessage, MessageAnalysis, MessageFormat};
use crate::Result;
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(not(any(target_os = "linux", target_os = "android")))]
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

#[cfg(not(any(target_os = "linux", target_os = "android")))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MessageFormat {
    Json,
    ProtoBuf,
    Binary,
    String,
    Unknown,
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageAnalysis {
    pub total_messages: usize,
    pub by_format: HashMap<MessageFormat, usize>,
    pub by_tag: HashMap<String, usize>,
    pub keywords: Vec<(String, usize)>,
    pub suspicious_patterns: Vec<String>,
    pub timestamp: u64,
}

// ======================== 决策数据结构 ========================

/// 决策类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DecisionType {
    None,
    Continue,
    Stop,
    Retry,
    SwitchStrategy,
    Alert,
    ExecuteAction,
}

/// 决策结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionResult {
    pub decision_type: DecisionType,
    pub action: Option<ActionType>,
    pub strategy_id: Option<String>,
    pub confidence: f64,
    pub reason: String,
    pub metadata: HashMap<String, String>,
    pub timestamp: u64,
}

/// 上下文状态
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextState {
    pub pid: u32,
    pub process_name: String,
    pub is_attached: bool,
    pub is_injected: bool,
    pub anti_cheat_detected: bool,
    pub anti_cheat_name: Option<String>,
    pub kernel_channel_active: bool,
    pub memory_region_count: usize,
    pub detected_message_count: usize,
    pub recent_errors: Vec<String>,
    pub last_action_time: u64,
    pub overall_success_rate: f64,
}

/// 决策上下文
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionContext {
    pub state: ContextState,
    pub recent_messages: Vec<DetectedMessage>,
    pub message_analysis: Option<MessageAnalysis>,
    pub recent_operations: Vec<OperationResult>,
    pub active_strategy: Option<Strategy>,
    pub pending_actions: Vec<ActionType>,
}

/// 对话历史记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationHistory {
    pub messages: VecDeque<ConversationMessage>,
    pub max_length: usize,
    pub last_update: u64,
}

/// 对话消息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationMessage {
    pub role: MessageRole,
    pub content: String,
    pub timestamp: u64,
    pub metadata: HashMap<String, String>,
}

/// 消息角色
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MessageRole {
    System,
    User,
    Assistant,
    Observation,
}

// ======================== 决策引擎配置 ========================

/// 决策引擎配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionEngineConfig {
    pub context_window_size: usize,
    pub max_conversation_length: usize,
    pub confidence_threshold: f64,
    pub risk_threshold: f64,
    pub auto_retry_max: usize,
    pub learning_enabled: bool,
    pub log_level: LogLevel,
}

/// 日志级别
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl Default for DecisionEngineConfig {
    fn default() -> Self {
        DecisionEngineConfig {
            context_window_size: 100,
            max_conversation_length: 50,
            confidence_threshold: 0.6,
            risk_threshold: 0.8,
            auto_retry_max: 3,
            learning_enabled: true,
            log_level: LogLevel::Info,
        }
    }
}

// ======================== 智能决策引擎 ========================

pub struct DecisionEngine {
    config: DecisionEngineConfig,
    context: Mutex<DecisionContext>,
    conversation: Mutex<ConversationHistory>,
    strategy_cache: Mutex<HashMap<String, Strategy>>,
    action_history: Mutex<Vec<OperationResult>>,
    last_decision: Mutex<Option<DecisionResult>>,
}

impl DecisionEngine {
    /// 创建新的决策引擎
    pub fn new(config: Option<DecisionEngineConfig>) -> Self {
        DecisionEngine {
            config: config.unwrap_or_default(),
            context: Mutex::new(DecisionContext {
                state: ContextState {
                    pid: 0,
                    process_name: String::new(),
                    is_attached: false,
                    is_injected: false,
                    anti_cheat_detected: false,
                    anti_cheat_name: None,
                    kernel_channel_active: false,
                    memory_region_count: 0,
                    detected_message_count: 0,
                    recent_errors: Vec::new(),
                    last_action_time: 0,
                    overall_success_rate: 1.0,
                },
                recent_messages: Vec::new(),
                message_analysis: None,
                recent_operations: Vec::new(),
                active_strategy: None,
                pending_actions: Vec::new(),
            }),
            conversation: Mutex::new(ConversationHistory {
                messages: VecDeque::new(),
                max_length: 50,
                last_update: 0,
            }),
            strategy_cache: Mutex::new(HashMap::new()),
            action_history: Mutex::new(Vec::new()),
            last_decision: Mutex::new(None),
        }
    }

    /// 更新上下文状态
    pub fn update_state(&self, state: ContextState) {
        let pid = state.pid;
        let mut ctx = self.context.lock().unwrap();
        ctx.state = state;
        self.log(LogLevel::Debug, &format!("状态更新: PID={}", pid));
    }

    /// 获取当前上下文状态
    pub fn get_state(&self) -> ContextState {
        self.context.lock().unwrap().state.clone()
    }

    /// 添加检测到的消息
    pub fn add_messages(&self, messages: &[DetectedMessage]) {
        let count = messages.len();
        let mut ctx = self.context.lock().unwrap();
        ctx.recent_messages.extend_from_slice(messages);
        ctx.state.detected_message_count += count;

        while ctx.recent_messages.len() > self.config.context_window_size {
            ctx.recent_messages.remove(0);
        }

        self.log(LogLevel::Debug, &format!("添加 {} 条消息", count));
    }

    /// 更新消息分析结果
    pub fn update_message_analysis(&self, analysis: MessageAnalysis) {
        let analysis_clone = analysis.clone();
        let mut ctx = self.context.lock().unwrap();
        ctx.message_analysis = Some(analysis);

        let mut conv = self.conversation.lock().unwrap();
        conv.add_message(MessageRole::Observation, &format!(
            "消息分析: {} 条消息, 关键词: {:?}",
            analysis_clone.total_messages,
            analysis_clone.keywords
        ));
    }

    /// 添加操作结果
    pub fn add_operation_result(&self, result: OperationResult) {
        let error_str = result.error.clone().unwrap_or_default();
        let is_success = result.success;
        let action_str = format!("{:?}", result.action);
        
        let mut ctx = self.context.lock().unwrap();
        ctx.recent_operations.push(result.clone());
        ctx.state.last_action_time = self.get_timestamp();

        while ctx.recent_operations.len() > self.config.context_window_size {
            ctx.recent_operations.remove(0);
        }

        let mut history = self.action_history.lock().unwrap();
        history.push(result.clone());

        ctx.state.overall_success_rate = self.calculate_success_rate(&history);

        let mut conv = self.conversation.lock().unwrap();
        let role = if is_success { MessageRole::Observation } else { MessageRole::System };
        conv.add_message(role, &format!(
            "操作结果: {} {} - {}",
            if is_success { "成功" } else { "失败" },
            action_str,
            error_str
        ));

        if !is_success {
            ctx.state.recent_errors.push(result.error.unwrap_or("未知错误".to_string()));
            while ctx.state.recent_errors.len() > 10 {
                ctx.state.recent_errors.remove(0);
            }
        }

        self.log(LogLevel::Info, &format!(
            "操作: {} - {}",
            if is_success { "成功" } else { "失败" },
            action_str
        ));
    }

    /// 计算成功率
    fn calculate_success_rate(&self, history: &[OperationResult]) -> f64 {
        if history.is_empty() {
            return 1.0;
        }

        let len = history.len();
        let start = len.saturating_sub(100);
        let recent = &history[start..];
        let success = recent.iter().filter(|r| r.success).count() as f64;
        success / recent.len() as f64
    }

    /// 注册策略
    pub fn register_strategy(&self, strategy: Strategy) {
        let name = strategy.name.clone();
        let mut cache = self.strategy_cache.lock().unwrap();
        cache.insert(strategy.id.clone(), strategy);
        self.log(LogLevel::Info, &format!("注册策略: {}", name));
    }

    /// 获取策略
    pub fn get_strategy(&self, id: &str) -> Option<Strategy> {
        let cache = self.strategy_cache.lock().unwrap();
        cache.get(id).cloned()
    }

    /// 设置当前策略
    pub fn set_active_strategy(&self, strategy: Option<Strategy>) {
        let mut ctx = self.context.lock().unwrap();
        ctx.active_strategy = strategy.clone();

        if let Some(s) = &strategy {
            let mut conv = self.conversation.lock().unwrap();
            conv.add_message(MessageRole::System, &format!("激活策略: {}", s.name));
            self.log(LogLevel::Info, &format!("激活策略: {}", s.name));
        }
    }

    /// 添加待执行动作
    pub fn add_pending_action(&self, action: ActionType) {
        let mut ctx = self.context.lock().unwrap();
        ctx.pending_actions.push(action);
    }

    /// 获取待执行动作
    pub fn get_pending_actions(&self) -> Vec<ActionType> {
        let ctx = self.context.lock().unwrap();
        ctx.pending_actions.clone()
    }

    /// 清除待执行动作
    pub fn clear_pending_actions(&self) {
        let mut ctx = self.context.lock().unwrap();
        ctx.pending_actions.clear();
    }

    /// 执行智能决策
    pub fn make_decision(&self) -> DecisionResult {
        let ctx = self.context.lock().unwrap();
        let history = self.action_history.lock().unwrap();
        let conv = self.conversation.lock().unwrap();

        let decision = self.reason(&ctx, &history, &conv);

        drop(ctx);
        drop(history);
        drop(conv);

        let mut last = self.last_decision.lock().unwrap();
        *last = Some(decision.clone());

        let mut conv = self.conversation.lock().unwrap();
        conv.add_message(MessageRole::Assistant, &format!(
            "决策: {:?} (置信度: {:.2}) - {}",
            decision.decision_type, decision.confidence, decision.reason
        ));

        self.log(LogLevel::Info, &format!(
            "决策: {:?} - {}",
            decision.decision_type, decision.reason
        ));

        decision
    }

    /// 核心推理逻辑
    fn reason(
        &self,
        ctx: &DecisionContext,
        _history: &[OperationResult],
        _conv: &ConversationHistory,
    ) -> DecisionResult {
        let mut reasons = Vec::new();
        let anti_cheat_penalty = if ctx.state.anti_cheat_detected {
            reasons.push("检测到反作弊系统".to_string());
            0.1
        } else {
            0.0
        };

        if ctx.state.recent_errors.len() >= 3 {
            reasons.push("连续失败超过3次".to_string());
            let confidence = f64::max(0.8 - anti_cheat_penalty, 0.0);

            return DecisionResult {
                decision_type: DecisionType::Stop,
                action: None,
                strategy_id: None,
                confidence,
                reason: reasons.join("; "),
                metadata: HashMap::new(),
                timestamp: self.get_timestamp(),
            };
        }

        if ctx.state.overall_success_rate < 0.5 {
            reasons.push("整体成功率低于50%".to_string());
            let confidence = f64::max(0.75 - anti_cheat_penalty, 0.0);

            if let Some(strategy) = &ctx.active_strategy {
                return DecisionResult {
                    decision_type: DecisionType::SwitchStrategy,
                    action: None,
                    strategy_id: Some(strategy.id.clone()),
                    confidence,
                    reason: reasons.join("; "),
                    metadata: HashMap::new(),
                    timestamp: self.get_timestamp(),
                };
            }
        }

        if !ctx.state.is_attached {
            reasons.push("未附着目标进程".to_string());
            let confidence = f64::max(0.9 - anti_cheat_penalty, 0.0);

            return DecisionResult {
                decision_type: DecisionType::ExecuteAction,
                action: Some(ActionType::Attach),
                strategy_id: None,
                confidence,
                reason: reasons.join("; "),
                metadata: HashMap::new(),
                timestamp: self.get_timestamp(),
            };
        }

        if !ctx.state.is_injected {
            reasons.push("未注入agent".to_string());
            let confidence = f64::max(0.9 - anti_cheat_penalty, 0.0);

            return DecisionResult {
                decision_type: DecisionType::ExecuteAction,
                action: Some(ActionType::Inject),
                strategy_id: None,
                confidence,
                reason: reasons.join("; "),
                metadata: HashMap::new(),
                timestamp: self.get_timestamp(),
            };
        }

        if !ctx.state.kernel_channel_active && ctx.state.detected_message_count == 0 {
            reasons.push("内核通道未激活，无法获取消息".to_string());
            let confidence = f64::max(0.6 - anti_cheat_penalty, 0.0);

            return DecisionResult {
                decision_type: DecisionType::ExecuteAction,
                action: Some(ActionType::StealthApply),
                strategy_id: None,
                confidence,
                reason: reasons.join("; "),
                metadata: HashMap::new(),
                timestamp: self.get_timestamp(),
            };
        }

        if !ctx.pending_actions.is_empty() {
            let action = ctx.pending_actions[0].clone();
            reasons.push(format!("有待执行动作: {:?}", action));
            let confidence = f64::max(0.85 - anti_cheat_penalty, 0.0);

            return DecisionResult {
                decision_type: DecisionType::ExecuteAction,
                action: Some(action),
                strategy_id: None,
                confidence,
                reason: reasons.join("; "),
                metadata: HashMap::new(),
                timestamp: self.get_timestamp(),
            };
        }

        if let Some(analysis) = &ctx.message_analysis {
            if !analysis.suspicious_patterns.is_empty() {
                reasons.push(format!("检测到可疑模式: {:?}", analysis.suspicious_patterns));
                let confidence = f64::max(0.7 - anti_cheat_penalty, 0.0);

                return DecisionResult {
                    decision_type: DecisionType::Alert,
                    action: None,
                    strategy_id: None,
                    confidence,
                    reason: reasons.join("; "),
                    metadata: HashMap::new(),
                    timestamp: self.get_timestamp(),
                };
            }
        }

        if ctx.state.last_action_time > 0 && self.get_timestamp() - ctx.state.last_action_time > 60 {
            reasons.push("超过60秒未执行操作".to_string());
            let confidence = f64::max(0.6 - anti_cheat_penalty, 0.0);

            return DecisionResult {
                decision_type: DecisionType::ExecuteAction,
                action: Some(ActionType::MemoryRead),
                strategy_id: None,
                confidence,
                reason: reasons.join("; "),
                metadata: HashMap::new(),
                timestamp: self.get_timestamp(),
            };
        }

        reasons.push("当前状态正常，继续监控".to_string());
        let confidence = f64::max(0.55 - anti_cheat_penalty, 0.0);

        DecisionResult {
            decision_type: DecisionType::Continue,
            action: None,
            strategy_id: None,
            confidence,
            reason: reasons.join("; "),
            metadata: HashMap::new(),
            timestamp: self.get_timestamp(),
        }
    }

    /// 获取最近的决策结果
    pub fn get_last_decision(&self) -> Option<DecisionResult> {
        self.last_decision.lock().unwrap().clone()
    }

    /// 添加对话消息
    pub fn add_conversation_message(&self, role: MessageRole, content: &str) {
        let mut conv = self.conversation.lock().unwrap();
        conv.add_message(role, content);
    }

    /// 获取对话历史
    pub fn get_conversation_history(&self) -> Vec<ConversationMessage> {
        let conv = self.conversation.lock().unwrap();
        conv.messages.clone().into_iter().collect()
    }

    /// 清空对话历史
    pub fn clear_conversation(&self) {
        let mut conv = self.conversation.lock().unwrap();
        conv.messages.clear();
    }

    /// 获取时间戳
    fn get_timestamp(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// 日志记录
    fn log(&self, level: LogLevel, message: &str) {
        if level as u8 <= self.config.log_level as u8 {
            match level {
                LogLevel::Trace => log::trace!("决策引擎: {}", message),
                LogLevel::Debug => log::debug!("决策引擎: {}", message),
                LogLevel::Info => log::info!("决策引擎: {}", message),
                LogLevel::Warn => log::warn!("决策引擎: {}", message),
                LogLevel::Error => log::error!("决策引擎: {}", message),
            }
        }
    }

    /// 获取配置
    pub fn config(&self) -> &DecisionEngineConfig {
        &self.config
    }

    /// 获取策略列表
    pub fn get_strategy_list(&self) -> Vec<Strategy> {
        let cache = self.strategy_cache.lock().unwrap();
        cache.values().cloned().collect()
    }
}

// ======================== 对话历史实现 ========================

impl ConversationHistory {
    /// 添加消息
    pub fn add_message(&mut self, role: MessageRole, content: &str) {
        self.messages.push_back(ConversationMessage {
            role,
            content: content.to_string(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            metadata: HashMap::new(),
        });

        while self.messages.len() > self.max_length {
            self.messages.pop_front();
        }

        self.last_update = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }

    /// 获取最近的消息
    pub fn get_recent(&self, count: usize) -> Vec<ConversationMessage> {
        let start = self.messages.len().saturating_sub(count);
        self.messages.iter().skip(start).cloned().collect()
    }

    /// 转换为文本格式
    pub fn to_text(&self) -> String {
        self.messages
            .iter()
            .map(|msg| format!("[{:?}] {}", msg.role, msg.content))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

// ======================== 策略执行器 ========================

/// 策略执行器
pub struct StrategyExecutor {
    engine: Arc<DecisionEngine>,
    current_step: usize,
    strategy: Strategy,
}

impl StrategyExecutor {
    /// 创建策略执行器
    pub fn new(engine: Arc<DecisionEngine>, strategy: Strategy) -> Self {
        StrategyExecutor {
            engine,
            current_step: 0,
            strategy,
        }
    }

    /// 执行下一步
    pub fn execute_next_step(&mut self) -> Result<DecisionResult> {
        if self.current_step >= self.strategy.steps.len() {
            return Ok(DecisionResult {
                decision_type: DecisionType::Stop,
                action: None,
                strategy_id: Some(self.strategy.id.clone()),
                confidence: 0.9,
                reason: "策略执行完成".to_string(),
                metadata: HashMap::new(),
                timestamp: self.engine.get_timestamp(),
            });
        }

        let step = &self.strategy.steps[self.current_step];
        self.current_step += 1;

        if step.required {
            self.engine.add_pending_action(ActionType::Hook);
            let decision = self.engine.make_decision();
            Ok(decision)
        } else {
            Ok(DecisionResult {
                decision_type: DecisionType::Continue,
                action: None,
                strategy_id: Some(self.strategy.id.clone()),
                confidence: 0.7,
                reason: format!("执行步骤 {}: {}", self.current_step, step.description),
                metadata: HashMap::new(),
                timestamp: self.engine.get_timestamp(),
            })
        }
    }

    /// 获取当前步骤
    pub fn current_step(&self) -> usize {
        self.current_step
    }

    /// 获取总步骤数
    pub fn total_steps(&self) -> usize {
        self.strategy.steps.len()
    }

    /// 重置执行器
    pub fn reset(&mut self) {
        self.current_step = 0;
    }

    /// 获取策略
    pub fn strategy(&self) -> &Strategy {
        &self.strategy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_creation() {
        let engine = DecisionEngine::new(None);
        assert_eq!(engine.config().context_window_size, 100);
    }

    #[test]
    fn test_state_update() {
        let engine = DecisionEngine::new(None);
        let state = ContextState {
            pid: 1234,
            process_name: "test".to_string(),
            is_attached: true,
            is_injected: false,
            anti_cheat_detected: false,
            anti_cheat_name: None,
            kernel_channel_active: true,
            memory_region_count: 10,
            detected_message_count: 5,
            recent_errors: Vec::new(),
            last_action_time: 0,
            overall_success_rate: 1.0,
        };

        engine.update_state(state.clone());
        let retrieved = engine.get_state();
        assert_eq!(retrieved.pid, state.pid);
        assert_eq!(retrieved.is_attached, state.is_attached);
    }

    #[test]
    fn test_decision_logic() {
        let engine = DecisionEngine::new(None);
        let state = ContextState {
            pid: 1234,
            process_name: "test".to_string(),
            is_attached: false,
            is_injected: false,
            anti_cheat_detected: false,
            anti_cheat_name: None,
            kernel_channel_active: false,
            memory_region_count: 0,
            detected_message_count: 0,
            recent_errors: Vec::new(),
            last_action_time: 0,
            overall_success_rate: 1.0,
        };

        engine.update_state(state);
        let decision = engine.make_decision();

        assert_eq!(decision.decision_type, DecisionType::ExecuteAction);
        assert_eq!(decision.action, Some(ActionType::Attach));
        assert!(decision.confidence >= 0.8);
    }

    #[test]
    fn test_conversation_history() {
        let mut history = ConversationHistory {
            messages: VecDeque::new(),
            max_length: 5,
            last_update: 0,
        };

        for i in 0..10 {
            history.add_message(MessageRole::User, &format!("消息 {}", i));
        }

        assert_eq!(history.messages.len(), 5);
        assert!(history.messages.front().unwrap().content.contains("消息 5"));
    }

    #[test]
    fn test_strategy_executor() {
        let engine = Arc::new(DecisionEngine::new(None));
        let strategy = Strategy {
            id: "test_strategy".to_string(),
            name: "测试策略".to_string(),
            actions: vec![ActionType::Attach],
            anti_cheats: Vec::new(),
            steps: vec![
                StrategyStep {
                    name: "附着进程".to_string(),
                    description: "附着进程".to_string(),
                    tool: "attach".to_string(),
                    params: HashMap::new(),
                    required: true,
                    fallback: None,
                },
            ],
            success_rate: 0.8,
            usage_count: 10,
            success_count: 8,
            avg_duration_ms: 100,
            last_used: 0,
            priority: 1,
        };

        let mut executor = StrategyExecutor::new(engine, strategy);
        let result = executor.execute_next_step();

        assert!(result.is_ok());
        assert_eq!(executor.current_step(), 1);
    }
}