//! Web UI 模块
//!
//! 提供实时 AI 执行步骤可视化界面
//! - 实时日志流
//! - AI 学习进度显示
//! - 操作历史查看
//! - 知识图谱可视化

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use serde::{Serialize, Deserialize};

// ======================== 日志条目 ========================

/// 日志级别
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LogLevel {
    Info,
    Success,
    Warning,
    Error,
    Debug,
}

/// 日志条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// 时间戳
    pub timestamp: u64,
    /// 日志级别
    pub level: LogLevel,
    /// 模块名称
    pub module: String,
    /// 消息内容
    pub message: String,
    /// 附加数据
    pub details: Option<String>,
    /// 执行时间（毫秒）
    pub duration_ms: Option<u64>,
}

/// AI 执行步骤
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIStep {
    /// 步骤ID
    pub id: String,
    /// 步骤名称
    pub name: String,
    /// 步骤状态
    pub status: StepStatus,
    /// 开始时间
    pub started_at: u64,
    /// 结束时间
    pub finished_at: Option<u64>,
    /// 子步骤
    pub substeps: Vec<SubStep>,
    /// 日志
    pub logs: Vec<LogEntry>,
}

/// 子步骤
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubStep {
    pub name: String,
    pub status: StepStatus,
    pub message: String,
    pub duration_ms: u64,
}

/// 步骤状态
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum StepStatus {
    Pending,
    Running,
    Success,
    Failed,
    Skipped,
}

// ======================== Web UI 服务器 ========================

/// Web UI 配置
#[derive(Debug, Clone)]
pub struct WebUIConfig {
    /// 监听端口
    pub port: u16,
    /// 是否启用
    pub enabled: bool,
    /// 最大日志数
    pub max_logs: usize,
}

impl Default for WebUIConfig {
    fn default() -> Self {
        WebUIConfig {
            port: 8080,
            enabled: true,
            max_logs: 1000,
        }
    }
}

/// Web UI 服务器
pub struct WebUIServer {
    config: WebUIConfig,
    logs: Arc<Mutex<VecDeque<LogEntry>>>,
    steps: Arc<Mutex<Vec<AIStep>>>,
    start_time: Instant,
}

impl WebUIServer {
    /// 创建新的 Web UI 服务器
    pub fn new(config: WebUIConfig) -> Self {
        WebUIServer {
            config,
            logs: Arc::new(Mutex::new(VecDeque::new())),
            steps: Arc::new(Mutex::new(Vec::new())),
            start_time: Instant::now(),
        }
    }

    /// 记录日志
    pub fn log(&self, level: LogLevel, module: &str, message: &str, details: Option<String>) {
        let entry = LogEntry {
            timestamp: self.get_timestamp(),
            level,
            module: module.to_string(),
            message: message.to_string(),
            details,
            duration_ms: None,
        };

        let mut logs = self.logs.lock().unwrap();
        if logs.len() >= self.config.max_logs {
            logs.pop_front();
        }
        logs.push_back(entry);
    }

    /// 记录信息日志
    pub fn info(&self, module: &str, message: &str) {
        self.log(LogLevel::Info, module, message, None);
    }

    /// 记录成功日志
    pub fn success(&self, module: &str, message: &str) {
        self.log(LogLevel::Success, module, message, None);
    }

    /// 记录警告日志
    pub fn warning(&self, module: &str, message: &str) {
        self.log(LogLevel::Warning, module, message, None);
    }

    /// 记录错误日志
    pub fn error(&self, module: &str, message: &str) {
        self.log(LogLevel::Error, module, message, None);
    }

    /// 开始新步骤
    pub fn begin_step(&self, name: &str) -> String {
        let id = format!("step_{}", self.steps.lock().unwrap().len() + 1);
        let step = AIStep {
            id: id.clone(),
            name: name.to_string(),
            status: StepStatus::Running,
            started_at: self.get_timestamp(),
            finished_at: None,
            substeps: Vec::new(),
            logs: Vec::new(),
        };

        self.steps.lock().unwrap().push(step);
        self.info("AI", &format!("▶ 开始: {}", name));

        id
    }

    /// 完成步骤
    pub fn end_step(&self, step_id: &str, success: bool) {
        let mut steps = self.steps.lock().unwrap();
        if let Some(step) = steps.iter_mut().find(|s| s.id == step_id) {
            step.status = if success { StepStatus::Success } else { StepStatus::Failed };
            step.finished_at = Some(self.get_timestamp());

            let status_icon = if success { "✅" } else { "❌" };
            let status_msg = if success { "成功" } else { "失败" };
            self.info("AI", &format!("{} 完成: {} ({})", status_icon, step.name, status_msg));
        }
    }

    /// 添加子步骤
    pub fn add_substep(&self, step_id: &str, name: &str, message: &str, duration_ms: u64) {
        let mut steps = self.steps.lock().unwrap();
        if let Some(step) = steps.iter_mut().find(|s| s.id == step_id) {
            step.substeps.push(SubStep {
                name: name.to_string(),
                status: StepStatus::Success,
                message: message.to_string(),
                duration_ms,
            });

            self.info("AI", &format!("  ├─ {}: {}", name, message));
        }
    }

    /// 获取日志列表
    pub fn get_logs(&self, limit: usize) -> Vec<LogEntry> {
        let logs = self.logs.lock().unwrap();
        logs.iter().rev().take(limit).cloned().collect()
    }

    /// 获取步骤列表
    pub fn get_steps(&self) -> Vec<AIStep> {
        self.steps.lock().unwrap().clone()
    }

    /// 获取统计信息
    pub fn get_stats(&self) -> WebUIStats {
        let steps = self.steps.lock().unwrap();
        let logs = self.logs.lock().unwrap();

        let total_steps = steps.len();
        let success_steps = steps.iter().filter(|s| s.status == StepStatus::Success).count();
        let failed_steps = steps.iter().filter(|s| s.status == StepStatus::Failed).count();
        let running_steps = steps.iter().filter(|s| s.status == StepStatus::Running).count();

        WebUIStats {
            uptime_seconds: self.start_time.elapsed().as_secs(),
            total_logs: logs.len(),
            total_steps,
            success_steps,
            failed_steps,
            running_steps,
            success_rate: if total_steps > 0 { success_steps as f64 / total_steps as f64 } else { 0.0 },
        }
    }

    /// 生成 HTML 页面
    pub fn generate_html(&self) -> String {
        let stats = self.get_stats();
        let steps = self.get_steps();
        let logs = self.get_logs(50);

        let mut html = format!(r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Frida-Rust AI 控制面板</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #1a1a2e; 
            color: #eee; 
            padding: 20px;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ 
            text-align: center; 
            margin-bottom: 30px;
            color: #00d4ff;
            text-shadow: 0 0 10px rgba(0, 212, 255, 0.5);
        }}
        .stats {{ 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px; 
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: #16213e;
            border-radius: 10px;
            padding: 20px;
            text-align: center;
            border: 1px solid #0f3460;
        }}
        .stat-value {{ 
            font-size: 2em; 
            font-weight: bold;
            color: #00d4ff;
        }}
        .stat-label {{ 
            font-size: 0.9em;
            color: #888;
            margin-top: 5px;
        }}
        .panel {{
            background: #16213e;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            border: 1px solid #0f3460;
        }}
        .panel-title {{
            font-size: 1.2em;
            font-weight: bold;
            margin-bottom: 15px;
            color: #00d4ff;
            border-bottom: 1px solid #0f3460;
            padding-bottom: 10px;
        }}
        .step {{
            background: #1a1a2e;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 10px;
            border-left: 4px solid #0f3460;
        }}
        .step.success {{ border-left-color: #00ff88; }}
        .step.failed {{ border-left-color: #ff4444; }}
        .step.running {{ border-left-color: #ffaa00; }}
        .step-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}
        .step-name {{ font-weight: bold; }}
        .step-status {{
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
        }}
        .status-success {{ background: #00ff8822; color: #00ff88; }}
        .status-failed {{ background: #ff444422; color: #ff4444; }}
        .status-running {{ background: #ffaa0022; color: #ffaa00; }}
        .substep {{
            margin-left: 20px;
            padding: 8px;
            border-left: 2px solid #0f3460;
            margin-bottom: 5px;
            font-size: 0.9em;
        }}
        .log-entry {{
            padding: 8px;
            border-bottom: 1px solid #0f346022;
            font-family: monospace;
            font-size: 0.9em;
        }}
        .log-info {{ color: #00d4ff; }}
        .log-success {{ color: #00ff88; }}
        .log-warning {{ color: #ffaa00; }}
        .log-error {{ color: #ff4444; }}
        .log-time {{ color: #666; margin-right: 10px; }}
        .log-module {{ color: #888; margin-right: 10px; }}
        .progress-bar {{
            width: 100%;
            height: 20px;
            background: #1a1a2e;
            border-radius: 10px;
            overflow: hidden;
            margin-top: 10px;
        }}
        .progress-fill {{
            height: 100%;
            background: linear-gradient(90deg, #00d4ff, #00ff88);
            transition: width 0.3s ease;
        }}
        .auto-refresh {{
            text-align: center;
            color: #666;
            margin-top: 20px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🤖 Frida-Rust AI 控制面板</h1>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-value">{uptime}s</div>
                <div class="stat-label">运行时间</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{total_steps}</div>
                <div class="stat-label">总步骤</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{success_steps}</div>
                <div class="stat-label">成功</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{failed_steps}</div>
                <div class="stat-label">失败</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{success_rate:.0}%</div>
                <div class="stat-label">成功率</div>
            </div>
        </div>

        <div class="panel">
            <div class="panel-title">📊 学习进度</div>
            <div class="progress-bar">
                <div class="progress-fill" style="width: {success_rate:.0}%"></div>
            </div>
        </div>

        <div class="panel">
            <div class="panel-title">🔄 执行步骤</div>
"#, 
            uptime = stats.uptime_seconds,
            total_steps = stats.total_steps,
            success_steps = stats.success_steps,
            failed_steps = stats.failed_steps,
            success_rate = stats.success_rate * 100.0,
        );

        // 添加步骤
        for step in steps.iter().rev() {
            let status_class = match step.status {
                StepStatus::Success => "success",
                StepStatus::Failed => "failed",
                StepStatus::Running => "running",
                _ => "",
            };
            let status_text = match step.status {
                StepStatus::Success => "✅ 成功",
                StepStatus::Failed => "❌ 失败",
                StepStatus::Running => "⏳ 运行中",
                StepStatus::Pending => "⏸ 等待",
                StepStatus::Skipped => "⏭ 跳过",
            };

            html.push_str(&format!(r#"
            <div class="step {status_class}">
                <div class="step-header">
                    <span class="step-name">{name}</span>
                    <span class="step-status status-{status_class}">{status_text}</span>
                </div>
"#, status_class = status_class, name = step.name, status_text = status_text));

            // 添加子步骤
            for substep in &step.substeps {
                html.push_str(&format!(r#"
                <div class="substep">
                    ├─ {name}: {message} ({duration}ms)
                </div>
"#, name = substep.name, message = substep.message, duration = substep.duration_ms));
            }

            html.push_str("</div>");
        }

        html.push_str(r#"
        </div>

        <div class="panel">
            <div class="panel-title">📝 实时日志</div>
"#);

        // 添加日志
        for log in &logs {
            let level_class = match log.level {
                LogLevel::Info => "log-info",
                LogLevel::Success => "log-success",
                LogLevel::Warning => "log-warning",
                LogLevel::Error => "log-error",
                LogLevel::Debug => "log-info",
            };
            let level_icon = match log.level {
                LogLevel::Info => "ℹ️",
                LogLevel::Success => "✅",
                LogLevel::Warning => "⚠️",
                LogLevel::Error => "❌",
                LogLevel::Debug => "🔍",
            };

            html.push_str(&format!(r#"
            <div class="log-entry {level_class}">
                <span class="log-time">{timestamp}</span>
                <span class="log-module">[{module}]</span>
                {icon} {message}
            </div>
"#, level_class = level_class, timestamp = log.timestamp, module = log.module, icon = level_icon, message = log.message));
        }

        html.push_str(r#"
        </div>

        <div class="auto-refresh">
            页面每 5 秒自动刷新
        </div>
    </div>

    <script>
        setTimeout(function() {
            location.reload();
        }, 5000);
    </script>
</body>
</html>
"#);

        html
    }

    fn get_timestamp(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

/// Web UI 统计信息
#[derive(Debug, Serialize, Deserialize)]
pub struct WebUIStats {
    pub uptime_seconds: u64,
    pub total_logs: usize,
    pub total_steps: usize,
    pub success_steps: usize,
    pub failed_steps: usize,
    pub running_steps: usize,
    pub success_rate: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webui_server_creation() {
        let server = WebUIServer::new(WebUIConfig::default());
        assert_eq!(server.config.port, 8080);
    }

    #[test]
    fn test_logging() {
        let server = WebUIServer::new(WebUIConfig::default());
        server.info("test", "测试消息");
        let logs = server.get_logs(10);
        assert_eq!(logs.len(), 1);
    }
}
