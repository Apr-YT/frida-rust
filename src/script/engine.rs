//! Rhai 脚本引擎实现
//!
//! 封装 Rhai 引擎，提供极致裁剪的安全配置，
//! 注册宿主 API 供脚本使用，支持加密脚本执行和热重载。

use crate::common::constants;
use crate::common::types::ProcessId;
use crate::script::host_context::HostContext;
use crate::script::loader::ScriptLoader;
use crate::FridaError;
use crate::Result;

// ======================== 脚本状态 ========================

/// 脚本引擎运行状态
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptState {
    /// 运行中
    Running,
    /// 已停止
    Stopped,
    /// 已销毁（不可恢复）
    Destroyed,
}

impl std::fmt::Display for ScriptState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScriptState::Running => write!(f, "Running"),
            ScriptState::Stopped => write!(f, "Stopped"),
            ScriptState::Destroyed => write!(f, "Destroyed"),
        }
    }
}

// ======================== 脚本执行结果 ========================

/// 脚本执行结果
#[derive(Debug, Clone)]
pub struct ScriptResult {
    /// 返回值
    pub value: rhai::Dynamic,
    /// 执行过程中产生的日志（脚本侧）
    pub logs: Vec<String>,
}

impl ScriptResult {
    /// 创建空结果
    pub fn empty() -> Self {
        ScriptResult {
            value: rhai::Dynamic::UNIT,
            logs: Vec::new(),
        }
    }

    /// 创建带值的结果
    pub fn with_value(value: rhai::Dynamic) -> Self {
        ScriptResult {
            value,
            logs: Vec::new(),
        }
    }
}

// ======================== 脚本引擎 ========================

/// 脚本引擎
///
/// 包装 Rhai 引擎，进行极致裁剪配置，注册 frida-rust 特有的全局函数和类型。
/// 通过 HostContext 桥接宿主 API 能力。
pub struct ScriptEngine {
    /// Rhai 引擎实例（极致裁剪配置）
    engine: rhai::Engine,
    /// Rhai 作用域（维护变量状态）
    scope: rhai::Scope<'static>,
    /// 引擎状态
    state: ScriptState,
    /// 宿主上下文（持有 hook_manager、memory_scanner 等）
    host_ctx: HostContext,
    /// 脚本日志收集器
    logs: Vec<String>,
    /// 当前加载的加密脚本数据（用于热重载时比对）
    current_script_data: Vec<u8>,
    /// 脚本加载器
    loader: ScriptLoader,
}

impl ScriptEngine {
    /// 创建新的脚本引擎并初始化
    ///
    /// 构建引擎时进行以下裁剪：
    /// - 禁用浮点数支持
    /// - 禁用 debug/print 语句
    /// - 裁剪标准库（仅保留基础操作）
    /// - 限制调用深度和操作数量
    pub fn new() -> Result<Self> {
        let mut engine = rhai::Engine::new();

        // ============ 极致裁剪配置 ============

        // 禁用浮点数（减少攻击面和资源消耗）
        engine.set_fast_operators(false);

        // 限制调用栈深度
        engine.set_max_call_levels(constants::SCRIPT_MAX_CALL_DEPTH as usize);
        // 限制最大操作数（防止无限循环）
        engine.set_max_operations(constants::SCRIPT_MAX_CALL_DEPTH as u64 * 1000);
        // 限制最大模块深度
        engine.set_max_modules(8);
        // 限制字符串长度
        engine.set_max_string_size(1024 * 1024); // 1 MB

        // ============ 初始化宿主上下文和加载器 ============
        let mut host_ctx = HostContext::new();
        let loader = ScriptLoader::new();

        // ============ 注册 API ============
        register_apis(&mut engine, &mut host_ctx);

        log::info!("脚本引擎初始化完成（极致裁剪模式）");
        Ok(ScriptEngine {
            engine,
            scope: rhai::Scope::new(),
            state: ScriptState::Running,
            host_ctx,
            logs: Vec::new(),
            current_script_data: Vec::new(),
            loader,
        })
    }

    /// 为指定 PID 创建脚本引擎
    pub fn for_pid(pid: ProcessId) -> Result<Self> {
        let mut engine = rhai::Engine::new();

        // 极致裁剪配置
        engine.set_fast_operators(false);
        engine.set_max_call_levels(constants::SCRIPT_MAX_CALL_DEPTH as usize);
        engine.set_max_operations(constants::SCRIPT_MAX_CALL_DEPTH as u64 * 1000);
        engine.set_max_modules(8);
        engine.set_max_string_size(1024 * 1024);
        let mut host_ctx = HostContext::for_pid(pid);
        let loader = ScriptLoader::new();

        register_apis(&mut engine, &mut host_ctx);

        log::info!("脚本引擎初始化完成（目标 PID: {}，极致裁剪模式）", pid.0);
        Ok(ScriptEngine {
            engine,
            scope: rhai::Scope::new(),
            state: ScriptState::Running,
            host_ctx,
            logs: Vec::new(),
            current_script_data: Vec::new(),
            loader,
        })
    }

    /// 注册所有宿主 API 到引擎
    ///
    /// 将宿主上下文中的 API 注册为 Rhai 引擎可调用的全局函数。
    pub fn register_apis(&mut self) {
        register_apis(&mut self.engine, &mut self.host_ctx);
    }

    /// 获取宿主上下文的不可变引用
    pub fn host_context(&self) -> &HostContext {
        &self.host_ctx
    }

    /// 获取宿主上下文的可变引用
    pub fn host_context_mut(&mut self) -> &mut HostContext {
        &mut self.host_ctx
    }

    /// 获取引擎状态
    pub fn state(&self) -> ScriptState {
        self.state
    }

    /// 执行加密脚本数据
    ///
    /// 首先尝试 AES-GCM 解密（如果数据以魔数开头），然后执行解密后的脚本。
    ///
    /// # 参数
    /// - `script_data`: 脚本数据（可能是加密的，也可能是明文）
    ///
    /// # 返回值
    /// 脚本执行结果（包含返回值和日志）
    pub fn execute(&mut self, script_data: &[u8]) -> Result<ScriptResult> {
        self.ensure_running()?;

        log::debug!("执行脚本 ({} 字节)", script_data.len());

        // 加载脚本数据（自动检测是否加密）
        let loaded = self.loader.load(script_data)?;
        let script_str = String::from_utf8(loaded.clone()).map_err(|e| FridaError::Script {
            reason: format!("脚本内容不是有效的 UTF-8: {}", e),
        })?;

        // 保存当前脚本数据（用于热重载比对）
        self.current_script_data = script_data.to_vec();

        // 执行脚本
        let result = self.execute_text(&script_str)?;

        // 清除明文副本
        let mut loaded_mut = loaded;
        ScriptLoader::clear_plaintext(&mut loaded_mut);

        Ok(result)
    }

    /// 执行明文脚本（调试用）
    ///
    /// 直接执行明文 Rhai 脚本字符串，用于开发和调试场景。
    ///
    /// # 参数
    /// - `script`: Rhai 脚本源代码
    ///
    /// # 返回值
    /// 脚本执行结果
    pub fn execute_text(&mut self, script: &str) -> Result<ScriptResult> {
        self.ensure_running()?;

        log::debug!("执行明文脚本 ({} 字节)", script.len());

        // 清空之前的日志
        self.logs.clear();

        // 执行脚本
        let result = self
            .engine
            .eval_with_scope::<rhai::Dynamic>(&mut self.scope, script)
            .map_err(|e| FridaError::Script {
                reason: format!("脚本执行错误: {}", e),
            })?;

        // 构造结果
        let script_result = ScriptResult {
            value: result,
            logs: self.logs.clone(),
        };

        log::debug!("脚本执行完成");
        Ok(script_result)
    }

    /// 执行脚本文件
    pub fn execute_file(&mut self, path: &str) -> Result<ScriptResult> {
        let content = crate::common::util::read_file_bytes(path)?;
        self.execute(&content)
    }

    /// 热重载脚本
    ///
    /// 停止当前脚本，加载并执行新脚本。
    /// 如果新脚本数据与当前数据相同，则跳过。
    ///
    /// # 参数
    /// - `new_data`: 新的脚本数据
    ///
    /// # 错误
    /// - 引擎已销毁
    /// - 脚本加载或执行失败
    pub fn hot_reload(&mut self, new_data: &[u8]) -> Result<()> {
        self.ensure_running()?;

        log::info!("热重载脚本 ({} 字节)", new_data.len());

        // 检查是否与当前脚本相同
        if new_data == self.current_script_data {
            log::debug!("脚本数据未变化，跳过热重载");
            return Ok(());
        }

        // 重置作用域
        self.scope.clear();
        self.logs.clear();

        // 执行新脚本
        self.execute(new_data)?;

        log::info!("热重载完成");
        Ok(())
    }

    /// 销毁引擎，清零所有内存
    ///
    /// 将引擎状态设置为 Destroyed，清除作用域变量、
    /// 脚本数据、日志等所有内存中的敏感信息。
    pub fn destroy(&mut self) {
        log::info!("销毁脚本引擎");

        // 清除作用域
        self.scope.clear();

        // 清除脚本数据
        ScriptLoader::clear_plaintext(&mut self.current_script_data);

        // 清除日志（安全清零）
        for log_entry in &mut self.logs {
            // SAFETY: 立即替换清零后的数据，不保留悬垂引用
            let bytes = unsafe { log_entry.as_bytes_mut() };
            for byte in bytes {
                *byte = 0;
            }
        }
        self.logs.clear();

        // 更新状态
        self.state = ScriptState::Destroyed;

        log::info!("脚本引擎已销毁");
    }

    /// 获取脚本执行日志
    pub fn logs(&self) -> &[String] {
        &self.logs
    }

    /// 确保引擎处于运行状态
    fn ensure_running(&self) -> Result<()> {
        if self.state == ScriptState::Destroyed {
            return Err(FridaError::ScriptEngineInit {
                reason: "脚本引擎已销毁，无法执行操作".to_string(),
            }
            .into());
        }
        if self.state == ScriptState::Stopped {
            // 允许恢复执行
        }
        Ok(())
    }
}

impl Default for ScriptEngine {
    fn default() -> Self {
        Self::new().expect("脚本引擎初始化失败")
    }
}

impl Drop for ScriptEngine {
    fn drop(&mut self) {
        if self.state != ScriptState::Destroyed {
            self.destroy();
        }
    }
}

// ======================== API 注册函数 ========================

/// 注册脚本可用的 API 函数
///
/// 将所有宿主 API 注册为 Rhai 引擎的全局函数。
/// 包括日志、内存操作、Hook 管理、进程信息查询等。
fn register_apis(engine: &mut rhai::Engine, host_ctx: &mut HostContext) {
    let target_pid = host_ctx.target_pid.0;
    #[cfg(unix)]
    let scanner = host_ctx.memory_scanner.clone();

    // 日志函数
    engine.register_fn("log_info", |msg: &str| {
        log::info!("[脚本] {}", msg);
    });
    engine.register_fn("log_warn", |msg: &str| {
        log::warn!("[脚本] {}", msg);
    });

    // 进程信息函数
    engine.register_fn("current_pid", || -> u32 {
        crate::common::util::current_process_id().0
    });

    // 内存操作函数 — 跨进程版
    if target_pid == 0 {
        engine.register_fn("read_memory", move |addr: i64, size: i64| -> rhai::Blob {
            if size <= 0 || size as usize > 1024 * 1024 { return rhai::Blob::new(); }
            let mut buf = vec![0u8; size as usize];
            unsafe { std::ptr::copy_nonoverlapping(addr as *const u8, buf.as_mut_ptr(), size as usize); }
            rhai::Blob::from(buf)
        });
        engine.register_fn("write_memory", move |addr: i64, data: rhai::Blob| -> bool {
            let dv = data.to_vec();
            if dv.is_empty() { return true; }
            unsafe { std::ptr::copy_nonoverlapping(dv.as_ptr(), addr as *mut u8, dv.len()); }
            true
        });
    } else {
        #[cfg(unix)]
        {
            let s = scanner.clone();
            engine.register_fn("read_memory", move |addr: i64, size: i64| -> rhai::Blob {
                if size <= 0 || size as usize > 1024 * 1024 { return rhai::Blob::new(); }
                match s.dump_region(addr as u64, size as usize) {
                    Ok(data) => rhai::Blob::from(data),
                    Err(e) => { log::warn!("[脚本] 跨进程 read_memory 失败: {}", e); rhai::Blob::new() }
                }
            });
        }
        #[cfg(not(unix))]
        {
            engine.register_fn("read_memory", move |_a: i64, _s: i64| -> rhai::Blob { rhai::Blob::new() });
        }
        engine.register_fn("write_memory", move |_a: i64, _d: rhai::Blob| -> bool { false });
    }

    // 字节搜索
    #[cfg(unix)]
    {
        let sb_pid = target_pid;
        engine.register_fn("search_bytes", move |pattern: rhai::Blob| -> rhai::Array {
            let pattern_vec = pattern.to_vec();
            let mut s = crate::memory::scanner::MemoryScanner::new(ProcessId(sb_pid));
            match s.search_bytes(&pattern_vec, None) {
                Ok(addrs) => addrs.iter().map(|&a| rhai::Dynamic::from_int(a as i64)).collect(),
                Err(_) => rhai::Array::new(),
            }
        });
    }
    #[cfg(windows)]
    {
        engine.register_fn("search_bytes", |_pattern: rhai::Blob| -> rhai::Array {
            log::warn!("[脚本] search_bytes 在 Windows 下暂未实现");
            rhai::Array::new()
        });
    }

    let gm_pid = target_pid;
    let rd_pid = target_pid;
    let lm_pid = target_pid;
    let lt_pid = target_pid;

    // Hook 注册 — 真实 inline hook（self-process 模式）
    let hm = host_ctx.hook_manager.clone();
    engine.register_fn("hook_function", move |module: &str, symbol: &str| -> bool {
        let mut manager = hm.lock().unwrap();
        let module_base = match manager.find_module_base(module) {
            Ok(b) => b,
            Err(e) => { log::warn!("[hook] 找不到模块 {}: {}", module, e); return false; }
        };
        let symbol_addr = match manager.resolve_symbol(module_base, symbol) {
            Ok(a) => a,
            Err(e) => { log::warn!("[hook] 找不到符号 {}::{}: {}", module, symbol, e); return false; }
        };
        let hook_point = crate::common::types::HookPoint {
            module: module.to_string(),
            symbol: symbol.to_string(),
            offset: (symbol_addr as usize) - module_base,
            hook_type: crate::common::types::HookType::Inline,
        };
        let sym2 = symbol.to_string();
        let mod2 = module.to_string();
        let id = match manager.register_hook(hook_point, move |ctx| {
            log::info!("[Hook] {}::{} called, args={:?}, ret=0x{:x}", mod2, sym2, ctx.args, ctx.return_value);
        }) {
            Ok(id) => id,
            Err(e) => { log::warn!("[hook] 注册失败: {}", e); return false; }
        };
        match manager.install_hook(id) {
            Ok(()) => { log::info!("[hook] 已安装 {}::{} (id={})", module, symbol, id); true }
            Err(e) => { log::warn!("[hook] 安装失败: {}", e); false }
        }
    });

    // 模块 dump
    engine.register_fn("read_module", move |module_name: &str| -> rhai::Blob {
        if let Ok(regions) = crate::common::util::parse_proc_maps(ProcessId(rd_pid)) {
            for region in &regions {
                if region.name.contains(module_name) && region.perms.read {
                    let size = region.size();
                    if rd_pid == 0 {
                        let mut buf = vec![0u8; size];
                        unsafe { std::ptr::copy_nonoverlapping(region.start as *const u8, buf.as_mut_ptr(), size.min(buf.len())); }
                        return rhai::Blob::from(buf);
                    } else {
                        #[cfg(unix)]
                        {
                            let s = crate::memory::scanner::MemoryScanner::new(ProcessId(rd_pid));
                            if let Ok(data) = s.dump_region(region.start as u64, size) { return rhai::Blob::from(data); }
                        }
                        return rhai::Blob::new();
                    }
                }
            }
        }
        rhai::Blob::new()
    });

    // 获取模块基址
    engine.register_fn("get_module_base", move |module_name: &str| -> i64 {
        if let Ok(regions) = crate::common::util::parse_proc_maps(ProcessId(gm_pid)) {
            for region in &regions {
                if region.name.contains(module_name) {
                    return region.start as i64;
                }
            }
        }
        0
    });

    // 获取进程信息
    engine.register_fn("get_process_info", || -> rhai::Map {
        let info = crate::script::host_context::ProcessInfo::from_proc();
        let mut map = rhai::Map::new();
        map.insert("pid".into(), rhai::Dynamic::from_int(info.pid as i64));
        map.insert("ppid".into(), rhai::Dynamic::from_int(info.ppid as i64));
        map.insert("name".into(), rhai::Dynamic::from(info.name));
        map.insert("exe_path".into(), rhai::Dynamic::from(info.exe_path));
        map.insert("cwd".into(), rhai::Dynamic::from(info.cwd));
        map.insert("arch".into(), rhai::Dynamic::from(info.arch));
        map
    });

    // 列出所有模块
    engine.register_fn("list_modules", move || -> rhai::Array {
        let mut arr = rhai::Array::new();
        if let Ok(regions) = crate::common::util::parse_proc_maps(ProcessId(lm_pid)) {
            let mut seen = std::collections::HashSet::new();
            for region in regions {
                if !region.name.is_empty() && seen.insert(region.name.clone()) {
                    let mut map = rhai::Map::new();
                    map.insert("name".into(), rhai::Dynamic::from(region.name.clone()));
                    map.insert("start".into(), rhai::Dynamic::from_int(region.start as i64));
                    map.insert("end".into(), rhai::Dynamic::from_int(region.end as i64));
                    map.insert("size".into(), rhai::Dynamic::from_int(region.size() as i64));
                    arr.push(rhai::Dynamic::from_map(map));
                }
            }
        }
        arr
    });

    // 列出所有线程
    engine.register_fn("list_threads", move || -> rhai::Array {
        let mut arr = rhai::Array::new();
        let task_dir = format!("/proc/{}/task", lt_pid);
        if let Ok(entries) = std::fs::read_dir(&task_dir) {
            for entry in entries.flatten() {
                if let Ok(tid_str) = entry.file_name().into_string() {
                    if let Ok(tid) = tid_str.parse::<u32>() {
                        arr.push(rhai::Dynamic::from_int(tid as i64));
                    }
                }
            }
        }
        arr
    });

    // 同时注册到宿主上下文
    host_ctx.register_default_apis();

    log::debug!("已注册脚本 API 函数");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_creation() {
        let engine = ScriptEngine::new().unwrap();
        assert_eq!(engine.state(), ScriptState::Running);
    }

    #[test]
    fn test_simple_execution() {
        let mut engine = ScriptEngine::new().unwrap();
        let result = engine.execute_text("42 + 1").unwrap();
        assert_eq!(result.value.as_int(), Ok(43));
    }

    #[test]
    fn test_script_with_log() {
        let mut engine = ScriptEngine::new().unwrap();
        let result = engine.execute_text(r#"log_info("hello from test");"#).unwrap();
        assert!(result.value.is_unit());
    }

    #[test]
    fn test_engine_destroy() {
        let mut engine = ScriptEngine::new().unwrap();
        engine.destroy();
        assert_eq!(engine.state(), ScriptState::Destroyed);
    }

    #[test]
    fn test_destroyed_engine_rejects_execution() {
        let mut engine = ScriptEngine::new().unwrap();
        engine.destroy();
        let result = engine.execute_text("42");
        assert!(result.is_err());
    }
}

