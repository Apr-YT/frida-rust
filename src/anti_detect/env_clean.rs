//! 环境变量清理模块
//!
//! 清除与 Frida 相关的环境变量，防止通过环境变量检测到 Frida。
//!
//! 实现策略：
//! 1. 在模块初始化时清除已知的 Frida 环境变量
//! 2. Hook setenv/unsetenv 防止重新设置敏感环境变量
//! 3. 支持自定义需要清除的环境变量列表

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};

// ======================== 全局状态 ========================

/// 保存原始 setenv 函数指针
#[cfg(any(target_os = "linux", target_os = "android"))]
static ENV_ORIGINAL_SETENV: AtomicUsize = AtomicUsize::new(0);

/// 保存原始 unsetenv 函数指针
#[cfg(any(target_os = "linux", target_os = "android"))]
static ENV_ORIGINAL_UNSETENV: AtomicUsize = AtomicUsize::new(0);

/// 需要清除的环境变量
#[cfg(any(target_os = "linux", target_os = "android"))]
static mut HIDDEN_ENV_VARS: Option<HashSet<String>> = None;

/// 默认需要清除的 Frida 环境变量
const DEFAULT_ENV_VARS: &[&str] = &[
    "FRIDA_VERSION",
    "FRIDA_SERVER_ADDRESS",
    "FRIDA_LISTEN_PORT",
    "FRIDA_DEVICE_ID",
    "FRIDA_HOST",
    "FRIDA_PATH",
    "FRIDA_SCRIPT",
    "FRIDA_AGENT_PATH",
    "FRIDA_GADGET_PATH",
    "LD_PRELOAD",           // 可能包含 Frida agent 路径
    "DYLD_INSERT_LIBRARIES", // macOS/iOS 对应 LD_PRELOAD
];

// ======================== 工具函数 ========================

/// 初始化需要清除的环境变量列表
#[cfg(any(target_os = "linux", target_os = "android"))]
unsafe fn init_env_vars() {
    if HIDDEN_ENV_VARS.is_some() {
        return;
    }
    
    let mut vars = HashSet::new();
    for &var in DEFAULT_ENV_VARS {
        vars.insert(var.to_string());
    }
    HIDDEN_ENV_VARS = Some(vars);
    log::debug!("环境变量清理: 初始化完成，默认清除变量 {:?}", DEFAULT_ENV_VARS);
}

/// 清除所有 Frida 相关环境变量
pub fn clear_frida_env_vars() {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        unsafe {
            init_env_vars();
            
            if let Some(ref vars) = HIDDEN_ENV_VARS {
                for var in vars {
                    // 检查环境变量是否存在
                    if std::env::var(var).is_ok() {
                        // 对于 LD_PRELOAD，需要特殊处理
                        // 不能直接删除，否则可能导致程序崩溃
                        if var == "LD_PRELOAD" || var == "DYLD_INSERT_LIBRARIES" {
                            // 从 LD_PRELOAD 中移除 Frida 相关路径
                            if let Ok(value) = std::env::var(var) {
                                let new_value = remove_frida_from_preload(&value);
                                if new_value.is_empty() {
                                    std::env::remove_var(var);
                                } else {
                                    std::env::set_var(var, &new_value);
                                }
                                log::info!("环境变量清理: 修改 {} = '{}'", var, new_value);
                            }
                        } else {
                            std::env::remove_var(var);
                            log::info!("环境变量清理: 清除 {}", var);
                        }
                    }
                }
            }
        }
    }
}

/// 从 LD_PRELOAD 值中移除 Frida 相关路径
fn remove_frida_from_preload(value: &str) -> String {
    let frida_keywords = ["frida", "gadget", "agent", "linjector"];
    
    let paths: Vec<&str> = value.split(':').collect();
    let filtered: Vec<&str> = paths.iter().filter(|path| {
        let path_lower = path.to_lowercase();
        !frida_keywords.iter().any(|kw| path_lower.contains(kw))
    }).copied().collect();
    
    filtered.join(":")
}

/// 添加自定义需要清除的环境变量
pub fn add_hidden_env_var(var: &str) {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        unsafe {
            init_env_vars();
            if let Some(ref mut vars) = HIDDEN_ENV_VARS {
                vars.insert(var.to_string());
                log::info!("环境变量清理: 添加自定义变量 '{}'", var);
            }
        }
    }
}

/// 设置 errno
#[inline]
unsafe fn set_errno(err: i32) {
    #[cfg(target_os = "android")]
    {
        *libc::__errno() = err;
    }
    #[cfg(not(target_os = "android"))]
    {
        *libc::__errno_location() = err;
    }
}

// ======================== 替换函数 ========================

/// setenv 替换函数 - 阻止设置敏感环境变量
#[cfg(any(target_os = "linux", target_os = "android"))]
unsafe extern "C" fn env_setenv_replace(
    name: *const libc::c_char,
    value: *const libc::c_char,
    overwrite: libc::c_int,
) -> libc::c_int {
    let original_fn = ENV_ORIGINAL_SETENV.load(Ordering::Relaxed);
    if original_fn == 0 {
        set_errno(libc::EINVAL);
        return -1;
    }

    // 读取环境变量名
    let name_str = if !name.is_null() {
        std::ffi::CStr::from_ptr(name).to_string_lossy().to_uppercase()
    } else {
        return -1;
    };

    // 初始化环境变量列表
    init_env_vars();
    
    // 检查是否为敏感环境变量
    if let Some(ref vars) = HIDDEN_ENV_VARS {
        if vars.contains(&name_str) {
            // 对于 LD_PRELOAD，需要特殊处理
            if name_str == "LD_PRELOAD" || name_str == "DYLD_INSERT_LIBRARIES" {
                // 检查新值是否包含 Frida 路径
                if !value.is_null() {
                    let value_str = std::ffi::CStr::from_ptr(value).to_string_lossy();
                    let frida_keywords = ["frida", "gadget", "agent", "linjector"];
                    let has_frida = frida_keywords.iter().any(|kw| value_str.to_lowercase().contains(kw));
                    
                    if has_frida {
                        log::trace!("环境变量清理: 阻止设置 {} 包含 Frida 路径", name_str);
                        // 返回成功但不实际设置
                        return 0;
                    }
                }
            } else {
                log::trace!("环境变量清理: 阻止设置 {}", name_str);
                // 返回成功但不实际设置
                return 0;
            }
        }
    }

    // 调用原始 setenv
    let original_setenv: unsafe extern "C" fn(
        *const libc::c_char,
        *const libc::c_char,
        libc::c_int,
    ) -> libc::c_int = std::mem::transmute(original_fn);
    
    original_setenv(name, value, overwrite)
}

/// unsetenv 替换函数 - 允许清除敏感环境变量
#[cfg(any(target_os = "linux", target_os = "android"))]
unsafe extern "C" fn env_unsetenv_replace(
    name: *const libc::c_char,
) -> libc::c_int {
    let original_fn = ENV_ORIGINAL_UNSETENV.load(Ordering::Relaxed);
    if original_fn == 0 {
        set_errno(libc::EINVAL);
        return -1;
    }

    // 读取环境变量名
    let name_str = if !name.is_null() {
        std::ffi::CStr::from_ptr(name).to_string_lossy().to_uppercase()
    } else {
        return -1;
    };

    // 初始化环境变量列表
    init_env_vars();
    
    // 检查是否为敏感环境变量
    if let Some(ref vars) = HIDDEN_ENV_VARS {
        if vars.contains(&name_str) {
            log::trace!("环境变量清理: 允许清除 {}", name_str);
        }
    }

    // 调用原始 unsetenv
    let original_unsetenv: unsafe extern "C" fn(
        *const libc::c_char,
    ) -> libc::c_int = std::mem::transmute(original_fn);
    
    original_unsetenv(name)
}

// ======================== 公共接口 ========================

/// 环境变量清理器
///
/// 管理环境变量清理功能的生命周期
pub struct EnvCleaner {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    hooker: Option<crate::hook::got_plt::GotPltHooker>,
}

impl EnvCleaner {
    /// 创建新的环境变量清理器
    pub fn new() -> Self {
        EnvCleaner {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            hooker: None,
        }
    }

    /// 安装环境变量清理 Hook
    ///
    /// 通过 GOT/PLT Hook 拦截 setenv 和 unsetenv 函数
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn install(&mut self) -> crate::Result<()> {
        use crate::common::util::parse_proc_maps;
        use crate::common::types::ProcessId;

        log::info!("环境变量清理: 开始安装 Hook...");

        // 获取当前进程的 libc 基址
        let regions = parse_proc_maps(ProcessId(0))?;
        let libc_region = regions.iter().find(|r| r.name.contains("libc.so") || r.name.contains("libc-"));
        
        let libc_base = match libc_region {
            Some(r) => r.start,
            None => {
                return Err(crate::FridaError::AntiDetect {
                    reason: "找不到 libc.so".to_string(),
                }.into());
            }
        };

        let mut hooker = crate::hook::got_plt::GotPltHooker::new(libc_base as u64);

        // Hook setenv
        let setenv_addr = hooker.resolve_symbol("setenv")?;
        ENV_ORIGINAL_SETENV.store(setenv_addr as usize, Ordering::Relaxed);
        hooker.hook_symbol("setenv", env_setenv_replace as *const ())?;

        // Hook unsetenv
        let unsetenv_addr = hooker.resolve_symbol("unsetenv")?;
        ENV_ORIGINAL_UNSETENV.store(unsetenv_addr as usize, Ordering::Relaxed);
        hooker.hook_symbol("unsetenv", env_unsetenv_replace as *const ())?;

        self.hooker = Some(hooker);

        // 初始化环境变量列表
        unsafe {
            init_env_vars();
        }

        log::info!("环境变量清理: Hook 安装完成");
        Ok(())
    }

    /// 卸载环境变量清理 Hook
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn uninstall(&mut self) -> crate::Result<()> {
        // 清除函数指针
        ENV_ORIGINAL_SETENV.store(0, Ordering::Relaxed);
        ENV_ORIGINAL_UNSETENV.store(0, Ordering::Relaxed);
        
        self.hooker = None;
        log::info!("环境变量清理: Hook 已卸载");
        Ok(())
    }

    /// 立即清除所有 Frida 相关环境变量
    pub fn clear_now(&self) {
        clear_frida_env_vars();
    }

    /// 添加自定义需要清除的环境变量
    pub fn add_var(&self, var: &str) {
        add_hidden_env_var(var);
    }
}

impl Default for EnvCleaner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remove_frida_from_preload() {
        let input = "/path/to/frida.so:/path/to/normal.so:/path/to/gadget.so";
        let result = remove_frida_from_preload(input);
        assert_eq!(result, "/path/to/normal.so");
    }

    #[test]
    fn test_remove_frida_from_preload_no_frida() {
        let input = "/path/to/normal.so:/path/to/other.so";
        let result = remove_frida_from_preload(input);
        assert_eq!(result, input);
    }

    #[test]
    fn test_env_cleaner_creation() {
        let cleaner = EnvCleaner::new();
        assert!(cleaner.hooker.is_none());
    }
}
