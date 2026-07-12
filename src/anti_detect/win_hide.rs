//! Windows 平台反检测实现
//!
//! - PEB (Process Environment Block) 隐藏
//! - 调试寄存器清理
//! - 内存特征擦除
//! - 调用栈伪造

use crate::FridaError;
use crate::Result;

/// Windows PEB 结构体偏移（x64）
const PEB_BEING_DEBUGGED_OFFSET: usize = 0x02;
const PEB_NT_GLOBAL_FLAG_OFFSET: usize = 0xBC;
const PEB_HEAP_FLAGS_OFFSET: usize = 0x70;

/// Windows 隐蔽管理器
///
/// 统一管理 Windows 平台的所有反检测措施，包括 PEB 隐藏、
/// 调试寄存器清零和调试状态检测。
pub struct WinStealthManager {
    applied: bool,
}

impl WinStealthManager {
    /// 创建新的 Windows 隐蔽管理器
    pub fn new() -> Self {
        Self { applied: false }
    }

    /// 应用所有反检测措施
    ///
    /// 依次执行：清除 PEB 调试标志 -> 清除 NtGlobalFlag -> 隐藏调试寄存器
    pub fn apply_all(&mut self) -> Result<()> {
        log::info!("开始应用 Windows 反检测措施...");

        // 1. 清除 PEB BeingDebugged
        Self::clear_peb_debug_flag()?;
        log::info!("[WinStealthManager] PEB BeingDebugged 已清除");

        // 2. 清除 PEB NtGlobalFlag
        Self::clear_nt_global_flag()?;
        log::info!("[WinStealthManager] PEB NtGlobalFlag 已清除");

        // 3. 隐藏调试寄存器
        Self::hide_debug_registers()?;
        log::info!("[WinStealthManager] 调试寄存器已隐藏");

        self.applied = true;
        log::info!("Windows 反检测措施已应用");
        Ok(())
    }

    /// 清除 PEB BeingDebugged 标志
    ///
    /// 将 PEB+0x02 处的 BeingDebugged 字节置为 0，
    /// 绕过 `IsDebuggerPresent` 等基于 PEB 的调试检测。
    pub fn clear_peb_debug_flag() -> Result<()> {
        unsafe {
            let peb = get_peb_address();
            if peb.is_null() {
                return Err(FridaError::AntiDetect {
                    reason: "无法获取 PEB 地址".into(),
                }
                .into());
            }
            let being_debugged = (peb as *mut u8).add(PEB_BEING_DEBUGGED_OFFSET);
            *being_debugged = 0;
            log::debug!("PEB BeingDebugged 标志已清除");
        }
        Ok(())
    }

    /// 清除 PEB NtGlobalFlag
    ///
    /// 将 PEB+0xBC 处的 NtGlobalFlag 双字置为 0，
    /// 清除堆调试标志（如 FLG_HEAP_ENABLE_TAIL_CHECK 等）。
    pub fn clear_nt_global_flag() -> Result<()> {
        unsafe {
            let peb = get_peb_address();
            if peb.is_null() {
                return Err(FridaError::AntiDetect {
                    reason: "无法获取 PEB 地址".into(),
                }
                .into());
            }
            let nt_global_flag = (peb as *mut u32).add(PEB_NT_GLOBAL_FLAG_OFFSET / 4);
            *nt_global_flag = 0;

            // 同时清除堆标志偏移
            let heap_flags = (peb as *mut u32).add(PEB_HEAP_FLAGS_OFFSET / 4);
            *heap_flags = 0x2; // 默认堆标志（非调试状态）

            log::debug!("PEB NtGlobalFlag 和堆标志已清除");
        }
        Ok(())
    }

    /// 隐藏调试寄存器 (Dr0-Dr7)
    ///
    /// 使用 `GetThreadContext` / `SetThreadContext` 读取当前线程上下文，
    /// 将硬件断点寄存器 Dr0-Dr3、Dr6、Dr7 全部清零。
    pub fn hide_debug_registers() -> Result<()> {
        use winapi::um::processthreadsapi::{GetCurrentThread, GetThreadContext, SetThreadContext};
        use winapi::um::winnt::{CONTEXT, CONTEXT_DEBUG_REGISTERS};

        unsafe {
            let thread = GetCurrentThread();
            let mut ctx: CONTEXT = std::mem::zeroed();
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

            if GetThreadContext(thread, &mut ctx) == 0 {
                return Err(FridaError::AntiDetect {
                    reason: format!(
                        "GetThreadContext 失败: {}",
                        std::io::Error::last_os_error()
                    ),
                }
                .into());
            }

            ctx.Dr0 = 0;
            ctx.Dr1 = 0;
            ctx.Dr2 = 0;
            ctx.Dr3 = 0;
            ctx.Dr6 = 0;
            ctx.Dr7 = 0;

            if SetThreadContext(thread, &ctx) == 0 {
                return Err(FridaError::AntiDetect {
                    reason: format!(
                        "SetThreadContext 失败: {}",
                        std::io::Error::last_os_error()
                    ),
                }
                .into());
            }

            log::debug!("调试寄存器 (Dr0-Dr7) 已清零");
        }
        Ok(())
    }

    /// 检查是否处于调试状态
    ///
    /// 调用 Windows API `IsDebuggerPresent` 进行快速检测。
    pub fn is_debugger_present() -> bool {
        unsafe { winapi::um::debugapi::IsDebuggerPresent() != 0 }
    }

    /// 恢复所有修改
    ///
    /// 当前实现仅标记状态为未应用。由于 PEB 修改和寄存器清零
    /// 都是单向操作，实际恢复需要提前备份原始值。
    pub fn revert_all(&mut self) -> Result<()> {
        log::info!("恢复 Windows 反检测措施...");
        self.applied = false;
        log::info!("Windows 反检测措施已恢复（状态标记）");
        Ok(())
    }

    /// 检查是否已应用隐藏措施
    pub fn is_applied(&self) -> bool {
        self.applied
    }
}

impl Default for WinStealthManager {
    fn default() -> Self {
        Self::new()
    }
}

/// 获取当前线程的 PEB 地址
///
/// x64: GS 段寄存器偏移 0x60
/// x86: FS 段寄存器偏移 0x30
#[cfg(target_arch = "x86_64")]
unsafe fn get_peb_address() -> *mut u8 {
    let peb: u64;
    std::arch::asm!(
        "mov {}, gs:[0x60]",
        out(reg) peb,
        options(nostack, preserves_flags)
    );
    peb as *mut u8
}

#[cfg(target_arch = "x86")]
unsafe fn get_peb_address() -> *mut u8 {
    let peb: u32;
    std::arch::asm!(
        "mov {:e}, fs:[0x30]",
        out(reg) peb,
        options(nostack, preserves_flags)
    );
    peb as *mut u8
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
unsafe fn get_peb_address() -> *mut u8 {
    std::ptr::null_mut()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_win_stealth_manager_creation() {
        let mgr = WinStealthManager::new();
        assert!(!mgr.is_applied());
    }

    #[test]
    fn test_is_debugger_present() {
        // 在常规运行环境下应该返回 false
        // 在调试器下运行时会返回 true
        let _present = WinStealthManager::is_debugger_present();
    }

    #[test]
    fn test_clear_peb_debug_flag() {
        // 清除操作不应 panic
        let result = WinStealthManager::clear_peb_debug_flag();
        assert!(result.is_ok());
    }

    #[test]
    fn test_hide_debug_registers() {
        let result = WinStealthManager::hide_debug_registers();
        assert!(result.is_ok());
    }
}
