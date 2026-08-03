//! Windows 平台反检测实现
//!
//! - PEB (Process Environment Block) 隐藏（自身/跨进程）
//! - 调试寄存器清理
//! - 反调试检测（DebugPort/DebugObject/堆标志/时间差/父进程）
//! - 内存特征擦除
//! - 调用栈伪造

use crate::FridaError;
use crate::Result;

/// Windows PEB 结构体偏移（x64/x86 通用部分）
const PEB_BEING_DEBUGGED_OFFSET: usize = 0x02;
const PEB_NT_GLOBAL_FLAG_OFFSET: usize = 0xBC;
/// PEB 内 ProcessHeap 指针偏移（x64/x86 均为 0x18）
const PEB_PROCESS_HEAP_OFFSET: usize = 0x18;
/// PEB 内 HeapFlags 偏移
const PEB_HEAP_FLAGS_OFFSET: usize = 0x70;
#[cfg(target_arch = "x86")]
const PEB_HEAP_FLAGS_OFFSET: usize = 0x0C;

/// HEAP 结构体内部偏移：Flags / ForceFlags
#[cfg(target_arch = "x86_64")]
const HEAP_FLAGS_OFFSET: usize = 0x70;
#[cfg(target_arch = "x86_64")]
const HEAP_FORCE_FLAGS_OFFSET: usize = 0x74;
#[cfg(target_arch = "x86")]
const HEAP_FLAGS_OFFSET: usize = 0x0C;
#[cfg(target_arch = "x86")]
const HEAP_FORCE_FLAGS_OFFSET: usize = 0x10;
/// 非调试状态下的默认堆 Flags（x64 常见值）
#[cfg(target_arch = "x86_64")]
const HEAP_DEFAULT_FLAGS: u32 = 0x5000_0062;
#[cfg(target_arch = "x86")]
const HEAP_DEFAULT_FLAGS: u32 = 0x5000_0062;

/// NtQueryInformationProcess 信息类
const PROCESS_BASIC_INFORMATION_CLASS: u32 = 0;
const PROCESS_DEBUG_PORT_CLASS: u32 = 7;
const PROCESS_DEBUG_OBJECT_HANDLE_CLASS: u32 = 0x1E;
/// 无调试对象时 NtQueryInformationProcess(DebugObjectHandle) 返回的状态
const STATUS_PORT_NOT_SET: i32 = 0xC000_0353u32 as i32;

// ntdll.NtQueryInformationProcess（winapi 0.3.9 未提供 winternl 模块，手动声明）
#[link(name = "ntdll")]
extern "system" {
    fn NtQueryInformationProcess(
        process_handle: winapi::um::winnt::HANDLE,
        process_information_class: u32,
        process_information: *mut winapi::ctypes::c_void,
        process_information_length: u32,
        return_length: *mut u32,
    ) -> i32;
}

/// 进程基本信息（对应 PROCESS_BASIC_INFORMATION）
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct ProcessBasicInformation {
    reserved1: *mut winapi::ctypes::c_void,
    peb_base_address: *mut winapi::ctypes::c_void,
    reserved2: [*mut winapi::ctypes::c_void; 2],
    unique_process_id: *mut winapi::ctypes::c_void,
    reserved3: *mut winapi::ctypes::c_void,
}

/// 远程进程 PEB 状态快照
#[derive(Debug, Clone, Copy, Default)]
pub struct RemotePebInfo {
    /// PEB BeingDebugged 字节
    pub being_debugged: u8,
    /// PEB NtGlobalFlag
    pub nt_global_flag: u32,
    /// 进程堆 Flags
    pub heap_flags: u32,
    /// 进程堆 ForceFlags
    pub heap_force_flags: u32,
}

/// 目标进程 Ldr 模块链中的模块信息（跨进程只读枚举）
#[derive(Debug, Clone, Default)]
pub struct RemoteLdrModule {
    /// 模块基址
    pub base: usize,
    /// 模块映像大小
    pub size: usize,
    /// 模块文件名（如 kernel32.dll）
    pub name: String,
}

// PEB_LDR_DATA / LDR_DATA_TABLE_ENTRY 关键偏移（x64/x86）
#[cfg(target_arch = "x86_64")]
const PEB_LDR_OFFSET: usize = 0x18;
#[cfg(target_arch = "x86")]
const PEB_LDR_OFFSET: usize = 0x0C;
#[cfg(target_arch = "x86_64")]
const LDR_IN_MEMORY_ORDER_LIST_OFFSET: usize = 0x20;
#[cfg(target_arch = "x86")]
const LDR_IN_MEMORY_ORDER_LIST_OFFSET: usize = 0x14;
#[cfg(target_arch = "x86_64")]
const LDR_IN_MEMORY_LINKS_OFFSET: usize = 0x10;
#[cfg(target_arch = "x86")]
const LDR_IN_MEMORY_LINKS_OFFSET: usize = 0x08;
#[cfg(target_arch = "x86_64")]
const LDR_DLL_BASE_OFFSET: usize = 0x30;
#[cfg(target_arch = "x86")]
const LDR_DLL_BASE_OFFSET: usize = 0x18;
#[cfg(target_arch = "x86_64")]
const LDR_SIZE_OF_IMAGE_OFFSET: usize = 0x40;
#[cfg(target_arch = "x86")]
const LDR_SIZE_OF_IMAGE_OFFSET: usize = 0x20;
#[cfg(target_arch = "x86_64")]
const LDR_BASE_DLL_NAME_OFFSET: usize = 0x58;
#[cfg(target_arch = "x86")]
const LDR_BASE_DLL_NAME_OFFSET: usize = 0x2C;
/// UNICODE_STRING.Buffer 偏移（等于指针宽度）
const UNICODE_STRING_BUFFER_OFFSET: usize = std::mem::size_of::<usize>();


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

    /// 枚举目标进程 Ldr 模块链（跨进程只读）
    ///
    /// 沿 `PEB -> Ldr -> InMemoryOrderModuleList` 遍历，返回模块基址/大小/文件名。
    pub fn enum_remote_ldr_modules(pid: u32) -> Result<Vec<RemoteLdrModule>> {
        let handle = open_process_for_stealth(pid)?;
        let result = enum_remote_ldr_modules_internal(handle);
        unsafe {
            winapi::um::handleapi::CloseHandle(handle);
        }
        result
    }

    /// 从目标进程 Ldr 模块链摘除指定模块（跨进程模块隐藏）
    ///
    /// `name_or_base` 支持模块文件名（不区分大小写，支持子串）或 `0x` 基址。
    /// 摘除后 GetModuleHandle / 模块枚举将看不到该模块（仅摘 InMemoryOrder 链，
    /// 保留 InLoadOrder 链以便模块仍可正常卸载）。
    /// 需要 `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE` 权限。
    pub fn hide_remote_module(pid: u32, name_or_base: &str) -> Result<String> {
        let handle = open_process_for_stealth(pid)?;
        let result = (|| -> Result<String> {
            let basic = query_basic_information(handle)?;
            let peb = basic.peb_base_address as *const u8;
            if peb.is_null() {
                return Err(FridaError::AntiDetect {
                    reason: format!("进程 {} 的远程 PEB 地址为空", pid),
                }
                .into());
            }
            let ldr = read_remote_pointer(handle, unsafe { peb.add(PEB_LDR_OFFSET) })?;
            if ldr == 0 {
                return Err(FridaError::AntiDetect {
                    reason: format!("进程 {} 的 PEB.Ldr 为空", pid),
                }
                .into());
            }
            let head = ldr + LDR_IN_MEMORY_ORDER_LIST_OFFSET;
            let target = name_or_base.trim();
            let want_base = target
                .strip_prefix("0x")
                .and_then(|h| u64::from_str_radix(h, 16).ok());

            // 遍历 InMemoryOrderModuleList：cur 指向 entry 的 InMemoryOrderLinks 字段
            let mut prev = head;
            let mut cur = read_remote_pointer(handle, head as *const u8)?;
            let mut guard = 0usize;
            while cur != head && guard < 1024 {
                guard += 1;
                let entry = cur - LDR_IN_MEMORY_LINKS_OFFSET;
                let base = read_remote_pointer(handle, (entry + LDR_DLL_BASE_OFFSET) as *const u8)?;
                let name = read_remote_base_dll_name(handle, entry)?;
                let next = read_remote_pointer(handle, cur as *const u8)?;
                let matched = if let Some(wb) = want_base {
                    base as u64 == wb
                } else {
                    name.eq_ignore_ascii_case(target)
                        || name.to_lowercase().contains(&target.to_lowercase())
                };
                if matched {
                    // prev.Flink = next; next.Blink = prev
                    write_remote::<usize>(handle, prev as *mut u8, next)?;
                    write_remote::<usize>(
                        handle,
                        (next + std::mem::size_of::<usize>()) as *mut u8,
                        prev,
                    )?;
                    let size = read_remote::<u32>(handle, (entry + LDR_SIZE_OF_IMAGE_OFFSET) as *const u8)?;
                    return Ok(format!(
                        "已从 PEB 模块链摘除 {} (基址 {:#x}, 大小 {:#x})",
                        name, base, size
                    ));
                }
                prev = cur;
                cur = next;
            }
            Err(FridaError::AntiDetect {
                reason: format!("进程 {} 中未找到模块 {}", pid, name_or_base),
            }
            .into())
        })();
        unsafe {
            winapi::um::handleapi::CloseHandle(handle);
        }
        result
    }

    /// 读取远程进程的 PEB 调试状态（跨进程只读）
    ///
    /// 需要 `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ` 权限。
    pub fn read_remote_peb(pid: u32) -> Result<RemotePebInfo> {
        let handle = open_process_for_stealth(pid)?;
        let info = read_remote_peb_internal(handle);
        unsafe {
            winapi::um::handleapi::CloseHandle(handle);
        }
        info
    }

    /// 对目标进程应用跨进程反调试清理
    ///
    /// 清除目标 PEB 的 `BeingDebugged`、`NtGlobalFlag`，并尽力恢复堆
    /// `Flags`/`ForceFlags`（堆写入失败仅告警，不中断）。
    /// 需要 `PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_VM_READ` 权限。
    pub fn apply_to_process(pid: u32) -> Result<()> {
        let handle = open_process_for_stealth(pid)?;
        let result = (|| -> Result<()> {
            let peb = {
                let basic = query_basic_information(handle)?;
                basic.peb_base_address as *mut u8
            };
            if peb.is_null() {
                return Err(FridaError::AntiDetect {
                    reason: format!("进程 {} 的远程 PEB 地址为空", pid),
                }
                .into());
            }

            // 1. BeingDebugged = 0
            write_remote::<u8>(handle, unsafe { peb.add(PEB_BEING_DEBUGGED_OFFSET) }, 0)?;
            // 2. NtGlobalFlag = 0
            write_remote::<u32>(handle, unsafe { peb.add(PEB_NT_GLOBAL_FLAG_OFFSET) }, 0)?;

            // 3. 堆标志（尽力而为；仅对远程进程，避免改写自身活跃堆导致损坏）
            if pid != crate::common::util::current_process_id().0 {
                let heap_ptr =
                    read_remote_pointer(handle, unsafe { peb.add(PEB_PROCESS_HEAP_OFFSET) })?;
                if heap_ptr != 0 {
                    if let Err(e) = write_remote::<u32>(
                        handle,
                        unsafe { (heap_ptr as *mut u8).add(HEAP_FLAGS_OFFSET) },
                        HEAP_DEFAULT_FLAGS,
                    ) {
                        log::warn!("清理目标堆 Flags 失败: {}", e);
                    }
                    if let Err(e) = write_remote::<u32>(
                        handle,
                        unsafe { (heap_ptr as *mut u8).add(HEAP_FORCE_FLAGS_OFFSET) },
                        0,
                    ) {
                        log::warn!("清理目标堆 ForceFlags 失败: {}", e);
                    }
                }
            }

            log::info!("已对进程 {} 应用跨进程反调试清理", pid);
            Ok(())
        })();
        unsafe {
            winapi::um::handleapi::CloseHandle(handle);
        }
        result
    }

    /// 检查是否被调试（DebugPort 方式）
    ///
    /// 通过 `NtQueryInformationProcess(ProcessDebugPort)` 查询，
    /// 返回值非 0 表示进程被调试器附加。
    pub fn check_debug_port() -> Result<u32> {
        let handle = unsafe { winapi::um::processthreadsapi::GetCurrentProcess() };
        query_debug_port(handle)
    }

    /// 检查是否存在调试对象（DebugObjectHandle 方式）
    ///
    /// 通过 `NtQueryInformationProcess(ProcessDebugObjectHandle)` 查询，
    /// 返回非空句柄表示进程被调试。
    pub fn check_debug_object_handle() -> Result<bool> {
        let handle = unsafe { winapi::um::processthreadsapi::GetCurrentProcess() };
        let obj = query_debug_object_handle(handle)?;
        Ok(!obj.is_null())
    }

    /// 跨进程查询 DebugPort（只读，最小权限）
    ///
    /// 打开目标进程句柄（仅需 `PROCESS_QUERY_INFORMATION`），
    /// 通过 `NtQueryInformationProcess(ProcessDebugPort)` 查询。
    pub fn check_remote_debug_port(pid: u32) -> Result<u32> {
        let handle = open_process_for_query(pid)?;
        let result = query_debug_port(handle);
        unsafe {
            winapi::um::handleapi::CloseHandle(handle);
        }
        result
    }

    /// 跨进程查询 DebugObjectHandle（只读，最小权限）
    pub fn check_remote_debug_object_handle(pid: u32) -> Result<bool> {
        let handle = open_process_for_query(pid)?;
        let result = query_debug_object_handle(handle).map(|obj| !obj.is_null());
        unsafe {
            winapi::um::handleapi::CloseHandle(handle);
        }
        result
    }

    /// 检查进程堆调试标志（Flags/ForceFlags）
    ///
    /// 调试状态下堆 Flags 会附加堆调试位（如 0x5000006F），
    /// ForceFlags 非 0 也说明进程曾被调试。
    pub fn check_heap_flags() -> Result<(u32, u32)> {
        unsafe {
            let peb = get_peb_address();
            if peb.is_null() {
                return Err(FridaError::AntiDetect {
                    reason: "无法获取 PEB 地址".into(),
                }
                .into());
            }
            let heap_ptr = read_pointer_at(peb.add(PEB_PROCESS_HEAP_OFFSET));
            if heap_ptr == 0 {
                return Ok((0, 0));
            }
            let flags = *((heap_ptr as *const u8).add(HEAP_FLAGS_OFFSET) as *const u32);
            let force_flags = *((heap_ptr as *const u8).add(HEAP_FORCE_FLAGS_OFFSET) as *const u32);
            Ok((flags, force_flags))
        }
    }

    /// 时间差检测（实验性）
    ///
    /// 以 `rdtsc + mfence` 序列包住两次 `QueryPerformanceCounter`，
    /// 调试器介入（单步/断点）会导致耗时显著增大。返回耗时（QPC 计数）。
    #[cfg(target_arch = "x86_64")]
    pub fn check_timing_diff() -> Result<u64> {
        use winapi::shared::ntdef::LARGE_INTEGER;
        use winapi::um::profileapi::QueryPerformanceCounter;
        let mut t1: LARGE_INTEGER = unsafe { std::mem::zeroed() };
        let mut t2: LARGE_INTEGER = unsafe { std::mem::zeroed() };
        unsafe {
            QueryPerformanceCounter(&mut t1);
            std::arch::x86_64::_mm_mfence();
            let _ = std::arch::x86_64::_rdtsc();
            std::arch::x86_64::_mm_mfence();
            let _ = std::arch::x86_64::_rdtsc();
            QueryPerformanceCounter(&mut t2);
        }
        let diff = unsafe { t2.QuadPart() - t1.QuadPart() };
        Ok(diff.max(0) as u64)
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn check_timing_diff() -> Result<u64> {
        Ok(0)
    }

    /// 检查是否处于调试状态
    ///
    /// 调用 Windows API `IsDebuggerPresent` 进行快速检测。
    pub fn is_debugger_present() -> bool {
        unsafe { winapi::um::debugapi::IsDebuggerPresent() != 0 }
    }

    /// 检查 PEB BeingDebugged 标志
    ///
    /// 读取 PEB+0x02 处的字节，非 0 表示进程正被调试。
    pub fn check_peb_being_debugged() -> Result<bool> {
        unsafe {
            let peb = get_peb_address();
            if peb.is_null() {
                return Err(FridaError::AntiDetect {
                    reason: "无法获取 PEB 地址".into(),
                }
                .into());
            }
            let being_debugged = (peb as *const u8).add(PEB_BEING_DEBUGGED_OFFSET);
            Ok(*being_debugged != 0)
        }
    }

    /// 检查 PEB NtGlobalFlag
    ///
    /// 读取 PEB+0xBC 处的双字。若设置了堆调试标志
    /// （FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK |
    /// FLG_HEAP_VALIDATE_PARAMETERS = 0x70），说明可能处于调试状态。
    pub fn check_nt_global_flag() -> Result<u32> {
        unsafe {
            let peb = get_peb_address();
            if peb.is_null() {
                return Err(FridaError::AntiDetect {
                    reason: "无法获取 PEB 地址".into(),
                }
                .into());
            }
            let flag = (peb as *const u32).add(PEB_NT_GLOBAL_FLAG_OFFSET / 4);
            Ok(*flag)
        }
    }

    /// 检查调试寄存器 (Dr0-Dr7)
    ///
    /// 读取当前线程上下文中的硬件断点寄存器，
    /// 任一非零说明设置了硬件断点。
    pub fn check_debug_registers() -> Result<bool> {
        use winapi::um::processthreadsapi::{GetCurrentThread, GetThreadContext};
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

            Ok(ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0 || ctx.Dr7 != 0)
        }
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

/// 以读写权限打开目标进程句柄（查询 + 读写内存）
fn open_process_for_stealth(pid: u32) -> Result<winapi::um::winnt::HANDLE> {
    use winapi::um::processthreadsapi::OpenProcess;
    use winapi::um::winnt::{
        PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
    };
    let handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
            0,
            pid,
        )
    };
    if handle.is_null() {
        let err = std::io::Error::last_os_error();
        return Err(FridaError::AntiDetect {
            reason: format!("OpenProcess({}) 失败: {}", pid, err),
        }
        .into());
    }
    Ok(handle)
}

/// 以查询权限打开目标进程句柄（跨进程只读分析，权限面最小化）
fn open_process_for_query(pid: u32) -> Result<winapi::um::winnt::HANDLE> {
    use winapi::um::processthreadsapi::OpenProcess;
    use winapi::um::winnt::PROCESS_QUERY_INFORMATION;
    let handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION, 0, pid) };
    if handle.is_null() {
        let err = std::io::Error::last_os_error();
        return Err(FridaError::AntiDetect {
            reason: format!("OpenProcess({}) 失败: {}", pid, err),
        }
        .into());
    }
    Ok(handle)
}

/// 读取远程进程内存（任意 Copy 类型）
fn read_remote<T: Copy>(handle: winapi::um::winnt::HANDLE, addr: *const u8) -> Result<T> {
    use winapi::um::memoryapi::ReadProcessMemory;
    let mut val: T = unsafe { std::mem::zeroed() };
    let mut read: usize = 0;
    let ok = unsafe {
        ReadProcessMemory(
            handle,
            addr as *const winapi::ctypes::c_void,
            &mut val as *mut T as *mut winapi::ctypes::c_void,
            std::mem::size_of::<T>(),
            &mut read,
        )
    };
    if ok == 0 {
        let err = std::io::Error::last_os_error();
        return Err(FridaError::AntiDetect {
            reason: format!("ReadProcessMemory({:#x}) 失败: {}", addr as usize, err),
        }
        .into());
    }
    Ok(val)
}

/// 写入远程进程内存（任意 Copy 类型）
fn write_remote<T: Copy>(handle: winapi::um::winnt::HANDLE, addr: *mut u8, val: T) -> Result<()> {
    use winapi::um::memoryapi::WriteProcessMemory;
    let mut written: usize = 0;
    let ok = unsafe {
        WriteProcessMemory(
            handle,
            addr as *mut winapi::ctypes::c_void,
            &val as *const T as *const winapi::ctypes::c_void,
            std::mem::size_of::<T>(),
            &mut written,
        )
    };
    if ok == 0 {
        let err = std::io::Error::last_os_error();
        return Err(FridaError::AntiDetect {
            reason: format!("WriteProcessMemory({:#x}) 失败: {}", addr as usize, err),
        }
        .into());
    }
    Ok(())
}

/// 读取远程进程的指针宽度值
fn read_remote_pointer(handle: winapi::um::winnt::HANDLE, addr: *const u8) -> Result<usize> {
    #[cfg(target_arch = "x86_64")]
    {
        Ok(read_remote::<u64>(handle, addr)? as usize)
    }
    #[cfg(target_arch = "x86")]
    {
        Ok(read_remote::<u32>(handle, addr)? as usize)
    }
}

/// 读取自身进程地址处的指针宽度值
#[cfg(target_arch = "x86_64")]
unsafe fn read_pointer_at(addr: *const u8) -> usize {
    *(addr as *const u64) as usize
}

/// 读取自身进程地址处的指针宽度值
#[cfg(target_arch = "x86")]
unsafe fn read_pointer_at(addr: *const u8) -> usize {
    *(addr as *const u32) as usize
}

/// 查询进程基本信息（获取远程 PEB 地址）
fn query_basic_information(
    handle: winapi::um::winnt::HANDLE,
) -> Result<ProcessBasicInformation> {
    let mut info: ProcessBasicInformation = unsafe { std::mem::zeroed() };
    let mut ret_len: u32 = 0;
    let status = unsafe {
        NtQueryInformationProcess(
            handle,
            PROCESS_BASIC_INFORMATION_CLASS,
            &mut info as *mut _ as *mut winapi::ctypes::c_void,
            std::mem::size_of::<ProcessBasicInformation>() as u32,
            &mut ret_len,
        )
    };
    if status != 0 {
        return Err(FridaError::AntiDetect {
            reason: format!(
                "NtQueryInformationProcess(BasicInformation) 失败: {:#x}",
                status
            ),
        }
        .into());
    }
    Ok(info)
}

/// 查询进程调试端口（DebugPort）
fn query_debug_port(handle: winapi::um::winnt::HANDLE) -> Result<u32> {
    // DebugPort 返回值为 ULONG_PTR（x64 下 8 字节），用 usize 接收避免长度不匹配
    let mut port: usize = 0;
    let mut ret_len: u32 = 0;
    let status = unsafe {
        NtQueryInformationProcess(
            handle,
            PROCESS_DEBUG_PORT_CLASS,
            &mut port as *mut usize as *mut winapi::ctypes::c_void,
            std::mem::size_of::<usize>() as u32,
            &mut ret_len,
        )
    };
    if status != 0 {
        return Err(FridaError::AntiDetect {
            reason: format!("NtQueryInformationProcess(DebugPort) 失败: {:#x}", status),
        }
        .into());
    }
    Ok(port as u32)
}

/// 查询进程调试对象句柄（DebugObjectHandle）
fn query_debug_object_handle(
    handle: winapi::um::winnt::HANDLE,
) -> Result<*mut winapi::ctypes::c_void> {
    let mut obj: *mut winapi::ctypes::c_void = std::ptr::null_mut();
    let mut ret_len: u32 = 0;
    let status = unsafe {
        NtQueryInformationProcess(
            handle,
            PROCESS_DEBUG_OBJECT_HANDLE_CLASS,
            &mut obj as *mut _ as *mut winapi::ctypes::c_void,
            std::mem::size_of::<*mut winapi::ctypes::c_void>() as u32,
            &mut ret_len,
        )
    };
    if status == STATUS_PORT_NOT_SET {
        // 无调试对象：视为未调试
        return Ok(std::ptr::null_mut());
    }
    if status != 0 {
        return Err(FridaError::AntiDetect {
            reason: format!(
                "NtQueryInformationProcess(DebugObjectHandle) 失败: {:#x}",
                status
            ),
        }
        .into());
    }
    Ok(obj)
}

/// 读取远程进程 PEB 调试状态（内部，需已持有句柄）
fn read_remote_peb_internal(handle: winapi::um::winnt::HANDLE) -> Result<RemotePebInfo> {
    let basic = query_basic_information(handle)?;
    let peb = basic.peb_base_address as *const u8;
    if peb.is_null() {
        return Err(FridaError::AntiDetect {
            reason: "远程 PEB 地址为空".into(),
        }
        .into());
    }
    let being_debugged =
        read_remote::<u8>(handle, unsafe { peb.add(PEB_BEING_DEBUGGED_OFFSET) })?;
    let nt_global_flag =
        read_remote::<u32>(handle, unsafe { peb.add(PEB_NT_GLOBAL_FLAG_OFFSET) })?;
    let heap_ptr =
        read_remote_pointer(handle, unsafe { peb.add(PEB_PROCESS_HEAP_OFFSET) })?;
    let (heap_flags, heap_force_flags) = if heap_ptr != 0 {
        let flags = read_remote::<u32>(
            handle,
            unsafe { (heap_ptr as *const u8).add(HEAP_FLAGS_OFFSET) },
        )?;
        let force = read_remote::<u32>(
            handle,
            unsafe { (heap_ptr as *const u8).add(HEAP_FORCE_FLAGS_OFFSET) },
        )?;
        (flags, force)
    } else {
        (0, 0)
    };
    Ok(RemotePebInfo {
        being_debugged,
        nt_global_flag,
        heap_flags,
        heap_force_flags,
    })
}

/// 枚举远程进程 Ldr 模块链（内部，需已持有句柄）
fn enum_remote_ldr_modules_internal(handle: winapi::um::winnt::HANDLE) -> Result<Vec<RemoteLdrModule>> {
    let basic = query_basic_information(handle)?;
    let peb = basic.peb_base_address as *const u8;
    if peb.is_null() {
        return Err(FridaError::AntiDetect {
            reason: "远程 PEB 地址为空".into(),
        }
        .into());
    }
    let ldr = read_remote_pointer(handle, unsafe { peb.add(PEB_LDR_OFFSET) })?;
    if ldr == 0 {
        return Ok(Vec::new());
    }
    let head = ldr + LDR_IN_MEMORY_ORDER_LIST_OFFSET;
    let mut modules = Vec::new();
    let mut cur = read_remote_pointer(handle, head as *const u8)?;
    let mut guard = 0usize;
    while cur != head && guard < 1024 {
        guard += 1;
        let entry = cur - LDR_IN_MEMORY_LINKS_OFFSET;
        let base = read_remote_pointer(handle, (entry + LDR_DLL_BASE_OFFSET) as *const u8)?;
        let size = read_remote::<u32>(handle, (entry + LDR_SIZE_OF_IMAGE_OFFSET) as *const u8)?;
        let name = read_remote_base_dll_name(handle, entry)?;
        modules.push(RemoteLdrModule {
            base,
            size: size as usize,
            name,
        });
        cur = read_remote_pointer(handle, cur as *const u8)?;
    }
    Ok(modules)
}

/// 读取远程 LDR_DATA_TABLE_ENTRY 的 BaseDllName（UNICODE_STRING）
fn read_remote_base_dll_name(
    handle: winapi::um::winnt::HANDLE,
    entry: usize,
) -> Result<String> {
    let name_addr = (entry + LDR_BASE_DLL_NAME_OFFSET) as *const u8;
    let length = read_remote::<u16>(handle, name_addr)? as usize;
    let buffer = read_remote_pointer(handle, unsafe {
        name_addr.add(UNICODE_STRING_BUFFER_OFFSET)
    })?;
    if length == 0 || buffer == 0 {
        return Ok(String::new());
    }
    // 读取 UTF-16LE 字节并解码
    let mut bytes = vec![0u8; length];
    let mut read_len = 0usize;
    let ok = unsafe {
        winapi::um::memoryapi::ReadProcessMemory(
            handle,
            buffer as *const winapi::ctypes::c_void,
            bytes.as_mut_ptr() as *mut winapi::ctypes::c_void,
            length,
            &mut read_len,
        )
    };
    if ok == 0 {
        return Ok(String::new());
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    Ok(String::from_utf16_lossy(&units))
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

    #[test]
    fn test_remote_peb_read_self() {
        let pid = crate::common::util::current_process_id().0;
        let info = WinStealthManager::read_remote_peb(pid).expect("读取自身 PEB 失败");
        // 未调试时 BeingDebugged 应为 0
        assert_eq!(info.being_debugged, 0, "常规运行下 BeingDebugged 应为 0");
        // NtGlobalFlag 至少能读到值（可为 0）
        let _ = info.nt_global_flag;
        let _ = info.heap_flags;
        let _ = info.heap_force_flags;
    }

    #[test]
    fn test_apply_to_process_self() {
        let pid = crate::common::util::current_process_id().0;
        let result = WinStealthManager::apply_to_process(pid);
        assert!(result.is_ok(), "对自身应用跨进程清理应成功: {:?}", result.err());
        let info = WinStealthManager::read_remote_peb(pid).expect("复查自身 PEB 失败");
        assert_eq!(info.being_debugged, 0);
    }

    #[test]
    fn test_enum_remote_ldr_modules_self() {
        let pid = crate::common::util::current_process_id().0;
        let modules = WinStealthManager::enum_remote_ldr_modules(pid)
            .expect("枚举自身 Ldr 模块链失败");
        assert!(!modules.is_empty(), "自身模块链不应为空");
        // 应至少包含一个含 .dll/.exe 的模块
        assert!(
            modules.iter().any(|m| m.name.to_lowercase().contains(".dll") || m.name.to_lowercase().contains(".exe")),
            "应包含 DLL/EXE 模块: {:?}",
            modules.iter().map(|m| m.name.as_str()).take(8).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_hide_remote_module_not_found() {
        let pid = crate::common::util::current_process_id().0;
        let result = WinStealthManager::hide_remote_module(pid, "definitely_not_exist_xyz.dll");
        assert!(
            result.is_err(),
            "隐藏不存在的模块应返回错误: {:?}",
            result
        );
    }

    #[test]
    fn test_check_remote_debug_port_self() {
        let pid = crate::common::util::current_process_id().0;
        let result = WinStealthManager::check_remote_debug_port(pid);
        assert!(result.is_ok(), "跨进程 DebugPort 查询应成功: {:?}", result.err());
    }

    #[test]
    fn test_check_remote_debug_object_handle_self() {
        let pid = crate::common::util::current_process_id().0;
        let result = WinStealthManager::check_remote_debug_object_handle(pid);
        assert!(result.is_ok(), "跨进程 DebugObjectHandle 查询应成功: {:?}", result.err());
    }

    #[test]
    fn test_check_debug_port() {
        let result = WinStealthManager::check_debug_port();
        assert!(result.is_ok(), "DebugPort 查询应成功: {:?}", result.err());
    }

    #[test]
    fn test_check_debug_object_handle() {
        let result = WinStealthManager::check_debug_object_handle();
        assert!(result.is_ok(), "DebugObjectHandle 查询应成功: {:?}", result.err());
    }

    #[test]
    fn test_check_heap_flags() {
        let result = WinStealthManager::check_heap_flags();
        assert!(result.is_ok(), "堆标志读取应成功: {:?}", result.err());
    }

    #[test]
    fn test_check_timing_diff() {
        let result = WinStealthManager::check_timing_diff();
        assert!(result.is_ok(), "时间差检测应成功: {:?}", result.err());
    }
}
