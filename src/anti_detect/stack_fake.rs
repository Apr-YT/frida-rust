//! 调用栈伪造模块
//!
//! 对 backtrace 等调用栈采集函数进行干扰，
//! 过滤掉来自 Hook 引擎内存范围的调用帧，
//! 伪造连续的合法调用栈序列，防止检测者通过调用栈分析发现 Hook 框架。

use std::ops::Range;

// ======================== 调用帧类型 ========================

/// 单个调用栈帧描述
#[derive(Debug, Clone)]
pub struct Frame {
    /// 返回地址
    pub addr: u64,
    /// 符号名称（可能为空）
    pub symbol_name: String,
    /// 所属模块名称（可能为空）
    pub module_name: String,
}

impl Frame {
    /// 创建新的调用栈帧
    pub fn new(addr: u64, symbol_name: &str, module_name: &str) -> Self {
        Frame {
            addr,
            symbol_name: symbol_name.to_string(),
            module_name: module_name.to_string(),
        }
    }

    /// 创建无符号信息的调用栈帧
    pub fn from_addr(addr: u64) -> Self {
        Frame {
            addr,
            symbol_name: String::new(),
            module_name: String::new(),
        }
    }
}

impl std::fmt::Display for Frame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.symbol_name.is_empty() && self.module_name.is_empty() {
            write!(f, "{:#x}", self.addr)
        } else if self.module_name.is_empty() {
            write!(f, "{} @ {:#x}", self.symbol_name, self.addr)
        } else {
            write!(
                f,
                "{} [{}] @ {:#x}",
                self.symbol_name, self.module_name, self.addr
            )
        }
    }
}

// ======================== 调用栈伪造器 ========================

/// 调用栈伪造器
///
/// 对采集到的调用栈进行分析和重写，
/// 移除来自 Hook 引擎的敏感帧，伪造连续的合法调用序列。
pub struct StackFaker {
    /// 需要过滤的内存范围列表（Hook 引擎所在的内存区域）
    deny_ranges: Vec<Range<u64>>,
    /// 允许伪造的目标范围列表（合法模块所在的内存区域）
    allow_ranges: Vec<Range<u64>>,
    /// 是否已启用
    enabled: bool,
}

impl StackFaker {
    /// 创建新的调用栈伪造器
    pub fn new() -> Self {
        StackFaker {
            deny_ranges: Vec::new(),
            allow_ranges: Vec::new(),
            enabled: true,
        }
    }

    /// 添加需要过滤的内存范围
    ///
    /// 来自这些范围内的调用帧会被移除。
    pub fn add_deny_range(&mut self, range: Range<u64>) {
        self.deny_ranges.push(range);
    }

    /// 添加允许伪造的目标内存范围
    ///
    /// 伪造的调用帧地址会在这些范围内生成。
    pub fn add_allow_range(&mut self, range: Range<u64>) {
        self.allow_ranges.push(range);
    }

    /// 从 /proc/self/maps 自动配置 deny 范围
    ///
    /// 读取当前进程的内存映射，将包含特征路径的区域添加到 deny 列表中。
    pub fn auto_configure_deny(&mut self) -> crate::Result<()> {
        let regions = crate::common::util::parse_proc_maps(crate::common::types::ProcessId(0))?;

        // 需要隐藏的特征关键词
        #[cfg(unix)]
        let keywords = ["frida", "agent", "gadget", "linjector", "hook"];
        #[cfg(windows)]
        let keywords = ["frida", "agent", "gadget", "linjector", "hook", "frida-rust", "dll"];

        for region in &regions {
            for keyword in &keywords {
                if region.name.to_lowercase().contains(keyword) {
                    log::debug!(
                        "调用栈伪造: 添加 deny 范围 {:#x}-{:#x} ({})",
                        region.start,
                        region.end,
                        region.name
                    );
                    self.deny_ranges.push(region.start as u64..region.end as u64);
                    break;
                }
            }
        }

        Ok(())
    }

    /// 从 /proc/self/maps 自动配置 allow 范围
    ///
    /// 将主程序和常见系统库的区域添加到 allow 列表中，
    /// 作为伪造调用帧的目标地址范围。
    pub fn auto_configure_allow(&mut self) -> crate::Result<()> {
        let regions = crate::common::util::parse_proc_maps(crate::common::types::ProcessId(0))?;

        // 允许的合法模块关键词
        #[cfg(unix)]
        let allow_keywords = [
            "libc.so",
            "libpthread",
            "libdl",
            "libm.so",
            "linker",
            "/system/",
            "app_process",
            "dalvik",
        ];
        #[cfg(windows)]
        let allow_keywords = [
            "kernel32.dll",
            "ntdll.dll",
            "user32.dll",
            "msvcrt.dll",
            "ucrtbase.dll",
            "kernelbase.dll",
            ".exe",
        ];

        for region in &regions {
            for keyword in &allow_keywords {
                if region.name.contains(keyword) && region.perms.execute {
                    log::debug!(
                        "调用栈伪造: 添加 allow 范围 {:#x}-{:#x} ({})",
                        region.start,
                        region.end,
                        region.name
                    );
                    self.allow_ranges.push(region.start as u64..region.end as u64);
                    break;
                }
            }
        }

        Ok(())
    }

    /// 伪造调用栈
    ///
    /// 对原始调用栈进行分析和重写：
    /// 1. 过滤掉来自 deny 范围内的调用帧
    /// 2. 在过滤后的栈中插入伪造的合法调用帧
    /// 3. 确保最终的调用栈是连续的、合法的
    ///
    /// # 参数
    /// - `original_stack`: 原始调用栈
    /// - `allowed_ranges`: 允许的合法内存范围（用于生成伪造帧）
    ///
    /// # 返回值
    /// 伪造后的调用栈
    pub fn fake_call_stack(
        &self,
        original_stack: &[Frame],
        allowed_ranges: &[Range<u64>],
    ) -> Vec<Frame> {
        if !self.enabled {
            return original_stack.to_vec();
        }

        // 第一步：过滤掉 deny 范围内的帧
        let filtered: Vec<Frame> = original_stack
            .iter()
            .filter(|frame| {
                // 检查帧地址是否在任何 deny 范围内
                !self.deny_ranges.iter().any(|range| range.contains(&frame.addr))
            })
            .cloned()
            .collect();

        if filtered.is_empty() || allowed_ranges.is_empty() {
            return filtered;
        }

        // 第二步：在帧之间插入伪造帧以保持连续性
        let mut result = Vec::with_capacity(filtered.len());

        for (i, frame) in filtered.iter().enumerate() {
            result.push(frame.clone());

            // 如果当前帧与下一帧之间的距离过大（超过页面大小），
            // 插入伪造的过渡帧
            if i + 1 < filtered.len() {
                let next = &filtered[i + 1];
                let gap = if next.addr > frame.addr {
                    next.addr - frame.addr
                } else {
                    frame.addr - next.addr
                };

                // 如果帧间距超过 256KB，可能需要填充
                if gap > 256 * 1024 {
                    // 在合法范围内生成一个伪造帧
                    if let Some(fake_addr) = self.generate_fake_addr(allowed_ranges) {
                        let fake_frame = Frame::from_addr(fake_addr);
                        log::trace!(
                            "调用栈伪造: 在 {:#x} 和 {:#x} 之间插入伪造帧 {:#x}",
                            frame.addr,
                            next.addr,
                            fake_addr
                        );
                        result.push(fake_frame);
                    }
                }
            }
        }

        result
    }

    /// 在允许范围内生成一个伪造地址
    ///
    /// 随机选择一个允许范围，在其中生成一个看起来合法的地址。
    fn generate_fake_addr(&self, allowed_ranges: &[Range<u64>]) -> Option<u64> {
        if allowed_ranges.is_empty() {
            return None;
        }

        // 随机选择一个范围
        let idx = (self.hash_random() as usize) % allowed_ranges.len();
        let range = &allowed_ranges[idx];

        // 在范围内生成地址（偏移对齐到 4 字节）
        let range_size = range.end.saturating_sub(range.start);
        if range_size < 16 {
            return None;
        }

        let offset = (self.hash_random() % (range_size / 4)) * 4;
        let fake_addr = range.start + offset;

        Some(fake_addr)
    }

    /// 简单的伪随机数生成（不使用 rand crate，避免额外依赖）
    fn hash_random(&self) -> u64 {
        use std::time::SystemTime;
        let time = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        // 简单的混合函数
        let mut h = time as u64;
        h ^= h >> 33;
        h = h.wrapping_mul(0xff51afd7ed558ccd);
        h ^= h >> 33;
        h = h.wrapping_mul(0xc4ceb9fe1a85ec53);
        h ^= h >> 33;
        h
    }

    /// 启用调用栈伪造
    pub fn enable(&mut self) {
        self.enabled = true;
        log::info!("调用栈伪造已启用");
    }

    /// 禁用调用栈伪造
    pub fn disable(&mut self) {
        self.enabled = false;
        log::info!("调用栈伪造已禁用");
    }

    /// 检查指定地址是否在 deny 范围内
    pub fn is_denied(&self, addr: u64) -> bool {
        self.deny_ranges.iter().any(|range| range.contains(&addr))
    }

    /// 获取当前的 deny 范围数量
    pub fn deny_range_count(&self) -> usize {
        self.deny_ranges.len()
    }

    /// 获取当前的 allow 范围数量
    pub fn allow_range_count(&self) -> usize {
        self.allow_ranges.len()
    }
}

impl Default for StackFaker {
    fn default() -> Self {
        Self::new()
    }
}

// ======================== 便捷函数 ========================

/// 伪造调用栈的便捷函数
///
/// 对原始调用栈进行伪造处理，过滤敏感帧并插入合法帧。
///
/// # 参数
/// - `original_stack`: 原始调用栈
/// - `allowed_ranges`: 允许的合法内存范围列表
///
/// # 返回值
/// 伪造后的调用栈
pub fn fake_call_stack(
    original_stack: &[Frame],
    allowed_ranges: &[Range<u64>],
) -> Vec<Frame> {
    let faker = StackFaker::new();
    faker.fake_call_stack(original_stack, allowed_ranges)
}

// ======================== Windows 栈回溯器 ========================

/// Windows 栈回溯器
///
/// 使用 `CaptureStackBackTrace` API 捕获当前调用栈。
#[cfg(windows)]
pub struct StackWalker;

#[cfg(windows)]
impl StackWalker {
    /// 捕获当前调用栈
    pub fn capture() -> Vec<Frame> {
        unsafe {
            const MAX_FRAMES: u32 = 64;
            let mut buffer: [*mut winapi::ctypes::c_void; MAX_FRAMES as usize] =
                std::mem::zeroed();

            let count = CaptureStackBackTrace(
                0,
                MAX_FRAMES,
                buffer.as_mut_ptr(),
                std::ptr::null_mut(),
            );

            let mut frames = Vec::with_capacity(count as usize);
            for i in 0..count as usize {
                frames.push(Frame::from_addr(buffer[i] as u64));
            }
            frames
        }
    }
}

#[cfg(windows)]
#[link(name = "dbghelp")]
extern "system" {
    fn CaptureStackBackTrace(
        FramesToSkip: u32,
        FramesToCapture: u32,
        BackTrace: *mut *mut winapi::ctypes::c_void,
        BackTraceHash: *mut u32,
    ) -> u32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_creation() {
        let frame = Frame::new(0x12345, "main", "app");
        assert_eq!(frame.addr, 0x12345);
        assert_eq!(frame.symbol_name, "main");
        assert_eq!(frame.module_name, "app");
    }

    #[test]
    fn test_frame_display() {
        let frame = Frame::new(0x12345, "main", "app");
        let s = format!("{}", frame);
        assert!(s.contains("main"));
        assert!(s.contains("app"));
    }

    #[test]
    fn test_stack_faker_filter() {
        let mut faker = StackFaker::new();
        faker.add_deny_range(0x10000..0x20000);

        let stack = vec![
            Frame::from_addr(0x5000),
            Frame::from_addr(0x15000), // 在 deny 范围内
            Frame::from_addr(0x30000),
        ];

        let result = faker.fake_call_stack(&stack, &[]);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].addr, 0x5000);
        assert_eq!(result[1].addr, 0x30000);
    }

    #[test]
    fn test_stack_faker_disabled() {
        let mut faker = StackFaker::new();
        faker.add_deny_range(0x10000..0x20000);
        faker.disable();

        let stack = vec![
            Frame::from_addr(0x5000),
            Frame::from_addr(0x15000),
        ];

        let result = faker.fake_call_stack(&stack, &[]);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_is_denied() {
        let mut faker = StackFaker::new();
        faker.add_deny_range(0x10000..0x20000);
        assert!(faker.is_denied(0x15000));
        assert!(!faker.is_denied(0x5000));
    }

    #[test]
    fn test_fake_call_stack_function() {
        let stack = vec![
            Frame::from_addr(0x1000),
            Frame::from_addr(0x2000),
        ];
        let ranges = vec![0x10000..0x20000];

        let result = fake_call_stack(&stack, &ranges);
        assert!(!result.is_empty());
    }
}
