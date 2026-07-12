//! Frida 特征字符串擦除模块
//!
//! 扫描并擦除内存中与 Frida 相关的特征字符串，
//! 防止通过字符串扫描检测到 Frida 的存在。
//!
//! 实现策略：
//! 1. 枚举所有可读内存区域
//! 2. 在每个区域中搜索已知的 Frida 特征字符串
//! 3. 找到后用零填充（或替换为无害字符串）

use crate::common::types::{MemoryRegion, ProcessId};
use crate::FridaError;
use crate::Result;

// ======================== 特征擦除器 Trait ========================

/// 特征擦除操作 trait
///
/// 使用 trait + 默认实现的方式，方便后续扩展不同的擦除策略。
pub trait SignatureEraser {
    /// 执行特征擦除
    fn erase(&self) -> Result<usize>;

    /// 获取已知的特征列表
    fn signatures(&self) -> &[&[u8]];

    /// 添加自定义特征
    fn add_signature(&mut self, sig: Vec<u8>);

    /// 设置是否用随机字符串替换（而非零填充）
    fn set_random_replace(&mut self, enable: bool);
}

// ======================== 默认特征擦除实现 ========================

/// 默认的特征字符串擦除器
///
/// 在进程地址空间中搜索并替换已知的特征字符串。
pub struct DefaultSignatureEraser {
    /// 已知的 Frida 特征字符串列表
    known_sigs: Vec<Vec<u8>>,
    /// 是否使用随机字符串替换（而非零填充）
    random_replace: bool,
}

impl DefaultSignatureEraser {
    /// 创建默认擦除器，使用预定义的特征列表
    pub fn new() -> Self {
        DefaultSignatureEraser {
            known_sigs: Self::default_signatures()
                .iter()
                .map(|s| s.to_vec())
                .collect(),
            random_replace: false,
        }
    }

    /// 获取默认的已知 Frida 特征列表
    pub fn default_signatures() -> &'static [&'static [u8]] {
        &SIGNATURE_LIST
    }

    /// 在指定内存区域中搜索特征字符串
    ///
    /// # 参数
    /// - `data`: 内存区域数据
    /// - `base_addr`: 区域起始地址（用于日志）
    ///
    /// # 返回值
    /// 找到的匹配位置列表：(偏移量, 特征索引)
    fn search_in_region(&self, data: &[u8], base_addr: usize) -> Vec<(usize, usize)> {
        let mut matches = Vec::new();

        for (sig_idx, sig) in self.known_sigs.iter().enumerate() {
            if sig.is_empty() {
                continue;
            }
            // 在数据中搜索特征
            let mut search_pos = 0;
            while search_pos + sig.len() <= data.len() {
                if let Some(pos) = data[search_pos..]
                    .windows(sig.len())
                    .position(|window| window == sig.as_slice())
                {
                    let abs_pos = search_pos + pos;
                    matches.push((abs_pos, sig_idx));
                    log::debug!(
                        "特征匹配: {:#x} (偏移 {}) -> 特征 #{}: {:?}",
                        base_addr + abs_pos,
                        abs_pos,
                        sig_idx,
                        String::from_utf8_lossy(sig)
                    );
                    search_pos = abs_pos + 1;
                } else {
                    break;
                }
            }
        }

        matches
    }

    /// 擦除指定位置的特征字符串
    ///
    /// # 参数
    /// - `data`: 内存区域数据（可变）
    /// - `offset`: 特征在数据中的偏移
    /// - `sig`: 特征字节
    #[allow(dead_code)]
    fn erase_at(data: &mut [u8], offset: usize, sig: &[u8]) {
        if offset + sig.len() > data.len() {
            return;
        }

        // 用零填充
        for i in 0..sig.len() {
            data[offset + i] = 0;
        }
    }

    /// 用随机字符串替换指定位置的特征
    #[allow(dead_code)]
    fn replace_at(data: &mut [u8], offset: usize, sig: &[u8]) {
        if offset + sig.len() > data.len() {
            return;
        }

        // 使用简单的伪随机字节替换（非零，以避免空字符串特征）
        for i in 0..sig.len() {
            // 对每个字符进行简单的替换
            data[offset + i] = b'x'; // 统一替换为 'x'（简单且可预测）
        }
    }
}

impl SignatureEraser for DefaultSignatureEraser {
    /// 执行特征擦除
    ///
    /// 遍历所有可读内存区域，搜索并擦除特征字符串。
    ///
    /// # 返回值
    /// 擦除的特征总数
    fn erase(&self) -> Result<usize> {
        log::info!("开始擦除 Frida 特征字符串");

        let regions = crate::common::util::parse_proc_maps(ProcessId(0))?;
        let mut total_erased = 0;

        for region in &regions {
            // 跳过不可读区域
            if !region.perms.read {
                continue;
            }

            // 跳过过大的区域（防止读取过多内存）
            if region.size() > 100 * 1024 * 1024 {
                log::debug!(
                    "跳过过大区域: {:#x}-{:#x} ({} bytes)",
                    region.start,
                    region.end,
                    region.size()
                );
                continue;
            }

            // 读取区域数据
            let data = match self.read_region(region) {
                Ok(d) => d,
                Err(_) => continue,
            };

            // 搜索特征
            let matches = self.search_in_region(&data, region.start);

            if !matches.is_empty() {
                log::info!(
                    "在区域 {:#x}-{:#x} ({}) 中发现 {} 个特征",
                    region.start,
                    region.end,
                    region.name,
                    matches.len()
                );

                // 擦除特征
                // 注意：需要写权限才能修改内存
                // 这里使用 unsafe 直接写入（实际场景需要先 mprotect）
                for (offset, sig_idx) in &matches {
                    let sig = &self.known_sigs[*sig_idx];
                    #[cfg(unix)]
                    unsafe {
                        let addr = (region.start + offset) as *mut u8;
                        for i in 0..sig.len() {
                            std::ptr::write_volatile(addr.add(i), 0);
                        }
                    }
                    #[cfg(windows)]
                    unsafe {
                        let addr = region.start + offset;
                        let mut written = 0;
                        let handle = winapi::um::processthreadsapi::GetCurrentProcess();
                        let zeros = vec![0u8; sig.len()];
                        let ok = winapi::um::memoryapi::WriteProcessMemory(
                            handle,
                            addr as *mut winapi::ctypes::c_void,
                            zeros.as_ptr() as *const winapi::ctypes::c_void,
                            sig.len(),
                            &mut written,
                        );
                        if ok == 0 {
                            log::warn!(
                                "WriteProcessMemory 失败于地址 {:#x}: {}",
                                addr,
                                std::io::Error::last_os_error()
                            );
                        }
                    }
                    total_erased += 1;
                }
            }
        }

        log::info!("特征擦除完成: 共擦除 {} 处", total_erased);
        Ok(total_erased)
    }

    /// 获取已知的特征列表
    fn signatures(&self) -> &[&[u8]] {
        // 返回引用（需要转换）
        // 这里简化处理：直接返回静态列表
        &SIGNATURE_LIST
    }

    /// 添加自定义特征
    fn add_signature(&mut self, sig: Vec<u8>) {
        if !sig.is_empty() && !self.known_sigs.contains(&sig) {
            log::info!("添加自定义特征: {:?}", String::from_utf8_lossy(&sig));
            self.known_sigs.push(sig);
        }
    }

    /// 设置是否用随机字符串替换
    fn set_random_replace(&mut self, enable: bool) {
        self.random_replace = enable;
    }
}

impl DefaultSignatureEraser {
    /// 读取指定内存区域的数据（Unix 版本）
    #[cfg(unix)]
    fn read_region(&self, region: &MemoryRegion) -> Result<Vec<u8>> {
        let size = region.size();
        if size == 0 {
            return Ok(Vec::new());
        }

        let mut buf = vec![0u8; size];

        // 通过 /proc/self/mem 读取
        // SAFETY: 调用者需确保地址有效且可读
        let pid = std::process::id() as libc::pid_t;
        let ret = unsafe {
            crate::common::syscall_wrapper::process_vm_readv(
                pid,
                &libc::iovec {
                    iov_base: buf.as_mut_ptr() as *mut libc::c_void,
                    iov_len: size,
                },
                1,
                &libc::iovec {
                    iov_base: region.start as *mut libc::c_void,
                    iov_len: size,
                },
                1,
                0,
            )
        };

        if ret < 0 {
            return Err(FridaError::MemoryRead {
                address: region.start,
                size,
                reason: format!("process_vm_readv 失败: {}", std::io::Error::last_os_error()),
            }
            .into());
        }

        Ok(buf)
    }

    /// 读取指定内存区域的数据（Windows 版本）
    #[cfg(windows)]
    fn read_region(&self, region: &MemoryRegion) -> Result<Vec<u8>> {
        let size = region.size();
        if size == 0 {
            return Ok(Vec::new());
        }

        let mut buf = vec![0u8; size];

        unsafe {
            let handle = winapi::um::processthreadsapi::GetCurrentProcess();
            let mut read: usize = 0;
            let ok = winapi::um::memoryapi::ReadProcessMemory(
                handle,
                region.start as *const winapi::ctypes::c_void,
                buf.as_mut_ptr() as *mut winapi::ctypes::c_void,
                size,
                &mut read,
            );

            if ok == 0 {
                return Err(FridaError::MemoryRead {
                    address: region.start,
                    size,
                    reason: format!(
                        "ReadProcessMemory 失败: {}",
                        std::io::Error::last_os_error()
                    ),
                }
                .into());
            }

            if read != size {
                buf.truncate(read);
            }
        }

        Ok(buf)
    }
}

impl Default for DefaultSignatureEraser {
    fn default() -> Self {
        Self::new()
    }
}

// ======================== 已知特征列表 ========================

/// 已知的 Frida 特征字符串列表
///
/// 包含 Frida 运行时、agent、gadget 等组件中常见的特征字符串。
/// 这些字符串可能被目标应用的检测代码扫描。
static SIGNATURE_LIST: &[&[u8]] = &[
    // Frida 核心特征
    b"frida",
    b"FRIDA",
    b"LIBFRIDA",
    // Agent 相关
    b"frida-agent",
    b"frida-agent-32.so",
    b"frida-agent-64.so",
    b"frida-gadget",
    b"frida-gadget-32.so",
    b"frida-gadget-64.so",
    b"frida-server",
    // Gum 相关（Frida 的运行时引擎）
    b"gum-js",
    b"gum-js-loop",
    b"gmain",
    // 注入器
    b"linjector",
    b"frida-x86",
    b"frida-arm",
    // D-Bus 和通信相关
    b"27042",   // Frida 默认端口
    b"27043",   // Frida 备用端口
    // 字符串搜索特征（检测代码可能搜索的）
    b"LIBFRIDA_AGENT_SO",
    b"REJECT",
    // Frida 线程名
    b"gdbus",
    b"pool-frida",
    b"glib",
];

// ======================== 便捷函数 ========================

/// 擦除内存中的 Frida 特征字符串（便捷函数）
pub fn erase_frida_signatures() -> crate::Result<()> {
    let eraser = DefaultSignatureEraser::new();
    eraser.erase()?;
    Ok(())
}

/// 获取已知的 Frida 特征列表（便捷函数）
pub fn known_signatures() -> &'static [&'static [u8]] {
    &SIGNATURE_LIST
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_signatures_not_empty() {
        let sigs = known_signatures();
        assert!(!sigs.is_empty());
        assert!(sigs.len() > 10);
    }

    #[test]
    fn test_default_eraser_creation() {
        let eraser = DefaultSignatureEraser::new();
        assert!(!eraser.signatures().is_empty());
    }

    #[test]
    fn test_search_in_region() {
        let eraser = DefaultSignatureEraser::new();
        let data = b"hello frida-agent world frida\x00";
        let matches = eraser.search_in_region(data, 0x1000);
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_search_no_match() {
        let eraser = DefaultSignatureEraser::new();
        let data = b"hello world this is clean";
        let matches = eraser.search_in_region(data, 0x1000);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_erase_at() {
        let mut data = vec![b'a'; 100];
        let sig = b"frida";
        DefaultSignatureEraser::erase_at(&mut data, 10, sig);
        assert_eq!(&data[10..15], &[0, 0, 0, 0, 0]);
        assert_eq!(data[9], b'a');
        assert_eq!(data[15], b'a');
    }

    #[test]
    fn test_replace_at() {
        let mut data = vec![b'a'; 100];
        let sig = b"frida";
        DefaultSignatureEraser::replace_at(&mut data, 10, sig);
        assert_eq!(&data[10..15], b"xxxxx");
    }

    #[test]
    fn test_add_custom_signature() {
        let mut eraser = DefaultSignatureEraser::new();
        let initial_count = eraser.known_sigs.len();
        eraser.add_signature(b"custom-signature".to_vec());
        assert_eq!(eraser.known_sigs.len(), initial_count + 1);
    }

    #[test]
    fn test_add_duplicate_signature_ignored() {
        let mut eraser = DefaultSignatureEraser::new();
        let initial_count = eraser.known_sigs.len();
        eraser.add_signature(b"frida".to_vec()); // 已存在
        assert_eq!(eraser.known_sigs.len(), initial_count);
    }
}
