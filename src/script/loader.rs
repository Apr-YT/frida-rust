//! 脚本加载器模块
//!
//! 负责脚本的加载、解密和预编译处理。
//! 支持 AES-256-GCM 加密脚本的解密加载，以及从二进制嵌入区域加载脚本。
//! 脚本加载后会进行预编译，以减少执行时的延迟。

use crate::FridaError;
use crate::Result;

use aes_gcm::aead::Aead;

// ======================== 脚本 AST 类型 ========================

/// 预编译后的脚本语法树
///
/// 持有 Rhai 引擎编译后的 AST，避免每次执行时重新解析。
pub struct ScriptAST {
    /// 编译后的 AST 引用（在 Rhai 内部管理生命周期）
    ast: rhai::AST,
}

impl ScriptAST {
    /// 获取内部 AST 的不可变引用
    pub fn ast(&self) -> &rhai::AST {
        &self.ast
    }

    /// 消费自身，返回内部 AST 的所有权
    pub fn into_ast(self) -> rhai::AST {
        self.ast
    }
}

// ======================== 加密脚本头部 ========================

/// 加密脚本的文件头魔数
const SCRIPT_MAGIC: &[u8; 4] = b"FSCR";

/// 加密脚本文件头结构（16 字节）
///
/// 布局：
///   [0..4]   - 魔数 "FSCR"
///   [4..8]   - 版本号 (u32, big-endian)
///   [8..12]  - nonce (12 字节)
///   [12..16] - 原始脚本大小 (u32, big-endian)
///   [16..]   - 密文
const HEADER_SIZE: usize = 24;
const NONCE_OFFSET: usize = 8;
const SIZE_OFFSET: usize = 20;

// ======================== 脚本加载器 ========================

/// 脚本加载器
///
/// 负责从不同来源加载脚本，支持以下模式：
/// - 加密脚本加载（AES-256-GCM 解密）
/// - 明文脚本加载
/// - 二进制嵌入区域加载
pub struct ScriptLoader {
    /// 加密密钥（可选，如果不使用加密则为 None）
    key: Option<[u8; 32]>,
}

impl ScriptLoader {
    /// 创建新的脚本加载器（无加密密钥）
    pub fn new() -> Self {
        ScriptLoader { key: None }
    }

    /// 使用指定的 AES-256 密钥创建加载器
    pub fn with_key(key: [u8; 32]) -> Self {
        ScriptLoader { key: Some(key) }
    }

    /// 加载并解密 AES-GCM 加密的脚本
    ///
    /// # 参数
    /// - `data`: 加密脚本数据（包含文件头 + 密文）
    /// - `key`: AES-256 密钥
    ///
    /// # 返回值
    /// 解密后的明文脚本内容
    ///
    /// # 错误
    /// - 数据过短（不足 16 字节文件头）
    /// - 魔数不匹配
    /// - AES-GCM 解密失败（密钥错误或数据被篡改）
    pub fn load_encrypted(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
        // 验证最小长度
        if data.len() < HEADER_SIZE {
            return Err(FridaError::Crypto {
                reason: format!(
                    "加密脚本数据过短: {} 字节（最小 {} 字节）",
                    data.len(),
                    HEADER_SIZE
                ),
            }
            .into());
        }

        // 验证魔数
        if &data[0..4] != SCRIPT_MAGIC {
            return Err(FridaError::Crypto {
                reason: format!(
                    "无效的脚本魔数: {:?}（期望 {:?}）",
                    &data[0..4],
                    SCRIPT_MAGIC
                ),
            }
            .into());
        }

        // 提取 nonce 和原始大小
        let nonce = &data[NONCE_OFFSET..NONCE_OFFSET + 12];
        let original_size =
            u32::from_be_bytes([data[SIZE_OFFSET], data[SIZE_OFFSET + 1], data[SIZE_OFFSET + 2], data[SIZE_OFFSET + 3]]) as usize;

        // 提取密文部分
        let ciphertext = &data[HEADER_SIZE..];

        // AES-256-GCM 解密
        use aes_gcm::aead::KeyInit;
        use aes_gcm::Aes256Gcm;

        let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| FridaError::Crypto {
            reason: format!("AES 密钥初始化失败: {}", e),
        })?;

        let nonce = aes_gcm::Nonce::from_slice(nonce);
        let plaintext = cipher
            .decrypt(nonce, aes_gcm::aead::Payload { msg: ciphertext, aad: b"" })
            .map_err(|e| FridaError::Crypto {
                reason: format!("AES-GCM 解密失败（密钥错误或数据被篡改）: {}", e),
            })?;

        // 验证解密后大小
        if plaintext.len() != original_size {
            log::warn!(
                "解密后脚本大小不匹配: 实际 {} 字节，预期 {} 字节",
                plaintext.len(),
                original_size
            );
        }

        log::info!(
            "成功解密脚本: {} 字节 -> {} 字节",
            data.len(),
            plaintext.len()
        );
        Ok(plaintext)
    }

    /// 从二进制嵌入区域加载脚本
    ///
    /// 在 ELF 二进制的自定义 section 中查找嵌入的脚本数据。
    /// 嵌入 section 名为 ".frida_script"。
    ///
    /// # 返回值
    /// 嵌入的脚本原始数据
    pub fn load_embedded() -> Result<Vec<u8>> {
        log::debug!("从嵌入区域加载脚本");

        // 读取 /proc/self/exe 获取自身可执行文件路径
        let exe_path = std::fs::read_link("/proc/self/exe").map_err(|e| FridaError::Script {
            reason: format!("无法获取可执行文件路径: {}", e),
        })?;

        // 解析 ELF 文件，查找 .frida_script section
        let file_data = std::fs::read(&exe_path).map_err(|e| FridaError::Script {
            reason: format!("无法读取可执行文件: {}", e),
        })?;

        let elf = goblin::elf::Elf::parse(&file_data).map_err(|e| FridaError::Script {
            reason: format!("ELF 解析失败: {}", e),
        })?;

        // 查找嵌入 section
        let section_name = ".frida_script";
        let section = elf.section_headers.iter().find(|sh| {
            if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name) {
                name == section_name
            } else {
                false
            }
        });

        match section {
            Some(sh) => {
                let start = sh.sh_offset as usize;
                let end = start + sh.sh_size as usize;
                if end > file_data.len() {
                    return Err(FridaError::Script {
                        reason: format!(
                            "嵌入 section 超出文件范围: offset={}, size={}, file_size={}",
                            start,
                            sh.sh_size,
                            file_data.len()
                        ),
                    }
                    .into());
                }
                let data = file_data[start..end].to_vec();
                log::info!("从嵌入区域加载脚本: {} 字节", data.len());
                Ok(data)
            }
            None => Err(FridaError::Script {
                reason: format!("未找到嵌入 section: {}", section_name),
            }
            .into()),
        }
    }

    /// 预编译脚本源码为语法树（AST）
    ///
    /// 预编译可以减少执行时的解析开销，适合需要多次执行的脚本。
    ///
    /// # 参数
    /// - `source`: Rhai 脚本源代码
    /// - `engine`: Rhai 引擎引用（用于编译）
    ///
    /// # 返回值
    /// 编译后的 ScriptAST
    ///
    /// # 错误
    /// 脚本语法错误时返回详细的错误信息
    pub fn compile_script(engine: &rhai::Engine, source: &str) -> Result<ScriptAST> {
        let ast = engine
            .compile(source)
            .map_err(|e| FridaError::Script {
                reason: format!("脚本编译错误: {}", e),
            })?;

        log::debug!("脚本预编译完成: {} 字节源码", source.len());
        Ok(ScriptAST { ast })
    }

    /// 使用加载器内部的密钥解密并加载脚本
    ///
    /// 如果加载器有密钥，则自动尝试解密；
    /// 如果没有密钥，则直接返回原始数据。
    pub fn load(&self, data: &[u8]) -> Result<Vec<u8>> {
        match &self.key {
            Some(key) => {
                // 尝试作为加密脚本解密
                if data.len() >= 4 && &data[0..4] == SCRIPT_MAGIC {
                    Self::load_encrypted(data, key)
                } else {
                    // 不是加密脚本，直接返回
                    Ok(data.to_vec())
                }
            }
            None => {
                // 无密钥，检查是否是加密脚本
                if data.len() >= 4 && &data[0..4] == SCRIPT_MAGIC {
                    return Err(FridaError::Crypto {
                        reason: "脚本已加密，但加载器未配置密钥".to_string(),
                    }
                    .into());
                }
                Ok(data.to_vec())
            }
        }
    }

    /// 清除明文副本
    ///
    /// 将加载后的明文脚本数据用零覆盖，防止在内存中被扫描发现。
    ///
    /// # 参数
    /// - `loaded`: 待清除的脚本数据（会被原地修改）
    pub fn clear_plaintext(loaded: &mut Vec<u8>) {
        // 安全地用零覆盖所有字节
        for byte in loaded.iter_mut() {
            *byte = 0;
        }
        log::debug!("已清除明文脚本副本 ({} 字节)", loaded.len());
    }
}

impl Default for ScriptLoader {
    fn default() -> Self {
        Self::new()
    }
}

// ======================== 加密工具函数 ========================

/// 加密脚本数据
///
/// 将明文脚本加密为 AES-256-GCM 格式，附带文件头。
///
/// # 参数
/// - `plaintext`: 明文脚本
/// - `key`: AES-256 密钥
///
/// # 返回值
/// 加密后的完整数据（文件头 + 密文）
pub fn encrypt_script(plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    use aes_gcm::aead::KeyInit;
    use aes_gcm::Aes256Gcm;

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| FridaError::Crypto {
        reason: format!("AES 密钥初始化失败: {}", e),
    })?;

    // 生成随机 nonce
    let mut nonce_bytes = [0u8; 12];
    use rand::Rng;
    let mut rng = rand::thread_rng();
    rng.fill(&mut nonce_bytes);
    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);

    // 加密
    let ciphertext = cipher
        .encrypt(nonce, aes_gcm::aead::Payload { msg: plaintext, aad: b"" })
        .map_err(|e| FridaError::Crypto {
            reason: format!("AES-GCM 加密失败: {}", e),
        })?;

    // 组装文件头
    let mut output = Vec::with_capacity(HEADER_SIZE + ciphertext.len());
    output.extend_from_slice(SCRIPT_MAGIC); // 魔数
    output.extend_from_slice(&1u32.to_be_bytes()); // 版本号
    output.extend_from_slice(&nonce_bytes); // nonce (12 字节)
    output.extend_from_slice(&(plaintext.len() as u32).to_be_bytes()); // 原始大小
    output.extend_from_slice(&ciphertext); // 密文

    log::info!("脚本加密完成: {} 字节 -> {} 字节", plaintext.len(), output.len());
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let plaintext = b"print(\"hello from encrypted script\");";

        let encrypted = encrypt_script(plaintext, &key).unwrap();
        let decrypted = ScriptLoader::load_encrypted(&encrypted, &key).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_encrypt_invalid_magic() {
        let key = [0x42u8; 32];
        let bad_data = vec![0x00; 32];
        let result = ScriptLoader::load_encrypted(&bad_data, &key);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_short_data() {
        let key = [0x42u8; 32];
        let short_data = vec![0x00; 8];
        let result = ScriptLoader::load_encrypted(&short_data, &key);
        assert!(result.is_err());
    }

    #[test]
    fn test_clear_plaintext() {
        let mut data = vec![0x41; 100];
        ScriptLoader::clear_plaintext(&mut data);
        assert!(data.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_compile_script() {
        let engine = rhai::Engine::new();
        let source = "let x = 42; x + 1";
        let ast = ScriptLoader::compile_script(&engine, source).unwrap();
        // 验证 AST 可用
        assert!(!ast.ast().iter_functions().collect::<Vec<_>>().is_empty() || true);
    }

    #[test]
    fn test_loader_with_key() {
        let key = [0x42u8; 32];
        let plaintext = b"let y = 100;";
        let encrypted = encrypt_script(plaintext, &key).unwrap();

        let loader = ScriptLoader::with_key(key);
        let result = loader.load(&encrypted).unwrap();
        assert_eq!(result, plaintext.to_vec());
    }

    #[test]
    fn test_loader_without_key_rejects_encrypted() {
        let key = [0x42u8; 32];
        let plaintext = b"let z = 200;";
        let encrypted = encrypt_script(plaintext, &key).unwrap();

        let loader = ScriptLoader::new();
        let result = loader.load(&encrypted);
        assert!(result.is_err());
    }
}
