//! 反汇编器实现
//!
//! 封装 capstone 引擎，提供安全、高效的反汇编能力。

use capstone::prelude::*;
use crate::common::types::Architecture;
use crate::Result;

#[derive(Debug, Clone)]
pub struct Instruction {
    pub address: u64,
    pub mnemonic: String,
    pub operands: String,
    pub bytes: Vec<u8>,
    pub size: usize,
}

#[derive(Debug, Clone)]
pub struct DisasmResult {
    pub instructions: Vec<Instruction>,
    pub architecture: Architecture,
    pub base_address: u64,
}

pub struct Disassembler {
    cs: Capstone,
    arch: Architecture,
}

impl Disassembler {
    pub fn new(arch: Architecture) -> Result<Self> {
        let cs = match arch {
            Architecture::X86_64 => Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode64)
                .syntax(arch::x86::ArchSyntax::Intel)
                .detail(true)
                .build()
                .map_err(|e| crate::FridaError::Disasm {
                    reason: format!("创建 x86_64 反汇编器失败: {}", e),
                })?,
            Architecture::Aarch64 => Capstone::new()
                .arm64()
                .mode(arch::arm64::ArchMode::Arm)
                .detail(true)
                .build()
                .map_err(|e| crate::FridaError::Disasm {
                    reason: format!("创建 AArch64 反汇编器失败: {}", e),
                })?,
            Architecture::Arm => Capstone::new()
                .arm()
                .mode(arch::arm::ArchMode::Arm)
                .detail(true)
                .build()
                .map_err(|e| crate::FridaError::Disasm {
                    reason: format!("创建 ARM 反汇编器失败: {}", e),
                })?,
        };

        Ok(Disassembler { cs, arch })
    }

    pub fn for_current_arch() -> Result<Self> {
        Self::new(Architecture::current())
    }

    pub fn arch(&self) -> Architecture {
        self.arch
    }

    pub fn disassemble(&self, bytes: &[u8], base_address: u64, count: Option<usize>) -> Result<DisasmResult> {
        let instructions = self.cs.disasm_all(bytes, base_address)
            .map_err(|e| crate::FridaError::Disasm {
                reason: format!("反汇编失败: {}", e),
            })?;

        let max_count = count.unwrap_or(usize::MAX);

        let mut result = Vec::with_capacity(instructions.len().min(max_count));
        for insn in instructions.iter().take(max_count) {
            result.push(Instruction {
                address: insn.address(),
                mnemonic: insn.mnemonic().unwrap_or("").to_string(),
                operands: insn.op_str().unwrap_or("").to_string(),
                bytes: insn.bytes().to_vec(),
                size: insn.len(),
            });
        }

        Ok(DisasmResult {
            instructions: result,
            architecture: self.arch,
            base_address,
        })
    }

    pub fn disassemble_to_string(&self, bytes: &[u8], base_address: u64, count: Option<usize>) -> Result<String> {
        let result = self.disassemble(bytes, base_address, count)?;
        let mut output = format!("Disassembly @ {:#x} ({:?}):\n\n", base_address, self.arch);
        
        for insn in &result.instructions {
            let hex_bytes: String = insn.bytes.iter().map(|b| format!("{:02x}", b)).collect();
            output.push_str(&format!("{:#010x}: {:24}  {:12}{}\n", 
                insn.address, 
                hex_bytes,
                insn.mnemonic,
                insn.operands
            ));
        }
        
        Ok(output)
    }
}

impl std::fmt::Display for Instruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#010x}: {} {}", self.address, self.mnemonic, self.operands)
    }
}

impl std::fmt::Display for DisasmResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DisasmResult(arch={:?}, base={:#x}, {} instructions)", 
            self.architecture, self.base_address, self.instructions.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aarch64_disasm() {
        let code = [0x91, 0x00, 0x00, 0x00, 0xb8, 0x10, 0x00, 0x00];
        let disasm = Disassembler::new(Architecture::Aarch64).unwrap();
        let result = disasm.disassemble(&code, 0x1000, None).unwrap();
        assert!(!result.instructions.is_empty());
    }

    #[test]
    fn test_x86_64_disasm() {
        let code = [0x55, 0x48, 0x8b, 0xec];
        let disasm = Disassembler::new(Architecture::X86_64).unwrap();
        let result = disasm.disassemble(&code, 0x1000, None).unwrap();
        assert!(!result.instructions.is_empty());
    }
}