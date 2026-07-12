//! Inline Hook 实现
//!
//! 通过修改目标函数入口处的指令实现函数拦截。
//! 支持 x86_64 和 AArch64 架构。
//!
//! ## 工作原理
//! 1. 解码目标函数入口处的指令，确定需要覆盖的字节数
//! 2. 在可执行内存中分配跳板（Trampoline）
//! 3. 将被覆盖的原始指令复制到跳板，并在末尾追加跳回指令
//! 4. 在目标函数入口处写入跳转到替换函数的指令
//! 5. 替换函数执行完毕后跳转到跳板，恢复原始执行流

use crate::common::util::{align_to_page, align_to_page_up};
use crate::Result;

#[cfg(all(not(target_os = "android"), not(windows)))]
extern "C" {
    fn __clear_cache(start: *mut libc::c_void, end: *mut libc::c_void);
}

#[cfg(target_os = "android")]
unsafe fn __clear_cache(start: *mut libc::c_void, end: *mut libc::c_void) {
    // Android NDK 没有 __clear_cache，使用 AArch64 内联汇编
    #[cfg(target_arch = "aarch64")]
    {
        let mut addr = start as usize;
        let end_addr = end as usize;
        // DC CIVAC — 清除数据 cache 到 PoC
        // IC IVAU — 清除指令 cache 到 PoU
        // ISB — 指令同步屏障
        while addr < end_addr {
            std::arch::asm!(
                "dc civac, {addr}",
                "ic ivau, {addr}",
                addr = in(reg) addr,
            );
            addr += 64; // cache line size
        }
        std::arch::asm!("isb");
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        // x86_64 不需要显式 cache flush
        let _ = (start, end);
    }
}

// ======================== Trampoline ========================

/// 跳板结构体
///
/// 保存 Hook 安装时被覆盖的原始指令及其重定位后的执行代码。
/// 当替换函数需要调用原始函数时，跳转到此地址执行。
pub struct Trampoline {
    /// 跳板内存的基地址（通过 mmap 分配）
    pub trampoline_addr: u64,
    /// 跳板内存的大小
    pub trampoline_size: usize,
    /// 目标函数的地址（被 Hook 的地址）
    pub target_addr: u64,
    /// 替换函数的地址
    pub detour_addr: u64,
    /// 被覆盖的原始指令字节数
    pub patched_size: usize,
    /// 保存的原始指令字节
    pub original_bytes: Vec<u8>,
}

impl std::fmt::Debug for Trampoline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Trampoline")
            .field("trampoline_addr", &format_args!("{:#x}", self.trampoline_addr))
            .field("trampoline_size", &self.trampoline_size)
            .field("target_addr", &format_args!("{:#x}", self.target_addr))
            .field("detour_addr", &format_args!("{:#x}", self.detour_addr))
            .field("patched_size", &self.patched_size)
            .finish()
    }
}

// ======================== x86_64 指令长度解码 ========================

/// x86_64 常见指令的长度表
///
/// 用于确定在目标函数入口需要覆盖多少字节才能完整地
/// 替换至少一条指令（跳转指令最少 5 字节：jmp rel32）。
#[cfg(target_arch = "x86_64")]
mod x86_decoder {
    /// 单字节指令长度映射（Opcode -> 长度）
    /// 0 表示需要进一步解码或是不支持的指令
    fn single_byte_len(opcode: u8) -> usize {
        match opcode {
            // NOP 系列
            0x90 => 1, // nop

            // PUSH/POP 寄存器
            0x50..=0x57 => 1, // push rax..rdi
            0x58..=0x5f => 1, // pop rax..rdi

            // MOV 寄存器之间 (89 = mov r/m, r; 8B = mov r, r/m)
            0x89 => decode_modrm(2),  // mov r/m, r (需要 ModR/M)
            0x8b => decode_modrm(2),  // mov r, r/m (需要 ModR/M)
            0x88 => decode_modrm(2),  // mov r/m8, r8
            0x8a => decode_modrm(2),  // mov r8, r/m8

            // MOV 立即数到寄存器
            0xb8..=0xbf => 1,  // mov reg, imm32 (REX.W 前缀存在时为 8 字节)

            // CALL / JMP 相对
            0xe8 => 5, // call rel32
            0xe9 => 5, // jmp rel32

            // JMP 短跳转
            0xeb => 2, // jmp rel8

            // LEA
            0x8d => decode_modrm(2), // lea r, m (需要 ModR/M)

            // SUB / ADD / CMP 共享 opcode 0x83 和 0x81
            0x83 => decode_modrm(3), // sub/add/cmp r/m, imm8 (需要 ModR/M + imm8)
            0x81 => decode_modrm(5), // sub/add/cmp r/m, imm32 (需要 ModR/M + imm32)
            0x29 => decode_modrm(2), // sub r/m, r

            // ADD
            0x01 => decode_modrm(2), // add r/m, r
            0x03 => decode_modrm(2), // add r, r/m

            // CMP
            0x39 => decode_modrm(2), // cmp r/m, r
            0x3b => decode_modrm(2), // cmp r, r/m

            // TEST
            0x85 => decode_modrm(2), // test r/m, r
            0x84 => decode_modrm(2), // test r/m8, r8
            0xa9 => 5,               // test rax, imm32
            0xa8 => 2,               // test al, imm8
            0xf7 => decode_modrm_f7(), // test r/m, imm32 等

            // XCHG
            0x87 => decode_modrm(2), // xchg r/m, r
            0x86 => decode_modrm(2), // xchg r/m8, r8
            0x90..=0x97 => 1,       // xchg eax, reg (其中 0x90 是 nop)

            // RET
            0xc3 => 1, // ret
            0xc2 => 3, // ret imm16

            // INT
            0xcd => 2, // int imm8

            // 条件跳转
            0x70..=0x7f => 2, // jcc rel8 (short)

            // 其他 REX 前缀 0x40-0x4F 由外层处理

            // XOR
            0x31 => decode_modrm(2), // xor r/m, r
            0x33 => decode_modrm(2), // xor r, r/m

            // AND
            0x21 => decode_modrm(2), // and r/m, r
            0x23 => decode_modrm(2), // and r, r/m

            // OR
            0x09 => decode_modrm(2), // or r/m, r
            0x0b => decode_modrm(2), // or r, r/m

            // 不支持的指令返回 0
            _ => 0,
        }
    }

    /// F7 组指令的长度解码
    fn decode_modrm_f7() -> usize {
        // F7 需要 ModR/M + 立即数，最保守估计 6 字节
        6
    }

    /// 简化版 ModR/M 解码（返回包含 ModR/M 字节在内的最小长度）
    /// 这里使用保守估计值
    fn decode_modrm(min_len: usize) -> usize {
        // 最简单情况：寄存器到寄存器（ModR/M = 1 字节）
        // 有 SIB 字节时额外 +1
        // 有 disp8 时额外 +1，有 disp32 时额外 +4
        // 我们返回最小长度作为估计值，实际代码中会通过读取字节精确计算
        min_len
    }

    /// 解码一条 x86_64 指令的长度
    ///
    /// # 参数
    /// - `code`: 指令所在的内存
    /// - `offset`: 从 code 开始的偏移量
    ///
    /// # 返回值
    /// 指令的字节长度，如果无法解码则返回 0
    pub fn decode_instruction_length(code: &[u8], offset: usize) -> usize {
        if offset >= code.len() {
            return 0;
        }

        let mut idx = offset;

        // 检查 REX 前缀 (0x40-0x4F)
        let has_rex = if code[idx] >= 0x40 && code[idx] <= 0x4f {
            idx += 1;
            true
        } else {
            false
        };

        if idx >= code.len() {
            return 0;
        }

        let opcode = code[idx];

        // 获取基础指令长度
        let base_len = single_byte_len(opcode);
        if base_len == 0 {
            // 无法识别的指令，保守返回 1 字节
            log::warn!("无法解码指令 @ {:#x}: opcode={:#04x}", offset as u64, opcode);
            return 1;
        }

        let mut total = base_len;

        // 如果有 REX.W 前缀且是 mov reg, imm32 (0xB8-0xBF)，实际是 mov reg, imm64 (8 字节)
        if has_rex && opcode >= 0xb8 && opcode <= 0xbf {
            total = 8; // mov r64, imm64
        }

        // 对于需要 ModR/M 字节的指令，尝试进一步解码
        if matches!(opcode, 0x89 | 0x8b | 0x88 | 0x8a | 0x8d | 0x01 | 0x03 | 0x29
            | 0x39 | 0x3b | 0x85 | 0x84 | 0x87 | 0x86 | 0x31 | 0x33 | 0x21 | 0x23 | 0x09 | 0x0b)
        {
            total = decode_modrm_full(code, idx + 1, total);
        }

        total
    }

    /// 完整的 ModR/M 解码，计算包含 SIB 和位移在内的指令长度
    fn decode_modrm_full(code: &[u8], modrm_offset: usize, base_len: usize) -> usize {
        if modrm_offset >= code.len() {
            return base_len;
        }

        let modrm = code[modrm_offset];
        let mod_val = (modrm >> 6) & 0x03;
        let _reg_val = (modrm >> 3) & 0x07;
        let rm_val = modrm & 0x07;

        let mut len = base_len; // 包含 opcode + modrm

        // 检查是否有 SIB 字节（当 rm == 4 且 mod != 3 时）
        let has_sib = rm_val == 4 && mod_val != 3;
        let _sib_offset = modrm_offset + 1;

        if has_sib {
            len += 1; // SIB 字节
        }

        // 检查位移
        match mod_val {
            0b00 => {
                // 无位移，但 rm == 5 时是 RIP-relative（disp32）
                if rm_val == 5 {
                    len += 4; // disp32
                }
            }
            0b01 => {
                len += 1; // disp8
            }
            0b10 => {
                len += 4; // disp32
            }
            0b11 => {
                // 寄存器直接寻址，无位移无 SIB
            }
            _ => unreachable!(),
        }

        len
    }

    /// 计算覆盖 N 字节指令所需的最小字节数（至少 5 字节用于 jmp rel32）
    pub fn calculate_patch_size(code: &[u8], offset: usize) -> usize {
        const MIN_PATCH_SIZE: usize = 5; // jmp rel32 的长度
        let mut total = 0;
        let mut idx = offset;

        while total < MIN_PATCH_SIZE && idx < code.len() {
            let instr_len = decode_instruction_length(code, idx);
            if instr_len == 0 {
                break;
            }
            total += instr_len;
            idx += instr_len;
        }

        // 确保至少覆盖 5 字节（长跳转的需要）
        if total < MIN_PATCH_SIZE {
            total = MIN_PATCH_SIZE;
        }

        total
    }
}

// ======================== AArch64 指令解码 ========================

/// AArch64 指令长度计算
///
/// AArch64 指令固定为 4 字节对齐，大部分指令长度为 4 字节。
/// 覆盖至少需要 4 字节（一条 B 指令或 LDR + BR 组合）。
#[cfg(target_arch = "aarch64")]
mod arm64_decoder {
    /// AArch64 指令固定 4 字节
    pub const INSTRUCTION_SIZE: usize = 4;

    /// AArch64 最小覆盖大小（一条指令 = 4 字节）
    #[cfg(target_arch = "aarch64")]
    #[allow(dead_code)]
    pub const MIN_PATCH_SIZE: usize = 4;

    /// 判断是否为 B 指令（无条件分支，26位偏移）
    pub fn is_b_instruction(inst: u32) -> bool {
        (inst & 0xFC000000) == 0x14000000
    }

    /// 判断是否为 BL 指令（带链接分支）
    pub fn is_bl_instruction(inst: u32) -> bool {
        (inst & 0xFC000000) == 0x94000000
    }

    /// 判断是否为 B.cond 指令（条件分支）
    pub fn is_bcond_instruction(inst: u32) -> bool {
        (inst & 0xFF000010) == 0x54000000
    }

    /// 判断是否为 CBZ/CBNZ 指令
    #[cfg(target_arch = "aarch64")]
    #[allow(dead_code)]
    pub fn is_cbz_cbnz(inst: u32) -> bool {
        (inst & 0x7E000000) == 0x34000000 || (inst & 0x7E000000) == 0x35000000
    }

    /// 判断是否为 STP 指令（存储寄存器对）
    pub fn is_stp_instruction(inst: u32) -> bool {
        (inst & 0x7FC00000) == 0x28000000
            || (inst & 0x7FC00000) == 0x29000000
            || (inst & 0x7FC00000) == 0x28800000
            || (inst & 0x7FC00000) == 0x29800000
            || (inst & 0x7FC00000) == 0x2D000000
            || (inst & 0x7FC00000) == 0x6D000000
            || (inst & 0x7FC00000) == 0x29400000
            || (inst & 0x7FC00000) == 0x69400000
    }

    /// 判断是否为 LDP 指令（加载寄存器对）
    pub fn is_ldp_instruction(inst: u32) -> bool {
        (inst & 0x7FC00000) == 0x28400000
            || (inst & 0x7FC00000) == 0x29400000
            || (inst & 0x7FC00000) == 0x5C000000
            || (inst & 0x7FC00000) == 0x5C400000
            || (inst & 0x7FC00000) == 0x69C00000
            || (inst & 0x7FC00000) == 0x29C00000
    }

    /// 计算需要覆盖多少条指令才能容纳跳转指令
    ///
    /// 如果目标地址在 +/-128MB 范围内，只需一条 B 指令（4 字节）。
    /// 否则需要两条指令：LDR X17, [PC, #8]; BR X17 + 8 字节地址（共 16 字节）。
    pub fn calculate_patch_size(target_addr: u64, detour_addr: u64) -> usize {
        let offset = (detour_addr as i64) - (target_addr as i64);
        let max_b_offset: i64 = 128 * 1024 * 1024; // B 指令最大偏移 +/-128MB

        if offset >= -max_b_offset && offset <= max_b_offset {
            INSTRUCTION_SIZE // 单条 B 指令
        } else {
            16 // LDR X17, [PC, #8]; BR X17; .quad addr
        }
    }
}

// ======================== Inline Hook 安装器 ========================

/// Inline Hook 安装器
///
/// 修改目标函数入口处的机器码，将执行流重定向到替换函数。
pub struct InlineHooker {
    /// 跳板内存池（预分配的可执行内存）
    trampoline_pages: Vec<TrampolinePage>,
}

/// 跳板内存页（用于批量分配小的跳板块）
struct TrampolinePage {
    /// 内存基地址
    base: u64,
    /// 页面大小
    size: usize,
    /// 当前分配偏移量
    offset: usize,
}

impl TrampolinePage {
    /// 分配指定大小的跳板块
    fn alloc(&mut self, size: usize) -> Option<u64> {
        let aligned_size = (size + 15) & !15; // 16 字节对齐
        if self.offset + aligned_size > self.size {
            return None;
        }
        let addr = self.base + self.offset as u64;
        self.offset += aligned_size;
        Some(addr)
    }
}

impl InlineHooker {
    /// 创建新的 Inline Hook 安装器
    pub fn new() -> Self {
        InlineHooker {
            trampoline_pages: Vec::new(),
        }
    }

    /// 安装 Inline Hook
    ///
    /// # 参数
    /// - `target_addr`: 目标函数的地址（将被修改入口指令）
    /// - `detour_addr`: 替换函数的地址
    ///
    /// # 返回值
    /// 返回包含跳板信息的 Trampoline
    ///
    /// # 安全性
    /// 此函数会直接修改目标地址处的内存，调用者需确保：
    /// 1. 目标地址是有效的可执行内存
    /// 2. 在调用期间没有其他线程正在执行目标函数
    #[cfg(target_arch = "x86_64")]
    pub fn install(&mut self, target_addr: u64, detour_addr: u64) -> Result<Trampoline> {
        log::info!(
            "安装 Inline Hook: target={:#x}, detour={:#x}",
            target_addr,
            detour_addr
        );

        // 1. 读取目标函数入口处的指令
        let code = self.read_memory(target_addr, 32)?;
        let patch_size = x86_decoder::calculate_patch_size(&code, 0);

        log::debug!("需要覆盖 {} 字节原始指令", patch_size);

        // 2. 分配跳板内存（RWX -> 写入 -> 改为 R-X）
        let trampoline_size = patch_size + 14; // 原始指令 + jmp [rip+0] + 8字节地址
        let trampoline_addr = self.alloc_trampoline(trampoline_size)?;

        // 3. 保存原始字节
        let original_bytes = code[..patch_size].to_vec();

        // 4. 构建跳板代码
        let mut trampoline_code = Vec::with_capacity(trampoline_size);

        // 复制原始指令到跳板
        // 注意：如果原始指令包含相对偏移（如 call, jmp, lea rip-relative），
        // 需要修正偏移量
        let relocated_code = self.relocate_instructions_x86(
            &original_bytes,
            target_addr,
            trampoline_addr,
        );
        trampoline_code.extend_from_slice(&relocated_code);

        // 在跳板末尾追加跳回目标函数的指令
        // 使用 jmp [rip+0] + 8字节绝对地址（14字节，支持 64 位地址空间）
        let return_addr = target_addr + patch_size as u64;
        trampoline_code.push(0xff); // jmp [rip+0]
        trampoline_code.push(0x25);
        trampoline_code.extend_from_slice(&0i32.to_le_bytes()); // +0 偏移
        trampoline_code.extend_from_slice(&return_addr.to_le_bytes()); // 绝对地址

        // 5. 写入跳板代码
        self.write_memory(trampoline_addr, &trampoline_code)?;

        // 6. 构建跳转指令写入目标函数入口
        let mut jump_code = Vec::new();
        let jump_offset = (detour_addr as i64) - (target_addr as i64 + 5) as i64;

        if jump_offset >= i32::MIN as i64 && jump_offset <= i32::MAX as i64 {
            // 短跳转：jmp rel32（5 字节）
            jump_code.push(0xe9);
            jump_code.extend_from_slice(&(jump_offset as i32).to_le_bytes());
        } else {
            // 长跳转：jmp [rip+0] + 8字节地址（14 字节）
            jump_code.push(0xff);
            jump_code.push(0x25);
            jump_code.extend_from_slice(&0i32.to_le_bytes());
            jump_code.extend_from_slice(&detour_addr.to_le_bytes());
        }

        // 用 NOP 填充剩余空间
        let remaining = patch_size - jump_code.len();
        for _ in 0..remaining {
            jump_code.push(0x90);
        }

        // 7. 修改目标函数入口的内存权限为 RWX，写入跳转指令
        self.write_memory(target_addr, &jump_code)?;

        // 8. 刷新指令缓存
        self.flush_instruction_cache(target_addr, patch_size);
        self.flush_instruction_cache(trampoline_addr, trampoline_code.len());

        log::info!(
            "Inline Hook 安装完成: trampoline={:#x}, patched_size={}",
            trampoline_addr,
            patch_size
        );

        Ok(Trampoline {
            trampoline_addr,
            trampoline_size,
            target_addr,
            detour_addr,
            patched_size: patch_size,
            original_bytes,
        })
    }

    /// 安装 Inline Hook (AArch64 版本)
    #[cfg(target_arch = "aarch64")]
    pub fn install(&mut self, target_addr: u64, detour_addr: u64) -> Result<Trampoline> {
        log::info!(
            "安装 Inline Hook (AArch64): target={:#x}, detour={:#x}",
            target_addr,
            detour_addr
        );

        // 1. 读取目标函数入口处的指令
        let code = self.read_memory(target_addr, 32)?;
        let patch_size = arm64_decoder::calculate_patch_size(target_addr, detour_addr);

        log::debug!("需要覆盖 {} 字节", patch_size);

        // 2. 分配跳板内存
        let trampoline_size = patch_size + 16; // 原始指令 + 跳回指令
        let trampoline_addr = self.alloc_trampoline(trampoline_size)?;

        // 3. 保存原始指令
        let original_bytes = code[..patch_size].to_vec();

        // 4. 构建跳板代码
        let mut trampoline_code = Vec::with_capacity(trampoline_size);

        // 复制并重定位原始指令到跳板
        let relocated_code = self.relocate_instructions_arm64(
            &original_bytes,
            target_addr,
            trampoline_addr,
        );
        trampoline_code.extend_from_slice(&relocated_code);

        // 跳回目标函数（跳过被覆盖的部分）
        let return_addr = target_addr + patch_size as u64;
        let return_offset = (return_addr as i64) - (trampoline_addr + trampoline_code.len() as u64) as i64;
        let max_b_offset: i64 = 128 * 1024 * 1024;

        if return_offset >= -max_b_offset && return_offset <= max_b_offset {
            // B 指令（26 位偏移，单位 4 字节）
            let imm26 = ((return_offset >> 2) & 0x03FFFFFF) as u32;
            let b_inst = 0x14000000 | imm26;
            trampoline_code.extend_from_slice(&b_inst.to_le_bytes());
        } else {
            // LDR X17, [PC, #8]; BR X17; .quad addr
            trampoline_code.extend_from_slice(&0x58000051u32.to_le_bytes()); // LDR X17, #8
            trampoline_code.extend_from_slice(&0xD61F0220u32.to_le_bytes()); // BR X17
            trampoline_code.extend_from_slice(&return_addr.to_le_bytes());
        }

        // 5. 写入跳板代码
        self.write_memory(trampoline_addr, &trampoline_code)?;

        // 6. 写入目标函数入口的跳转指令
        let mut hook_code = Vec::new();
        let hook_offset = (detour_addr as i64) - target_addr as i64;

        if patch_size == 4 {
            // 单条 B 指令即可
            if hook_offset >= -max_b_offset && hook_offset <= max_b_offset {
                let imm26 = ((hook_offset >> 2) & 0x03FFFFFF) as u32;
                let b_inst = 0x14000000 | imm26;
                hook_code.extend_from_slice(&b_inst.to_le_bytes());
            } else {
                // LDR X17, [PC, #8]; BR X17; .quad addr (16 字节)
                hook_code.extend_from_slice(&0x58000051u32.to_le_bytes());
                hook_code.extend_from_slice(&0xD61F0220u32.to_le_bytes());
                hook_code.extend_from_slice(&detour_addr.to_le_bytes());
            }
        } else {
            // 需要覆盖多条指令
            // LDR X17, [PC, #8]; BR X17; .quad addr (16 字节)
            hook_code.extend_from_slice(&0x58000051u32.to_le_bytes());
            hook_code.extend_from_slice(&0xD61F0220u32.to_le_bytes());
            hook_code.extend_from_slice(&detour_addr.to_le_bytes());

            // NOP 填充剩余空间
            while hook_code.len() < patch_size {
                hook_code.extend_from_slice(&0xD503201Fu32.to_le_bytes()); // NOP
            }
        }

        // 7. 写入跳转指令到目标函数入口
        self.write_memory(target_addr, &hook_code)?;

        // 8. 刷新指令缓存
        self.flush_instruction_cache(target_addr, patch_size);
        self.flush_instruction_cache(trampoline_addr, trampoline_code.len());

        log::info!(
            "AArch64 Inline Hook 安装完成: trampoline={:#x}, patched_size={}",
            trampoline_addr,
            patch_size
        );

        Ok(Trampoline {
            trampoline_addr,
            trampoline_size,
            target_addr,
            detour_addr,
            patched_size: patch_size,
            original_bytes,
        })
    }

    /// 卸载 Inline Hook，恢复原始指令
    ///
    /// # 参数
    /// - `trampoline`: 安装时返回的跳板信息
    pub fn uninstall(&mut self, trampoline: &Trampoline) -> Result<()> {
        log::info!(
            "卸载 Inline Hook: target={:#x}",
            trampoline.target_addr
        );

        // 恢复原始指令
        self.write_memory(trampoline.target_addr, &trampoline.original_bytes)?;

        // 刷新指令缓存
        self.flush_instruction_cache(trampoline.target_addr, trampoline.original_bytes.len());

        // 释放跳板内存（标记为可回收）
        // 注意：简单实现中不立即释放，等待整个 Hooker 析构时统一释放

        log::info!("Inline Hook 已卸载");
        Ok(())
    }

    /// 读取目标地址处的原始字节
    pub fn read_original_bytes(&self, target_addr: u64, size: usize) -> Vec<u8> {
        self.read_memory(target_addr, size).unwrap_or_default()
    }

    // ======================== 内存操作 ========================

    /// 从指定地址读取内存
    fn read_memory(&self, addr: u64, size: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; size];

        // SAFETY: 调用者需确保地址有效
        let ret = unsafe {
            libc::memcpy(
                buf.as_mut_ptr() as *mut libc::c_void,
                addr as *const libc::c_void,
                size,
            )
        };

        if ret.is_null() && size > 0 {
            return Err(crate::FridaError::MemoryRead {
                address: addr as usize,
                size,
                reason: "memcpy 失败".to_string(),
            }
            .into());
        }

        Ok(buf)
    }

    /// 向指定地址写入内存（自动处理内存保护）
    pub fn write_memory(&self, addr: u64, data: &[u8]) -> Result<()> {
        let page_addr = align_to_page(addr as usize);
        let end_addr = align_to_page_up((addr + data.len() as u64) as usize);
        let protect_size = end_addr - page_addr;

        #[cfg(windows)]
        {
            use winapi::um::memoryapi::VirtualProtect;
            use winapi::um::winnt::PAGE_EXECUTE_READWRITE;

            let mut old_protect = 0u32;
            let ret = unsafe {
                VirtualProtect(
                    page_addr as *mut _,
                    protect_size,
                    PAGE_EXECUTE_READWRITE,
                    &mut old_protect,
                )
            };
            if ret == 0 {
                return Err(crate::FridaError::MemoryProtect {
                    address: page_addr,
                    reason: format!("VirtualProtect 失败: {}", std::io::Error::last_os_error()),
                }
                .into());
            }

            unsafe {
                std::ptr::copy_nonoverlapping(
                    data.as_ptr(),
                    addr as *mut u8,
                    data.len(),
                );
            }

            let _ = unsafe {
                VirtualProtect(
                    page_addr as *mut _,
                    protect_size,
                    old_protect,
                    &mut old_protect,
                )
            };
        }

        #[cfg(not(windows))]
        {
            // 保存原始保护属性
            let _old_prot = libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC;

            // 修改内存保护为 RWX
            let ret = unsafe {
                libc::mprotect(
                    page_addr as *mut libc::c_void,
                    protect_size,
                    libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                )
            };

            if ret != 0 {
                return Err(crate::FridaError::MemoryProtect {
                    address: page_addr,
                    reason: format!("mprotect 失败: {}", std::io::Error::last_os_error()),
                }
                .into());
            }

            // 写入数据
            // SAFETY: 已将内存设为可写
            let ret = unsafe {
                libc::memcpy(
                    addr as *mut libc::c_void,
                    data.as_ptr() as *const libc::c_void,
                    data.len(),
                )
            };

            if ret.is_null() && !data.is_empty() {
                return Err(crate::FridaError::MemoryWrite {
                    address: addr as usize,
                    size: data.len(),
                    reason: "memcpy 写入失败".to_string(),
                }
                .into());
            }

            // 恢复内存保护为 R-X
            let _ = _old_prot; // 简化处理：恢复为可读可执行
            let ret = unsafe {
                libc::mprotect(
                    page_addr as *mut libc::c_void,
                    protect_size,
                    libc::PROT_READ | libc::PROT_EXEC,
                )
            };

            if ret != 0 {
                log::warn!(
                    "恢复内存保护失败 @ {:#x}: {}",
                    page_addr,
                    std::io::Error::last_os_error()
                );
            }
        }

        Ok(())
    }

    /// 分配跳板内存（RWX 权限）
    fn alloc_trampoline(&mut self, size: usize) -> Result<u64> {
        // 先尝试在现有页面中分配
        for page in &mut self.trampoline_pages {
            if let Some(addr) = page.alloc(size) {
                return Ok(addr);
            }
        }

        #[cfg(windows)]
        {
            use winapi::um::memoryapi::VirtualAlloc;
            use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE};

            let alloc_size = 4096usize.max(size);
            let addr = unsafe {
                VirtualAlloc(
                    std::ptr::null_mut(),
                    alloc_size,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE,
                )
            };

            if addr.is_null() {
                return Err(crate::FridaError::MemoryWrite {
                    address: 0,
                    size,
                    reason: format!("VirtualAlloc 跳板内存失败: {}", std::io::Error::last_os_error()),
                }
                .into());
            }

            log::debug!("分配跳板页 (Windows): {:#x}, 大小: {}", addr as u64, alloc_size);

            let mut page = TrampolinePage {
                base: addr as u64,
                size: alloc_size,
                offset: 0,
            };

            let trampoline_addr = page.alloc(size).unwrap();
            self.trampoline_pages.push(page);
            Ok(trampoline_addr)
        }

        #[cfg(not(windows))]
        {
            // 需要分配新页面
            let ps = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
            let alloc_size = if ps > 0 { ps as usize } else { 4096 }.max(4096);
            let addr = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    alloc_size,
                    libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };

            if addr == libc::MAP_FAILED {
                return Err(crate::FridaError::MemoryWrite {
                    address: 0,
                    size,
                    reason: format!("mmap 跳板内存失败: {}", std::io::Error::last_os_error()),
                }
                .into());
            }

            log::debug!("分配跳板页: {:#x}, 大小: {}", addr as u64, alloc_size);

            let mut page = TrampolinePage {
                base: addr as u64,
                size: alloc_size,
                offset: 0,
            };

            let trampoline_addr = page.alloc(size).unwrap(); // 新页面一定能分配

            self.trampoline_pages.push(page);
            Ok(trampoline_addr)
        }
    }

    // ======================== 指令重定位 ========================

    /// x86_64 指令重定位
    ///
    /// 将原始指令从 target_addr 复制到 trampoline_addr，
    /// 修正其中的相对偏移（如 RIP-relative 寻址、相对跳转等）。
    #[cfg(target_arch = "x86_64")]
    fn relocate_instructions_x86(
        &self,
        original: &[u8],
        from_addr: u64,
        to_addr: u64,
    ) -> Vec<u8> {
        let mut result = Vec::with_capacity(original.len() + 16);
        let mut idx = 0;

        while idx < original.len() {
            let instr_len = x86_decoder::decode_instruction_length(original, idx);
            if instr_len == 0 || idx + instr_len > original.len() {
                break;
            }

            let instr = &original[idx..idx + instr_len];
            let original_ip = from_addr + idx as u64;
            let new_ip = to_addr + result.len() as u64;
            let delta = (new_ip as i64) - (original_ip as i64);

            // 检查是否是相对跳转/调用指令
            if instr.len() >= 5 && (instr[0] == 0xe8 || instr[0] == 0xe9) {
                // CALL rel32 / JMP rel32 - 需要修正偏移
                let rel32 = i32::from_le_bytes([instr[1], instr[2], instr[3], instr[4]]);
                let new_rel = (rel32 as i64 + delta) as i32;

                result.push(instr[0]);
                result.extend_from_slice(&new_rel.to_le_bytes());
            } else if instr.len() >= 2 && instr[0] == 0x0f && (instr[1] & 0xf0) == 0x80 {
                // JCC rel32 (0F 8x) - 条件跳转
                let rel32 = i32::from_le_bytes([instr[2], instr[3], instr[4], instr[5]]);
                let new_rel = (rel32 as i64 + delta) as i32;

                result.push(0x0f);
                result.push(instr[1]);
                result.extend_from_slice(&new_rel.to_le_bytes());
            } else if instr.len() >= 2 && instr[0] == 0xeb {
                // JMP rel8 - 转换为 JMP rel32
                let rel8 = instr[1] as i8;
                let target = (original_ip as i64 + 2 + rel8 as i64) as u64;
                let new_rel = ((target as i64) - (new_ip as i64 + 5)) as i32;

                result.push(0xe9);
                result.extend_from_slice(&new_rel.to_le_bytes());
            } else {
                // 其他指令 - 需要检查 RIP-relative 寻址
                let is_rip_relative = self.check_rip_relative(instr);

                if is_rip_relative && instr.len() >= 6 {
                    // 修正 ModR/M 字节，将 RIP-relative 改为 [rip + new_disp32]
                    // 重新编码 ModR/M + SIB + disp32
                    let mut fixed_instr = instr.to_vec();
                    // 修正位移量
                    let disp_offset = fixed_instr.len() - 4;
                    if disp_offset + 4 <= fixed_instr.len() {
                        let old_disp =
                            i32::from_le_bytes(fixed_instr[disp_offset..disp_offset + 4].try_into().unwrap());
                        let new_disp = (old_disp as i64 - delta) as i32;
                        fixed_instr[disp_offset..disp_offset + 4].copy_from_slice(&new_disp.to_le_bytes());
                    }
                    result.extend_from_slice(&fixed_instr);
                } else {
                    // 不需要修正，直接复制
                    result.extend_from_slice(instr);
                }
            }

            idx += instr_len;
        }

        result
    }

    /// 检查 x86_64 指令是否使用 RIP-relative 寻址
    #[cfg(target_arch = "x86_64")]
    fn check_rip_relative(&self, instr: &[u8]) -> bool {
        // 跳过 REX 前缀
        let mut i = 0;
        while i < instr.len() && instr[i] >= 0x40 && instr[i] <= 0x4f {
            i += 1;
        }

        if i >= instr.len() {
            return false;
        }

        let opcode = instr[i];
        i += 1;

        // 检查是否是有 ModR/M 字节的指令
        let has_modrm = matches!(
            opcode,
            0x89 | 0x8b | 0x88 | 0x8a | 0x8d | 0x01 | 0x03 | 0x29
                | 0x39 | 0x3b | 0x85 | 0x84 | 0x87 | 0x86 | 0x31 | 0x33 | 0x21 | 0x23 | 0x09 | 0x0b
                | 0xf7 | 0xff | 0x8f
        );

        if !has_modrm || i >= instr.len() {
            return false;
        }

        let modrm = instr[i];
        let mod_val = (modrm >> 6) & 0x03;
        let rm_val = modrm & 0x07;

        // RIP-relative: mod=00, rm=101
        mod_val == 0b00 && rm_val == 0b101
    }

    /// AArch64 指令重定位
    #[cfg(target_arch = "aarch64")]
    fn relocate_instructions_arm64(
        &self,
        original: &[u8],
        from_addr: u64,
        to_addr: u64,
    ) -> Vec<u8> {
        let mut result = Vec::with_capacity(original.len() + 16);
        let mut idx = 0;

        while idx + 4 <= original.len() {
            let inst = u32::from_le_bytes([original[idx], original[idx + 1], original[idx + 2], original[idx + 3]]);
            let original_ip = from_addr + idx as u64;
            let new_ip = to_addr + result.len() as u64;

            if arm64_decoder::is_b_instruction(inst) {
                // B 指令 - 修正偏移
                let imm26 = (inst & 0x03FFFFFF) as i32;
                let offset = (imm26 as i64) << 2;
                let target = original_ip as i64 + offset;
                let new_offset = target - new_ip as i64;
                let new_imm26 = ((new_offset >> 2) & 0x03FFFFFF) as u32;
                let new_inst = (inst & 0xFC000000) | new_imm26;
                result.extend_from_slice(&new_inst.to_le_bytes());
            } else if arm64_decoder::is_bl_instruction(inst) {
                // BL 指令 - 修正偏移
                let imm26 = (inst & 0x03FFFFFF) as i32;
                let offset = (imm26 as i64) << 2;
                let target = original_ip as i64 + offset;
                let new_offset = target - new_ip as i64;
                let new_imm26 = ((new_offset >> 2) & 0x03FFFFFF) as u32;
                let new_inst = (inst & 0xFC000000) | new_imm26;
                result.extend_from_slice(&new_inst.to_le_bytes());
            } else if arm64_decoder::is_bcond_instruction(inst) {
                // B.cond 指令 - 修正偏移
                let imm19 = (inst & 0x00FFFFE0) as i32;
                let offset = (imm19 as i64) << 2;
                let target = original_ip as i64 + offset;
                let new_offset = target - new_ip as i64;
                let new_imm19 = ((new_offset >> 2) & 0x000FFFFF) as u32;
                let new_inst = (inst & 0xFF00001F) | ((new_imm19 << 5) & 0x00FFFFE0);
                result.extend_from_slice(&new_inst.to_le_bytes());
            } else if arm64_decoder::is_stp_instruction(inst) || arm64_decoder::is_ldp_instruction(inst) {
                // STP/LDP 指令 - 可能包含 PC-relative 寻址，需要修正
                // 简化处理：直接复制（大多数 STP/LDP 使用 SP 或寄存器基址寻址，不需要修正）
                result.extend_from_slice(&inst.to_le_bytes());
            } else {
                // 其他指令 - 直接复制
                result.extend_from_slice(&inst.to_le_bytes());
            }

            idx += 4;
        }

        result
    }

    /// 刷新指令缓存
    ///
    /// 在修改可执行内存后必须调用，确保 CPU 使用最新的指令。
    /// 对于跨进程 Hook，需要通过 ptrace 在目标进程中刷新。
    fn flush_instruction_cache(&self, addr: u64, size: usize) {
        #[cfg(windows)]
        {
            use winapi::um::processthreadsapi::{FlushInstructionCache, GetCurrentProcess};
            unsafe {
                FlushInstructionCache(GetCurrentProcess(), addr as *const _, size);
            }
            log::debug!("指令缓存已刷新 (Windows): {:#x} - {:#x}", addr, addr + size as u64);
        }

        #[cfg(not(windows))]
        {
            // SAFETY: __clear_cache 是 GCC/Clang 内建函数，
            // 用于刷新指令缓存的一致性
            unsafe {
                // 从 addr 到 addr+size 刷新指令缓存
                __clear_cache(
                    addr as *mut libc::c_void,
                    (addr + size as u64) as *mut libc::c_void,
                );
            }
            log::debug!("指令缓存已刷新: {:#x} - {:#x}", addr, addr + size as u64);
        }
    }
}

impl Default for InlineHooker {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for InlineHooker {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            use winapi::um::memoryapi::VirtualFree;
            use winapi::um::winnt::MEM_RELEASE;

            for page in &self.trampoline_pages {
                let ret = unsafe { VirtualFree(page.base as *mut _, 0, MEM_RELEASE) };
                if ret == 0 {
                    log::warn!(
                        "释放跳板内存失败 @ {:#x}: {}",
                        page.base,
                        std::io::Error::last_os_error()
                    );
                } else {
                    log::debug!("释放跳板内存 @ {:#x}", page.base);
                }
            }
        }

        #[cfg(not(windows))]
        {
            // 释放所有跳板内存页
            for page in &self.trampoline_pages {
                let ret = unsafe {
                    libc::munmap(
                        page.base as *mut libc::c_void,
                        page.size,
                    )
                };
                if ret != 0 {
                    log::warn!(
                        "释放跳板内存失败 @ {:#x}: {}",
                        page.base,
                        std::io::Error::last_os_error()
                    );
                } else {
                    log::debug!("释放跳板内存 @ {:#x}", page.base);
                }
            }
        }
    }
}

// ======================== 不支持的架构 ========================

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
impl InlineHooker {
    pub fn new() -> Self {
        InlineHooker {}
    }

    pub fn install(&mut self, _target_addr: u64, _detour_addr: u64) -> Result<Trampoline> {
        Err(crate::FridaError::Unsupported {
            reason: "Inline Hook 不支持当前架构".to_string(),
        }
        .into())
    }

    pub fn uninstall(&mut self, _trampoline: &Trampoline) -> Result<()> {
        Ok(())
    }
}
