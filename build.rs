//! 构建脚本 - 编译期优化配置
//!
//! - 启用 LTO 链接时优化
//! - 代码优化级别配置
//! - 编译目标架构检测

fn main() {
    // LTO 通过 Cargo.toml 的 lto 配置启用，不再通过链接参数传递
    // println!("cargo:rustc-link-arg=-Wl,--lto");

    // 静态链接标准库（可选）
    // println!("cargo:rustc-link-lib=static=c");

    // 编译优化
    println!("cargo:rustc-env=BUILD_TARGET={}", std::env::var("TARGET").unwrap_or_default());
    println!("cargo:rustc-env=PROFILE={}", std::env::var("PROFILE").unwrap_or_default());
    println!("cargo:rustc-env=BUILD_DATE={}", chrono_build_date());

    // 条件编译提示
    if cfg!(target_arch = "aarch64") {
        println!("cargo:rustc-cfg=target_arch_aarch64");
    } else if cfg!(target_arch = "x86_64") {
        println!("cargo:rustc-cfg=target_arch_x86_64");
    }
}

fn chrono_build_date() -> String {
    // 简单的构建日期
    format!("built on {}", std::env::var("SOURCE_DATE_EPOCH").map(|e| {
        let ts: i64 = e.parse().unwrap_or(0);
        // 简单格式化
        format!("{}", ts)
    }).unwrap_or_else(|_| "unknown".to_string()))
}
