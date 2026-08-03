log_info("=== Frida-Rust 微信 Hook 测试 ===");

let info = get_process_info();
log_info("进程信息:");
log_info("  PID: " + info["pid"].to_string());
log_info("  Name: " + info["name"].to_string());

let modules = list_modules();
log_info("模块数量: " + modules.len().to_string());

let libart_base = get_module_base("libart.so");
if libart_base != 0 {
    log_info("libart.so 基址: 0x" + libart_base.to_string(16));
} else {
    log_warn("未找到 libart.so");
}

let libwechat_base = get_module_base("libwechatcommon.so");
if libwechat_base != 0 {
    log_info("libwechatcommon.so 基址: 0x" + libwechat_base.to_string(16));
}

log_info("测试完成");