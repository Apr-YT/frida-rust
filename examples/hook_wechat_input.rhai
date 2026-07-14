log_info("=== Frida-Rust 微信输入框 Hook 测试 ===");

log_info("获取当前进程信息");
let proc_info = get_process_info();
log_info("进程名: " + proc_info["name"].to_string());
log_info("PID: " + proc_info["pid"].to_string());

log_info("列出已加载模块");
let modules = list_modules();
log_info("模块数量: " + modules.len().to_string());

let found_art = false;
for mod in modules {
    let name = mod["name"].to_string();
    if name.contains("libart.so") {
        let start_addr = mod["start"].to_int();
        log_info("找到 libart.so: " + name);
        found_art = true;
    }
}

if found_art == false {
    log_warn("未找到 libart.so");
}

log_info("测试完成");