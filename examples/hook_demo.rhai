// Frida-Rust Hook 示例脚本
// 演示如何使用 Rhai 脚本进行 Hook 操作

// 获取目标模块基址
let base = get_module_base("libtarget.so");
if base == 0 {
    log_warn("未找到目标模块");
} else {
    log_info("目标模块基址: " + base.to_string());

    // 注册 Hook
    let ok = hook_function("libtarget.so", "target_function");
    if ok {
        log_info("Hook 注册成功");
    }
}

// 读取内存数据
let data = read_memory(base + 0x1000, 64);
log_info("读取到数据: " + data.len().to_string() + " 字节");

// 搜索特征码
let pattern = [0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC];
let results = search_bytes(pattern);
log_info("搜索到 " + results.len().to_string() + " 个匹配");

// 列出所有模块
let modules = list_modules();
log_info("进程中有 " + modules.len().to_string() + " 个模块");
for m in modules {
    log_info("  " + m["name"] + " @ " + m["start"].to_string());
}

// 列出所有线程
let threads = list_threads();
log_info("进程中有 " + threads.len().to_string() + " 个线程");

// 获取进程信息
let info = get_process_info();
log_info("进程 PID: " + info["pid"].to_string());
log_info("进程名: " + info["name"]);
