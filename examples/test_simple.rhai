// 简单测试脚本 - 测试基本 API 功能

log_info("=== 基本 API 测试 ===");

// 获取进程信息
let info = get_process_info();
log_info("进程 PID: " + info["pid"].to_string());
log_info("进程名: " + info["name"]);

// 列出所有模块
let modules = list_modules();
log_info("进程中有 " + modules.len().to_string() + " 个模块");
if modules.len() > 0 {
    log_info("第一个模块: " + modules[0]["name"] + " @ " + modules[0]["start"].to_string());
}

// 列出所有线程
let threads = list_threads();
log_info("进程中有 " + threads.len().to_string() + " 个线程");

// 获取当前 PID
let pid = current_pid();
log_info("当前 PID: " + pid.to_string());

log_info("=== 测试完成 ===");
