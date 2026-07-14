use crate::common::types::ProcessId;
use crate::Result;
use std::ffi::{CStr, CString};

#[no_mangle]
pub extern "C" fn frida_agent_init(_agent_data: *const u8, _data_size: usize) -> i32 {
    log::info!("Frida-Rust Agent 初始化");
    
    std::thread::spawn(|| {
        match run_wechat_hook() {
            Ok(_) => log::info!("微信 Hook 完成"),
            Err(e) => log::error!("微信 Hook 失败: {}", e),
        }
    });
    
    0
}

fn run_wechat_hook() -> Result<()> {
    log::info!("开始微信输入框 Hook");
    
    let pid = crate::common::util::current_process_id();
    log::info!("当前进程 PID: {}", pid.0);
    
    Ok(())
}

#[no_mangle]
pub extern "C" fn frida_agent_destroy() {
    log::info!("Frida-Rust Agent 销毁");
}