use libc::{c_char, c_int};
use std::ffi::CString;

#[link(name = "log")]
extern "C" {
    fn __android_log_print(prio: c_int, tag: *const c_char, fmt: *const c_char, ...) -> c_int;
}

macro_rules! log_info {
    ($($arg:tt)*) => {{
        let tag = b"frida-agent\0".as_ptr() as *const c_char;
        let fmt = CString::new(format!($($arg)*)).unwrap();
        unsafe {
            __android_log_print(4, tag, fmt.as_ptr());
        }
    }};
}

#[no_mangle]
pub extern "C" fn frida_agent_init(_agent_data: *const u8, _data_size: usize) -> i32 {
    log_info!("Frida-Rust Agent 初始化");
    
    std::thread::spawn(|| {
        log_info!("Agent 工作线程启动");
        
        let pid = unsafe { libc::getpid() };
        log_info!("当前进程 PID: {}", pid);
        
        log_info!("Agent 工作线程完成");
    });
    
    0
}

#[no_mangle]
pub extern "C" fn frida_agent_destroy() {
    log_info!("Frida-Rust Agent 销毁");
}