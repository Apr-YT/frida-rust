//! 注入到 Android 进程的 Agent 动态库（仅支持 Android 目标平台）。
//!
//! 该库依赖 JNI 与 Android 的 liblog，在非 Android 平台（如 Windows/Linux 开发机）
//! 构建时自动编译为空库，避免 `__android_log_print` 链接错误。

#![cfg(target_os = "android")]

use libc::{c_char, c_int, c_void};
#[cfg(unix)]
use libc::pid_t;
use std::ffi::{CString, CStr};
use std::ptr;

#[link_section = ".init_array"]
#[used]
static AGENT_INIT: extern "C" fn() = agent_constructor;

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

type JNIEnv = *mut c_void;
type jobject = *mut c_void;
type jclass = *mut c_void;
type jmethodID = *mut c_void;
type jstring = *mut c_void;
type jboolean = bool;
type JavaVM = *mut c_void;

static mut JAVA_VM: JavaVM = ptr::null_mut();

extern "C" fn agent_constructor() {
    log_info!("Agent constructor called");
    let pid = unsafe { libc::getpid() };
    log_info!("PID in constructor: {}", pid);
}

#[no_mangle]
#[allow(improper_ctypes_definitions)]
pub extern "C" fn frida_agent_init(_agent_data: *const u8, _data_size: usize) -> i32 {
    log_info!("Frida-Rust Agent 初始化");
    
    std::thread::spawn(|| {
        log_info!("Agent 工作线程启动");
        
        let pid = unsafe { libc::getpid() };
        log_info!("当前进程 PID: {}", pid);
        
        match init_jni() {
            Ok(_) => {
                log_info!("JNI 初始化成功");
                if let Err(e) = hook_wechat_message_send() {
                    log_info!("Hook 失败: {}", e);
                }
                if let Err(e) = send_test_message() {
                    log_info!("发送测试消息失败: {}", e);
                }
            }
            Err(e) => {
                log_info!("JNI 初始化失败: {}", e);
            }
        }
        
        log_info!("Agent 工作线程完成");
    });
    
    0
}

#[cfg(unix)]
fn init_jni() -> Result<(), String> {
    let libart_name = CString::new("libart.so").map_err(|_| "创建 libart.so 字符串失败".to_string())?;
    
    let handle = unsafe { libc::dlopen(libart_name.as_ptr(), libc::RTLD_NOW) };
    if handle.is_null() {
        return Err("加载 libart.so 失败".to_string());
    }
    
    let jni_get_vms_name = CString::new("JNI_GetCreatedJavaVMs").map_err(|_| "创建 JNI_GetCreatedJavaVMs 字符串失败".to_string())?;
    let jni_get_vms = unsafe { libc::dlsym(handle, jni_get_vms_name.as_ptr()) };
    
    if jni_get_vms.is_null() {
        return Err("未找到 JNI_GetCreatedJavaVMs".to_string());
    }
    
    let mut vm_ptr: JavaVM = ptr::null_mut();
    let mut num_vms: c_int = 0;
    
    unsafe {
        let jni_get_vms_fn: extern "system" fn(
            *mut JavaVM,
            c_int,
            *mut c_int,
        ) -> c_int = std::mem::transmute(jni_get_vms);
        
        let ret = jni_get_vms_fn(&mut vm_ptr, 1, &mut num_vms);
        if ret != 0 || num_vms == 0 || vm_ptr.is_null() {
            return Err(format!("获取 JavaVM 失败: ret={}, num_vms={}", ret, num_vms));
        }
        
        JAVA_VM = vm_ptr;
    }
    
    log_info!("JavaVM 获取成功: {:?}", unsafe { JAVA_VM });
    
    Ok(())
}

#[cfg(windows)]
fn init_jni() -> Result<(), String> {
    Err("JNI 初始化仅支持 Android/Unix 平台".to_string())
}

fn get_jni_env() -> Result<JNIEnv, String> {
    const JNI_VERSION_1_6: i32 = 0x0001_0006;
    const JNI_EDETACHED: i32 = -2;
    
    let vm = unsafe { JAVA_VM };
    if vm.is_null() {
        return Err("JavaVM 未初始化".to_string());
    }
    
    let mut env_ptr: JNIEnv = ptr::null_mut();
    
    unsafe {
        let vm_invoke_interface = *(vm as *const *const c_void);
        let get_env_fn = *(vm_invoke_interface.add(6) as *const *const c_void);
        
        if get_env_fn.is_null() {
            return Err("GetEnv 函数指针为空".to_string());
        }
        
        type GetEnvFn = extern "system" fn(JavaVM, *mut JNIEnv, i32) -> i32;
        let get_env: GetEnvFn = std::mem::transmute(get_env_fn);
        let ret = get_env(vm, &mut env_ptr, JNI_VERSION_1_6);
        
        if ret == 0 && !env_ptr.is_null() {
            return Ok(env_ptr);
        }
        
        if ret == JNI_EDETACHED {
            let attach_fn = *(vm_invoke_interface.add(4) as *const *const c_void);
            if attach_fn.is_null() {
                return Err("AttachCurrentThread 函数指针为空".to_string());
            }
            
            type AttachFn = extern "system" fn(JavaVM, *mut JNIEnv, *mut c_void) -> i32;
            let attach: AttachFn = std::mem::transmute(attach_fn);
            let ret = attach(vm, &mut env_ptr, ptr::null_mut());
            
            if ret != 0 || env_ptr.is_null() {
                return Err(format!("AttachCurrentThread 失败: ret={}", ret));
            }
            
            return Ok(env_ptr);
        }
        
        Err(format!("GetEnv 返回错误: ret={}", ret))
    }
}

fn find_class(env: JNIEnv, class_name: &str) -> Result<jclass, String> {
    let jni_class_name = class_name.replace('.', "/");
    let c_class_name = CString::new(jni_class_name.as_str()).map_err(|e| format!("创建类名字符串失败: {}", e))?;
    
    unsafe {
        let jni_env_ptr = *(env as *const *const c_void);
        let func_table = *(jni_env_ptr as *const *const c_void);
        let find_class_fn = *(func_table.add(6) as *const *const c_void);
        
        if find_class_fn.is_null() {
            return Err("FindClass 函数指针为空".to_string());
        }
        
        type FindClassFn = extern "system" fn(JNIEnv, *const c_char) -> jclass;
        let find_class: FindClassFn = std::mem::transmute(find_class_fn);
        let class = find_class(env, c_class_name.as_ptr());
        
        if class.is_null() {
            log_info!("FindClass({}) 返回 NULL", class_name);
        }
        
        Ok(class)
    }
}

fn get_method_id(env: JNIEnv, class: jclass, method_name: &str, sig: &str) -> Result<jmethodID, String> {
    let c_method_name = CString::new(method_name).map_err(|e| format!("创建方法名字符串失败: {}", e))?;
    let c_sig = CString::new(sig).map_err(|e| format!("创建签名字符串失败: {}", e))?;
    
    unsafe {
        let jni_env_ptr = *(env as *const *const c_void);
        let func_table = *(jni_env_ptr as *const *const c_void);
        let get_method_id_fn = *(func_table.add(33) as *const *const c_void);
        
        if get_method_id_fn.is_null() {
            return Err("GetMethodID 函数指针为空".to_string());
        }
        
        type GetMethodIDFn = extern "system" fn(JNIEnv, jclass, *const c_char, *const c_char) -> jmethodID;
        let get_method_id: GetMethodIDFn = std::mem::transmute(get_method_id_fn);
        let method_id = get_method_id(env, class, c_method_name.as_ptr(), c_sig.as_ptr());
        
        if method_id.is_null() {
            log_info!("GetMethodID({}, {}) 返回 NULL", method_name, sig);
        }
        
        Ok(method_id)
    }
}

fn get_static_method_id(env: JNIEnv, class: jclass, method_name: &str, sig: &str) -> Result<jmethodID, String> {
    let c_method_name = CString::new(method_name).map_err(|e| format!("创建方法名字符串失败: {}", e))?;
    let c_sig = CString::new(sig).map_err(|e| format!("创建签名字符串失败: {}", e))?;
    
    unsafe {
        let jni_env_ptr = *(env as *const *const c_void);
        let func_table = *(jni_env_ptr as *const *const c_void);
        let get_static_method_id_fn = *(func_table.add(34) as *const *const c_void);
        
        if get_static_method_id_fn.is_null() {
            return Err("GetStaticMethodID 函数指针为空".to_string());
        }
        
        type GetStaticMethodIDFn = extern "system" fn(JNIEnv, jclass, *const c_char, *const c_char) -> jmethodID;
        let get_static_method_id: GetStaticMethodIDFn = std::mem::transmute(get_static_method_id_fn);
        let method_id = get_static_method_id(env, class, c_method_name.as_ptr(), c_sig.as_ptr());
        
        if method_id.is_null() {
            log_info!("GetStaticMethodID({}, {}) 返回 NULL", method_name, sig);
        }
        
        Ok(method_id)
    }
}

unsafe fn call_object_method(env: JNIEnv, obj: jobject, method_id: jmethodID, args: *const c_void) -> jobject {
    let jni_env_ptr = *(env as *const *const c_void);
    let func_table = *(jni_env_ptr as *const *const c_void);
    let call_object_method_fn = *(func_table.add(31) as *const *const c_void);
    
    if call_object_method_fn.is_null() {
        return ptr::null_mut();
    }
    
    type CallObjectMethodFn = unsafe extern "system" fn(JNIEnv, jobject, jmethodID, ...) -> jobject;
    let call_object_method: CallObjectMethodFn = std::mem::transmute(call_object_method_fn);
    
    if args.is_null() {
        call_object_method(env, obj, method_id)
    } else {
        let arg1 = *(args as *const jobject);
        call_object_method(env, obj, method_id, arg1)
    }
}

unsafe fn call_object_method2(env: JNIEnv, obj: jobject, method_id: jmethodID, arg1: jobject, arg2: jobject) -> jobject {
    let jni_env_ptr = *(env as *const *const c_void);
    let func_table = *(jni_env_ptr as *const *const c_void);
    let call_object_method_fn = *(func_table.add(31) as *const *const c_void);
    
    if call_object_method_fn.is_null() {
        return ptr::null_mut();
    }
    
    type CallObjectMethodFn = unsafe extern "system" fn(JNIEnv, jobject, jmethodID, ...) -> jobject;
    let call_object_method: CallObjectMethodFn = std::mem::transmute(call_object_method_fn);
    call_object_method(env, obj, method_id, arg1, arg2)
}

unsafe fn call_static_object_method(env: JNIEnv, class: jclass, method_id: jmethodID, args: *const c_void) -> jobject {
    let jni_env_ptr = *(env as *const *const c_void);
    let func_table = *(jni_env_ptr as *const *const c_void);
    let call_static_object_method_fn = *(func_table.add(45) as *const *const c_void);
    
    if call_static_object_method_fn.is_null() {
        return ptr::null_mut();
    }
    
    type CallStaticObjectMethodFn = unsafe extern "system" fn(JNIEnv, jclass, jmethodID, ...) -> jobject;
    let call_static_object_method: CallStaticObjectMethodFn = std::mem::transmute(call_static_object_method_fn);
    
    if args.is_null() {
        call_static_object_method(env, class, method_id)
    } else {
        let arg1 = *(args as *const jobject);
        call_static_object_method(env, class, method_id, arg1)
    }
}

unsafe fn call_void_method(env: JNIEnv, obj: jobject, method_id: jmethodID, args: *const c_void) {
    let jni_env_ptr = *(env as *const *const c_void);
    let func_table = *(jni_env_ptr as *const *const c_void);
    let call_void_method_fn = *(func_table.add(30) as *const *const c_void);
    
    if call_void_method_fn.is_null() {
        return;
    }
    
    type CallVoidMethodFn = unsafe extern "system" fn(JNIEnv, jobject, jmethodID, ...);
    let call_void_method: CallVoidMethodFn = std::mem::transmute(call_void_method_fn);
    
    if args.is_null() {
        call_void_method(env, obj, method_id)
    } else {
        let arg1 = *(args as *const jobject);
        call_void_method(env, obj, method_id, arg1)
    }
}

fn new_string_utf(env: JNIEnv, s: &str) -> jstring {
    let c_str = match CString::new(s) {
        Ok(c) => c,
        Err(_) => return ptr::null_mut(),
    };
    
    unsafe {
        let jni_env_ptr = *(env as *const *const c_void);
        let func_table = *(jni_env_ptr as *const *const c_void);
        let new_string_utf_fn = *(func_table.add(11) as *const *const c_void);
        
        if new_string_utf_fn.is_null() {
            return ptr::null_mut();
        }
        
        type NewStringUTFfn = extern "system" fn(JNIEnv, *const c_char) -> jstring;
        let new_string_utf: NewStringUTFfn = std::mem::transmute(new_string_utf_fn);
        new_string_utf(env, c_str.as_ptr())
    }
}

unsafe fn new_object(env: JNIEnv, class: jclass, method_id: jmethodID, args: *const c_void, arg_count: usize) -> jobject {
    let jni_env_ptr = *(env as *const *const c_void);
    let func_table = *(jni_env_ptr as *const *const c_void);
    let new_object_fn = *(func_table.add(17) as *const *const c_void);
    
    if new_object_fn.is_null() {
        return ptr::null_mut();
    }
    
    type NewObjectFn = unsafe extern "system" fn(JNIEnv, jclass, jmethodID, ...) -> jobject;
    let new_object: NewObjectFn = std::mem::transmute(new_object_fn);
    
    match arg_count {
        0 => new_object(env, class, method_id),
        1 => {
            let arg1 = *(args as *const jobject);
            new_object(env, class, method_id, arg1)
        }
        2 => {
            let args_arr = args as *const [jobject; 2];
            new_object(env, class, method_id, (*args_arr)[0], (*args_arr)[1])
        }
        _ => ptr::null_mut(),
    }
}

fn hook_wechat_message_send() -> Result<(), String> {
    let env = get_jni_env()?;
    
    let target_class_name = "com.tencent.mm.modelmsg.CMessageWrap";
    let target_method_name = "sendMessage";
    let target_signature = "(Lcom/tencent/mm/modelmsg/CMessageWrap;)Z";
    
    log_info!("尝试 Hook: {}.{} {}", target_class_name, target_method_name, target_signature);
    
    let jni_class = find_class(env, target_class_name)?;
    if jni_class.is_null() {
        log_info!("未找到目标类: {}", target_class_name);
        return Ok(());
    }
    
    let method_id = get_method_id(env, jni_class, target_method_name, target_signature)?;
    if method_id.is_null() {
        log_info!("未找到目标方法: {}", target_method_name);
        return Ok(());
    }
    
    log_info!("找到目标方法: {:?}", method_id);
    
    let art_method_addr = method_id as u64;
    log_info!("ArtMethod 地址: 0x{:x}", art_method_addr);
    
    let entry_point_offset = get_entry_point_offset();
    
    let entry_point_addr = art_method_addr + entry_point_offset as u64;
    log_info!("entry_point_from_jni 地址: 0x{:x}", entry_point_addr);
    
    let original_entry_point = unsafe { *(entry_point_addr as *const u64) };
    log_info!("原始 entry_point: 0x{:x}", original_entry_point);
    
    let hook_addr = wechat_send_hook as u64;
    log_info!("替换函数地址: 0x{:x}", hook_addr);
    
    unsafe {
        *(entry_point_addr as *mut u64) = hook_addr;
    }
    
    log_info!("Hook 安装成功！");
    
    Ok(())
}

fn get_entry_point_offset() -> usize {
    let android_version = get_android_version();
    log_info!("Android 版本: {}", android_version);
    
    match android_version.as_str() {
        "7.0" | "7.1" | "8.0" | "8.1" => 48,
        "9" | "10" | "11" | "12" | "13" | "14" | "15" | "16" => 0,
        _ => 0,
    }
}

fn get_android_version() -> String {
    if let Ok(prop) = std::fs::read_to_string("/system/build.prop") {
        for line in prop.lines() {
            if line.starts_with("ro.build.version.release=") {
                return line.split('=').nth(1).unwrap_or("unknown").to_string();
            }
        }
    }
    
    if let Ok(prop) = std::fs::read_to_string("/proc/version") {
        if prop.contains("Android 16") { return "16".to_string(); }
        if prop.contains("Android 15") { return "15".to_string(); }
        if prop.contains("Android 14") { return "14".to_string(); }
        if prop.contains("Android 13") { return "13".to_string(); }
        if prop.contains("Android 12") { return "12".to_string(); }
        if prop.contains("Android 11") { return "11".to_string(); }
        if prop.contains("Android 10") { return "10".to_string(); }
        if prop.contains("Android 9") { return "9".to_string(); }
        if prop.contains("Android 8") { return "8.0".to_string(); }
        if prop.contains("Android 7") { return "7.0".to_string(); }
    }
    
    "unknown".to_string()
}

extern "system" fn wechat_send_hook(env: JNIEnv, _this: jobject, msg_wrap: jobject) -> jboolean {
    log_info!("微信消息发送被拦截！");
    
    if !msg_wrap.is_null() {
        log_info!("消息对象地址: {:?}", msg_wrap);
        
        let msg_text = extract_message_content(env, msg_wrap);
        log_info!("消息内容: {}", msg_text);
    }
    
    true
}

fn extract_message_content(env: JNIEnv, msg_wrap: jobject) -> String {
    let msg_class = find_class(env, "com.tencent.mm.modelmsg.CMessageWrap");
    if msg_class.is_err() || msg_class.as_ref().unwrap().is_null() {
        return "[无法获取消息内容]".to_string();
    }
    
    let class = msg_class.unwrap();
    
    let get_content_method = get_method_id(env, class, "getTalker", "()Ljava/lang/String;");
    if get_content_method.is_err() || get_content_method.as_ref().unwrap().is_null() {
        let get_content_method2 = get_method_id(env, class, "content", "()Ljava/lang/String;");
        if get_content_method2.is_err() || get_content_method2.as_ref().unwrap().is_null() {
            return "[无法获取消息内容]".to_string();
        }
        let content_obj = unsafe { call_object_method(env, msg_wrap, get_content_method2.unwrap(), ptr::null_mut()) };
        return jstring_to_string(env, content_obj);
    }
    
    let content_obj = unsafe { call_object_method(env, msg_wrap, get_content_method.unwrap(), ptr::null_mut()) };
    jstring_to_string(env, content_obj)
}

fn jstring_to_string(env: JNIEnv, jstr: jstring) -> String {
    if jstr.is_null() {
        return "null".to_string();
    }
    
    unsafe {
        let jni_env_ptr = *(env as *const *const c_void);
        let func_table = *(jni_env_ptr as *const *const c_void);
        let get_string_utf_chars_fn = *(func_table.add(16) as *const *const c_void);
        
        if get_string_utf_chars_fn.is_null() {
            return "[无法转换字符串]".to_string();
        }
        
        type GetStringUTFCharsFn = extern "system" fn(JNIEnv, jstring, *mut c_void) -> *const c_char;
        let get_string_utf_chars: GetStringUTFCharsFn = std::mem::transmute(get_string_utf_chars_fn);
        let c_str = get_string_utf_chars(env, jstr, ptr::null_mut());
        
        if c_str.is_null() {
            return "[字符串为空]".to_string();
        }
        
        let result = CStr::from_ptr(c_str).to_string_lossy().to_string();
        
        let release_string_utf_chars_fn = *(func_table.add(17) as *const *const c_void);
        if !release_string_utf_chars_fn.is_null() {
            type ReleaseStringUTFCharsFn = extern "system" fn(JNIEnv, jstring, *const c_char);
            let release_string_utf_chars: ReleaseStringUTFCharsFn = std::mem::transmute(release_string_utf_chars_fn);
            release_string_utf_chars(env, jstr, c_str);
        }
        
        result
    }
}

fn send_test_message() -> Result<(), String> {
    let env = get_jni_env()?;
    
    let content = "微信 Hook 测试消息";
    log_info!("发送测试消息到文件传输助手: {}", content);
    
    send_wechat_message(env, "filehelper", content)?;
    
    log_info!("测试消息发送完成");
    
    Ok(())
}

fn send_wechat_message(env: JNIEnv, to_user: &str, content: &str) -> Result<(), String> {
    let talker_class = find_class(env, "com.tencent.mm.modelmsg.CMessageWrap")?;
    if talker_class.is_null() {
        log_info!("未找到 CMessageWrap 类，尝试其他方式");
        return send_via_broadcast(env, content);
    }
    
    let jni_to_user = new_string_utf(env, to_user);
    let jni_content = new_string_utf(env, content);
    
    if jni_to_user.is_null() || jni_content.is_null() {
        return Err("创建 Java 字符串失败".to_string());
    }
    
    log_info!("通过 CMessageWrap 发送消息");
    
    let constructor_sig = "(Ljava/lang/String;Ljava/lang/String;)V";
    let constructor_id = get_method_id(env, talker_class, "<init>", constructor_sig)?;
    
    if constructor_id.is_null() {
        log_info!("未找到构造函数，尝试其他签名");
        let constructor_sig2 = "(Ljava/lang/String;)V";
        let constructor_id2 = get_method_id(env, talker_class, "<init>", constructor_sig2)?;
        
        if !constructor_id2.is_null() {
            let msg_obj = unsafe { new_object(env, talker_class, constructor_id2, jni_to_user as *const c_void, 1) };
            if !msg_obj.is_null() {
                set_message_content(env, msg_obj, jni_content)?;
                return send_message_obj(env, msg_obj, talker_class);
            }
        }
        
        return send_via_broadcast(env, content);
    }
    
    let args = [jni_to_user, jni_content];
    let msg_obj = unsafe { new_object(env, talker_class, constructor_id, args.as_ptr() as *const c_void, 2) };
    
    if msg_obj.is_null() {
        log_info!("创建消息对象失败，尝试广播方式");
        return send_via_broadcast(env, content);
    }
    
    log_info!("消息对象创建成功: {:?}", msg_obj);
    
    send_message_obj(env, msg_obj, talker_class)?;
    
    Ok(())
}

fn set_message_content(env: JNIEnv, msg_obj: jobject, content: jstring) -> Result<(), String> {
    let msg_class = find_class(env, "com.tencent.mm.modelmsg.CMessageWrap")?;
    if msg_class.is_null() {
        return Err("未找到消息类".to_string());
    }
    
    let set_content_method = get_method_id(env, msg_class, "setContent", "(Ljava/lang/String;)V");
    if set_content_method.is_ok() && !set_content_method.as_ref().unwrap().is_null() {
        unsafe { call_void_method(env, msg_obj, set_content_method.unwrap(), content as *const c_void) };
        return Ok(());
    }
    
    let set_content_method2 = get_method_id(env, msg_class, "setTalker", "(Ljava/lang/String;)V");
    if set_content_method2.is_ok() && !set_content_method2.as_ref().unwrap().is_null() {
        unsafe { call_void_method(env, msg_obj, set_content_method2.unwrap(), content as *const c_void) };
        return Ok(());
    }
    
    Ok(())
}

fn send_message_obj(env: JNIEnv, msg_obj: jobject, msg_class: jclass) -> Result<(), String> {
    let send_method = get_method_id(env, msg_class, "sendMessage", "()Z");
    if send_method.is_ok() && !send_method.as_ref().unwrap().is_null() {
        let result = unsafe { call_object_method(env, msg_obj, send_method.unwrap(), ptr::null_mut()) };
        log_info!("发送结果: {:?}", result);
        return Ok(());
    }
    
    let send_method2 = get_static_method_id(env, msg_class, "sendMessage", "(Lcom/tencent/mm/modelmsg/CMessageWrap;)Z");
    if send_method2.is_ok() && !send_method2.as_ref().unwrap().is_null() {
        let result = unsafe { call_static_object_method(env, msg_class, send_method2.unwrap(), msg_obj as *const c_void) };
        log_info!("发送结果: {:?}", result);
        return Ok(());
    }
    
    log_info!("未找到发送方法，尝试广播方式");
    
    Ok(())
}

fn send_via_broadcast(env: JNIEnv, content: &str) -> Result<(), String> {
    log_info!("尝试通过广播发送消息");
    
    let context = get_application_context(env)?;
    if context.is_null() {
        return Err("获取 ApplicationContext 失败".to_string());
    }
    
    let intent_class = find_class(env, "android.content.Intent")?;
    if intent_class.is_null() {
        return Err("未找到 Intent 类".to_string());
    }
    
    let action_name = new_string_utf(env, "com.tencent.mm.intent.action.SEND_MESSAGE");
    if action_name.is_null() {
        return Err("创建 action 字符串失败".to_string());
    }
    
    let intent_ctor_sig = "(Ljava/lang/String;)V";
    let intent_ctor = get_method_id(env, intent_class, "<init>", intent_ctor_sig)?;
    if intent_ctor.is_null() {
        return Err("未找到 Intent 构造函数".to_string());
    }
    
    let intent = unsafe { new_object(env, intent_class, intent_ctor, action_name as *const c_void, 1) };
    if intent.is_null() {
        return Err("创建 Intent 失败".to_string());
    }
    
    let put_extra_sig = "(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;";
    let put_extra_method = get_method_id(env, intent_class, "putExtra", put_extra_sig)?;
    
    if !put_extra_method.is_null() {
        let key_str = new_string_utf(env, "msg_content");
        let msg_str = new_string_utf(env, content);
        
        if !key_str.is_null() && !msg_str.is_null() {
            unsafe { call_object_method2(env, intent, put_extra_method, key_str, msg_str) };
            log_info!("Intent 参数设置完成");
        }
    }
    
    let context_class = find_class(env, "android.content.Context")?;
    if !context_class.is_null() {
        let send_broadcast_sig = "(Landroid/content/Intent;)V";
        let send_broadcast_method = get_method_id(env, context_class, "sendBroadcast", send_broadcast_sig)?;
        
        if !send_broadcast_method.is_null() {
            unsafe { call_void_method(env, context, send_broadcast_method, intent as *const c_void) };
            log_info!("广播已发送");
        }
    }
    
    Ok(())
}

fn get_application_context(env: JNIEnv) -> Result<jobject, String> {
    let activity_thread_class = find_class(env, "android.app.ActivityThread")?;
    if activity_thread_class.is_null() {
        return Err("未找到 ActivityThread 类".to_string());
    }
    
    let current_method = get_static_method_id(env, activity_thread_class, "currentActivityThread", "()Landroid/app/ActivityThread;")?;
    if current_method.is_null() {
        return Err("未找到 currentActivityThread 方法".to_string());
    }
    
    let activity_thread = unsafe { call_static_object_method(env, activity_thread_class, current_method, ptr::null_mut()) };
    if activity_thread.is_null() {
        return Err("获取 ActivityThread 失败".to_string());
    }
    
    let get_app_method = get_method_id(env, activity_thread_class, "getApplication", "()Landroid/app/Application;")?;
    if get_app_method.is_null() {
        return Err("未找到 getApplication 方法".to_string());
    }
    
    let app = unsafe { call_object_method(env, activity_thread, get_app_method, ptr::null_mut()) };
    
    if app.is_null() {
        log_info!("获取 Application 失败，尝试 getApplicationContext");
        let get_context_method = get_method_id(env, activity_thread_class, "getApplicationContext", "()Landroid/content/Context;")?;
        if !get_context_method.is_null() {
            return Ok(unsafe { call_object_method(env, activity_thread, get_context_method, ptr::null_mut()) });
        }
    }
    
    Ok(app)
}

#[no_mangle]
pub extern "C" fn frida_agent_destroy() {
    log_info!("Frida-Rust Agent 销毁");
}

#[no_mangle]
pub extern "C" fn send_message_to_wechat(content: *const c_char) -> c_int {
    let c_str = unsafe { CStr::from_ptr(content) };
    let content_str = c_str.to_string_lossy().to_string();
    
    log_info!("外部调用发送消息: {}", content_str);
    
    match get_jni_env() {
        Ok(env) => {
            match send_wechat_message(env, "filehelper", &content_str) {
                Ok(_) => 0,
                Err(e) => {
                    log_info!("发送失败: {}", e);
                    -1
                }
            }
        }
        Err(e) => {
            log_info!("获取 JNIEnv 失败: {}", e);
            -1
        }
    }
}
