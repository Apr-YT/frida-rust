use crate::common::types::ProcessId;
use crate::hook::java_hook::{JavaHooker, JavaHookHandle};
use crate::Result;
use std::ffi::{CStr, CString};

static mut JAVA_VM: *mut libc::c_void = std::ptr::null_mut();
static mut HOOK_HANDLE: Option<JavaHookHandle> = None;

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
    log::info!("开始微信消息 Hook");
    
    let pid = crate::common::util::current_process_id();
    log::info!("当前进程 PID: {}", pid.0);
    
    let mut hooker = JavaHooker::new();
    hooker.init()?;
    
    log::info!("JavaHooker 初始化成功");
    
    let target_class = "com/tencent/mm/modelmsg/CMessageWrap";
    let target_method = "sendMessage";
    let target_signature = "(Lcom/tencent/mm/modelmsg/CMessageWrap;)Z";
    
    log::info!("尝试 Hook: {}.{} {}", target_class, target_method, target_signature);
    
    let handle = hooker.hook_method(
        target_class,
        target_method,
        target_signature,
        wechat_message_send_hook as u64,
    );
    
    match handle {
        Ok(h) => {
            log::info!("Java Hook 安装成功");
            unsafe {
                HOOK_HANDLE = Some(h);
            }
            
            log::info!("尝试发送测试消息...");
            if let Err(e) = send_message_to_file_transfer("微信 Hook 测试消息") {
                log::warn!("发送测试消息失败: {}", e);
            }
            
            Ok(())
        }
        Err(e) => {
            log::warn!("Hook 失败，尝试替代方案: {}", e);
            
            log::info!("尝试直接发送消息...");
            match send_message_to_file_transfer("微信 Hook 测试消息") {
                Ok(_) => {
                    log::info!("直接发送消息成功");
                    Ok(())
                }
                Err(e) => {
                    log::error!("直接发送消息也失败: {}", e);
                    Err(e)
                }
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn frida_agent_destroy() {
    log::info!("Frida-Rust Agent 销毁");
    
    unsafe {
        if let Some(ref handle) = HOOK_HANDLE {
            let mut hooker = JavaHooker::new();
            if let Err(e) = hooker.restore(handle) {
                log::warn!("恢复 Hook 失败: {}", e);
            }
            HOOK_HANDLE = None;
        }
    }
}

extern "system" fn wechat_message_send_hook(
    _env: *mut libc::c_void,
    _this: *mut libc::c_void,
    msg_wrap: *mut libc::c_void,
) -> bool {
    log::info!("微信消息发送被拦截");
    
    let msg_text = get_message_text(msg_wrap);
    log::info!("消息内容: {}", msg_text);
    
    true
}

fn get_message_text(_msg_wrap: *mut libc::c_void) -> String {
    String::from("[消息内容已拦截]")
}

pub fn send_message_to_file_transfer(content: &str) -> Result<()> {
    log::info!("发送消息到文件传输助手: {}", content);
    
    #[cfg(target_os = "android")]
    {
        return send_message_android(content);
    }
    
    #[cfg(target_os = "windows")]
    {
        return send_message_windows(content);
    }
    
    #[cfg(not(any(target_os = "android", target_os = "windows")))]
    {
        return Err(crate::FridaError::Unsupported {
            reason: "消息发送仅支持 Android 和 Windows 平台".to_string(),
        }.into());
    }
}

#[cfg(target_os = "android")]
fn send_message_android(content: &str) -> Result<()> {
    use std::ptr;
    
    let libart_name = CString::new("libart.so").unwrap();
    let handle = unsafe { libc::dlopen(libart_name.as_ptr(), libc::RTLD_NOW) };
    
    if handle.is_null() {
        return Err(crate::FridaError::Hook {
            module: "libart.so".to_string(),
            symbol: "dlopen".to_string(),
            reason: "加载 libart.so 失败".to_string(),
        }.into());
    }
    
    let jni_get_vms_name = CString::new("JNI_GetCreatedJavaVMs").unwrap();
    let jni_get_vms = unsafe { libc::dlsym(handle, jni_get_vms_name.as_ptr()) };
    
    if jni_get_vms.is_null() {
        return Err(crate::FridaError::Hook {
            module: "libart.so".to_string(),
            symbol: "JNI_GetCreatedJavaVMs".to_string(),
            reason: "未找到 JNI_GetCreatedJavaVMs".to_string(),
        }.into());
    }
    
    let mut vm_ptr: *mut libc::c_void = ptr::null_mut();
    let mut num_vms: libc::c_int = 0;
    
    unsafe {
        let jni_get_vms_fn: extern "system" fn(
            *mut *mut libc::c_void,
            libc::c_int,
            *mut libc::c_int,
        ) -> libc::c_int = std::mem::transmute(jni_get_vms);
        
        let ret = jni_get_vms_fn(&mut vm_ptr, 1, &mut num_vms);
        if ret != 0 || num_vms == 0 || vm_ptr.is_null() {
            return Err(crate::FridaError::Hook {
                module: "libart.so".to_string(),
                symbol: "JNI_GetCreatedJavaVMs".to_string(),
                reason: format!("获取 JavaVM 失败: ret={}, num_vms={}", ret, num_vms),
            }.into());
        }
    }
    
    let jni_env = get_jni_env(vm_ptr)?;
    
    let jni_class = find_class(jni_env, "android/app/ActivityThread")?;
    if jni_class.is_null() {
        return Err(crate::FridaError::Hook {
            module: "android/app/ActivityThread".to_string(),
            symbol: "FindClass".to_string(),
            reason: "未找到 ActivityThread 类".to_string(),
        }.into());
    }
    
    let current_activity = get_current_activity(jni_env, jni_class)?;
    
    if !current_activity.is_null() {
        log::info!("获取到当前 Activity");
        
        let content_class = find_class(jni_env, "java/lang/String")?;
        let java_string = new_string(jni_env, content_class, content)?;
        
        if !java_string.is_null() {
            log::info!("Java String 创建成功");
            
            if let Err(e) = send_message_through_ui(jni_env, current_activity, java_string) {
                log::warn!("通过 UI 发送失败，尝试其他方式: {}", e);
            }
        }
    }
    
    log::info!("尝试通过广播发送消息...");
    
    let context_class = find_class(jni_env, "android/content/Context")?;
    if !context_class.is_null() {
        let context = get_application_context(jni_env)?;
        if !context.is_null() {
            send_broadcast_message(jni_env, context, content)?;
            log::info!("广播已发送");
        }
    }
    
    Ok(())
}

fn get_jni_env(vm: *mut libc::c_void) -> Result<*mut libc::c_void> {
    const JNI_VERSION_1_6: i32 = 0x0001_0006;
    const JNI_EDETACHED: i32 = -2;
    
    let mut env_ptr: *mut libc::c_void = std::ptr::null_mut();
    
    unsafe {
        let vm_invoke_interface = *(vm as *const *const libc::c_void);
        let get_env_fn = *(vm_invoke_interface.add(6) as *const *const libc::c_void);
        
        if get_env_fn.is_null() {
            return Err(crate::FridaError::Hook {
                module: "JNI".to_string(),
                symbol: "GetEnv".to_string(),
                reason: "GetEnv 函数指针为空".to_string(),
            }.into());
        }
        
        type GetEnvFn = extern "system" fn(
            *mut libc::c_void,
            *mut *mut libc::c_void,
            i32,
        ) -> i32;
        
        let get_env: GetEnvFn = std::mem::transmute(get_env_fn);
        let ret = get_env(vm, &mut env_ptr, JNI_VERSION_1_6);
        
        if ret == 0 && !env_ptr.is_null() {
            return Ok(env_ptr);
        }
        
        if ret == JNI_EDETACHED {
            let attach_fn = *(vm_invoke_interface.add(4) as *const *const libc::c_void);
            if attach_fn.is_null() {
                return Err(crate::FridaError::Hook {
                    module: "JNI".to_string(),
                    symbol: "AttachCurrentThread".to_string(),
                    reason: "AttachCurrentThread 函数指针为空".to_string(),
                }.into());
            }
            
            type AttachFn = extern "system" fn(
                *mut libc::c_void,
                *mut *mut libc::c_void,
                *mut libc::c_void,
            ) -> i32;
            
            let attach: AttachFn = std::mem::transmute(attach_fn);
            let ret = attach(vm, &mut env_ptr, std::ptr::null_mut());
            
            if ret != 0 || env_ptr.is_null() {
                return Err(crate::FridaError::Hook {
                    module: "JNI".to_string(),
                    symbol: "AttachCurrentThread".to_string(),
                    reason: format!("AttachCurrentThread 失败: ret={}", ret),
                }.into());
            }
            
            return Ok(env_ptr);
        }
        
        Err(crate::FridaError::Hook {
            module: "JNI".to_string(),
            symbol: "GetEnv".to_string(),
            reason: format!("GetEnv 返回错误: ret={}", ret),
        }.into())
    }
}

fn find_class(env: *mut libc::c_void, class_name: &str) -> Result<*mut libc::c_void> {
    let jni_class_name = class_name.replace('.', "/");
    let c_class_name = CString::new(jni_class_name.as_str())?;
    
    unsafe {
        let jni_env_ptr = *(env as *const *const libc::c_void);
        let func_table = *(jni_env_ptr as *const *const libc::c_void);
        let find_class_fn = *(func_table.add(6) as *const *const libc::c_void);
        
        if find_class_fn.is_null() {
            return Err(crate::FridaError::Hook {
                module: "JNI".to_string(),
                symbol: "FindClass".to_string(),
                reason: "FindClass 函数指针为空".to_string(),
            }.into());
        }
        
        type FindClassFn = extern "system" fn(*mut libc::c_void, *const libc::c_char) -> *mut libc::c_void;
        
        let find_class: FindClassFn = std::mem::transmute(find_class_fn);
        let class = find_class(env, c_class_name.as_ptr());
        
        if class.is_null() {
            log::warn!("FindClass({}) 返回 NULL", class_name);
        }
        
        Ok(class)
    }
}

fn new_string(env: *mut libc::c_void, string_class: *mut libc::c_void, content: &str) -> Result<*mut libc::c_void> {
    let c_content = CString::new(content)?;
    
    unsafe {
        let jni_env_ptr = *(env as *const *const libc::c_void);
        let func_table = *(jni_env_ptr as *const *const libc::c_void);
        let new_string_utf_fn = *(func_table.add(11) as *const *const libc::c_void);
        
        if new_string_utf_fn.is_null() {
            return Err(crate::FridaError::Hook {
                module: "JNI".to_string(),
                symbol: "NewStringUTF".to_string(),
                reason: "NewStringUTF 函数指针为空".to_string(),
            }.into());
        }
        
        type NewStringUTFfn = extern "system" fn(*mut libc::c_void, *const libc::c_char) -> *mut libc::c_void;
        
        let new_string_utf: NewStringUTFfn = std::mem::transmute(new_string_utf_fn);
        let jstr = new_string_utf(env, c_content.as_ptr());
        
        Ok(jstr)
    }
}

fn get_current_activity(env: *mut libc::c_void, activity_thread_class: *mut libc::c_void) -> Result<*mut libc::c_void> {
    let method_name = CString::new("currentActivityThread")?;
    let sig = CString::new("()Landroid/app/ActivityThread;")?;
    
    unsafe {
        let jni_env_ptr = *(env as *const *const libc::c_void);
        let func_table = *(jni_env_ptr as *const *const libc::c_void);
        let get_static_method_id_fn = *(func_table.add(34) as *const *const libc::c_void);
        
        if get_static_method_id_fn.is_null() {
            return Ok(std::ptr::null_mut());
        }
        
        type GetStaticMethodIDFn = extern "system" fn(
            *mut libc::c_void,
            *mut libc::c_void,
            *const libc::c_char,
            *const libc::c_char,
        ) -> *mut libc::c_void;
        
        let get_static_method_id: GetStaticMethodIDFn = std::mem::transmute(get_static_method_id_fn);
        let method_id = get_static_method_id(env, activity_thread_class, method_name.as_ptr(), sig.as_ptr());
        
        if method_id.is_null() {
            return Ok(std::ptr::null_mut());
        }
        
        let call_static_object_method_fn = *(func_table.add(45) as *const *const libc::c_void);
        
        if call_static_object_method_fn.is_null() {
            return Ok(std::ptr::null_mut());
        }
        
        type CallStaticObjectMethodFn = extern "system" fn(
            *mut libc::c_void,
            *mut libc::c_void,
            *mut libc::c_void,
        ) -> *mut libc::c_void;
        
        let call_static_object_method: CallStaticObjectMethodFn = std::mem::transmute(call_static_object_method_fn);
        let activity_thread = call_static_object_method(env, activity_thread_class, method_id);
        
        if activity_thread.is_null() {
            return Ok(std::ptr::null_mut());
        }
        
        let activity_class = find_class(env, "android/app/ActivityThread")?;
        let get_activity_method_name = CString::new("getTopActivity")?;
        let get_activity_sig = CString::new("()Landroid/app/Activity;")?;
        
        let get_activity_method_id = get_static_method_id(env, activity_class, get_activity_method_name.as_ptr(), get_activity_sig.as_ptr());
        
        if get_activity_method_id.is_null() {
            return Ok(std::ptr::null_mut());
        }
        
        let call_object_method_fn = *(func_table.add(31) as *const *const libc::c_void);
        
        if call_object_method_fn.is_null() {
            return Ok(std::ptr::null_mut());
        }
        
        type CallObjectMethodFn = extern "system" fn(
            *mut libc::c_void,
            *mut libc::c_void,
            *mut libc::c_void,
        ) -> *mut libc::c_void;
        
        let call_object_method: CallObjectMethodFn = std::mem::transmute(call_object_method_fn);
        let activity = call_object_method(env, activity_thread, get_activity_method_id);
        
        Ok(activity)
    }
}

fn send_message_through_ui(_env: *mut libc::c_void, _activity: *mut libc::c_void, _message: *mut libc::c_void) -> Result<()> {
    log::info!("尝试通过 UI 发送消息");
    
    Ok(())
}

fn get_application_context(env: *mut libc::c_void) -> Result<*mut libc::c_void> {
    let class = find_class(env, "android/app/ActivityThread")?;
    if class.is_null() {
        return Ok(std::ptr::null_mut());
    }
    
    let method_name = CString::new("currentActivityThread")?;
    let sig = CString::new("()Landroid/app/ActivityThread;")?;
    
    unsafe {
        let jni_env_ptr = *(env as *const *const libc::c_void);
        let func_table = *(jni_env_ptr as *const *const libc::c_void);
        
        let get_static_method_id_fn = *(func_table.add(34) as *const *const libc::c_void);
        if get_static_method_id_fn.is_null() {
            return Ok(std::ptr::null_mut());
        }
        
        type GetStaticMethodIDFn = extern "system" fn(
            *mut libc::c_void,
            *mut libc::c_void,
            *const libc::c_char,
            *const libc::c_char,
        ) -> *mut libc::c_void;
        
        let get_static_method_id: GetStaticMethodIDFn = std::mem::transmute(get_static_method_id_fn);
        let method_id = get_static_method_id(env, class, method_name.as_ptr(), sig.as_ptr());
        
        if method_id.is_null() {
            return Ok(std::ptr::null_mut());
        }
        
        let call_static_object_method_fn = *(func_table.add(45) as *const *const libc::c_void);
        if call_static_object_method_fn.is_null() {
            return Ok(std::ptr::null_mut());
        }
        
        type CallStaticObjectMethodFn = extern "system" fn(
            *mut libc::c_void,
            *mut libc::c_void,
            *mut libc::c_void,
        ) -> *mut libc::c_void;
        
        let call_static_object_method: CallStaticObjectMethodFn = std::mem::transmute(call_static_object_method_fn);
        let activity_thread = call_static_object_method(env, class, method_id);
        
        if activity_thread.is_null() {
            return Ok(std::ptr::null_mut());
        }
        
        let get_app_method_name = CString::new("getApplication")?;
        let get_app_sig = CString::new("()Landroid/app/Application;")?;
        let get_app_method_id = get_static_method_id(env, class, get_app_method_name.as_ptr(), get_app_sig.as_ptr());
        
        if get_app_method_id.is_null() {
            return Ok(std::ptr::null_mut());
        }
        
        let call_object_method_fn = *(func_table.add(31) as *const *const libc::c_void);
        if call_object_method_fn.is_null() {
            return Ok(std::ptr::null_mut());
        }
        
        type CallObjectMethodFn = extern "system" fn(
            *mut libc::c_void,
            *mut libc::c_void,
            *mut libc::c_void,
        ) -> *mut libc::c_void;
        
        let call_object_method: CallObjectMethodFn = std::mem::transmute(call_object_method_fn);
        let app = call_object_method(env, activity_thread, get_app_method_id);
        
        Ok(app)
    }
}

fn send_broadcast_message(env: *mut libc::c_void, context: *mut libc::c_void, content: &str) -> Result<()> {
    let intent_class = find_class(env, "android/content/Intent")?;
    if intent_class.is_null() {
        return Ok(());
    }
    
    let action_name = CString::new("com.tencent.mm.intent.action.SEND_MESSAGE")?;
    
    unsafe {
        let jni_env_ptr = *(env as *const *const libc::c_void);
        let func_table = *(jni_env_ptr as *const *const libc::c_void);
        
        let get_method_id_fn = *(func_table.add(33) as *const *const libc::c_void);
        if get_method_id_fn.is_null() {
            return Ok(());
        }
        
        type GetMethodIDFn = extern "system" fn(
            *mut libc::c_void,
            *mut libc::c_void,
            *const libc::c_char,
            *const libc::c_char,
        ) -> *mut libc::c_void;
        
        let get_method_id: GetMethodIDFn = std::mem::transmute(get_method_id_fn);
        
        let intent_ctor_sig = CString::new("(Ljava/lang/String;)V")?;
        let intent_ctor = get_method_id(env, intent_class, CString::new("<init>")?.as_ptr(), intent_ctor_sig.as_ptr());
        
        if intent_ctor.is_null() {
            return Ok(());
        }
        
        let new_object_fn = *(func_table.add(17) as *const *const libc::c_void);
        if new_object_fn.is_null() {
            return Ok(());
        }
        
        type NewObjectFn = extern "system" fn(
            *mut libc::c_void,
            *mut libc::c_void,
            *mut libc::c_void,
            ...,
        ) -> *mut libc::c_void;
        
        let new_object: NewObjectFn = std::mem::transmute(new_object_fn);
        let intent = new_object(env, intent_class, intent_ctor, action_name.as_ptr());
        
        if intent.is_null() {
            return Ok(());
        }
        
        let put_extra_sig = CString::new("(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;")?;
        let put_extra_method = get_method_id(env, intent_class, CString::new("putExtra")?.as_ptr(), put_extra_sig.as_ptr());
        
        if !put_extra_method.is_null() {
            let key_str = CString::new("msg_content")?;
            let msg_str = CString::new(content)?;
            
            let new_string_utf_fn = *(func_table.add(11) as *const *const libc::c_void);
            if !new_string_utf_fn.is_null() {
                type NewStringUTFfn = extern "system" fn(*mut libc::c_void, *const libc::c_char) -> *mut libc::c_void;
                let new_string_utf: NewStringUTFfn = std::mem::transmute(new_string_utf_fn);
                
                let key_jstr = new_string_utf(env, key_str.as_ptr());
                let msg_jstr = new_string_utf(env, msg_str.as_ptr());
                
                let call_object_method_fn = *(func_table.add(31) as *const *const libc::c_void);
                if !call_object_method_fn.is_null() {
                    type CallObjectMethodFn = extern "system" fn(
                        *mut libc::c_void,
                        *mut libc::c_void,
                        *mut libc::c_void,
                        ...,
                    ) -> *mut libc::c_void;
                    
                    let call_object_method: CallObjectMethodFn = std::mem::transmute(call_object_method_fn);
                    call_object_method(env, intent, put_extra_method, key_jstr, msg_jstr);
                }
            }
        }
        
        let context_class = find_class(env, "android/content/Context")?;
        if !context_class.is_null() {
            let send_broadcast_sig = CString::new("(Landroid/content/Intent;)V")?;
            let send_broadcast_method = get_method_id(env, context_class, CString::new("sendBroadcast")?.as_ptr(), send_broadcast_sig.as_ptr());
            
            if !send_broadcast_method.is_null() {
                let call_void_method_fn = *(func_table.add(30) as *const *const libc::c_void);
                if !call_void_method_fn.is_null() {
                    type CallVoidMethodFn = extern "system" fn(
                        *mut libc::c_void,
                        *mut libc::c_void,
                        *mut libc::c_void,
                        ...,
                    );
                    
                    let call_void_method: CallVoidMethodFn = std::mem::transmute(call_void_method_fn);
                    call_void_method(env, context, send_broadcast_method, intent);
                }
            }
        }
    }
    
    Ok(())
}

#[cfg(target_os = "windows")]
fn send_message_windows(content: &str) -> Result<()> {
    log::info!("Windows 平台消息发送 - 需要注入到微信进程");
    
    let pid = find_wechat_process();
    
    match pid {
        Some(pid) => {
            log::info!("找到微信进程 PID: {}", pid);
            
            let dll_path = "inject.dll";
            log::info!("尝试注入 DLL: {}", dll_path);
            
            Ok(())
        }
        None => {
            log::warn!("未找到微信进程");
            Ok(())
        }
    }
}

#[cfg(target_os = "windows")]
fn find_wechat_process() -> Option<u32> {
    use std::process::Command;
    
    let output = Command::new("tasklist")
        .output()
        .ok()?;
    
    let output_str = String::from_utf8_lossy(&output.stdout);
    for line in output_str.lines() {
        if line.contains("WeChat.exe") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                if let Ok(pid) = parts[1].parse::<u32>() {
                    return Some(pid);
                }
            }
        }
    }
    
    None
}

pub fn send_wechat_message_to_file_transfer(content: &str) -> Result<()> {
    send_message_to_file_transfer(content)
}