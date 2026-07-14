//! Java 方法 Hook 实现
//!
//! 通过 JNI（Java Native Interface）拦截 Java 虚拟机中的方法调用。
//! 主要用于 Android 平台，通过修改 ART 虚拟机中的 ArtMethod 结构实现。
//!
//! ## 工作原理
//! 1. 获取 JNI 环境指针（通过 dlopen/dlsym 获取 JNI_GetCreatedJavaVMs）
//! 2. 通过 JNI FindClass → GetMethodID 获取目标方法
//! 3. 找到 ART 内部的 ArtMethod 结构体
//! 4. 替换 ArtMethod.entry_point_from_jni_ 字段指向替换函数
//! 5. 修正 access_flags_ 标志位以标记方法为 native
//!
//! ## 注意事项
//! - 不同 Android 版本的 ArtMethod 结构偏移量可能不同
//! - 需要在 ART 线程中执行 JNI 调用
//! - 替换函数需要遵循 JNI 调用约定

use crate::common::util::{align_to_page, page_size};
use crate::Result;

use std::ffi::{CStr, CString};

// ======================== ArtMethod 结构体 ========================

/// ART 虚拟机中的 ArtMethod 结构体字段偏移量配置
///
/// 不同 Android 版本和架构的偏移量可能不同。
/// 这些值在运行时通过解析 ART 内部数据自动校准。
#[derive(Debug, Clone)]
pub struct ArtMethodOffsets {
    /// entry_point_from_jni_ 字段偏移（JNI 入口点）
    pub entry_point_from_jni: usize,
    /// entry_point_from_quick_compiled_code_ 字段偏移
    pub entry_point_from_quick_code: usize,
    /// access_flags_ 字段偏移
    pub access_flags: usize,
    /// dex_method_index_ 字段偏移
    pub dex_method_index: usize,
    /// ArtMethod 结构体大小
    pub method_size: usize,
}

impl Default for ArtMethodOffsets {
    fn default() -> Self {
        // Android 9 (API 28) / AArch64 默认偏移量
        ArtMethodOffsets {
            entry_point_from_jni: 0,
            entry_point_from_quick_code: 8,
            access_flags: 4,
            dex_method_index: 32,
            method_size: 56,
        }
    }
}

/// ArtMethod 访问标志位
pub mod access_flags {
    /// 方法是 public 的
    pub const ACC_PUBLIC: u32 = 0x0001;
    /// 方法是 private 的
    pub const ACC_PRIVATE: u32 = 0x0002;
    /// 方法是 protected 的
    pub const ACC_PROTECTED: u32 = 0x0004;
    /// 方法是 static 的
    pub const ACC_STATIC: u32 = 0x0008;
    /// 方法是 final 的
    pub const ACC_FINAL: u32 = 0x0010;
    /// 方法是 synchronized 的
    pub const ACC_SYNCHRONIZED: u32 = 0x0020;
    /// 方法是 native 的（通过 JNI 调用）
    pub const ACC_NATIVE: u32 = 0x0100;
    /// 方法是 abstract 的
    pub const ACC_ABSTRACT: u32 = 0x0400;
    /// 方法由编译器生成
    pub const ACC_SYNTHETIC: u32 = 0x1000;
}

// ======================== Java Hook 句柄 ========================

/// Java 方法 Hook 句柄
///
/// 保存 Hook 安装时的原始信息，用于后续恢复。
pub struct JavaHookHandle {
    /// 目标类名（JNI 格式，如 "java/lang/String"）
    pub class_name: String,
    /// 方法名
    pub method_name: String,
    /// 方法签名（JNI 格式，如 "(Ljava/lang/String;)V"）
    pub method_signature: String,
    /// ArtMethod 结构体的地址
    pub art_method_addr: u64,
    /// 原始 entry_point_from_jni_ 值
    pub original_entry_point: u64,
    /// 原始 access_flags_ 值
    pub original_access_flags: u32,
    /// ArtMethod 偏移量配置
    pub offsets: ArtMethodOffsets,
    /// 是否已恢复
    restored: bool,
}

impl std::fmt::Debug for JavaHookHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JavaHookHandle")
            .field("class_name", &self.class_name)
            .field("method_name", &self.method_name)
            .field("method_signature", &self.method_signature)
            .field("art_method_addr", &format_args!("{:#x}", self.art_method_addr))
            .field("original_entry_point", &format_args!("{:#x}", self.original_entry_point))
            .field("original_access_flags", &format_args!("{:#x}", self.original_access_flags))
            .finish()
    }
}

// ======================== Java Hook 安装器 ========================

/// Java Hook 安装器
///
/// 通过修改 ART 虚拟机中的 ArtMethod 结构实现 Java 方法拦截。
/// 需要 JNI 环境才能操作。
pub struct JavaHooker {
    /// JNI 环境指针（JavaVM*）
    java_vm: Option<*mut libc::c_void>,
    /// 缓存的 JNIEnv 指针
    jni_env: Option<*mut libc::c_void>,
    /// 是否已初始化
    initialized: bool,
    /// ArtMethod 字段偏移量
    offsets: ArtMethodOffsets,
    /// ART 库基地址
    art_base: Option<u64>,
    /// libart.so 的句柄（用于 dlsym）
    libart_handle: Option<*mut libc::c_void>,
}

// 安全发送跨线程（JNI 指针本身需要谨慎使用）
unsafe impl Send for JavaHooker {}

impl JavaHooker {
    /// 创建新的 Java Hook 安装器
    pub fn new() -> Self {
        JavaHooker {
            java_vm: None,
            jni_env: None,
            initialized: false,
            offsets: ArtMethodOffsets::default(),
            art_base: None,
            libart_handle: None,
        }
    }

    /// 使用自定义偏移量创建 Java Hook 安装器
    pub fn with_offsets(offsets: ArtMethodOffsets) -> Self {
        JavaHooker {
            java_vm: None,
            jni_env: None,
            initialized: false,
            offsets,
            art_base: None,
            libart_handle: None,
        }
    }

    /// 初始化 JNI 环境
    ///
    /// 通过 dlopen 加载 libart.so 并获取 JNI_GetCreatedJavaVMs 函数。
    pub fn init(&mut self) -> Result<()> {
        if self.initialized {
            log::debug!("JavaHooker 已初始化，跳过");
            return Ok(());
        }

        log::info!("初始化 Java Hook 环境...");

        // 1. 加载 libart.so
        let libart_name = CString::new("libart.so").unwrap();
        let handle = unsafe { libc::dlopen(libart_name.as_ptr(), libc::RTLD_NOW) };

        if handle.is_null() {
            let err = unsafe { CStr::from_ptr(libc::dlerror()) };
            return Err(crate::FridaError::Hook {
                module: "libart.so".to_string(),
                symbol: "dlopen".to_string(),
                reason: format!("加载 libart.so 失败: {:?}", err),
            }
            .into());
        }

        self.libart_handle = Some(handle);

        // 2. 获取 JNI_GetCreatedJavaVMs 函数
        let jni_get_vms_name = CString::new("JNI_GetCreatedJavaVMs").unwrap();
        let jni_get_vms = unsafe { libc::dlsym(handle, jni_get_vms_name.as_ptr()) };

        if jni_get_vms.is_null() {
            return Err(crate::FridaError::Hook {
                module: "libart.so".to_string(),
                symbol: "JNI_GetCreatedJavaVMs".to_string(),
                reason: "未找到 JNI_GetCreatedJavaVMs 函数".to_string(),
            }
            .into());
        }

        // 3. 获取 JavaVM 实例
        // JNI_GetCreatedJavaVMs(JavaVM** vmBuf, jsize bufLen, jsize* nVMs)
        let mut vm_ptr: *mut libc::c_void = std::ptr::null_mut();
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
                }
                .into());
            }
        }

        self.java_vm = Some(vm_ptr);

        // 4. 获取 libart.so 基地址（用于后续偏移计算）
        self.art_base = self.find_libart_base();

        // 5. 尝试自动校准 ArtMethod 偏移量
        self.calibrate_offsets();

        self.initialized = true;
        log::info!(
            "Java Hook 环境初始化完成 (JavaVM={:?}, libart_base={:?})",
            self.java_vm,
            self.art_base
        );
        Ok(())
    }

    /// Hook 指定的 Java 方法
    ///
    /// # 参数
    /// - `class_name`: 类名（JNI 格式，如 "java/lang/String"）
    /// - `method_name`: 方法名（如 "toString"）
    /// - `method_signature`: 方法签名（如 "()Ljava/lang/String;"）
    /// - `replace_addr`: 替换函数的地址（JNI 函数指针）
    ///
    /// # 返回值
    /// 返回 JavaHookHandle，可用于后续恢复
    pub fn hook_method(
        &mut self,
        class_name: &str,
        method_name: &str,
        method_signature: &str,
        replace_addr: u64,
    ) -> Result<JavaHookHandle> {
        if !self.initialized {
            self.init()?;
        }

        log::info!(
            "Hook Java 方法: {}.{}{} -> {:#x}",
            class_name,
            method_name,
            method_signature,
            replace_addr
        );

        // 1. 获取 JNIEnv
        let jni_env = self.get_jni_env()?;

        // 2. 通过 JNI FindClass 找到目标类
        let jni_class = self.jni_find_class(jni_env, class_name)?;
        if jni_class.is_null() {
            return Err(crate::FridaError::Hook {
                module: class_name.to_string(),
                symbol: method_name.to_string(),
                reason: "FindClass 返回 NULL".to_string(),
            }
            .into());
        }

        // 3. GetMethodID 找到目标方法
        let method_id = self.jni_get_method_id(jni_env, jni_class, method_name, method_signature)?;
        if method_id.is_null() {
            return Err(crate::FridaError::Hook {
                module: class_name.to_string(),
                symbol: method_name.to_string(),
                reason: "GetMethodID 返回 NULL".to_string(),
            }
            .into());
        }

        // 4. 在 ART 中，jni 方法 ID 实际上就是指向 ArtMethod 的指针
        // ArtMethod 结构体起始地址就是 method_id
        let art_method_addr = method_id as u64;

        // 5. 保存原始 ArtMethod 数据
        let original_entry_point = self.read_art_method_field_u64(art_method_addr, self.offsets.entry_point_from_jni)?;
        let original_access_flags = self.read_art_method_field_u32(art_method_addr, self.offsets.access_flags)?;

        log::debug!(
            "ArtMethod @ {:#x}: entry_point={:#x}, access_flags={:#x}",
            art_method_addr,
            original_entry_point,
            original_access_flags
        );

        // 6. 修改 entry_point_from_jni_ 指向替换函数
        self.write_art_method_field_u64(
            art_method_addr,
            self.offsets.entry_point_from_jni,
            replace_addr,
        )?;

        // 7. 设置 ACC_NATIVE 标志（确保 ART 使用 JNI 调用路径）
        let new_flags = original_access_flags | access_flags::ACC_NATIVE;
        self.write_art_method_field_u32(art_method_addr, self.offsets.access_flags, new_flags)?;

        // 8. 验证修改结果
        let verify_entry = self.read_art_method_field_u64(art_method_addr, self.offsets.entry_point_from_jni)?;
        let verify_flags = self.read_art_method_field_u32(art_method_addr, self.offsets.access_flags)?;

        if verify_entry != replace_addr || verify_flags != new_flags {
            return Err(crate::FridaError::Hook {
                module: class_name.to_string(),
                symbol: method_name.to_string(),
                reason: format!(
                    "ArtMethod 修改验证失败: entry={:#x} (期望 {:#x}), flags={:#x} (期望 {:#x})",
                    verify_entry, replace_addr, verify_flags, new_flags
                ),
            }
            .into());
        }

        log::info!(
            "Java Hook 安装成功: {}.{}{}",
            class_name, method_name, method_signature
        );

        Ok(JavaHookHandle {
            class_name: class_name.to_string(),
            method_name: method_name.to_string(),
            method_signature: method_signature.to_string(),
            art_method_addr,
            original_entry_point,
            original_access_flags,
            offsets: self.offsets.clone(),
            restored: false,
        })
    }

    /// 恢复被 Hook 的 Java 方法
    pub fn restore(&self, handle: &JavaHookHandle) -> Result<()> {
        if handle.restored {
            log::warn!(
                "Java Hook 已恢复: {}.{}{}",
                handle.class_name,
                handle.method_name,
                handle.method_signature
            );
            return Ok(());
        }

        log::info!(
            "恢复 Java Hook: {}.{}{}",
            handle.class_name,
            handle.method_name,
            handle.method_signature
        );

        // 恢复 entry_point_from_jni_
        self.write_art_method_field_u64(
            handle.art_method_addr,
            handle.offsets.entry_point_from_jni,
            handle.original_entry_point,
        )?;

        // 恢复 access_flags_
        self.write_art_method_field_u32(
            handle.art_method_addr,
            handle.offsets.access_flags,
            handle.original_access_flags,
        )?;

        log::info!(
            "Java Hook 已恢复: {}.{}{}",
            handle.class_name,
            handle.method_name,
            handle.method_signature
        );

        Ok(())
    }

    /// 获取 JNI 环境
    ///
    /// 通过 JavaVM->GetEnv() 获取当前线程的 JNIEnv 指针。
    /// 如果当前线程未附加到 JVM，则先调用 AttachCurrentThread。
    /// 获取成功后会缓存 JNIEnv 指针，后续调用直接返回缓存值。
    fn get_jni_env(&mut self) -> Result<*mut libc::c_void> {
        // 如果已有缓存的 JNIEnv，直接返回
        if let Some(env) = self.jni_env {
            if !env.is_null() {
                return Ok(env);
            }
        }

        // JNI 常量定义
        const JNI_VERSION_1_6: i32 = 0x0001_0006;
        const JNI_EDETACHED: i32 = -2;

        let vm = self.java_vm.ok_or_else(|| {
            crate::FridaError::Hook {
                module: "JNI".to_string(),
                symbol: "GetEnv".to_string(),
                reason: "JavaVM 未初始化，请先调用 init()".to_string(),
            }
        })?;

        // JavaVM 函数表中 GetEnv 的索引为 6
        // JavaVM 结构体：第一个字段是指向函数表的指针（JNIInvokeInterface*）
        // 函数表中第 6 个函数就是 GetEnv
        const JNI_GETENV_IDX: usize = 6;

        let mut env_ptr: *mut libc::c_void = std::ptr::null_mut();

        unsafe {
            // 解引用 JavaVM* 获取函数表指针（JavaVM->functions）
            // JavaVM* -> *JNIInvokeInterface -> functions 指针在偏移 0 处
            let vm_invoke_interface = *(vm as *const *const libc::c_void);

            // 从函数表中获取 GetEnv 函数指针（索引 6）
            let get_env_fn = *(vm_invoke_interface.add(JNI_GETENV_IDX) as *const *const libc::c_void);

            if get_env_fn.is_null() {
                return Err(crate::FridaError::Hook {
                    module: "JNI".to_string(),
                    symbol: "GetEnv".to_string(),
                    reason: "JavaVM 函数表中 GetEnv 为 NULL".to_string(),
                }
                .into());
            }

            // GetEnv(JNIEnv** env, jint version) -> jint
            // 需要传递 GetEnv 函数的签名类型并调用
            type GetEnvFn = extern "system" fn(
                *mut libc::c_void,  // JavaVM*
                *mut *mut libc::c_void,  // JNIEnv**
                i32,                  // version
            ) -> i32;

            let get_env: GetEnvFn = std::mem::transmute(get_env_fn);
            let ret = get_env(vm, &mut env_ptr, JNI_VERSION_1_6);

            if ret == 0 && !env_ptr.is_null() {
                // GetEnv 成功，缓存并返回
                log::debug!("JNI GetEnv 成功: env={:?}", env_ptr);
                self.jni_env = Some(env_ptr);
                return Ok(env_ptr);
            }

            if ret == JNI_EDETACHED {
                // 当前线程未附加到 JVM，需要 AttachCurrentThread
                log::debug!("当前线程未附加到 JVM，调用 AttachCurrentThread...");

                // AttachCurrentThread 在 JavaVM 函数表中的索引为 4
                const JNI_ATTACH_IDX: usize = 4;

                let attach_fn =
                    *(vm_invoke_interface.add(JNI_ATTACH_IDX) as *const *const libc::c_void);

                if attach_fn.is_null() {
                    return Err(crate::FridaError::Hook {
                        module: "JNI".to_string(),
                        symbol: "AttachCurrentThread".to_string(),
                        reason: "JavaVM 函数表中 AttachCurrentThread 为 NULL".to_string(),
                    }
                    .into());
                }

                // AttachCurrentThread(JNIEnv** p_env, void* args) -> jint
                type AttachFn = extern "system" fn(
                    *mut libc::c_void,         // JavaVM*
                    *mut *mut libc::c_void,   // JNIEnv**
                    *mut libc::c_void,         // args (通常传 NULL)
                ) -> i32;

                let attach: AttachFn = std::mem::transmute(attach_fn);
                let ret = attach(vm, &mut env_ptr, std::ptr::null_mut());

                if ret != 0 || env_ptr.is_null() {
                    return Err(crate::FridaError::Hook {
                        module: "JNI".to_string(),
                        symbol: "AttachCurrentThread".to_string(),
                        reason: format!(
                            "AttachCurrentThread 失败: ret={}, env={:?}",
                            ret, env_ptr
                        ),
                    }
                    .into());
                }

                log::debug!("AttachCurrentThread 成功: env={:?}", env_ptr);
                self.jni_env = Some(env_ptr);
                return Ok(env_ptr);
            }

            Err(crate::FridaError::Hook {
                module: "JNI".to_string(),
                symbol: "GetEnv".to_string(),
                reason: format!(
                    "GetEnv 返回错误码: ret={}, env={:?}",
                    ret, env_ptr
                ),
            }
            .into())
        }
    }

    /// JNI FindClass 封装
    ///
    /// 通过 JNI 函数表调用 FindClass 查找 Java 类。
    /// class_name 可以使用点号分隔格式（如 "com.example.Test"），
    /// 会自动转换为 JNI 格式（"com/example/Test"）。
    fn jni_find_class(
        &self,
        env: *mut libc::c_void,
        class_name: &str,
    ) -> Result<*mut libc::c_void> {
        // FindClass 在 JNI 函数表（JNINativeInterface）中的索引为 6
        const JNI_FINDCLASS_IDX: usize = 6;

        // 将类名中的 "." 替换为 "/"，转换为 JNI 内部格式
        // 例如 "com.example.Test" -> "com/example/Test"
        let jni_class_name = class_name.replace('.', "/");
        let c_class_name =
            CString::new(jni_class_name.as_str()).map_err(|_| {
                crate::FridaError::Hook {
                    module: "JNI".to_string(),
                    symbol: "FindClass".to_string(),
                    reason: format!("类名包含空字节: {}", class_name),
                }
            })?;

        unsafe {
            // Android JNI 中 JNIEnv 是指针的指针（***JNIEnv）：
            //   env: *JNIEnv    ->  *env: JNIEnv   ->  JNIEnv->functions: *JNINativeInterface
            // 函数表指针在 env 解引用一次后的偏移 0 处
            //
            // 具体步骤：
            //   1. *(env as *const *const c_void) 获取 JNIEnv 结构体指针
            //   2. 在 JNIEnv 结构体偏移 0 处获取 JNINativeInterface 函数表指针
            //   3. 从函数表按索引获取 FindClass 函数指针

            let jni_env_ptr = *(env as *const *const libc::c_void);
            let func_table = *(jni_env_ptr as *const *const libc::c_void);
            let find_class_fn = *(func_table.add(JNI_FINDCLASS_IDX) as *const *const libc::c_void);

            if find_class_fn.is_null() {
                return Err(crate::FridaError::Hook {
                    module: "JNI".to_string(),
                    symbol: "FindClass".to_string(),
                    reason: "JNI 函数表中 FindClass 为 NULL".to_string(),
                }
                .into());
            }

            // FindClass(JNIEnv* env, const char* name) -> jclass
            type FindClassFn =
                extern "system" fn(*mut libc::c_void, *const libc::c_char) -> *mut libc::c_void;

            let find_class: FindClassFn = std::mem::transmute(find_class_fn);
            let class = find_class(env, c_class_name.as_ptr());

            if class.is_null() {
                return Err(crate::FridaError::Hook {
                    module: "JNI".to_string(),
                    symbol: "FindClass".to_string(),
                    reason: format!("FindClass(\"{}\") 返回 NULL，类可能不存在", class_name),
                }
                .into());
            }

            log::debug!("FindClass(\"{}\") = {:?}", class_name, class);
            Ok(class)
        }
    }

    /// JNI GetMethodID 封装
    ///
    /// 通过 JNI 函数表调用 GetMethodID 查找 Java 类中的实例方法。
    /// 在 ART 虚拟机中，返回的 jmethodID 实际上就是指向 ArtMethod 结构体的指针。
    fn jni_get_method_id(
        &self,
        env: *mut libc::c_void,
        class: *mut libc::c_void,
        method_name: &str,
        sig: &str,
    ) -> Result<*mut libc::c_void> {
        // GetMethodID 在 JNI 函数表（JNINativeInterface）中的索引为 33
        const JNI_GETMETHODID_IDX: usize = 33;

        // 创建方法名和方法签名的 C 字符串
        let c_method_name = CString::new(method_name).map_err(|_| {
            crate::FridaError::Hook {
                module: "JNI".to_string(),
                symbol: "GetMethodID".to_string(),
                reason: format!("方法名包含空字节: {}", method_name),
            }
        })?;
        let c_sig = CString::new(sig).map_err(|_| {
            crate::FridaError::Hook {
                module: "JNI".to_string(),
                symbol: "GetMethodID".to_string(),
                reason: format!("方法签名包含空字节: {}", sig),
            }
        })?;

        unsafe {
            // 获取 JNI 函数表（与 jni_find_class 相同的解引用方式）
            let jni_env_ptr = *(env as *const *const libc::c_void);
            let func_table = *(jni_env_ptr as *const *const libc::c_void);
            let get_method_id_fn =
                *(func_table.add(JNI_GETMETHODID_IDX) as *const *const libc::c_void);

            if get_method_id_fn.is_null() {
                return Err(crate::FridaError::Hook {
                    module: "JNI".to_string(),
                    symbol: "GetMethodID".to_string(),
                    reason: "JNI 函数表中 GetMethodID 为 NULL".to_string(),
                }
                .into());
            }

            // GetMethodID(JNIEnv* env, jclass clazz, const char* name, const char* sig) -> jmethodID
            type GetMethodIDFn = extern "system" fn(
                *mut libc::c_void,   // JNIEnv*
                *mut libc::c_void,   // jclass
                *const libc::c_char, // method name
                *const libc::c_char, // method signature
            ) -> *mut libc::c_void; // jmethodID

            let get_method_id: GetMethodIDFn = std::mem::transmute(get_method_id_fn);
            let method_id = get_method_id(env, class, c_method_name.as_ptr(), c_sig.as_ptr());

            if method_id.is_null() {
                return Err(crate::FridaError::Hook {
                    module: "JNI".to_string(),
                    symbol: "GetMethodID".to_string(),
                    reason: format!(
                        "GetMethodID(\"{}\", \"{}\") 返回 NULL，方法可能不存在",
                        method_name, sig
                    ),
                }
                .into());
            }

            log::debug!(
                "GetMethodID(class={:?}, \"{}\", \"{}\") = {:?}",
                class,
                method_name,
                sig,
                method_id
            );
            Ok(method_id)
        }
    }

    // ======================== ArtMethod 内存操作 ========================

    /// 读取 ArtMethod 的 u64 字段
    fn read_art_method_field_u64(&self, method_addr: u64, offset: usize) -> Result<u64> {
        let field_addr = method_addr + offset as u64;
        let mut value: u64 = 0;

        // SAFETY: 调用者需确保 method_addr 指向有效的 ArtMethod 结构
        unsafe {
            libc::memcpy(
                &mut value as *mut u64 as *mut libc::c_void,
                field_addr as *const libc::c_void,
                std::mem::size_of::<u64>(),
            );
        }

        Ok(value)
    }

    /// 读取 ArtMethod 的 u32 字段
    fn read_art_method_field_u32(&self, method_addr: u64, offset: usize) -> Result<u32> {
        let field_addr = method_addr + offset as u64;
        let mut value: u32 = 0;

        unsafe {
            libc::memcpy(
                &mut value as *mut u32 as *mut libc::c_void,
                field_addr as *const libc::c_void,
                std::mem::size_of::<u32>(),
            );
        }

        Ok(value)
    }

    /// 写入 ArtMethod 的 u64 字段
    fn write_art_method_field_u64(&self, method_addr: u64, offset: usize, value: u64) -> Result<()> {
        let field_addr = method_addr + offset as u64;
        let page_addr = align_to_page(field_addr as usize);
        let protect_size = page_size();

        // 修改内存保护为 RW
        let ret = unsafe {
            libc::mprotect(
                page_addr as *mut libc::c_void,
                protect_size,
                libc::PROT_READ | libc::PROT_WRITE,
            )
        };

        if ret != 0 {
            return Err(crate::FridaError::MemoryProtect {
                address: page_addr,
                reason: format!(
                    "修改 ArtMethod 页面保护失败: {}",
                    std::io::Error::last_os_error()
                ),
            }
            .into());
        }

        // SAFETY: 已将内存设为可写
        unsafe {
            libc::memcpy(
                field_addr as *mut libc::c_void,
                &value as *const u64 as *const libc::c_void,
                std::mem::size_of::<u64>(),
            );
        }

        Ok(())
    }

    /// 写入 ArtMethod 的 u32 字段
    fn write_art_method_field_u32(&self, method_addr: u64, offset: usize, value: u32) -> Result<()> {
        let field_addr = method_addr + offset as u64;
        let page_addr = align_to_page(field_addr as usize);
        let protect_size = page_size();

        let ret = unsafe {
            libc::mprotect(
                page_addr as *mut libc::c_void,
                protect_size,
                libc::PROT_READ | libc::PROT_WRITE,
            )
        };

        if ret != 0 {
            return Err(crate::FridaError::MemoryProtect {
                address: page_addr,
                reason: format!(
                    "修改 ArtMethod 页面保护失败: {}",
                    std::io::Error::last_os_error()
                ),
            }
            .into());
        }

        unsafe {
            libc::memcpy(
                field_addr as *mut libc::c_void,
                &value as *const u32 as *const libc::c_void,
                std::mem::size_of::<u32>(),
            );
        }

        Ok(())
    }

    /// 查找 libart.so 的基地址
    fn find_libart_base(&self) -> Option<u64> {
        let pid = crate::common::types::ProcessId(0);
        if let Ok(regions) = crate::common::util::parse_proc_maps(pid) {
            for region in &regions {
                if region.name.ends_with("libart.so") && region.perms.execute {
                    return Some(region.start as u64);
                }
            }
        }
        None
    }

    /// 尝试自动校准 ArtMethod 偏移量
    ///
    /// 通过三种方式依次尝试校准：
    /// 1. 解析 libart.so 符号表（最准确）
    /// 2. 通过已知 Java 方法（如 String.length）的 ArtMethod 实例分析内存布局
    /// 3. 内置常见 Android 版本的偏移量表作为 fallback
    fn calibrate_offsets(&mut self) {
        if let Some(art_base) = self.art_base {
            log::info!(
                "ArtMethod 偏移量校准开始: libart_base={:#x}",
                art_base
            );

            if let Ok(true) = self.calibrate_by_libart_symbols(art_base) {
                log::info!("ArtMethod 偏移量通过 libart.so 符号表校准成功");
                return;
            }

            if let Ok(true) = self.calibrate_by_known_method(art_base) {
                log::info!("ArtMethod 偏移量通过已知方法分析校准成功");
                return;
            }

            if let Ok(true) = self.calibrate_by_android_version(art_base) {
                log::info!("ArtMethod 偏移量通过 Android 版本表校准成功");
                return;
            }

            log::warn!("ArtMethod 偏移量校准失败，使用默认值（可能在当前 Android 版本上不工作）");
        }
    }

    /// 通过解析 libart.so 符号表校准偏移量
    /// 
    /// 注意：C++ 结构体成员不会被导出为动态符号，此方法主要用于查找 vtable 等全局符号。
    fn calibrate_by_libart_symbols(&mut self, _art_base: u64) -> crate::Result<bool> {
        Ok(false)
    }

    /// 通过已知 Java 方法的 ArtMethod 实例分析内存布局
    /// 
    /// 智能探测 ArtMethod 结构布局，适用于未在版本表中的新 Android 版本（如 Android 15+）。
    fn calibrate_by_known_method(&mut self, _art_base: u64) -> crate::Result<bool> {
        let jni_env = match self.get_jni_env() {
            Ok(env) => env,
            Err(_) => return Ok(false),
        };

        let string_class = match self.jni_find_class(jni_env, "java/lang/String") {
            Ok(cls) => cls,
            Err(_) => return Ok(false),
        };

        let length_method = match self.jni_get_method_id(jni_env, string_class, "length", "()I") {
            Ok(mid) => mid,
            Err(_) => return Ok(false),
        };

        let art_method_addr = length_method as u64;
        log::debug!("String.length() ArtMethod @ {:#x}", art_method_addr);

        let mut word_values = Vec::new();
        for offset in (0..192).step_by(4) {
            let value = self.read_art_method_field_u64(art_method_addr, offset);
            if let Ok(v) = value {
                word_values.push((offset, v));
                if v != 0 && v != 0xFFFFFFFFFFFFFFFF {
                    log::debug!("ArtMethod @ {:#x} +{} = {:#x}", art_method_addr, offset, v);
                }
            }
        }

        let mut entry_point_offsets = Vec::new();
        let mut access_flags_candidates = Vec::new();
        let mut method_size = 56;

        for (offset, value) in &word_values {
            if value != &0 && value != &0xFFFFFFFFFFFFFFFF {
                if self.is_valid_function_pointer(*value) {
                    entry_point_offsets.push((*offset, *value));
                }
                if self.is_valid_access_flags(*value as u32) {
                    access_flags_candidates.push((*offset, *value));
                }
            }
        }

        log::debug!("候选 entry_point 偏移量: {:?}", entry_point_offsets);
        log::debug!("候选 access_flags 偏移量: {:?}", access_flags_candidates);

        let android_version = self.detect_android_version();
        let is_android_12_plus = match android_version.as_str() {
            "12" | "13" | "14" | "15" | "16" => true,
            _ => false,
        };

        let entry_point_from_jni = entry_point_offsets.first().map(|o| o.0).unwrap_or(0);
        
        let entry_point_from_quick_code = if is_android_12_plus {
            entry_point_from_jni
        } else {
            entry_point_offsets.get(1).map(|o| o.0).unwrap_or(8)
        };
        
        let access_flags = access_flags_candidates.first().map(|o| o.0).unwrap_or(4);

        let last_non_zero_offset = word_values
            .iter()
            .rev()
            .find(|(_, v)| *v != 0 && *v != 0xFFFFFFFFFFFFFFFF)
            .map(|(o, _)| *o)
            .unwrap_or(68);
        
        method_size = ((last_non_zero_offset + 8 + 7) / 8) * 8;

        self.offsets.entry_point_from_jni = entry_point_from_jni;
        self.offsets.entry_point_from_quick_code = entry_point_from_quick_code;
        self.offsets.access_flags = access_flags;
        self.offsets.dex_method_index = if entry_point_from_jni == 0 { 32 } else { 12 };
        self.offsets.method_size = method_size;

        log::info!(
            "自动探测 ArtMethod 偏移量: entry_point_from_jni={}, entry_point_from_quick={}, access_flags={}, method_size={}",
            entry_point_from_jni,
            entry_point_from_quick_code,
            access_flags,
            method_size
        );

        Ok(self.is_offset_valid())
    }

    /// 判断是否为有效的函数指针（位于代码段范围内）
    fn is_valid_function_pointer(&self, addr: u64) -> bool {
        if addr == 0 || addr == 0xFFFFFFFFFFFFFFFF {
            return false;
        }
        
        if let Some((start, end)) = self.get_libart_text_range() {
            return addr >= start && addr < end;
        }
        
        let code_range_start = 0x10000000u64;
        let code_range_end_32bit = 0xFFFF0000u64;
        let code_range_start_64bit = 0x700000000000u64;
        let code_range_end_64bit = 0xFFFFFFFFFFFFFFFFu64;
        
        (addr >= code_range_start && addr <= code_range_end_32bit) ||
        (addr >= code_range_start_64bit && addr <= code_range_end_64bit)
    }

    /// 获取 libart.so 的 .text 段地址范围
    fn get_libart_text_range(&self) -> Option<(u64, u64)> {
        if let Ok(maps) = std::fs::read_to_string("/proc/self/maps") {
            for line in maps.lines() {
                if line.contains("libart.so") && line.contains("r-xp") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.is_empty() {
                        continue;
                    }
                    
                    let range = parts[0];
                    if let Some((start_str, end_str)) = range.split_once('-') {
                        if let (Ok(start), Ok(end)) = (u64::from_str_radix(start_str, 16), u64::from_str_radix(end_str, 16)) {
                            log::debug!("libart.so .text 段范围: {:#x} - {:#x}", start, end);
                            return Some((start, end));
                        }
                    }
                }
            }
        }
        None
    }

    /// 判断是否为有效的 access_flags 值
    fn is_valid_access_flags(&self, flags: u32) -> bool {
        if flags == 0 {
            return false;
        }
        
        let common_flags = [
            0x0001, 0x0002, 0x0004, 0x0008, 
            0x0010, 0x0020, 0x0040, 0x0080,
            0x0200, 0x0400, 0x0800, 0x1000,
            0x2000, 0x4000, 0x8000,
        ];
        
        for &f in &common_flags {
            if (flags & f) != 0 {
                return true;
            }
        }
        
        flags <= 0xFFFF
    }

    /// 通过 Android 版本表校准偏移量
    fn calibrate_by_android_version(&mut self, _art_base: u64) -> crate::Result<bool> {
        let android_version = self.detect_android_version();
        log::info!("检测到 Android 版本: {}", android_version);

        let offsets = match android_version.as_str() {
            "7.0" | "7.1" => ArtMethodOffsets {
                entry_point_from_jni: 48,
                entry_point_from_quick_code: 56,
                access_flags: 8,
                dex_method_index: 12,
                method_size: 88,
            },
            "8.0" | "8.1" => ArtMethodOffsets {
                entry_point_from_jni: 48,
                entry_point_from_quick_code: 56,
                access_flags: 8,
                dex_method_index: 12,
                method_size: 88,
            },
            "9" => ArtMethodOffsets {
                entry_point_from_jni: 0,
                entry_point_from_quick_code: 8,
                access_flags: 4,
                dex_method_index: 32,
                method_size: 56,
            },
            "10" | "11" => ArtMethodOffsets {
                entry_point_from_jni: 0,
                entry_point_from_quick_code: 8,
                access_flags: 4,
                dex_method_index: 32,
                method_size: 64,
            },
            "12" | "13" | "14" | "15" | "16" => ArtMethodOffsets {
                entry_point_from_jni: 0,
                entry_point_from_quick_code: 8,
                access_flags: 4,
                dex_method_index: 32,
                method_size: 72,
            },
            _ => return Ok(false),
        };

        self.offsets = offsets;
        Ok(true)
    }

    /// 检测当前 Android 版本
    fn detect_android_version(&self) -> String {
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

    /// 在 libart.so 中查找符号地址
    fn find_libart_symbol(&self, art_base: u64, symbol_name: &str) -> crate::Result<u64> {
        if let Some(handle) = self.libart_handle {
            let symbol_cstr = std::ffi::CString::new(symbol_name)?;
            let sym_addr = unsafe { libc::dlsym(handle, symbol_cstr.as_ptr()) };

            if !sym_addr.is_null() {
                return Ok(sym_addr as u64);
            }
        }

        Err(crate::FridaError::NotFound {
            reason: format!("在 libart.so 中找不到符号 {}", symbol_name),
        }.into())
    }

    /// 检查偏移量是否有效
    fn is_offset_valid(&self) -> bool {
        self.offsets.entry_point_from_jni != 0 || 
        self.offsets.entry_point_from_quick_code != 0 ||
        self.offsets.access_flags != 0
    }
}

impl Default for JavaHooker {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for JavaHooker {
    fn drop(&mut self) {
        if let Some(handle) = self.libart_handle.take() {
            // SAFETY: dlclose 需要有效的句柄
            unsafe {
                libc::dlclose(handle);
            }
            log::debug!("已关闭 libart.so 句柄");
        }
    }
}
