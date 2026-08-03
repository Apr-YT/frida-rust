# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Android 主机侧 adb 直连能力（P0）
  - `src/android/adb.rs` - adb 封装（设备发现 / shell / push / forward，任意主机平台可用）
  - `src/android/device.rs` - DeviceClient（设备信息 / 进程列表 / 包列表 / logcat）
  - MCP `device_list` 工具 + 现有安卓工具改为 adb 直连（不再受主机平台限制）
- 设备端 `frida-server` 守护进程（crates/frida-server）
  - Android root 环境运行，抽象 Unix socket `localabstract:frida` 监听
  - 长度前缀 JSON 帧协议：ping / process_list / package_list
  - 部署脚本 `scripts/deploy-frida-server.ps1`（WSL 交叉编译 + 推送 + setenforce 0 + adb forward）
- Windows 反射式 DLL 注入（`process_inject_reflect`）
  - `WinReflectInjector` + `PeImage` 解析：PE32/PE32+ 头部、节区表、导入表、重定位表
  - 本地构建完整映射映像（重定位 + IAT 全部本地修正），目标进程仅需一次 `VirtualAllocEx + WriteProcessMemory`
  - 不调用 `LoadLibrary`、不注册到 PEB 模块链，对模块枚举 / GetModuleHandle 天然不可见
  - 依赖 DLL 基址取自目标进程模块表，函数 RVA 在注入器进程解析；x64 DllMain thunk
  - 局限：依赖 DLL 需已在目标进程；ordinal 导入项跳过；DllMain 不会自动调用
- 脚本引擎并发执行支持
  - 开启 Rhai `sync` 特性，`ScriptEngine` 支持跨线程传递（`Send + Sync`）
  - 新增线程安全句柄 `ScriptEngineHandle`（`Send + Clone`，互斥串行化）
  - 脚本侧 `log_info`/`log_warn` 写入执行结果日志
- MCP 脚本执行工具
  - `run_script` - 执行 Rhai 脚本（源码或文件路径，按 PID 缓存引擎）
  - `script_reset` - 重置脚本引擎
- Windows 字节搜索支持
  - 脚本引擎 `search_bytes` 落地 Windows 实现
  - `WinMemoryScanner` 分块滑动扫描，宽容处理并发读取
- 内存模式搜索通配符支持
  - `??` 匹配任意字节，支持 `"48 8B ?? 90"` 与 `"488B??90"` 两种格式
  - `memory_search` MCP 工具接入通配符模式解析
- MCP `memory_regions` 工具 - 列出目标进程内存区域（地址范围/权限/大小）
- 内存模式搜索支持 `limit` 上限
  - `memory_search` 新增 `limit` 参数（默认 100），达到上限后提前终止扫描
- Windows 反调试检测补全
  - `stealth_analyze` 落地 PEB BeingDebugged / NtGlobalFlag / 调试寄存器 Dr0-Dr7 真实检测
- 内存模式搜索支持范围过滤
  - `memory_search` 新增 `start`/`end` 地址范围参数，仅在指定区间内扫描
  - 匹配结果附带地址上下文（前 16 字节 hex + ASCII）
- MCP `module_info` 工具 - 查询目标进程模块基址与大小
- `hook_set` 增强
  - 支持 `offset` 参数（模块内偏移 hook）
  - 返回 Hook id 便于后续管理
- MCP 进程控制工具
  - `process_suspend` - 暂停目标进程（Unix SIGSTOP / Windows NtSuspendProcess）
  - `process_resume` - 恢复已暂停进程（SIGCONT / NtResumeProcess）
  - `process_kill` - 终止目标进程（SIGKILL / TerminateProcess）
- MCP 内存字符串工具
  - `memory_search_text` - 按文本字符串搜索内存（支持 UTF-16LE 宽字符，wide=true）
  - `memory_read_string` - 读取内存字符串（utf8/ascii/utf16 编码）
- `process_info` 增强 - 输出状态、父进程 PID、UID、命令行
- `memory_dump` 支持 `module` 参数 - 从模块基址开始 dump
- MCP Hook 管理工具
  - `hook_uninstall` - 按 Hook id 卸载
  - `hook_list` - 列出已注册 Hook（id/状态/目标）
- `memory_write` / `memory_disasm` 支持 `module` + `offset` 参数 - 从模块基址+偏移定位
- `memory_search` / `memory_search_text` 支持 `module` 参数 - 限定在指定模块内搜索
- `memory_read` 支持 `module` + `offset` 参数 - 从模块基址+偏移读取
- `run_script` 支持 `timeout` 参数 - 默认 30 秒，防止脚本长时间占用 MCP 调用
- `memory_search` 结果按地址排序输出
- `symbols_find` 支持名称部分匹配（Windows）
- 脚本宿主函数新增 `read_string` / `write_string` - 脚本内读写字符串（支持跨进程）
- MCP 进程工具
  - `process_list` - 列出系统所有进程（PID/名称/状态）
  - `process_find` - 按名称/命令行查找进程
- `memory_regions` 支持 `perm` 权限过滤
  - 新增 `perm` 参数（如 `rwx`/`r`/`x`），缺省列出全部区域
  - 按读/写/执行位精确过滤并输出统计
- `memory_dump` 支持 `to_hex` 参数
  - `to_hex=true` 时直接输出 hex dump 文本而非写入文件
- 内存分配与管理工具
  - `memory_alloc` - 在目标进程分配内存（可选可执行权限）
  - `memory_free` - 释放 `memory_alloc` 分配的内存（跨调用注册表跟踪）
  - `memory_protect` - 修改内存页保护属性（`rwx` 组合映射 `PAGE_*`/`PROT_*`）
  - `memory_write_string` - 写入字符串（utf8/ascii/utf16，可选结束符）
- `WinRemoteAllocator` 新增 `protect_perms` - 按权限字符串修改远程内存保护
- `RemoteAllocator` 新增 `free_remote` - 按地址+大小直接释放（跨调用场景）
- `memory_search_value` 数值扫描工具
  - 支持 u8/i8/u16/i16/u32/i32/u64/i64/f32/f64 类型
  - 支持十进制与 `0x` 十六进制、可选对齐字节、模块/范围/上限过滤
- `module_list` 工具 - 列出目标进程所有模块（名称/基址/大小/路径）
- `process_memory_stats` 工具 - 进程内存统计（虚拟/常驻/私有/峰值）
  - Windows: `GetProcessMemoryInfo`（WorkingSet/Pagefile/Private/Peak）
  - Unix: 解析 `/proc/pid/status`（VmSize/VmRSS/VmData/VmStk/VmHWM）
- 新增 `MemoryStats` 公共类型
- 反检测增强（Windows）
  - `stealth_apply` 支持跨进程清理目标 PEB（BeingDebugged / NtGlobalFlag / 堆标志），pid=0 表示自身
  - `stealth_apply` 的 auto_detect 在 Windows 落地"分析→应用"闭环
  - `stealth_analyze` 新增 DebugPort / DebugObjectHandle / 堆标志 / 时间差 / 父进程链检测
  - `stealth_analyze` 跨进程模式支持只读 DebugPort / DebugObjectHandle / 父进程链查询（最小权限 PROCESS_QUERY_INFORMATION）
- 注入即隐身
  - `WinInjector::inject_library_hidden` - 注入 DLL 后自动从目标进程 PEB Ldr 链摘除
  - `process_inject` 新增 `hide` 参数（Windows），`hide=true` 时注入完成后立即隐藏模块
  - `inject_library` 现在返回远程线程退出码校验，LoadLibraryA 失败（基址 0）会明确报错
- `stealth_apply` 修正（Unix）- 目标进程非自身时改为只读分析输出，避免误对自身进程应用清理
- MCP `module_hide` 工具 - 从目标进程 PEB Ldr 链摘除模块（Windows）
  - 支持模块名（大小写不敏感/子串）或 `0x` 基址定位
  - 摘除 InMemoryOrderModuleList 后对模块枚举 / GetModuleHandle 不可见，保留 InLoadOrder 链以便正常卸载
  - 复用跨进程 PEB 读写基础设施（PROCESS_QUERY_INFORMATION | VM_READ | VM_WRITE）
- 反检测增强（Unix）
  - `stealth_analyze` 新增目标进程级分析：解析 `/proc/pid/status`（State/TracerPid/Seccomp/NoNewPrivs/PPid）
  - 报告父进程名称与 `LD_PRELOAD`/`LD_LIBRARY_PATH`/`LD_AUDIT`/`LD_DEBUG` 加载器注入痕迹
  - TracerPid 非 0、Seccomp filter、no_new_privs、预加载变量均带风险提示
  - `WinStealthManager` 新增 `read_remote_peb` / `apply_to_process` / `check_debug_port` 等 API
  - 自声明 `NtQueryInformationProcess`（winapi 0.3.9 无 winternl 模块）
  - README/stealth_info 反作弊表述改为诚实说明（不承诺绕过商业反作弊）

### Fixed
- MCP `memory_write` 在 Windows 下未实际写入的问题
- `WinMemoryScanner` 在并发堆操作下 `ReadProcessMemory` 部分失败导致漏检

## [0.35.0] - 2026-07-12

### Added
- AI 全面自我学习系统
  - 自动经验收集 - 每次操作自动记录
  - 智能反馈循环 - 遇到问题自动分析原因
  - 策略迭代优化 - 根据成功率自动调整策略
  - 知识图谱构建 - 反作弊特征关系图
- 执行日志与 HTML 报告模块
  - 日志记录 - 记录 AI 每一步操作的日志与统计（内存聚合）
  - 步骤记录 - 展示 AI 执行流程与耗时
  - 学习统计 - 显示成功率和统计
  - HTML 报告生成 - 将日志/步骤渲染为静态 HTML 报告（无内置 HTTP 服务）
- PE 解析器 (Windows)
  - 导出表解析
  - 符号查询支持
- 完整 Windows 支持
  - 内存读写搜索
  - 进程信息查询
  - 反调试分析
- 工程化配置
  - GitHub Actions CI/CD
  - rustfmt.toml 代码格式化
  - clippy.toml 代码检查
  - MIT LICENSE

### Changed
- 简化 MCP 工具为树状结构 (20个)
- 优化错误处理
- 清理 warnings

## [0.3.0] - 2026-07-12

### Added
- 树状结构 MCP 工具设计
- 14个核心工具

### Changed
- 工具从 36个 简化为 14个
- 参数总数从 ~80个 减少到 ~35个

## [0.2.0] - 2026-07-12

### Added
- 国内反作弊支持
  - 腾讯 ACE/TP/MTP
  - 米哈游 Protect
  - 网易 UProtect/Yidun
- ESP 绘制分析
  - 游戏引擎检测
  - 数据结构分析
  - 偏移量查找
  - 代码生成

## [0.1.0] - 2026-07-11

### Added
- 初始版本
- 基础 Frida 功能实现
- Inline Hook / GOT-PLT Hook / Java Hook
- ptrace 注入 / 反射注入
- 内存扫描 / ELF 解析
- Rhai 脚本引擎
- 基础反检测功能
- MCP 服务器基础功能
