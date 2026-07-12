//! 跨平台系统调用包装
//! Android Bionic 缺少 process_vm_readv/writev 的 C 包装，需要直接 syscall

use libc::{c_ulong, iovec, pid_t, ssize_t};

/// Android AArch64 syscall 编号
#[cfg(all(target_os = "android", target_arch = "aarch64"))]
const SYS_PROCESS_VM_READV: libc::c_long = 270;
#[cfg(all(target_os = "android", target_arch = "aarch64"))]
const SYS_PROCESS_VM_WRITEV: libc::c_long = 271;

/// Linux 上直接使用 libc 包装
#[cfg(not(target_os = "android"))]
pub unsafe fn process_vm_readv(
    pid: pid_t,
    local_iov: *const iovec,
    liovcnt: c_ulong,
    remote_iov: *const iovec,
    riovcnt: c_ulong,
    flags: c_ulong,
) -> ssize_t {
    libc::process_vm_readv(pid, local_iov, liovcnt, remote_iov, riovcnt, flags)
}

/// Android 上通过 syscall 直接调用
#[cfg(target_os = "android")]
pub unsafe fn process_vm_readv(
    pid: pid_t,
    local_iov: *const iovec,
    liovcnt: c_ulong,
    remote_iov: *const iovec,
    riovcnt: c_ulong,
    flags: c_ulong,
) -> ssize_t {
    libc::syscall(
        SYS_PROCESS_VM_READV,
        pid,
        local_iov,
        liovcnt,
        remote_iov,
        riovcnt,
        flags,
    ) as ssize_t
}

/// Linux 上直接使用 libc 包装
#[cfg(not(target_os = "android"))]
pub unsafe fn process_vm_writev(
    pid: pid_t,
    local_iov: *const iovec,
    liovcnt: c_ulong,
    remote_iov: *const iovec,
    riovcnt: c_ulong,
    flags: c_ulong,
) -> ssize_t {
    libc::process_vm_writev(pid, local_iov, liovcnt, remote_iov, riovcnt, flags)
}

/// Android 上通过 syscall 直接调用
#[cfg(target_os = "android")]
pub unsafe fn process_vm_writev(
    pid: pid_t,
    local_iov: *const iovec,
    liovcnt: c_ulong,
    remote_iov: *const iovec,
    riovcnt: c_ulong,
    flags: c_ulong,
) -> ssize_t {
    libc::syscall(
        SYS_PROCESS_VM_WRITEV,
        pid,
        local_iov,
        liovcnt,
        remote_iov,
        riovcnt,
        flags,
    ) as ssize_t
}
