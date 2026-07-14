use libc::{c_int, c_long, c_void, pid_t, PTRACE_ATTACH, PTRACE_CONT, PTRACE_DETACH, PTRACE_GETREGS, PTRACE_POKEDATA, PTRACE_SETREGS};
use std::env;
use std::ffi::CString;
use std::process;

const PTRACE_ATTACH_VAL: c_int = 16;
const PTRACE_CONT_VAL: c_int = 7;
const PTRACE_DETACH_VAL: c_int = 17;
const PTRACE_GETREGS_VAL: c_int = 12;
const PTRACE_SETREGS_VAL: c_int = 13;
const PTRACE_POKEDATA_VAL: c_int = 5;

#[repr(C)]
struct user_regs_struct {
    regs: [u64; 31],
    sp: u64,
    pc: u64,
    pstate: u64,
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <pid> <libpath>", args[0]);
        process::exit(1);
    }

    let pid: pid_t = match args[1].parse() {
        Ok(p) => p,
        Err(_) => {
            eprintln!("Invalid PID");
            process::exit(1);
        }
    };

    let lib_path = CString::new(args[2].as_str()).unwrap();

    println!("Simple Injector");
    println!("Target PID: {}", pid);
    println!("Library: {}", args[2]);

    unsafe {
        if ptrace(PTRACE_ATTACH_VAL, pid, std::ptr::null_mut(), std::ptr::null_mut()) != 0 {
            eprintln!("ptrace attach failed");
            process::exit(1);
        }
        println!("✓ ptrace attach OK");

        let mut status: i32 = 0;
        while waitpid(pid, &mut status, 0) == -1 {}
        println!("✓ process stopped");

        let mut regs: user_regs_struct = std::mem::zeroed();
        if ptrace(PTRACE_GETREGS_VAL, pid, std::ptr::null_mut(), &mut regs as *mut _ as *mut c_void) != 0 {
            eprintln!("ptrace getregs failed");
            ptrace(PTRACE_DETACH_VAL, pid, std::ptr::null_mut(), std::ptr::null_mut());
            process::exit(1);
        }
        println!("✓ got registers");

        let dlopen_addr = find_dlopen(pid);
        if dlopen_addr == 0 {
            eprintln!("Could not find dlopen");
            ptrace(PTRACE_DETACH_VAL, pid, std::ptr::null_mut(), std::ptr::null_mut());
            process::exit(1);
        }
        println!("✓ found dlopen at 0x{:x}", dlopen_addr);

        let remote_path_addr = alloc_remote(pid, lib_path.as_bytes().len() + 1);
        if remote_path_addr == 0 {
            eprintln!("Failed to allocate remote memory");
            ptrace(PTRACE_DETACH_VAL, pid, std::ptr::null_mut(), std::ptr::null_mut());
            process::exit(1);
        }
        println!("✓ allocated remote memory at 0x{:x}", remote_path_addr);

        write_remote(pid, remote_path_addr, lib_path.as_bytes());
        println!("✓ wrote library path");

        regs.regs[0] = remote_path_addr;
        regs.regs[1] = 1;
        regs.pc = dlopen_addr;

        if ptrace(PTRACE_SETREGS_VAL, pid, std::ptr::null_mut(), &mut regs as *mut _ as *mut c_void) != 0 {
            eprintln!("ptrace setregs failed");
            ptrace(PTRACE_DETACH_VAL, pid, std::ptr::null_mut(), std::ptr::null_mut());
            process::exit(1);
        }
        println!("✓ set registers");

        if ptrace(PTRACE_CONT_VAL, pid, std::ptr::null_mut(), std::ptr::null_mut()) != 0 {
            eprintln!("ptrace cont failed");
            ptrace(PTRACE_DETACH_VAL, pid, std::ptr::null_mut(), std::ptr::null_mut());
            process::exit(1);
        }

        std::thread::sleep(std::time::Duration::from_millis(500));

        if ptrace(PTRACE_DETACH_VAL, pid, std::ptr::null_mut(), std::ptr::null_mut()) != 0 {
            eprintln!("ptrace detach failed");
            process::exit(1);
        }
        println!("✓ detached");
    }

    println!("✓ Injection completed!");
}

unsafe fn find_dlopen(pid: pid_t) -> u64 {
    let maps_path = format!("/proc/{}/maps", pid);
    let maps_cstr = CString::new(maps_path).unwrap();
    
    let fd = libc::open(maps_cstr.as_ptr(), libc::O_RDONLY);
    if fd == -1 {
        return 0;
    }

    let mut buf = [0u8; 8192];
    let n = libc::read(fd, buf.as_mut_ptr() as *mut c_void, buf.len());
    libc::close(fd);

    if n <= 0 {
        return 0;
    }

    let maps_str = String::from_utf8_lossy(&buf[..n as usize]);
    for line in maps_str.lines() {
        if line.contains("libdl.so") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if !parts.is_empty() {
                let range: Vec<&str> = parts[0].split('-').collect();
                if range.len() >= 2 {
                    let start = u64::from_str_radix(range[0], 16).unwrap_or(0);
                    return start + 0x1000;
                }
            }
        }
    }

    0
}

unsafe fn alloc_remote(pid: pid_t, size: usize) -> u64 {
    let shmem_name = format!("/dev/shm/shmem_{}", pid);
    let shmem_cstr = CString::new(shmem_name).unwrap();
    
    let fd = libc::open(
        shmem_cstr.as_ptr(),
        libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
        0o644
    );
    if fd == -1 {
        return 0;
    }

    libc::ftruncate(fd, size as i64);
    let addr = libc::mmap(
        std::ptr::null_mut(),
        size,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_SHARED,
        fd,
        0
    );

    libc::close(fd);
    addr as u64
}

unsafe fn write_remote(pid: pid_t, addr: u64, data: &[u8]) {
    for (i, &byte) in data.iter().enumerate() {
        ptrace(PTRACE_POKEDATA_VAL, pid, (addr + i as u64) as *mut c_void, byte as *mut c_void);
    }
    ptrace(PTRACE_POKEDATA_VAL, pid, (addr + data.len() as u64) as *mut c_void, 0u64 as *mut c_void);
}

#[link(name = "c")]
extern "C" {
    fn ptrace(request: c_int, pid: pid_t, addr: *mut c_void, data: *mut c_void) -> c_long;
    fn waitpid(pid: pid_t, status: *mut i32, options: c_int) -> pid_t;
}