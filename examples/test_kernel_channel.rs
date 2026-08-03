// 独立测试程序：验证与 nova_stealth 内核模块的 Netlink 通信
// 协议: NETLINK_FIREWALL (3)
// 用法: test_kernel_channel [ping|version|status]

// 注意：该示例仅支持 Linux 平台（依赖 AF_NETLINK socket）。
#[cfg(unix)]
use std::os::unix::io::RawFd;

#[cfg(unix)]
const NLMSG_HDRLEN: usize = 16;
#[cfg(unix)]
const NOVA_NETLINK_PROTO: i32 = 3; // NETLINK_FIREWALL
#[cfg(unix)]
const NOVA_CMD_PING: u32 = 11;
#[cfg(unix)]
const NOVA_CMD_VERSION: u32 = 12;
#[cfg(unix)]
const NOVA_CMD_GET_STATUS: u32 = 16;

#[cfg(unix)]
#[repr(C)]
struct NlMsgHdr {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
}

#[cfg(unix)]
#[repr(C)]
struct NovaRequest {
    cmd: u32,
    seq: u32,
    target_pid: u32,
    data_len: u32,
}

#[cfg(unix)]
#[repr(C)]
struct NovaResponse {
    seq: u32,
    result: i32,
    data_len: u32,
}

#[cfg(unix)]
#[repr(C)]
struct NovaStatus {
    version: u32,
    hidden_proc_count: u32,
    hooked_region_count: u32,
    netlink_packets_rx: u32,
    netlink_packets_tx: u32,
    mem_read_count: u32,
    mem_write_count: u32,
    inject_count: u32,
    errors: u32,
}

#[cfg(unix)]
const NOVA_REQUEST_HEADER_SIZE: usize = std::mem::size_of::<NovaRequest>();
#[cfg(unix)]
const NOVA_RESPONSE_HEADER_SIZE: usize = std::mem::size_of::<NovaResponse>();

#[cfg(unix)]
fn main() {
    let action = std::env::args().nth(1).unwrap_or_else(|| "ping".to_string());
    let cmd = match action.as_str() {
        "ping" => NOVA_CMD_PING,
        "version" => NOVA_CMD_VERSION,
        "status" => NOVA_CMD_GET_STATUS,
        _ => {
            eprintln!("用法: test_kernel_channel [ping|version|status]");
            std::process::exit(1);
        }
    };

    // 创建 Netlink socket
    let fd: RawFd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM, NOVA_NETLINK_PROTO) };
    if fd < 0 {
        eprintln!("✗ socket(AF_NETLINK, SOCK_DGRAM, {}) 失败", NOVA_NETLINK_PROTO);
        std::process::exit(1);
    }
    println!("✓ socket(AF_NETLINK, SOCK_DGRAM, {}) OK, fd={}", NOVA_NETLINK_PROTO, fd);

    // bind
    let mut src: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    src.nl_family = libc::AF_NETLINK as u16;
    src.nl_pid = 0;
    src.nl_groups = 0;
    let ret = unsafe {
        libc::bind(
            fd,
            &src as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        eprintln!("✗ bind 失败");
        unsafe { libc::close(fd); }
        std::process::exit(1);
    }
    println!("✓ bind OK");

    // 设置接收超时 5 秒
    let timeout = libc::timeval { tv_sec: 5, tv_usec: 0 };
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &timeout as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }

    let my_pid = unsafe { libc::getpid() } as u32;
    let seq: u32 = 1;
    println!("发送 {} 请求 (seq={}, pid={})", action, seq, my_pid);

    // 构造并发送请求
    let total = NLMSG_HDRLEN + NOVA_REQUEST_HEADER_SIZE;
    let mut buf = vec![0u8; total];
    unsafe {
        let nlh = buf.as_mut_ptr() as *mut NlMsgHdr;
        (*nlh).nlmsg_len = total as u32;
        (*nlh).nlmsg_type = 0;
        (*nlh).nlmsg_flags = 0;
        (*nlh).nlmsg_seq = seq;
        (*nlh).nlmsg_pid = my_pid;

        let req = (buf.as_mut_ptr().add(NLMSG_HDRLEN)) as *mut NovaRequest;
        (*req).cmd = cmd;
        (*req).seq = seq;
        (*req).target_pid = 0;
        (*req).data_len = 0;
    }

    let mut dest: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    dest.nl_family = libc::AF_NETLINK as u16;
    dest.nl_pid = 0;
    dest.nl_groups = 0;

    let len = unsafe {
        libc::sendto(
            fd,
            buf.as_ptr() as *const libc::c_void,
            total,
            0,
            &dest as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if len < 0 {
        eprintln!("✗ sendto 失败");
        unsafe { libc::close(fd); }
        std::process::exit(1);
    }
    println!("✓ sendto OK");

    // 接收响应
    let mut recv_buf = vec![0u8; 4096];
    let len = unsafe {
        libc::recvfrom(
            fd,
            recv_buf.as_mut_ptr() as *mut libc::c_void,
            recv_buf.len(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if len < 0 {
        eprintln!("✗ {} 测试失败 (recvfrom 超时或错误)", action);
        unsafe { libc::close(fd); }
        std::process::exit(1);
    }

    if (len as usize) < NLMSG_HDRLEN + NOVA_RESPONSE_HEADER_SIZE {
        eprintln!("✗ 响应过短: {}", len);
        unsafe { libc::close(fd); }
        std::process::exit(1);
    }

    unsafe {
        let resp = (recv_buf.as_ptr().add(NLMSG_HDRLEN)) as *const NovaResponse;
        println!("收到响应: seq={} result={} data_len={}", (*resp).seq, (*resp).result, (*resp).data_len);

        if (*resp).seq != seq {
            eprintln!("✗ seq 不匹配");
            unsafe { libc::close(fd); }
            std::process::exit(1);
        }
        if (*resp).result != 0 {
            eprintln!("✗ 内核返回错误: {}", (*resp).result);
            unsafe { libc::close(fd); }
            std::process::exit(1);
        }

        let data_len = (*resp).data_len as usize;
        if data_len > 0 {
            let data_start = NLMSG_HDRLEN + NOVA_RESPONSE_HEADER_SIZE;
            println!("响应数据 ({} 字节):", data_len);
            if data_len >= std::mem::size_of::<NovaStatus>() {
                let st = (recv_buf.as_ptr().add(data_start)) as *const NovaStatus;
                println!("  version:           {}", (*st).version);
                println!("  hidden_proc_count: {}", (*st).hidden_proc_count);
                println!("  hooked_region:     {}", (*st).hooked_region_count);
                println!("  nl_pkts_rx:        {}", (*st).netlink_packets_rx);
                println!("  nl_pkts_tx:        {}", (*st).netlink_packets_tx);
                println!("  mem_read:          {}", (*st).mem_read_count);
                println!("  mem_write:         {}", (*st).mem_write_count);
                println!("  inject:            {}", (*st).inject_count);
                println!("  errors:            {}", (*st).errors);
            } else if data_len == 4 {
                let ver = u32::from_le_bytes([
                    recv_buf[data_start],
                    recv_buf[data_start + 1],
                    recv_buf[data_start + 2],
                    recv_buf[data_start + 3],
                ]);
                println!("  version: {}", ver);
            }
        }
    }

    println!("\n✓ {} 测试成功", action);
    unsafe { libc::close(fd); }
}

#[cfg(not(unix))]
fn main() {
    eprintln!("错误：test_kernel_channel 仅支持 Linux（依赖 netlink 内核模块）");
    std::process::exit(1);
}
