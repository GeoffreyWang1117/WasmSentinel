use sentinel_abi::{EventFields, JsonEvent, RawEvent};
use serde_json::Value;

// ---------------------------------------------------------------------------
// Guest ABI v2: host-visible allocator.
//
// The host calls `alloc` once per rule instance to obtain an event buffer in
// linear memory, copies the serialized event into it and then calls
// `detect(ptr, len)`. The buffer is released with `dealloc` when the host grows
// it or drops the instance. Writing at a fixed offset (the pre-v2 behaviour)
// is no longer supported: it silently overlapped the shadow stack.
// ---------------------------------------------------------------------------

/// Allocate `size` bytes in linear memory and hand ownership to the host.
#[no_mangle]
pub extern "C" fn alloc(size: usize) -> *mut u8 {
    let mut buf = Vec::<u8>::with_capacity(size);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

/// Release a buffer previously returned by [`alloc`] with the same `size`.
///
/// # Safety
/// `ptr` must come from `alloc(size)` and must not be used afterwards.
#[no_mangle]
pub unsafe extern "C" fn dealloc(ptr: *mut u8, size: usize) {
    if !ptr.is_null() && size > 0 {
        drop(Vec::from_raw_parts(ptr, 0, size));
    }
}

/// 检测函数 - 分析事件并返回威胁级别
///
/// # 参数
/// * `event_ptr` - 事件数据指针
/// * `event_len` - 事件数据长度
///
/// # 返回值
/// * 0 - 无威胁
/// * 1-10 - 威胁级别 (1=最低, 10=最高)
#[no_mangle]
pub extern "C" fn detect(event_ptr: *const u8, event_len: usize) -> i32 {
    // 安全地读取事件数据
    let event_data = unsafe {
        if event_ptr.is_null() || event_len == 0 {
            return 0;
        }
        std::slice::from_raw_parts(event_ptr, event_len)
    };

    // 解析 JSON 事件
    let event: Value = match serde_json::from_slice(event_data) {
        Ok(event) => event,
        Err(_) => return 0, // 解析失败，认为无威胁
    };
    detect_value(&event)
}

/// 二进制路径：宿主把内核事件记录（sentinel-abi 布局）直接写进线性内存，
/// 规则直接按字段读取记录，不解析 JSON、不重建 JSON 树。
#[no_mangle]
pub extern "C" fn detect_raw(payload_ptr: *const u8, payload_len: usize) -> i32 {
    if payload_ptr.is_null() || payload_len == 0 {
        return 0;
    }
    let bytes = unsafe { std::slice::from_raw_parts(payload_ptr, payload_len) };
    let payload = match sentinel_abi::parse(bytes) {
        Ok(p) => p,
        Err(_) => return 0,
    };
    detect_fields(&RawEvent(&payload))
}

/// JSON 路径与二进制路径共用的检测入口：两条路径只在字段访问层不同。
fn detect_value(event: &Value) -> i32 {
    detect_fields(&JsonEvent(event))
}

fn detect_fields<E: EventFields>(event: &E) -> i32 {
    match event.event_type() {
        "process" => detect_process_threat(event),
        "network" => detect_network_threat(event),
        "file" => detect_file_threat(event),
        _ => 0,
    }
}

/// 检测进程威胁
fn detect_process_threat<E: EventFields>(event: &E) -> i32 {
    let mut threat_level = 0;

    // 检查可执行文件路径
    if let Some(executable) = event.executable() {
        threat_level += check_suspicious_executable(executable);
    }

    // 检查进程名
    if let Some(name) = event.process_name() {
        threat_level += check_suspicious_process_name(name);
    }

    // 检查命令行参数
    if let Some(cmdline) = event.command_line() {
        threat_level += check_suspicious_cmdline(&cmdline);
    }

    // 检查用户
    if let Some(user) = event.user() {
        threat_level += check_suspicious_user(user);
    }

    // 检查事件动作
    if event.action() == Some("suspicious_activity") {
        threat_level += 3;
    }

    // 限制威胁级别在有效范围内
    if threat_level > 10 {
        threat_level = 10;
    }

    threat_level
}

/// 检测网络威胁
fn detect_network_threat<E: EventFields>(event: &E) -> i32 {
    let mut threat_level = 0;

    // 检查目标端口
    if let Some(dest_port) = event.dest_port() {
        threat_level += check_suspicious_port(dest_port as i32);
    }

    // 检查目标 IP
    if let Some(dest_ip) = event.dest_ip() {
        threat_level += check_suspicious_ip(&dest_ip);
    }

    // 检查协议
    if event.protocol() == Some("tcp") {
        threat_level += 1; // TCP 连接相对可疑
    }

    // 检查连接方向
    if event.direction() == Some("outbound") {
        threat_level += 2; // 出站连接更可疑
    }

    if threat_level > 10 {
        threat_level = 10;
    }

    threat_level
}

/// 检测文件威胁
fn detect_file_threat<E: EventFields>(event: &E) -> i32 {
    let mut threat_level = 0;

    // 检查文件路径
    if let Some(path) = event.file_path() {
        threat_level += check_suspicious_file_path(path);
    }

    // 检查操作类型
    if let Some(operation) = event.file_operation() {
        threat_level += check_suspicious_file_operation(operation);
    }

    if threat_level > 10 {
        threat_level = 10;
    }

    threat_level
}

/// 检查可疑的可执行文件
fn check_suspicious_executable(executable: &str) -> i32 {
    let suspicious_executables = [
        "/bin/sh",
        "/bin/bash",
        "/bin/zsh",
        "/bin/dash",
        "/usr/bin/python",
        "/usr/bin/perl",
        "/usr/bin/ruby",
        "/usr/bin/nc",
        "/usr/bin/netcat",
        "/usr/bin/ncat",
        "/usr/bin/socat",
        "/usr/bin/wget",
        "/usr/bin/curl",
        "/tmp/",
        "/var/tmp/",
    ];

    for suspicious in &suspicious_executables {
        if executable.contains(suspicious) {
            return match *suspicious {
                "/bin/sh" | "/bin/bash" => 6, // shell 高风险
                "/tmp/" | "/var/tmp/" => 8,   // 临时目录执行极高风险
                _ => 4,                       // 其他可疑程序中等风险
            };
        }
    }

    0
}

/// 检查可疑的进程名
fn check_suspicious_process_name(name: &str) -> i32 {
    let suspicious_names = [
        "sh", "bash", "zsh", "dash", "python", "perl", "ruby", "php", "nc", "netcat", "ncat",
        "socat", "wget", "curl", "ftp", "tftp", "ssh", "scp", "rsync",
    ];

    for suspicious in &suspicious_names {
        if name == *suspicious {
            return match *suspicious {
                "sh" | "bash" | "zsh" => 5,
                "nc" | "netcat" | "ncat" | "socat" => 7,
                _ => 3,
            };
        }
    }

    0
}

/// 检查可疑的命令行参数
fn check_suspicious_cmdline(cmdline: &str) -> i32 {
    let mut threat_level = 0;

    let suspicious_patterns = [
        ("-c", 4),        // shell 命令执行
        ("--help", -2),   // 帮助命令，降低威胁
        ("rm -rf", 8),    // 危险删除命令
        ("chmod +x", 6),  // 修改执行权限
        ("wget http", 5), // 下载文件
        ("curl http", 5), // 下载文件
        ("/dev/tcp/", 7), // 网络重定向
        ("base64", 4),    // 编码/解码
        ("eval", 6),      // 动态执行
        ("exec", 5),      // 程序执行
        ("nohup", 4),     // 后台执行
        ("&", 3),         // 后台进程
        ("|", 2),         // 管道操作
        (">>", 3),        // 重定向追加
    ];

    for (pattern, score) in &suspicious_patterns {
        if cmdline.contains(pattern) {
            threat_level += score;
        }
    }

    // 检查长命令行（可能是混淆攻击）
    if cmdline.len() > 200 {
        threat_level += 3;
    }

    // 检查多个命令分隔符
    let separators = [";", "&&", "||"];
    for sep in &separators {
        threat_level += cmdline.matches(sep).count() as i32;
    }

    threat_level
}

/// 检查可疑用户
fn check_suspicious_user(user: &str) -> i32 {
    match user {
        "root" => 3,     // root 用户操作需要关注
        "nobody" => 2,   // nobody 用户异常活动
        "www-data" => 2, // web 服务用户异常活动
        _ => {
            // 检查是否为数字 UID（可能是提权后的用户）
            if user.chars().all(char::is_numeric) {
                return 4;
            }
            0
        }
    }
}

/// 检查可疑端口
fn check_suspicious_port(port: i32) -> i32 {
    let high_risk_ports = [22, 23, 3389, 4444, 5555, 6666, 7777, 8888, 9999];
    let medium_risk_ports = [21, 25, 53, 80, 135, 139, 443, 445, 993, 995];

    if high_risk_ports.contains(&port) {
        return 6;
    }

    if medium_risk_ports.contains(&port) {
        return 3;
    }

    // 高端口可能是后门
    if port > 10000 && port < 65535 {
        return 2;
    }

    0
}

/// 检查可疑 IP 地址
fn check_suspicious_ip(ip: &str) -> i32 {
    // 检查是否为外部 IP（非私有地址）
    if !is_private_ip(ip) && ip != "127.0.0.1" && ip != "0.0.0.0" {
        return 4;
    }

    // 检查已知恶意 IP 范围（示例）
    let suspicious_ranges = [
        "10.0.0.",    // 某些内网扫描
        "192.168.1.", // 常见内网段
    ];

    for range in &suspicious_ranges {
        if ip.starts_with(range) {
            return 2;
        }
    }

    0
}

/// 检查是否为私有 IP
fn is_private_ip(ip: &str) -> bool {
    ip.starts_with("10.")
        || ip.starts_with("192.168.")
        || ip.starts_with("172.16.")
        || ip.starts_with("172.17.")
        || ip.starts_with("172.18.")
        || ip.starts_with("172.19.")
        || ip.starts_with("172.20.")
        || ip.starts_with("172.21.")
        || ip.starts_with("172.22.")
        || ip.starts_with("172.23.")
        || ip.starts_with("172.24.")
        || ip.starts_with("172.25.")
        || ip.starts_with("172.26.")
        || ip.starts_with("172.27.")
        || ip.starts_with("172.28.")
        || ip.starts_with("172.29.")
        || ip.starts_with("172.30.")
        || ip.starts_with("172.31.")
}

/// 检查可疑文件路径
fn check_suspicious_file_path(path: &str) -> i32 {
    let suspicious_paths = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/root/",
        "/tmp/",
        "/var/tmp/",
        "/dev/shm/",
        "/.ssh/",
        "/home/*/.ssh/",
    ];

    for suspicious in &suspicious_paths {
        if path.contains(suspicious) {
            return match *suspicious {
                "/etc/passwd" | "/etc/shadow" => 8,
                "/etc/sudoers" => 9,
                "/root/" => 7,
                "/.ssh/" => 6,
                _ => 4,
            };
        }
    }

    // 检查隐藏文件
    if path.contains("/.") {
        return 2;
    }

    0
}

/// 检查可疑文件操作
fn check_suspicious_file_operation(operation: &str) -> i32 {
    match operation {
        "write" | "create" => 3,
        "delete" | "unlink" => 5,
        "chmod" | "chown" => 4,
        "rename" | "move" => 2,
        _ => 0,
    }
}

#[cfg(test)]
mod raw_parity_tests {
    use super::*;
    use sentinel_abi::{encode, RawRecord, EVENT_FILE_OPEN, EVENT_PROCESS_EXEC};

    fn put(dst: &mut [u8], s: &[u8]) -> u32 {
        dst[..s.len()].copy_from_slice(s);
        s.len() as u32
    }

    #[test]
    fn raw_and_json_paths_agree() {
        let mut r = RawRecord::default();
        r.event_type = EVENT_PROCESS_EXEC;
        r.pid = 7;
        put(&mut r.comm, b"bash");
        put(&mut r.filename, b"/usr/bin/bash");
        r.args_len = put(&mut r.args, b"bash\0-c\0rm -rf /tmp/x\0");
        let payload = encode(&r, "root", "root", "");
        let value = sentinel_abi::to_value(&sentinel_abi::parse(&payload).unwrap());
        let json = serde_json::to_vec(&value).unwrap();

        let via_json = detect(json.as_ptr(), json.len());
        let via_raw = detect_raw(payload.as_ptr(), payload.len());
        assert_eq!(via_json, via_raw);
        assert_eq!(via_raw, 10, "bash -c rm -rf as root saturates the score");

        let mut r = RawRecord::default();
        r.event_type = EVENT_FILE_OPEN;
        put(&mut r.filename, b"/etc/shadow");
        r.flags = 0x1; // O_WRONLY -> "write"
        let payload = encode(&r, "alice", "alice", "");
        let value = sentinel_abi::to_value(&sentinel_abi::parse(&payload).unwrap());
        let json = serde_json::to_vec(&value).unwrap();
        assert_eq!(
            detect(json.as_ptr(), json.len()),
            detect_raw(payload.as_ptr(), payload.len())
        );
        assert!(detect_raw(payload.as_ptr(), payload.len()) > 0);

        let mut r = RawRecord::default();
        r.event_type = sentinel_abi::EVENT_NETWORK_CONNECT;
        put(&mut r.comm, b"nc");
        r.family = 2;
        r.daddr = 0x0101a8c0;
        r.dport = 4444;
        let payload = encode(&r, "", "", "");
        let value = sentinel_abi::to_value(&sentinel_abi::parse(&payload).unwrap());
        let json = serde_json::to_vec(&value).unwrap();
        assert_eq!(
            detect(json.as_ptr(), json.len()),
            detect_raw(payload.as_ptr(), payload.len())
        );
    }
}
