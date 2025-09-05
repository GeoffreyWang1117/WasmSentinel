package threat.detection

# 默认规则
default allow = false
default threat_level = 0

# 进程威胁检测
threat_level = 8 {
    input.type == "process"
    dangerous_command
}

threat_level = 6 {
    input.type == "process"
    suspicious_shell
}

threat_level = 5 {
    input.type == "process"
    network_tool
}

# 网络威胁检测
threat_level = 7 {
    input.type == "network"
    suspicious_port
}

threat_level = 6 {
    input.type == "network"
    external_connection
}

# 文件威胁检测
threat_level = 9 {
    input.type == "file"
    sensitive_file_access
}

# 规则定义

dangerous_command {
    input.data.process.command_line
    commands := [
        "rm -rf /",
        "mkfs",
        "dd if=/dev/zero",
        ":(){ :|:& };:",  # fork bomb
        "curl | sh",
        "wget | sh"
    ]
    some command in commands
    contains(input.data.process.command_line, command)
}

suspicious_shell {
    input.data.process.name in ["bash", "sh", "zsh", "dash"]
    suspicious_patterns := [
        "base64",
        "eval",
        "exec",
        "/dev/tcp/",
        "nohup",
        "& disown"
    ]
    some pattern in suspicious_patterns
    contains(input.data.process.command_line, pattern)
}

network_tool {
    input.data.process.name in [
        "nc", "netcat", "ncat", "socat",
        "wget", "curl", "ftp", "tftp",
        "ssh", "scp", "rsync"
    ]
}

suspicious_port {
    input.data.network.dest_port in [
        22, 23, 135, 139, 445, 3389,  # 常见服务端口
        1234, 4444, 5555, 6666, 7777, 8888, 9999  # 常见后门端口
    ]
}

external_connection {
    input.data.network.direction == "outbound"
    not private_ip(input.data.network.dest_ip)
}

sensitive_file_access {
    sensitive_paths := [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/root/.ssh/",
        "/home/*/.ssh/",
        "/var/log/auth.log",
        "/var/log/secure"
    ]
    some path in sensitive_paths
    startswith(input.data.file.path, path)
}

# 辅助函数

private_ip(ip) {
    net.cidr_contains("10.0.0.0/8", ip)
}

private_ip(ip) {
    net.cidr_contains("172.16.0.0/12", ip)
}

private_ip(ip) {
    net.cidr_contains("192.168.0.0/16", ip)
}

private_ip(ip) {
    ip == "127.0.0.1"
}
