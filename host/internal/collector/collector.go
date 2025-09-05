package collector

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/wasm-threat-detector/host/internal/events"
)

// Collector 事件收集器接口
type Collector interface {
	Start(ctx context.Context) error
	Stop() error
	EventChannel() <-chan *events.Event
}

// ProcessCollector 进程事件收集器
type ProcessCollector struct {
	logger    *logrus.Logger
	eventChan chan *events.Event
	done      chan struct{}
}

// NewProcessCollector 创建新的进程收集器
func NewProcessCollector(logger *logrus.Logger) *ProcessCollector {
	return &ProcessCollector{
		logger:    logger,
		eventChan: make(chan *events.Event, 1000),
		done:      make(chan struct{}),
	}
}

// Start 启动进程监控
func (pc *ProcessCollector) Start(ctx context.Context) error {
	pc.logger.Info("Starting process collector")

	go pc.monitorProcesses(ctx)
	go pc.monitorSystemCalls(ctx)

	return nil
}

// Stop 停止收集器
func (pc *ProcessCollector) Stop() error {
	pc.logger.Info("Stopping process collector")
	close(pc.done)
	close(pc.eventChan)
	return nil
}

// EventChannel 返回事件通道
func (pc *ProcessCollector) EventChannel() <-chan *events.Event {
	return pc.eventChan
}

// monitorProcesses 监控进程创建/退出
func (pc *ProcessCollector) monitorProcesses(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	lastProcesses := make(map[int32]bool)

	for {
		select {
		case <-ctx.Done():
			return
		case <-pc.done:
			return
		case <-ticker.C:
			currentProcesses := pc.getCurrentProcesses()

			// 检测新进程
			for pid := range currentProcesses {
				if !lastProcesses[pid] {
					if proc := pc.getProcessInfo(pid); proc != nil {
						event := &events.Event{
							ID:        fmt.Sprintf("proc_%d_%d", pid, time.Now().Unix()),
							Type:      events.EventTypeProcess,
							Timestamp: time.Now(),
							Source:    "process_collector",
							Data: map[string]interface{}{
								"action":  "create",
								"process": proc,
							},
						}

						select {
						case pc.eventChan <- event:
						default:
							pc.logger.Warn("Event channel full, dropping process event")
						}
					}
				}
			}

			lastProcesses = currentProcesses
		}
	}
}

// monitorSystemCalls 监控系统调用（简化版，实际应使用 eBPF）
func (pc *ProcessCollector) monitorSystemCalls(ctx context.Context) {
	// 这里是一个简化的实现，实际生产环境应该使用 eBPF
	// 监控可疑的系统调用模式

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-pc.done:
			return
		case <-ticker.C:
			// 检查当前运行的可疑进程
			pc.checkSuspiciousProcesses()
		}
	}
}

// getCurrentProcesses 获取当前所有进程
func (pc *ProcessCollector) getCurrentProcesses() map[int32]bool {
	processes := make(map[int32]bool)

	cmd := exec.Command("ps", "-eo", "pid")
	output, err := cmd.Output()
	if err != nil {
		pc.logger.Warnf("Failed to get process list: %v", err)
		return processes
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	scanner.Scan() // 跳过标题行

	for scanner.Scan() {
		pidStr := strings.TrimSpace(scanner.Text())
		if pid, err := strconv.ParseInt(pidStr, 10, 32); err == nil {
			processes[int32(pid)] = true
		}
	}

	return processes
}

// getProcessInfo 获取进程详细信息
func (pc *ProcessCollector) getProcessInfo(pid int32) *events.ProcessInfo {
	// 读取 /proc/{pid}/stat 获取进程信息
	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	statData, err := os.ReadFile(statPath)
	if err != nil {
		return nil
	}

	fields := strings.Fields(string(statData))
	if len(fields) < 4 {
		return nil
	}

	// 获取可执行文件路径
	exePath := fmt.Sprintf("/proc/%d/exe", pid)
	executable, _ := os.Readlink(exePath)

	// 获取命令行
	cmdlinePath := fmt.Sprintf("/proc/%d/cmdline", pid)
	cmdlineData, err := os.ReadFile(cmdlinePath)
	var commandLine string
	if err == nil {
		commandLine = strings.ReplaceAll(string(cmdlineData), "\x00", " ")
		commandLine = strings.TrimSpace(commandLine)
	}

	// 解析 PPID
	ppid, _ := strconv.ParseInt(fields[3], 10, 32)

	// 获取进程名（从 stat 文件中提取）
	name := fields[1]
	if len(name) > 2 && name[0] == '(' && name[len(name)-1] == ')' {
		name = name[1 : len(name)-1]
	}

	return &events.ProcessInfo{
		PID:         pid,
		PPID:        int32(ppid),
		Name:        name,
		Executable:  executable,
		CommandLine: commandLine,
		User:        pc.getProcessUser(pid),
		Group:       pc.getProcessGroup(pid),
	}
}

// getProcessUser 获取进程用户
func (pc *ProcessCollector) getProcessUser(pid int32) string {
	statusPath := fmt.Sprintf("/proc/%d/status", pid)
	statusData, err := os.ReadFile(statusPath)
	if err != nil {
		return "unknown"
	}

	lines := strings.Split(string(statusData), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) > 1 {
				return fields[1] // 返回 real UID
			}
		}
	}

	return "unknown"
}

// getProcessGroup 获取进程组
func (pc *ProcessCollector) getProcessGroup(pid int32) string {
	statusPath := fmt.Sprintf("/proc/%d/status", pid)
	statusData, err := os.ReadFile(statusPath)
	if err != nil {
		return "unknown"
	}

	lines := strings.Split(string(statusData), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "Gid:") {
			fields := strings.Fields(line)
			if len(fields) > 1 {
				return fields[1] // 返回 real GID
			}
		}
	}

	return "unknown"
}

// checkSuspiciousProcesses 检查可疑进程活动
func (pc *ProcessCollector) checkSuspiciousProcesses() {
	// 检查常见的可疑进程
	suspiciousPatterns := []string{
		"/bin/sh",
		"/bin/bash",
		"/bin/zsh",
		"nc",
		"netcat",
		"ncat",
		"socat",
		"python",
		"perl",
		"ruby",
		"wget",
		"curl",
	}

	cmd := exec.Command("ps", "-eo", "pid,comm,args")
	output, err := cmd.Output()
	if err != nil {
		pc.logger.Warnf("Failed to get process list for suspicious check: %v", err)
		return
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	scanner.Scan() // 跳过标题行

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		pidStr := fields[0]
		pid, err := strconv.ParseInt(pidStr, 10, 32)
		if err != nil {
			continue
		}

		comm := fields[1]
		args := strings.Join(fields[2:], " ")

		// 检查是否匹配可疑模式
		for _, pattern := range suspiciousPatterns {
			if strings.Contains(comm, pattern) || strings.Contains(args, pattern) {
				if proc := pc.getProcessInfo(int32(pid)); proc != nil {
					event := &events.Event{
						ID:        fmt.Sprintf("suspicious_%d_%d", pid, time.Now().Unix()),
						Type:      events.EventTypeProcess,
						Timestamp: time.Now(),
						Source:    "process_collector",
						Data: map[string]interface{}{
							"action":     "suspicious_activity",
							"pattern":    pattern,
							"process":    proc,
							"risk_level": "medium",
						},
					}

					select {
					case pc.eventChan <- event:
					default:
						pc.logger.Warn("Event channel full, dropping suspicious process event")
					}
				}
				break
			}
		}
	}
}

// NetworkCollector 网络事件收集器（简化版）
type NetworkCollector struct {
	logger    *logrus.Logger
	eventChan chan *events.Event
	done      chan struct{}
}

// NewNetworkCollector 创建网络收集器
func NewNetworkCollector(logger *logrus.Logger) *NetworkCollector {
	return &NetworkCollector{
		logger:    logger,
		eventChan: make(chan *events.Event, 1000),
		done:      make(chan struct{}),
	}
}

// Start 启动网络监控
func (nc *NetworkCollector) Start(ctx context.Context) error {
	nc.logger.Info("Starting network collector")

	go nc.monitorConnections(ctx)

	return nil
}

// Stop 停止收集器
func (nc *NetworkCollector) Stop() error {
	nc.logger.Info("Stopping network collector")
	close(nc.done)
	close(nc.eventChan)
	return nil
}

// EventChannel 返回事件通道
func (nc *NetworkCollector) EventChannel() <-chan *events.Event {
	return nc.eventChan
}

// monitorConnections 监控网络连接
func (nc *NetworkCollector) monitorConnections(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-nc.done:
			return
		case <-ticker.C:
			nc.checkNetworkConnections()
		}
	}
}

// checkNetworkConnections 检查网络连接
func (nc *NetworkCollector) checkNetworkConnections() {
	// 读取 /proc/net/tcp 和 /proc/net/tcp6
	for _, protocol := range []string{"tcp", "tcp6"} {
		path := fmt.Sprintf("/proc/net/%s", protocol)
		nc.parseNetworkFile(path, protocol)
	}
}

// parseNetworkFile 解析网络文件
func (nc *NetworkCollector) parseNetworkFile(path, protocol string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue // 跳过标题行和空行
		}

		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		// 解析本地和远程地址
		localAddr := fields[1]
		remoteAddr := fields[2]
		state := fields[3]

		// 只关注已建立的连接
		if state != "01" { // 01 表示 ESTABLISHED
			continue
		}

		localIP, localPort := nc.parseAddress(localAddr)
		remoteIP, remotePort := nc.parseAddress(remoteAddr)

		// 检查是否为可疑连接
		if nc.isSuspiciousConnection(remoteIP, remotePort) {
			event := &events.Event{
				ID:        fmt.Sprintf("net_%s_%d", remoteAddr, time.Now().Unix()),
				Type:      events.EventTypeNetwork,
				Timestamp: time.Now(),
				Source:    "network_collector",
				Data: map[string]interface{}{
					"network": events.NetworkInfo{
						Protocol:   protocol,
						SourceIP:   localIP,
						SourcePort: localPort,
						DestIP:     remoteIP,
						DestPort:   remotePort,
						Direction:  "outbound",
					},
					"risk_level": "high",
				},
			}

			select {
			case nc.eventChan <- event:
			default:
				nc.logger.Warn("Event channel full, dropping network event")
			}
		}
	}
}

// parseAddress 解析地址字符串
func (nc *NetworkCollector) parseAddress(addr string) (string, int) {
	parts := strings.Split(addr, ":")
	if len(parts) != 2 {
		return "", 0
	}

	// 解析 IP 地址（十六进制格式）
	ipHex := parts[0]
	portHex := parts[1]

	var ip string
	if len(ipHex) == 8 { // IPv4
		ip = nc.parseIPv4(ipHex)
	} else { // IPv6
		ip = nc.parseIPv6(ipHex)
	}

	port, _ := strconv.ParseInt(portHex, 16, 32)

	return ip, int(port)
}

// parseIPv4 解析 IPv4 地址
func (nc *NetworkCollector) parseIPv4(hex string) string {
	if len(hex) != 8 {
		return ""
	}

	var parts []string
	for i := 6; i >= 0; i -= 2 {
		part, _ := strconv.ParseInt(hex[i:i+2], 16, 32)
		parts = append(parts, strconv.Itoa(int(part)))
	}

	return strings.Join(parts, ".")
}

// parseIPv6 解析 IPv6 地址（简化版）
func (nc *NetworkCollector) parseIPv6(hex string) string {
	// 这里简化处理，实际应该正确解析 IPv6
	return fmt.Sprintf("IPv6:%s", hex)
}

// isSuspiciousConnection 检查是否为可疑连接
func (nc *NetworkCollector) isSuspiciousConnection(ip string, port int) bool {
	// 检查可疑端口
	suspiciousPorts := []int{22, 23, 3389, 4444, 5555, 6666, 7777, 8888, 9999}
	for _, suspPort := range suspiciousPorts {
		if port == suspPort {
			return true
		}
	}

	// 检查私有 IP 范围外的连接
	if !nc.isPrivateIP(ip) && ip != "127.0.0.1" && ip != "0.0.0.0" {
		return true
	}

	return false
}

// isPrivateIP 检查是否为私有 IP
func (nc *NetworkCollector) isPrivateIP(ip string) bool {
	// 简化的私有 IP 检查
	return strings.HasPrefix(ip, "10.") ||
		strings.HasPrefix(ip, "192.168.") ||
		strings.HasPrefix(ip, "172.")
}
