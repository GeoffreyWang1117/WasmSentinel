package events

import (
	"encoding/json"
	"time"
)

// EventType 定义事件类型
type EventType string

const (
	EventTypeProcess EventType = "process"
	EventTypeNetwork EventType = "network"
	EventTypeFile    EventType = "file"
)

// Event 表示一个系统事件
type Event struct {
	ID        string                 `json:"id"`
	Type      EventType              `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	Source    string                 `json:"source"`
	Data      map[string]interface{} `json:"data"`
}

// ProcessEvent 进程事件
type ProcessEvent struct {
	Event
	ProcessInfo ProcessInfo `json:"process"`
}

// ProcessInfo 进程信息
type ProcessInfo struct {
	PID         int32  `json:"pid"`
	PPID        int32  `json:"ppid"`
	Name        string `json:"name"`
	Executable  string `json:"executable"`
	CommandLine string `json:"command_line"`
	User        string `json:"user"`
	Group       string `json:"group"`
}

// NetworkEvent 网络事件
type NetworkEvent struct {
	Event
	NetworkInfo NetworkInfo `json:"network"`
}

// NetworkInfo 网络信息
type NetworkInfo struct {
	Protocol    string `json:"protocol"`
	SourceIP    string `json:"source_ip"`
	SourcePort  int    `json:"source_port"`
	DestIP      string `json:"dest_ip"`
	DestPort    int    `json:"dest_port"`
	Direction   string `json:"direction"`
	DataSize    int64  `json:"data_size"`
	ProcessName string `json:"process_name"`
}

// FileEvent 文件事件
type FileEvent struct {
	Event
	FileInfo FileInfo `json:"file"`
}

// FileInfo 文件信息
type FileInfo struct {
	Path        string `json:"path"`
	Operation   string `json:"operation"`
	Permissions string `json:"permissions"`
	ProcessName string `json:"process_name"`
	User        string `json:"user"`
}

// DetectionResult 检测结果
type DetectionResult struct {
	RuleName    string                 `json:"rule_name"`
	Severity    string                 `json:"severity"`
	Threat      bool                   `json:"threat"`
	Confidence  float64                `json:"confidence"`
	Description string                 `json:"description"`
	Event       Event                  `json:"event"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// ToJSON 将事件转换为 JSON 字节数组
func (e *Event) ToJSON() ([]byte, error) {
	return json.Marshal(e)
}

// FromJSON 从 JSON 字节数组创建事件
func FromJSON(data []byte) (*Event, error) {
	var event Event
	err := json.Unmarshal(data, &event)
	return &event, err
}
