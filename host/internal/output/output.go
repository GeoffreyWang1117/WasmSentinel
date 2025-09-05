package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/wasm-threat-detector/host/internal/events"
)

// OutputHandler 输出处理器接口
type OutputHandler interface {
	Handle(result *events.DetectionResult) error
	Close() error
}

// LogOutputHandler 日志输出处理器
type LogOutputHandler struct {
	logger *logrus.Logger
	file   *os.File
	mu     sync.Mutex
}

// NewLogOutputHandler 创建日志输出处理器
func NewLogOutputHandler(logger *logrus.Logger, logFile string) (*LogOutputHandler, error) {
	var file *os.File
	var err error

	if logFile != "" {
		file, err = os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file %s: %w", logFile, err)
		}
	}

	return &LogOutputHandler{
		logger: logger,
		file:   file,
	}, nil
}

// Handle 处理检测结果
func (l *LogOutputHandler) Handle(result *events.DetectionResult) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// 格式化输出
	logEntry := map[string]interface{}{
		"timestamp":   time.Now().Format(time.RFC3339),
		"rule_name":   result.RuleName,
		"severity":    result.Severity,
		"threat":      result.Threat,
		"confidence":  result.Confidence,
		"description": result.Description,
		"event_type":  result.Event.Type,
		"event_id":    result.Event.ID,
		"source":      result.Event.Source,
		"metadata":    result.Metadata,
	}

	// 添加事件特定数据
	switch result.Event.Type {
	case events.EventTypeProcess:
		if processData, ok := result.Event.Data["process"]; ok {
			logEntry["process"] = processData
		}
	case events.EventTypeNetwork:
		if networkData, ok := result.Event.Data["network"]; ok {
			logEntry["network"] = networkData
		}
	case events.EventTypeFile:
		if fileData, ok := result.Event.Data["file"]; ok {
			logEntry["file"] = fileData
		}
	}

	// 转换为 JSON
	jsonData, err := json.MarshalIndent(logEntry, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal detection result: %w", err)
	}

	// 写入文件（如果指定）
	if l.file != nil {
		if _, err := l.file.Write(jsonData); err != nil {
			return fmt.Errorf("failed to write to log file: %w", err)
		}
		if _, err := l.file.WriteString("\n"); err != nil {
			return fmt.Errorf("failed to write newline to log file: %w", err)
		}
	}

	// 同时输出到控制台
	l.logger.WithFields(logrus.Fields{
		"rule":       result.RuleName,
		"severity":   result.Severity,
		"confidence": result.Confidence,
		"event_type": result.Event.Type,
	}).Warn(result.Description)

	return nil
}

// Close 关闭处理器
func (l *LogOutputHandler) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file != nil {
		return l.file.Close()
	}

	return nil
}

// WebhookOutputHandler Webhook 输出处理器
type WebhookOutputHandler struct {
	logger    *logrus.Logger
	url       string
	client    *http.Client
	headers   map[string]string
	batchSize int
	batch     []*events.DetectionResult
	mu        sync.Mutex
}

// NewWebhookOutputHandler 创建 Webhook 输出处理器
func NewWebhookOutputHandler(logger *logrus.Logger, url string, headers map[string]string) *WebhookOutputHandler {
	return &WebhookOutputHandler{
		logger:    logger,
		url:       url,
		client:    &http.Client{Timeout: 30 * time.Second},
		headers:   headers,
		batchSize: 10,
		batch:     make([]*events.DetectionResult, 0, 10),
	}
}

// Handle 处理检测结果
func (w *WebhookOutputHandler) Handle(result *events.DetectionResult) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.batch = append(w.batch, result)

	// 如果批次满了，发送数据
	if len(w.batch) >= w.batchSize {
		return w.sendBatch()
	}

	return nil
}

// sendBatch 发送批次数据
func (w *WebhookOutputHandler) sendBatch() error {
	if len(w.batch) == 0 {
		return nil
	}

	// 构建请求体
	payload := map[string]interface{}{
		"timestamp": time.Now().Format(time.RFC3339),
		"alerts":    w.batch,
		"count":     len(w.batch),
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook payload: %w", err)
	}

	// 创建 HTTP 请求
	req, err := http.NewRequest("POST", w.url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create webhook request: %w", err)
	}

	// 设置请求头
	req.Header.Set("Content-Type", "application/json")
	for key, value := range w.headers {
		req.Header.Set(key, value)
	}

	// 发送请求
	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send webhook request: %w", err)
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("webhook request failed with status %d: %s", resp.StatusCode, string(body))
	}

	w.logger.Infof("Sent %d alerts to webhook %s", len(w.batch), w.url)

	// 清空批次
	w.batch = w.batch[:0]

	return nil
}

// Close 关闭处理器
func (w *WebhookOutputHandler) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// 发送剩余的批次数据
	if len(w.batch) > 0 {
		return w.sendBatch()
	}

	return nil
}

// PrometheusOutputHandler Prometheus 指标输出处理器
type PrometheusOutputHandler struct {
	logger   *logrus.Logger
	counters map[string]int64
	mu       sync.RWMutex
}

// NewPrometheusOutputHandler 创建 Prometheus 输出处理器
func NewPrometheusOutputHandler(logger *logrus.Logger) *PrometheusOutputHandler {
	return &PrometheusOutputHandler{
		logger:   logger,
		counters: make(map[string]int64),
	}
}

// Handle 处理检测结果
func (p *PrometheusOutputHandler) Handle(result *events.DetectionResult) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// 更新计数器
	key := fmt.Sprintf("%s_%s", result.RuleName, result.Severity)
	p.counters[key]++

	// 总体威胁计数
	p.counters["total_threats"]++

	p.logger.Debugf("Updated Prometheus metrics for rule %s, severity %s", result.RuleName, result.Severity)

	return nil
}

// GetMetrics 获取 Prometheus 格式的指标
func (p *PrometheusOutputHandler) GetMetrics() string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var metrics []string

	// 添加威胁计数指标
	for key, count := range p.counters {
		if key == "total_threats" {
			metrics = append(metrics, fmt.Sprintf("wasm_threat_detector_total_threats %d", count))
		} else {
			// 解析规则名和严重程度
			parts := splitLast(key, "_")
			if len(parts) == 2 {
				metrics = append(metrics, fmt.Sprintf("wasm_threat_detector_threats{rule=\"%s\",severity=\"%s\"} %d", parts[0], parts[1], count))
			}
		}
	}

	// 添加时间戳
	timestamp := time.Now().Unix()
	var result string
	for _, metric := range metrics {
		result += fmt.Sprintf("%s %d\n", metric, timestamp)
	}

	return result
}

// Close 关闭处理器
func (p *PrometheusOutputHandler) Close() error {
	return nil
}

// splitLast 从后向前分割字符串
func splitLast(s, sep string) []string {
	if idx := lastIndex(s, sep); idx >= 0 {
		return []string{s[:idx], s[idx+len(sep):]}
	}
	return []string{s}
}

// lastIndex 查找最后一个分隔符的位置
func lastIndex(s, sep string) int {
	for i := len(s) - len(sep); i >= 0; i-- {
		if s[i:i+len(sep)] == sep {
			return i
		}
	}
	return -1
}

// MultiOutputHandler 多输出处理器
type MultiOutputHandler struct {
	handlers []OutputHandler
	logger   *logrus.Logger
}

// NewMultiOutputHandler 创建多输出处理器
func NewMultiOutputHandler(logger *logrus.Logger, handlers ...OutputHandler) *MultiOutputHandler {
	return &MultiOutputHandler{
		handlers: handlers,
		logger:   logger,
	}
}

// Handle 处理检测结果
func (m *MultiOutputHandler) Handle(result *events.DetectionResult) error {
	var lastErr error

	for _, handler := range m.handlers {
		if err := handler.Handle(result); err != nil {
			m.logger.Warnf("Output handler failed: %v", err)
			lastErr = err
		}
	}

	return lastErr
}

// Close 关闭所有处理器
func (m *MultiOutputHandler) Close() error {
	var lastErr error

	for _, handler := range m.handlers {
		if err := handler.Close(); err != nil {
			m.logger.Warnf("Failed to close output handler: %v", err)
			lastErr = err
		}
	}

	return lastErr
}
