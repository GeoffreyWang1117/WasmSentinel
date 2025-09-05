package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/bytecodealliance/wasmtime-go/v17"
	"github.com/sirupsen/logrus"
	"github.com/wasm-threat-detector/host/internal/events"
)

// WasmRule 表示一个 Wasm 检测规则
type WasmRule struct {
	Name     string
	Module   *wasmtime.Module
	Instance *wasmtime.Instance
	Store    *wasmtime.Store
	DetectFn *wasmtime.Func
	mu       sync.RWMutex
}

// Engine Wasm 规则引擎
type Engine struct {
	engine *wasmtime.Engine
	rules  map[string]*WasmRule
	mu     sync.RWMutex
	logger *logrus.Logger
}

// NewEngine 创建新的 Wasm 引擎
func NewEngine(logger *logrus.Logger) *Engine {
	config := wasmtime.NewConfig()
	config.SetWasmMultiMemory(true)
	config.SetWasmMemory64(false)

	return &Engine{
		engine: wasmtime.NewEngineWithConfig(config),
		rules:  make(map[string]*WasmRule),
		logger: logger,
	}
}

// LoadRule 加载 Wasm 规则模块
func (e *Engine) LoadRule(name, wasmPath string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// 读取 Wasm 文件
	wasmBytes, err := os.ReadFile(wasmPath)
	if err != nil {
		return fmt.Errorf("failed to read wasm file %s: %w", wasmPath, err)
	}

	// 编译模块
	module, err := wasmtime.NewModule(e.engine, wasmBytes)
	if err != nil {
		return fmt.Errorf("failed to compile wasm module %s: %w", wasmPath, err)
	}

	// 创建 Store
	store := wasmtime.NewStore(e.engine)

	// 创建 linker
	linker := wasmtime.NewLinker(e.engine)
	err = linker.DefineWasi()
	if err != nil {
		return fmt.Errorf("failed to define WASI: %w", err)
	}

	// 创建 WASI 配置
	wasiConfig := wasmtime.NewWasiConfig()
	wasiConfig.InheritStdout()
	wasiConfig.InheritStderr()

	// 在 store 中设置 WASI
	store.SetWasi(wasiConfig)

	// 实例化模块
	instance, err := linker.Instantiate(store, module)
	if err != nil {
		return fmt.Errorf("failed to instantiate wasm module %s: %w", wasmPath, err)
	} // 获取检测函数
	detectFn := instance.GetFunc(store, "detect")
	if detectFn == nil {
		return fmt.Errorf("wasm module %s does not export 'detect' function", wasmPath)
	}

	rule := &WasmRule{
		Name:     name,
		Module:   module,
		Instance: instance,
		Store:    store,
		DetectFn: detectFn,
	}

	e.rules[name] = rule
	e.logger.Infof("Loaded Wasm rule: %s from %s", name, wasmPath)

	return nil
}

// LoadRulesFromDir 从目录加载所有 Wasm 规则
func (e *Engine) LoadRulesFromDir(rulesDir string) error {
	return filepath.Walk(rulesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if filepath.Ext(path) == ".wasm" {
			name := filepath.Base(path)
			name = name[:len(name)-5] // 移除 .wasm 扩展名
			return e.LoadRule(name, path)
		}

		return nil
	})
}

// UnloadRule 卸载规则
func (e *Engine) UnloadRule(name string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if _, exists := e.rules[name]; !exists {
		return fmt.Errorf("rule %s not found", name)
	}

	delete(e.rules, name)
	e.logger.Infof("Unloaded Wasm rule: %s", name)

	return nil
}

// DetectThreat 使用所有规则检测威胁
func (e *Engine) DetectThreat(ctx context.Context, event *events.Event) ([]*events.DetectionResult, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var results []*events.DetectionResult

	// 将事件转换为 JSON
	eventData, err := event.ToJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize event: %w", err)
	}

	// 对每个规则执行检测
	for _, rule := range e.rules {
		result, err := e.runRule(ctx, rule, eventData, event)
		if err != nil {
			e.logger.Warnf("Rule %s failed: %v", rule.Name, err)
			continue
		}

		if result != nil {
			results = append(results, result)
		}
	}

	return results, nil
}

// runRule 运行单个规则
func (e *Engine) runRule(ctx context.Context, rule *WasmRule, eventData []byte, event *events.Event) (*events.DetectionResult, error) {
	rule.mu.Lock()
	defer rule.mu.Unlock()

	// 分配内存并写入事件数据
	memory := rule.Instance.GetExport(rule.Store, "memory").Memory()
	if memory == nil {
		return nil, fmt.Errorf("rule %s has no memory export", rule.Name)
	}

	// 在 Wasm 内存中分配空间
	dataPtr := int32(1024) // 简单的固定偏移
	dataLen := int32(len(eventData))

	// 写入事件数据到 Wasm 内存
	memoryData := memory.UnsafeData(rule.Store)
	if len(memoryData) < int(dataPtr)+len(eventData) {
		return nil, fmt.Errorf("insufficient memory in rule %s", rule.Name)
	}

	copy(memoryData[dataPtr:], eventData)

	// 调用检测函数
	result, err := rule.DetectFn.Call(rule.Store, dataPtr, dataLen)
	if err != nil {
		return nil, fmt.Errorf("failed to call detect function in rule %s: %w", rule.Name, err)
	}

	// 解析结果 - Wasmtime 返回的是 Val 类型
	if result == nil {
		return nil, fmt.Errorf("rule %s returned no result", rule.Name)
	}

	// 转换为 int32
	threatLevel := result.(int32)
	if threatLevel > 0 {
		return &events.DetectionResult{
			RuleName:    rule.Name,
			Severity:    e.getSeverityLevel(threatLevel),
			Threat:      true,
			Confidence:  float64(threatLevel) / 10.0, // 简单的置信度计算
			Description: fmt.Sprintf("Threat detected by rule %s", rule.Name),
			Event:       *event,
		}, nil
	}

	return nil, nil
}

// getSeverityLevel 根据威胁级别返回严重程度
func (e *Engine) getSeverityLevel(level int32) string {
	switch {
	case level >= 8:
		return "critical"
	case level >= 6:
		return "high"
	case level >= 4:
		return "medium"
	case level >= 2:
		return "low"
	default:
		return "info"
	}
}

// GetLoadedRules 获取已加载的规则列表
func (e *Engine) GetLoadedRules() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var rules []string
	for name := range e.rules {
		rules = append(rules, name)
	}

	return rules
}

// Close 关闭引擎并清理资源
func (e *Engine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	for name := range e.rules {
		delete(e.rules, name)
	}

	e.logger.Info("Wasm engine closed")
	return nil
}
