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

// SimpleWasmRule 简化的 Wasm 规则
type SimpleWasmRule struct {
	Name   string
	Module *wasmtime.Module
	Engine *wasmtime.Engine
	mu     sync.RWMutex
}

// SimpleEngine 简化的 Wasm 引擎
type SimpleEngine struct {
	engine *wasmtime.Engine
	rules  map[string]*SimpleWasmRule
	mu     sync.RWMutex
	logger *logrus.Logger
}

// NewSimpleEngine 创建新的简化 Wasm 引擎
func NewSimpleEngine(logger *logrus.Logger) *SimpleEngine {
	config := wasmtime.NewConfig()
	return &SimpleEngine{
		engine: wasmtime.NewEngineWithConfig(config),
		rules:  make(map[string]*SimpleWasmRule),
		logger: logger,
	}
}

// LoadRule 加载 Wasm 规则模块
func (e *SimpleEngine) LoadRule(name, wasmPath string) error {
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

	rule := &SimpleWasmRule{
		Name:   name,
		Module: module,
		Engine: e.engine,
	}

	e.rules[name] = rule
	e.logger.Infof("Loaded Wasm rule: %s from %s", name, wasmPath)

	return nil
}

// LoadRulesFromDir 从目录加载所有 Wasm 规则
func (e *SimpleEngine) LoadRulesFromDir(rulesDir string) error {
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
func (e *SimpleEngine) UnloadRule(name string) error {
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
func (e *SimpleEngine) DetectThreat(ctx context.Context, event *events.Event) ([]*events.DetectionResult, error) {
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
		result, err := e.runSimpleRule(ctx, rule, eventData, event)
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

// runSimpleRule 运行单个规则（简化版本）
func (e *SimpleEngine) runSimpleRule(ctx context.Context, rule *SimpleWasmRule, eventData []byte, event *events.Event) (*events.DetectionResult, error) {
	rule.mu.Lock()
	defer rule.mu.Unlock()

	// 创建 Store
	store := wasmtime.NewStore(rule.Engine)

	// 创建 linker
	linker := wasmtime.NewLinker(rule.Engine)
	err := linker.DefineWasi()
	if err != nil {
		return nil, fmt.Errorf("failed to define WASI: %w", err)
	}

	// 创建 WASI 配置
	wasiConfig := wasmtime.NewWasiConfig()
	wasiConfig.InheritStdout()
	wasiConfig.InheritStderr()
	store.SetWasi(wasiConfig)

	// 实例化模块
	instance, err := linker.Instantiate(store, rule.Module)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate wasm module %s: %w", rule.Name, err)
	}

	// 获取检测函数
	detectFn := instance.GetFunc(store, "detect")
	if detectFn == nil {
		return nil, fmt.Errorf("wasm module %s does not export 'detect' function", rule.Name)
	}

	// 获取内存
	memory := instance.GetExport(store, "memory")
	if memory == nil {
		return nil, fmt.Errorf("rule %s has no memory export", rule.Name)
	}

	memoryObj := memory.Memory()
	if memoryObj == nil {
		return nil, fmt.Errorf("rule %s memory export is not a memory", rule.Name)
	}

	// 在 Wasm 内存中分配空间（简化版本）
	dataPtr := int32(1024) // 固定偏移
	dataLen := int32(len(eventData))

	// 写入事件数据到 Wasm 内存
	memoryData := memoryObj.UnsafeData(store)
	if len(memoryData) < int(dataPtr)+len(eventData) {
		return nil, fmt.Errorf("insufficient memory in rule %s", rule.Name)
	}

	copy(memoryData[dataPtr:], eventData)

	// 调用检测函数
	result, err := detectFn.Call(store, dataPtr, dataLen)
	if err != nil {
		return nil, fmt.Errorf("failed to call detect function in rule %s: %w", rule.Name, err)
	}

	// 检查返回值 - Call 返回单个值
	if result == nil {
		return nil, fmt.Errorf("rule %s returned no result", rule.Name)
	}

	// 获取威胁级别 - 直接从 Val 类型获取
	threatLevel, ok := result.(int32)
	if !ok {
		// 尝试从 Val 获取
		if val, ok := result.(*wasmtime.Val); ok {
			threatLevel = val.I32()
		} else {
			return nil, fmt.Errorf("rule %s returned unexpected result type", rule.Name)
		}
	}

	if threatLevel > 0 {
		return &events.DetectionResult{
			RuleName:    rule.Name,
			Severity:    e.getSeverityLevel(threatLevel),
			Threat:      true,
			Confidence:  float64(threatLevel) / 10.0,
			Description: fmt.Sprintf("Threat detected by rule %s", rule.Name),
			Event:       *event,
		}, nil
	}

	return nil, nil
}

// getSeverityLevel 根据威胁级别返回严重程度
func (e *SimpleEngine) getSeverityLevel(level int32) string {
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
func (e *SimpleEngine) GetLoadedRules() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var rules []string
	for name := range e.rules {
		rules = append(rules, name)
	}

	return rules
}

// Close 关闭引擎并清理资源
func (e *SimpleEngine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	for name := range e.rules {
		delete(e.rules, name)
	}

	e.logger.Info("Simple Wasm engine closed")
	return nil
}
