package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/GeoffreyWang1117/WasmSentinel/host/internal/collector"
	"github.com/GeoffreyWang1117/WasmSentinel/host/internal/engine"
	"github.com/GeoffreyWang1117/WasmSentinel/host/internal/metrics"
	"github.com/GeoffreyWang1117/WasmSentinel/host/internal/output"
	"github.com/GeoffreyWang1117/WasmSentinel/host/internal/pipeline"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// wasmtimeVersion is the wasmtime-go major version linked into this binary.
const wasmtimeVersion = "wasmtime-go/v17"

var (
	cfgFile     string
	rulesDir    string
	logLevel    string
	logFile     string
	webhookURL  string
	metricsPort int

	ruleMemoryMB int
	ruleFuel     uint64
	ruleTimeout  time.Duration

	collectorMode string
	ebpfHooks     string
	eventEncoding string
	replayFile    string
	replayEPS     int
	replayLoop    bool
)

// rootCmd 代表基本命令
var rootCmd = &cobra.Command{
	Use:   "wasmsentinel",
	Short: "基于 WebAssembly 的轻量化实时威胁检测工具",
	Long: `WasmSentinel 是一个基于 WebAssembly 技术的轻量级、安全、
可移植的实时威胁检测工具。通过 Wasm 沙箱环境运行检测规则，
提供高性能、低延迟的安全检测能力。`,
	Run: func(cmd *cobra.Command, args []string) {
		run()
	},
}

func main() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// 全局标志
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "配置文件 (默认查找 $HOME/.wasmsentinel.yaml)")
	rootCmd.PersistentFlags().StringVar(&rulesDir, "rules", "./rules", "Wasm 规则目录")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "info", "日志级别 (debug, info, warn, error)")
	rootCmd.PersistentFlags().StringVar(&logFile, "log-file", "", "日志文件路径")
	rootCmd.PersistentFlags().StringVar(&webhookURL, "webhook", "", "Webhook URL for alerts")
	rootCmd.PersistentFlags().IntVar(&metricsPort, "metrics-port", 8080, "Prometheus 指标端口")
	rootCmd.PersistentFlags().IntVar(&ruleMemoryMB, "rule-memory-mb", int(engine.DefaultMaxMemoryBytes>>20), "每条规则的线性内存上限 (MiB)")
	rootCmd.PersistentFlags().Uint64Var(&ruleFuel, "rule-fuel", engine.DefaultFuel, "每次检测调用的 fuel 预算 (0 = 不限制)")
	rootCmd.PersistentFlags().DurationVar(&ruleTimeout, "rule-timeout", engine.DefaultTimeout, "每次检测调用的墙钟超时 (0 = 不限制)")
	rootCmd.PersistentFlags().StringVar(&collectorMode, "collector", "proc", "事件采集器: proc (/proc 轮询, 无需特权), ebpf (内核钩子, 需要 root) 或 replay (回放 syscall 轨迹)")
	rootCmd.PersistentFlags().StringVar(&replayFile, "replay-file", "", "collector=replay 时的轨迹文件或目录 (ADFA-LD 格式: 空格分隔的 syscall 号)")
	rootCmd.PersistentFlags().IntVar(&replayEPS, "replay-eps", 0, "回放速率 (事件/秒, 0 = 尽快)")
	rootCmd.PersistentFlags().BoolVar(&replayLoop, "replay-loop", false, "轨迹播完后循环")
	rootCmd.PersistentFlags().StringVar(&ebpfHooks, "ebpf-hooks", "all", "eBPF 钩子列表, 逗号分隔: exec,exit,open,connect,accept,syscall 或 all")
	rootCmd.PersistentFlags().StringVar(&eventEncoding, "event-encoding", "json", "交给规则的事件编码: json 或 binary (binary 仅对 eBPF 事件且规则导出 detect_raw 时生效, 否则回退 json)")

	// 绑定标志到 viper
	viper.BindPFlag("rules", rootCmd.PersistentFlags().Lookup("rules"))
	viper.BindPFlag("log-level", rootCmd.PersistentFlags().Lookup("log-level"))
	viper.BindPFlag("log-file", rootCmd.PersistentFlags().Lookup("log-file"))
	viper.BindPFlag("webhook", rootCmd.PersistentFlags().Lookup("webhook"))
	viper.BindPFlag("metrics-port", rootCmd.PersistentFlags().Lookup("metrics-port"))
	viper.BindPFlag("rule-memory-mb", rootCmd.PersistentFlags().Lookup("rule-memory-mb"))
	viper.BindPFlag("rule-fuel", rootCmd.PersistentFlags().Lookup("rule-fuel"))
	viper.BindPFlag("rule-timeout", rootCmd.PersistentFlags().Lookup("rule-timeout"))
	viper.BindPFlag("collector", rootCmd.PersistentFlags().Lookup("collector"))
	viper.BindPFlag("replay-file", rootCmd.PersistentFlags().Lookup("replay-file"))
	viper.BindPFlag("replay-eps", rootCmd.PersistentFlags().Lookup("replay-eps"))
	viper.BindPFlag("replay-loop", rootCmd.PersistentFlags().Lookup("replay-loop"))
	viper.BindPFlag("ebpf-hooks", rootCmd.PersistentFlags().Lookup("ebpf-hooks"))
	viper.BindPFlag("event-encoding", rootCmd.PersistentFlags().Lookup("event-encoding"))
}

// initConfig 读取配置文件和环境变量
func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		viper.AddConfigPath(home)
		viper.AddConfigPath(".")
		viper.SetConfigType("yaml")
		viper.SetConfigName(".wasmsentinel")
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}

// run 主运行逻辑
func run() {
	// 设置日志
	logger := setupLogger()

	logger.Info("Starting WasmSentinel")

	// 创建上下文
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 创建 Wasm 引擎：每条规则一个长寿实例，内存 / fuel / 超时三重限额
	limits := engine.Limits{
		MaxMemoryBytes: int64(viper.GetInt("rule-memory-mb")) << 20,
		Fuel:           viper.GetUint64("rule-fuel"),
		Timeout:        viper.GetDuration("rule-timeout"),
	}
	wasmEngine := engine.New(logger, limits)
	defer wasmEngine.Close()
	encoding, err := engine.ParseEncoding(viper.GetString("event-encoding"))
	if err != nil {
		logger.Fatal(err)
	}
	wasmEngine.SetEncoding(encoding)
	logger.WithFields(logrus.Fields{
		"memory_bytes": wasmEngine.Limits().MaxMemoryBytes,
		"fuel":         wasmEngine.Limits().Fuel,
		"timeout":      wasmEngine.Limits().Timeout.String(),
		"encoding":     string(encoding),
	}).Info("Wasm rule limits")

	// 指标：真实计数器，规则调用由引擎观察者喂入，威胁计数由输出链喂入
	m := metrics.New()
	m.SetBuildInfo(viper.GetString("collector"), string(encoding), wasmtimeVersion)
	wasmEngine.SetObserver(m)
	m.RegisterEngine(wasmEngine)

	// 加载规则
	rulesPath := viper.GetString("rules")
	if err := loadRules(wasmEngine, rulesPath, logger); err != nil {
		logger.Fatalf("Failed to load rules: %v", err)
	}

	// 创建输出处理器
	outputHandler, err := createOutputHandler(logger, m)
	if err != nil {
		logger.Fatalf("Failed to create output handler: %v", err)
	}
	defer outputHandler.Close()

	// 创建事件收集器
	collectors := createCollectors(logger)
	for _, col := range collectors {
		if s, ok := col.(metrics.EBPFStatser); ok {
			m.RegisterEBPF(s)
		}
	}

	// 启动收集器
	for _, col := range collectors {
		if err := col.Start(ctx); err != nil {
			logger.Fatalf("Failed to start collector: %v", err)
		}
		defer col.Stop()
	}

	// 启动 Prometheus 指标服务器
	go startMetricsServer(logger, m)

	// 处理事件：采集器全部关闭（回放结束）或收到信号时结束
	done := make(chan pipeline.Stats, 1)
	go func() {
		done <- pipeline.Run(ctx, pipeline.Config{
			Engine: wasmEngine, Collectors: collectors, Output: outputHandler, Metrics: m, Logger: logger,
		})
	}()

	logger.Info("WasmSentinel started successfully")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-sigChan:
		logger.Info("Shutting down WasmSentinel")
		cancel()
		select {
		case st := <-done:
			logPipelineStats(logger, st)
		case <-time.After(5 * time.Second):
			logger.Warn("Pipeline did not stop within 5s")
		}
	case st := <-done:
		logger.Info("Pipeline finished: all collectors closed")
		logPipelineStats(logger, st)
		cancel()
	}

	for name, st := range wasmEngine.Stats() {
		logger.WithFields(logrus.Fields{
			"rule":             name,
			"calls":            st.Calls,
			"calls_raw":        st.CallsRaw,
			"threats":          st.Threats,
			"errors":           st.Errors,
			"traps_fuel":       st.TrapsFuel,
			"traps_timeout":    st.TrapsTimeout,
			"traps_memory":     st.TrapsMemory,
			"reinstantiations": st.Reinstantiations,
			"fuel_total":       st.FuelTotal,
			"latency_max":      st.LatencyMax.String(),
			"memory_bytes":     st.MemoryBytes,
		}).Info("Rule statistics")
	}
	logger.Info("WasmSentinel stopped")
}

// setupLogger 设置日志
func setupLogger() *logrus.Logger {
	logger := logrus.New()

	// 设置日志级别
	level, err := logrus.ParseLevel(viper.GetString("log-level"))
	if err != nil {
		level = logrus.InfoLevel
	}
	logger.SetLevel(level)

	// 设置日志格式
	logger.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.RFC3339,
	})

	// 设置日志输出
	logFilePath := viper.GetString("log-file")
	if logFilePath != "" {
		file, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			logger.Fatalf("Failed to open log file: %v", err)
		}
		logger.SetOutput(file)
	}

	return logger
}

// loadRules 加载 Wasm 规则
func loadRules(wasmEngine engine.ThreatEngine, rulesPath string, logger *logrus.Logger) error {
	// 检查路径是文件还是目录
	info, err := os.Stat(rulesPath)
	if err != nil {
		return fmt.Errorf("rules path does not exist: %s", rulesPath)
	}

	if info.IsDir() {
		// 从目录加载
		if err := wasmEngine.LoadRulesFromDir(rulesPath); err != nil {
			return err
		}
	} else {
		// 单个文件
		if strings.HasSuffix(rulesPath, ".wasm") {
			ruleName := strings.TrimSuffix(info.Name(), ".wasm")
			if err := wasmEngine.LoadRule(ruleName, rulesPath); err != nil {
				return err
			}
		} else {
			return fmt.Errorf("invalid rule file: %s (must be .wasm)", rulesPath)
		}
	}

	// 显示加载的规则
	rules := wasmEngine.GetLoadedRules()
	logger.Infof("Loaded %d rules: %v", len(rules), rules)

	return nil
}

// createOutputHandler 创建输出处理器
func createOutputHandler(logger *logrus.Logger, m *metrics.Metrics) (output.OutputHandler, error) {
	var handlers []output.OutputHandler

	// 日志输出处理器
	logHandler, err := output.NewLogOutputHandler(logger, viper.GetString("log-file"))
	if err != nil {
		return nil, err
	}
	handlers = append(handlers, logHandler)

	// Webhook 输出处理器
	webhookURL := viper.GetString("webhook")
	if webhookURL != "" {
		webhookHandler := output.NewWebhookOutputHandler(logger, webhookURL, nil)
		handlers = append(handlers, webhookHandler)
	}

	// Prometheus 威胁计数
	handlers = append(handlers, m)

	return output.NewMultiOutputHandler(logger, handlers...), nil
}

// createCollectors 创建事件收集器：--collector=ebpf 用内核 eBPF 钩子（需要 root），
// --collector=proc 用 /proc 轮询（无特权，默认）。
func createCollectors(logger *logrus.Logger) []collector.Collector {
	switch mode := viper.GetString("collector"); mode {
	case "ebpf":
		logger.WithField("hooks", viper.GetString("ebpf-hooks")).Info("Using eBPF collector")
		return []collector.Collector{
			collector.NewEBPFCollector(logger, collector.EBPFConfig{Hooks: viper.GetString("ebpf-hooks")}),
		}
	case "proc":
		logger.Info("Using /proc polling collectors")
		return []collector.Collector{
			collector.NewProcessCollector(logger),
			collector.NewNetworkCollector(logger),
		}
	case "replay":
		c, err := collector.NewReplayCollector(logger, collector.ReplayConfig{
			Path:            viper.GetString("replay-file"),
			EventsPerSecond: viper.GetInt("replay-eps"),
			Loop:            viper.GetBool("replay-loop"),
			Binary:          true,
		})
		if err != nil {
			logger.Fatalf("replay collector: %v", err)
		}
		return []collector.Collector{c}
	default:
		logger.Fatalf("unknown --collector %q (use proc, ebpf or replay)", mode)
		return nil
	}
}

// logPipelineStats 输出一次运行的汇总
func logPipelineStats(logger *logrus.Logger, st pipeline.Stats) {
	eps := 0.0
	if st.Elapsed > 0 {
		eps = float64(st.Events) / st.Elapsed.Seconds()
	}
	logger.WithFields(logrus.Fields{
		"events":        st.Events,
		"alerts":        st.Alerts,
		"detect_errors": st.DetectErrors,
		"output_errors": st.OutputErrors,
		"elapsed":       st.Elapsed.String(),
		"events_per_s":  fmt.Sprintf("%.0f", eps),
	}).Info("Pipeline statistics")
}

// startMetricsServer 启动 Prometheus 指标与健康检查服务
func startMetricsServer(logger *logrus.Logger, m *metrics.Metrics) {
	port := viper.GetInt("metrics-port")

	mux := http.NewServeMux()
	mux.Handle("/metrics", m.Handler())
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	logger.Infof("Starting metrics server on port %d", port)
	if err := http.ListenAndServe(fmt.Sprintf(":%d", port), mux); err != nil {
		logger.Errorf("Metrics server failed: %v", err)
	}
}
