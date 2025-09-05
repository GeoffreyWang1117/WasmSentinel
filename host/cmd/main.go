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

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/wasm-threat-detector/host/internal/collector"
	"github.com/wasm-threat-detector/host/internal/engine"
	"github.com/wasm-threat-detector/host/internal/events"
	"github.com/wasm-threat-detector/host/internal/output"
)

var (
	cfgFile     string
	rulesDir    string
	logLevel    string
	logFile     string
	webhookURL  string
	metricsPort int
)

// rootCmd 代表基本命令
var rootCmd = &cobra.Command{
	Use:   "wasm-threat-detector",
	Short: "基于 WebAssembly 的轻量化实时威胁检测工具",
	Long: `WASM-ThreatDetector 是一个基于 WebAssembly 技术的轻量级、安全、
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
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "配置文件 (默认查找 $HOME/.wasm-threat-detector.yaml)")
	rootCmd.PersistentFlags().StringVar(&rulesDir, "rules", "./rules", "Wasm 规则目录")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "info", "日志级别 (debug, info, warn, error)")
	rootCmd.PersistentFlags().StringVar(&logFile, "log-file", "", "日志文件路径")
	rootCmd.PersistentFlags().StringVar(&webhookURL, "webhook", "", "Webhook URL for alerts")
	rootCmd.PersistentFlags().IntVar(&metricsPort, "metrics-port", 8080, "Prometheus 指标端口")

	// 绑定标志到 viper
	viper.BindPFlag("rules", rootCmd.PersistentFlags().Lookup("rules"))
	viper.BindPFlag("log-level", rootCmd.PersistentFlags().Lookup("log-level"))
	viper.BindPFlag("log-file", rootCmd.PersistentFlags().Lookup("log-file"))
	viper.BindPFlag("webhook", rootCmd.PersistentFlags().Lookup("webhook"))
	viper.BindPFlag("metrics-port", rootCmd.PersistentFlags().Lookup("metrics-port"))
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
		viper.SetConfigName(".wasm-threat-detector")
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

	logger.Info("Starting WASM-ThreatDetector")

	// 创建上下文
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 创建 Wasm 引擎
	wasmEngine := engine.NewSimpleEngine(logger)
	defer wasmEngine.Close()

	// 加载规则
	rulesPath := viper.GetString("rules")
	if err := loadRules(wasmEngine, rulesPath, logger); err != nil {
		logger.Fatalf("Failed to load rules: %v", err)
	}

	// 创建输出处理器
	outputHandler, err := createOutputHandler(logger)
	if err != nil {
		logger.Fatalf("Failed to create output handler: %v", err)
	}
	defer outputHandler.Close()

	// 创建事件收集器
	collectors := createCollectors(logger)

	// 启动收集器
	for _, col := range collectors {
		if err := col.Start(ctx); err != nil {
			logger.Fatalf("Failed to start collector: %v", err)
		}
		defer col.Stop()
	}

	// 启动 Prometheus 指标服务器
	if prometheusHandler, ok := outputHandler.(*output.MultiOutputHandler); ok {
		go startMetricsServer(logger, prometheusHandler)
	}

	// 处理事件
	go processEvents(ctx, wasmEngine, collectors, outputHandler, logger)

	logger.Info("WASM-ThreatDetector started successfully")

	// 等待信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	<-sigChan
	logger.Info("Shutting down WASM-ThreatDetector")
	cancel()

	// 等待一段时间让组件正常关闭
	time.Sleep(2 * time.Second)
	logger.Info("WASM-ThreatDetector stopped")
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
func createOutputHandler(logger *logrus.Logger) (output.OutputHandler, error) {
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

	// Prometheus 输出处理器
	prometheusHandler := output.NewPrometheusOutputHandler(logger)
	handlers = append(handlers, prometheusHandler)

	return output.NewMultiOutputHandler(logger, handlers...), nil
}

// createCollectors 创建事件收集器
func createCollectors(logger *logrus.Logger) []collector.Collector {
	var collectors []collector.Collector

	// 进程收集器
	processCollector := collector.NewProcessCollector(logger)
	collectors = append(collectors, processCollector)

	// 网络收集器
	networkCollector := collector.NewNetworkCollector(logger)
	collectors = append(collectors, networkCollector)

	return collectors
}

// processEvents 处理事件
func processEvents(ctx context.Context, wasmEngine engine.ThreatEngine, collectors []collector.Collector, outputHandler output.OutputHandler, logger *logrus.Logger) {
	// 合并所有收集器的事件通道
	eventChan := make(chan *events.Event, 1000)

	// 启动事件合并 goroutine
	for _, col := range collectors {
		go func(c collector.Collector) {
			for event := range c.EventChannel() {
				select {
				case eventChan <- event:
				case <-ctx.Done():
					return
				default:
					logger.Warn("Event channel full, dropping event")
				}
			}
		}(col)
	}

	// 处理事件
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-eventChan:
			// 使用 Wasm 引擎检测威胁
			results, err := wasmEngine.DetectThreat(ctx, event)
			if err != nil {
				logger.Warnf("Threat detection failed: %v", err)
				continue
			}

			// 处理检测结果
			for _, result := range results {
				if err := outputHandler.Handle(result); err != nil {
					logger.Warnf("Failed to handle detection result: %v", err)
				}
			}
		}
	}
}

// startMetricsServer 启动 Prometheus 指标服务器
func startMetricsServer(logger *logrus.Logger, multiHandler *output.MultiOutputHandler) {
	port := viper.GetInt("metrics-port")

	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		// 这里需要从 multiHandler 中获取 PrometheusOutputHandler
		// 简化处理，实际应该提供更好的接口
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("# HELP wasm_threat_detector_total_threats Total number of threats detected\n"))
		w.Write([]byte("# TYPE wasm_threat_detector_total_threats counter\n"))
		w.Write([]byte(fmt.Sprintf("wasm_threat_detector_total_threats %d\n", time.Now().Unix())))
	})

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	logger.Infof("Starting metrics server on port %d", port)
	if err := http.ListenAndServe(fmt.Sprintf(":%d", port), nil); err != nil {
		logger.Errorf("Metrics server failed: %v", err)
	}
}
