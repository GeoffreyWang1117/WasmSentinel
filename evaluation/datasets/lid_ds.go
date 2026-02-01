// Package datasets provides data loading utilities for standard security datasets
package datasets

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// LIDDSDataset represents the Leipzig Intrusion Detection Dataset
// Reference: https://www.2021.2021.2021.2021.2021.2021
type LIDDSDataset struct {
	Name        string
	Description string
	BaseURL     string
	LocalPath   string
	Scenarios   []LIDDSScenario
}

// LIDDSScenario represents a single attack scenario in LID-DS
type LIDDSScenario struct {
	Name          string
	Description   string
	AttackType    string
	TrainingRuns  []string
	ValidationRuns []string
	TestRuns      []string
}

// SyscallEvent represents a system call event from LID-DS
type SyscallEvent struct {
	Timestamp   time.Time
	ThreadID    int
	SyscallName string
	SyscallNr   int
	ReturnValue int
	Arguments   []string
	IsAttack    bool
}

// DatasetConfig holds configuration for dataset loading
type DatasetConfig struct {
	LocalPath     string
	DownloadURL   string
	CacheEnabled  bool
	MaxEvents     int // 0 = unlimited
}

// DefaultLIDDSScenarios returns the default LID-DS scenarios
func DefaultLIDDSScenarios() []LIDDSScenario {
	return []LIDDSScenario{
		{
			Name:        "Bruteforce_CWE-307",
			Description: "Brute force authentication attack",
			AttackType:  "bruteforce",
		},
		{
			Name:        "CVE-2012-2122",
			Description: "MySQL authentication bypass",
			AttackType:  "authentication_bypass",
		},
		{
			Name:        "CVE-2014-0160",
			Description: "Heartbleed vulnerability",
			AttackType:  "information_disclosure",
		},
		{
			Name:        "CVE-2017-7529",
			Description: "Nginx integer overflow",
			AttackType:  "buffer_overflow",
		},
		{
			Name:        "CVE-2018-3760",
			Description: "Sprockets path traversal",
			AttackType:  "path_traversal",
		},
		{
			Name:        "CVE-2019-5418",
			Description: "Rails file content disclosure",
			AttackType:  "information_disclosure",
		},
		{
			Name:        "CWE-89-SQL-injection",
			Description: "SQL injection attack",
			AttackType:  "sql_injection",
		},
		{
			Name:        "EPS_CWE-434",
			Description: "Unrestricted file upload",
			AttackType:  "file_upload",
		},
		{
			Name:        "Juice-Shop",
			Description: "OWASP Juice Shop attacks",
			AttackType:  "web_attacks",
		},
		{
			Name:        "PHP_CWE-434",
			Description: "PHP file upload vulnerability",
			AttackType:  "file_upload",
		},
		{
			Name:        "ZipSlip",
			Description: "Zip slip vulnerability",
			AttackType:  "path_traversal",
		},
	}
}

// LIDDSLoader loads and parses LID-DS dataset
type LIDDSLoader struct {
	config    DatasetConfig
	scenarios []LIDDSScenario
}

// NewLIDDSLoader creates a new LID-DS dataset loader
func NewLIDDSLoader(config DatasetConfig) *LIDDSLoader {
	return &LIDDSLoader{
		config:    config,
		scenarios: DefaultLIDDSScenarios(),
	}
}

// Download downloads the LID-DS dataset
func (l *LIDDSLoader) Download(scenario string) error {
	scenarioPath := filepath.Join(l.config.LocalPath, scenario)
	if err := os.MkdirAll(scenarioPath, 0755); err != nil {
		return fmt.Errorf("failed to create scenario directory: %w", err)
	}

	// LID-DS dataset structure:
	// scenario/
	//   training/
	//     run_0.sc, run_1.sc, ...
	//   validation/
	//     run_0.sc, ...
	//   test/
	//     run_0.sc, ...

	fmt.Printf("Note: Please download LID-DS dataset manually from:\n")
	fmt.Printf("  https://www.2021.2021.2021.2021/datasets/lid-ds-2021\n")
	fmt.Printf("  Extract to: %s\n", l.config.LocalPath)

	return nil
}

// LoadScenario loads a specific scenario's syscall traces
func (l *LIDDSLoader) LoadScenario(scenario string, split string) ([]SyscallEvent, error) {
	scenarioPath := filepath.Join(l.config.LocalPath, scenario, split)

	files, err := filepath.Glob(filepath.Join(scenarioPath, "*.sc"))
	if err != nil {
		return nil, fmt.Errorf("failed to find syscall files: %w", err)
	}

	if len(files) == 0 {
		// Try gzipped files
		files, err = filepath.Glob(filepath.Join(scenarioPath, "*.sc.gz"))
		if err != nil {
			return nil, fmt.Errorf("failed to find gzipped syscall files: %w", err)
		}
	}

	var allEvents []SyscallEvent
	for _, file := range files {
		events, err := l.parseFile(file)
		if err != nil {
			return nil, fmt.Errorf("failed to parse %s: %w", file, err)
		}
		allEvents = append(allEvents, events...)

		if l.config.MaxEvents > 0 && len(allEvents) >= l.config.MaxEvents {
			allEvents = allEvents[:l.config.MaxEvents]
			break
		}
	}

	return allEvents, nil
}

// parseFile parses a single syscall trace file
func (l *LIDDSLoader) parseFile(filename string) ([]SyscallEvent, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var reader io.Reader = file

	// Handle gzipped files
	if strings.HasSuffix(filename, ".gz") {
		gzReader, err := gzip.NewReader(file)
		if err != nil {
			return nil, err
		}
		defer gzReader.Close()
		reader = gzReader
	}

	var events []SyscallEvent
	scanner := bufio.NewScanner(reader)

	// Increase buffer size for long lines
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		event, err := l.parseLine(line)
		if err != nil {
			// Skip malformed lines
			continue
		}

		events = append(events, event)
	}

	return events, scanner.Err()
}

// parseLine parses a single line of syscall trace
// Format: timestamp thread_id syscall_name(args) = return_value
func (l *LIDDSLoader) parseLine(line string) (SyscallEvent, error) {
	var event SyscallEvent

	// Parse timestamp
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 3 {
		return event, fmt.Errorf("invalid line format")
	}

	ts, err := strconv.ParseFloat(parts[0], 64)
	if err != nil {
		return event, err
	}
	event.Timestamp = time.Unix(int64(ts), int64((ts-float64(int64(ts)))*1e9))

	// Parse thread ID
	tid, err := strconv.Atoi(parts[1])
	if err != nil {
		return event, err
	}
	event.ThreadID = tid

	// Parse syscall and return value
	rest := parts[2]
	eqIdx := strings.LastIndex(rest, " = ")
	if eqIdx < 0 {
		return event, fmt.Errorf("no return value found")
	}

	syscallPart := rest[:eqIdx]
	retPart := strings.TrimSpace(rest[eqIdx+3:])

	// Parse return value
	retVal, _ := strconv.Atoi(retPart)
	event.ReturnValue = retVal

	// Parse syscall name and arguments
	parenIdx := strings.Index(syscallPart, "(")
	if parenIdx < 0 {
		event.SyscallName = syscallPart
	} else {
		event.SyscallName = syscallPart[:parenIdx]
		argsStr := syscallPart[parenIdx+1 : len(syscallPart)-1]
		event.Arguments = parseSyscallArgs(argsStr)
	}

	return event, nil
}

// parseSyscallArgs parses syscall arguments
func parseSyscallArgs(argsStr string) []string {
	if argsStr == "" {
		return nil
	}

	var args []string
	var current strings.Builder
	depth := 0
	inString := false

	for _, c := range argsStr {
		switch c {
		case '"':
			inString = !inString
			current.WriteRune(c)
		case '(':
			depth++
			current.WriteRune(c)
		case ')':
			depth--
			current.WriteRune(c)
		case ',':
			if depth == 0 && !inString {
				args = append(args, strings.TrimSpace(current.String()))
				current.Reset()
			} else {
				current.WriteRune(c)
			}
		default:
			current.WriteRune(c)
		}
	}

	if current.Len() > 0 {
		args = append(args, strings.TrimSpace(current.String()))
	}

	return args
}

// ConvertToWasmEvent converts a SyscallEvent to WasmSentinel event format
func (e *SyscallEvent) ConvertToWasmEvent() map[string]interface{} {
	return map[string]interface{}{
		"timestamp":   e.Timestamp.UnixNano(),
		"event_type":  "syscall",
		"syscall_nr":  e.SyscallNr,
		"syscall_name": e.SyscallName,
		"return_value": e.ReturnValue,
		"thread_id":   e.ThreadID,
		"arguments":   e.Arguments,
		"is_attack":   e.IsAttack,
	}
}

// ADFALDDataset represents the ADFA-LD dataset for Linux attacks
type ADFALDDataset struct {
	LocalPath string
}

// ADFALDLoader loads ADFA-LD dataset
type ADFALDLoader struct {
	config DatasetConfig
}

// NewADFALDLoader creates a new ADFA-LD loader
func NewADFALDLoader(config DatasetConfig) *ADFALDLoader {
	return &ADFALDLoader{config: config}
}

// LoadTraining loads training (normal) syscall traces
func (l *ADFALDLoader) LoadTraining() ([][]int, error) {
	return l.loadDirectory(filepath.Join(l.config.LocalPath, "ADFA-LD", "Training_Data_Master"))
}

// LoadAttack loads attack syscall traces
func (l *ADFALDLoader) LoadAttack(attackName string) ([][]int, error) {
	return l.loadDirectory(filepath.Join(l.config.LocalPath, "ADFA-LD", "Attack_Data_Master", attackName))
}

// LoadValidation loads validation (normal) syscall traces
func (l *ADFALDLoader) LoadValidation() ([][]int, error) {
	return l.loadDirectory(filepath.Join(l.config.LocalPath, "ADFA-LD", "Validation_Data_Master"))
}

func (l *ADFALDLoader) loadDirectory(path string) ([][]int, error) {
	files, err := filepath.Glob(filepath.Join(path, "*.txt"))
	if err != nil {
		return nil, err
	}

	var traces [][]int
	for _, file := range files {
		trace, err := l.loadTrace(file)
		if err != nil {
			continue
		}
		traces = append(traces, trace)
	}

	return traces, nil
}

func (l *ADFALDLoader) loadTrace(filename string) ([]int, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	parts := strings.Fields(string(data))
	var syscalls []int
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			continue
		}
		syscalls = append(syscalls, n)
	}

	return syscalls, nil
}

// SyntheticDataGenerator generates synthetic test events
type SyntheticDataGenerator struct {
	attackRatio float64
}

// NewSyntheticDataGenerator creates a new synthetic data generator
func NewSyntheticDataGenerator(attackRatio float64) *SyntheticDataGenerator {
	return &SyntheticDataGenerator{attackRatio: attackRatio}
}

// GenerateEvents generates synthetic events for testing
func (g *SyntheticDataGenerator) GenerateEvents(count int) []SyscallEvent {
	events := make([]SyscallEvent, count)

	normalSyscalls := []string{
		"read", "write", "open", "close", "stat", "fstat", "lstat",
		"poll", "lseek", "mmap", "mprotect", "munmap", "brk",
		"ioctl", "access", "pipe", "select", "sched_yield",
	}

	attackSyscalls := []string{
		"execve", "fork", "clone", "ptrace", "socket", "connect",
		"sendto", "recvfrom", "chmod", "chown", "setuid", "setgid",
	}

	attackCount := int(float64(count) * g.attackRatio)
	normalCount := count - attackCount

	// Generate normal events
	for i := 0; i < normalCount; i++ {
		events[i] = SyscallEvent{
			Timestamp:   time.Now().Add(time.Duration(i) * time.Millisecond),
			ThreadID:    1000 + (i % 10),
			SyscallName: normalSyscalls[i%len(normalSyscalls)],
			ReturnValue: 0,
			IsAttack:    false,
		}
	}

	// Generate attack events
	for i := 0; i < attackCount; i++ {
		events[normalCount+i] = SyscallEvent{
			Timestamp:   time.Now().Add(time.Duration(normalCount+i) * time.Millisecond),
			ThreadID:    2000 + (i % 5),
			SyscallName: attackSyscalls[i%len(attackSyscalls)],
			ReturnValue: 0,
			IsAttack:    true,
		}
	}

	return events
}

// DatasetStats holds statistics about a loaded dataset
type DatasetStats struct {
	TotalEvents   int
	NormalEvents  int
	AttackEvents  int
	UniqueSyscalls int
	Duration      time.Duration
}

// CalculateStats calculates statistics for a set of events
func CalculateStats(events []SyscallEvent) DatasetStats {
	stats := DatasetStats{
		TotalEvents: len(events),
	}

	if len(events) == 0 {
		return stats
	}

	syscallSet := make(map[string]struct{})
	for _, e := range events {
		syscallSet[e.SyscallName] = struct{}{}
		if e.IsAttack {
			stats.AttackEvents++
		} else {
			stats.NormalEvents++
		}
	}

	stats.UniqueSyscalls = len(syscallSet)
	stats.Duration = events[len(events)-1].Timestamp.Sub(events[0].Timestamp)

	return stats
}

// DownloadFile downloads a file from URL to local path
func DownloadFile(url, filepath string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

// DatasetInfo holds metadata about a dataset
type DatasetInfo struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	URL         string   `json:"url"`
	Citation    string   `json:"citation"`
	AttackTypes []string `json:"attack_types"`
	Size        string   `json:"size"`
}

// GetAvailableDatasets returns information about available datasets
func GetAvailableDatasets() []DatasetInfo {
	return []DatasetInfo{
		{
			Name:        "LID-DS 2021",
			Description: "Leipzig Intrusion Detection Dataset - Modern container-based attacks",
			URL:         "https://2021.2021.2021.2021/datasets/lid-ds-2021",
			Citation:    "Grimmer et al., LID-DS: A Dataset for Host-Based Intrusion Detection Systems, RAID 2021",
			AttackTypes: []string{"bruteforce", "sql_injection", "path_traversal", "file_upload", "buffer_overflow"},
			Size:        "~50GB",
		},
		{
			Name:        "ADFA-LD",
			Description: "Australian Defence Force Academy Linux Dataset - Syscall sequences",
			URL:         "https://research.unsw.edu.au/projects/adfa-ids-datasets",
			Citation:    "Creech and Hu, ADFA IDS Datasets, ACSW 2013",
			AttackTypes: []string{"hydra_ftp", "hydra_ssh", "adduser", "java_meterpreter", "meterpreter", "web_shell"},
			Size:        "~100MB",
		},
		{
			Name:        "CICIDS 2017",
			Description: "Canadian Institute for Cybersecurity IDS Dataset",
			URL:         "https://www.unb.ca/cic/datasets/ids-2017.html",
			Citation:    "Sharafaldin et al., CICIDS2017, ICISSP 2018",
			AttackTypes: []string{"dos", "ddos", "brute_force", "xss", "sql_injection", "infiltration", "botnet"},
			Size:        "~50GB",
		},
	}
}

// SaveEventsToJSON saves events to a JSON file for caching
func SaveEventsToJSON(events []SyscallEvent, filename string) error {
	data, err := json.MarshalIndent(events, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

// LoadEventsFromJSON loads cached events from JSON file
func LoadEventsFromJSON(filename string) ([]SyscallEvent, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var events []SyscallEvent
	if err := json.Unmarshal(data, &events); err != nil {
		return nil, err
	}

	return events, nil
}
