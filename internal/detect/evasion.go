/*
Package detect includes evasion technique detection (Phase 4+).
*/
package detect

import (
	"regexp"
	"sync"

	"github.com/aegis/svalinn/internal/literalextract"
)

// EvasionConfig configures evasion detector thresholds.
type EvasionConfig struct {
	Enabled            bool
	AmsiThreshold      int
	EtwThreshold       int
	UnhookingThreshold int
	SandboxThreshold   int
	SyscallThreshold   int
	ModuleThreshold    int
	TimestampThreshold int
	AlertThreshold     float64
	BlockThreshold     float64
}

// EvasionDetector detects evasion techniques.
type EvasionDetector struct {
	config   EvasionConfig
	patterns map[string][]*regexp.Regexp
	// prefilter is built once here and read-only afterwards.
	// REQ SVALINN-DETECTPREFILTER-001.
	prefilter *literalextract.Groups
	mitreMap  map[string][]string
	stats     EvasionStats
	lock      sync.Mutex
}

// EvasionStats tracks detection stats.
type EvasionStats struct {
	Analyzed        int64            `json:"analyzed"`
	Detections      map[string]int64 `json:"detections"`
	TotalDetections int64            `json:"total_detections"`
}

// EvasionResult holds detection results.
type EvasionResult struct {
	Detected   bool             `json:"detected"`
	Techniques []string         `json:"techniques"`
	Confidence float64          `json:"confidence"`
	MitreIDs   []string         `json:"mitre_ids"`
	Evidence   []map[string]any `json:"evidence"`
}

// NewEvasionDetector creates a new evasion detector.
func NewEvasionDetector(cfg EvasionConfig) *EvasionDetector {
	if cfg.AmsiThreshold == 0 {
		cfg.AmsiThreshold = 35
	}
	if cfg.EtwThreshold == 0 {
		cfg.EtwThreshold = 30
	}
	if cfg.UnhookingThreshold == 0 {
		cfg.UnhookingThreshold = 40
	}
	if cfg.SandboxThreshold == 0 {
		cfg.SandboxThreshold = 25
	}
	if cfg.SyscallThreshold == 0 {
		cfg.SyscallThreshold = 45
	}
	if cfg.ModuleThreshold == 0 {
		cfg.ModuleThreshold = 35
	}
	if cfg.TimestampThreshold == 0 {
		cfg.TimestampThreshold = 30
	}
	if cfg.AlertThreshold == 0 {
		cfg.AlertThreshold = 70
	}
	if cfg.BlockThreshold == 0 {
		cfg.BlockThreshold = 75
	}

	patterns := map[string][]*regexp.Regexp{
		"amsiBypass": {
			regexp.MustCompile(`(?i)AmsiScanBuffer`),
			regexp.MustCompile(`(?i)AmsiScanString`),
			regexp.MustCompile(`(?i)AmsiInitFailed`),
			regexp.MustCompile(`(?i)amsi\.dll`),
			regexp.MustCompile(`(?i)AmsiContext`),
			regexp.MustCompile(`(?i)AmsiOpenSession`),
			regexp.MustCompile(`(?i)AmsiCloseSession`),
			regexp.MustCompile(`(?i)\\x41\\x6d\\x73\\x69`),
		},
		"etwPatch": {
			regexp.MustCompile(`(?i)EtwEventWrite`),
			regexp.MustCompile(`(?i)EtwEventRegister`),
			regexp.MustCompile(`(?i)EtwpEventWrite`),
			regexp.MustCompile(`(?i)NtTraceEvent`),
			regexp.MustCompile(`(?i)NtTraceControl`),
			regexp.MustCompile(`(?i)ntdll!Etw`),
		},
		"unhooking": {
			regexp.MustCompile(`(?i)NtProtectVirtualMemory`),
			regexp.MustCompile(`(?i)ZwProtectVirtualMemory`),
			regexp.MustCompile(`(?i)NtWriteVirtualMemory`),
			regexp.MustCompile(`(?i)GetModuleHandle.*ntdll`),
			regexp.MustCompile(`(?i)\\x4c\\x8b\\xd1\\xb8`),
			regexp.MustCompile(`(?i)syscall stub`),
			regexp.MustCompile(`(?i)unhook`),
		},
		"sandboxEvasion": {
			regexp.MustCompile(`(?i)GetTickCount(64)?`),
			regexp.MustCompile(`(?i)QueryPerformanceCounter`),
			regexp.MustCompile(`(?i)IsDebuggerPresent`),
			regexp.MustCompile(`(?i)CheckRemoteDebuggerPresent`),
			regexp.MustCompile(`(?i)NtQueryInformationProcess`),
			regexp.MustCompile(`(?i)NtQuerySystemInformation`),
			regexp.MustCompile(`(?i)GetSystemTimeAsFileTime`),
			regexp.MustCompile(`(?i)Sleep\s*\(\s*\d{4,}\s*\)`),
			regexp.MustCompile(`(?i)mouse_event`),
			regexp.MustCompile(`(?i)GetCursorPos`),
			regexp.MustCompile(`(?i)GetLastInputInfo`),
			regexp.MustCompile(`(?i)VMware|VirtualBox|QEMU|Sandbox`),
		},
		"directSyscall": {
			regexp.MustCompile(`(?i)syscall`),
			regexp.MustCompile(`(?i)sysenter`),
			regexp.MustCompile(`(?i)int\s+0x2e`),
			regexp.MustCompile(`(?i)int\s+0x80`),
			regexp.MustCompile(`(?i)NtAllocateVirtualMemory`),
			regexp.MustCompile(`(?i)NtCreateThreadEx`),
			regexp.MustCompile(`(?i)NtWriteVirtualMemory`),
			// Deliberately case-SENSITIVE (REQ SVALINN-EVASION-NTPATTERN-FP-001):
			// real Windows Nt*/Zw* syscall names are always exact PascalCase.
			// Under (?i) this matched "nt" + any two letters anywhere,
			// case-insensitive -- one of the most common trigrams in ordinary
			// text (e.g. "continue", "planted", "Content-Type"), making it an
			// unusable false-positive generator rather than a syscall detector.
			regexp.MustCompile(`Nt[A-Z][a-zA-Z]+`),
		},
		"moduleStomping": {
			regexp.MustCompile(`(?i)LoadLibrary.*\.(dll|exe)`),
			regexp.MustCompile(`(?i)MapViewOfFile`),
			regexp.MustCompile(`(?i)NtMapViewOfSection`),
			regexp.MustCompile(`(?i)RtlImageNtHeader`),
			regexp.MustCompile(`(?i)hollow`),
			regexp.MustCompile(`(?i)stomp`),
		},
		"timestampManipulation": {
			regexp.MustCompile(`(?i)SetFileTime`),
			regexp.MustCompile(`(?i)NtSetInformationFile`),
			regexp.MustCompile(`(?i)timestomp`),
			regexp.MustCompile(`(?i)FileBasicInfo`),
		},
	}

	return &EvasionDetector{
		config:    cfg,
		patterns:  patterns,
		prefilter: literalextract.NewGroups(patterns),
		mitreMap: map[string][]string{
			"amsiBypass":            {"T1562.001"},
			"etwPatch":              {"T1562.006"},
			"unhooking":             {"T1562.001"},
			"sandboxEvasion":        {"T1497"},
			"directSyscall":         {"T1106"},
			"moduleStomping":        {"T1055.001"},
			"timestampManipulation": {"T1070.006"},
		},
		stats: EvasionStats{Detections: make(map[string]int64)},
	}
}

// Analyze inspects data for evasion patterns.
func (e *EvasionDetector) Analyze(data string) *EvasionResult {
	if !e.config.Enabled {
		return &EvasionResult{}
	}

	e.lock.Lock()
	e.stats.Analyzed++
	e.lock.Unlock()

	result := &EvasionResult{
		Techniques: []string{},
		MitreIDs:   []string{},
		Evidence:   []map[string]any{},
	}

	score := 0.0
	checks := []struct {
		name      string
		threshold int
	}{
		{"amsiBypass", e.config.AmsiThreshold},
		{"etwPatch", e.config.EtwThreshold},
		{"unhooking", e.config.UnhookingThreshold},
		{"sandboxEvasion", e.config.SandboxThreshold},
		{"directSyscall", e.config.SyscallThreshold},
		{"moduleStomping", e.config.ModuleThreshold},
		{"timestampManipulation", e.config.TimestampThreshold},
	}

	// One combined Aho-Corasick pass for every category, before any regex
	// is evaluated. REQ SVALINN-DETECTPREFILTER-001.
	cand := e.prefilter.Candidates(data)

	for _, check := range checks {
		patterns := e.patterns[check.name]
		matches := checkPatternsFiltered(data, patterns, e.prefilter.Slice(cand, check.name))
		if len(matches) == 0 {
			continue
		}

		score += float64(check.threshold) * float64(minInt(len(matches), 2))
		result.Detected = true
		result.Techniques = append(result.Techniques, check.name)
		result.MitreIDs = append(result.MitreIDs, e.mitreMap[check.name]...)
		result.Evidence = append(result.Evidence, map[string]any{
			"technique":  check.name,
			"matchCount": len(matches),
			"patterns":   matches,
		})

		e.lock.Lock()
		e.stats.Detections[check.name]++
		e.lock.Unlock()
	}

	result.Confidence = minFloat(score, 100)
	result.MitreIDs = uniqueStrings(result.MitreIDs)

	if result.Detected {
		e.lock.Lock()
		e.stats.TotalDetections++
		e.lock.Unlock()
	}

	return result
}

// GetStats returns detector stats.
func (e *EvasionDetector) GetStats() map[string]interface{} {
	e.lock.Lock()
	defer e.lock.Unlock()

	detectionRate := "0%"
	if e.stats.Analyzed > 0 {
		detectionRate = formatPercent(float64(e.stats.TotalDetections) / float64(e.stats.Analyzed) * 100)
	}

	return map[string]interface{}{
		"analyzed":         e.stats.Analyzed,
		"detections":       e.stats.Detections,
		"total_detections": e.stats.TotalDetections,
		"detection_rate":   detectionRate,
		"enabled":          e.config.Enabled,
		"alert_threshold":  e.config.AlertThreshold,
		"block_threshold":  e.config.BlockThreshold,
	}
}
