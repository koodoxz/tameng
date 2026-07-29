/*
Package semantic implements semantic payload analysis.
*/
package semantic

import (
	"regexp"
	"sync"
	"time"

	"github.com/aegis/svalinn/internal/scanbudget"
)

// AnalyzerConfig configures semantic analysis.
type AnalyzerConfig struct {
	Enabled        bool
	AlertThreshold float64
	BlockThreshold float64
}

// Analyzer detects semantic attack intent.
type Analyzer struct {
	config   AnalyzerConfig
	patterns map[string][]*regexp.Regexp
	stats    Stats
	lock     sync.Mutex
}

// Stats holds analyzer metrics.
type Stats struct {
	Analyzed       int64            `json:"analyzed"`
	Detections     int64            `json:"detections"`
	ByCategory     map[string]int64 `json:"by_category"`
	LastDetection  time.Time        `json:"last_detection"`
}

// Result captures analysis output.
type Result struct {
	Detected   bool              `json:"detected"`
	Categories []string          `json:"categories"`
	Score      float64           `json:"score"`
	Severity   string            `json:"severity"`
	Evidence   map[string][]string `json:"evidence"`
}

// NewAnalyzer creates a semantic analyzer.
func NewAnalyzer(cfg AnalyzerConfig) *Analyzer {
	if cfg.AlertThreshold == 0 {
		cfg.AlertThreshold = 60
	}
	if cfg.BlockThreshold == 0 {
		cfg.BlockThreshold = 85
	}

	patterns := map[string][]*regexp.Regexp{
		"exploit_intent": {
			regexp.MustCompile(`(?i)exploit|payload|shellcode|rop\s*chain`),
			regexp.MustCompile(`(?i)buffer\s*overflow|heap\s*spray|privilege\s*escalation`),
		},
		"evasion_intent": {
			regexp.MustCompile(`(?i)bypass|amsi|etw|unhook|sandbox`),
			regexp.MustCompile(`(?i)obfuscate|encrypt\s*payload|stager`),
		},
		"credential_abuse": {
			regexp.MustCompile(`(?i)credential\s*stuffing|bruteforce|password\s*spray`),
			regexp.MustCompile(`(?i)session\s*hijack|token\s*theft`),
		},
		"data_exfil": {
			regexp.MustCompile(`(?i)exfiltrate|data\s*leak|dump\s*database`),
			regexp.MustCompile(`(?i)collect\s*secrets|steal\s*keys`),
		},
	}

	return &Analyzer{
		config:   cfg,
		patterns: patterns,
		stats:    Stats{ByCategory: make(map[string]int64)},
	}
}

// analyzeBudget bounds the wall-clock time a single Analyze call may spend
// (REQ SVALINN-SCANBUDGET-001) -- see internal/detect/helpers.go's
// checkPatternsBudget for the full rationale; same fail-open design.
// ponytail: ceiling is 100ms, deliberately well above the ~4ms measured on
// dev hardware for an 8KiB benign body, to leave margin for the production
// VPS's independently-known ~6x slower single-thread throughput. Verify
// against real VPS timing before trusting further; lower only with real
// production benchmark data, not a guess.
const analyzeBudget = 100 * time.Millisecond

// Analyze inspects text for semantic intent.
func (a *Analyzer) Analyze(content string) *Result {
	return a.analyzeWithDeadline(content, time.Now().Add(analyzeBudget))
}

// analyzeWithDeadline is Analyze's real implementation, taking an explicit
// deadline so tests can force the budget-exceeded path deterministically.
// Category iteration order and each category's pattern order are shuffled
// per call so a budget cutoff can't deterministically favor evading the
// same patterns every request (REQ SVALINN-SCANBUDGET-001).
func (a *Analyzer) analyzeWithDeadline(content string, deadline time.Time) *Result {
	if !a.config.Enabled {
		return &Result{}
	}

	a.lock.Lock()
	a.stats.Analyzed++
	a.lock.Unlock()

	categories := make([]string, 0, len(a.patterns))
	for category := range a.patterns {
		categories = append(categories, category)
	}
	categoryOrder := scanbudget.ShuffledIndices(len(categories))

	result := &Result{Evidence: make(map[string][]string)}
	for _, ci := range categoryOrder {
		if time.Now().After(deadline) {
			break
		}
		category := categories[ci]
		patterns := a.patterns[category]
		matches := []string{}
		for _, pi := range scanbudget.ShuffledIndices(len(patterns)) {
			if time.Now().After(deadline) {
				break
			}
			found := patterns[pi].FindAllString(content, 3)
			if len(found) > 0 {
				matches = append(matches, found...)
			}
		}
		if len(matches) > 0 {
			result.Detected = true
			result.Categories = append(result.Categories, category)
			result.Evidence[category] = matches
			a.lock.Lock()
			a.stats.Detections++
			a.stats.ByCategory[category]++
			a.stats.LastDetection = time.Now()
			a.lock.Unlock()
		}
	}

	result.Score = float64(len(result.Categories)) * 30
	result.Severity = severityFromScore(result.Score)

	return result
}

// Stats returns analyzer stats.
func (a *Analyzer) Stats() map[string]interface{} {
	a.lock.Lock()
	defer a.lock.Unlock()

	return map[string]interface{}{
		"analyzed":        a.stats.Analyzed,
		"detections":      a.stats.Detections,
		"by_category":     a.stats.ByCategory,
		"last_detection":  a.stats.LastDetection,
		"alert_threshold": a.config.AlertThreshold,
		"block_threshold": a.config.BlockThreshold,
		"enabled":         a.config.Enabled,
	}
}

func severityFromScore(score float64) string {
	if score >= 80 {
		return "high"
	}
	if score >= 60 {
		return "medium"
	}
	return "low"
}
