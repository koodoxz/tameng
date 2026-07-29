/*
Package logic implements business logic abuse detection.
*/
package logic

import (
	"net/http"
	"strings"
	"sync"
	"time"
)

// AbuseConfig controls abuse detection.
type AbuseConfig struct {
	Enabled           bool
	Mode              string // detect|block|challenge
	FlowWindow        time.Duration
	MaxActions        int
	MaxSensitiveHits  int
	SensitivePaths    []string
	CleanupInterval   time.Duration
}

// AbuseDetector tracks request flows for abuse.
type AbuseDetector struct {
	config    AbuseConfig
	flows     map[string]*flowState
	stats     AbuseStats
	lock      sync.Mutex
}

type flowState struct {
	firstSeen time.Time
	lastSeen  time.Time
	actions   []flowAction
}

type flowAction struct {
	timestamp time.Time
	path      string
	method    string
	status    int
}

// AbuseStats tracks detector metrics.
type AbuseStats struct {
	FlowsTracked int64            `json:"flows_tracked"`
	AbuseDetected int64           `json:"abuse_detected"`
	Blocked      int64            `json:"blocked"`
	ByReason     map[string]int64 `json:"by_reason"`
}

// AbuseResult represents detected abuse.
type AbuseResult struct {
	Detected bool     `json:"detected"`
	Severity string   `json:"severity"`
	Reasons  []string `json:"reasons"`
}

// NewAbuseDetector creates a new detector.
func NewAbuseDetector(cfg AbuseConfig) *AbuseDetector {
	if cfg.FlowWindow == 0 {
		cfg.FlowWindow = 5 * time.Minute
	}
	if cfg.MaxActions == 0 {
		cfg.MaxActions = 120
	}
	if cfg.MaxSensitiveHits == 0 {
		cfg.MaxSensitiveHits = 15
	}
	if cfg.Mode == "" {
		cfg.Mode = "detect"
	}
	if cfg.CleanupInterval == 0 {
		cfg.CleanupInterval = 2 * time.Minute
	}

	detector := &AbuseDetector{
		config: cfg,
		flows:  make(map[string]*flowState),
		stats: AbuseStats{ByReason: make(map[string]int64)},
	}

	if cfg.Enabled {
		go detector.cleanupLoop()
	}

	return detector
}

// Track records an action and detects abuse.
func (d *AbuseDetector) Track(sessionID string, r *http.Request, status int) *AbuseResult {
	if !d.config.Enabled {
		return &AbuseResult{}
	}
	if sessionID == "" {
		sessionID = "anonymous"
	}

	d.lock.Lock()
	defer d.lock.Unlock()

	flow := d.flows[sessionID]
	if flow == nil {
		flow = &flowState{firstSeen: time.Now(), lastSeen: time.Now()}
		d.flows[sessionID] = flow
		d.stats.FlowsTracked++
	}

	action := flowAction{timestamp: time.Now(), path: r.URL.Path, method: r.Method, status: status}
	flow.actions = append(flow.actions, action)
	flow.lastSeen = time.Now()

	cutoff := time.Now().Add(-d.config.FlowWindow)
	filtered := flow.actions[:0]
	for _, act := range flow.actions {
		if act.timestamp.After(cutoff) {
			filtered = append(filtered, act)
		}
	}
	flow.actions = filtered

	return d.detect(flow)
}

// Stats returns detector stats.
func (d *AbuseDetector) Stats() map[string]interface{} {
	d.lock.Lock()
	defer d.lock.Unlock()

	return map[string]interface{}{
		"flows_tracked": d.stats.FlowsTracked,
		"abuse_detected": d.stats.AbuseDetected,
		"blocked":       d.stats.Blocked,
		"by_reason":     d.stats.ByReason,
		"enabled":       d.config.Enabled,
		"mode":          d.config.Mode,
	}
}

func (d *AbuseDetector) detect(flow *flowState) *AbuseResult {
	result := &AbuseResult{Detected: false, Severity: "low", Reasons: []string{}}

	if len(flow.actions) >= d.config.MaxActions {
		result.Detected = true
		result.Severity = "high"
		result.Reasons = append(result.Reasons, "excessive_actions")
		d.stats.AbuseDetected++
		d.stats.ByReason["excessive_actions"]++
	}

	sensitiveHits := 0
	for _, act := range flow.actions {
		if isSensitivePath(act.path, d.config.SensitivePaths) {
			sensitiveHits++
		}
	}
	if sensitiveHits >= d.config.MaxSensitiveHits {
		result.Detected = true
		if result.Severity == "low" {
			result.Severity = "medium"
		}
		result.Reasons = append(result.Reasons, "sensitive_path_abuse")
		d.stats.AbuseDetected++
		d.stats.ByReason["sensitive_path_abuse"]++
	}

	return result
}

func (d *AbuseDetector) cleanupLoop() {
	ticker := time.NewTicker(d.config.CleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		cutoff := time.Now().Add(-d.config.FlowWindow * 2)
		d.lock.Lock()
		for key, flow := range d.flows {
			if flow.lastSeen.Before(cutoff) {
				delete(d.flows, key)
			}
		}
		d.lock.Unlock()
	}
}

func isSensitivePath(path string, patterns []string) bool {
	if len(patterns) == 0 {
		patterns = []string{"/admin", "/billing", "/checkout", "/password", "/token", "/api/v9"}
	}

	for _, pattern := range patterns {
		if strings.HasPrefix(path, pattern) {
			return true
		}
	}
	return false
}
