/*
Package preattack implements pre-attack signal detection

Detects reconnaissance, port scanning, and other pre-attack indicators
*/
package preattack

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/koodoxz/tameng/internal/netutil"
)

// Detector detects pre-attack signals
type Detector struct {
	scanPatterns sync.Map // IP -> *ScanPattern
	dnsQueries   sync.Map // Domain -> []Query
	config       Config
}

// Config holds detector configuration
type Config struct {
	Enabled              bool
	ReconThreshold       int
	PortScanWindow       time.Duration
	DNSEnumThreshold     int
	SuspiciousPathsCount int
}

// ScanPattern tracks potential scanning behavior
type ScanPattern struct {
	IP               string
	FirstSeen        time.Time
	LastSeen         time.Time
	RequestCount     int
	UniquePathstried []string
	SequentialPaths  bool
	RapidRequests    bool
	SuspiciousPaths  []string
	NotFoundCount    int
}

// Result contains detection results
type Result struct {
	IsRecon           bool
	IsPortScan        bool
	IsDNSEnum         bool
	IsPathEnum        bool
	Score             float64
	Indicators        []string
	RecommendedAction string
}

// NewDetector creates a new pre-attack detector
func NewDetector(cfg Config) *Detector {
	if cfg.ReconThreshold == 0 {
		cfg.ReconThreshold = 20
	}
	if cfg.PortScanWindow == 0 {
		cfg.PortScanWindow = 1 * time.Minute
	}
	if cfg.DNSEnumThreshold == 0 {
		cfg.DNSEnumThreshold = 10
	}
	if cfg.SuspiciousPathsCount == 0 {
		cfg.SuspiciousPathsCount = 5
	}

	return &Detector{
		config: cfg,
	}
}

// Analyze analyzes request for pre-attack signals
func (d *Detector) Analyze(r *http.Request) *Result {
	result := &Result{
		Indicators: []string{},
	}

	if !d.config.Enabled {
		return result
	}

	ip := getClientIP(r)
	path := r.URL.Path

	// Get or create scan pattern
	patternVal, exists := d.scanPatterns.Load(ip)
	var pattern *ScanPattern

	if !exists {
		pattern = &ScanPattern{
			IP:               ip,
			FirstSeen:        time.Now(),
			UniquePathstried: []string{},
			SuspiciousPaths:  []string{},
		}
		d.scanPatterns.Store(ip, pattern)
	} else {
		pattern = patternVal.(*ScanPattern)
	}

	// Update pattern
	pattern.LastSeen = time.Now()
	pattern.RequestCount++
	pattern.UniquePathstried = append(pattern.UniquePathstried, path)

	// 1. Detect reconnaissance (many 404s)
	if r.Context().Value("status") == 404 {
		pattern.NotFoundCount++
	}

	if pattern.NotFoundCount > d.config.ReconThreshold {
		result.IsRecon = true
		result.Indicators = append(result.Indicators, "excessive_404s")
	}

	// 2. Detect path enumeration
	if len(pattern.UniquePathstried) > d.config.SuspiciousPathsCount {
		result.IsPathEnum = true
		result.Indicators = append(result.Indicators, "path_enumeration")
	}

	// 3. Detect rapid sequential requests (automation)
	timeSinceFirst := pattern.LastSeen.Sub(pattern.FirstSeen)
	if timeSinceFirst < d.config.PortScanWindow && pattern.RequestCount > 50 {
		pattern.RapidRequests = true
		result.Indicators = append(result.Indicators, "rapid_requests")
	}

	// 4. Check for suspicious paths
	suspiciousPaths := []string{
		"/.git", "/.env", "/.aws", "/.ssh",
		"/admin", "/phpmyadmin", "/wp-admin",
		"/config", "/backup", "/test",
		"/.well-known", "/robots.txt", "/sitemap.xml",
	}

	for _, susPath := range suspiciousPaths {
		if strings.Contains(path, susPath) {
			pattern.SuspiciousPaths = append(pattern.SuspiciousPaths, path)
		}
	}

	if len(pattern.SuspiciousPaths) >= 3 {
		result.IsRecon = true
		result.Indicators = append(result.Indicators, "suspicious_path_probing")
	}

	// 5. Sequential path testing (1, 2, 3, 4...)
	if d.detectSequentialPaths(pattern.UniquePathstried) {
		pattern.SequentialPaths = true
		result.Indicators = append(result.Indicators, "sequential_enumeration")
	}

	// Calculate score
	score := 0.0
	if result.IsRecon {
		score += 0.4
	}
	if result.IsPathEnum {
		score += 0.3
	}
	if pattern.RapidRequests {
		score += 0.2
	}
	if pattern.SequentialPaths {
		score += 0.1
	}

	result.Score = score

	// Determine action
	if score >= 0.7 {
		result.RecommendedAction = "BLOCK"
	} else if score >= 0.4 {
		result.RecommendedAction = "MONITOR"
	} else {
		result.RecommendedAction = "ALLOW"
	}

	return result
}

// detectSequentialPaths detects sequential path testing
func (d *Detector) detectSequentialPaths(paths []string) bool {
	if len(paths) < 5 {
		return false
	}

	// Check last 5 paths for numeric sequences
	recent := paths[len(paths)-5:]
	sequential := 0

	for i := 0; i < len(recent)-1; i++ {
		// Simple heuristic: check if paths differ by single digit
		if d.pathsDifferBySingleChar(recent[i], recent[i+1]) {
			sequential++
		}
	}

	return sequential >= 3
}

// pathsDifferBySingleChar checks if two paths differ by a single character
func (d *Detector) pathsDifferBySingleChar(a, b string) bool {
	if len(a) != len(b) {
		return false
	}

	diff := 0
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			diff++
		}
	}

	return diff == 1
}

// GetStats returns detector statistics
func (d *Detector) GetStats() map[string]interface{} {
	trackedIPs := 0
	reconDetected := 0

	d.scanPatterns.Range(func(_, val interface{}) bool {
		trackedIPs++
		pattern := val.(*ScanPattern)
		if pattern.NotFoundCount > d.config.ReconThreshold {
			reconDetected++
		}
		return true
	})

	return map[string]interface{}{
		"tracked_ips":    trackedIPs,
		"recon_detected": reconDetected,
		"enabled":        d.config.Enabled,
	}
}

// Helper
// getClientIP resolves the request's client address, which keys the scan
// patterns behind recon and path-enumeration detection. Trust decisions live in
// netutil (REQ SVALINN-CLIENTIP-SPOOF-002): only the local nginx peer may speak
// for another address, so a scanner cannot rotate a forged header to stay under
// the recon thresholds.
func getClientIP(r *http.Request) string {
	return netutil.TrustedClientIP(r)
}
