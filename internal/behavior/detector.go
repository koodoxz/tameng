/*
Package behavior implements advanced behavioral detection for SVALINN.

Ported from Node.js behavioral-detector.js (Phase 4+).
*/
package behavior

import (
	"net/http"
	"strings"
	"sync"
	"time"
)

// DetectorConfig controls behavioral detection thresholds.
type DetectorConfig struct {
	Enabled                      bool
	CleanupInterval              time.Duration
	CredentialStuffingThreshold  int
	APIEnumerationThreshold      int
	ScrapingThreshold            int
	ErrorRateThreshold           float64
	AlertScoreThreshold          float64
	BlockScoreThreshold          float64
	SuspiciousSessionThreshold   int
	TemporalAnomalyThreshold     int
	MaxTrackedEvents             int
	SessionWindow                time.Duration
	ShortWindow                  time.Duration
	MediumWindow                 time.Duration
	LongWindow                   time.Duration
}

// Alert represents a behavioral detection alert.
type Alert struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Severity    string                 `json:"severity"`
	Score       float64                `json:"score"`
	Description string                 `json:"description"`
	Evidence    map[string]interface{} `json:"evidence"`
}

// Detector performs behavioral analysis.
type Detector struct {
	config   DetectorConfig
	profiles sync.Map // map[string]*Profile
	stats    DetectorStats
	lock     sync.Mutex
	shutdown chan struct{}
}

// DetectorStats holds stats for the behavioral detector.
type DetectorStats struct {
	TotalAnalyzed   int64
	AlertsGenerated int64
	AlertsByType    map[string]int64
	TopAlertedIPs   map[string]int64
}

// Profile tracks behavioral data per IP.
type Profile struct {
	Events       []RequestEvent
	UserAgents   map[string]int
	SessionIDs   map[string]time.Time
	LastSeen     time.Time
	AlertCount   int
	FailedLogins int
}

// RequestEvent tracks a single request observation.
type RequestEvent struct {
	Timestamp    time.Time
	Path         string
	Status       int
	ResponseSize int
	SessionID    string
}

// NewDetector creates a new behavioral detector.
func NewDetector(cfg DetectorConfig) *Detector {
	if cfg.CleanupInterval == 0 {
		cfg.CleanupInterval = 5 * time.Minute
	}
	if cfg.CredentialStuffingThreshold == 0 {
		cfg.CredentialStuffingThreshold = 20
	}
	if cfg.APIEnumerationThreshold == 0 {
		cfg.APIEnumerationThreshold = 40
	}
	if cfg.ScrapingThreshold == 0 {
		cfg.ScrapingThreshold = 120
	}
	if cfg.ErrorRateThreshold == 0 {
		cfg.ErrorRateThreshold = 0.4
	}
	if cfg.AlertScoreThreshold == 0 {
		cfg.AlertScoreThreshold = 60
	}
	if cfg.BlockScoreThreshold == 0 {
		cfg.BlockScoreThreshold = 85
	}
	if cfg.SuspiciousSessionThreshold == 0 {
		cfg.SuspiciousSessionThreshold = 5
	}
	if cfg.TemporalAnomalyThreshold == 0 {
		cfg.TemporalAnomalyThreshold = 20
	}
	if cfg.MaxTrackedEvents == 0 {
		cfg.MaxTrackedEvents = 500
	}
	if cfg.SessionWindow == 0 {
		cfg.SessionWindow = 10 * time.Minute
	}
	if cfg.ShortWindow == 0 {
		cfg.ShortWindow = 1 * time.Minute
	}
	if cfg.MediumWindow == 0 {
		cfg.MediumWindow = 5 * time.Minute
	}
	if cfg.LongWindow == 0 {
		cfg.LongWindow = 1 * time.Hour
	}

	d := &Detector{
		config: cfg,
		stats: DetectorStats{
			AlertsByType:  make(map[string]int64),
			TopAlertedIPs: make(map[string]int64),
		},
		shutdown: make(chan struct{}),
	}

	if cfg.Enabled {
		go d.cleanupLoop()
	}

	return d
}

// AnalyzeRequest analyzes a request and returns an alert if detected.
func (d *Detector) AnalyzeRequest(r *http.Request, status int, responseSize int, sessionID string) *Alert {
	if !d.config.Enabled {
		return nil
	}

	ip := getClientIP(r)
	profile := d.getOrCreateProfile(ip)

	event := RequestEvent{
		Timestamp:    time.Now(),
		Path:         r.URL.Path,
		Status:       status,
		ResponseSize: responseSize,
		SessionID:    sessionID,
	}

	d.recordEvent(profile, event, r.UserAgent())
	d.lock.Lock()
	d.stats.TotalAnalyzed++
	d.lock.Unlock()

	if alert := d.detectCredentialStuffing(profile, r.URL.Path, status); alert != nil {
		d.recordAlert(ip, alert)
		return alert
	}
	if alert := d.detectAPIEnumeration(profile); alert != nil {
		d.recordAlert(ip, alert)
		return alert
	}
	if alert := d.detectScraping(profile); alert != nil {
		d.recordAlert(ip, alert)
		return alert
	}
	if alert := d.detectSessionAnomaly(profile); alert != nil {
		d.recordAlert(ip, alert)
		return alert
	}
	if alert := d.detectTemporalAnomaly(profile); alert != nil {
		d.recordAlert(ip, alert)
		return alert
	}
	if alert := d.detectErrorRate(profile); alert != nil {
		d.recordAlert(ip, alert)
		return alert
	}

	return nil
}

// GetStats returns current detector statistics.
func (d *Detector) GetStats() map[string]interface{} {
	tracked := 0
	d.profiles.Range(func(_, _ interface{}) bool {
		tracked++
		return true
	})

	d.lock.Lock()
	defer d.lock.Unlock()

	return map[string]interface{}{
		"total_analyzed":    d.stats.TotalAnalyzed,
		"alerts_generated":  d.stats.AlertsGenerated,
		"alerts_by_type":    d.stats.AlertsByType,
		"top_alerted_ips":   d.stats.TopAlertedIPs,
		"tracked_profiles":  tracked,
		"enabled":           d.config.Enabled,
		"alert_threshold":   d.config.AlertScoreThreshold,
		"block_threshold":   d.config.BlockScoreThreshold,
		"error_rate_limit":  d.config.ErrorRateThreshold,
		"session_threshold": d.config.SuspiciousSessionThreshold,
	}
}

func (d *Detector) getOrCreateProfile(ip string) *Profile {
	if val, exists := d.profiles.Load(ip); exists {
		return val.(*Profile)
	}

	profile := &Profile{
		Events:     make([]RequestEvent, 0, d.config.MaxTrackedEvents),
		UserAgents: make(map[string]int),
		SessionIDs: make(map[string]time.Time),
		LastSeen:   time.Now(),
	}

	actual, _ := d.profiles.LoadOrStore(ip, profile)
	return actual.(*Profile)
}

func (d *Detector) recordEvent(profile *Profile, event RequestEvent, userAgent string) {
	profile.Events = append(profile.Events, event)
	if len(profile.Events) > d.config.MaxTrackedEvents {
		profile.Events = profile.Events[len(profile.Events)-d.config.MaxTrackedEvents:]
	}

	if userAgent != "" {
		profile.UserAgents[userAgent]++
	}
	if event.SessionID != "" {
		profile.SessionIDs[event.SessionID] = event.Timestamp
	}

	profile.LastSeen = event.Timestamp
}

func (d *Detector) detectCredentialStuffing(profile *Profile, path string, status int) *Alert {
	if !isLoginPath(path) {
		return nil
	}
	if status != http.StatusUnauthorized && status != http.StatusForbidden && status != http.StatusBadRequest {
		return nil
	}

	failed := d.countEvents(profile, d.config.MediumWindow, func(ev RequestEvent) bool {
		return isLoginPath(ev.Path) && (ev.Status == http.StatusUnauthorized || ev.Status == http.StatusForbidden || ev.Status == http.StatusBadRequest)
	})

	if failed < d.config.CredentialStuffingThreshold {
		return nil
	}

	score := float64(failed) * 2.0
	severity := severityFromScore(score)
	return &Alert{
		ID:          "BEHAVIOR-RATE-001",
		Name:        "Credential Stuffing",
		Severity:    severity,
		Score:       minFloat(score, 100),
		Description: "Repeated failed login attempts",
		Evidence: map[string]interface{}{
			"failed_logins": failed,
			"window":        d.config.MediumWindow.String(),
		},
	}
}

func (d *Detector) detectAPIEnumeration(profile *Profile) *Alert {
	paths := d.uniquePaths(profile, d.config.ShortWindow, func(path string) bool {
		return strings.HasPrefix(path, "/api/")
	})

	if paths < d.config.APIEnumerationThreshold {
		return nil
	}

	score := 50.0 + float64(paths-d.config.APIEnumerationThreshold)
	return &Alert{
		ID:          "BEHAVIOR-RATE-002",
		Name:        "API Enumeration",
		Severity:    severityFromScore(score),
		Score:       minFloat(score, 100),
		Description: "High volume of unique API paths",
		Evidence: map[string]interface{}{
			"unique_paths": paths,
			"window":       d.config.ShortWindow.String(),
		},
	}
}

func (d *Detector) detectScraping(profile *Profile) *Alert {
	count := d.countEvents(profile, d.config.ShortWindow, func(_ RequestEvent) bool { return true })
	unique := d.uniquePaths(profile, d.config.ShortWindow, func(string) bool { return true })
	if count < d.config.ScrapingThreshold || unique < d.config.APIEnumerationThreshold {
		return nil
	}

	score := 60.0 + float64(count-d.config.ScrapingThreshold)/2
	return &Alert{
		ID:          "BEHAVIOR-RATE-003",
		Name:        "Aggressive Scraping",
		Severity:    severityFromScore(score),
		Score:       minFloat(score, 100),
		Description: "High request velocity with many unique paths",
		Evidence: map[string]interface{}{
			"requests":     count,
			"unique_paths": unique,
			"window":       d.config.ShortWindow.String(),
		},
	}
}

func (d *Detector) detectSessionAnomaly(profile *Profile) *Alert {
	threshold := d.config.SuspiciousSessionThreshold
	if threshold == 0 {
		return nil
	}

	now := time.Now()
	active := 0
	for _, seen := range profile.SessionIDs {
		if now.Sub(seen) <= d.config.SessionWindow {
			active++
		}
	}

	if active < threshold {
		return nil
	}

	score := 55.0 + float64(active-threshold)*5
	return &Alert{
		ID:          "BEHAVIOR-SESSION-001",
		Name:        "Suspicious Session Churn",
		Severity:    severityFromScore(score),
		Score:       minFloat(score, 100),
		Description: "High number of distinct sessions in short window",
		Evidence: map[string]interface{}{
			"distinct_sessions": active,
			"window":            d.config.SessionWindow.String(),
		},
	}
}

func (d *Detector) detectTemporalAnomaly(profile *Profile) *Alert {
	now := time.Now()
	if now.Hour() >= 5 {
		return nil
	}

	count := d.countEvents(profile, d.config.ShortWindow, func(_ RequestEvent) bool { return true })
	if count < d.config.TemporalAnomalyThreshold {
		return nil
	}

	score := 50.0 + float64(count-d.config.TemporalAnomalyThreshold)
	return &Alert{
		ID:          "BEHAVIOR-TEMP-001",
		Name:        "Off-hours Burst",
		Severity:    severityFromScore(score),
		Score:       minFloat(score, 100),
		Description: "High activity during off-hours",
		Evidence: map[string]interface{}{
			"requests": count,
			"hour":     now.Hour(),
		},
	}
}

func (d *Detector) detectErrorRate(profile *Profile) *Alert {
	window := d.config.MediumWindow
	total := d.countEvents(profile, window, func(_ RequestEvent) bool { return true })
	if total == 0 {
		return nil
	}

	errors := d.countEvents(profile, window, func(ev RequestEvent) bool {
		return ev.Status >= 400
	})

	rate := float64(errors) / float64(total)
	if rate < d.config.ErrorRateThreshold {
		return nil
	}

	score := 40.0 + rate*100
	return &Alert{
		ID:          "BEHAVIOR-RESP-001",
		Name:        "High Error Rate",
		Severity:    severityFromScore(score),
		Score:       minFloat(score, 100),
		Description: "Excessive error responses in short window",
		Evidence: map[string]interface{}{
			"error_rate": rate,
			"errors":     errors,
			"total":      total,
		},
	}
}

func (d *Detector) countEvents(profile *Profile, window time.Duration, match func(RequestEvent) bool) int {
	cutoff := time.Now().Add(-window)
	count := 0
	for _, ev := range profile.Events {
		if ev.Timestamp.Before(cutoff) {
			continue
		}
		if match(ev) {
			count++
		}
	}
	return count
}

func (d *Detector) uniquePaths(profile *Profile, window time.Duration, filter func(string) bool) int {
	cutoff := time.Now().Add(-window)
	unique := make(map[string]struct{})
	for _, ev := range profile.Events {
		if ev.Timestamp.Before(cutoff) {
			continue
		}
		if filter(ev.Path) {
			unique[ev.Path] = struct{}{}
		}
	}
	return len(unique)
}

func (d *Detector) recordAlert(ip string, alert *Alert) {
	d.lock.Lock()
	defer d.lock.Unlock()

	d.stats.AlertsGenerated++
	d.stats.AlertsByType[alert.ID]++
	d.stats.TopAlertedIPs[ip]++
}

func (d *Detector) cleanupLoop() {
	ticker := time.NewTicker(d.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			d.cleanup()
		case <-d.shutdown:
			return
		}
	}
}

func (d *Detector) cleanup() {
	cutoff := time.Now().Add(-d.config.LongWindow)
	d.profiles.Range(func(key, value interface{}) bool {
		profile := value.(*Profile)
		if profile.LastSeen.Before(cutoff) {
			d.profiles.Delete(key)
			return true
		}

		filtered := profile.Events[:0]
		for _, ev := range profile.Events {
			if ev.Timestamp.After(cutoff) {
				filtered = append(filtered, ev)
			}
		}
		profile.Events = filtered
		return true
	})
}

func isLoginPath(path string) bool {
	lower := strings.ToLower(path)
	return strings.Contains(lower, "login") || strings.Contains(lower, "signin") || strings.Contains(lower, "auth")
}

func severityFromScore(score float64) string {
	switch {
	case score >= 85:
		return "high"
	case score >= 70:
		return "medium"
	case score >= 50:
		return "low"
	default:
		return "info"
	}
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
