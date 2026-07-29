/*
Package egress provides advanced egress protection.
*/
package egress

import (
	"math"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Config defines advanced egress settings.
type Config struct {
	Enabled                 bool
	BlockedCountries        []string
	AllowedCountries        []string
	GeofenceMode            string // block|alert|log
	VelocityWindow          time.Duration
	MaxBytesPerWindow       int
	MaxRequestsPerWindow    int
	VelocitySpikeMultiplier float64
	TrustedPackageHosts     []string
	MaxEncodedPayloadSize   int
	EntropyThreshold        float64
}

// Request captures outbound payload details.
type Request struct {
	Hostname string
	Path     string
	Method   string
	IP       string
	UserID   string
	Body     string
	BodySize int
}

// ThreatResult captures egress threats.
type ThreatResult struct {
	Type     string                 `json:"type"`
	Severity string                 `json:"severity"`
	Reason   string                 `json:"reason"`
	Details  map[string]interface{} `json:"details"`
}

// AnalysisResult captures overall analysis.
type AnalysisResult struct {
	Allowed bool           `json:"allowed"`
	Score   float64        `json:"score"`
	Threats []ThreatResult `json:"threats"`
}

// Engine handles egress analysis.
type Engine struct {
	config          Config
	highRiskTLD     map[string]string
	highRiskIPs     []ipRange
	userFlows       map[string]*flowState
	globalFlow      *flowState
	packageBaseline map[string]*packageBaseline
	secretPatterns  []secretPattern
	stats           Stats
	alerts          []ThreatResult
	lock            sync.Mutex
}

type ipRange struct {
	start   string
	end     string
	country string
}

type flowState struct {
	bytes       int
	requests    int
	windowStart time.Time
	baseline    flowBaseline
}

type flowBaseline struct {
	avgBytes    float64
	avgRequests float64
	samples     int
}

type packageBaseline struct {
	hosts     map[string]struct{}
	count     int
	firstSeen time.Time
}

type secretPattern struct {
	name    string
	pattern *regexp.Regexp
}

// Stats captures egress metrics.
type Stats struct {
	GeofenceBlocked    int64 `json:"geofence_blocked"`
	VelocityAlerts     int64 `json:"velocity_alerts"`
	SupplyChainAlerts  int64 `json:"supply_chain_alerts"`
	EncodedDataBlocked int64 `json:"encoded_data_blocked"`
	SecretsDetected    int64 `json:"secrets_detected"`
	TotalAnalyzed      int64 `json:"total_analyzed"`
}

// NewEngine constructs an egress engine.
func NewEngine(cfg Config) *Engine {
	if cfg.GeofenceMode == "" {
		cfg.GeofenceMode = "block"
	}
	if cfg.VelocityWindow == 0 {
		cfg.VelocityWindow = 1 * time.Minute
	}
	if cfg.MaxBytesPerWindow == 0 {
		cfg.MaxBytesPerWindow = 10 * 1024 * 1024
	}
	if cfg.MaxRequestsPerWindow == 0 {
		cfg.MaxRequestsPerWindow = 100
	}
	if cfg.VelocitySpikeMultiplier == 0 {
		cfg.VelocitySpikeMultiplier = 5
	}
	if cfg.MaxEncodedPayloadSize == 0 {
		cfg.MaxEncodedPayloadSize = 10000
	}
	if cfg.EntropyThreshold == 0 {
		cfg.EntropyThreshold = 4.5
	}
	if len(cfg.TrustedPackageHosts) == 0 {
		cfg.TrustedPackageHosts = []string{"registry.npmjs.org", "registry.yarnpkg.com", "github.com", "raw.githubusercontent.com", "api.github.com"}
	}

	engine := &Engine{
		config: cfg,
		highRiskTLD: map[string]string{
			".ru": "RU",
			".su": "RU",
			".cn": "CN",
			".hk": "HK",
			".kp": "KP",
			".ir": "IR",
			".by": "BY",
			".cu": "CU",
			".sy": "SY",
		},
		highRiskIPs: []ipRange{
			{start: "5.8.0.0", end: "5.8.255.255", country: "RU"},
			{start: "31.13.0.0", end: "31.13.255.255", country: "RU"},
			{start: "1.0.0.0", end: "1.0.63.255", country: "CN"},
			{start: "1.1.0.0", end: "1.1.255.255", country: "CN"},
		},
		userFlows:       make(map[string]*flowState),
		globalFlow:      &flowState{windowStart: time.Now()},
		packageBaseline: make(map[string]*packageBaseline),
		secretPatterns: []secretPattern{
			{name: "AWS Key", pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
			{name: "AWS Secret", pattern: regexp.MustCompile(`(?i)(?:aws)?.{0,10}[0-9a-zA-Z/+]{40}`)},
			{name: "GitHub Token", pattern: regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{36,}`)},
			{name: "Google API", pattern: regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)},
			{name: "Slack Token", pattern: regexp.MustCompile(`xox[baprs]-[0-9]{10,13}-[a-zA-Z0-9-]*`)},
			{name: "Stripe Key", pattern: regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`)},
			{name: "JWT", pattern: regexp.MustCompile(`eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*`)},
			{name: "Private Key", pattern: regexp.MustCompile(`-----BEGIN (RSA |EC )?PRIVATE KEY-----`)},
			{name: "Password Field", pattern: regexp.MustCompile(`"(password|passwd|pwd|secret)"\s*:\s*"[^"]+"`)},
		},
	}

	return engine
}

// Analyze inspects outbound traffic for egress threats.
func (e *Engine) Analyze(req Request) AnalysisResult {
	if !e.config.Enabled {
		return AnalysisResult{Allowed: true}
	}

	e.lock.Lock()
	e.stats.TotalAnalyzed++
	e.lock.Unlock()

	result := AnalysisResult{Allowed: true, Threats: []ThreatResult{}}

	if geoThreat := e.checkGeofence(req); geoThreat != nil {
		result.Threats = append(result.Threats, *geoThreat)
		result.Score += 40
		if e.config.GeofenceMode == "block" {
			result.Allowed = false
		}
	}

	if velocityThreat := e.checkVelocity(req); velocityThreat != nil {
		result.Threats = append(result.Threats, *velocityThreat)
		result.Score += 25
	}

	if supplyThreat := e.checkSupplyChain(req); supplyThreat != nil {
		result.Threats = append(result.Threats, *supplyThreat)
		result.Score += 35
	}

	if encodedThreat := e.checkEncoded(req); encodedThreat != nil {
		result.Threats = append(result.Threats, *encodedThreat)
		result.Score += 30
		if encodedThreat.Severity == "critical" {
			result.Allowed = false
		}
	}

	if secretThreat := e.checkSecretLeak(req); secretThreat != nil {
		result.Threats = append(result.Threats, *secretThreat)
		result.Score += 50
		result.Allowed = false
	}

	if len(result.Threats) > 0 {
		e.recordAlert(result.Threats...)
	}

	return result
}

// Stats returns egress stats.
func (e *Engine) Stats() map[string]interface{} {
	e.lock.Lock()
	defer e.lock.Unlock()

	return map[string]interface{}{
		"geofence_blocked":     e.stats.GeofenceBlocked,
		"velocity_alerts":      e.stats.VelocityAlerts,
		"supply_chain_alerts":  e.stats.SupplyChainAlerts,
		"encoded_data_blocked": e.stats.EncodedDataBlocked,
		"secrets_detected":     e.stats.SecretsDetected,
		"total_analyzed":       e.stats.TotalAnalyzed,
		"alerts_count":         len(e.alerts),
		"enabled":              e.config.Enabled,
		"geofence_mode":        e.config.GeofenceMode,
	}
}

// Alerts returns recent alerts.
func (e *Engine) Alerts(limit int) []ThreatResult {
	e.lock.Lock()
	defer e.lock.Unlock()
	if limit <= 0 || limit > len(e.alerts) {
		limit = len(e.alerts)
	}
	return append([]ThreatResult{}, e.alerts[len(e.alerts)-limit:]...)
}

func (e *Engine) recordAlert(alerts ...ThreatResult) {
	e.lock.Lock()
	defer e.lock.Unlock()
	e.alerts = append(e.alerts, alerts...)
	if len(e.alerts) > 1000 {
		e.alerts = e.alerts[len(e.alerts)-500:]
	}
}

func (e *Engine) checkGeofence(req Request) *ThreatResult {
	hostname := strings.ToLower(req.Hostname)
	if hostname == "" {
		return nil
	}

	for tld, country := range e.highRiskTLD {
		if strings.HasSuffix(hostname, tld) && containsCountry(e.config.BlockedCountries, country) {
			e.lock.Lock()
			e.stats.GeofenceBlocked++
			e.lock.Unlock()
			return &ThreatResult{
				Type:     "GEOFENCE",
				Severity: "high",
				Reason:   "High-risk TLD blocked",
				Details: map[string]interface{}{
					"tld":     tld,
					"country": country,
					"host":    hostname,
				},
			}
		}
	}

	if ipCountry := e.ipToCountry(hostname); ipCountry != "" && containsCountry(e.config.BlockedCountries, ipCountry) {
		e.lock.Lock()
		e.stats.GeofenceBlocked++
		e.lock.Unlock()
		return &ThreatResult{
			Type:     "GEOFENCE",
			Severity: "high",
			Reason:   "IP in blocked country",
			Details: map[string]interface{}{
				"country": ipCountry,
				"host":    hostname,
			},
		}
	}

	return nil
}

func (e *Engine) checkVelocity(req Request) *ThreatResult {
	userID := req.UserID
	if userID == "" {
		userID = req.IP
	}
	if userID == "" {
		userID = "global"
	}

	e.lock.Lock()
	defer e.lock.Unlock()

	state := e.userFlows[userID]
	if state == nil {
		state = &flowState{windowStart: time.Now()}
		e.userFlows[userID] = state
	}

	now := time.Now()
	if now.Sub(state.windowStart) > e.config.VelocityWindow {
		state.baseline.avgBytes = (state.baseline.avgBytes*float64(state.baseline.samples) + float64(state.bytes)) / float64(state.baseline.samples+1)
		state.baseline.avgRequests = (state.baseline.avgRequests*float64(state.baseline.samples) + float64(state.requests)) / float64(state.baseline.samples+1)
		state.baseline.samples++
		state.bytes = 0
		state.requests = 0
		state.windowStart = now
	}

	state.bytes += req.BodySize
	state.requests++

	if state.bytes > e.config.MaxBytesPerWindow {
		e.stats.VelocityAlerts++
		return &ThreatResult{
			Type:     "VELOCITY",
			Severity: "high",
			Reason:   "Data volume exceeded",
			Details: map[string]interface{}{
				"bytes":          state.bytes,
				"window_seconds": e.config.VelocityWindow.Seconds(),
			},
		}
	}

	if state.baseline.samples >= 3 && state.baseline.avgBytes > 0 {
		spike := float64(state.bytes) / state.baseline.avgBytes
		if spike >= e.config.VelocitySpikeMultiplier {
			e.stats.VelocityAlerts++
			return &ThreatResult{
				Type:     "VELOCITY",
				Severity: "critical",
				Reason:   "Velocity spike detected",
				Details: map[string]interface{}{
					"spike": spike,
					"bytes": state.bytes,
				},
			}
		}
	}

	return nil
}

func (e *Engine) checkSupplyChain(req Request) *ThreatResult {
	hostname := req.Hostname
	path := req.Path
	module := req.UserID
	if module == "" {
		module = "unknown"
	}

	isPackageHost := false
	for _, host := range e.config.TrustedPackageHosts {
		if strings.Contains(hostname, host) {
			isPackageHost = true
			break
		}
	}

	e.lock.Lock()
	defer e.lock.Unlock()

	baseline := e.packageBaseline[module]
	if baseline == nil {
		baseline = &packageBaseline{hosts: make(map[string]struct{}), firstSeen: time.Now()}
		e.packageBaseline[module] = baseline
	}

	if isPackageHost {
		baseline.hosts[hostname] = struct{}{}
		baseline.count++
		return nil
	}

	if len(baseline.hosts) > 0 {
		onlyPackages := true
		for host := range baseline.hosts {
			if !containsHost(e.config.TrustedPackageHosts, host) {
				onlyPackages = false
				break
			}
		}
		if onlyPackages {
			e.stats.SupplyChainAlerts++
			return &ThreatResult{
				Type:     "SUPPLY_CHAIN",
				Severity: "high",
				Reason:   "Module accessing non-package host",
				Details:  map[string]interface{}{"host": hostname, "path": path, "module": module},
			}
		}
	}

	if regexp.MustCompile(`(?i)/(node_modules|package|dist|bundle)`).MatchString(path) {
		e.stats.SupplyChainAlerts++
		return &ThreatResult{
			Type:     "SUPPLY_CHAIN",
			Severity: "medium",
			Reason:   "Package-like path to non-registry host",
			Details:  map[string]interface{}{"host": hostname, "path": path},
		}
	}

	return nil
}

func (e *Engine) checkEncoded(req Request) *ThreatResult {
	body := req.Body
	if len(body) < 100 {
		return nil
	}

	base64Pattern := regexp.MustCompile(`[A-Za-z0-9+/=]{100,}`)
	matches := base64Pattern.FindAllString(body, -1)
	for _, match := range matches {
		if len(match) > e.config.MaxEncodedPayloadSize {
			e.lock.Lock()
			e.stats.EncodedDataBlocked++
			e.lock.Unlock()
			return &ThreatResult{
				Type:     "ENCODED_DATA",
				Severity: "high",
				Reason:   "Large Base64 payload detected",
				Details:  map[string]interface{}{"length": len(match)},
			}
		}
	}

	entropy := calculateEntropy(body)
	if entropy > e.config.EntropyThreshold && len(body) > 500 {
		return &ThreatResult{
			Type:     "ENCODED_DATA",
			Severity: "medium",
			Reason:   "High entropy payload",
			Details:  map[string]interface{}{"entropy": entropy},
		}
	}

	return nil
}

func (e *Engine) checkSecretLeak(req Request) *ThreatResult {
	body := req.Body
	if body == "" {
		return nil
	}

	secrets := []map[string]interface{}{}
	for _, secret := range e.secretPatterns {
		if matches := secret.pattern.FindAllString(body, 2); len(matches) > 0 {
			secrets = append(secrets, map[string]interface{}{
				"type":  secret.name,
				"count": len(matches),
			})
		}
	}

	if len(secrets) == 0 {
		return nil
	}

	e.lock.Lock()
	e.stats.SecretsDetected++
	e.lock.Unlock()
	return &ThreatResult{
		Type:     "SECRET_LEAK",
		Severity: "critical",
		Reason:   "Potential secret leak detected",
		Details: map[string]interface{}{
			"secrets": secrets,
			"host":    req.Hostname,
		},
	}
}

func (e *Engine) ipToCountry(ip string) string {
	for _, r := range e.highRiskIPs {
		if ipInRange(ip, r.start, r.end) {
			return r.country
		}
	}
	return ""
}

func ipInRange(ip string, start string, end string) bool {
	ipNum := ipToNumber(ip)
	if ipNum == 0 {
		return false
	}
	return ipNum >= ipToNumber(start) && ipNum <= ipToNumber(end)
}

func ipToNumber(ip string) uint32 {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return 0
	}
	var num uint32
	for _, part := range parts {
		value := 0
		for _, ch := range part {
			if ch < '0' || ch > '9' {
				return 0
			}
			value = value*10 + int(ch-'0')
		}
		num = (num << 8) + uint32(value)
	}
	return num
}

func calculateEntropy(input string) float64 {
	if len(input) == 0 {
		return 0
	}

	freq := make(map[rune]int)
	for _, ch := range input {
		freq[ch]++
	}

	entropy := 0.0
	length := float64(len(input))
	for _, count := range freq {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}

	return entropy
}

func containsCountry(list []string, country string) bool {
	for _, entry := range list {
		if strings.EqualFold(entry, country) {
			return true
		}
	}
	return false
}

func containsHost(list []string, host string) bool {
	for _, entry := range list {
		if strings.Contains(host, entry) {
			return true
		}
	}
	return false
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]struct{})
	unique := make([]string, 0, len(values))
	for _, val := range values {
		if _, ok := seen[val]; ok {
			continue
		}
		seen[val] = struct{}{}
		unique = append(unique, val)
	}
	sort.Strings(unique)
	return unique
}
