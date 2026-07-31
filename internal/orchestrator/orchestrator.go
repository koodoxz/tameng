/*
Package orchestrator implements the Active Defense Orchestrator.

Ported from Node.js active-defense-orchestrator.js (690 lines)
Coordinates all defense mechanisms based on:
- Kill chain stage progression
- Behavioral fingerprints (JA3/JA4)
- Cross-session actor correlation
- Threat intelligence feeds
*/
package orchestrator

import (
	"net/http"
	"sync"
	"time"

	"github.com/koodoxz/tameng/internal/actor"
	"github.com/koodoxz/tameng/internal/fingerprint"
)

// Countermeasure types
type Countermeasure string

const (
	Monitor   Countermeasure = "monitor"
	Challenge Countermeasure = "challenge"
	Tarpit    Countermeasure = "tarpit"
	Honeypot  Countermeasure = "honeypot"
	Block     Countermeasure = "block"
	Blackhole Countermeasure = "blackhole"
	Isolate   Countermeasure = "isolate"
)

// Kill Chain Stages
type KillChainStage string

const (
	Reconnaissance      KillChainStage = "Reconnaissance"
	Weaponization       KillChainStage = "Weaponization"
	Delivery            KillChainStage = "Delivery"
	Exploitation        KillChainStage = "Exploitation"
	Installation        KillChainStage = "Installation"
	CommandControl      KillChainStage = "Command & Control"
	ActionsOnObjectives KillChainStage = "Actions on Objectives"
)

// StageAction defines the action for each kill chain stage
type StageAction struct {
	Action      Countermeasure
	Delay       time.Duration
	Description string
}

// Stage action mappings
var StageActions = map[KillChainStage]StageAction{
	Reconnaissance: {
		Action:      Monitor,
		Delay:       0,
		Description: "Silent monitoring, collect intel",
	},
	Weaponization: {
		Action:      Challenge,
		Delay:       500 * time.Millisecond,
		Description: "Inject PoW challenge or CAPTCHA",
	},
	Delivery: {
		Action:      Tarpit,
		Delay:       2 * time.Second,
		Description: "Slow down responses",
	},
	Exploitation: {
		Action:      Honeypot,
		Delay:       1 * time.Second,
		Description: "Redirect to honeypot with fake data",
	},
	Installation: {
		Action:      Block,
		Delay:       0,
		Description: "Block request, log extensively",
	},
	CommandControl: {
		Action:      Blackhole,
		Delay:       0,
		Description: "Black hole all traffic",
	},
	ActionsOnObjectives: {
		Action:      Isolate,
		Delay:       0,
		Description: "Full isolation + alert",
	},
}

// Orchestrator coordinates active defense responses
type Orchestrator struct {
	reserseTracker        *actor.ReserseTracker
	fingerprinter         *fingerprint.Engine
	killChain             *KillChainStateMachine
	activeCountermeasures map[string]Countermeasure
	blockedIPs            map[string]time.Time
	ja3Clusters           map[string]map[string]struct{}
	lock                  sync.RWMutex

	// Configuration
	config Config

	// Statistics
	stats Stats
}

// Config holds orchestrator configuration
type Config struct {
	Enabled       bool
	AutoEscalate  bool
	TarpitDelay   time.Duration
	HoneypotPath  string
	BlockDuration time.Duration
}

// Stats holds orchestrator statistics
type Stats struct {
	Processed          int64
	Monitored          int64
	Challenged         int64
	Tarpitted          int64
	Honeypotted        int64
	Blocked            int64
	Blackholed         int64
	Isolated           int64
	JA3Clustered       int64
	CrossSessionLinked int64
}

// Result represents the orchestration result
type Result struct {
	IP                string
	Timestamp         time.Time
	Action            string
	Reason            string
	KillChainStage    KillChainStage
	JA3               string
	JA3Family         string
	ThreatScore       float64
	CrossSessionMatch bool
	Countermeasure    Countermeasure
	ProcessingTimeMs  int64
	Delay             time.Duration
	ChallengeToken    string
	RedirectPath      string
}

// NewOrchestrator creates a new active defense orchestrator
func NewOrchestrator(reserseTracker *actor.ReserseTracker, fingerprinter *fingerprint.Engine, cfg Config) *Orchestrator {
	if cfg.BlockDuration == 0 {
		cfg.BlockDuration = 1 * time.Hour
	}
	if cfg.TarpitDelay == 0 {
		cfg.TarpitDelay = 2 * time.Second
	}
	if cfg.HoneypotPath == "" {
		cfg.HoneypotPath = "/observatory"
	}

	return &Orchestrator{
		reserseTracker:        reserseTracker,
		fingerprinter:         fingerprinter,
		killChain:             NewKillChainStateMachine(),
		activeCountermeasures: make(map[string]Countermeasure),
		blockedIPs:            make(map[string]time.Time),
		ja3Clusters:           make(map[string]map[string]struct{}),
		config:                cfg,
	}
}

// Orchestrate processes a request and determines countermeasure
func (o *Orchestrator) Orchestrate(r *http.Request, clientIP string) *Result {
	if !o.config.Enabled {
		return &Result{
			Action: "pass",
			Reason: "orchestrator disabled",
		}
	}

	o.stats.Processed++
	startTime := time.Now()

	result := &Result{
		IP:        clientIP,
		Timestamp: time.Now(),
		Action:    "pass",
	}

	// Check if already blocked
	if o.isBlocked(clientIP) {
		result.Action = "blocked"
		result.Reason = "ip_blocked"
		result.ProcessingTimeMs = time.Since(startTime).Milliseconds()
		return result
	}

	// Fingerprint analysis
	fp := o.fingerprinter.GenerateHTTPFingerprint(r)
	if fp != nil {
		result.JA3 = fp.Hash
		if fp.Suspicious {
			result.ThreatScore += 30
		}
	}

	if fp != nil {
		o.clusterJA3(clientIP, fp.Hash)
	}

	// Detect attack technique
	technique := detectTechnique(r)
	if technique != "" {
		state := o.killChain.DetectTechnique(technique, clientIP)
		if state != nil {
			result.KillChainStage = state.Stage
			result.ThreatScore += 25
		}

		// Track in Reserse
		if o.reserseTracker != nil {
			event := actor.TimelineEvent{
				Timestamp:   time.Now(),
				EventType:   "attack",
				Description: technique,
				IP:          clientIP,
				Path:        r.URL.Path,
				Signature:   technique,
			}
			fpHash := ""
			if fp != nil {
				fpHash = fp.Hash
			}
			o.reserseTracker.Track(clientIP, fpHash, event)
		}
	} else {
		state := o.killChain.GetOrCreateState(clientIP)
		result.KillChainStage = state.Stage
	}

	// Cross-session correlation via JA3
	if fp != nil {
		if o.isCrossSession(fp.Hash, clientIP) {
			result.CrossSessionMatch = true
			result.ThreatScore += 20
			o.stats.CrossSessionLinked++
		}
	}

	// Determine countermeasure
	countermeasure := o.determineCountermeasure(clientIP, result)
	result.Countermeasure = countermeasure

	// Execute countermeasure
	o.executeCountermeasure(countermeasure, result)

	result.ProcessingTimeMs = time.Since(startTime).Milliseconds()
	return result
}

// determineCountermeasure decides appropriate action
func (o *Orchestrator) determineCountermeasure(ip string, result *Result) Countermeasure {
	o.lock.RLock()
	defer o.lock.RUnlock()

	// Check existing countermeasure
	if existing, ok := o.activeCountermeasures[ip]; ok {
		return existing
	}

	// Based on kill chain stage
	if stageAction, ok := StageActions[result.KillChainStage]; ok {
		// Escalate based on threat score
		if result.ThreatScore >= 80 {
			return Block
		} else if result.ThreatScore >= 60 {
			return Honeypot
		} else if result.ThreatScore >= 40 {
			return Tarpit
		}
		return stageAction.Action
	}

	// Default based on threat score alone
	if result.ThreatScore >= 80 {
		return Block
	} else if result.ThreatScore >= 50 {
		return Tarpit
	} else if result.ThreatScore >= 30 {
		return Challenge
	}

	return Monitor
}

// executeCountermeasure applies the determined action
func (o *Orchestrator) executeCountermeasure(action Countermeasure, result *Result) {
	switch action {
	case Monitor:
		result.Action = "pass"
		result.Reason = "monitoring"
		o.stats.Monitored++

	case Challenge:
		result.Action = "challenge"
		result.Reason = "proof_of_work_required"
		result.ChallengeToken = generateChallengeToken()
		o.stats.Challenged++

	case Tarpit:
		result.Action = "tarpit"
		result.Reason = "response_delayed"
		result.Delay = o.config.TarpitDelay
		o.stats.Tarpitted++

	case Honeypot:
		result.Action = "honeypot"
		result.Reason = "redirected_to_honeypot"
		result.RedirectPath = o.config.HoneypotPath
		o.stats.Honeypotted++

	case Block:
		result.Action = "block"
		result.Reason = "blocked_by_active_defense"
		o.blockIP(result.IP, o.config.BlockDuration)
		o.stats.Blocked++

	case Blackhole:
		result.Action = "blackhole"
		result.Reason = "traffic_blackholed"
		o.blockIP(result.IP, o.config.BlockDuration*24)
		o.stats.Blackholed++

	case Isolate:
		result.Action = "isolate"
		result.Reason = "fully_isolated"
		o.blockIP(result.IP, 365*24*time.Hour) // 1 year
		o.stats.Isolated++

	default:
		result.Action = "pass"
		result.Reason = "default_pass"
	}
}

// blockIP blocks an IP for specified duration
func (o *Orchestrator) blockIP(ip string, duration time.Duration) {
	o.lock.Lock()
	defer o.lock.Unlock()
	o.blockedIPs[ip] = time.Now().Add(duration)
}

// isBlocked checks if IP is currently blocked
func (o *Orchestrator) isBlocked(ip string) bool {
	o.lock.RLock()
	defer o.lock.RUnlock()

	if expiry, ok := o.blockedIPs[ip]; ok {
		if time.Now().Before(expiry) {
			return true
		}
		// Expired, clean up
		o.lock.RUnlock()
		o.lock.Lock()
		delete(o.blockedIPs, ip)
		o.lock.Unlock()
		o.lock.RLock()
	}
	return false
}

// GetStats returns current statistics
func (o *Orchestrator) GetStats() Stats {
	return o.stats
}

func (o *Orchestrator) KillChainStats() map[string]interface{} {
	if o.killChain == nil {
		return map[string]interface{}{}
	}
	return o.killChain.Stats()
}

func (o *Orchestrator) GetJA3Clusters() []map[string]interface{} {
	o.lock.RLock()
	defer o.lock.RUnlock()
	clusters := make([]map[string]interface{}, 0, len(o.ja3Clusters))
	for ja3, ips := range o.ja3Clusters {
		list := make([]string, 0, len(ips))
		for ip := range ips {
			list = append(list, ip)
		}
		clusters = append(clusters, map[string]interface{}{
			"ja3":   ja3,
			"ips":   list,
			"count": len(list),
		})
	}
	return clusters
}

func (o *Orchestrator) GetKillChainTimeline(ip string) map[string]interface{} {
	if o.killChain == nil {
		return map[string]interface{}{}
	}
	return o.killChain.VisualizeChain(ip)
}

func (o *Orchestrator) GetActiveActors() []*actor.ReserseProfile {
	if o.reserseTracker == nil {
		return []*actor.ReserseProfile{}
	}
	return o.reserseTracker.GetAllProfiles()
}

func (o *Orchestrator) clusterJA3(ip, ja3 string) {
	if ja3 == "" {
		return
	}
	o.lock.Lock()
	defer o.lock.Unlock()
	cluster, ok := o.ja3Clusters[ja3]
	if !ok {
		cluster = make(map[string]struct{})
		o.ja3Clusters[ja3] = cluster
	}
	if _, exists := cluster[ip]; !exists {
		cluster[ip] = struct{}{}
		o.stats.JA3Clustered++
	}
}

func (o *Orchestrator) isCrossSession(ja3, ip string) bool {
	o.lock.RLock()
	cluster, ok := o.ja3Clusters[ja3]
	o.lock.RUnlock()
	if !ok {
		return false
	}
	count := 0
	for member := range cluster {
		if member != ip {
			count++
		}
	}
	return count > 0
}

// Helper: detect attack technique from request
func detectTechnique(r *http.Request) string {
	path := r.URL.Path
	query := r.URL.RawQuery

	// SQL Injection patterns
	if containsAny(path+query, []string{"union", "select", "' or ", "-- ", "/*", "sleep(", "waitfor"}) {
		return "SQL Injection"
	}

	// Path traversal
	if containsAny(path, []string{"../", "..\\", "..%2f", "..%5c"}) {
		return "Path Traversal"
	}

	// Command injection
	if containsAny(query, []string{"|", ";", "`", "$(", "&&"}) {
		return "Command Injection"
	}

	// XSS
	if containsAny(path+query, []string{"<script", "javascript:", "onerror=", "onload="}) {
		return "XSS"
	}

	// Reconnaissance
	if containsAny(path, []string{"/.git", "/.env", "/wp-admin", "/phpmyadmin", "/.aws"}) {
		return "Reconnaissance"
	}

	return ""
}

// Helper: map technique to kill chain stage
func mapTechniqueToStage(technique string) KillChainStage {
	switch technique {
	case "Reconnaissance":
		return Reconnaissance
	case "SQL Injection", "XSS", "Command Injection":
		return Exploitation
	case "Path Traversal":
		return Delivery
	default:
		return Reconnaissance
	}
}

// Helper functions
func generateChallengeToken() string {
	// Simplified - should use crypto/rand in production
	return time.Now().Format("20060102150405")
}

func containsAny(s string, substrs []string) bool {
	for _, substr := range substrs {
		if len(s) >= len(substr) {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
		}
	}
	return false
}
