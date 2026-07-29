/*
Package detect implements attack chain and threat detection for SVALINN.

Migrated from:
- attack-chain.js
- attack-chain-analyzer.js
- kill-chain-state.js
- red-team-detector.js
- c2-detector.js
- silent-hunter.js
*/
package detect

import (
	"sync"
	"time"
)

// KillChainPhase represents a phase in the cyber kill chain
type KillChainPhase int

const (
	PhaseRecon KillChainPhase = iota
	PhaseWeaponize
	PhaseDelivery
	PhaseExploitation
	PhaseInstallation
	PhaseC2
	PhaseActions
)

// String returns the phase name
func (p KillChainPhase) String() string {
	phases := []string{
		"Reconnaissance",
		"Weaponization",
		"Delivery",
		"Exploitation",
		"Installation",
		"Command & Control",
		"Actions on Objectives",
	}
	if int(p) < len(phases) {
		return phases[p]
	}
	return "Unknown"
}

// AttackChain represents a detected attack chain
type AttackChain struct {
	ID          string
	ActorIP     string
	StartTime   time.Time
	LastUpdate  time.Time
	Phase       KillChainPhase
	Events      []AttackEvent
	ThreatScore float64
	Techniques  []string // MITRE ATT&CK IDs
	Confidence  float64
	Status      string // active, completed, blocked
}

// AttackEvent represents a single event in an attack chain
type AttackEvent struct {
	Timestamp time.Time
	Type      string
	Phase     KillChainPhase
	Path      string
	Payload   string
	Signature string
	Score     float64
	Technique string // MITRE ATT&CK ID
}

// C2Indicator represents a potential C2 communication indicator
type C2Indicator struct {
	Type        string // beacon, dns, http, websocket
	Destination string
	Interval    time.Duration
	Regularity  float64 // 0-1, how regular the beaconing is
	Encrypted   bool
	Port        int
}

// Analyzer is the attack chain analyzer
type Analyzer struct {
	chains     sync.Map // map[string]*AttackChain
	c2Suspects sync.Map // map[string]*C2Analysis

	// Thresholds
	chainTimeout    time.Duration
	alertThreshold  float64
	beaconThreshold float64

	// Callbacks
	onChainAdvance func(*AttackChain)
	onC2Detected   func(*C2Analysis)

	// Stats
	totalChains     int64
	completedChains int64
	blockedChains   int64
	c2Detected      int64

	lock sync.RWMutex
}

// C2Analysis represents C2 analysis for an actor
type C2Analysis struct {
	IP           string
	Indicators   []C2Indicator
	BeaconScore  float64
	DNSBeacon    bool
	HTTPBeacon   bool
	IsC2         bool
	LastAnalysis time.Time
}

// Config holds analyzer configuration
type Config struct {
	ChainTimeout    time.Duration
	AlertThreshold  float64
	BeaconThreshold float64
}

// NewAnalyzer creates a new attack chain analyzer
func NewAnalyzer(cfg *Config) *Analyzer {
	if cfg.ChainTimeout == 0 {
		cfg.ChainTimeout = 1 * time.Hour
	}
	if cfg.AlertThreshold == 0 {
		cfg.AlertThreshold = 0.7
	}
	if cfg.BeaconThreshold == 0 {
		cfg.BeaconThreshold = 0.8
	}

	a := &Analyzer{
		chainTimeout:    cfg.ChainTimeout,
		alertThreshold:  cfg.AlertThreshold,
		beaconThreshold: cfg.BeaconThreshold,
	}

	// Start cleanup goroutine
	go a.cleanupLoop()

	return a
}

// ProcessEvent processes a security event and updates attack chains
func (a *Analyzer) ProcessEvent(ip string, event AttackEvent) *AttackChain {
	// Get or create chain for this IP
	chain := a.getOrCreateChain(ip)

	chain.Events = append(chain.Events, event)
	chain.LastUpdate = time.Now()
	chain.ThreatScore += event.Score

	// Add technique if present
	if event.Technique != "" {
		if !contains(chain.Techniques, event.Technique) {
			chain.Techniques = append(chain.Techniques, event.Technique)
		}
	}

	// Determine phase progression
	newPhase := a.determinePhase(chain)
	if newPhase > chain.Phase {
		chain.Phase = newPhase
		chain.Confidence = a.calculateConfidence(chain)

		// Fire callback
		if a.onChainAdvance != nil {
			a.onChainAdvance(chain)
		}
	}

	return chain
}

// getOrCreateChain gets or creates an attack chain for an IP
func (a *Analyzer) getOrCreateChain(ip string) *AttackChain {
	if chainVal, exists := a.chains.Load(ip); exists {
		chain := chainVal.(*AttackChain)
		// Check if chain is still active (not timed out)
		if time.Since(chain.LastUpdate) < a.chainTimeout {
			return chain
		}
		// Chain timed out, create new one
	}

	chain := &AttackChain{
		ID:         generateID(),
		ActorIP:    ip,
		StartTime:  time.Now(),
		LastUpdate: time.Now(),
		Phase:      PhaseRecon,
		Events:     make([]AttackEvent, 0),
		Status:     "active",
	}

	a.chains.Store(ip, chain)
	a.totalChains++

	return chain
}

// determinePhase determines the kill chain phase based on events
func (a *Analyzer) determinePhase(chain *AttackChain) KillChainPhase {
	// Map event types to phases
	phaseIndicators := map[string]KillChainPhase{
		"scanner":       PhaseRecon,
		"enumeration":   PhaseRecon,
		"sqli":          PhaseExploitation,
		"xss":           PhaseExploitation,
		"rce":           PhaseExploitation,
		"cmd_injection": PhaseExploitation,
		"file_upload":   PhaseInstallation,
		"webshell":      PhaseInstallation,
		"c2_beacon":     PhaseC2,
		"data_exfil":    PhaseActions,
	}

	highestPhase := PhaseRecon

	for _, event := range chain.Events {
		if phase, ok := phaseIndicators[event.Type]; ok {
			if phase > highestPhase {
				highestPhase = phase
			}
		}
	}

	return highestPhase
}

// calculateConfidence calculates the confidence in the attack chain
func (a *Analyzer) calculateConfidence(chain *AttackChain) float64 {
	if len(chain.Events) == 0 {
		return 0
	}

	// Factors: number of events, phase progression, techniques diversity
	eventFactor := min(float64(len(chain.Events))/10.0, 1.0)
	phaseFactor := float64(chain.Phase) / float64(PhaseActions)
	techniqueFactor := min(float64(len(chain.Techniques))/5.0, 1.0)

	return (eventFactor + phaseFactor + techniqueFactor) / 3.0
}

// AnalyzeC2 analyzes an IP for potential C2 communication
func (a *Analyzer) AnalyzeC2(ip string, requests []RequestPattern) *C2Analysis {
	analysis := &C2Analysis{
		IP:           ip,
		Indicators:   make([]C2Indicator, 0),
		LastAnalysis: time.Now(),
	}

	if len(requests) < 3 {
		return analysis
	}

	// Calculate beacon regularity
	var intervals []time.Duration
	for i := 1; i < len(requests); i++ {
		interval := requests[i].Timestamp.Sub(requests[i-1].Timestamp)
		intervals = append(intervals, interval)
	}

	if len(intervals) > 0 {
		regularity := calculateRegularity(intervals)
		analysis.BeaconScore = regularity

		if regularity > a.beaconThreshold {
			analysis.HTTPBeacon = true
			analysis.Indicators = append(analysis.Indicators, C2Indicator{
				Type:       "http",
				Regularity: regularity,
				Interval:   calculateAvgInterval(intervals),
			})
		}
	}

	// Determine if C2
	analysis.IsC2 = analysis.BeaconScore > a.beaconThreshold

	if analysis.IsC2 && a.onC2Detected != nil {
		a.onC2Detected(analysis)
		a.c2Detected++
	}

	a.c2Suspects.Store(ip, analysis)

	return analysis
}

// RequestPattern represents a request pattern for C2 analysis
type RequestPattern struct {
	Timestamp time.Time
	Path      string
	Size      int
	Encrypted bool
}

// GetChain returns an attack chain by IP
func (a *Analyzer) GetChain(ip string) *AttackChain {
	if chainVal, exists := a.chains.Load(ip); exists {
		return chainVal.(*AttackChain)
	}
	return nil
}

// GetActiveChains returns all active attack chains
func (a *Analyzer) GetActiveChains() []*AttackChain {
	var result []*AttackChain

	a.chains.Range(func(_, value interface{}) bool {
		chain := value.(*AttackChain)
		if chain.Status == "active" {
			result = append(result, chain)
		}
		return true
	})

	return result
}

// OnChainAdvance sets the callback for chain phase advancement
func (a *Analyzer) OnChainAdvance(fn func(*AttackChain)) {
	a.onChainAdvance = fn
}

// OnC2Detected sets the callback for C2 detection
func (a *Analyzer) OnC2Detected(fn func(*C2Analysis)) {
	a.onC2Detected = fn
}

// BlockChain marks a chain as blocked
func (a *Analyzer) BlockChain(ip string) {
	if chain := a.GetChain(ip); chain != nil {
		chain.Status = "blocked"
		a.blockedChains++
	}
}

// cleanupLoop removes old chains periodically
func (a *Analyzer) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		a.cleanup()
	}
}

// cleanup removes stale attack chains
func (a *Analyzer) cleanup() {
	cutoff := time.Now().Add(-a.chainTimeout)

	a.chains.Range(func(key, value interface{}) bool {
		chain := value.(*AttackChain)
		if chain.LastUpdate.Before(cutoff) && chain.Status == "active" {
			chain.Status = "completed"
			a.completedChains++
		}
		return true
	})
}

// Stats returns analyzer statistics
func (a *Analyzer) Stats() map[string]interface{} {
	return map[string]interface{}{
		"total_chains":     a.totalChains,
		"completed_chains": a.completedChains,
		"blocked_chains":   a.blockedChains,
		"c2_detected":      a.c2Detected,
	}
}

// Helpers
func generateID() string {
	return time.Now().Format("20060102-150405")
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func calculateRegularity(intervals []time.Duration) float64 {
	if len(intervals) < 2 {
		return 0
	}

	// Calculate standard deviation / mean
	var sum float64
	for _, d := range intervals {
		sum += float64(d)
	}
	mean := sum / float64(len(intervals))

	var variance float64
	for _, d := range intervals {
		diff := float64(d) - mean
		variance += diff * diff
	}
	variance /= float64(len(intervals))
	stddev := variance // sqrt approximation not needed for comparison

	if mean == 0 {
		return 0
	}

	// Lower coefficient of variation = more regular = higher score
	cv := stddev / mean
	regularity := 1.0 / (1.0 + cv)

	return regularity
}

func calculateAvgInterval(intervals []time.Duration) time.Duration {
	if len(intervals) == 0 {
		return 0
	}

	var sum time.Duration
	for _, d := range intervals {
		sum += d
	}

	return sum / time.Duration(len(intervals))
}
