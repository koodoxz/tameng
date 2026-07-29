/*
Package intel implements threat intelligence for SVALINN.

Features:
- MITRE ATT&CK mapping
- STIX/TAXII integration
- Threat feed management
- IOC (Indicators of Compromise) tracking
*/
package intel

import (
	"sync"
	"time"
)

// ThreatLevel represents the threat severity
type ThreatLevel int

const (
	ThreatUnknown ThreatLevel = iota
	ThreatLow
	ThreatMedium
	ThreatHigh
	ThreatCritical
)

// String returns the threat level name
func (t ThreatLevel) String() string {
	switch t {
	case ThreatLow:
		return "low"
	case ThreatMedium:
		return "medium"
	case ThreatHigh:
		return "high"
	case ThreatCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// MITRETechnique represents a MITRE ATT&CK technique
type MITRETechnique struct {
	ID          string   `json:"id"`     // e.g., "T1190"
	Name        string   `json:"name"`   // e.g., "Exploit Public-Facing Application"
	Tactic      string   `json:"tactic"` // e.g., "Initial Access"
	Description string   `json:"description"`
	Platforms   []string `json:"platforms"`
	Detection   string   `json:"detection"`
	URL         string   `json:"url"`
}

// IOC represents an Indicator of Compromise
type IOC struct {
	Type        string      `json:"type"` // ip, domain, url, hash, email
	Value       string      `json:"value"`
	ThreatLevel ThreatLevel `json:"threat_level"`
	Source      string      `json:"source"`
	FirstSeen   time.Time   `json:"first_seen"`
	LastSeen    time.Time   `json:"last_seen"`
	Tags        []string    `json:"tags"`
	MITRE       []string    `json:"mitre,omitempty"`
}

// ThreatActor represents a known threat actor
type ThreatActor struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Aliases     []string `json:"aliases"`
	Description string   `json:"description"`
	Country     string   `json:"country,omitempty"`
	Targets     []string `json:"targets"`
	TTPs        []string `json:"ttps"` // MITRE technique IDs
	Active      bool     `json:"active"`
}

// Hub is the threat intelligence hub
type Hub struct {
	// MITRE ATT&CK database
	techniques map[string]*MITRETechnique

	// IOC database
	iocs           map[string]*IOC
	blockedIPs     map[string]*IOC
	blockedDomains map[string]*IOC

	// Threat actors
	actors map[string]*ThreatActor

	// Sync
	lock sync.RWMutex

	// Config
	enabled bool
}

// Config holds threat intel configuration
type Config struct {
	Enabled      bool
	MITREEnabled bool
	STIXEnabled  bool
	FeedsEnabled bool
	SyncInterval time.Duration
}

// NewHub creates a new threat intelligence hub
func NewHub(cfg *Config) *Hub {
	h := &Hub{
		techniques:     make(map[string]*MITRETechnique),
		iocs:           make(map[string]*IOC),
		blockedIPs:     make(map[string]*IOC),
		blockedDomains: make(map[string]*IOC),
		actors:         make(map[string]*ThreatActor),
		enabled:        cfg.Enabled,
	}

	// Load built-in MITRE techniques
	if cfg.MITREEnabled {
		h.loadMITRE()
	}

	return h
}

// loadMITRE loads built-in MITRE ATT&CK techniques
func (h *Hub) loadMITRE() {
	techniques := []*MITRETechnique{
		{ID: "T1190", Name: "Exploit Public-Facing Application", Tactic: "Initial Access", Description: "Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network."},
		{ID: "T1059", Name: "Command and Scripting Interpreter", Tactic: "Execution", Description: "Adversaries may abuse command and script interpreters to execute commands."},
		{ID: "T1059.001", Name: "PowerShell", Tactic: "Execution", Description: "Adversaries may abuse PowerShell commands and scripts for execution."},
		{ID: "T1059.007", Name: "JavaScript", Tactic: "Execution", Description: "Adversaries may abuse JavaScript for execution."},
		{ID: "T1083", Name: "File and Directory Discovery", Tactic: "Discovery", Description: "Adversaries may enumerate files and directories on a compromised system."},
		{ID: "T1090", Name: "Proxy", Tactic: "Command and Control", Description: "Adversaries may use a proxy to direct network traffic."},
		{ID: "T1566", Name: "Phishing", Tactic: "Initial Access", Description: "Adversaries may send phishing messages to gain access to victim systems."},
		{ID: "T1046", Name: "Network Service Discovery", Tactic: "Discovery", Description: "Adversaries may attempt to get a listing of services running on remote hosts."},
		{ID: "T1110", Name: "Brute Force", Tactic: "Credential Access", Description: "Adversaries may use brute force techniques to gain access to accounts."},
		{ID: "T1133", Name: "External Remote Services", Tactic: "Persistence", Description: "Adversaries may leverage external-facing remote services to initially access a network."},
	}

	for _, t := range techniques {
		h.techniques[t.ID] = t
	}
}

// GetTechnique returns a MITRE technique by ID
func (h *Hub) GetTechnique(id string) *MITRETechnique {
	h.lock.RLock()
	defer h.lock.RUnlock()
	return h.techniques[id]
}

// MapToMITRE maps a signature match to MITRE techniques
func (h *Hub) MapToMITRE(signatureID string, category string) []*MITRETechnique {
	h.lock.RLock()
	defer h.lock.RUnlock()

	// Simple mapping based on category
	var techniqueIDs []string

	switch category {
	case "sqli", "xss", "path_traversal", "cmd_injection":
		techniqueIDs = []string{"T1190"}
	case "scanner":
		techniqueIDs = []string{"T1046"}
	case "brute_force":
		techniqueIDs = []string{"T1110"}
	case "ssrf":
		techniqueIDs = []string{"T1090"}
	}

	var result []*MITRETechnique
	for _, id := range techniqueIDs {
		if t, exists := h.techniques[id]; exists {
			result = append(result, t)
		}
	}

	return result
}

// AddIOC adds an indicator of compromise
func (h *Hub) AddIOC(ioc *IOC) {
	h.lock.Lock()
	defer h.lock.Unlock()

	h.iocs[ioc.Type+":"+ioc.Value] = ioc

	// Add to specific blocklists
	if ioc.Type == "ip" {
		h.blockedIPs[ioc.Value] = ioc
	} else if ioc.Type == "domain" {
		h.blockedDomains[ioc.Value] = ioc
	}
}

// IsBlockedIP checks if an IP is in the blocklist
func (h *Hub) IsBlockedIP(ip string) (*IOC, bool) {
	h.lock.RLock()
	defer h.lock.RUnlock()

	ioc, exists := h.blockedIPs[ip]
	return ioc, exists
}

// IsBlockedDomain checks if a domain is in the blocklist
func (h *Hub) IsBlockedDomain(domain string) (*IOC, bool) {
	h.lock.RLock()
	defer h.lock.RUnlock()

	ioc, exists := h.blockedDomains[domain]
	return ioc, exists
}

// GetIOCStats returns IOC statistics
func (h *Hub) GetIOCStats() map[string]int {
	h.lock.RLock()
	defer h.lock.RUnlock()

	stats := map[string]int{
		"total_iocs":       len(h.iocs),
		"blocked_ips":      len(h.blockedIPs),
		"blocked_domains":  len(h.blockedDomains),
		"mitre_techniques": len(h.techniques),
		"threat_actors":    len(h.actors),
	}

	return stats
}

// ThreatScore calculates a threat score based on intel
func (h *Hub) ThreatScore(ip string, domain string, userAgent string) float64 {
	score := 0.0

	// Check IP
	if ioc, blocked := h.IsBlockedIP(ip); blocked {
		switch ioc.ThreatLevel {
		case ThreatCritical:
			score += 1.0
		case ThreatHigh:
			score += 0.8
		case ThreatMedium:
			score += 0.5
		case ThreatLow:
			score += 0.2
		}
	}

	// Check domain
	if ioc, blocked := h.IsBlockedDomain(domain); blocked {
		switch ioc.ThreatLevel {
		case ThreatCritical:
			score += 0.8
		case ThreatHigh:
			score += 0.6
		case ThreatMedium:
			score += 0.4
		case ThreatLow:
			score += 0.2
		}
	}

	return score
}
