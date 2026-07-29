/*
Package detect includes network attack detection (Phase 4+).
*/
package detect

import (
	"regexp"
	"sync"
	"time"

	"github.com/aegis/svalinn/internal/literalextract"
)

// NetworkAttackConfig configures network attack detector thresholds.
type NetworkAttackConfig struct {
	Enabled             bool
	ARPThreshold        int
	DNSThreshold        int
	SMBThreshold        int
	KerberoastThreshold int
	PoisoningThreshold  int
	PTXThreshold        int
	AlertThreshold      float64
	BlockThreshold      float64
	ConnectionTTL       time.Duration
}

// NetworkAttackDetector detects network attack patterns.
type NetworkAttackDetector struct {
	config   NetworkAttackConfig
	patterns map[string][]*regexp.Regexp
	// prefilter is built once here and read-only afterwards.
	// REQ SVALINN-DETECTPREFILTER-001.
	prefilter *literalextract.Groups
	mitreMap  map[string][]string
	states    sync.Map // clientID -> *ConnectionState
	stats     NetworkAttackStats
	lock      sync.Mutex
}

// ConnectionState tracks network connection anomalies.
type ConnectionState struct {
	Packets    int
	Anomalies  int
	Attacks    []string
	FirstSeen  time.Time
	LastUpdate time.Time
}

// NetworkAttackStats tracks detection stats.
type NetworkAttackStats struct {
	Analyzed        int64            `json:"analyzed"`
	Detections      map[string]int64 `json:"detections"`
	TotalDetections int64            `json:"total_detections"`
}

// NetworkAttackResult holds detection results.
type NetworkAttackResult struct {
	Detected   bool             `json:"detected"`
	Attacks    []string         `json:"attacks"`
	Confidence float64          `json:"confidence"`
	MitreIDs   []string         `json:"mitre_ids"`
	Evidence   []map[string]any `json:"evidence"`
}

// NewNetworkAttackDetector creates a new network attack detector.
func NewNetworkAttackDetector(cfg NetworkAttackConfig) *NetworkAttackDetector {
	if cfg.ARPThreshold == 0 {
		cfg.ARPThreshold = 25
	}
	if cfg.DNSThreshold == 0 {
		cfg.DNSThreshold = 30
	}
	if cfg.SMBThreshold == 0 {
		cfg.SMBThreshold = 35
	}
	if cfg.KerberoastThreshold == 0 {
		cfg.KerberoastThreshold = 40
	}
	if cfg.PoisoningThreshold == 0 {
		cfg.PoisoningThreshold = 30
	}
	if cfg.PTXThreshold == 0 {
		cfg.PTXThreshold = 45
	}
	if cfg.AlertThreshold == 0 {
		cfg.AlertThreshold = 70
	}
	if cfg.BlockThreshold == 0 {
		cfg.BlockThreshold = 85
	}
	if cfg.ConnectionTTL == 0 {
		cfg.ConnectionTTL = 10 * time.Minute
	}

	patterns := map[string][]*regexp.Regexp{
		"arpSpoof": {
			regexp.MustCompile(`(?i)arp.*spoof`),
			regexp.MustCompile(`(?i)arp.*poison`),
			regexp.MustCompile(`(?i)gratuitous\s*arp`),
			regexp.MustCompile(`(?i)arp\s+reply.*is-at`),
		},
		"dnsTunnel": {
			regexp.MustCompile(`(?i)[a-z0-9]{32,}\.[a-z]{2,10}`),
			regexp.MustCompile(`(?i)dns.*tunnel`),
			regexp.MustCompile(`(?i)iodine|dnscat|dns2tcp`),
			regexp.MustCompile(`(?i)TXT.*AAAA.*record`),
		},
		"icmpCovert": {
			regexp.MustCompile(`(?i)icmp.*tunnel`),
			regexp.MustCompile(`(?i)icmp.*covert`),
			regexp.MustCompile(`(?i)ptunnel|icmpsh`),
			regexp.MustCompile(`(?i)ping.*data.*exfil`),
		},
		"smbRelay": {
			regexp.MustCompile(`(?i)smb.*relay`),
			regexp.MustCompile(`(?i)ntlm.*relay`),
			regexp.MustCompile(`(?i)responder`),
			regexp.MustCompile(`(?i)impacket.*ntlmrelay`),
			regexp.MustCompile(`(?i)smb.*negotiate`),
			regexp.MustCompile(`(?i)ntlm.*challenge`),
		},
		"kerberoast": {
			regexp.MustCompile(`(?i)kerberoast`),
			regexp.MustCompile(`(?i)GetUserSPNs`),
			regexp.MustCompile(`(?i)TGS-REQ.*RC4`),
			regexp.MustCompile(`(?i)servicePrincipalName`),
			regexp.MustCompile(`(?i)Invoke-Kerberoast`),
			regexp.MustCompile(`(?i)rubeus.*kerberoast`),
		},
		"passHash": {
			regexp.MustCompile(`(?i)pass.*the.*hash`),
			regexp.MustCompile(`(?i)pth-winexe`),
			regexp.MustCompile(`(?i)mimikatz.*sekurlsa`),
			regexp.MustCompile(`(?i)sekurlsa::pth`),
			regexp.MustCompile(`(?i)wmiexec.*hash`),
			regexp.MustCompile(`(?i)psexec.*hash`),
		},
		"passTicket": {
			regexp.MustCompile(`(?i)pass.*the.*ticket`),
			regexp.MustCompile(`(?i)golden.*ticket`),
			regexp.MustCompile(`(?i)silver.*ticket`),
			regexp.MustCompile(`(?i)krbtgt`),
			regexp.MustCompile(`(?i)kerberos::ptt`),
			regexp.MustCompile(`(?i)\.kirbi`),
		},
		"poisoning": {
			regexp.MustCompile(`(?i)llmnr.*poison`),
			regexp.MustCompile(`(?i)nbt-ns.*poison`),
			regexp.MustCompile(`(?i)nbns.*spoof`),
			regexp.MustCompile(`(?i)responder.*-I`),
			regexp.MustCompile(`(?i)inveigh`),
			regexp.MustCompile(`(?i)multicast.*dns`),
		},
	}

	return &NetworkAttackDetector{
		config:    cfg,
		patterns:  patterns,
		prefilter: literalextract.NewGroups(patterns),
		mitreMap: map[string][]string{
			"arpSpoof":   {"T1557.002"},
			"dnsTunnel":  {"T1071.004"},
			"icmpCovert": {"T1095"},
			"smbRelay":   {"T1557.001"},
			"kerberoast": {"T1558.003"},
			"passHash":   {"T1550.002"},
			"passTicket": {"T1550.003"},
			"poisoning":  {"T1557.001"},
		},
		stats: NetworkAttackStats{Detections: make(map[string]int64)},
	}
}

// Analyze inspects data for network attack patterns.
func (n *NetworkAttackDetector) Analyze(data string) *NetworkAttackResult {
	if !n.config.Enabled {
		return &NetworkAttackResult{}
	}

	n.lock.Lock()
	n.stats.Analyzed++
	n.lock.Unlock()

	result := &NetworkAttackResult{
		Attacks:  []string{},
		MitreIDs: []string{},
		Evidence: []map[string]any{},
	}

	score := 0.0
	cand := n.prefilter.Candidates(data)

	for key, patterns := range n.patterns {
		matches := checkPatternsFiltered(data, patterns, n.prefilter.Slice(cand, key))
		if len(matches) == 0 {
			continue
		}

		threshold := n.thresholdForType(key)
		score += float64(threshold) * float64(minInt(len(matches), 2))
		result.Detected = true
		result.Attacks = append(result.Attacks, key)
		result.MitreIDs = append(result.MitreIDs, n.mitreMap[key]...)
		result.Evidence = append(result.Evidence, map[string]any{
			"attack":     key,
			"matchCount": len(matches),
			"patterns":   matches,
		})

		n.lock.Lock()
		n.stats.Detections[key]++
		n.lock.Unlock()
	}

	result.Confidence = minFloat(score, 100)
	result.MitreIDs = uniqueStrings(result.MitreIDs)

	if result.Detected {
		n.lock.Lock()
		n.stats.TotalDetections++
		n.lock.Unlock()
	}

	return result
}

// TrackConnection tracks a client connection and aggregates anomalies.
func (n *NetworkAttackDetector) TrackConnection(clientID string, data string) *ConnectionState {
	if clientID == "" {
		clientID = "unknown"
	}

	val, ok := n.states.Load(clientID)
	state := &ConnectionState{}
	if ok {
		state = val.(*ConnectionState)
	} else {
		state = &ConnectionState{FirstSeen: time.Now(), LastUpdate: time.Now()}
		n.states.Store(clientID, state)
	}

	state.Packets++
	state.LastUpdate = time.Now()
	result := n.Analyze(data)
	if result.Detected {
		state.Anomalies++
		state.Attacks = append(state.Attacks, result.Attacks...)
	}

	return state
}

// Cleanup removes stale connection states.
func (n *NetworkAttackDetector) Cleanup() {
	cutoff := time.Now().Add(-n.config.ConnectionTTL)
	n.states.Range(func(key, value interface{}) bool {
		state := value.(*ConnectionState)
		if state.LastUpdate.Before(cutoff) {
			n.states.Delete(key)
		}
		return true
	})
}

// GetStats returns detector stats.
func (n *NetworkAttackDetector) GetStats() map[string]interface{} {
	n.lock.Lock()
	defer n.lock.Unlock()

	detectionRate := "0%"
	if n.stats.Analyzed > 0 {
		detectionRate = formatPercent(float64(n.stats.TotalDetections) / float64(n.stats.Analyzed) * 100)
	}

	connections := 0
	n.states.Range(func(_, _ interface{}) bool {
		connections++
		return true
	})

	return map[string]interface{}{
		"analyzed":           n.stats.Analyzed,
		"detections":         n.stats.Detections,
		"total_detections":   n.stats.TotalDetections,
		"detection_rate":     detectionRate,
		"active_connections": connections,
		"enabled":            n.config.Enabled,
		"alert_threshold":    n.config.AlertThreshold,
		"block_threshold":    n.config.BlockThreshold,
	}
}

func (n *NetworkAttackDetector) thresholdForType(name string) int {
	switch name {
	case "arpSpoof":
		return n.config.ARPThreshold
	case "dnsTunnel":
		return n.config.DNSThreshold
	case "smbRelay":
		return n.config.SMBThreshold
	case "kerberoast":
		return n.config.KerberoastThreshold
	case "poisoning":
		return n.config.PoisoningThreshold
	case "passHash", "passTicket", "icmpCovert":
		return n.config.PTXThreshold
	default:
		return 30
	}
}
