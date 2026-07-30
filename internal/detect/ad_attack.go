/*
Package detect includes Active Directory attack detection (Phase 4+).
*/
package detect

import (
	"regexp"
	"sync"

	"github.com/koodoxz/tameng/internal/literalextract"
)

// ADAttackConfig configures AD attack detector thresholds.
type ADAttackConfig struct {
	Enabled             bool
	DCSyncThreshold     int
	GoldenThreshold     int
	SilverThreshold     int
	SkeletonThreshold   int
	AdminSDThreshold    int
	GPOThreshold        int
	BloodhoundThreshold int
	LDAPThreshold       int
	AlertThreshold      float64
	BlockThreshold      float64
}

// ADAttackDetector detects Active Directory attack patterns.
type ADAttackDetector struct {
	config   ADAttackConfig
	patterns map[string][]*regexp.Regexp
	// prefilter is built once here and read-only afterwards.
	// REQ SVALINN-DETECTPREFILTER-001.
	prefilter *literalextract.Groups
	mitreMap  map[string][]string
	stats     ADAttackStats
	lock      sync.Mutex
}

// ADAttackStats tracks detection stats.
type ADAttackStats struct {
	Analyzed        int64            `json:"analyzed"`
	Detections      map[string]int64 `json:"detections"`
	TotalDetections int64            `json:"total_detections"`
}

// ADAttackResult holds detection results.
type ADAttackResult struct {
	Detected   bool             `json:"detected"`
	Attacks    []string         `json:"attacks"`
	Confidence float64          `json:"confidence"`
	MitreIDs   []string         `json:"mitre_ids"`
	Evidence   []map[string]any `json:"evidence"`
	Severity   string           `json:"severity"`
}

// NewADAttackDetector creates a new AD attack detector.
func NewADAttackDetector(cfg ADAttackConfig) *ADAttackDetector {
	if cfg.DCSyncThreshold == 0 {
		cfg.DCSyncThreshold = 50
	}
	if cfg.GoldenThreshold == 0 {
		cfg.GoldenThreshold = 50
	}
	if cfg.SilverThreshold == 0 {
		cfg.SilverThreshold = 45
	}
	if cfg.SkeletonThreshold == 0 {
		cfg.SkeletonThreshold = 40
	}
	if cfg.AdminSDThreshold == 0 {
		cfg.AdminSDThreshold = 40
	}
	if cfg.GPOThreshold == 0 {
		cfg.GPOThreshold = 35
	}
	if cfg.BloodhoundThreshold == 0 {
		cfg.BloodhoundThreshold = 30
	}
	if cfg.LDAPThreshold == 0 {
		cfg.LDAPThreshold = 25
	}
	if cfg.AlertThreshold == 0 {
		cfg.AlertThreshold = 70
	}
	if cfg.BlockThreshold == 0 {
		cfg.BlockThreshold = 85
	}

	patterns := map[string][]*regexp.Regexp{
		"dcsync": {
			regexp.MustCompile(`(?i)DCSync`),
			regexp.MustCompile(`(?i)mimikatz.*lsadump::dcsync`),
			regexp.MustCompile(`(?i)secretsdump`),
			regexp.MustCompile(`(?i)DS-Replication-Get-Changes`),
			regexp.MustCompile(`(?i)DS-Replication-Get-Changes-All`),
			regexp.MustCompile(`(?i)GetNCChanges`),
			regexp.MustCompile(`(?i)DRS_EXTENSIONS_INT`),
			regexp.MustCompile(`(?i)1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`),
			regexp.MustCompile(`(?i)1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`),
		},
		"goldenTicket": {
			regexp.MustCompile(`(?i)golden.*ticket`),
			regexp.MustCompile(`(?i)krbtgt`),
			regexp.MustCompile(`(?i)kerberos::golden`),
			regexp.MustCompile(`(?i)mimikatz.*kerberos::golden`),
			regexp.MustCompile(`(?i)ticketer\.py.*-domain`),
			regexp.MustCompile(`(?i)TRUSTED_FOR_DELEGATION`),
			regexp.MustCompile(`(?i)Rubeus.*golden`),
		},
		"silverTicket": {
			regexp.MustCompile(`(?i)silver.*ticket`),
			regexp.MustCompile(`(?i)kerberos::silver`),
			regexp.MustCompile(`(?i)service.*ticket.*forged`),
			regexp.MustCompile(`(?i)tgs.*forge`),
			regexp.MustCompile(`(?i)Rubeus.*silver`),
		},
		"skeletonKey": {
			regexp.MustCompile(`(?i)skeleton.*key`),
			regexp.MustCompile(`(?i)mimikatz.*misc::skeleton`),
			regexp.MustCompile(`(?i)lsass.*patch`),
			regexp.MustCompile(`(?i)skeleton.*password`),
		},
		"adminSD": {
			regexp.MustCompile(`(?i)AdminSDHolder`),
			regexp.MustCompile(`(?i)SDPropagator`),
			regexp.MustCompile(`(?i)AD.*persistence`),
			regexp.MustCompile(`(?i)adminCount=1`),
			regexp.MustCompile(`(?i)Add-ObjectAcl.*AdminSDHolder`),
		},
		"gpoAbuse": {
			regexp.MustCompile(`(?i)GPO.*abuse`),
			regexp.MustCompile(`(?i)Group.*Policy.*hijack`),
			regexp.MustCompile(`(?i)SharpGPOAbuse`),
			regexp.MustCompile(`(?i)New-GPOImmediateTask`),
			regexp.MustCompile(`(?i)gPCFileSysPath`),
			regexp.MustCompile(`(?i)SYSVOL.*scripts`),
		},
		"bloodhound": {
			regexp.MustCompile(`(?i)BloodHound`),
			regexp.MustCompile(`(?i)SharpHound`),
			regexp.MustCompile(`(?i)Invoke-BloodHound`),
			regexp.MustCompile(`(?i)msDS-AllowedToDelegateTo`),
			regexp.MustCompile(`(?i)msDS-AllowedToActOnBehalfOfOtherIdentity`),
			regexp.MustCompile(`(?i)LDAP.*objectClass=computer`),
			regexp.MustCompile(`(?i)LDAP.*objectClass=user.*adminCount`),
			regexp.MustCompile(`(?i)GetNetDomainController`),
			regexp.MustCompile(`(?i)Get-DomainUser.*-AdminCount`),
		},
		"ldapRecon": {
			regexp.MustCompile(`(?i)ldapsearch`),
			regexp.MustCompile(`(?i)LDAP.*enumeration`),
			regexp.MustCompile(`(?i)objectClass=\*`),
			regexp.MustCompile(`(?i)servicePrincipalName=\*`),
			regexp.MustCompile(`(?i)userAccountControl:1\.2\.840\.113556`),
			regexp.MustCompile(`(?i)Get-ADUser.*-Filter`),
			regexp.MustCompile(`(?i)Get-ADComputer.*-Filter`),
		},
	}

	return &ADAttackDetector{
		config:    cfg,
		patterns:  patterns,
		prefilter: literalextract.NewGroups(patterns),
		mitreMap: map[string][]string{
			"dcsync":       {"T1003.006"},
			"goldenTicket": {"T1558.001"},
			"silverTicket": {"T1558.002"},
			"skeletonKey":  {"T1556.001"},
			"adminSD":      {"T1098"},
			"gpoAbuse":     {"T1484.001"},
			"bloodhound":   {"T1087.002"},
			"ldapRecon":    {"T1018"},
		},
		stats: ADAttackStats{Detections: make(map[string]int64)},
	}
}

// Analyze inspects data for AD attack patterns.
func (a *ADAttackDetector) Analyze(data string) *ADAttackResult {
	if !a.config.Enabled {
		return &ADAttackResult{}
	}

	a.lock.Lock()
	a.stats.Analyzed++
	a.lock.Unlock()

	result := &ADAttackResult{
		Attacks:  []string{},
		MitreIDs: []string{},
		Evidence: []map[string]any{},
		Severity: "low",
	}

	severityOrder := map[string]int{"low": 0, "medium": 1, "high": 2, "critical": 3}
	checks := []struct {
		name      string
		threshold int
		severity  string
	}{
		{"dcsync", a.config.DCSyncThreshold, "critical"},
		{"goldenTicket", a.config.GoldenThreshold, "critical"},
		{"silverTicket", a.config.SilverThreshold, "high"},
		{"skeletonKey", a.config.SkeletonThreshold, "critical"},
		{"adminSD", a.config.AdminSDThreshold, "high"},
		{"gpoAbuse", a.config.GPOThreshold, "high"},
		{"bloodhound", a.config.BloodhoundThreshold, "medium"},
		{"ldapRecon", a.config.LDAPThreshold, "low"},
	}

	cand := a.prefilter.Candidates(data)

	score := 0.0
	for _, check := range checks {
		matches := checkPatternsFiltered(data, a.patterns[check.name], a.prefilter.Slice(cand, check.name))
		if len(matches) == 0 {
			continue
		}

		score += float64(check.threshold) * float64(minInt(len(matches), 2))
		result.Detected = true
		result.Attacks = append(result.Attacks, check.name)
		result.MitreIDs = append(result.MitreIDs, a.mitreMap[check.name]...)
		result.Evidence = append(result.Evidence, map[string]any{
			"attack":     check.name,
			"matchCount": len(matches),
			"patterns":   matches,
			"severity":   check.severity,
		})

		if severityOrder[check.severity] > severityOrder[result.Severity] {
			result.Severity = check.severity
		}

		a.lock.Lock()
		a.stats.Detections[check.name]++
		a.lock.Unlock()
	}

	result.Confidence = minFloat(score, 100)
	result.MitreIDs = uniqueStrings(result.MitreIDs)

	if result.Detected {
		a.lock.Lock()
		a.stats.TotalDetections++
		a.lock.Unlock()
	}

	return result
}

// GetStats returns detector stats.
func (a *ADAttackDetector) GetStats() map[string]interface{} {
	a.lock.Lock()
	defer a.lock.Unlock()

	detectionRate := "0%"
	if a.stats.Analyzed > 0 {
		detectionRate = formatPercent(float64(a.stats.TotalDetections) / float64(a.stats.Analyzed) * 100)
	}

	return map[string]interface{}{
		"analyzed":         a.stats.Analyzed,
		"detections":       a.stats.Detections,
		"total_detections": a.stats.TotalDetections,
		"detection_rate":   detectionRate,
		"enabled":          a.config.Enabled,
		"alert_threshold":  a.config.AlertThreshold,
		"block_threshold":  a.config.BlockThreshold,
	}
}
