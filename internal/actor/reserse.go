/*
Package actor - Reserse-level tracking implementation.

Migrated from a legacy Node.js prototype:
- actor-graph.js
- attacker-memory.js
- triangulation-engine.js
*/
package actor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// ReserseProfile represents an advanced attacker profile
type ReserseProfile struct {
	ID            string
	IPs           []string
	Fingerprints  []string
	UserAgents    []string
	SessionCount  int
	TTPProfile    []string // MITRE techniques used
	Timeline      []TimelineEvent
	Relationships []Relationship
	FirstSeen     time.Time
	LastSeen      time.Time
	ThreatLevel   string
	Attribution   string

	// Behavioral DNA
	RequestPattern    *RequestPattern
	TimingPattern     *TimingPattern
	NavigationPattern *NavigationPattern

	// Advanced correlation
	TTPSignature       string    // Hash of attack methodology
	GeoLocations       []string  // Countries detected
	ASNs               []string  // Autonomous Systems
	HeaderPatterns     []string  // Unique header injection patterns
	BlocksTriggered    int       // How many times blocked
	RequestsAfterBlock int       // Persistence attempts post-block
	LastBlockTime      time.Time // Last block timestamp

	lock sync.RWMutex
}

// TimelineEvent represents an event in the attacker timeline
type TimelineEvent struct {
	Timestamp   time.Time
	EventType   string
	Description string
	IP          string
	Path        string
	Signature   string
	Score       float64
}

// Relationship represents a relationship to another entity
type Relationship struct {
	TargetID   string
	Type       string // same_fingerprint, same_pattern, same_asn
	Confidence float64
	Evidence   []string
}

// RequestPattern represents request pattern DNA
type RequestPattern struct {
	AvgInterval      time.Duration
	IntervalVariance float64
	BurstFrequency   float64
	PathDepth        float64
	MethodRatio      map[string]float64
}

// TimingPattern represents timing behavioral DNA
type TimingPattern struct {
	ActiveHours     [24]float64
	ActiveDays      [7]float64
	SessionDuration time.Duration
	Timezone        string
}

// NavigationPattern represents navigation behavioral DNA
type NavigationPattern struct {
	EntryPaths   []string
	ExitPaths    []string
	CommonFlows  [][]string
	DepthProfile map[int]int
}

// ReserseTracker is the advanced attacker tracking system
type ReserseTracker struct {
	profiles     sync.Map // map[string]*ReserseProfile
	ipToProfile  sync.Map // map[string]string - IP to profile ID
	fpToProfile  sync.Map // map[string]string - Fingerprint to profile ID
	ttpToProfile sync.Map // map[string]string - TTP signature to profile ID
	uaToProfiles sync.Map // map[string][]string - User-Agent to profile IDs

	// Fingerprint uniqueness tracking
	fpUniqueIPs sync.Map // map[string]map[string]bool - Fingerprint -> set of unique IPs

	// Correlation
	correlationThreshold float64
	temporalWindow       time.Duration // Time window for correlation (default 5 min)

	// Stats
	totalProfiles       int64
	correlatedEvents    int64
	multiIPCorrelations int64 // New: multi-IP correlations detected

	lock sync.RWMutex
}

// genericFPThreshold: fingerprints seen from more IPs than this are considered
// generic (common HTTP library) and get reduced correlation weight.
const genericFPThreshold = 10

// NewReserseTracker creates a new Reserse-level tracker
func NewReserseTracker(correlationThreshold float64) *ReserseTracker {
	if correlationThreshold == 0 {
		correlationThreshold = 0.7
	}

	return &ReserseTracker{
		correlationThreshold: correlationThreshold,
		temporalWindow:       5 * time.Minute, // Default 5-minute correlation window
	}
}

// trackFingerprintIP records that a fingerprint was seen from a given IP and returns the unique IP count.
func (t *ReserseTracker) trackFingerprintIP(fingerprint, ip string) int {
	if fingerprint == "" {
		return 0
	}
	actual, _ := t.fpUniqueIPs.LoadOrStore(fingerprint, &sync.Map{})
	ipSet := actual.(*sync.Map)
	ipSet.Store(ip, true)

	count := 0
	ipSet.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	return count
}

// fingerprintWeight returns a correlation weight [0.0, 1.0] based on how many
// unique IPs share this fingerprint. Unique fingerprints get full weight;
// generic ones (common HTTP libraries) get near-zero.
// Formula: min(1.0, 1.0 / log2(uniqueIPs + 1))
func (t *ReserseTracker) fingerprintWeight(fingerprint string) float64 {
	if fingerprint == "" {
		return 0.0
	}
	val, ok := t.fpUniqueIPs.Load(fingerprint)
	if !ok {
		return 1.0 // unseen fingerprint = assume unique
	}
	count := 0
	val.(*sync.Map).Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	if count <= 1 {
		return 1.0
	}
	return math.Min(1.0, 1.0/math.Log2(float64(count)+1))
}

// isGenericFingerprint returns true if the fingerprint is shared by too many IPs
func (t *ReserseTracker) isGenericFingerprint(fingerprint string) bool {
	if fingerprint == "" {
		return false
	}
	val, ok := t.fpUniqueIPs.Load(fingerprint)
	if !ok {
		return false
	}
	count := 0
	val.(*sync.Map).Range(func(_, _ interface{}) bool {
		count++
		return count <= genericFPThreshold // stop counting early
	})
	return count > genericFPThreshold
}

// CorrelationSignals contains multi-signal correlation data
type CorrelationSignals struct {
	IP            string
	Fingerprint   string
	UserAgent     string
	GeoLocation   string
	ASN           string
	HeaderPattern string
	AttackPhase   string
	Timestamp     time.Time
}

// Track tracks an event and links it to a profile using advanced multi-signal correlation
func (t *ReserseTracker) Track(ip string, fingerprint string, event TimelineEvent) *ReserseProfile {
	// Track fingerprint frequency for weight calculation
	t.trackFingerprintIP(fingerprint, ip)

	// Try exact IP match first (fast path)
	if profileID, exists := t.ipToProfile.Load(ip); exists {
		if profileVal, ok := t.profiles.Load(profileID); ok {
			profile := profileVal.(*ReserseProfile)
			t.updateProfile(profile, ip, fingerprint, event)
			return profile
		}
	}

	// Try exact fingerprint match — but ONLY if fingerprint is unique enough.
	// Generic fingerprints (shared by >10 IPs, e.g. Go net/http default) would
	// cause false-positive correlations (like Censys ↔ unrelated scanners).
	if fingerprint != "" && !t.isGenericFingerprint(fingerprint) {
		if profileID, exists := t.fpToProfile.Load(fingerprint); exists {
			if profileVal, ok := t.profiles.Load(profileID); ok {
				profile := profileVal.(*ReserseProfile)
				t.ipToProfile.Store(ip, profile.ID)
				t.updateProfile(profile, ip, fingerprint, event)
				return profile
			}
		}
	}

	// Advanced multi-signal correlation for new IPs
	// (fingerprint weight is applied inside calculateCorrelationScore)
	if profile := t.correlateAdvanced(ip, fingerprint, event); profile != nil {
		t.multiIPCorrelations++
		t.ipToProfile.Store(ip, profile.ID)
		t.updateProfile(profile, ip, fingerprint, event)
		return profile
	}

	// No correlation found - create new profile
	profile := t.createProfile(ip, fingerprint, event)
	return profile
}

// correlateAdvanced performs multi-signal correlation to link new IPs to existing profiles
func (t *ReserseTracker) correlateAdvanced(ip string, fingerprint string, event TimelineEvent) *ReserseProfile {
	var bestMatch *ReserseProfile
	bestScore := 0.0

	// Get all active profiles (attacked within temporal window)
	cutoff := time.Now().Add(-t.temporalWindow)

	t.profiles.Range(func(_, value interface{}) bool {
		profile := value.(*ReserseProfile)

		// Skip if profile is too old (outside temporal window)
		if profile.LastSeen.Before(cutoff) {
			return true
		}

		score := t.calculateCorrelationScore(ip, fingerprint, event, profile)

		if score >= t.correlationThreshold && score > bestScore {
			bestScore = score
			bestMatch = profile
		}

		return true
	})

	return bestMatch
}

// calculateCorrelationScore computes weighted correlation score using multiple signals
func (t *ReserseTracker) calculateCorrelationScore(ip string, fingerprint string, event TimelineEvent, profile *ReserseProfile) float64 {
	profile.lock.RLock()
	defer profile.lock.RUnlock()

	score := 0.0

	// Signal 1: IP Subnet Similarity (30% weight)
	for _, existingIP := range profile.IPs {
		if sameSubnet(ip, existingIP, 24) {
			score += 0.30
			break
		} else if sameSubnet(ip, existingIP, 16) {
			score += 0.15
			break
		}
	}

	// Signal 2: Fingerprint Match (40% weight, scaled by uniqueness)
	// Generic fingerprints shared by many IPs get reduced weight to prevent
	// false correlations (e.g. Go net/http default fingerprint → 269 IPs).
	if fingerprint != "" {
		fpWeight := t.fingerprintWeight(fingerprint)
		for _, fp := range profile.Fingerprints {
			if fp == fingerprint {
				score += 0.40 * fpWeight
				break
			} else if fuzzyFingerprintMatch(fp, fingerprint) {
				score += 0.20 * fpWeight
				break
			}
		}
	}

	// Signal 3: Temporal Proximity (20% weight)
	timeDiff := time.Since(profile.LastSeen)
	if timeDiff < 2*time.Minute {
		score += 0.20
	} else if timeDiff < 5*time.Minute {
		score += 0.10
	}

	// Signal 4: User-Agent Consistency (10% weight)
	if event.Description != "" {
		// Extract UA from event description if available
		for _, ua := range profile.UserAgents {
			if ua != "" && strings.Contains(event.Description, ua) {
				score += 0.10
				break
			}
		}
	}

	// Bonus: TTP Signature Match (+50%)
	if event.Signature != "" && profile.TTPSignature != "" {
		eventTTP := generateTTPSignature([]string{event.Signature})
		if eventTTP == profile.TTPSignature {
			score += 0.50
		} else if len(profile.TTPSignature) >= 8 && strings.HasPrefix(eventTTP, profile.TTPSignature[:minInt(8, len(profile.TTPSignature))]) {
			// Partial TTP match
			score += 0.25
		}
	}

	// Bonus: Geo-hopping Pattern Detection (+30%)
	// If IP geo changes but timing + behavior matches = likely VPN rotation
	if len(profile.GeoLocations) > 0 && len(profile.IPs) > 0 {
		// Different geo but same attack window = suspicious
		if timeDiff < 3*time.Minute {
			score += 0.30
		}
	}

	// Bonus: Header Injection Pattern Match (+20%)
	if event.Path != "" {
		for _, pattern := range profile.HeaderPatterns {
			if pattern != "" && strings.Contains(event.Description, pattern) {
				score += 0.20
				break
			}
		}
	}

	return score
}

// createProfile creates a new Reserse profile
func (t *ReserseTracker) createProfile(ip string, fingerprint string, event TimelineEvent) *ReserseProfile {
	id := generateProfileID()

	profile := &ReserseProfile{
		ID:          id,
		IPs:         []string{ip},
		FirstSeen:   time.Now(),
		LastSeen:    time.Now(),
		ThreatLevel: "unknown",
		Timeline:    []TimelineEvent{event},
		RequestPattern: &RequestPattern{
			MethodRatio: make(map[string]float64),
		},
		TimingPattern:     &TimingPattern{},
		NavigationPattern: &NavigationPattern{},
	}

	if fingerprint != "" {
		profile.Fingerprints = []string{fingerprint}
		t.fpToProfile.Store(fingerprint, id)
	}

	t.profiles.Store(id, profile)
	t.ipToProfile.Store(ip, id)
	t.totalProfiles++

	return profile
}

// updateProfile updates an existing profile
func (t *ReserseTracker) updateProfile(profile *ReserseProfile, ip string, fingerprint string, event TimelineEvent) {
	profile.lock.Lock()
	defer profile.lock.Unlock()

	profile.LastSeen = time.Now()
	profile.Timeline = append(profile.Timeline, event)

	// Add IP if new
	if !containsStr(profile.IPs, ip) {
		profile.IPs = append(profile.IPs, ip)
		t.ipToProfile.Store(ip, profile.ID)
	}

	// Add fingerprint if new
	if fingerprint != "" && !containsStr(profile.Fingerprints, fingerprint) {
		profile.Fingerprints = append(profile.Fingerprints, fingerprint)
		t.fpToProfile.Store(fingerprint, profile.ID)
	}

	// Update timing pattern
	hour := time.Now().Hour()
	day := time.Now().Weekday()
	profile.TimingPattern.ActiveHours[hour]++
	profile.TimingPattern.ActiveDays[day]++

	// Add technique if new
	if event.Signature != "" && !containsStr(profile.TTPProfile, event.Signature) {
		profile.TTPProfile = append(profile.TTPProfile, event.Signature)
		// Regenerate TTP signature
		profile.TTPSignature = generateTTPSignature(profile.TTPProfile)
		if profile.TTPSignature != "" {
			t.ttpToProfile.Store(profile.TTPSignature, profile.ID)
		}
	}

	// Extract and track User-Agent from event description
	if strings.Contains(event.Description, "User-Agent:") {
		parts := strings.Split(event.Description, "User-Agent:")
		if len(parts) > 1 {
			ua := strings.TrimSpace(strings.Split(parts[1], ",")[0])
			if ua != "" && !containsStr(profile.UserAgents, ua) {
				profile.UserAgents = append(profile.UserAgents, ua)
			}
		}
	}

	// Track header patterns (e.g., X-Forwarded-For injection)
	if strings.Contains(event.Description, "X-Forwarded-For") || strings.Contains(event.Description, "header injection") {
		pattern := "xff_injection"
		if !containsStr(profile.HeaderPatterns, pattern) {
			profile.HeaderPatterns = append(profile.HeaderPatterns, pattern)
		}
	}

	// Update threat level based on activity
	profile.ThreatLevel = t.calculateThreatLevel(profile)

	// Keep timeline bounded
	if len(profile.Timeline) > 1000 {
		profile.Timeline = profile.Timeline[len(profile.Timeline)-1000:]
	}

	t.correlatedEvents++
}

// calculateThreatLevel calculates the threat level for a profile
func (t *ReserseTracker) calculateThreatLevel(profile *ReserseProfile) string {
	score := 0.0

	// More IPs = more persistent/sophisticated
	score += float64(len(profile.IPs)) * 0.1

	// More fingerprints = likely evasion attempts
	score += float64(len(profile.Fingerprints)) * 0.15

	// More techniques = more capable
	score += float64(len(profile.TTPProfile)) * 0.2

	// Timeline length indicates persistence
	score += float64(len(profile.Timeline)) * 0.01

	// Duration indicates determination
	duration := time.Since(profile.FirstSeen).Hours()
	if duration > 24 {
		score += 0.2
	}
	if duration > 168 { // 1 week
		score += 0.3
	}

	if score >= 2.0 {
		return "critical"
	} else if score >= 1.0 {
		return "high"
	} else if score >= 0.5 {
		return "medium"
	}
	return "low"
}

// GetProfile returns a profile by ID
func (t *ReserseTracker) GetProfile(id string) *ReserseProfile {
	if profileVal, exists := t.profiles.Load(id); exists {
		return profileVal.(*ReserseProfile)
	}
	return nil
}

// GetProfileTimeline returns a copy of the timeline for a profile, optionally limited to the most recent events.
func (t *ReserseTracker) GetProfileTimeline(id string, limit int) []TimelineEvent {
	profile := t.GetProfile(id)
	if profile == nil {
		return nil
	}

	profile.lock.RLock()
	defer profile.lock.RUnlock()

	if len(profile.Timeline) == 0 {
		return []TimelineEvent{}
	}

	start := 0
	if limit > 0 && len(profile.Timeline) > limit {
		start = len(profile.Timeline) - limit
	}

	result := make([]TimelineEvent, len(profile.Timeline[start:]))
	copy(result, profile.Timeline[start:])
	return result
}

// GetProfileByIP returns a profile by IP
func (t *ReserseTracker) GetProfileByIP(ip string) *ReserseProfile {
	if profileID, exists := t.ipToProfile.Load(ip); exists {
		if profileVal, ok := t.profiles.Load(profileID); ok {
			return profileVal.(*ReserseProfile)
		}
	}
	return nil
}

// GetAllProfiles returns all profiles
func (t *ReserseTracker) GetAllProfiles() []*ReserseProfile {
	var result []*ReserseProfile

	t.profiles.Range(func(_, value interface{}) bool {
		profile := value.(*ReserseProfile)
		result = append(result, profile)
		return true
	})

	return result
}

// GetHighThreatProfiles returns profiles with high/critical threat levels
func (t *ReserseTracker) GetHighThreatProfiles() []*ReserseProfile {
	var result []*ReserseProfile

	t.profiles.Range(func(_, value interface{}) bool {
		profile := value.(*ReserseProfile)
		if profile.ThreatLevel == "high" || profile.ThreatLevel == "critical" {
			result = append(result, profile)
		}
		return true
	})

	return result
}

// Correlate finds related profiles based on behavioral similarity
func (t *ReserseTracker) Correlate(profile *ReserseProfile) []*ReserseProfile {
	var related []*ReserseProfile

	t.profiles.Range(func(_, value interface{}) bool {
		other := value.(*ReserseProfile)
		if other.ID == profile.ID {
			return true
		}

		similarity := t.calculateSimilarity(profile, other)
		if similarity >= t.correlationThreshold {
			related = append(related, other)
		}

		return true
	})

	return related
}

// calculateSimilarity calculates behavioral similarity between profiles
func (t *ReserseTracker) calculateSimilarity(a, b *ReserseProfile) float64 {
	score := 0.0
	factors := 0.0

	// Shared fingerprints (weighted by uniqueness)
	sharedFPWeight := 0.0
	for _, fp := range a.Fingerprints {
		if containsStr(b.Fingerprints, fp) {
			sharedFPWeight += t.fingerprintWeight(fp)
		}
	}
	if len(a.Fingerprints) > 0 {
		score += sharedFPWeight / float64(len(a.Fingerprints))
		factors++
	}

	// Shared techniques
	sharedTTP := 0
	for _, ttp := range a.TTPProfile {
		if containsStr(b.TTPProfile, ttp) {
			sharedTTP++
		}
	}
	if len(a.TTPProfile) > 0 {
		score += float64(sharedTTP) / float64(len(a.TTPProfile))
		factors++
	}

	// Similar timing patterns
	timingSimilarity := calculateTimingSimilarity(a.TimingPattern, b.TimingPattern)
	score += timingSimilarity
	factors++

	if factors == 0 {
		return 0
	}

	return score / factors
}

// calculateTimingSimilarity calculates timing pattern similarity
func calculateTimingSimilarity(a, b *TimingPattern) float64 {
	if a == nil || b == nil {
		return 0
	}

	// Compare active hours
	similarity := 0.0
	for i := 0; i < 24; i++ {
		if a.ActiveHours[i] > 0 && b.ActiveHours[i] > 0 {
			similarity += 1.0 / 24.0
		}
	}

	return similarity
}

// RecordBlock records a block event for a profile and tracks persistence
func (t *ReserseTracker) RecordBlock(ip string) {
	profile := t.GetProfileByIP(ip)
	if profile == nil {
		return
	}

	profile.lock.Lock()
	defer profile.lock.Unlock()

	profile.BlocksTriggered++
	profile.LastBlockTime = time.Now()
}

// RecordPostBlockRequest tracks requests made after being blocked
func (t *ReserseTracker) RecordPostBlockRequest(ip string) int {
	profile := t.GetProfileByIP(ip)
	if profile == nil {
		return 0
	}

	profile.lock.Lock()
	defer profile.lock.Unlock()

	// Only count if block was recent (within last hour)
	if !profile.LastBlockTime.IsZero() && time.Since(profile.LastBlockTime) < time.Hour {
		profile.RequestsAfterBlock++
	}

	return profile.RequestsAfterBlock
}

// ShouldEscalateBlock determines if a blocked IP should get escalated enforcement
func (t *ReserseTracker) ShouldEscalateBlock(ip string) (bool, time.Duration, string) {
	profile := t.GetProfileByIP(ip)
	if profile == nil {
		return false, 0, ""
	}

	profile.lock.RLock()
	defer profile.lock.RUnlock()

	// Persistent offender: 50+ requests after block
	if profile.RequestsAfterBlock > 50 {
		// Exponential backoff: 2^blocks hours
		duration := time.Hour * time.Duration(math.Pow(2, float64(profile.BlocksTriggered)))
		if duration > 168*time.Hour { // Cap at 1 week
			duration = 168 * time.Hour
		}
		reason := fmt.Sprintf("Persistent attacker: %d requests after block, %d blocks triggered",
			profile.RequestsAfterBlock, profile.BlocksTriggered)
		return true, duration, reason
	}

	// Multiple blocks in short time
	if profile.BlocksTriggered >= 3 {
		duration := time.Hour * 24 * time.Duration(profile.BlocksTriggered)
		if duration > 168*time.Hour {
			duration = 168 * time.Hour
		}
		reason := fmt.Sprintf("Repeated blocks: %d times", profile.BlocksTriggered)
		return true, duration, reason
	}

	return false, 0, ""
}

// Stats returns tracker statistics
func (t *ReserseTracker) Stats() map[string]interface{} {
	highThreat := 0
	criticalThreat := 0
	multiIP := 0
	persistent := 0

	t.profiles.Range(func(_, value interface{}) bool {
		profile := value.(*ReserseProfile)
		if profile.ThreatLevel == "high" {
			highThreat++
		} else if profile.ThreatLevel == "critical" {
			criticalThreat++
		}
		if len(profile.IPs) > 1 {
			multiIP++
		}
		if profile.RequestsAfterBlock > 50 {
			persistent++
		}
		return true
	})

	// Count tracked fingerprints and generic ones
	trackedFPs := 0
	genericFPs := 0
	t.fpUniqueIPs.Range(func(key, value interface{}) bool {
		trackedFPs++
		count := 0
		value.(*sync.Map).Range(func(_, _ interface{}) bool {
			count++
			return count <= genericFPThreshold
		})
		if count > genericFPThreshold {
			genericFPs++
		}
		return true
	})

	return map[string]interface{}{
		"total_profiles":        t.totalProfiles,
		"correlated_events":     t.correlatedEvents,
		"multi_ip_correlations": t.multiIPCorrelations,
		"high_threat":           highThreat,
		"critical_threat":       criticalThreat,
		"multi_ip_actors":       multiIP,
		"persistent_attackers":  persistent,
		"tracked_fingerprints":  trackedFPs,
		"generic_fingerprints":  genericFPs,
	}
}

// ImportLegacyActorMemory loads attacker-memory.json from legacy Node data and
// hydrates Reserse profiles for correlation with new events.
func (t *ReserseTracker) ImportLegacyActorMemory(filePath string) (int, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return 0, err
	}

	var memory legacyActorMemory
	if err := json.Unmarshal(data, &memory); err != nil {
		return 0, err
	}

	imported := 0
	for key, legacy := range memory.Actors {
		ip := legacy.ID
		if ip == "" {
			ip = key
		}
		if ip == "" {
			continue
		}

		if profileID, exists := t.ipToProfile.Load(ip); exists {
			if profileVal, ok := t.profiles.Load(profileID); ok {
				profile := profileVal.(*ReserseProfile)
				for _, event := range legacy.Timeline {
					t.updateProfile(profile, ip, "", convertLegacyEvent(ip, legacy.RiskScore, event))
				}
				applyLegacyThreatLevel(profile, legacy)
				imported++
				continue
			}
		}

		firstSeen := parseLegacyTime(legacy.FirstSeen)
		lastSeen := parseLegacyTime(legacy.LastSeen)
		if lastSeen.IsZero() {
			lastSeen = firstSeen
		}

		profile := &ReserseProfile{
			ID:                legacyProfileID(ip),
			IPs:               []string{ip},
			FirstSeen:         firstSeen,
			LastSeen:          lastSeen,
			ThreatLevel:       legacyThreatLevel(legacy),
			Timeline:          []TimelineEvent{},
			RequestPattern:    &RequestPattern{MethodRatio: make(map[string]float64)},
			TimingPattern:     &TimingPattern{},
			NavigationPattern: &NavigationPattern{},
		}

		for _, event := range legacy.Timeline {
			profile.Timeline = append(profile.Timeline, convertLegacyEvent(ip, legacy.RiskScore, event))
		}

		t.profiles.Store(profile.ID, profile)
		t.ipToProfile.Store(ip, profile.ID)
		t.totalProfiles++
		imported++
	}

	return imported, nil
}

type legacyActorMemory struct {
	Actors map[string]legacyActor `json:"actors"`
}

type legacyActor struct {
	ID        string              `json:"id"`
	FirstSeen string              `json:"firstSeen"`
	LastSeen  string              `json:"lastSeen"`
	Status    string              `json:"status"`
	RiskScore float64             `json:"riskScore"`
	Timeline  []legacyTimelineEvt `json:"timeline"`
}

type legacyTimelineEvt struct {
	Timestamp string                 `json:"timestamp"`
	Action    string                 `json:"action"`
	Details   map[string]interface{} `json:"details"`
	Severity  string                 `json:"severity"`
}

func legacyProfileID(ip string) string {
	return "legacy-" + ip
}

func parseLegacyTime(value string) time.Time {
	if value == "" {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}
	}
	return parsed
}

func legacyThreatLevel(actor legacyActor) string {
	if actor.Status == "BLOCKED" {
		return "critical"
	}
	if actor.RiskScore >= 90 {
		return "critical"
	}
	if actor.RiskScore >= 70 {
		return "high"
	}
	if actor.RiskScore >= 40 {
		return "medium"
	}
	return "low"
}

func applyLegacyThreatLevel(profile *ReserseProfile, actor legacyActor) {
	level := legacyThreatLevel(actor)
	if level == "critical" || (level == "high" && profile.ThreatLevel != "critical") {
		profile.ThreatLevel = level
	}
}

func convertLegacyEvent(ip string, defaultScore float64, legacy legacyTimelineEvt) TimelineEvent {
	when := parseLegacyTime(legacy.Timestamp)
	if when.IsZero() {
		when = time.Now()
	}

	score := defaultScore
	if legacy.Details != nil {
		if confidence, ok := legacy.Details["confidence"].(float64); ok {
			score = confidence * 100
		}
	}

	action := strings.TrimSpace(legacy.Action)
	if action == "" {
		action = "legacy_activity"
	}

	return TimelineEvent{
		Timestamp:   when,
		EventType:   "legacy",
		Description: action,
		IP:          ip,
		Path:        "",
		Signature:   "",
		Score:       score,
	}
}

// Helpers
func containsStr(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func generateProfileID() string {
	return time.Now().Format("20060102-150405.000")
}

// sameSubnet checks if two IPs are in the same subnet
func sameSubnet(ip1, ip2 string, cidr int) bool {
	parsedIP1 := net.ParseIP(ip1)
	parsedIP2 := net.ParseIP(ip2)

	if parsedIP1 == nil || parsedIP2 == nil {
		return false
	}

	// Create CIDR mask
	mask := net.CIDRMask(cidr, 32)
	if parsedIP1.To4() == nil {
		// IPv6
		mask = net.CIDRMask(cidr, 128)
	}

	// Apply mask to both IPs
	network1 := parsedIP1.Mask(mask)
	network2 := parsedIP2.Mask(mask)

	return network1.Equal(network2)
}

// fuzzyFingerprintMatch checks if two fingerprints are similar (share prefix)
func fuzzyFingerprintMatch(fp1, fp2 string) bool {
	if len(fp1) < 8 || len(fp2) < 8 {
		return false
	}

	// Match first 8 characters (indicates similar browser/client)
	return fp1[:8] == fp2[:8]
}

// generateTTPSignature creates a hash signature from TTP techniques
func generateTTPSignature(techniques []string) string {
	if len(techniques) == 0 {
		return ""
	}

	// Sort techniques for consistent hashing
	sorted := make([]string, len(techniques))
	copy(sorted, techniques)
	sort.Strings(sorted)

	// Create hash
	combined := strings.Join(sorted, "|")
	hash := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(hash[:])
}

// minInt returns the smaller of two integers
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
