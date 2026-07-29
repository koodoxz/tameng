/*
Package observatory implements the public threat dashboard for SVALINN.

Migrated from:
- fusion/api-server.js (getObservatoryData, generateObservatoryData)
- fusion/public/observatory.html

The Observatory is a public "Hall of Fame" that shows:
- Top attackers with codenames
- Attack categories
- Real-time threat activity
- Defense outcomes
*/
package observatory

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Actor represents an attacker in the Observatory
type Actor struct {
	Codename      string  `json:"codename"`
	ThreatScore   float64 `json:"threatScore"`
	Type          string  `json:"type"`
	Persistence   string  `json:"persistence"`
	Actions       int     `json:"actions"`
	ActivityLevel string  `json:"activityLevel"`
	Outcome       string  `json:"outcome"`
	LastSeen      string  `json:"lastSeen,omitempty"`
}

// RecentEvent represents a recent security event
type RecentEvent struct {
	Time      string `json:"time"`
	EventType string `json:"eventType"`
	Codename  string `json:"codename"`
	Action    string `json:"action"`
}

// ObservatoryData represents the full observatory response
type ObservatoryData struct {
	Stats struct {
		TotalThreatsToday int     `json:"totalThreatsToday"`
		TotalBlocked      int     `json:"totalBlocked"`
		TotalChallenged   int     `json:"totalChallenged"`
		ActiveActors      int     `json:"activeActors"`
		AvgThreatScore    float64 `json:"avgThreatScore"`
		UptimeHours       float64 `json:"uptimeHours"`
	} `json:"stats"`
	Highlights   []Actor       `json:"highlights"`
	RecentEvents []RecentEvent `json:"recentEvents"`
	LastUpdated  string        `json:"lastUpdated"`
	Version      string        `json:"version"`
}

// ActorProvider interface for getting actor data
type ActorProvider interface {
	GetTopRiskyActors(limit int) []RiskyActor
	GetRecentEvents(limit int) []Event
}

// RiskyActor represents an actor from the tracker
type RiskyActor struct {
	ID               string
	RiskScore        float64
	TotalActions     int
	ActionsByType    map[string]int
	PersistenceScore float64
	Status           string
	LastSeen         time.Time
}

// Event represents a security event
type Event struct {
	Timestamp time.Time
	Type      string
	ActorID   string
	Action    string
}

// Observatory manages the public threat dashboard
type Observatory struct {
	provider  ActorProvider
	cache     *ObservatoryData
	cacheTime time.Time
	cacheTTL  time.Duration
	startTime time.Time

	// Stats
	totalThreats    int64
	totalBlocked    int64
	totalChallenged int64

	lock sync.RWMutex
}

// New creates a new Observatory
func New(provider ActorProvider) *Observatory {
	return &Observatory{
		provider:  provider,
		cacheTTL:  5 * time.Second,
		startTime: time.Now(),
	}
}

// Codename generation constants
var (
	adjectives = []string{"VOID", "SILENT", "PHANTOM", "GHOST", "SHADOW", "IRON", "DARK", "SWIFT", "CYBER", "ARCTIC", "CRIMSON", "ECHO", "OMEGA", "ZERO", "DELTA"}
	animals    = []string{"FOX", "COBRA", "WOLF", "RAVEN", "VIPER", "HAWK", "TIGER", "BEAR", "DRAGON", "FALCON", "LYNX", "PANTHER", "SCORPION", "HYDRA", "PHOENIX"}
)

// GenerateCodename generates a deterministic codename for an actor
func GenerateCodename(id string) string {
	today := time.Now().Format("2006-01-02")
	seed := id + today

	var hash uint32
	for _, c := range seed {
		hash = ((hash << 5) - hash) + uint32(c)
	}

	adj := adjectives[hash%uint32(len(adjectives))]
	animal := animals[(hash>>4)%uint32(len(animals))]

	return fmt.Sprintf("%s-%s", adj, animal)
}

// GetData returns the observatory data (cached)
func (o *Observatory) GetData() *ObservatoryData {
	o.lock.Lock()
	defer o.lock.Unlock()

	now := time.Now()
	if o.cache == nil || now.Sub(o.cacheTime) > o.cacheTTL {
		o.cache = o.generateData()
		o.cacheTime = now
	}

	return o.cache
}

// generateData generates fresh observatory data
func (o *Observatory) generateData() *ObservatoryData {
	data := &ObservatoryData{
		Version:     "SVALINN-GO v1.0",
		LastUpdated: time.Now().Format(time.RFC3339),
	}

	// Stats
	data.Stats.TotalThreatsToday = int(o.totalThreats)
	data.Stats.TotalBlocked = int(o.totalBlocked)
	data.Stats.TotalChallenged = int(o.totalChallenged)
	data.Stats.UptimeHours = time.Since(o.startTime).Hours()

	// Get actors if provider available
	if o.provider != nil {
		actors := o.provider.GetTopRiskyActors(100)

		// Calculate active actors and avg threat score
		var totalScore float64
		for _, actor := range actors {
			totalScore += actor.RiskScore
		}

		data.Stats.ActiveActors = len(actors)
		if len(actors) > 0 {
			data.Stats.AvgThreatScore = totalScore / float64(len(actors))
		}

		// Generate highlights (top 3)
		highlights := o.generateHighlights(actors, 3)
		data.Highlights = highlights

		// Get recent events
		events := o.provider.GetRecentEvents(10)
		data.RecentEvents = o.formatRecentEvents(events)
	}

	return data
}

// generateHighlights generates the Hall of Fame entries
func (o *Observatory) generateHighlights(actors []RiskyActor, limit int) []Actor {
	if len(actors) == 0 {
		return []Actor{}
	}

	if len(actors) < limit {
		limit = len(actors)
	}

	highlights := make([]Actor, limit)

	for i := 0; i < limit; i++ {
		actor := actors[i]

		// Determine category
		category := o.categorizeActor(actor)

		// Determine persistence level
		persistence := "MODERATE"
		if actor.TotalActions > 100 || actor.PersistenceScore > 70 {
			persistence = "CRITICAL"
		} else if actor.TotalActions < 10 {
			persistence = "LOW"
		}

		// Determine activity level
		activityLevel := "Moderate Activity"
		if actor.TotalActions > 200 {
			activityLevel = "High Volumetric (>200 events)"
		} else if actor.TotalActions > 100 {
			activityLevel = "Elevated Volume"
		} else if actor.TotalActions > 50 {
			activityLevel = "Bursty Pattern"
		} else if actor.TotalActions < 20 {
			activityLevel = "Low & Slow"
		}

		// Determine outcome
		outcome := o.determineOutcome(actor, category)

		highlights[i] = Actor{
			Codename:      GenerateCodename(actor.ID),
			ThreatScore:   actor.RiskScore,
			Type:          category,
			Persistence:   persistence,
			Actions:       actor.TotalActions,
			ActivityLevel: activityLevel,
			Outcome:       outcome,
			LastSeen:      actor.LastSeen.Format("15:04:05"),
		}
	}

	return highlights
}

// categorizeActor determines the attack category
func (o *Observatory) categorizeActor(actor RiskyActor) string {
	actions := actor.ActionsByType
	total := actor.TotalActions

	uniqueTools := 0
	for _, count := range actions {
		if count > 0 {
			uniqueTools++
		}
	}

	// Advanced AI detection
	if uniqueTools >= 3 && total > 50 {
		return "Adversarial AI Agent"
	}
	if actions["EXPLOIT_ATTEMPT"] > 10 {
		return "Automated Vuln-Scan"
	}
	if actions["TRAP_HIT"] > 2 {
		return "Active Deception Trap"
	}
	if actions["PROBE"] > 50 || actions["SCAN"] > 50 {
		return "Recursive Fuzzing"
	}
	if actions["CREDENTIAL_STUFFING"] > 0 {
		return "Credential Stuffing"
	}
	if actions["EXPLOIT_ATTEMPT"] > 0 {
		return "Exploit Probing"
	}
	if actions["SUSPICIOUS_FINGERPRINT"] > 0 {
		return "Probe / Scanner"
	}
	if actions["HTTP_REQUEST"] > 20 {
		return "Infrastructure Probing"
	}
	if actions["TRAP_HIT"] > 0 {
		return "CMS Reconnaissance"
	}

	return "Unknown Pattern"
}

// determineOutcome determines the defense outcome
func (o *Observatory) determineOutcome(actor RiskyActor, category string) string {
	outcomes := []string{"CONTAINED", "SHADOW_BANNED", "TARPITTED", "HONEYPOTTED", "QUARANTINED"}

	if actor.Status == "BLOCKED" {
		return "TERMINATED"
	}
	if actor.Status == "ACTIVE_THREAT" {
		return "CONTAINED"
	}
	if category == "Adversarial AI Agent" {
		return "DECOUPLED"
	}

	idx := int(actor.RiskScore) * len(outcomes) / 100
	if idx >= len(outcomes) {
		idx = len(outcomes) - 1
	}

	return outcomes[idx]
}

// formatRecentEvents formats events for display
func (o *Observatory) formatRecentEvents(events []Event) []RecentEvent {
	result := make([]RecentEvent, len(events))

	for i, event := range events {
		result[i] = RecentEvent{
			Time:      event.Timestamp.Format("15:04:05"),
			EventType: event.Type,
			Codename:  GenerateCodename(event.ActorID),
			Action:    event.Action,
		}
	}

	return result
}

// RecordThreat records a threat for stats
func (o *Observatory) RecordThreat() {
	o.lock.Lock()
	defer o.lock.Unlock()
	o.totalThreats++
}

// RecordBlock records a block for stats
func (o *Observatory) RecordBlock() {
	o.lock.Lock()
	defer o.lock.Unlock()
	o.totalBlocked++
}

// RecordChallenge records a challenge for stats
func (o *Observatory) RecordChallenge() {
	o.lock.Lock()
	defer o.lock.Unlock()
	o.totalChallenged++
}

// Handler returns an HTTP handler for the Observatory API
func (o *Observatory) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data := o.GetData()

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=5")
		json.NewEncoder(w).Encode(data)
	}
}
