/*
Package dataloader implements data loading from JSON files for SVALINN-GO.

This loads imported backup data:
- gray-zone.json
- attacker-memory.json
- forecasts/all_forecasts.json
- evolved-rules.json
*/
package dataloader

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// GrayZoneEvent represents a gray zone security event
type GrayZoneEvent struct {
	Timestamp         string                 `json:"timestamp"`
	IP                string                 `json:"ip"`
	Method            string                 `json:"method"`
	Path              string                 `json:"path"`
	Query             map[string]interface{} `json:"query"`
	Headers           map[string]string      `json:"headers"`
	MLScore           float64                `json:"mlScore"`
	ThreatLevel       string                 `json:"threatLevel"`
	AnomalyScore      float64                `json:"anomalyScore"`
	HoneypotTriggered bool                   `json:"honeypotTriggered"`
	SignatureMatches  []string               `json:"signatureMatches"`
	Fingerprint       string                 `json:"fingerprint"`
	FingerprintRisk   string                 `json:"fingerprintRisk"`
	IsScanner         bool                   `json:"isScanner"`
	IsNewPattern      bool                   `json:"isNewPattern"`
	Category          string                 `json:"category"`
	Blocked           bool                   `json:"blocked"`
	Reason            string                 `json:"reason"`
	EvolutionValue    string                 `json:"evolutionValue"`
}

// ActorMemory represents the attacker memory database
type ActorMemory struct {
	Actors map[string]*Actor `json:"actors"`
}

// Actor represents a tracked attacker
type Actor struct {
	ID                  string       `json:"id"`
	FirstSeen           string       `json:"firstSeen"`
	LastSeen            string       `json:"lastSeen"`
	Status              string       `json:"status"`
	RiskScore           float64      `json:"riskScore"`
	PersistenceScore    float64      `json:"persistenceScore"`
	AggressivenessIndex float64      `json:"aggressivenessIndex"`
	Fingerprint         *Fingerprint `json:"fingerprint"`
	Behavior            *Behavior    `json:"behavior"`
}

// Fingerprint represents actor fingerprint data
type Fingerprint struct {
	IPCluster    []string `json:"ipCluster"`
	ASN          string   `json:"asn"`
	UserAgents   []string `json:"userAgents"`
	HeaderShapes []string `json:"headerShapes"`
	JA3Hash      string   `json:"ja3Hash"`
}

// Behavior represents actor behavior data
type Behavior struct {
	TotalActions  int            `json:"totalActions"`
	ActionsToday  int            `json:"actionsToday"`
	ActionsByHour []int          `json:"actionsByHour"`
	ActionsByType map[string]int `json:"actionsByType"`
}

// Forecast represents a Prophet ML forecast
type Forecast struct {
	Date       string  `json:"ds"`
	Prediction float64 `json:"yhat"`
	Lower      float64 `json:"yhat_lower"`
	Upper      float64 `json:"yhat_upper"`
	ThreatType string  `json:"threat_type"`
}

// EvolvedRule represents a custom WAF rule
type EvolvedRule struct {
	RuleID      string `json:"rule_id"`
	Name        string `json:"name"`
	Pattern     string `json:"pattern"`
	MatchTarget string `json:"match_target"`
	Action      string `json:"action"`
	Score       int    `json:"score"`
	Rationale   string `json:"rationale"`
}

// Loader manages loading and caching of data files
type Loader struct {
	dataDir string

	// Cached data
	grayZone     []GrayZoneEvent
	actorMemory  *ActorMemory
	forecasts    []Forecast
	evolvedRules []EvolvedRule

	// Load timestamps
	lastGrayZoneLoad     time.Time
	lastActorMemoryLoad  time.Time
	lastForecastsLoad    time.Time
	lastEvolvedRulesLoad time.Time

	cacheTTL time.Duration
	lock     sync.RWMutex
}

// NewLoader creates a new data loader
func NewLoader(dataDir string) *Loader {
	return &Loader{
		dataDir:  dataDir,
		cacheTTL: 5 * time.Minute,
	}
}

// GetGrayZone returns gray zone events (cached)
func (l *Loader) GetGrayZone() ([]GrayZoneEvent, error) {
	l.lock.Lock()
	defer l.lock.Unlock()

	if time.Since(l.lastGrayZoneLoad) < l.cacheTTL && l.grayZone != nil {
		return l.grayZone, nil
	}

	data, err := os.ReadFile(filepath.Join(l.dataDir, "gray-zone.json"))
	if err != nil {
		return nil, err
	}

	var events []GrayZoneEvent
	if err := json.Unmarshal(data, &events); err != nil {
		return nil, err
	}

	l.grayZone = events
	l.lastGrayZoneLoad = time.Now()
	return events, nil
}

// GetGrayZoneRecent returns the N most recent gray zone events
func (l *Loader) GetGrayZoneRecent(limit int) ([]GrayZoneEvent, error) {
	events, err := l.GetGrayZone()
	if err != nil {
		return nil, err
	}

	if len(events) <= limit {
		return events, nil
	}

	// Return last N events (most recent)
	return events[len(events)-limit:], nil
}

// GetActorMemory returns the actor memory database
func (l *Loader) GetActorMemory() (*ActorMemory, error) {
	l.lock.Lock()
	defer l.lock.Unlock()

	if time.Since(l.lastActorMemoryLoad) < l.cacheTTL && l.actorMemory != nil {
		return l.actorMemory, nil
	}

	data, err := os.ReadFile(filepath.Join(l.dataDir, "attacker-memory.json"))
	if err != nil {
		return nil, err
	}

	var memory ActorMemory
	if err := json.Unmarshal(data, &memory); err != nil {
		return nil, err
	}

	l.actorMemory = &memory
	l.lastActorMemoryLoad = time.Now()
	return &memory, nil
}

// GetTopActors returns the top N actors by risk score
func (l *Loader) GetTopActors(limit int) ([]*Actor, error) {
	memory, err := l.GetActorMemory()
	if err != nil {
		return nil, err
	}

	// Convert to slice and sort by risk score
	var actors []*Actor
	for _, actor := range memory.Actors {
		actors = append(actors, actor)
	}

	// Simple bubble sort for top N (small dataset)
	for i := 0; i < len(actors) && i < limit; i++ {
		for j := i + 1; j < len(actors); j++ {
			if actors[j].RiskScore > actors[i].RiskScore {
				actors[i], actors[j] = actors[j], actors[i]
			}
		}
	}

	if len(actors) > limit {
		return actors[:limit], nil
	}
	return actors, nil
}

// GetForecasts returns ML forecasts
func (l *Loader) GetForecasts() ([]Forecast, error) {
	l.lock.Lock()
	defer l.lock.Unlock()

	if time.Since(l.lastForecastsLoad) < l.cacheTTL && l.forecasts != nil {
		return l.forecasts, nil
	}

	data, err := os.ReadFile(filepath.Join(l.dataDir, "forecasts", "all_forecasts.json"))
	if err != nil {
		return nil, err
	}

	var forecasts []Forecast
	if err := json.Unmarshal(data, &forecasts); err != nil {
		return nil, err
	}

	l.forecasts = forecasts
	l.lastForecastsLoad = time.Now()
	return forecasts, nil
}

// GetForecastsByType returns forecasts filtered by threat type
func (l *Loader) GetForecastsByType(threatType string) ([]Forecast, error) {
	forecasts, err := l.GetForecasts()
	if err != nil {
		return nil, err
	}

	var filtered []Forecast
	for _, f := range forecasts {
		if f.ThreatType == threatType {
			filtered = append(filtered, f)
		}
	}
	return filtered, nil
}

// GetEvolvedRules returns custom WAF rules
func (l *Loader) GetEvolvedRules() ([]EvolvedRule, error) {
	l.lock.Lock()
	defer l.lock.Unlock()

	if time.Since(l.lastEvolvedRulesLoad) < l.cacheTTL && l.evolvedRules != nil {
		return l.evolvedRules, nil
	}

	data, err := os.ReadFile(filepath.Join(l.dataDir, "evolved-rules.json"))
	if err != nil {
		return nil, err
	}

	var rules []EvolvedRule
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, err
	}

	l.evolvedRules = rules
	l.lastEvolvedRulesLoad = time.Now()
	return rules, nil
}

// Stats returns loader statistics
func (l *Loader) Stats() map[string]interface{} {
	l.lock.RLock()
	defer l.lock.RUnlock()

	return map[string]interface{}{
		"gray_zone_count":     len(l.grayZone),
		"actor_count":         len(l.actorMemory.Actors),
		"forecast_count":      len(l.forecasts),
		"evolved_rules_count": len(l.evolvedRules),
		"data_dir":            l.dataDir,
	}
}
