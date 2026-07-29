/*
Package intel implements STIX/TAXII functionality.
*/
package intel

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// STIXConfig configures STIX/TAXII engine.
type STIXConfig struct {
	Enabled             bool
	DefaultTLP          string
	IOCTTL              time.Duration
	MaxIndicators       int
	ConfidenceThreshold float64
	BlockOnMatch        bool
}

// STIXEngine handles STIX bundles and indicator matching.
type STIXEngine struct {
	config     STIXConfig
	indicators map[string]*STIXIndicator
	stats      STIXStats
	lock       sync.RWMutex
}

// STIXIndicator represents a simplified indicator.
type STIXIndicator struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Pattern     string         `json:"pattern"`
	PatternType string         `json:"pattern_type"`
	ValidFrom   time.Time      `json:"valid_from"`
	ValidUntil  time.Time      `json:"valid_until,omitempty"`
	Labels      []string       `json:"labels"`
	Confidence  float64        `json:"confidence"`
	TLP         string         `json:"tlp"`
	MITRE       string         `json:"mitre"`
	Regex       *regexp.Regexp `json:"-"`
}

// STIXBundle represents a STIX 2.1 bundle.
type STIXBundle struct {
	Type    string        `json:"type"`
	ID      string        `json:"id"`
	Objects []interface{} `json:"objects"`
}

// STIXStats tracks STIX usage.
type STIXStats struct {
	IndicatorsLoaded int64     `json:"indicators_loaded"`
	PatternsMatched  int64     `json:"patterns_matched"`
	BundlesParsed    int64     `json:"bundles_parsed"`
	IOCHits          int64     `json:"ioc_hits"`
	LastUpdate       time.Time `json:"last_update"`
}

// NewSTIXEngine creates a STIX engine.
func NewSTIXEngine(cfg STIXConfig) *STIXEngine {
	if cfg.DefaultTLP == "" {
		cfg.DefaultTLP = "AMBER"
	}
	if cfg.IOCTTL == 0 {
		cfg.IOCTTL = 24 * time.Hour
	}
	if cfg.MaxIndicators == 0 {
		cfg.MaxIndicators = 10000
	}
	if cfg.ConfidenceThreshold == 0 {
		cfg.ConfidenceThreshold = 50
	}

	return &STIXEngine{
		config:     cfg,
		indicators: make(map[string]*STIXIndicator),
	}
}

// ParseBundle parses a STIX bundle and loads indicators.
func (s *STIXEngine) ParseBundle(bundleData interface{}) *STIXBundle {
	if !s.config.Enabled {
		return nil
	}

	bundleBytes, err := json.Marshal(bundleData)
	if err != nil {
		return nil
	}

	var bundle STIXBundle
	if err := json.Unmarshal(bundleBytes, &bundle); err != nil {
		return nil
	}
	if bundle.Type != "bundle" {
		return nil
	}

	s.lock.Lock()
	s.stats.BundlesParsed++
	s.stats.LastUpdate = time.Now()
	s.lock.Unlock()

	for _, obj := range bundle.Objects {
		m, ok := obj.(map[string]interface{})
		if !ok {
			continue
		}
		if typ, ok := m["type"].(string); ok && typ == "indicator" {
			s.addIndicatorFromMap(m)
		}
	}

	return &bundle
}

// ExportBundle exports indicators as a STIX bundle.
func (s *STIXEngine) ExportBundle(limit int) *STIXBundle {
	if !s.config.Enabled {
		return nil
	}

	s.lock.RLock()
	defer s.lock.RUnlock()

	objects := make([]interface{}, 0)
	count := 0
	for _, indicator := range s.indicators {
		if limit > 0 && count >= limit {
			break
		}
		objects = append(objects, map[string]interface{}{
			"type":         "indicator",
			"spec_version": "2.1",
			"id":           indicator.ID,
			"name":         indicator.Name,
			"pattern":      indicator.Pattern,
			"pattern_type": indicator.PatternType,
			"valid_from":   indicator.ValidFrom.Format(time.RFC3339),
			"valid_until":  indicator.ValidUntil.Format(time.RFC3339),
			"confidence":   indicator.Confidence,
			"labels":       indicator.Labels,
		})
		count++
	}

	return &STIXBundle{Type: "bundle", ID: "bundle--" + time.Now().Format("20060102150405"), Objects: objects}
}

// MatchIndicators matches content against stored indicators.
func (s *STIXEngine) MatchIndicators(content string, minConfidence float64) []STIXIndicator {
	if !s.config.Enabled {
		return nil
	}
	if minConfidence == 0 {
		minConfidence = s.config.ConfidenceThreshold
	}

	matches := []STIXIndicator{}

	s.lock.RLock()
	defer s.lock.RUnlock()

	now := time.Now()
	for _, indicator := range s.indicators {
		if indicator.ValidUntil.After(time.Time{}) && indicator.ValidUntil.Before(now) {
			continue
		}
		if indicator.Confidence < minConfidence {
			continue
		}
		if indicator.Regex != nil && indicator.Regex.MatchString(content) {
			matches = append(matches, *indicator)
		}
	}

	if len(matches) > 0 {
		s.lock.Lock()
		s.stats.PatternsMatched += int64(len(matches))
		s.stats.IOCHits += int64(len(matches))
		s.lock.Unlock()
	}

	return matches
}

// Stats returns STIX stats.
func (s *STIXEngine) Stats() map[string]interface{} {
	s.lock.RLock()
	defer s.lock.RUnlock()

	return map[string]interface{}{
		"indicators_loaded":    s.stats.IndicatorsLoaded,
		"patterns_matched":     s.stats.PatternsMatched,
		"bundles_parsed":       s.stats.BundlesParsed,
		"ioc_hits":             s.stats.IOCHits,
		"last_update":          s.stats.LastUpdate,
		"total_indicators":     len(s.indicators),
		"enabled":              s.config.Enabled,
		"default_tlp":          s.config.DefaultTLP,
		"confidence_threshold": s.config.ConfidenceThreshold,
	}
}

func (s *STIXEngine) addIndicatorFromMap(data map[string]interface{}) {
	id, _ := data["id"].(string)
	pattern, _ := data["pattern"].(string)
	patternType, _ := data["pattern_type"].(string)
	name, _ := data["name"].(string)
	confidence := float64FromInterface(data["confidence"], s.config.ConfidenceThreshold)

	if pattern == "" || id == "" {
		return
	}
	regex := patternToRegex(pattern, patternType)
	indicator := &STIXIndicator{
		ID:          id,
		Name:        name,
		Pattern:     pattern,
		PatternType: patternType,
		ValidFrom:   time.Now(),
		ValidUntil:  time.Now().Add(s.config.IOCTTL),
		Confidence:  confidence,
		TLP:         s.config.DefaultTLP,
		Regex:       regex,
	}

	s.lock.Lock()
	defer s.lock.Unlock()
	if s.config.MaxIndicators > 0 && len(s.indicators) >= s.config.MaxIndicators {
		return
	}
	s.indicators[id] = indicator
	s.stats.IndicatorsLoaded++
	s.stats.LastUpdate = time.Now()
}

func patternToRegex(pattern string, patternType string) *regexp.Regexp {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return nil
	}

	if patternType == "pcre" || patternType == "regex" {
		re, err := regexp.Compile(pattern)
		if err == nil {
			return re
		}
		return nil
	}

	valueMatch := regexp.MustCompile(`'([^']+)'`).FindStringSubmatch(pattern)
	if len(valueMatch) == 0 {
		return nil
	}

	escaped := regexp.QuoteMeta(valueMatch[1])
	re, err := regexp.Compile(escaped)
	if err != nil {
		return nil
	}
	return re
}

func float64FromInterface(value interface{}, fallback float64) float64 {
	switch v := value.(type) {
	case float64:
		return v
	case int:
		return float64(v)
	case int64:
		return float64(v)
	case string:
		if parsed, err := strconv.ParseFloat(v, 64); err == nil {
			return parsed
		}
	}
	return fallback
}
