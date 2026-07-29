/*
Package ml - Triangulation engine for intelligence validation.

Ported from Node.js triangulation-engine.js (Phase 3).
*/
package ml

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// TriangulationConfig controls triangulation weights and thresholds.
type TriangulationConfig struct {
	DeterministicWeight float64
	BehavioralWeight    float64
	OSINTWeight         float64
	HighConfidence      float64
	MediumConfidence    float64
	LowConfidence       float64
}

// TriangulationEngine validates intelligence items through multiple layers.
type TriangulationEngine struct {
	config TriangulationConfig
}

// TriangulationCheck describes a validation check.
type TriangulationCheck struct {
	Check      string      `json:"check"`
	Passed     bool        `json:"passed"`
	Confidence float64     `json:"confidence,omitempty"`
	Reason     string      `json:"reason,omitempty"`
	Meta       interface{} `json:"meta,omitempty"`
}

// TriangulationLayerResult contains the output of a single layer.
type TriangulationLayerResult struct {
	Passed     bool                 `json:"passed"`
	Confidence float64              `json:"confidence"`
	Checks     []TriangulationCheck `json:"checks"`
	Reason     string               `json:"reason"`
}

// ValidationStep summarizes a layer validation step.
type ValidationStep struct {
	Layer      string  `json:"layer"`
	Passed     bool    `json:"passed"`
	Confidence float64 `json:"confidence"`
	Reason     string  `json:"reason"`
}

// TriangulationResult is the full triangulation output.
type TriangulationResult struct {
	ID               string                             `json:"id"`
	Timestamp        time.Time                          `json:"timestamp"`
	OriginalItem     map[string]interface{}             `json:"originalItem"`
	Layers           map[string]TriangulationLayerResult `json:"layers"`
	FinalConfidence  float64                            `json:"finalConfidence"`
	ConfidenceLevel  string                             `json:"confidenceLevel"`
	Validated        bool                               `json:"validated"`
	ValidationPath   []ValidationStep                   `json:"validationPath"`
	ProcessingTimeMs int64                              `json:"processingTimeMs"`
	LayersPassed     int                                `json:"layersPassed"`
	LayersTotal      int                                `json:"layersTotal"`
	Error            string                             `json:"error,omitempty"`
}

// NewTriangulationEngine creates a new triangulation engine.
func NewTriangulationEngine(cfg TriangulationConfig) *TriangulationEngine {
	if cfg.DeterministicWeight == 0 {
		cfg.DeterministicWeight = 0.40
	}
	if cfg.BehavioralWeight == 0 {
		cfg.BehavioralWeight = 0.35
	}
	if cfg.OSINTWeight == 0 {
		cfg.OSINTWeight = 0.25
	}
	if cfg.HighConfidence == 0 {
		cfg.HighConfidence = 0.80
	}
	if cfg.MediumConfidence == 0 {
		cfg.MediumConfidence = 0.60
	}
	if cfg.LowConfidence == 0 {
		cfg.LowConfidence = 0.40
	}

	return &TriangulationEngine{config: cfg}
}

// Triangulate validates a single intelligence item.
func (t *TriangulationEngine) Triangulate(item map[string]interface{}) *TriangulationResult {
	start := time.Now()
	result := &TriangulationResult{
		ID:           hashID(fmt.Sprintf("%v-%v", time.Now().UnixNano(), item["id"])),
		Timestamp:    time.Now(),
		OriginalItem: item,
		Layers:       make(map[string]TriangulationLayerResult),
		LayersTotal:  3,
	}

	deterministic := t.validateDeterministic(item)
	behavioral := t.validateBehavioral(item)
	osint := t.validateOSINT(item)

	result.Layers["deterministic"] = deterministic
	result.Layers["behavioral"] = behavioral
	result.Layers["osint"] = osint

	result.ValidationPath = []ValidationStep{
		{Layer: "DETERMINISTIC", Passed: deterministic.Passed, Confidence: deterministic.Confidence, Reason: deterministic.Reason},
		{Layer: "BEHAVIORAL", Passed: behavioral.Passed, Confidence: behavioral.Confidence, Reason: behavioral.Reason},
		{Layer: "OSINT", Passed: osint.Passed, Confidence: osint.Confidence, Reason: osint.Reason},
	}

	result.FinalConfidence = t.calculateFinalConfidence(deterministic, behavioral, osint)
	result.ConfidenceLevel = t.getConfidenceLevel(result.FinalConfidence)
	result.Validated = result.FinalConfidence >= t.config.LowConfidence

	passedLayers := 0
	if deterministic.Passed {
		passedLayers++
	}
	if behavioral.Passed {
		passedLayers++
	}
	if osint.Passed {
		passedLayers++
	}
	result.LayersPassed = passedLayers
	result.ProcessingTimeMs = time.Since(start).Milliseconds()
	return result
}

func (t *TriangulationEngine) validateDeterministic(item map[string]interface{}) TriangulationLayerResult {
	checks := make([]TriangulationCheck, 0)
	maxScore := 0.0
	totalScore := 0.0

	maxScore++
	severityValid := t.validateSeverity(item)
	checks = append(checks, TriangulationCheck{Check: "severity_valid", Passed: severityValid})
	if severityValid {
		totalScore++
	}

	maxScore++
	indicators := t.extractIndicators(item)
	hasIndicators := len(indicators) > 0
	checks = append(checks, TriangulationCheck{Check: "valid_indicators", Passed: hasIndicators, Meta: map[string]interface{}{"count": len(indicators)}})
	if hasIndicators {
		totalScore++
	}

	maxScore++
	sourceScore := t.sourceReputation(item)
	checks = append(checks, TriangulationCheck{Check: "source_reputation", Passed: sourceScore >= 0.5, Confidence: sourceScore})
	if sourceScore >= 0.5 {
		totalScore++
	}

	maxScore++
	fresh := t.isFresh(item)
	checks = append(checks, TriangulationCheck{Check: "data_fresh", Passed: fresh})
	if fresh {
		totalScore++
	}

	maxScore++
	entropyOK := t.validateEntropy(item)
	checks = append(checks, TriangulationCheck{Check: "entropy_valid", Passed: entropyOK})
	if entropyOK {
		totalScore++
	}

	confidence := totalScore / maxScore
	passed := confidence >= 0.6
	reason := fmt.Sprintf("%0.0f/%0.0f deterministic checks passed", totalScore, maxScore)
	if !passed {
		reason = fmt.Sprintf("only %0.0f/%0.0f deterministic checks passed", totalScore, maxScore)
	}

	return TriangulationLayerResult{Passed: passed, Confidence: confidence, Checks: checks, Reason: reason}
}

func (t *TriangulationEngine) validateBehavioral(item map[string]interface{}) TriangulationLayerResult {
	checks := make([]TriangulationCheck, 0)
	maxScore := 0.0
	totalScore := 0.0

	maxScore++
	patterns := t.matchThreatPatterns(item)
	checks = append(checks, TriangulationCheck{Check: "pattern_match", Passed: patterns, Meta: map[string]interface{}{"matched": patterns}})
	if patterns {
		totalScore++
	}

	maxScore++
	sequence := t.hasTags(item)
	checks = append(checks, TriangulationCheck{Check: "sequence_valid", Passed: sequence})
	if sequence {
		totalScore++
	}

	maxScore++
	actorAlign := t.actorAlignment(item)
	checks = append(checks, TriangulationCheck{Check: "ttp_alignment", Passed: actorAlign})
	if actorAlign {
		totalScore++
	}

	confidence := totalScore / maxScore
	passed := confidence >= 0.5
	reason := fmt.Sprintf("behavioral validation %0.0f/%0.0f", totalScore, maxScore)

	return TriangulationLayerResult{Passed: passed, Confidence: confidence, Checks: checks, Reason: reason}
}

func (t *TriangulationEngine) validateOSINT(item map[string]interface{}) TriangulationLayerResult {
	checks := make([]TriangulationCheck, 0)
	maxScore := 0.0
	totalScore := 0.0

	maxScore++
	multiSource := t.hasMultipleSources(item)
	checks = append(checks, TriangulationCheck{Check: "multi_source", Passed: multiSource})
	if multiSource {
		totalScore++
	}

	maxScore++
	geoContext := t.checkGeoContext(item)
	checks = append(checks, TriangulationCheck{Check: "geo_context", Passed: geoContext})
	if geoContext {
		totalScore++
	}

	maxScore++
	timeCorrelation := t.checkTimeCorrelation(item)
	checks = append(checks, TriangulationCheck{Check: "time_correlation", Passed: timeCorrelation})
	if timeCorrelation {
		totalScore++
	}

	confidence := totalScore / maxScore
	passed := confidence >= 0.5
	reason := fmt.Sprintf("osint confirmation %0.0f/%0.0f", totalScore, maxScore)

	return TriangulationLayerResult{Passed: passed, Confidence: confidence, Checks: checks, Reason: reason}
}

func (t *TriangulationEngine) calculateFinalConfidence(det, beh, os TriangulationLayerResult) float64 {
	weighted := det.Confidence*t.config.DeterministicWeight + beh.Confidence*t.config.BehavioralWeight + os.Confidence*t.config.OSINTWeight
	if det.Passed && beh.Passed && os.Passed {
		weighted *= 1.1
	}
	if weighted > 1 {
		weighted = 1
	}
	return weighted
}

func (t *TriangulationEngine) getConfidenceLevel(score float64) string {
	switch {
	case score >= t.config.HighConfidence:
		return "HIGH"
	case score >= t.config.MediumConfidence:
		return "MEDIUM"
	case score >= t.config.LowConfidence:
		return "LOW"
	default:
		return "INSUFFICIENT"
	}
}

func (t *TriangulationEngine) validateSeverity(item map[string]interface{}) bool {
	severity := strings.ToUpper(stringVal(item["severity"]))
	text := strings.ToLower(fmt.Sprintf("%v %v", item["title"], item["description"]))
	if severity == "CRITICAL" {
		return strings.Contains(text, "critical") || strings.Contains(text, "zero-day") || strings.Contains(text, "actively exploited")
	}
	if severity == "HIGH" {
		return strings.Contains(text, "ransomware") || strings.Contains(text, "breach") || strings.Contains(text, "vulnerability")
	}
	return severity != ""
}

func (t *TriangulationEngine) extractIndicators(item map[string]interface{}) []string {
	ind := make([]string, 0)
	if raw, ok := item["indicators"]; ok {
		switch v := raw.(type) {
		case []interface{}:
			for _, entry := range v {
				ind = append(ind, fmt.Sprintf("%v", entry))
			}
		case []string:
			ind = append(ind, v...)
		case string:
			if v != "" {
				ind = append(ind, v)
			}
		}
	}
	return ind
}

func (t *TriangulationEngine) sourceReputation(item map[string]interface{}) float64 {
	source := strings.ToLower(stringVal(item["source"]))
	if source == "" {
		return 0.5
	}
	reputations := map[string]float64{
		"nvd": 1.0, "cisa": 1.0, "mitre": 1.0,
		"bleepingcomputer": 0.85, "thehackernews": 0.85, "krebs": 0.9,
		"twitter": 0.5, "reddit": 0.4, "pastebin": 0.3,
	}
	for key, score := range reputations {
		if strings.Contains(source, key) {
			return score
		}
	}
	return 0.5
}

func (t *TriangulationEngine) isFresh(item map[string]interface{}) bool {
	if ts, ok := item["timestamp"].(string); ok {
		if parsed, err := time.Parse(time.RFC3339, ts); err == nil {
			return time.Since(parsed) < 7*24*time.Hour
		}
	}
	return true
}

func (t *TriangulationEngine) validateEntropy(item map[string]interface{}) bool {
	text := fmt.Sprintf("%v %v", item["title"], item["description"])
	if len(text) < 10 {
		return false
	}
	unique := make(map[rune]struct{})
	for _, r := range strings.ToLower(text) {
		if r == ' ' {
			continue
		}
		unique[r] = struct{}{}
	}
	entropyRatio := float64(len(unique)) / float64(minInt(len(text), 50))
	return entropyRatio > 0.3
}

func (t *TriangulationEngine) matchThreatPatterns(item map[string]interface{}) bool {
	text := strings.ToLower(fmt.Sprintf("%v %v", item["title"], item["description"]))
	patterns := []string{"ransomware", "phishing", "apt", "breach", "exploit", "zero-day"}
	for _, p := range patterns {
		if strings.Contains(text, p) {
			return true
		}
	}
	return false
}

func (t *TriangulationEngine) hasTags(item map[string]interface{}) bool {
	if tags, ok := item["tags"].([]interface{}); ok {
		return len(tags) > 0
	}
	return false
}

func (t *TriangulationEngine) actorAlignment(item map[string]interface{}) bool {
	text := strings.ToLower(fmt.Sprintf("%v %v", item["title"], item["description"]))
	return strings.Contains(text, "apt") || strings.Contains(text, "campaign")
}

func (t *TriangulationEngine) hasMultipleSources(item map[string]interface{}) bool {
	if sources, ok := item["sources"].([]interface{}); ok {
		return len(sources) > 1
	}
	return stringVal(item["source"]) != ""
}

func (t *TriangulationEngine) checkGeoContext(item map[string]interface{}) bool {
	text := strings.ToLower(fmt.Sprintf("%v %v", item["title"], item["description"]))
	return strings.Contains(text, "sanction") || strings.Contains(text, "conflict") || strings.Contains(text, "election")
}

func (t *TriangulationEngine) checkTimeCorrelation(item map[string]interface{}) bool {
	if ts, ok := item["timestamp"].(string); ok {
		if parsed, err := time.Parse(time.RFC3339, ts); err == nil {
			hour := parsed.Hour()
			return hour >= 6 && hour <= 22
		}
	}
	return true
}

func stringVal(v interface{}) string {
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func hashID(input string) string {
	sum := sha1.Sum([]byte(input))
	return hex.EncodeToString(sum[:])
}
