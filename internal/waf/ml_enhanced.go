/*
Package waf implements ML-enhanced WAF scoring and enforcement.
*/
package waf

import (
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/koodoxz/tameng/internal/ml"
)

// MLEnhancedConfig controls ML-enhanced WAF behavior.
type MLEnhancedConfig struct {
	Enabled        bool
	ModelPath      string
	AlertThreshold float64
	BlockThreshold float64
	MLWeight       float64
	AnomalyWeight  float64
}

// MLEnhancedEngine evaluates ML-based threat scores.
type MLEnhancedEngine struct {
	config  MLEnhancedConfig
	scorer  *ml.ThreatScorer
	anomaly *ml.AnomalyDetector

	lock  sync.Mutex
	stats MLEnhancedStats
}

// MLEnhancedStats tracks ML WAF statistics.
type MLEnhancedStats struct {
	TotalAnalyzed  int64
	AlertsRaised   int64
	BlocksEnforced int64
	TotalScore     float64
}

// MLEnhancedResult holds scoring results.
type MLEnhancedResult struct {
	Score        float64  `json:"score"`
	MLScore      float64  `json:"ml_score"`
	AnomalyScore float64  `json:"anomaly_score"`
	Severity     string   `json:"severity"`
	Reasons      []string `json:"reasons"`
	Blocked      bool     `json:"blocked"`
}

// NewMLEnhancedEngine creates an ML-enhanced WAF engine.
func NewMLEnhancedEngine(cfg MLEnhancedConfig, anomaly *ml.AnomalyDetector, log ml.Logger) (*MLEnhancedEngine, error) {
	if cfg.AlertThreshold == 0 {
		cfg.AlertThreshold = 70
	}
	if cfg.BlockThreshold == 0 {
		cfg.BlockThreshold = 85
	}
	if cfg.MLWeight == 0 {
		cfg.MLWeight = 0.7
	}
	if cfg.AnomalyWeight == 0 {
		cfg.AnomalyWeight = 0.3
	}

	engine := &MLEnhancedEngine{
		config:  cfg,
		anomaly: anomaly,
	}

	if cfg.ModelPath != "" {
		scorer, err := ml.NewThreatScorer(cfg.ModelPath, log)
		if err != nil {
			return nil, err
		}
		engine.scorer = scorer
	}

	return engine, nil
}

// AnalyzeRequest scores a request and returns ML WAF results.
func (e *MLEnhancedEngine) AnalyzeRequest(r *http.Request, status int, responseSize int, responseTime time.Duration, actor interface{}) *MLEnhancedResult {
	if !e.config.Enabled {
		return nil
	}

	features := &ml.ThreatFeatures{}
	mlScore := 50.0
	if e.scorer != nil {
		features = e.scorer.ExtractFeatures(r, actor)
		mlScore = e.scorer.Score(features)
	}

	anomalyScore := 0.0
	reasons := []string{}
	if e.anomaly != nil {
		metrics := buildRequestMetrics(r, status, responseSize, responseTime)
		result := e.anomaly.AnalyzeRequest(r, metrics)
		anomalyScore = result.Score * 100
		if result.IsAnomaly {
			reasons = append(reasons, result.Reasons...)
		}
	}

	weightML, weightAnomaly := normalizeWeights(e.config.MLWeight, e.config.AnomalyWeight)
	finalScore := mlScore*weightML + anomalyScore*weightAnomaly
	severity := severityFromScore(finalScore)
	blocked := finalScore >= e.config.BlockThreshold

	if status >= http.StatusBadRequest {
		reasons = append(reasons, "elevated_error_response")
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "ml_scoring")
	}

	e.lock.Lock()
	e.stats.TotalAnalyzed++
	e.stats.TotalScore += finalScore
	if finalScore >= e.config.AlertThreshold {
		e.stats.AlertsRaised++
	}
	if blocked {
		e.stats.BlocksEnforced++
	}
	e.lock.Unlock()

	return &MLEnhancedResult{
		Score:        finalScore,
		MLScore:      mlScore,
		AnomalyScore: anomalyScore,
		Severity:     severity,
		Reasons:      reasons,
		Blocked:      blocked,
	}
}

// Stats returns ML WAF statistics.
func (e *MLEnhancedEngine) Stats() map[string]interface{} {
	e.lock.Lock()
	defer e.lock.Unlock()

	average := 0.0
	if e.stats.TotalAnalyzed > 0 {
		average = e.stats.TotalScore / float64(e.stats.TotalAnalyzed)
	}

	return map[string]interface{}{
		"total_analyzed":  e.stats.TotalAnalyzed,
		"alerts_raised":   e.stats.AlertsRaised,
		"blocks_enforced": e.stats.BlocksEnforced,
		"average_score":   average,
		"enabled":         e.config.Enabled,
		"alert_threshold": e.config.AlertThreshold,
		"block_threshold": e.config.BlockThreshold,
	}
}

func buildRequestMetrics(r *http.Request, status int, responseSize int, responseTime time.Duration) ml.RequestMetrics {
	path := r.URL.Path + "?" + r.URL.RawQuery
	return ml.RequestMetrics{
		PathLength:   len(r.URL.Path),
		QueryLength:  len(r.URL.RawQuery),
		HeaderCount:  len(r.Header),
		SpecialChars: countSpecialChars(path),
		Entropy:      pathEntropy(path),
		ResponseTime: responseTime,
	}
}

func countSpecialChars(s string) int {
	count := 0
	for _, ch := range s {
		if strings.ContainsRune("'\"<>{}[]()|&;$%*`,\\", ch) {
			count++
		}
	}
	return count
}

func pathEntropy(path string) float64 {
	if len(path) == 0 {
		return 0
	}

	freq := make(map[rune]int)
	for _, ch := range path {
		freq[ch]++
	}

	length := float64(len(path))
	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}

	return math.Min(entropy/5.0, 1.0)
}

func normalizeWeights(mlWeight, anomalyWeight float64) (float64, float64) {
	total := mlWeight + anomalyWeight
	if total <= 0 {
		return 0.7, 0.3
	}
	return mlWeight / total, anomalyWeight / total
}

func severityFromScore(score float64) string {
	switch {
	case score >= 85:
		return "high"
	case score >= 70:
		return "medium"
	case score >= 50:
		return "low"
	default:
		return "info"
	}
}
