/*
Package ml - Anomaly Detection Engine

Pure Go implementation of statistical anomaly detection
Based on Node.js SVALINN anomaly-ml.js
*/
package ml

import (
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/aegis/svalinn/internal/netutil"
)

// AnomalyDetector performs ML-based anomaly detection
type AnomalyDetector struct {
	baselines    sync.Map // IP -> *BaselineStats
	transitions  sync.Map // IP -> *PathTransitions
	requestTimes sync.Map // IP -> []time.Time

	// Configuration
	zScoreThreshold float64
	iqrMultiplier   float64
	speedThreshold  float64 // requests per second

	// Statistics
	totalChecks       int64
	anomaliesDetected int64

	mx sync.RWMutex
}

// BaselineStats holds statistical baseline for an IP
type BaselineStats struct {
	Mean    float64
	StdDev  float64
	Samples []float64
	Count   int
}

// PathTransitions tracks path transition patterns
type PathTransitions struct {
	Previous    string
	Transitions map[string]int // fromPath-toPath -> count
}

// AnomalyResult contains detection results
type AnomalyResult struct {
	IsAnomaly  bool
	Severity   string // low, medium, high, critical
	Score      float64
	Reasons    []string
	Detections map[string]bool

	ZScoreAnomaly     bool
	IQRAnomaly        bool
	SpeedAnomaly      bool
	TransitionAnomaly bool
}

// RequestMetrics contains metrics for analysis
type RequestMetrics struct {
	PathLength   int
	QueryLength  int
	HeaderCount  int
	SpecialChars int
	Entropy      float64
	ResponseTime time.Duration
}

// NewAnomalyDetector creates a new anomaly detector
func NewAnomalyDetector() *AnomalyDetector {
	return &AnomalyDetector{
		zScoreThreshold: 3.0, // 3 standard deviations
		iqrMultiplier:   1.5,
		speedThreshold:  100.0, // 100 req/s is suspicious
	}
}

// AnalyzeRequest performs comprehensive anomaly detection
func (a *AnomalyDetector) AnalyzeRequest(r *http.Request, metrics RequestMetrics) *AnomalyResult {
	a.mx.Lock()
	a.totalChecks++
	a.mx.Unlock()

	result := &AnomalyResult{
		Reasons:    []string{},
		Detections: make(map[string]bool),
	}

	ip := getClientIP(r)
	path := r.URL.Path

	// 1. Z-Score Anomaly (Statistical outlier)
	result.ZScoreAnomaly = a.detectZScoreAnomaly(ip, float64(metrics.PathLength))
	if result.ZScoreAnomaly {
		result.Reasons = append(result.Reasons, "Z-Score outlier detected")
		result.Detections["zscore"] = true
	}

	// 2. IQR Anomaly (Interquartile range)
	result.IQRAnomaly = a.detectIQRAnomaly(ip, float64(metrics.HeaderCount))
	if result.IQRAnomaly {
		result.Reasons = append(result.Reasons, "IQR outlier detected")
		result.Detections["iqr"] = true
	}

	// 3. Speed Anomaly (Rapid requests)
	result.SpeedAnomaly = a.detectSpeedAnomaly(ip)
	if result.SpeedAnomaly {
		result.Reasons = append(result.Reasons, "High request velocity detected")
		result.Detections["speed"] = true
	}

	// 4. Transition Anomaly (Unusual path sequences)
	result.TransitionAnomaly = a.detectTransitionAnomaly(ip, path)
	if result.TransitionAnomaly {
		result.Reasons = append(result.Reasons, "Unusual path transition detected")
		result.Detections["transition"] = true
	}

	// Calculate overall anomaly score
	score := 0.0
	if result.ZScoreAnomaly {
		score += 0.3
	}
	if result.IQRAnomaly {
		score += 0.2
	}
	if result.SpeedAnomaly {
		score += 0.3
	}
	if result.TransitionAnomaly {
		score += 0.2
	}

	result.Score = score
	result.IsAnomaly = score > 0.5

	// Determine severity
	if score >= 0.8 {
		result.Severity = "critical"
	} else if score >= 0.6 {
		result.Severity = "high"
	} else if score >= 0.4 {
		result.Severity = "medium"
	} else {
		result.Severity = "low"
	}

	if result.IsAnomaly {
		a.mx.Lock()
		a.anomaliesDetected++
		a.mx.Unlock()
	}

	// Update baselines
	a.updateBaseline(ip, float64(metrics.PathLength))

	return result
}

// detectZScoreAnomaly detects statistical outliers
func (a *AnomalyDetector) detectZScoreAnomaly(ip string, value float64) bool {
	baselineVal, exists := a.baselines.Load(ip)
	if !exists {
		return false // Not enough data yet
	}

	baseline := baselineVal.(*BaselineStats)
	if baseline.Count < 10 {
		return false // Need more samples
	}

	// Z-Score = |value - mean| / stddev
	zScore := math.Abs(value-baseline.Mean) / baseline.StdDev

	return zScore > a.zScoreThreshold
}

// detectIQRAnomaly detects outliers using Interquartile Range
func (a *AnomalyDetector) detectIQRAnomaly(ip string, value float64) bool {
	baselineVal, exists := a.baselines.Load(ip)
	if !exists {
		return false
	}

	baseline := baselineVal.(*BaselineStats)
	if len(baseline.Samples) < 20 {
		return false
	}

	// Calculate Q1 and Q3
	sorted := make([]float64, len(baseline.Samples))
	copy(sorted, baseline.Samples)
	sortFloat64s(sorted)

	n := len(sorted)
	q1 := sorted[n/4]
	q3 := sorted[3*n/4]
	iqr := q3 - q1

	// Outlier if outside [Q1 - 1.5*IQR, Q3 + 1.5*IQR]
	lowerBound := q1 - a.iqrMultiplier*iqr
	upperBound := q3 + a.iqrMultiplier*iqr

	return value < lowerBound || value > upperBound
}

// detectSpeedAnomaly detects rapid request patterns
func (a *AnomalyDetector) detectSpeedAnomaly(ip string) bool {
	now := time.Now()

	// Get request times for this IP
	var times []time.Time
	if timesVal, exists := a.requestTimes.Load(ip); exists {
		times = timesVal.([]time.Time)
	}

	// Add current request
	times = append(times, now)

	// Keep only last 100 requests
	if len(times) > 100 {
		times = times[len(times)-100:]
	}

	a.requestTimes.Store(ip, times)

	// Check requests in last second
	if len(times) < 10 {
		return false
	}

	oneSecondAgo := now.Add(-1 * time.Second)
	recentCount := 0
	for _, t := range times {
		if t.After(oneSecondAgo) {
			recentCount++
		}
	}

	reqPerSec := float64(recentCount)
	return reqPerSec > a.speedThreshold
}

// detectTransitionAnomaly detects unusual path sequences
func (a *AnomalyDetector) detectTransitionAnomaly(ip, currentPath string) bool {
	transVal, exists := a.transitions.Load(ip)
	if !exists {
		// First request - create transition tracker
		trans := &PathTransitions{
			Previous:    currentPath,
			Transitions: make(map[string]int),
		}
		a.transitions.Store(ip, trans)
		return false
	}

	trans := transVal.(*PathTransitions)

	// Record transition
	transitionKey := trans.Previous + "->" + currentPath
	trans.Transitions[transitionKey]++

	// Check if this is a new/rare transition
	total := 0
	for _, count := range trans.Transitions {
		total += count
	}

	currentCount := trans.Transitions[transitionKey]
	probability := float64(currentCount) / float64(total)

	// Update previous path
	trans.Previous = currentPath

	// Anomaly if transition probability < 10% and we have seen >= 20 transitions
	return total >= 20 && probability < 0.1
}

// updateBaseline updates statistical baseline for an IP
func (a *AnomalyDetector) updateBaseline(ip string, value float64) {
	baselineVal, exists := a.baselines.Load(ip)
	var baseline *BaselineStats

	if !exists {
		baseline = &BaselineStats{
			Samples: []float64{},
		}
	} else {
		baseline = baselineVal.(*BaselineStats)
	}

	// Add sample
	baseline.Samples = append(baseline.Samples, value)
	baseline.Count++

	// Keep only last 1000 samples
	if len(baseline.Samples) > 1000 {
		baseline.Samples = baseline.Samples[len(baseline.Samples)-1000:]
	}

	// Recalculate statistics
	sum := 0.0
	for _, s := range baseline.Samples {
		sum += s
	}
	baseline.Mean = sum / float64(len(baseline.Samples))

	// Calculate standard deviation
	variance := 0.0
	for _, s := range baseline.Samples {
		diff := s - baseline.Mean
		variance += diff * diff
	}
	variance /= float64(len(baseline.Samples))
	baseline.StdDev = math.Sqrt(variance)

	a.baselines.Store(ip, baseline)
}

// GetStats returns detector statistics
func (a *AnomalyDetector) GetStats() map[string]interface{} {
	a.mx.RLock()
	defer a.mx.RUnlock()

	baselineCount := 0
	a.baselines.Range(func(_, _ interface{}) bool {
		baselineCount++
		return true
	})

	return map[string]interface{}{
		"total_checks":       a.totalChecks,
		"anomalies_detected": a.anomaliesDetected,
		"tracked_ips":        baselineCount,
		"enabled":            true,
	}
}

// Helper functions
// getClientIP resolves the request's client address, which keys every anomaly
// baseline, path-transition chain and request-time series in this package. Trust
// decisions live in netutil (REQ SVALINN-CLIENTIP-SPOOF-002): only the local
// nginx peer may speak for another address, so an attacker cannot rotate a
// forged header to keep the ML baselines permanently empty.
func getClientIP(r *http.Request) string {
	return netutil.TrustedClientIP(r)
}

func sortFloat64s(arr []float64) {
	// Simple bubble sort (good enough for small arrays)
	n := len(arr)
	for i := 0; i < n-1; i++ {
		for j := 0; j < n-i-1; j++ {
			if arr[j] > arr[j+1] {
				arr[j], arr[j+1] = arr[j+1], arr[j]
			}
		}
	}
}
