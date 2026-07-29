/*
Package fingerprint - Timing Analysis Module

Tracks request timing patterns to detect automated scanners and bots.
Based on SVALINN Node.js fingerprinting.js timing analysis.
*/
package fingerprint

import (
	"sync"
	"time"
)

// TimingPattern represents request timing data for a fingerprint
type TimingPattern struct {
	FingerprintHash string
	RequestTimes    []time.Time
	Intervals       []time.Duration
	AvgInterval     time.Duration
	MinInterval     time.Duration
	MaxInterval     time.Duration
	StdDev          time.Duration
	IsRapid         bool
	IsRegular       bool // Machine-like regularity
	RiskScore       float64
}

// TimingAnalyzer tracks timing patterns for fingerprints
type TimingAnalyzer struct {
	patterns       sync.Map      // map[string]*TimingPattern
	maxHistory     int           // Maximum number of timestamps to keep
	rapidThreshold time.Duration // Threshold for rapid requests
	lock           sync.RWMutex
}

// NewTimingAnalyzer creates a new timing analyzer
func NewTimingAnalyzer() *TimingAnalyzer {
	return &TimingAnalyzer{
		maxHistory:     50,                     // Keep last 50 requests
		rapidThreshold: 100 * time.Millisecond, // < 100ms is suspicious
	}
}

// RecordRequest records a request timestamp for a fingerprint
func (ta *TimingAnalyzer) RecordRequest(fingerprintHash string) *TimingPattern {
	now := time.Now()

	// Get or create pattern
	var pattern *TimingPattern
	if patternVal, exists := ta.patterns.Load(fingerprintHash); exists {
		pattern = patternVal.(*TimingPattern)
	} else {
		pattern = &TimingPattern{
			FingerprintHash: fingerprintHash,
			RequestTimes:    []time.Time{},
			Intervals:       []time.Duration{},
		}
		ta.patterns.Store(fingerprintHash, pattern)
	}

	// Add new timestamp
	pattern.RequestTimes = append(pattern.RequestTimes, now)

	// Calculate interval if we have previous request
	if len(pattern.RequestTimes) > 1 {
		lastIdx := len(pattern.RequestTimes) - 2
		interval := now.Sub(pattern.RequestTimes[lastIdx])
		pattern.Intervals = append(pattern.Intervals, interval)
	}

	// Trim to max history
	if len(pattern.RequestTimes) > ta.maxHistory {
		pattern.RequestTimes = pattern.RequestTimes[len(pattern.RequestTimes)-ta.maxHistory:]
	}
	if len(pattern.Intervals) > ta.maxHistory-1 {
		pattern.Intervals = pattern.Intervals[len(pattern.Intervals)-(ta.maxHistory-1):]
	}

	// Analyze pattern
	ta.analyzePattern(pattern)

	return pattern
}

// analyzePattern analyzes timing patterns for suspicious behavior
func (ta *TimingAnalyzer) analyzePattern(pattern *TimingPattern) {
	if len(pattern.Intervals) < 2 {
		return
	}

	// Calculate statistics
	var sum time.Duration
	min := pattern.Intervals[0]
	max := pattern.Intervals[0]

	for _, interval := range pattern.Intervals {
		sum += interval
		if interval < min {
			min = interval
		}
		if interval > max {
			max = interval
		}
	}

	avg := sum / time.Duration(len(pattern.Intervals))
	pattern.AvgInterval = avg
	pattern.MinInterval = min
	pattern.MaxInterval = max

	// Calculate standard deviation
	var variance float64
	for _, interval := range pattern.Intervals {
		diff := float64(interval - avg)
		variance += diff * diff
	}
	variance /= float64(len(pattern.Intervals))
	stdDev := time.Duration(variance) // Simplified

	pattern.StdDev = stdDev

	// Detect rapid requests
	pattern.IsRapid = min < ta.rapidThreshold

	// Detect regular/machine-like patterns
	// Low standard deviation = very regular intervals = bot
	if len(pattern.Intervals) >= 5 {
		regularity := float64(stdDev) / float64(avg)
		pattern.IsRegular = regularity < 0.2 // Less than 20% variation
	}

	// Calculate risk score
	riskScore := 0.0

	// Rapid requests (+30 risk)
	if pattern.IsRapid {
		riskScore += 30.0
	}

	//  Regular intervals (+40 risk)
	if pattern.IsRegular {
		riskScore += 40.0
	}

	// Very short average interval (< 500ms) (+20 risk)
	if avg < 500*time.Millisecond {
		riskScore += 20.0
	}

	// High request rate in short time (+10 risk)
	if len(pattern.RequestTimes) >= 20 {
		timespan := pattern.RequestTimes[len(pattern.RequestTimes)-1].Sub(pattern.RequestTimes[0])
		if timespan < 10*time.Second {
			riskScore += 10.0
		}
	}

	pattern.RiskScore = riskScore
}

// GetPattern returns timing pattern for a fingerprint
func (ta *TimingAnalyzer) GetPattern(fingerprintHash string) *TimingPattern {
	if patternVal, exists := ta.patterns.Load(fingerprintHash); exists {
		return patternVal.(*TimingPattern)
	}
	return nil
}

// Stats returns timing analyzer statistics
func (ta *TimingAnalyzer) Stats() map[string]interface{} {
	totalPatterns := 0
	rapidCount := 0
	regularCount := 0

	ta.patterns.Range(func(_, value interface{}) bool {
		totalPatterns++
		pattern := value.(*TimingPattern)
		if pattern.IsRapid {
			rapidCount++
		}
		if pattern.IsRegular {
			regularCount++
		}
		return true
	})

	return map[string]interface{}{
		"total_patterns": totalPatterns,
		"rapid_count":    rapidCount,
		"regular_count":  regularCount,
	}
}
