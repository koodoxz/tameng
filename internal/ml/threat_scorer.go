package ml

import (
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/dmitryikh/leaves"
)

// ThreatScorer provides ML-based threat scoring using LightGBM
type ThreatScorer struct {
	model  *leaves.Ensemble
	logger Logger
}

// ThreatFeatures represents features for threat prediction
type ThreatFeatures struct {
	RequestRate    float64 // requests per minute
	PathEntropy    float64 // shannon entropy of path
	PayloadSize    float64 // payload size in bytes
	ErrorRate      float64 // 4xx/5xx error rate
	GeoRisk        float64 // country risk score (0-1)
	UserAgentAge   float64 // normalized UA age
	TimeOfDay      float64 // hour normalized 0-1
	IsSuspiciousUA float64 // 0 or 1
	HasPayload     float64 // 0 or 1
	IsKnownScanner float64 // 0 or 1
}

// NewThreatScorer creates a new threat scorer with LightGBM model
func NewThreatScorer(modelPath string, logger Logger) (*ThreatScorer, error) {
	// Try to load the model
	model, err := leaves.LGEnsembleFromFile(modelPath, true)
	if err != nil {
		// Model file not found - use fallback (no ML)
		logger.Warn("LightGBM model load failed, threat scorer disabled (using rule-based only)", "path", modelPath, "error", err)
		return &ThreatScorer{
			model:  nil,
			logger: logger,
		}, nil
	}

	logger.Info("LightGBM threat scorer initialized", "path", modelPath)

	return &ThreatScorer{
		model:  model,
		logger: logger,
	}, nil
}

// Score calculates ML-based threat score from features
func (ts *ThreatScorer) Score(features *ThreatFeatures) float64 {
	if ts.model == nil {
		// No model loaded, return neutral score
		return 50.0
	}

	// Convert features to slice for prediction
	fv := []float64{
		features.RequestRate,
		features.PathEntropy,
		features.PayloadSize,
		features.ErrorRate,
		features.GeoRisk,
		features.UserAgentAge,
		features.TimeOfDay,
		features.IsSuspiciousUA,
		features.HasPayload,
		features.IsKnownScanner,
	}

	// Get prediction from LightGBM
	predictions := make([]float64, 1) // Output buffer
	err := ts.model.Predict(fv, 0, predictions)
	if err != nil {
		// Prediction failed, return neutral score
		return 50.0
	}

	// Get first prediction (binary classification)
	prediction := predictions[0]

	// Normalize to 0-100 scale
	score := normalizeScore(prediction)

	return score
}

// ExtractFeatures extracts threat features from HTTP request
func (ts *ThreatScorer) ExtractFeatures(r *http.Request, actor interface{}) *ThreatFeatures {
	features := &ThreatFeatures{
		PathEntropy: calculatePathEntropy(r.URL.Path),
		PayloadSize: normalizePayloadSize(r.ContentLength),
		TimeOfDay:   normalizeTimeOfDay(time.Now()),
		HasPayload:  boolToFloat(r.ContentLength > 0),
	}

	// Extract user agent features
	ua := r.UserAgent()
	features.IsSuspiciousUA = boolToFloat(isSuspiciousUserAgent(ua))
	features.UserAgentAge = estimateUserAgentAge(ua)

	// Actor-specific features (if available)
	if actor != nil {
		// Type assertion based on your actor struct
		// features.RequestRate = calculateRequestRate(actor)
		// features.ErrorRate = actor.ErrorRate
		// features.IsKnownScanner = boolToFloat(actor.IsScanner)
		// For now, use defaults
		features.RequestRate = 0.5
		features.ErrorRate = 0.0
		features.IsKnownScanner = 0.0
	}

	// Default geo risk (would need GeoIP integration)
	features.GeoRisk = 0.5

	return features
}

// Helper functions

func normalizeScore(rawScore float64) float64 {
	// LightGBM output is typically probability or log-odds
	// Normalize to 0-100 scale
	normalized := 1.0 / (1.0 + math.Exp(-rawScore)) // Sigmoid
	return normalized * 100.0
}

func calculatePathEntropy(path string) float64 {
	if len(path) == 0 {
		return 0.0
	}

	// Calculate Shannon entropy
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

	// Normalize to 0-1 range (typical path entropy is 2-5)
	return math.Min(entropy/5.0, 1.0)
}

func normalizePayloadSize(size int64) float64 {
	if size <= 0 {
		return 0.0
	}
	// Normalize: 0 = 0, 1MB = 1.0
	normalized := float64(size) / (1024.0 * 1024.0)
	return math.Min(normalized, 1.0)
}

func normalizeTimeOfDay(t time.Time) float64 {
	// Normalize hour to 0-1
	return float64(t.Hour()) / 24.0
}

func boolToFloat(b bool) float64 {
	if b {
		return 1.0
	}
	return 0.0
}

func isSuspiciousUserAgent(ua string) bool {
	ua = strings.ToLower(ua)
	suspicious := []string{
		"bot", "crawler", "spider", "scan", "curl", "wget",
		"python", "java", "perl", "ruby", "go-http",
		"masscan", "nmap", "nikto", "sqlmap", "metasploit",
		"zgrab", "scrapy", "httpx",
	}

	for _, pattern := range suspicious {
		if strings.Contains(ua, pattern) {
			return true
		}
	}
	return false
}

func estimateUserAgentAge(ua string) float64 {
	// Simple heuristic: check for modern browser versions
	// Modern = 0.0, Old = 1.0
	ua = strings.ToLower(ua)

	// Very old browsers
	if strings.Contains(ua, "msie") || strings.Contains(ua, "trident") {
		return 1.0 // IE is ancient
	}

	// Check for recent versions
	modern := []string{
		"chrome/12", "firefox/12", "safari/17", "edge/12",
	}

	for _, pattern := range modern {
		if strings.Contains(ua, pattern) {
			return 0.0 // Modern
		}
	}

	// Default: somewhat old
	return 0.5
}

// Simple logger interface - compatible with zerolog
type Logger interface {
	Info(msg string, keysAndValues ...interface{})
	Warn(msg string, keysAndValues ...interface{})
	Error(msg string, keysAndValues ...interface{})
}
