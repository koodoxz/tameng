/*
Package ml - Prophet Forecaster (Python Bridge)

Integrates Python Prophet for threat forecasting
Based on Node.js SVALINN threat-forecast.js
*/
package ml

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// ProphetForecaster provides threat forecasting via Python Prophet
type ProphetForecaster struct {
	pythonPath   string
	scriptsDir   string
	forecastsDir string
	modelsDir    string
	enabled      bool

	cachedForecasts []Forecast
	lastLoad        time.Time
	cacheTTL        time.Duration
}

// Forecast represents a single forecast data point
type Forecast struct {
	Date       time.Time `json:"ds"`
	ThreatType string    `json:"threat_type"`
	Predicted  float64   `json:"yhat"`
	LowerBound float64   `json:"yhat_lower"`
	UpperBound float64   `json:"yhat_upper"`
	Trend      string    `json:"trend"`
}

// HighRiskDay represents a day with elevated threat predictions
type HighRiskDay struct {
	Date           time.Time
	AvgThreatLevel float64
	Threats        []ThreatPrediction
}

// ThreatPrediction contains threat-specific predictions
type ThreatPrediction struct {
	Type      string
	Predicted float64
	Lower     float64
	Upper     float64
}

// NewProphetForecaster creates a new prophet forecaster
func NewProphetForecaster(pythonPath, dataDir string) *ProphetForecaster {
	// Check if Python is available
	if pythonPath == "" {
		pythonPath = "/usr/bin/python3"
	}

	_, err := os.Stat(pythonPath)
	enabled := err == nil

	return &ProphetForecaster{
		pythonPath:   pythonPath,
		scriptsDir:   "", // Will be set based on svalinn location
		forecastsDir: filepath.Join(dataDir, "forecasts"),
		modelsDir:    filepath.Join(dataDir, "models"),
		enabled:      enabled,
		cacheTTL:     1 * time.Hour,
	}
}

// SetScriptsDir sets the directory containing Python scripts
func (p *ProphetForecaster) SetScriptsDir(dir string) {
	p.scriptsDir = dir
}

// GenerateForecasts calls Python to generate forecasts
func (p *ProphetForecaster) GenerateForecasts(days int) error {
	if !p.enabled {
		return fmt.Errorf("prophet not available: python not found")
	}

	scriptPath := filepath.Join(p.scriptsDir, "prophet_predictor.py")
	if _, err := os.Stat(scriptPath); err != nil {
		return fmt.Errorf("prophet script not found: %s", scriptPath)
	}

	// Run Python script
	cmd := exec.Command(p.pythonPath, scriptPath, "ALL", fmt.Sprintf("%d", days))
	cmd.Dir = p.scriptsDir

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("prophet execution failed: %v, output: %s", err, string(output))
	}

	// Invalidate cache
	p.lastLoad = time.Time{}

	return nil
}

// LoadForecasts loads forecasts from JSON file
func (p *ProphetForecaster) LoadForecasts() ([]Forecast, error) {
	// Check cache
	if time.Since(p.lastLoad) < p.cacheTTL && p.cachedForecasts != nil {
		return p.cachedForecasts, nil
	}

	forecastPath := filepath.Join(p.forecastsDir, "all_forecasts.json")

	data, err := os.ReadFile(forecastPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read forecasts: %v", err)
	}

	var forecasts []Forecast
	if err := json.Unmarshal(data, &forecasts); err != nil {
		return nil, fmt.Errorf("failed to parse forecasts: %v", err)
	}

	// Cache results
	p.cachedForecasts = forecasts
	p.lastLoad = time.Now()

	return forecasts, nil
}

// GetForecastByType returns forecasts for a specific threat type
func (p *ProphetForecaster) GetForecastByType(threatType string) ([]Forecast, error) {
	all, err := p.LoadForecasts()
	if err != nil {
		return nil, err
	}

	var filtered []Forecast
	for _, f := range all {
		if f.ThreatType == threatType {
			filtered = append(filtered, f)
		}
	}

	return filtered, nil
}

// GetHighRiskDays identifies days with elevated threat levels
func (p *ProphetForecaster) GetHighRiskDays(threshold float64) ([]HighRiskDay, error) {
	forecasts, err := p.LoadForecasts()
	if err != nil {
		return nil, err
	}

	// Group by date
	byDate := make(map[string][]Forecast)
	for _, f := range forecasts {
		dateStr := f.Date.Format("2006-01-02")
		byDate[dateStr] = append(byDate[dateStr], f)
	}

	// Find high-risk days
	var highRisk []HighRiskDay
	for dateStr, dayForecasts := range byDate {
		if len(dayForecasts) == 0 {
			continue
		}

		// Calculate average threat level
		total := 0.0
		for _, f := range dayForecasts {
			total += f.Predicted
		}
		avgLevel := total / float64(len(dayForecasts))

		if avgLevel > threshold {
			date, _ := time.Parse("2006-01-02", dateStr)

			threats := make([]ThreatPrediction, len(dayForecasts))
			for i, f := range dayForecasts {
				threats[i] = ThreatPrediction{
					Type:      f.ThreatType,
					Predicted: f.Predicted,
					Lower:     f.LowerBound,
					Upper:     f.UpperBound,
				}
			}

			highRisk = append(highRisk, HighRiskDay{
				Date:           date,
				AvgThreatLevel: avgLevel,
				Threats:        threats,
			})
		}
	}

	return highRisk, nil
}

// GetTrend analyzes overall threat trend
func (p *ProphetForecaster) GetTrend() (string, error) {
	forecasts, err := p.LoadForecasts()
	if err != nil {
		return "unknown", err
	}

	if len(forecasts) < 7 {
		return "insufficient_data", nil
	}

	// Compare first week vs last week
	firstWeek := forecasts[:7]
	lastWeek := forecasts[len(forecasts)-7:]

	firstAvg := 0.0
	for _, f := range firstWeek {
		firstAvg += f.Predicted
	}
	firstAvg /= 7.0

	lastAvg := 0.0
	for _, f := range lastWeek {
		lastAvg += f.Predicted
	}
	lastAvg /= 7.0

	change := (lastAvg - firstAvg) / firstAvg

	if change > 0.1 {
		return "increasing", nil
	} else if change < -0.1 {
		return "decreasing", nil
	}
	return "stable", nil
}

// IsEnabled returns whether prophet is available
func (p *ProphetForecaster) IsEnabled() bool {
	return p.enabled
}

// GetStats returns forecaster statistics
func (p *ProphetForecaster) GetStats() map[string]interface{} {
	stats := map[string]interface{}{
		"enabled":     p.enabled,
		"python_path": p.pythonPath,
		"cache_age":   time.Since(p.lastLoad).String(),
	}

	if p.cachedForecasts != nil {
		stats["cached_forecasts"] = len(p.cachedForecasts)
	}

	trend, err := p.GetTrend()
	if err == nil {
		stats["trend"] = trend
	}

	return stats
}
