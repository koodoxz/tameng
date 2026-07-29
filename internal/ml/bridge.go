/*
Package ml implements the ML Engine bridge for SVALINN.

This package communicates with the Python ML engine via HTTP/gRPC
for threat classification, anomaly detection, and behavioral analysis.
*/
package ml

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// Prediction represents an ML model prediction
type Prediction struct {
	Label      string  `json:"label"`
	Confidence float64 `json:"confidence"`
	Score      float64 `json:"score"`
	IsAttack   bool    `json:"is_attack"`
	Category   string  `json:"category,omitempty"`
}

// Request represents a request to analyze
type Request struct {
	Method    string            `json:"method"`
	Path      string            `json:"path"`
	Query     string            `json:"query"`
	Body      string            `json:"body"`
	Headers   map[string]string `json:"headers"`
	UserAgent string            `json:"user_agent"`
	IP        string            `json:"ip"`
	Country   string            `json:"country,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
}

// FeedbackEntry represents feedback for model training
type FeedbackEntry struct {
	RequestID  string    `json:"request_id"`
	IsAttack   bool      `json:"is_attack"`
	AttackType string    `json:"attack_type,omitempty"`
	Feedback   string    `json:"feedback"` // "fp" (false positive), "fn" (false negative), "tp", "tn"
	Timestamp  time.Time `json:"timestamp"`
}

// Engine is the ML bridge between SVALINN and Python ML models
type Engine struct {
	client  *http.Client
	baseURL string

	// Go-based ML components
	AnomalyDetector *AnomalyDetector
	Prophet         *ProphetForecaster

	fallbackToRules bool
	enabled         bool
	mu              sync.RWMutex
}

// Config holds ML bridge configuration
type Config struct {
	EngineURL       string
	Timeout         time.Duration
	FallbackToRules bool
	Enabled         bool
}

// NewEngine creates a new ML engine
func NewEngine(modelsPath, dataPath string, enabled bool) *Engine {
	e := &Engine{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		enabled:         enabled,
		fallbackToRules: true,
	}

	if !enabled {
		return e
	}

	// Initialize Go-based ML components
	e.AnomalyDetector = NewAnomalyDetector()
	e.Prophet = NewProphetForecaster("/usr/bin/python3", dataPath)

	// Set scripts directory for Prophet
	if e.Prophet != nil {
		e.Prophet.SetScriptsDir(modelsPath)
	}

	return e
}

// Predict sends a request to the ML engine for prediction
func (e *Engine) Predict(ctx context.Context, req *Request) (*Prediction, error) {
	if !e.enabled {
		return nil, fmt.Errorf("ML engine disabled")
	}

	// Convert request to JSON
	data, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, "POST", e.baseURL+"/predict", bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	// Send request
	resp, err := e.client.Do(httpReq)
	if err != nil {
		if e.fallbackToRules {
			return &Prediction{Label: "unknown", Confidence: 0, Score: 0.5}, nil
		}
		return nil, fmt.Errorf("ML engine request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ML engine error: %s - %s", resp.Status, string(body))
	}

	// Parse response
	var prediction Prediction
	if err := json.NewDecoder(resp.Body).Decode(&prediction); err != nil {
		return nil, fmt.Errorf("failed to parse prediction: %w", err)
	}

	return &prediction, nil
}

// SendFeedback sends feedback to the ML engine for model improvement
func (e *Engine) SendFeedback(ctx context.Context, feedback *FeedbackEntry) error {
	if !e.enabled {
		return nil
	}

	data, err := json.Marshal(feedback)
	if err != nil {
		return fmt.Errorf("failed to marshal feedback: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", e.baseURL+"/feedback", bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := e.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("feedback request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("feedback error: %s - %s", resp.Status, string(body))
	}

	return nil
}

// Health checks the ML engine health
func (e *Engine) Health(ctx context.Context) (bool, error) {
	if !e.enabled {
		return false, nil
	}

	httpReq, err := http.NewRequestWithContext(ctx, "GET", e.baseURL+"/health", nil)
	if err != nil {
		return false, err
	}

	resp, err := e.client.Do(httpReq)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK, nil
}

// BatchPredict sends multiple requests for batch prediction
func (e *Engine) BatchPredict(ctx context.Context, requests []*Request) ([]*Prediction, error) {
	if !e.enabled {
		return nil, fmt.Errorf("ML engine disabled")
	}

	data, err := json.Marshal(requests)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal requests: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", e.baseURL+"/predict/batch", bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := e.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("batch predict failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("batch predict error: %s - %s", resp.Status, string(body))
	}

	var predictions []*Prediction
	if err := json.NewDecoder(resp.Body).Decode(&predictions); err != nil {
		return nil, fmt.Errorf("failed to parse predictions: %w", err)
	}

	return predictions, nil
}

// IsEnabled returns whether the ML engine is enabled
func (e *Engine) IsEnabled() bool {
	return e.enabled
}

// SetEnabled enables or disables the ML engine
func (e *Engine) SetEnabled(enabled bool) {
	e.enabled = enabled
}
