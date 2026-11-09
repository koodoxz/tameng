package ml

import (
	"testing"
)

type nopLogger struct{}

func (n *nopLogger) Debug(msg string, keysAndValues ...interface{}) {}
func (n *nopLogger) Info(msg string, keysAndValues ...interface{})  {}
func (n *nopLogger) Warn(msg string, keysAndValues ...interface{})  {}
func (n *nopLogger) Error(msg string, keysAndValues ...interface{}) {}

// REQ-SVALINN-ML-MODELVERSION-001: Model must load into a non-nil ensemble
func TestThreatScorer_LoadsModelSuccessfully(t *testing.T) {
	ts, err := NewThreatScorer("../../data/models/threat_scorer.txt", &nopLogger{})
	if err != nil {
		t.Fatalf("NewThreatScorer returned unexpected error: %v", err)
	}
	if ts.model == nil {
		t.Fatalf("NewThreatScorer failed to load model: ts.model is nil (fallback active)")
	}
}
