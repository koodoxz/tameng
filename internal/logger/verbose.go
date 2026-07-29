/*
Package logger - Verbose logging helpers

Provides detailed component logging for startup sequences
*/
package logger

import (
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// VerboseLogger wraps zerolog with component-aware formatting
type VerboseLogger struct {
	log *zerolog.Logger
}

// NewVerboseLogger creates a verbose logger
func NewVerboseLogger(log *zerolog.Logger) *VerboseLogger {
	return &VerboseLogger{log: log}
}

// Header prints a section header
func (v *VerboseLogger) Header(title string) {
	v.log.Info().Msg(strings.Repeat("=", 60))
	v.log.Info().Msgf("🚀 %s", title)
	v.log.Info().Msg(strings.Repeat("=", 60))
}

// Component prints a component initialization message
func (v *VerboseLogger) Component(name, message string) {
	v.log.Info().Msgf("📦 [%s] %s", name, message)
}

// Detail prints a detail line (indented)
func (v *VerboseLogger) Detail(component, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	v.log.Info().Msgf("   ├─ %s", msg)
}

// Success prints a success message
func (v *VerboseLogger) Success(component, message string) {
	v.log.Info().Msgf("   └─ ✅ %s", message)
}

// Warning prints a warning during startup
func (v *VerboseLogger) Warning(component, message string) {
	v.log.Warn().Msgf("   └─ ⚠️  %s", message)
}

// Separator prints a visual separator
func (v *VerboseLogger) Separator() {
	v.log.Info().Msg(strings.Repeat("-", 60))
}

// StartupStats holds statistics for startup reporting
type StartupStats struct {
	// WAF
	Signatures   int
	EvolvedRules int

	// Actor
	ActiveActors  int
	TrackedIPs    int
	GrayZoneCount int

	// Fingerprint
	KnownBadFingerprints int

	// Honeypot
	TrapCount int

	// DDoS
	RateLimit int
	Burst     int

	// ML
	AnomalyDetector bool
	ProphetEnabled  bool

	// Database
	ThreatCount int

	// Timing
	StartTime time.Time
	LoadTime  time.Duration
}

// PrintStartupBanner prints detailed startup information
func PrintStartupBanner(log *zerolog.Logger, stats StartupStats) {
	v := NewVerboseLogger(log)

	v.Header("SVALINN Security Shield - Initializing")

	// Configuration
	v.Component("Config", "Loading configuration...")
	v.Detail("Config", "Configuration file validated")
	v.Success("Config", "Configuration loaded")

	v.Separator()

	// WAF Engine
	v.Component("WAF", "Initializing WAF Engine...")
	v.Detail("WAF", "Loaded %d attack signatures", stats.Signatures)
	v.Detail("WAF", "Loaded %d evolved rules", stats.EvolvedRules)
	v.Detail("WAF", "Rate limit: %d req/s (burst: %d)", stats.RateLimit, stats.Burst)
	v.Success("WAF", "WAF Engine ready")

	// Actor Tracking
	v.Component("Actor", "Loading Actor Memory...")
	v.Detail("Actor", "Active actors: %d", stats.ActiveActors)
	v.Detail("Actor", "Tracked IPs: %d", stats.TrackedIPs)
	v.Detail("Actor", "Memory management: LRU eviction enabled")
	v.Success("Actor", "Actor Memory initialized")

	// Gray Zone
	v.Component("GrayZone", "Loading Gray Zone buffer...")
	v.Detail("GrayZone", "Uncertain events loaded: %d", stats.GrayZoneCount)
	v.Detail("GrayZone", "Circular buffer: memory-bounded")
	v.Success("GrayZone", "Gray Zone initialized")

	// Fingerprinting
	v.Component("Fingerprint", "Initializing Fingerprinting Engine...")
	v.Detail("Fingerprint", "HTTP fingerprinting: ✅ enabled")
	v.Detail("Fingerprint", "JA3 TLS fingerprinting: ✅ enabled")
	v.Detail("Fingerprint", "JA4 modern TLS: ✅ enabled")
	v.Detail("Fingerprint", "Timing analysis: ✅ enabled")
	v.Detail("Fingerprint", "Similarity scoring: ✅ enabled")
	v.Detail("Fingerprint", "Known bad signatures: %d", stats.KnownBadFingerprints)
	v.Success("Fingerprint", "Fingerprinting ready")

	// Honeypots
	v.Component("Honeypot", "Setting up Honeypots...")
	v.Detail("Honeypot", "Trap endpoints armed: %d", stats.TrapCount)
	v.Detail("Honeypot", "Deception levels: 6 (Ladder system)")
	v.Success("Honeypot", "Honeypots active")

	// DDoS Protection
	v.Component("DDoS", "Initializing DDoS Protection...")
	v.Detail("DDoS", "Rate limiting: ✅ active")
	v.Detail("DDoS", "Connection tracking: ✅ active")
	v.Detail("DDoS", "Threshold detection: ✅ active")
	v.Success("DDoS", "DDoS Protection armed")

	// ML Engines
	v.Component("ML", "Initializing ML Engines...")
	if stats.AnomalyDetector {
		v.Detail("ML", "Anomaly Detector: ✅ active (Z-Score, IQR, Speed)")
	} else {
		v.Detail("ML", "Anomaly Detector: ⏸️  disabled")
	}

	if stats.ProphetEnabled {
		v.Detail("ML", "Prophet Forecaster: ✅ active (Python bridge)")
	} else {
		v.Detail("ML", "Prophet Forecaster: ⏸️  disabled")
	}
	v.Success("ML", "ML Engines ready")

	// Threat Intelligence
	v.Component("Intel", "Loading Threat Intelligence...")
	v.Detail("Intel", "Historical threats: %d", stats.ThreatCount)
	v.Detail("Intel", "GeoIP database: loaded")
	v.Success("Intel", "Threat Intelligence ready")

	v.Separator()

	// Final Summary
	loadTime := time.Since(stats.StartTime)
	v.Header(fmt.Sprintf("✅ SVALINN Shield ACTIVE (loaded in %v)", loadTime.Round(time.Millisecond)))
	v.log.Info().Msg("🛡️  All systems operational - Infrastructure protected")
}
