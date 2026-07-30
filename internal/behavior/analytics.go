/*
Package behavior implements user behavior analytics

Migrated from Node.js user-behavior.js
*/
package behavior

import (
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/koodoxz/tameng/internal/netutil"
)

// Analytics performs user behavior analysis
type Analytics struct {
	userProfiles sync.Map // userID -> *UserProfile
	config       Config
}

// Config holds behavior analytics configuration
type Config struct {
	Enabled               bool
	DeviationThreshold    float64
	MinSamplesForBaseline int
}

// UserProfile holds behavioral baseline for a user
type UserProfile struct {
	UserID string

	// Temporal patterns
	TypicalHours    map[int]int    // Hour of day -> access count
	TypicalWeekdays map[string]int // Day name -> count

	// Activity patterns
	AvgSessionDuration time.Duration
	AvgRequestsPerHour float64
	CommonPaths        map[string]int

	// Device patterns
	KnownDevices map[string]bool // device hashes
	KnownIPs     map[string]bool

	// Statistics
	TotalRequests int
	FirstSeen     time.Time
	LastSeen      time.Time
	LastUpdate    time.Time
}

// Result contains behavior analysis results
type Result struct {
	IsAnomaly           bool
	DeviationScore      float64
	Violations          []string
	UnusualHour         bool
	UnusualDay          bool
	UnknownDevice       bool
	UnknownIP           bool
	AbnormalRequestRate bool
}

// NewAnalytics creates a new behavior analytics engine
func NewAnalytics(cfg Config) *Analytics {
	if cfg.DeviationThreshold == 0 {
		cfg.DeviationThreshold = 0.7
	}
	if cfg.MinSamplesForBaseline == 0 {
		cfg.MinSamplesForBaseline = 50
	}

	return &Analytics{
		config: cfg,
	}
}

// AnalyzeUser performs behavior analysis for a user
func (a *Analytics) AnalyzeUser(r *http.Request, userID string, deviceHash string) *Result {
	result := &Result{
		Violations: []string{},
	}

	if !a.config.Enabled || userID == "" {
		return result
	}

	// Get or create user profile
	profileVal, exists := a.userProfiles.Load(userID)
	var profile *UserProfile

	if !exists {
		profile = &UserProfile{
			UserID:          userID,
			TypicalHours:    make(map[int]int),
			TypicalWeekdays: make(map[string]int),
			CommonPaths:     make(map[string]int),
			KnownDevices:    make(map[string]bool),
			KnownIPs:        make(map[string]bool),
			FirstSeen:       time.Now(),
		}
		a.userProfiles.Store(userID, profile)
	} else {
		profile = profileVal.(*UserProfile)
	}

	// Skip analysis if not enough samples
	if profile.TotalRequests < a.config.MinSamplesForBaseline {
		a.updateProfile(profile, r, deviceHash)
		return result
	}

	// Perform behavior analysis
	now := time.Now()
	hour := now.Hour()
	weekday := now.Weekday().String()
	ip := getClientIP(r)

	// 1. Temporal anomalies
	avgAccessesThisHour := float64(profile.TypicalHours[hour])
	if avgAccessesThisHour < 1 && profile.TotalRequests > 100 {
		result.UnusualHour = true
		result.Violations = append(result.Violations, "unusual_hour")
	}

	avgAccessesThisDay := float64(profile.TypicalWeekdays[weekday])
	if avgAccessesThisDay < 2 && profile.TotalRequests > 200 {
		result.UnusualDay = true
		result.Violations = append(result.Violations, "unusual_day")
	}

	// 2. Device anomalies
	if !profile.KnownDevices[deviceHash] && len(profile.KnownDevices) > 0 {
		result.UnknownDevice = true
		result.Violations = append(result.Violations, "unknown_device")
		// Add to known devices after alert
		profile.KnownDevices[deviceHash] = true
	}

	// 3. IP anomalies
	if !profile.KnownIPs[ip] && len(profile.KnownIPs) >= 3 {
		result.UnknownIP = true
		result.Violations = append(result.Violations, "unknown_ip")
		// Add to known IPs (up to 10)
		if len(profile.KnownIPs) < 10 {
			profile.KnownIPs[ip] = true
		}
	}

	// 4. Request rate anomaly
	if profile.TotalRequests > 50 {
		timeSinceFirst := now.Sub(profile.FirstSeen)
		currentRate := float64(profile.TotalRequests) / timeSinceFirst.Hours()

		if profile.AvgRequestsPerHour > 0 {
			deviation := math.Abs(currentRate-profile.AvgRequestsPerHour) / profile.AvgRequestsPerHour
			if deviation > 5.0 { // 500% deviation
				result.AbnormalRequestRate = true
				result.Violations = append(result.Violations, "abnormal_request_rate")
			}
		}
	}

	// Calculate deviation score
	score := 0.0
	if result.UnusualHour {
		score += 0.15
	}
	if result.UnusualDay {
		score += 0.15
	}
	if result.UnknownDevice {
		score += 0.3
	}
	if result.UnknownIP {
		score += 0.2
	}
	if result.AbnormalRequestRate {
		score += 0.2
	}

	result.DeviationScore = score
	result.IsAnomaly = score >= a.config.DeviationThreshold

	// Update profile
	a.updateProfile(profile, r, deviceHash)

	return result
}

// updateProfile updates user behavioral baseline
func (a *Analytics) updateProfile(profile *UserProfile, r *http.Request, deviceHash string) {
	now := time.Now()
	hour := now.Hour()
	weekday := now.Weekday().String()
	path := r.URL.Path
	ip := getClientIP(r)

	// Update temporal patterns
	profile.TypicalHours[hour]++
	profile.TypicalWeekdays[weekday]++

	// Update path frequencies
	profile.CommonPaths[path]++

	// Track devices and IPs
	profile.KnownDevices[deviceHash] = true
	if len(profile.KnownIPs) < 10 {
		profile.KnownIPs[ip] = true
	}

	// Update statistics
	profile.TotalRequests++
	profile.LastSeen = now
	profile.LastUpdate = now

	// Recalculate average request rate
	if profile.TotalRequests > 10 {
		timeSinceFirst := now.Sub(profile.FirstSeen)
		profile.AvgRequestsPerHour = float64(profile.TotalRequests) / timeSinceFirst.Hours()
	}
}

// Stats returns basic analytics statistics
func (a *Analytics) Stats() map[string]interface{} {
	profiles := 0
	a.userProfiles.Range(func(_, _ interface{}) bool {
		profiles++
		return true
	})

	return map[string]interface{}{
		"profiles":                 profiles,
		"deviation_threshold":      a.config.DeviationThreshold,
		"min_samples_for_baseline": a.config.MinSamplesForBaseline,
		"enabled":                  a.config.Enabled,
	}
}

// GetStats returns analytics statistics
func (a *Analytics) GetStats() map[string]interface{} {
	trackedUsers := 0
	anomalousUsers := 0

	a.userProfiles.Range(func(_, val interface{}) bool {
		trackedUsers++
		// Could track anomalous users if we persist them
		return true
	})

	return map[string]interface{}{
		"tracked_users":   trackedUsers,
		"anomalous_users": anomalousUsers,
		"enabled":         a.config.Enabled,
	}
}

// Helper
// getClientIP resolves the request's client address, which keys every per-IP
// behavioural profile in this package. Trust decisions live in netutil
// (REQ SVALINN-CLIENTIP-SPOOF-002): only the local nginx peer may speak for
// another address.
func getClientIP(r *http.Request) string {
	return netutil.TrustedClientIP(r)
}
