/*
Package session implements session security and hijacking detection

Migrated from Node.js session-guard.js
*/
package session

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sync"
	"time"

	"github.com/aegis/svalinn/internal/netutil"
)

// Guard performs session security checks
type Guard struct {
	sessions sync.Map // sessionID -> *SessionInfo
	config   Config
}

// Config holds session guard configuration
type Config struct {
	Enabled          bool
	DeviceBinding    bool
	MaxDeviceChanges int
	SessionTimeout   time.Duration
}

// SessionInfo holds session metadata
type SessionInfo struct {
	ID            string
	UserID        string
	DeviceHash    string
	IP            string
	UserAgent     string
	FirstSeen     time.Time
	LastSeen      time.Time
	RequestCount  int
	DeviceChanges int
	Suspicious    bool
	Violations    []string
}

// DeviceFingerprint represents a device fingerprint
type DeviceFingerprint struct {
	IP        string
	UserAgent string
	Headers   map[string]string
}

// NewGuard creates a new session guard
func NewGuard(cfg Config) *Guard {
	if cfg.SessionTimeout == 0 {
		cfg.SessionTimeout = 24 * time.Hour
	}
	if cfg.MaxDeviceChanges == 0 {
		cfg.MaxDeviceChanges = 2
	}

	return &Guard{
		config: cfg,
	}
}

// CheckSession validates session security
func (g *Guard) CheckSession(r *http.Request, sessionID string, userID string) *SessionResult {
	result := &SessionResult{
		Valid:      true,
		Violations: []string{},
	}

	if !g.config.Enabled || sessionID == "" {
		return result
	}

	// Get or create session info
	sessionVal, exists := g.sessions.Load(sessionID)
	var session *SessionInfo

	deviceHash := g.computeDeviceHash(r)

	if !exists {
		// New session
		session = &SessionInfo{
			ID:           sessionID,
			UserID:       userID,
			DeviceHash:   deviceHash,
			IP:           g.getClientIP(r),
			UserAgent:    r.UserAgent(),
			FirstSeen:    time.Now(),
			LastSeen:     time.Now(),
			RequestCount: 1,
			Violations:   []string{},
		}
		g.sessions.Store(sessionID, session)
		return result
	}

	session = sessionVal.(*SessionInfo)

	// Check for violations
	now := time.Now()

	// 1. Session timeout check
	if now.Sub(session.LastSeen) > g.config.SessionTimeout {
		result.Valid = false
		result.Violations = append(result.Violations, "session_timeout")
		result.Action = "require_reauth"
		return result
	}

	// 2. Device binding check
	if g.config.DeviceBinding && deviceHash != session.DeviceHash {
		session.DeviceChanges++
		session.Violations = append(session.Violations, "device_change")
		result.Violations = append(result.Violations, "device_mismatch")

		if session.DeviceChanges > g.config.MaxDeviceChanges {
			result.Valid = false
			result.Action = "require_reauth"
			session.Suspicious = true
		} else {
			result.Warning = "Device change detected"
			// Update device hash for legitimate device changes
			session.DeviceHash = deviceHash
		}
	}

	// 3. IP change detection (warn only)
	currentIP := g.getClientIP(r)
	if currentIP != session.IP {
		result.Violations = append(result.Violations, "ip_change")
		result.Warning = "IP address changed"
		session.IP = currentIP
	}

	// 4. User-Agent change detection
	if r.UserAgent() != session.UserAgent {
		result.Violations = append(result.Violations, "user_agent_change")
		result.Warning = "User agent changed"
		session.Suspicious = true
	}

	// 5. Continuous authentication - check request velocity
	if session.RequestCount > 1000 && now.Sub(session.FirstSeen) < 1*time.Minute {
		result.Violations = append(result.Violations, "high_velocity")
		result.Valid = false
		result.Action = "rate_limit"
		session.Suspicious = true
	}

	// Update session
	session.LastSeen = now
	session.RequestCount++
	g.sessions.Store(sessionID, session)

	return result
}

// SessionResult contains session validation results
type SessionResult struct {
	Valid      bool
	Violations []string
	Action     string // require_reauth, rate_limit, block
	Warning    string
}

// computeDeviceHash creates a device fingerprint hash
func (g *Guard) computeDeviceHash(r *http.Request) string {
	components := []string{
		r.UserAgent(),
		r.Header.Get("Accept-Language"),
		r.Header.Get("Accept-Encoding"),
		r.Header.Get("Accept"),
	}

	hash := sha256.New()
	for _, comp := range components {
		hash.Write([]byte(comp))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

// getClientIP extracts the client IP bound to a session and compared on every
// request for hijack detection. Trust decisions live in netutil
// (REQ SVALINN-CLIENTIP-SPOOF-002): only the local nginx peer may speak for
// another address, so a forged header can neither bind a session to a victim
// nor manufacture an ip_change violation.
func (g *Guard) getClientIP(r *http.Request) string {
	return netutil.TrustedClientIP(r)
}

// GetStats returns session statistics
func (g *Guard) GetStats() map[string]interface{} {
	activeSessions := 0
	suspiciousSessions := 0

	g.sessions.Range(func(_, val interface{}) bool {
		activeSessions++
		session := val.(*SessionInfo)
		if session.Suspicious {
			suspiciousSessions++
		}
		return true
	})

	return map[string]interface{}{
		"active_sessions":     activeSessions,
		"suspicious_sessions": suspiciousSessions,
		"enabled":             g.config.Enabled,
	}
}

// CleanupExpired removes expired sessions
func (g *Guard) CleanupExpired() int {
	now := time.Now()
	removed := 0

	g.sessions.Range(func(key, val interface{}) bool {
		session := val.(*SessionInfo)
		if now.Sub(session.LastSeen) > g.config.SessionTimeout*2 {
			g.sessions.Delete(key)
			removed++
		}
		return true
	})

	return removed
}
