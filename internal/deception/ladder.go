/*
Package deception implements the Deception Ladder

6-level escalation system that progressively wastes attacker resources
*/
package deception

import (
	"net/http"
	"sync"
	"time"
)

// Level represents the current deception level for an IP
type Level int

const (
	LevelNone      Level = iota // 0: No deception
	LevelMonitor                // 1: Silent monitoring only
	LevelDelay                  // 2: Subtle delays (50-200ms)
	LevelChallenge              // 3: CAPTCHAs, proof-of-work
	LevelMisdirect              // 4: Fake data, wrong redirects
	LevelTarpit                 // 5: Extreme delays (5-30s)
	LevelBlock                  // 6: Full block
)

// Ladder manages deception levels per IP
type Ladder struct {
	levels    map[string]*LevelInfo // IP -> level info
	mu        sync.RWMutex
	maxLevel  Level
	decayTime time.Duration // Time to decay one level
}

// LevelInfo holds level information for an IP
type LevelInfo struct {
	Current        Level
	EscalateAt     time.Time
	ViolationCount int
	LastUpdate     time.Time
}

// NewLadder creates a new deception ladder
func NewLadder() *Ladder {
	return &Ladder{
		levels:    make(map[string]*LevelInfo),
		maxLevel:  LevelBlock,
		decayTime: 1 * time.Hour, // Decay one level per hour of good behavior
	}
}

// GetLevel returns current level for an IP
func (l *Ladder) GetLevel(ip string) Level {
	l.mu.RLock()
	defer l.mu.RUnlock()

	info, exists := l.levels[ip]
	if !exists {
		return LevelNone
	}

	// Check if level should decay
	if time.Since(info.LastUpdate) > l.decayTime && info.Current > LevelNone {
		info.Current--
		info.LastUpdate = time.Now()
	}

	return info.Current
}

// Escalate increases the deception level for an IP
func (l *Ladder) Escalate(ip string, reason string) Level {
	l.mu.Lock()
	defer l.mu.Unlock()

	info, exists := l.levels[ip]
	if !exists {
		info = &LevelInfo{
			Current:        LevelMonitor,
			ViolationCount: 1,
			LastUpdate:     time.Now(),
		}
		l.levels[ip] = info
		return info.Current
	}

	// Escalate
	if info.Current < l.maxLevel {
		info.Current++
	}
	info.ViolationCount++
	info.LastUpdate = time.Now()

	return info.Current
}

// Apply applies deception based on level
func (l *Ladder) Apply(w http.ResponseWriter, r *http.Request, level Level) bool {
	switch level {
	case LevelNone:
		return false // No deception

	case LevelMonitor:
		// Silent monitoring - no action
		return false

	case LevelDelay:
		// Subtle delays
		time.Sleep(time.Millisecond * 100)
		return false

	case LevelChallenge:
		// Send proof-of-work challenge
		w.Header().Set("X-Challenge", "proof-of-work-required")
		w.Header().Set("X-Difficulty", "moderate")
		// For now, just delay - full PoW implementation would be more complex
		time.Sleep(time.Millisecond * 500)
		return false

	case LevelMisdirect:
		// Redirect to honeypot or fake page
		http.Redirect(w, r, "/honeypot", http.StatusFound)
		return true // Stop processing

	case LevelTarpit:
		// Extreme delays to waste attacker time
		time.Sleep(time.Second * 10)
		return false

	case LevelBlock:
		// Full block
		http.Error(w, "Forbidden", http.StatusForbidden)
		return true // Stop processing
	}

	return false
}

// GetLevelName returns human-readable level name
func (l *Ladder) GetLevelName(level Level) string {
	names := map[Level]string{
		LevelNone:      "None",
		LevelMonitor:   "Monitor",
		LevelDelay:     "Delay",
		LevelChallenge: "Challenge",
		LevelMisdirect: "Misdirect",
		LevelTarpit:    "Tarpit",
		LevelBlock:     "Block",
	}
	return names[level]
}

// GetStats returns ladder statistics
func (l *Ladder) GetStats() map[string]interface{} {
	l.mu.RLock()
	defer l.mu.RUnlock()

	levelCounts := make(map[Level]int)
	totalViolations := 0

	for _, info := range l.levels {
		levelCounts[info.Current]++
		totalViolations += info.ViolationCount
	}

	return map[string]interface{}{
		"tracked_ips":      len(l.levels),
		"total_violations": totalViolations,
		"level_counts": map[string]int{
			"monitor":   levelCounts[LevelMonitor],
			"delay":     levelCounts[LevelDelay],
			"challenge": levelCounts[LevelChallenge],
			"misdirect": levelCounts[LevelMisdirect],
			"tarpit":    levelCounts[LevelTarpit],
			"block":     levelCounts[LevelBlock],
		},
	}
}

// Reset resets an IP to no deception level
func (l *Ladder) Reset(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.levels, ip)
}
