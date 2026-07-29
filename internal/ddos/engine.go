/*
Package ddos implements DDoS protection for SVALINN.

Features:
- EWMA (Exponentially Weighted Moving Average) rate detection
- Three-phase escalation: Challenge → Throttle → Block
- Proof-of-Work challenges for suspected bots
- ASN-based rate limiting
*/
package ddos

import (
	"sync"
	"sync/atomic"
	"time"
)

// Phase represents the DDoS protection phase
type Phase int

const (
	PhaseNormal Phase = iota
	PhaseChallenge
	PhaseThrottle
	PhaseBlock
)

// String returns the phase name
func (p Phase) String() string {
	switch p {
	case PhaseNormal:
		return "normal"
	case PhaseChallenge:
		return "challenge"
	case PhaseThrottle:
		return "throttle"
	case PhaseBlock:
		return "block"
	default:
		return "unknown"
	}
}

// IPState tracks the DDoS state for an IP
type IPState struct {
	IP            string
	RequestCount  int64
	EWMA          float64
	Phase         Phase
	PhaseUntil    time.Time
	ChallengePass int
	ChallengeFail int
	LastRequest   time.Time
	Blocked       bool

	lock sync.RWMutex
}

// Engine is the DDoS protection engine
type Engine struct {
	states sync.Map // map[string]*IPState

	// Config
	ewmaAlpha          float64 // EWMA smoothing factor (0-1)
	challengeThreshold float64 // RPS threshold for challenge
	throttleThreshold  float64 // RPS threshold for throttle
	blockThreshold     float64 // RPS threshold for block
	challengeDuration  time.Duration
	throttleDuration   time.Duration
	blockDuration      time.Duration

	// Global stats
	totalRequests   int64
	blockedRequests int64
	challengesSent  int64
	currentRPS      float64

	// Feature flags
	phase3Enabled    bool
	challengeEnabled bool
	throttleEnabled  bool
	blockEnabled     bool

	// Cleanup
	shutdown chan struct{}
}

// Config holds DDoS engine configuration
type Config struct {
	EWMAWindow         time.Duration
	ChallengeThreshold float64
	ThrottleThreshold  float64
	BlockThreshold     float64
	ChallengeDuration  time.Duration
	ThrottleDuration   time.Duration
	BlockDuration      time.Duration
	Phase3Enabled      bool
	ChallengeEnabled   bool
	ThrottleEnabled    bool
	BlockEnabled       bool
}

// NewEngine creates a new DDoS protection engine
func NewEngine(cfg *Config) *Engine {
	e := &Engine{
		ewmaAlpha:          2.0 / (float64(cfg.EWMAWindow.Seconds()) + 1),
		challengeThreshold: cfg.ChallengeThreshold,
		throttleThreshold:  cfg.ThrottleThreshold,
		blockThreshold:     cfg.BlockThreshold,
		challengeDuration:  cfg.ChallengeDuration,
		throttleDuration:   cfg.ThrottleDuration,
		blockDuration:      cfg.BlockDuration,
		phase3Enabled:      cfg.Phase3Enabled,
		challengeEnabled:   cfg.ChallengeEnabled,
		throttleEnabled:    cfg.ThrottleEnabled,
		blockEnabled:       cfg.BlockEnabled,
		shutdown:           make(chan struct{}),
	}

	// Start cleanup goroutine
	go e.cleanupLoop()

	return e
}

// Check checks an IP and returns the action to take
func (e *Engine) Check(ip string) (Phase, *IPState) {
	state := e.getOrCreateState(ip)

	state.lock.Lock()
	defer state.lock.Unlock()

	now := time.Now()

	// Update request count and EWMA
	atomic.AddInt64(&state.RequestCount, 1)
	atomic.AddInt64(&e.totalRequests, 1)

	// Calculate time delta
	delta := now.Sub(state.LastRequest).Seconds()
	if delta < 0.001 {
		delta = 0.001 // Minimum 1ms
	}

	// Calculate instant RPS for this request
	instantRPS := 1.0 / delta

	// Update EWMA
	if state.LastRequest.IsZero() {
		state.EWMA = instantRPS
	} else {
		state.EWMA = e.ewmaAlpha*instantRPS + (1-e.ewmaAlpha)*state.EWMA
	}

	state.LastRequest = now

	// Check if still in a phase timeout
	if now.Before(state.PhaseUntil) {
		return state.Phase, state
	}

	// Determine new phase based on EWMA
	newPhase := e.determinePhase(state.EWMA)

	if newPhase != PhaseNormal {
		state.Phase = newPhase
		switch newPhase {
		case PhaseChallenge:
			state.PhaseUntil = now.Add(e.challengeDuration)
			atomic.AddInt64(&e.challengesSent, 1)
		case PhaseThrottle:
			state.PhaseUntil = now.Add(e.throttleDuration)
		case PhaseBlock:
			state.PhaseUntil = now.Add(e.blockDuration)
			state.Blocked = true
			atomic.AddInt64(&e.blockedRequests, 1)
		}
	} else {
		state.Phase = PhaseNormal
		state.Blocked = false
	}

	return state.Phase, state
}

// determinePhase determines the appropriate phase based on RPS
func (e *Engine) determinePhase(rps float64) Phase {
	if !e.phase3Enabled {
		return PhaseNormal
	}

	if e.blockEnabled && rps >= e.blockThreshold {
		return PhaseBlock
	}
	if e.throttleEnabled && rps >= e.throttleThreshold {
		return PhaseThrottle
	}
	if e.challengeEnabled && rps >= e.challengeThreshold {
		return PhaseChallenge
	}

	return PhaseNormal
}

// RecordChallengeResult records challenge pass/fail
func (e *Engine) RecordChallengeResult(ip string, passed bool) {
	state := e.getOrCreateState(ip)

	state.lock.Lock()
	defer state.lock.Unlock()

	if passed {
		state.ChallengePass++
		// Successful challenge reduces phase
		if state.Phase == PhaseChallenge {
			state.Phase = PhaseNormal
			state.PhaseUntil = time.Time{}
		}
	} else {
		state.ChallengeFail++
		// Failed challenge escalates to throttle/block
		if e.throttleEnabled {
			state.Phase = PhaseThrottle
			state.PhaseUntil = time.Now().Add(e.throttleDuration)
		}
	}
}

// Block manually blocks an IP
func (e *Engine) Block(ip string, duration time.Duration, reason string) {
	state := e.getOrCreateState(ip)

	state.lock.Lock()
	defer state.lock.Unlock()

	state.Phase = PhaseBlock
	state.PhaseUntil = time.Now().Add(duration)
	state.Blocked = true
	atomic.AddInt64(&e.blockedRequests, 1)
}

// Unblock removes a block from an IP
func (e *Engine) Unblock(ip string) {
	state := e.getOrCreateState(ip)

	state.lock.Lock()
	defer state.lock.Unlock()

	state.Phase = PhaseNormal
	state.PhaseUntil = time.Time{}
	state.Blocked = false
}

// IsBlocked checks if an IP is currently blocked
func (e *Engine) IsBlocked(ip string) bool {
	if stateVal, exists := e.states.Load(ip); exists {
		state := stateVal.(*IPState)
		state.lock.RLock()
		defer state.lock.RUnlock()

		return state.Blocked && time.Now().Before(state.PhaseUntil)
	}
	return false
}

// getOrCreateState gets or creates an IP state
func (e *Engine) getOrCreateState(ip string) *IPState {
	if stateVal, exists := e.states.Load(ip); exists {
		return stateVal.(*IPState)
	}

	state := &IPState{
		IP:          ip,
		Phase:       PhaseNormal,
		LastRequest: time.Now(),
	}

	actual, _ := e.states.LoadOrStore(ip, state)
	return actual.(*IPState)
}

// GetState returns the current state for an IP
func (e *Engine) GetState(ip string) *IPState {
	if stateVal, exists := e.states.Load(ip); exists {
		return stateVal.(*IPState)
	}
	return nil
}

// Stats returns current DDoS engine statistics
func (e *Engine) Stats() map[string]interface{} {
	return map[string]interface{}{
		"total_requests":    atomic.LoadInt64(&e.totalRequests),
		"blocked_requests":  atomic.LoadInt64(&e.blockedRequests),
		"challenges_sent":   atomic.LoadInt64(&e.challengesSent),
		"phase3_enabled":    e.phase3Enabled,
		"challenge_enabled": e.challengeEnabled,
		"throttle_enabled":  e.throttleEnabled,
		"block_enabled":     e.blockEnabled,
	}
}

// cleanupLoop removes old states periodically
func (e *Engine) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			e.cleanup()
		case <-e.shutdown:
			return
		}
	}
}

// cleanup removes stale IP states
func (e *Engine) cleanup() {
	staleThreshold := time.Now().Add(-30 * time.Minute)

	e.states.Range(func(key, value interface{}) bool {
		state := value.(*IPState)
		state.lock.RLock()
		lastRequest := state.LastRequest
		blocked := state.Blocked
		state.lock.RUnlock()

		// Remove if old and not blocked
		if !blocked && lastRequest.Before(staleThreshold) {
			e.states.Delete(key)
		}
		return true
	})
}

// Stop shuts down the engine
func (e *Engine) Stop() {
	close(e.shutdown)
}

// EWMA calculates exponentially weighted moving average
func EWMA(current, previous, alpha float64) float64 {
	return alpha*current + (1-alpha)*previous
}

// CalculateAlpha calculates EWMA alpha from window duration
func CalculateAlpha(window time.Duration) float64 {
	return 2.0 / (window.Seconds() + 1)
}
