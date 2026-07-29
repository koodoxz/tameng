/*
Package actor implements memory-safe actor tracking for SVALINN.

Key design principles:
- Bounded memory: Max actors enforced via LRU eviction
- Two-stage tracking: Lightweight IP counters → Full Actor objects
- Atomic operations: Thread-safe without excessive locking
*/
package actor

import (
	"sync"
	"sync/atomic"
	"time"
)

// Actor represents a tracked entity (usually by IP)
type Actor struct {
	IP            string
	FirstSeen     time.Time
	LastSeen      time.Time
	RequestCount  int64
	BlockedCount  int64
	ThreatScore   float64
	ThreatTypes   []string
	UserAgents    map[string]int
	Paths         map[string]int
	Fingerprints  []string
	Country       string
	ASN           string
	IsBlocked     bool
	BlockedUntil  time.Time
	BlockReason   string
	Challenges    int
	ChallengePass int

	// Enhanced threat indicators
	HoneypotHits    int // Honeypot/deception triggers
	SuspiciousPaths int // Path traversal, sensitive file access
	SQLiAttempts    int // SQL injection attempts
	XSSAttempts     int // XSS attempts
	ScannerHits     int // Known scanner patterns detected

	// Behavioral data
	AvgRequestInterval time.Duration
	LastPaths          []string // Last N paths visited

	lock sync.RWMutex
}

func (a *Actor) RecordUserAgent(ua string) {
	if ua == "" {
		return
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.UserAgents == nil {
		a.UserAgents = make(map[string]int)
	}
	a.UserAgents[ua]++
}

func (a *Actor) RecordPath(path string) {
	if path == "" {
		return
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.Paths == nil {
		a.Paths = make(map[string]int)
	}
	a.Paths[path]++
}

// CalculateRiskScore computes a 0-100 risk score based on threat indicators
// This is the authoritative scoring for AEGIS ecosystem sync
func (a *Actor) CalculateRiskScore() float64 {
	a.lock.RLock()
	defer a.lock.RUnlock()

	score := 0.0

	// 1. Blocked count (strong indicator) - up to 30 points
	if a.BlockedCount > 0 {
		score += min(30, float64(a.BlockedCount)*5)
	}

	// 2. Honeypot hits (very strong indicator) - up to 25 points
	if a.HoneypotHits > 0 {
		score += min(25, float64(a.HoneypotHits)*10)
	}

	// 3. Attack technique diversity - up to 20 points
	score += min(20, float64(len(a.ThreatTypes))*4)

	// 4. Specific attack types - up to 15 points
	score += min(5, float64(a.SQLiAttempts)*2.5)
	score += min(5, float64(a.XSSAttempts)*2.5)
	score += min(5, float64(a.SuspiciousPaths)*2.5)

	// 5. Scanner behavior - up to 10 points
	if a.ScannerHits > 0 {
		score += min(10, float64(a.ScannerHits)*2)
	}

	// 6. Fingerprint evasion (multiple fingerprints = evasion) - up to 10 points
	if len(a.Fingerprints) > 1 {
		score += min(10, float64(len(a.Fingerprints)-1)*3)
	}

	// 7. Persistence bonus (active for long time) - up to 10 points
	duration := time.Since(a.FirstSeen).Hours()
	if duration > 24 {
		score += 5
	}
	if duration > 168 { // 1 week
		score += 5
	}

	// 8. Request volume penalty (high volume = suspicious) - up to 10 points
	if a.RequestCount > 100 {
		score += min(10, float64(a.RequestCount)/100)
	}

	// Clamp to 0-100
	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}

	return score
}

// min returns the smaller of two float64 values
func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// IPCounter is a lightweight counter for initial IP tracking
type IPCounter struct {
	Count     int64
	FirstSeen time.Time
	LastSeen  time.Time
}

// Tracker manages actor tracking with bounded memory
type Tracker struct {
	// Two-stage tracking
	counters sync.Map // map[string]*IPCounter - lightweight
	actors   sync.Map // map[string]*Actor - full tracking

	// Settings
	maxActors          int
	promotionThreshold int64
	evictionInterval   time.Duration

	// Stats
	activeCounters int64
	activeActors   int64

	// Shutdown
	shutdown chan struct{}
}

// NewTracker creates a new actor tracker
func NewTracker(maxActors int, promotionThreshold int, evictionInterval time.Duration) *Tracker {
	t := &Tracker{
		maxActors:          maxActors,
		promotionThreshold: int64(promotionThreshold),
		evictionInterval:   evictionInterval,
		shutdown:           make(chan struct{}),
	}

	// Start background eviction
	go t.evictionLoop()

	return t
}

// Track records a request from an IP
func (t *Tracker) Track(ip string) *Actor {
	now := time.Now()

	// First, check if already a full actor
	if actorVal, exists := t.actors.Load(ip); exists {
		actor := actorVal.(*Actor)
		actor.lock.Lock()
		actor.LastSeen = now
		atomic.AddInt64(&actor.RequestCount, 1)
		actor.lock.Unlock()
		return actor
	}

	// Check/update lightweight counter
	counterVal, loaded := t.counters.LoadOrStore(ip, &IPCounter{
		Count:     1,
		FirstSeen: now,
		LastSeen:  now,
	})

	if loaded {
		counter := counterVal.(*IPCounter)
		count := atomic.AddInt64(&counter.Count, 1)
		counter.LastSeen = now

		// Check for promotion to full actor
		if count >= t.promotionThreshold {
			return t.promote(ip, counter)
		}
	} else {
		atomic.AddInt64(&t.activeCounters, 1)
	}

	return nil // Not yet a full actor
}

// promote upgrades an IP counter to a full Actor
func (t *Tracker) promote(ip string, counter *IPCounter) *Actor {
	// Check memory limits before promotion
	if atomic.LoadInt64(&t.activeActors) >= int64(t.maxActors) {
		t.evictOldest()
	}

	actor := &Actor{
		IP:           ip,
		FirstSeen:    counter.FirstSeen,
		LastSeen:     counter.LastSeen,
		RequestCount: counter.Count,
		UserAgents:   make(map[string]int),
		Paths:        make(map[string]int),
		Fingerprints: make([]string, 0),
		ThreatTypes:  make([]string, 0),
		LastPaths:    make([]string, 0, 10),
	}

	// Atomic swap: store actor, delete counter
	t.actors.Store(ip, actor)
	t.counters.Delete(ip)
	atomic.AddInt64(&t.activeActors, 1)
	atomic.AddInt64(&t.activeCounters, -1)

	return actor
}

// Get returns an actor by IP (nil if not tracked or only counter)
func (t *Tracker) Get(ip string) *Actor {
	if actorVal, exists := t.actors.Load(ip); exists {
		return actorVal.(*Actor)
	}
	return nil
}

// GetOrCreate returns an existing actor or creates a new one
func (t *Tracker) GetOrCreate(ip string) *Actor {
	// Check existing
	if actor := t.Get(ip); actor != nil {
		return actor
	}

	// Track and potentially promote
	return t.Track(ip)
}

// Block marks an actor as blocked
func (t *Tracker) Block(ip string, reason string, duration time.Duration) *Actor {
	actor := t.GetOrCreate(ip)
	if actor == nil {
		// Force create actor for blocking
		actor = &Actor{
			IP:          ip,
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
			UserAgents:  make(map[string]int),
			Paths:       make(map[string]int),
			ThreatTypes: make([]string, 0),
		}
		t.actors.Store(ip, actor)
		atomic.AddInt64(&t.activeActors, 1)
	}

	actor.lock.Lock()
	actor.IsBlocked = true
	actor.BlockedUntil = time.Now().Add(duration)
	actor.BlockReason = reason
	atomic.AddInt64(&actor.BlockedCount, 1)
	actor.lock.Unlock()

	return actor
}

// Unblock removes block from an actor
func (t *Tracker) Unblock(ip string) {
	if actorVal, exists := t.actors.Load(ip); exists {
		actor := actorVal.(*Actor)
		actor.lock.Lock()
		actor.IsBlocked = false
		actor.BlockedUntil = time.Time{}
		actor.lock.Unlock()
	}
}

// IsBlocked checks if an IP is currently blocked
func (t *Tracker) IsBlocked(ip string) (bool, string) {
	if actorVal, exists := t.actors.Load(ip); exists {
		actor := actorVal.(*Actor)
		actor.lock.RLock()
		defer actor.lock.RUnlock()

		if actor.IsBlocked && time.Now().Before(actor.BlockedUntil) {
			return true, actor.BlockReason
		}
		// Auto-unblock if expired
		if actor.IsBlocked && time.Now().After(actor.BlockedUntil) {
			actor.IsBlocked = false
		}
	}
	return false, ""
}

// AddThreat records a threat for an actor
func (t *Tracker) AddThreat(ip string, threatType string, score float64) {
	actor := t.GetOrCreate(ip)
	if actor == nil {
		return
	}

	actor.lock.Lock()
	defer actor.lock.Unlock()

	actor.ThreatTypes = append(actor.ThreatTypes, threatType)
	actor.ThreatScore += score

	// Keep last 100 threats
	if len(actor.ThreatTypes) > 100 {
		actor.ThreatTypes = actor.ThreatTypes[len(actor.ThreatTypes)-100:]
	}
}

// evictionLoop runs periodic cleanup
func (t *Tracker) evictionLoop() {
	ticker := time.NewTicker(t.evictionInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			t.cleanup()
		case <-t.shutdown:
			return
		}
	}
}

// cleanup removes stale entries
func (t *Tracker) cleanup() {
	now := time.Now()
	staleThreshold := now.Add(-1 * time.Hour) // 1 hour idle = stale

	// Cleanup old counters
	t.counters.Range(func(key, value interface{}) bool {
		counter := value.(*IPCounter)
		if counter.LastSeen.Before(staleThreshold) {
			t.counters.Delete(key)
			atomic.AddInt64(&t.activeCounters, -1)
		}
		return true
	})

	// Cleanup old actors (keep blocked ones)
	t.actors.Range(func(key, value interface{}) bool {
		actor := value.(*Actor)
		actor.lock.RLock()
		isBlocked := actor.IsBlocked
		lastSeen := actor.LastSeen
		actor.lock.RUnlock()

		if !isBlocked && lastSeen.Before(staleThreshold) {
			t.actors.Delete(key)
			atomic.AddInt64(&t.activeActors, -1)
		}
		return true
	})
}

// evictOldest removes the oldest actor to make room
func (t *Tracker) evictOldest() {
	var oldestKey interface{}
	var oldestTime time.Time = time.Now()

	t.actors.Range(func(key, value interface{}) bool {
		actor := value.(*Actor)
		actor.lock.RLock()
		if !actor.IsBlocked && actor.LastSeen.Before(oldestTime) {
			oldestTime = actor.LastSeen
			oldestKey = key
		}
		actor.lock.RUnlock()
		return true
	})

	if oldestKey != nil {
		t.actors.Delete(oldestKey)
		atomic.AddInt64(&t.activeActors, -1)
	}
}

// Stats returns current tracking statistics
func (t *Tracker) Stats() (counters, actors int64) {
	return atomic.LoadInt64(&t.activeCounters), atomic.LoadInt64(&t.activeActors)
}

// Stop shuts down the tracker
func (t *Tracker) Stop() {
	close(t.shutdown)
}
