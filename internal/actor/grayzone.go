/*
Package actor - Gray Zone implementation.

Gray Zone is a circular buffer that stores uncertain attack events
for later analysis by the Evolution Engine (LLM).
*/
package actor

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// GrayZoneEntry represents an uncertain event
type GrayZoneEntry struct {
	ID        string            `json:"id"`
	Timestamp time.Time         `json:"timestamp"`
	IP        string            `json:"ip"`
	Method    string            `json:"method"`
	Path      string            `json:"path"`
	Headers   map[string]string `json:"headers"`
	Body      string            `json:"body"`
	Score     float64           `json:"score"`
	Reason    string            `json:"reason"`
	Matched   []string          `json:"matched"`
	UserAgent string            `json:"user_agent"`
	Country   string            `json:"country"`

	// ML metadata
	MLScore      float64 `json:"ml_score,omitempty"`
	MLPrediction string  `json:"ml_prediction,omitempty"`
}

// GrayZone is a bounded circular buffer for uncertain events
type GrayZone struct {
	entries []GrayZoneEntry
	size    int
	head    int
	count   int
	lock    sync.RWMutex

	// Persistence
	filePath string
}

// NewGrayZone creates a new gray zone buffer
func NewGrayZone(size int, filePath string) *GrayZone {
	gz := &GrayZone{
		entries:  make([]GrayZoneEntry, size),
		size:     size,
		filePath: filePath,
	}

	// Try to load existing data
	gz.loadFromFile()

	return gz
}

// Add adds an entry to the gray zone (circular buffer)
func (gz *GrayZone) Add(entry GrayZoneEntry) {
	gz.lock.Lock()
	defer gz.lock.Unlock()

	// Generate ID if not set
	if entry.ID == "" {
		entry.ID = generateID()
	}

	// Set timestamp if not set
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}

	// Add to circular buffer
	gz.entries[gz.head] = entry
	gz.head = (gz.head + 1) % gz.size

	if gz.count < gz.size {
		gz.count++
	}
}

// GetAll returns all entries in the gray zone
func (gz *GrayZone) GetAll() []GrayZoneEntry {
	gz.lock.RLock()
	defer gz.lock.RUnlock()
	return gz.getAllLocked()
}

// getAllLocked returns all entries. Caller must already hold gz.lock
// (read or write) -- it does not lock itself, to avoid recursive RLock
// calls that can deadlock against a pending writer (see SaveToFile).
func (gz *GrayZone) getAllLocked() []GrayZoneEntry {
	result := make([]GrayZoneEntry, gz.count)

	// Read from oldest to newest
	start := 0
	if gz.count == gz.size {
		start = gz.head
	}

	for i := 0; i < gz.count; i++ {
		idx := (start + i) % gz.size
		result[i] = gz.entries[idx]
	}

	return result
}

// GetRecent returns the N most recent entries
func (gz *GrayZone) GetRecent(n int) []GrayZoneEntry {
	gz.lock.RLock()
	defer gz.lock.RUnlock()

	if n > gz.count {
		n = gz.count
	}

	result := make([]GrayZoneEntry, n)

	for i := 0; i < n; i++ {
		// Read from newest backwards
		idx := (gz.head - 1 - i + gz.size) % gz.size
		result[i] = gz.entries[idx]
	}

	return result
}

// Count returns the number of entries in the buffer
func (gz *GrayZone) Count() int {
	gz.lock.RLock()
	defer gz.lock.RUnlock()
	return gz.count
}

// Clear empties the gray zone
func (gz *GrayZone) Clear() {
	gz.lock.Lock()
	defer gz.lock.Unlock()

	gz.entries = make([]GrayZoneEntry, gz.size)
	gz.head = 0
	gz.count = 0
}

// SaveToFile persists the gray zone to disk. It takes the exclusive lock
// (not RLock) because concurrent SaveToFile calls must not race each
// other writing the same file, and because it must not re-enter the
// lock via GetAll() (see getAllLocked). The lock is held only long enough
// to snapshot the buffer -- marshaling and the disk write happen outside
// it, so Add() on the hot request path isn't blocked for the duration of
// a syscall.
func (gz *GrayZone) SaveToFile() error {
	if gz.filePath == "" {
		return nil
	}

	gz.lock.Lock()
	snapshot := gz.getAllLocked()
	gz.lock.Unlock()

	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(gz.filePath, data, 0644)
}

// loadFromFile loads gray zone data from disk
func (gz *GrayZone) loadFromFile() {
	if gz.filePath == "" {
		return
	}

	data, err := os.ReadFile(gz.filePath)
	if err != nil {
		return // File doesn't exist, start fresh
	}

	var entries []GrayZoneEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return
	}

	// Reload entries into buffer
	for _, entry := range entries {
		if gz.count < gz.size {
			gz.entries[gz.head] = entry
			gz.head = (gz.head + 1) % gz.size
			gz.count++
		}
	}
}

// GetByIP returns all entries from a specific IP
func (gz *GrayZone) GetByIP(ip string) []GrayZoneEntry {
	gz.lock.RLock()
	defer gz.lock.RUnlock()

	var result []GrayZoneEntry

	for i := 0; i < gz.count; i++ {
		idx := i
		if gz.count == gz.size {
			idx = (gz.head + i) % gz.size
		}

		if gz.entries[idx].IP == ip {
			result = append(result, gz.entries[idx])
		}
	}

	return result
}

// GetByScoreRange returns entries within a score range
func (gz *GrayZone) GetByScoreRange(minScore, maxScore float64) []GrayZoneEntry {
	gz.lock.RLock()
	defer gz.lock.RUnlock()

	var result []GrayZoneEntry

	for i := 0; i < gz.count; i++ {
		idx := i
		if gz.count == gz.size {
			idx = (gz.head + i) % gz.size
		}

		score := gz.entries[idx].Score
		if score >= minScore && score <= maxScore {
			result = append(result, gz.entries[idx])
		}
	}

	return result
}

// generateID creates a unique ID for entries
func generateID() string {
	return time.Now().Format("20060102-150405") + "-" + randomHex(4)
}

// randomHex generates random hex string
func randomHex(n int) string {
	const chars = "0123456789abcdef"
	b := make([]byte, n)
	for i := range b {
		b[i] = chars[time.Now().UnixNano()%16]
		time.Sleep(1) // Ensure different values
	}
	return string(b)
}
