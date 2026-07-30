/*
Package countermeasures implements controlled micro-countermeasures.

Ported from Node.js engine/countermeasures.js.
*/
package countermeasures

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/koodoxz/tameng/internal/actor"
)

const (
	ActionThrottle     = "THROTTLE"
	ActionTempBlock    = "TEMP_BLOCK"
	ActionSoftIsolate  = "SOFT_ISOLATE"
	ActionRotateKey    = "ROTATE_KEY"
	ActionDisableDecoy = "DISABLE_DECOY"
	ActionSwitchDecoy  = "SWITCH_DECOY"
	ActionAlert        = "ALERT"
)

var BlockEscalation = map[int]time.Duration{
	1: 5 * time.Minute,
	2: 15 * time.Minute,
	3: 30 * time.Minute,
	4: 60 * time.Minute,
	5: 24 * time.Hour,
}

type ActionLog struct {
	Actions []ActionEntry `json:"actions"`
	Version string        `json:"version"`
}

type ActionEntry struct {
	ID         string                 `json:"id"`
	Timestamp  time.Time              `json:"timestamp"`
	Type       string                 `json:"type"`
	Target     string                 `json:"target"`
	Details    map[string]interface{} `json:"details"`
	Reversible bool                   `json:"reversible"`
	Reversed   bool                   `json:"reversed"`
	ReversedAt *time.Time             `json:"reversed_at,omitempty"`
}

type BlockEntry struct {
	Until  time.Time
	Level  int
	Reason string
}

type ThrottleEntry struct {
	Multiplier float64
	Until      time.Time
}

type IsolationEntry struct {
	Mode  string
	Until time.Time
}

type Countermeasures struct {
	blockedIPs   map[string]BlockEntry
	throttledIPs map[string]ThrottleEntry
	isolatedIPs  map[string]IsolationEntry
	rotatedKeys  map[string]string
	logPath      string
	log          ActionLog
	lock         sync.RWMutex
}

func New(logPath string) *Countermeasures {
	cm := &Countermeasures{
		blockedIPs:   make(map[string]BlockEntry),
		throttledIPs: make(map[string]ThrottleEntry),
		isolatedIPs:  make(map[string]IsolationEntry),
		rotatedKeys:  make(map[string]string),
		logPath:      logPath,
		log:          ActionLog{Version: "9.0"},
	}
	cm.loadLog()
	return cm
}

func (c *Countermeasures) Throttle(ip string, multiplier float64, duration time.Duration) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.throttledIPs[ip] = ThrottleEntry{Multiplier: multiplier, Until: time.Now().Add(duration)}
	c.logAction(ActionThrottle, ip, map[string]interface{}{
		"multiplier":  multiplier,
		"duration_ms": duration.Milliseconds(),
	})
}

func (c *Countermeasures) TempBlock(ip string, reason string) BlockEntry {
	c.lock.Lock()
	defer c.lock.Unlock()
	level := 1
	if existing, ok := c.blockedIPs[ip]; ok {
		if existing.Level < 5 {
			level = existing.Level + 1
		}
	}
	duration := BlockEscalation[level]
	entry := BlockEntry{Until: time.Now().Add(duration), Level: level, Reason: reason}
	c.blockedIPs[ip] = entry
	c.logAction(ActionTempBlock, ip, map[string]interface{}{
		"level":       level,
		"duration_ms": duration.Milliseconds(),
		"reason":      reason,
	})
	return entry
}

func (c *Countermeasures) SoftIsolate(ip string, duration time.Duration) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.isolatedIPs[ip] = IsolationEntry{Mode: "log-only", Until: time.Now().Add(duration)}
	c.logAction(ActionSoftIsolate, ip, map[string]interface{}{
		"duration_ms": duration.Milliseconds(),
	})
}

func (c *Countermeasures) IsBlocked(ip string) (BlockEntry, bool) {
	c.lock.RLock()
	entry, ok := c.blockedIPs[ip]
	c.lock.RUnlock()
	if !ok {
		return BlockEntry{}, false
	}
	if time.Now().After(entry.Until) {
		c.lock.Lock()
		delete(c.blockedIPs, ip)
		c.lock.Unlock()
		return BlockEntry{}, false
	}
	return entry, true
}

func (c *Countermeasures) Unblock(ip string) bool {
	c.lock.Lock()
	defer c.lock.Unlock()
	if _, ok := c.blockedIPs[ip]; !ok {
		return false
	}
	delete(c.blockedIPs, ip)
	entry := ActionEntry{
		ID:         randomID(),
		Timestamp:  time.Now(),
		Type:       ActionTempBlock,
		Target:     ip,
		Details:    map[string]interface{}{"reversed": true},
		Reversible: true,
		Reversed:   true,
	}
	c.log.Actions = append(c.log.Actions, entry)
	if len(c.log.Actions) > 1000 {
		c.log.Actions = c.log.Actions[len(c.log.Actions)-1000:]
	}
	c.saveLog()
	return true
}

func (c *Countermeasures) ReverseLastBlock(ip string) bool {
	c.lock.Lock()
	defer c.lock.Unlock()
	var idx int = -1
	for i := len(c.log.Actions) - 1; i >= 0; i-- {
		a := c.log.Actions[i]
		if a.Target == ip && a.Type == ActionTempBlock && !a.Reversed {
			idx = i
			break
		}
	}
	if idx == -1 {
		return false
	}
	delete(c.blockedIPs, ip)
	now := time.Now()
	c.log.Actions[idx].Reversed = true
	c.log.Actions[idx].ReversedAt = &now
	c.saveLog()
	return true
}

func (c *Countermeasures) ThrottleMultiplier(ip string) float64 {
	c.lock.RLock()
	entry, ok := c.throttledIPs[ip]
	c.lock.RUnlock()
	if !ok {
		return 1
	}
	if time.Now().After(entry.Until) {
		c.lock.Lock()
		delete(c.throttledIPs, ip)
		c.lock.Unlock()
		return 1
	}
	return entry.Multiplier
}

func (c *Countermeasures) IsIsolated(ip string) bool {
	c.lock.RLock()
	entry, ok := c.isolatedIPs[ip]
	c.lock.RUnlock()
	if !ok {
		return false
	}
	if time.Now().After(entry.Until) {
		c.lock.Lock()
		delete(c.isolatedIPs, ip)
		c.lock.Unlock()
		return false
	}
	return true
}

func (c *Countermeasures) AutoRespond(ip string, actorObj *actor.Actor) []string {
	if actorObj == nil {
		return nil
	}
	risk := actorObj.CalculateRiskScore()
	actions := make([]string, 0)
	if risk > 70 {
		c.TempBlock(ip, "high_risk")
		actions = append(actions, ActionTempBlock)
	} else if risk > 40 {
		c.Throttle(ip, 5, 15*time.Minute)
		c.SoftIsolate(ip, 60*time.Minute)
		actions = append(actions, ActionThrottle, ActionSoftIsolate)
	} else if risk > 20 {
		c.Throttle(ip, 2, 5*time.Minute)
		actions = append(actions, ActionThrottle)
	}
	return actions
}

func (c *Countermeasures) Cleanup() {
	c.lock.Lock()
	defer c.lock.Unlock()
	now := time.Now()
	for ip, entry := range c.blockedIPs {
		if now.After(entry.Until) {
			delete(c.blockedIPs, ip)
		}
	}
	for ip, entry := range c.throttledIPs {
		if now.After(entry.Until) {
			delete(c.throttledIPs, ip)
		}
	}
	for ip, entry := range c.isolatedIPs {
		if now.After(entry.Until) {
			delete(c.isolatedIPs, ip)
		}
	}
}

func (c *Countermeasures) Stats() map[string]int {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return map[string]int{
		"blocked":   len(c.blockedIPs),
		"throttled": len(c.throttledIPs),
		"isolated":  len(c.isolatedIPs),
	}
}

func (c *Countermeasures) RecentActions(limit int) []ActionEntry {
	c.lock.RLock()
	defer c.lock.RUnlock()
	if limit <= 0 {
		return []ActionEntry{}
	}
	if len(c.log.Actions) <= limit {
		return append([]ActionEntry{}, c.log.Actions...)
	}
	start := len(c.log.Actions) - limit
	return append([]ActionEntry{}, c.log.Actions[start:]...)
}

func (c *Countermeasures) logAction(actionType, target string, details map[string]interface{}) {
	entry := ActionEntry{
		ID:         randomID(),
		Timestamp:  time.Now(),
		Type:       actionType,
		Target:     target,
		Details:    details,
		Reversible: true,
		Reversed:   false,
	}
	c.log.Actions = append(c.log.Actions, entry)
	if len(c.log.Actions) > 1000 {
		c.log.Actions = c.log.Actions[len(c.log.Actions)-1000:]
	}
	c.saveLog()
}

func (c *Countermeasures) loadLog() {
	if c.logPath == "" {
		return
	}
	data, err := os.ReadFile(c.logPath)
	if err != nil {
		return
	}
	_ = json.Unmarshal(data, &c.log)
}

func (c *Countermeasures) saveLog() {
	if c.logPath == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(c.logPath), 0755); err != nil {
		return
	}
	data, err := json.MarshalIndent(c.log, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(c.logPath, data, 0644)
}

func randomID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
