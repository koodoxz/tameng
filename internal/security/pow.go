/*
Package security implements proof-of-work challenges.
*/
package security

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"time"
)

// PoWConfig configures proof-of-work behavior.
type PoWConfig struct {
	Enabled    bool
	Difficulty int
	TokenTTL   time.Duration
}

// Stats returns PoW stats.
func (p *PoWEngine) Stats() map[string]interface{} {
	p.lock.Lock()
	defer p.lock.Unlock()

	return map[string]interface{}{
		"challenges_issued": p.stats.ChallengesIssued,
		"challenges_solved": p.stats.ChallengesSolved,
		"challenges_failed": p.stats.ChallengesFailed,
		"active_tokens":     len(p.tokens),
		"enabled":           p.config.Enabled,
		"difficulty":        p.config.Difficulty,
		"token_ttl":         p.config.TokenTTL.String(),
	}
}

// PoWEngine issues and validates PoW challenges.
type PoWEngine struct {
	config PoWConfig
	tokens map[string]powToken
	stats  PoWStats
	lock   sync.Mutex
}

type powToken struct {
	prefix    string
	expiresAt time.Time
}

// PoWStats tracks proof-of-work usage.
type PoWStats struct {
	ChallengesIssued int64 `json:"challenges_issued"`
	ChallengesSolved int64 `json:"challenges_solved"`
	ChallengesFailed int64 `json:"challenges_failed"`
}

// NewPoWEngine creates a new PoW engine.
func NewPoWEngine(cfg PoWConfig) *PoWEngine {
	if cfg.Difficulty == 0 {
		cfg.Difficulty = 4
	}
	if cfg.TokenTTL == 0 {
		cfg.TokenTTL = 2 * time.Minute
	}

	return &PoWEngine{
		config: cfg,
		tokens: make(map[string]powToken),
	}
}

// Challenge issues a new PoW token and prefix.
func (p *PoWEngine) Challenge() (token string, prefix string) {
	p.lock.Lock()
	defer p.lock.Unlock()

	prefix = randomHex(8)
	token = randomHex(16)
	p.tokens[token] = powToken{
		prefix:    prefix,
		expiresAt: time.Now().Add(p.config.TokenTTL),
	}
	p.stats.ChallengesIssued++
	return token, prefix
}

// Validate verifies a PoW solution.
func (p *PoWEngine) Validate(token string, nonce string) bool {
	if !p.config.Enabled {
		return true
	}

	p.lock.Lock()
	defer p.lock.Unlock()

	stored, ok := p.tokens[token]
	if !ok {
		return false
	}
	if time.Now().After(stored.expiresAt) {
		delete(p.tokens, token)
		p.stats.ChallengesFailed++
		return false
	}

	hash := sha256.Sum256([]byte(stored.prefix + nonce))
	hexHash := hex.EncodeToString(hash[:])
	if strings.HasPrefix(hexHash, strings.Repeat("0", p.config.Difficulty)) {
		delete(p.tokens, token)
		p.stats.ChallengesSolved++
		return true
	}

	p.stats.ChallengesFailed++

	return false
}

// Cleanup removes expired tokens.
func (p *PoWEngine) Cleanup() {
	p.lock.Lock()
	defer p.lock.Unlock()

	now := time.Now()
	for token, data := range p.tokens {
		if now.After(data.expiresAt) {
			delete(p.tokens, token)
		}
	}
}

func randomHex(bytes int) string {
	buf := make([]byte, bytes)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}
