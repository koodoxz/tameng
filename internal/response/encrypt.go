/*
Package response implements dynamic response obfuscation.
*/
package response

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"sync"
	"time"
)

// EncryptConfig controls response obfuscation.
type EncryptConfig struct {
	Enabled      bool
	ProtectPaths []string
	ExcludePaths []string
	TokenTTL     time.Duration
	EncryptHTML  bool
	EncryptJS    bool
}

// Encryptor manages response encryption tokens.
type Encryptor struct {
	config EncryptConfig
	tokens map[string]time.Time
	lock   sync.Mutex
}

// NewEncryptor creates a new encryptor.
func NewEncryptor(cfg EncryptConfig) *Encryptor {
	if cfg.TokenTTL == 0 {
		cfg.TokenTTL = 5 * time.Minute
	}
	if cfg.ProtectPaths == nil {
		cfg.ProtectPaths = []string{"/admin", "/dashboard", "/api/v9"}
	}
	if cfg.ExcludePaths == nil {
		cfg.ExcludePaths = []string{"/health", "/metrics"}
	}

	return &Encryptor{
		config: cfg,
		tokens: make(map[string]time.Time),
	}
}

// Stats returns encryptor stats.
func (e *Encryptor) Stats() map[string]interface{} {
	e.lock.Lock()
	defer e.lock.Unlock()

	return map[string]interface{}{
		"active_tokens": len(e.tokens),
		"enabled":       e.config.Enabled,
		"token_ttl":     e.config.TokenTTL.String(),
		"protect_paths": e.config.ProtectPaths,
	}
}

// Token issues a new response token.
func (e *Encryptor) Token() string {
	token := randomHex(16)
	e.lock.Lock()
	e.tokens[token] = time.Now().Add(e.config.TokenTTL)
	e.lock.Unlock()
	return token
}

// ShouldProtect checks whether a path should be protected.
func (e *Encryptor) ShouldProtect(path string) bool {
	for _, exclude := range e.config.ExcludePaths {
		if strings.HasPrefix(path, exclude) {
			return false
		}
	}
	for _, protect := range e.config.ProtectPaths {
		if strings.HasPrefix(path, protect) {
			return true
		}
	}
	return false
}

// Obfuscate performs lightweight obfuscation.
func (e *Encryptor) Obfuscate(contentType string, body []byte, token string) []byte {
	if contentType == "" {
		return body
	}
	if e.config.EncryptHTML && strings.Contains(contentType, "text/html") {
		return append(body, []byte("<!-- svalinn-token:"+token+" -->")...)
	}
	if e.config.EncryptJS && strings.Contains(contentType, "javascript") {
		return append(body, []byte("\n// svalinn-token:"+token)...)
	}
	return body
}

// Cleanup removes expired tokens.
func (e *Encryptor) Cleanup() {
	e.lock.Lock()
	defer e.lock.Unlock()

	now := time.Now()
	for token, expiry := range e.tokens {
		if now.After(expiry) {
			delete(e.tokens, token)
		}
	}
}

func randomHex(bytes int) string {
	buf := make([]byte, bytes)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}
