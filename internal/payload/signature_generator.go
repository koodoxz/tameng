/*
Package payload provides payload signature generation utilities.
*/
package payload

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

// SignatureConfig configures payload signature generation.
type SignatureConfig struct {
	Enabled      bool
	YARAEnabled  bool
	SigmaEnabled bool
	SnortEnabled bool
}

// Generator produces signatures from payloads.
type Generator struct {
	config     SignatureConfig
	signatures map[string]GeneratedSignatures
	stats      GeneratorStats
	lock       sync.Mutex
}

// GeneratorStats tracks generation metrics.
type GeneratorStats struct {
	Generated int64     `json:"generated"`
	Cached    int64     `json:"cached"`
	UpdatedAt time.Time `json:"updated_at"`
}

// GeneratedSignatures holds generated rules.
type GeneratedSignatures struct {
	YARA  string   `json:"yara,omitempty"`
	Sigma string   `json:"sigma,omitempty"`
	Snort string   `json:"snort,omitempty"`
	Regex []string `json:"regex,omitempty"`
}

// NewGenerator creates a payload signature generator.
func NewGenerator(cfg SignatureConfig) *Generator {
	return &Generator{
		config:     cfg,
		signatures: make(map[string]GeneratedSignatures),
	}
}

// GenerateFromPayload generates signatures for a payload string.
func (g *Generator) GenerateFromPayload(name string, payload string) GeneratedSignatures {
	if !g.config.Enabled {
		return GeneratedSignatures{}
	}

	normalized := NormalizePolymorphicCode(payload)
	hash := payloadHash(normalized)

	g.lock.Lock()
	if cached, ok := g.signatures[hash]; ok {
		g.stats.Cached++
		g.lock.Unlock()
		return cached
	}
	g.lock.Unlock()

	patterns := []string{normalized}
	result := GeneratedSignatures{}

	if g.config.YARAEnabled {
		result.YARA = g.GenerateYARARule(name, patterns)
	}
	if g.config.SigmaEnabled {
		result.Sigma = g.GenerateSigmaRule(name, patterns, "high")
	}
	if g.config.SnortEnabled {
		result.Snort = g.GenerateSnortRule(name, patterns, "trojan-activity")
	}
	result.Regex = g.GenerateRegexPatterns(patterns)

	g.lock.Lock()
	g.signatures[hash] = result
	g.stats.Generated++
	g.stats.UpdatedAt = time.Now()
	g.lock.Unlock()

	return result
}

// GenerateYARARule generates a YARA rule.
func (g *Generator) GenerateYARARule(name string, patterns []string) string {
	return fmt.Sprintf("rule %s { strings: $a = \"%s\" condition: $a }", sanitizeName(name), patterns[0])
}

// GenerateSigmaRule generates a Sigma rule.
func (g *Generator) GenerateSigmaRule(name string, patterns []string, level string) string {
	return fmt.Sprintf("title: %s\nid: %s\nstatus: experimental\nlevel: %s\nlogsource:\n  product: web\ndetection:\n  selection:\n    Payload|contains: '%s'\n  condition: selection\n", name, payloadHash(name), level, patterns[0])
}

// GenerateSnortRule generates a Snort rule.
func (g *Generator) GenerateSnortRule(name string, patterns []string, classtype string) string {
	return fmt.Sprintf("alert tcp any any -> any any (msg:\"%s\"; content:\"%s\"; classtype:%s; sid:%d; rev:1;)", name, patterns[0], classtype, time.Now().Unix()%100000)
}

// GenerateRegexPatterns creates regex patterns for payloads.
func (g *Generator) GenerateRegexPatterns(patterns []string) []string {
	results := make([]string, 0, len(patterns))
	for _, pattern := range patterns {
		escaped := regexp.QuoteMeta(pattern)
		results = append(results, fmt.Sprintf("(?i)%s", escaped))
	}
	return results
}

// Stats returns generator stats.
func (g *Generator) Stats() map[string]interface{} {
	g.lock.Lock()
	defer g.lock.Unlock()
	return map[string]interface{}{
		"generated": g.stats.Generated,
		"cached":    g.stats.Cached,
		"updated_at": g.stats.UpdatedAt,
		"cached_signatures": len(g.signatures),
		"enabled": g.config.Enabled,
		"yara_enabled": g.config.YARAEnabled,
		"sigma_enabled": g.config.SigmaEnabled,
		"snort_enabled": g.config.SnortEnabled,
	}
}

// NormalizePolymorphicCode normalizes payloads for signature generation.
func NormalizePolymorphicCode(payload string) string {
	trimmed := strings.TrimSpace(payload)
	trimmed = strings.ReplaceAll(trimmed, "\r", "")
	trimmed = strings.ReplaceAll(trimmed, "\n", " ")
	trimmed = strings.Join(strings.Fields(trimmed), " ")
	return trimmed
}

func payloadHash(payload string) string {
	hash := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(hash[:])
}

func sanitizeName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "payload_signature"
	}
	name = strings.ReplaceAll(name, " ", "_")
	name = strings.ReplaceAll(name, "-", "_")
	return name
}
