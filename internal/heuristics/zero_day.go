/*
Package heuristics implements zero-day attack detection

Uses heuristic analysis to detect unknown attacks
*/
package heuristics

import (
	"math"
	"net/http"
	"regexp"
	"strings"
)

// Engine performs heuristic analysis
type Engine struct {
	entropyThreshold float64
	obfuscationScore int
	polymorphicScore float64
}

// Result contains heuristic analysis results
type Result struct {
	IsSuspicious     bool
	Score            float64
	Entropy          float64
	HasObfuscation   bool
	IsPolymorphic    bool
	HasSQLInjection  bool
	HasXSS           bool
	HasCommandInj    bool
	HasPathTraversal bool
	Indicators       []string
}

// NewEngine creates a new heuristics engine
func NewEngine() *Engine {
	return &Engine{
		entropyThreshold: 4.5, // Shannon entropy threshold
		obfuscationScore: 2,   // Minimum indicators for obfuscation
		polymorphicScore: 0.6, // Polymorphic detection threshold
	}
}

// Analyze performs comprehensive heuristic analysis
func (e *Engine) Analyze(r *http.Request) *Result {
	payload := r.URL.RawQuery

	// Also check body for POST requests
	if r.Method == "POST" {
		// Body reading would go here - skipped for brevity
	}

	result := &Result{
		Indicators: []string{},
	}

	// Calculate entropy
	result.Entropy = e.calculateEntropy(payload)
	if result.Entropy > e.entropyThreshold {
		result.Indicators = append(result.Indicators, "high_entropy")
	}

	// Check for obfuscation
	result.HasObfuscation = e.detectObfuscation(payload)
	if result.HasObfuscation {
		result.Indicators = append(result.Indicators, "obfuscation_detected")
	}

	// Check for polymorphic patterns
	result.IsPolymorphic = e.detectPolymorphic(payload)
	if result.IsPolymorphic {
		result.Indicators = append(result.Indicators, "polymorphic_pattern")
	}

	// Check for common attack vectors
	result.HasSQLInjection = e.detectSQLInjection(payload)
	if result.HasSQLInjection {
		result.Indicators = append(result.Indicators, "sql_injection")
	}

	result.HasXSS = e.detectXSS(payload)
	if result.HasXSS {
		result.Indicators = append(result.Indicators, "xss_attempt")
	}

	result.HasCommandInj = e.detectCommandInjection(payload)
	if result.HasCommandInj {
		result.Indicators = append(result.Indicators, "command_injection")
	}

	result.HasPathTraversal = e.detectPathTraversal(payload)
	if result.HasPathTraversal {
		result.Indicators = append(result.Indicators, "path_traversal")
	}

	// Calculate overall score
	result.Score = e.calculateScore(result)
	result.IsSuspicious = result.Score > 0.5

	return result
}

// calculateEntropy calculates Shannon entropy
func (e *Engine) calculateEntropy(data string) float64 {
	if len(data) == 0 {
		return 0
	}

	freq := make(map[rune]int)
	for _, char := range data {
		freq[char]++
	}

	var entropy float64
	length := float64(len(data))

	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// detectObfuscation detects obfuscation patterns
func (e *Engine) detectObfuscation(payload string) bool {
	indicators := []string{
		"eval(", "unescape(", "fromCharCode", "String.fromCharCode",
		"\\x", "\\u", "%u",
		"base64", "atob", "btoa",
		"innerHTML", "document.write",
		"setTimeout", "setInterval",
	}

	score := 0
	lower := strings.ToLower(payload)

	for _, indicator := range indicators {
		if strings.Contains(lower, indicator) {
			score++
		}
	}

	return score >= e.obfuscationScore
}

// detectPolymorphic detects polymorphic attack patterns
func (e *Engine) detectPolymorphic(payload string) bool {
	// Multiple encoding layers
	hasMultipleEncodings := strings.Contains(payload, "\\x") &&
		(strings.Contains(payload, "%") || strings.Contains(payload, "\\u"))

	// High entropy + multiple encodings
	entropy := e.calculateEntropy(payload)
	hasRandomPadding := len(payload) > 100 && entropy > 4.5

	// Excessive special characters
	specialCount := 0
	for _, char := range payload {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9')) {
			specialCount++
		}
	}
	specialRatio := float64(specialCount) / float64(len(payload))

	return hasMultipleEncodings || hasRandomPadding || specialRatio > 0.4
}

// detectSQLInjection detects SQL injection attempts
func (e *Engine) detectSQLInjection(payload string) bool {
	patterns := []string{
		`(?i)(union.*select|select.*from|insert.*into|delete.*from|drop.*table)`,
		`(?i)(or\s+1\s*=\s*1|and\s+1\s*=\s*1)`,
		`(?i)(exec\s*\(|execute\s*\()`,
		`;--`,
		`/\*.*\*/`,
	}

	for _, pattern := range patterns {
		matched, _ := regexp.MatchString(pattern, payload)
		if matched {
			return true
		}
	}

	return false
}

// detectXSS detects XSS attempts
func (e *Engine) detectXSS(payload string) bool {
	lower := strings.ToLower(payload)

	patterns := []string{
		"<script", "javascript:", "onerror=", "onload=",
		"onclick=", "onmouseover=", "<iframe", "<object",
		"<embed", "alert(", "prompt(", "confirm(",
	}

	for _, pattern := range patterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}

	return false
}

// detectCommandInjection detects command injection
func (e *Engine) detectCommandInjection(payload string) bool {
	patterns := []string{
		`[;&|]\s*\w+`,
		`\$\(`,
		"`",
		`>\s*/`,
		`<\s*/`,
	}

	for _, pattern := range patterns {
		matched, _ := regexp.MatchString(pattern, payload)
		if matched {
			return true
		}
	}

	return false
}

// detectPathTraversal detects path traversal attempts
func (e *Engine) detectPathTraversal(payload string) bool {
	patterns := []string{
		`\.\.\/`,
		`\.\.\\`,
		`%2e%2e/`,
		`%2e%2e\\`,
	}

	for _, pattern := range patterns {
		if strings.Contains(strings.ToLower(payload), strings.ToLower(pattern)) {
			return true
		}
	}

	return false
}

// calculateScore calculates overall heuristic score
func (e *Engine) calculateScore(result *Result) float64 {
	score := 0.0

	// Entropy contribution
	if result.Entropy > e.entropyThreshold {
		score += 0.2
	}

	// Obfuscation
	if result.HasObfuscation {
		score += 0.3
	}

	// Polymorphic
	if result.IsPolymorphic {
		score += 0.2
	}

	// Attack vectors
	if result.HasSQLInjection {
		score += 0.4
	}
	if result.HasXSS {
		score += 0.3
	}
	if result.HasCommandInj {
		score += 0.4
	}
	if result.HasPathTraversal {
		score += 0.3
	}

	// Cap at 1.0
	if score > 1.0 {
		score = 1.0
	}

	return score
}
