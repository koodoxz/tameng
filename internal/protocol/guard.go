/*
Package protocol implements protocol-level security for SVALINN.

Migrated from:
- request-smuggling.js
- http2-security.js
- websocket-guard.js
- graphql-protection.js
*/
package protocol

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
)

// ViolationType represents the type of protocol violation
type ViolationType string

const (
	ViolationRequestSmuggling  ViolationType = "request_smuggling"
	ViolationCRLFInjection     ViolationType = "crlf_injection"
	ViolationHTTP2Violation    ViolationType = "http2_violation"
	ViolationWebSocketAbuse    ViolationType = "websocket_abuse"
	ViolationGraphQLDepth      ViolationType = "graphql_depth"
	ViolationGraphQLComplexity ViolationType = "graphql_complexity"
	ViolationHeaderInjection   ViolationType = "header_injection"
)

// Violation represents a protocol security violation
type Violation struct {
	Type        ViolationType
	Severity    string
	Description string
	Details     map[string]interface{}
}

// Guard is the protocol security guard
type Guard struct {
	// GraphQL settings
	maxGraphQLDepth      int
	maxGraphQLComplexity int

	// WebSocket settings
	wsRateLimit int

	// Detection patterns
	smugglingPatterns []*regexp.Regexp
	crlfPatterns      []*regexp.Regexp

	// Stats. Plain int64 counters here previously raced under concurrent
	// CheckRequest calls from the HTTP middleware chain (REQ
	// SVALINN-PROTOCOL-GUARD-RACE-001) -- atomic.Int64 makes every
	// increment/read safe without a mutex, since the two counters have no
	// compound invariant between them that would need lock-step updates.
	violations      atomic.Int64
	requestsChecked atomic.Int64
}

// Config holds guard configuration
type Config struct {
	MaxGraphQLDepth      int
	MaxGraphQLComplexity int
	WSRateLimit          int
}

// NewGuard creates a new protocol guard
func NewGuard(cfg *Config) *Guard {
	g := &Guard{
		maxGraphQLDepth:      cfg.MaxGraphQLDepth,
		maxGraphQLComplexity: cfg.MaxGraphQLComplexity,
		wsRateLimit:          cfg.WSRateLimit,
	}

	if g.maxGraphQLDepth == 0 {
		g.maxGraphQLDepth = 10
	}
	if g.maxGraphQLComplexity == 0 {
		g.maxGraphQLComplexity = 1000
	}
	if g.wsRateLimit == 0 {
		g.wsRateLimit = 100
	}

	// Compile detection patterns
	g.compilePatterns()

	return g
}

// compilePatterns compiles regex patterns for detection
func (g *Guard) compilePatterns() {
	// Request smuggling patterns
	smugglingPatterns := []string{
		`(?i)content-length\s*:\s*\d+.*content-length\s*:\s*\d+`, // Duplicate CL
		`(?i)transfer-encoding\s*:\s*chunked.*content-length`,    // TE + CL
		`(?i)content-length.*transfer-encoding\s*:\s*chunked`,    // CL + TE
		`(?i)transfer-encoding\s*:\s*.*,\s*chunked`,              // TE obfuscation
		`(?i)transfer-encoding\s*:\s*chunked\s*,`,                // TE trailing comma
	}

	for _, pattern := range smugglingPatterns {
		if re, err := regexp.Compile(pattern); err == nil {
			g.smugglingPatterns = append(g.smugglingPatterns, re)
		}
	}

	// CRLF injection patterns
	crlfPatterns := []string{
		`%0[dD]%0[aA]`, // URL encoded CRLF
		`%0[dD]`,       // URL encoded CR
		`%0[aA]`,       // URL encoded LF
		`\r\n`,         // Raw CRLF
		`\r`,           // Raw CR
		`\n`,           // Raw LF
	}

	for _, pattern := range crlfPatterns {
		if re, err := regexp.Compile(pattern); err == nil {
			g.crlfPatterns = append(g.crlfPatterns, re)
		}
	}
}

// CheckRequest checks a request for protocol violations
func (g *Guard) CheckRequest(r *http.Request) []Violation {
	g.requestsChecked.Add(1)
	var violations []Violation

	// Check for request smuggling
	if v := g.checkRequestSmuggling(r); v != nil {
		violations = append(violations, *v)
	}

	// Check for CRLF injection
	if v := g.checkCRLFInjection(r); v != nil {
		violations = append(violations, *v)
	}

	// Check for header injection
	if v := g.checkHeaderInjection(r); v != nil {
		violations = append(violations, *v)
	}

	g.violations.Add(int64(len(violations)))
	return violations
}

// checkRequestSmuggling detects HTTP request smuggling attempts
func (g *Guard) checkRequestSmuggling(r *http.Request) *Violation {
	// Build header string for pattern matching
	var headerBuilder strings.Builder
	for name, values := range r.Header {
		for _, v := range values {
			headerBuilder.WriteString(name)
			headerBuilder.WriteString(": ")
			headerBuilder.WriteString(v)
			headerBuilder.WriteString("\n")
		}
	}
	headers := headerBuilder.String()

	// Check for smuggling patterns
	for _, pattern := range g.smugglingPatterns {
		if pattern.MatchString(headers) {
			return &Violation{
				Type:        ViolationRequestSmuggling,
				Severity:    "critical",
				Description: "Potential HTTP Request Smuggling detected",
				Details: map[string]interface{}{
					"pattern": pattern.String(),
				},
			}
		}
	}

	// Check for conflicting Content-Length headers
	clHeaders := r.Header["Content-Length"]
	if len(clHeaders) > 1 {
		// Multiple CL headers
		return &Violation{
			Type:        ViolationRequestSmuggling,
			Severity:    "critical",
			Description: "Multiple Content-Length headers detected",
			Details: map[string]interface{}{
				"content_lengths": clHeaders,
			},
		}
	}

	// Check CL vs actual body size mismatch (simplified)
	if len(clHeaders) == 1 && r.Body != nil {
		cl, err := strconv.ParseInt(clHeaders[0], 10, 64)
		if err == nil && cl > r.ContentLength && r.ContentLength > 0 {
			return &Violation{
				Type:        ViolationRequestSmuggling,
				Severity:    "high",
				Description: "Content-Length header exceeds actual body size",
				Details: map[string]interface{}{
					"header_cl": cl,
					"actual_cl": r.ContentLength,
				},
			}
		}
	}

	return nil
}

// checkCRLFInjection detects CRLF injection attempts
func (g *Guard) checkCRLFInjection(r *http.Request) *Violation {
	// Check URL path
	path := r.URL.Path + r.URL.RawQuery

	for _, pattern := range g.crlfPatterns {
		if pattern.MatchString(path) {
			return &Violation{
				Type:        ViolationCRLFInjection,
				Severity:    "high",
				Description: "CRLF Injection attempt detected in URL",
				Details: map[string]interface{}{
					"path": path,
				},
			}
		}
	}

	// Check headers for CRLF
	for name, values := range r.Header {
		for _, v := range values {
			for _, pattern := range g.crlfPatterns {
				if pattern.MatchString(v) {
					return &Violation{
						Type:        ViolationCRLFInjection,
						Severity:    "high",
						Description: "CRLF Injection attempt detected in header",
						Details: map[string]interface{}{
							"header": name,
						},
					}
				}
			}
		}
	}

	return nil
}

// checkHeaderInjection detects header injection attempts
func (g *Guard) checkHeaderInjection(r *http.Request) *Violation {
	dangerousHeaders := []string{
		"X-Forwarded-For",
		"X-Real-IP",
		"X-Forwarded-Host",
		"X-Forwarded-Proto",
		"Host",
	}

	for _, header := range dangerousHeaders {
		values := r.Header[header]
		if len(values) > 3 { // Suspicious number of same headers
			return &Violation{
				Type:        ViolationHeaderInjection,
				Severity:    "medium",
				Description: "Suspicious number of duplicate headers",
				Details: map[string]interface{}{
					"header": header,
					"count":  len(values),
				},
			}
		}
	}

	return nil
}

// CheckGraphQL checks a GraphQL query for abuse
func (g *Guard) CheckGraphQL(query string) []Violation {
	var violations []Violation

	// Check query depth
	depth := g.calculateGraphQLDepth(query)
	if depth > g.maxGraphQLDepth {
		violations = append(violations, Violation{
			Type:        ViolationGraphQLDepth,
			Severity:    "medium",
			Description: "GraphQL query exceeds maximum depth",
			Details: map[string]interface{}{
				"depth":     depth,
				"max_depth": g.maxGraphQLDepth,
			},
		})
	}

	// Check query complexity (simplified)
	complexity := g.calculateGraphQLComplexity(query)
	if complexity > g.maxGraphQLComplexity {
		violations = append(violations, Violation{
			Type:        ViolationGraphQLComplexity,
			Severity:    "medium",
			Description: "GraphQL query exceeds maximum complexity",
			Details: map[string]interface{}{
				"complexity":     complexity,
				"max_complexity": g.maxGraphQLComplexity,
			},
		})
	}

	return violations
}

// calculateGraphQLDepth calculates the nesting depth of a GraphQL query
func (g *Guard) calculateGraphQLDepth(query string) int {
	maxDepth := 0
	currentDepth := 0

	for _, char := range query {
		if char == '{' {
			currentDepth++
			if currentDepth > maxDepth {
				maxDepth = currentDepth
			}
		} else if char == '}' {
			currentDepth--
		}
	}

	return maxDepth
}

// calculateGraphQLComplexity estimates query complexity
func (g *Guard) calculateGraphQLComplexity(query string) int {
	// Simplified: count field selections
	complexity := strings.Count(query, "{") * 10
	complexity += strings.Count(query, "(") * 5 // Arguments
	complexity += len(query) / 10               // Size factor
	return complexity
}

// Stats returns guard statistics
func (g *Guard) Stats() map[string]interface{} {
	return map[string]interface{}{
		"requests_checked": g.requestsChecked.Load(),
		"violations":       g.violations.Load(),
	}
}
