/*
Package waf implements the Web Application Firewall for SVALINN.

FULL SIGNATURE DATABASE - Migrated from Node.js SignatureEngine
Contains 200+ patterns across 17 categories
*/
package waf

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/koodoxz/tameng/internal/scanbudget"
	ahocorasick "github.com/petar-dambovaliev/aho-corasick"
)

// Severity levels
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
)

// Signature represents a WAF detection rule
type Signature struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Category string   `json:"category"`
	Severity string   `json:"severity"`
	Pattern  string   `json:"pattern"`
	Targets  []string `json:"targets"`
	Enabled  bool     `json:"enabled"`
	Score    float64  `json:"score"`
	MITRE    string   `json:"mitre,omitempty"`
	regex    *regexp.Regexp

	// requiredLiterals is populated in addSignature from requiredLiterals()
	// (literal_prefilter.go) -- non-nil only when a sound, sufficiently-
	// selective required literal set could be proven for Pattern. nil means
	// "no safe optimization available", not "no literals" -- Scan always
	// evaluates such a signature directly, exactly as before this REQ.
	// REQ SVALINN-WAFSCAN-ACPREFILTER-001.
	requiredLiterals []string
}

// bodyUnicodeFoldReplacer folds the two non-ASCII runes that Go's regexp
// (?i) full Unicode case folding treats as equivalent to an ASCII letter,
// down to that ASCII letter, before the ASCII-only Aho-Corasick body
// prefilter runs. Written with explicit \u escapes, not the literal glyphs,
// so the source itself can't be misread the same way an attacker's payload
// could be. REQ SVALINN-WAFSCAN-ACPREFILTER-001.
var bodyUnicodeFoldReplacer = strings.NewReplacer(
	"\u017F", "s", // LATIN SMALL LETTER LONG S, folds with s/S
	"\u212A", "k", // KELVIN SIGN, folds with k/K
)

// Match represents a signature match
type Match struct {
	Signature   *Signature
	Target      string
	MatchedText string
	Position    int
}

// ScanResult represents the WAF scan result
type ScanResult struct {
	Blocked    bool
	Score      float64
	Matches    []Match
	Categories map[string]int
	Severity   string
	Reason     string
}

// Engine is the WAF engine
type Engine struct {
	signatures     []*Signature
	byCategory     map[string][]*Signature
	byID           map[string]*Signature
	blockThreshold float64
	logThreshold   float64
	lock           sync.RWMutex

	// bodyAC is a combined Aho-Corasick automaton over every body-targeting
	// signature's requiredLiterals (deduplicated). When ready, Scan uses it
	// to skip evaluating a signature's "body" target only when NONE of that
	// signature's own required literals were found present anywhere in the
	// body -- sound by construction (requiredLiterals only returns
	// substrings proven necessary for a match), not a heuristic. Signatures
	// with no provably-required literal (requiredLiterals == nil, about a
	// quarter of the default set) are unaffected and always evaluated
	// directly, exactly as before this REQ. bodyACReady false means "not
	// built" (no useful literals in the current signature set, or nothing
	// loaded yet) -- Scan then always falls back to evaluating every
	// signature, the original, always-safe behavior.
	// REQ SVALINN-WAFSCAN-ACPREFILTER-001.
	//
	// queryAC/queryACPatterns/queryACReady are the exact same mechanism,
	// scoped to query-targeting signatures instead -- REQ
	// SVALINN-WAF-QUERYPREFILTER-001, filed as a follow-up once the query
	// target existed as a first-class scan target with its own decoded
	// fallback pass (SVALINN-WAF-QUERYDECODE-001). Built in the same pass
	// as bodyAC (see rebuildPrefilters) rather than a second locked loop
	// over e.signatures.
	bodyAC          ahocorasick.AhoCorasick
	bodyACPatterns  []string
	bodyACReady     bool
	queryAC         ahocorasick.AhoCorasick
	queryACPatterns []string
	queryACReady    bool
}

// rebuildPrefilters recompiles the combined body-literal and query-literal
// Aho-Corasick automatons from the current signature set's requiredLiterals,
// in one pass over e.signatures under one lock acquisition. Must be called
// once after any bulk change to e.signatures (initial load, Reload,
// LoadEvolvedRules) -- not per-signature, to avoid rebuilding on every
// single addSignature call.
func (e *Engine) rebuildPrefilters() {
	e.lock.Lock()
	defer e.lock.Unlock()

	bodyLitSet := make(map[string]struct{})
	queryLitSet := make(map[string]struct{})
	for _, sig := range e.signatures {
		if len(sig.requiredLiterals) == 0 {
			continue
		}
		isBody, isQuery := false, false
		for _, target := range sig.Targets {
			switch target {
			case "body":
				isBody = true
			case "query":
				isQuery = true
			}
		}
		if !isBody && !isQuery {
			continue
		}
		for _, lit := range sig.requiredLiterals {
			if isBody {
				bodyLitSet[lit] = struct{}{}
			}
			if isQuery {
				queryLitSet[lit] = struct{}{}
			}
		}
	}

	e.bodyAC, e.bodyACPatterns, e.bodyACReady = buildPrefilterAC(bodyLitSet)
	e.queryAC, e.queryACPatterns, e.queryACReady = buildPrefilterAC(queryLitSet)
}

// buildPrefilterAC builds one Aho-Corasick automaton from a literal set, or
// reports not-ready if the set is empty -- shared by rebuildPrefilters for
// both the body and query automatons, which are built identically.
func buildPrefilterAC(litSet map[string]struct{}) (ahocorasick.AhoCorasick, []string, bool) {
	if len(litSet) == 0 {
		return ahocorasick.AhoCorasick{}, nil, false
	}
	patterns := make([]string, 0, len(litSet))
	for lit := range litSet {
		patterns = append(patterns, lit)
	}
	builder := ahocorasick.NewAhoCorasickBuilder(ahocorasick.Opts{
		AsciiCaseInsensitive: true,
		MatchOnlyWholeWords:  false,
		MatchKind:            ahocorasick.StandardMatch,
	})
	return builder.Build(patterns), patterns, true
}

// collectACLiteralHits runs an Aho-Corasick automaton over content (after
// applying the same ſ/K homoglyph fold the prefilter has always needed --
// two ASCII letters ('s'/'S', 'k'/'K') whose Unicode simple case-folding
// orbit, used by the (?i)-compiled regexes, escapes ASCII, while this
// automaton is ASCII-case-insensitive only) and unions every matched
// literal into found. content is passed by value, so the fold never leaks
// into the caller's copy. Shared by the body and query literal-presence
// prefilters (REQ SVALINN-WAFSCAN-ACPREFILTER-001,
// SVALINN-WAF-QUERYPREFILTER-001), which apply identical logic to different
// content.
func collectACLiteralHits(ac ahocorasick.AhoCorasick, patterns []string, content string, found map[string]struct{}) {
	if strings.ContainsRune(content, 'ſ') || strings.ContainsRune(content, 'K') {
		content = bodyUnicodeFoldReplacer.Replace(content)
	}
	it := ac.IterOverlapping(content)
	for {
		m := it.Next()
		if m == nil {
			break
		}
		found[patterns[m.Pattern()]] = struct{}{}
	}
}

// NewEngine creates a new WAF engine with 200+ signatures
func NewEngine(signaturesPath string, blockThreshold, logThreshold float64) (*Engine, error) {
	e := &Engine{
		signatures:     make([]*Signature, 0),
		byCategory:     make(map[string][]*Signature),
		byID:           make(map[string]*Signature),
		blockThreshold: blockThreshold,
		logThreshold:   logThreshold,
	}

	if err := e.loadSignatures(signaturesPath); err != nil {
		e.loadDefaultSignatures()
	}
	e.rebuildPrefilters()

	return e, nil
}

func (e *Engine) loadSignatures(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var sigs []*Signature
	if err := json.Unmarshal(data, &sigs); err != nil {
		return err
	}
	for _, sig := range sigs {
		e.addSignature(sig)
	}
	return nil
}

func (e *Engine) addSignature(sig *Signature) error {
	if !sig.Enabled {
		return nil
	}
	regex, err := regexp.Compile("(?i)" + sig.Pattern)
	if err != nil {
		return err
	}
	sig.regex = regex
	sig.requiredLiterals = requiredLiterals(sig.Pattern)
	e.lock.Lock()
	defer e.lock.Unlock()
	e.signatures = append(e.signatures, sig)
	e.byID[sig.ID] = sig
	e.byCategory[sig.Category] = append(e.byCategory[sig.Category], sig)
	return nil
}

// signatureScanBudget bounds the wall-clock time a single Scan call may spend
// evaluating signatures (REQ SVALINN-SCANBUDGET-001): the AC-prefilter
// (SVALINN-WAFSCAN-ACPREFILTER-001) is fully defeated by an adaptive
// attacker who pads the body with every required literal, so this budget
// is the backstop that actually bounds worst-case cost regardless of
// whether the prefilter helps for a given request. ponytail: ceiling is
// 100ms, deliberately well above the ~3ms (benign) / ~15ms (adaptive-
// attacker-shaped) measured on dev hardware for an 8KiB body, to leave
// margin for the production VPS's independently-known ~6x slower
// single-thread throughput. Verify against real VPS timing before trusting
// further; lower only with real production benchmark data, not a guess.
const signatureScanBudget = 100 * time.Millisecond

// Scan checks request against all signatures
func (e *Engine) Scan(path, query, body string, headers map[string]string, userAgent string) *ScanResult {
	return e.scanWithDeadline(path, query, body, headers, userAgent, time.Now().Add(signatureScanBudget))
}

// scanWithDeadline is Scan's real implementation, taking an explicit
// deadline so tests can force the budget-exceeded path deterministically.
// Signature evaluation order is shuffled per call so a budget cutoff can't
// deterministically favor evading the same subset of signatures on every
// request (fail-open by design: signatures not reached before the deadline
// are simply not evaluated for this request, never blocked outright).
func (e *Engine) scanWithDeadline(path, query, body string, headers map[string]string, userAgent string, deadline time.Time) *ScanResult {
	e.lock.RLock()
	defer e.lock.RUnlock()

	result := &ScanResult{
		Matches:    make([]Match, 0),
		Categories: make(map[string]int),
	}

	targets := map[string]string{
		"path":       path,
		"query":      query,
		"body":       body,
		"user_agent": userAgent,
	}
	for k, v := range headers {
		targets["header_"+strings.ToLower(k)] = v
	}

	// Body literal-presence prefilter: a signature with a provably-required
	// literal set (sig.requiredLiterals != nil) can only be skipped for the
	// "body" target if NONE of its own required literals were found present
	// anywhere in body -- sound by construction, not a heuristic. Signatures
	// with requiredLiterals == nil are unaffected. REQ
	// SVALINN-WAFSCAN-ACPREFILTER-001.
	//
	// Case-fold mismatch guard: addSignature compiles each regex with a
	// bare "(?i)" prefix, which is Go's full Unicode simple case folding,
	// but bodyAC was built with AsciiCaseInsensitive (ASCII-only). Two
	// ASCII letters have fold orbits that escape ASCII -- 's'/'S' also
	// folds with U+017F (ſ, LATIN SMALL LETTER LONG S) and 'k'/'K' also
	// folds with U+212A (K, KELVIN SIGN). Left unhandled, an attacker can
	// homoglyph-substitute a required literal (e.g. "<ſcript>") so the
	// regex still matches but the ASCII-only AC scan does not, silently
	// skipping a signature that should have fired. Folding both runes down
	// before the AC search closes this without touching regex compilation
	// or the extraction logic.
	// REQ SVALINN-WAF-QUERYDECODE-001: query and (for urlencoded bodies)
	// body are the raw, undecoded values (middleware.go never decodes
	// either before calling Scan). No signature requiring `\s+` can ever
	// match the raw form -- Go's HTTP request-line parser rejects a
	// literal space or control byte in a URI before the app ever sees it,
	// so real multi-word SQL/RCE syntax only ever arrives '+'-encoded (the
	// standard application/x-www-form-urlencoded space); the same applies
	// to a urlencoded POST body. decodedQuery/decodedBody are computed
	// once, up front, and checked as a fallback only when a signature
	// misses on the raw form (see the match loop below) -- never
	// non-empty unless decoding was a true no-op, so a plain "" check is
	// enough to skip the fallback pass.
	//
	// Deliberately NO length cap on the decoded-query pass (Opus judge
	// review, REQ SVALINN-WAF-QUERYDECODE-001 follow-up): an earlier
	// version of this fix skipped decoding above 4096 bytes to bound scan
	// cost, but len(query) is attacker-controlled -- that cap was itself a
	// trivially attacker-toggled switch to disable detection entirely
	// (pad the query past 4KB with a harmless param and the real payload
	// goes unscanned). The existing 100ms signatureScanBudget already
	// bounds worst-case cost for exactly this reason and degrades
	// gracefully (fewer signatures reached within budget) rather than
	// off a cliff (zero decoded scanning). A bounded latency cost beats
	// an unbounded bypass. Body has no separate cap either, since
	// middleware.go's maxScannedBodyBytes (8KiB) already bounds it by
	// rejecting oversized bodies outright (413), not by silently skipping
	// detection -- that is the sound version of a size guard, and a real
	// query-side equivalent (414 Too Long, not silent skip) is a separate
	// REQ, not a gate on this one.
	decodedQuery := ""
	if query != "" {
		if dq := decodeQueryLenient(query); dq != query {
			decodedQuery = dq
		}
	}
	decodedBody := ""
	if isFormURLEncoded(targets["header_content-type"]) && body != "" {
		if db := decodeQueryLenient(body); db != body {
			decodedBody = db
		}
	}

	// Fold scoped to collectACLiteralHits's local copy only -- it must never
	// leak into targets["body"]/targets["query"], which are what the real
	// signature regexes below scan and what Match.MatchedText reports.
	// Folding the shared map entry would make the WAF report a
	// homoglyph-normalized string instead of the attacker's actual bytes.
	//
	// A required literal that only appears after decoding (e.g. "<script"
	// from "%3Cscript") must not be silently prefiltered away just because
	// the RAW content doesn't contain it -- union the decoded content's
	// literal hits into the same presence set so the match loop below
	// (which tries the decoded form as a fallback) is never blocked by the
	// prefilter from reaching a signature it would otherwise match.
	var bodyLiteralsFound map[string]struct{}
	if bodyContent, ok := targets["body"]; ok && bodyContent != "" && e.bodyACReady {
		bodyLiteralsFound = make(map[string]struct{})
		collectACLiteralHits(e.bodyAC, e.bodyACPatterns, bodyContent, bodyLiteralsFound)
		if decodedBody != "" {
			collectACLiteralHits(e.bodyAC, e.bodyACPatterns, decodedBody, bodyLiteralsFound)
		}
	}

	// queryLiteralsFound mirrors bodyLiteralsFound exactly, for the query
	// target's own Aho-Corasick prefilter -- REQ
	// SVALINN-WAF-QUERYPREFILTER-001.
	var queryLiteralsFound map[string]struct{}
	if queryContent, ok := targets["query"]; ok && queryContent != "" && e.queryACReady {
		queryLiteralsFound = make(map[string]struct{})
		collectACLiteralHits(e.queryAC, e.queryACPatterns, queryContent, queryLiteralsFound)
		if decodedQuery != "" {
			collectACLiteralHits(e.queryAC, e.queryACPatterns, decodedQuery, queryLiteralsFound)
		}
	}

	for _, si := range scanbudget.ShuffledIndices(len(e.signatures)) {
		if time.Now().After(deadline) {
			break
		}
		sig := e.signatures[si]
		for _, target := range sig.Targets {
			var literalsFound map[string]struct{}
			switch target {
			case "body":
				literalsFound = bodyLiteralsFound
			case "query":
				literalsFound = queryLiteralsFound
			}
			if literalsFound != nil && len(sig.requiredLiterals) > 0 {
				anyPresent := false
				for _, lit := range sig.requiredLiterals {
					if _, ok := literalsFound[lit]; ok {
						anyPresent = true
						break
					}
				}
				if !anyPresent {
					continue
				}
			}
			content, exists := targets[target]
			if !exists || content == "" {
				continue
			}
			matches := sig.regex.FindStringSubmatch(content)
			// Decoded query/body fallback: only on a raw-form miss (never
			// both -- would double-count and inflate scores, manufacturing
			// new false positives), and EVADE-006 (raw control-byte
			// detection) is deliberately excluded on both targets since
			// CRLF-001/003/004 and EVADE-005 already flag those bytes on
			// the raw percent-encoded form for CR/LF/NUL specifically
			// (declined coverage gain for other C0 bytes, not a regression
			// -- EVADE-006 could never fire on the raw undecoded form
			// anyway); re-enabling it here would add score-inflation risk
			// for no reachable-today detection loss.
			if matches == nil && sig.ID != "EVADE-006" {
				if target == "query" && decodedQuery != "" {
					matches = sig.regex.FindStringSubmatch(decodedQuery)
				} else if target == "body" && decodedBody != "" {
					matches = sig.regex.FindStringSubmatch(decodedBody)
				}
			}
			if matches != nil {
				result.Matches = append(result.Matches, Match{
					Signature:   sig,
					Target:      target,
					MatchedText: matches[0],
				})
				result.Score += sig.Score
				result.Categories[sig.Category]++
			}
		}
	}

	if len(result.Matches) > 0 {
		result.Severity = e.highestSeverity(result.Matches)
		result.Reason = result.Matches[0].Signature.Name
	}
	result.Blocked = result.Score >= e.blockThreshold
	return result
}

func (e *Engine) highestSeverity(matches []Match) string {
	order := map[string]int{SeverityCritical: 4, SeverityHigh: 3, SeverityMedium: 2, SeverityLow: 1}
	highest := SeverityLow
	for _, m := range matches {
		if order[m.Signature.Severity] > order[highest] {
			highest = m.Signature.Severity
		}
	}
	return highest
}

func (e *Engine) GetSignature(id string) *Signature     { return e.byID[id] }
func (e *Engine) GetByCategory(cat string) []*Signature { return e.byCategory[cat] }
func (e *Engine) Stats() map[string]int {
	stats := map[string]int{"total": len(e.signatures)}
	for cat, sigs := range e.byCategory {
		stats[cat] = len(sigs)
	}
	return stats
}

// loadDefaultSignatures loads ALL 200+ signatures from Node.js SignatureEngine
func (e *Engine) loadDefaultSignatures() {
	allTargets := []string{"path", "query", "body", "user_agent"}

	// REQ-SVALINN-WAF-HEADERTARGET-001: Inspect high-risk request headers for payload
	// injection categories (sqli, xss, rce, log4j) while excluding API tokens / SSRF to avoid FPs.
	headerTargets := []string{"header_cookie", "header_referer", "header_x-forwarded-for", "header_x-forwarded-host"}
	injectionTargets := append([]string{"path", "query", "body", "user_agent"}, headerTargets...)

	// REQ-SVALINN-WAF-SQLICOMMENT-001: SQL token separator matching whitespace and comments (/**/, --, #)
	sqlSep := `(?:\s|/\*.*?\*/|--[^\r\n]*(?:[\r\n]|$)|#[^\r\n]*(?:[\r\n]|$))+`

	// ═══════════════════════════════════════════════════════════════
	// SQL INJECTION (35 patterns)
	// ═══════════════════════════════════════════════════════════════
	sqli := []struct{ id, name, pattern string }{
		{"SQLI-001", "Classic OR/AND injection", `'\s*(OR|AND)\s+['"]?\d+['"]?\s*=\s*['"]?\d+`},
		{"SQLI-002", "String comparison injection", `'\s*(OR|AND)\s+['"]?[a-z]+['"]?\s*=\s*['"]?[a-z]+`},
		{"SQLI-003", "Stacked queries", `';\s*(DROP|DELETE|UPDATE|INSERT|ALTER|CREATE|TRUNCATE)`},
		{"SQLI-004", "UNION-based injection", `UNION` + sqlSep + `(?:(?:ALL|DISTINCT)` + sqlSep + `)?SELECT`},
		{"SQLI-005", "Comment termination", `'\s*--\s*$`},
		{"SQLI-006", "MySQL comment", `'\s*#\s*$`},
		{"SQLI-007", "Block comment", `'\s*/\*.*\*/`},
		{"SQLI-010", "Boolean-based blind", `'\s*AND\s+\d+\s*=\s*\d+`},
		{"SQLI-011", "Substring extraction", `'\s*AND\s+SUBSTRING\s*\(`},
		{"SQLI-012", "ASCII extraction", `'\s*AND\s+ASCII\s*\(`},
		{"SQLI-020", "MySQL SLEEP", `SLEEP\s*\(\s*\d+\s*\)`},
		{"SQLI-021", "MSSQL WAITFOR", `WAITFOR\s+DELAY`},
		{"SQLI-022", "MySQL BENCHMARK", `BENCHMARK\s*\(`},
		{"SQLI-023", "PostgreSQL pg_sleep", `PG_SLEEP\s*\(`},
		{"SQLI-030", "MySQL EXTRACTVALUE", `EXTRACTVALUE\s*\(`},
		{"SQLI-031", "MySQL UPDATEXML", `UPDATEXML\s*\(`},
		{"SQLI-040", "MySQL LOAD_FILE", `LOAD_FILE\s*\(`},
		{"SQLI-041", "MySQL file write", `INTO\s+(OUT|DUMP)FILE`},
		{"SQLI-043", "MSSQL xp_cmdshell", `XP_CMDSHELL`},
		{"SQLI-050", "MySQL version comment", `/\*!.*\*/`},
		{"SQLI-051", "CHAR() encoding", `CHAR\s*\(\s*\d+`},
		{"SQLI-052", "Hex encoding", `0x[0-9a-f]{10,}`},
		{"SQLI-053", "CONCAT hex", `CONCAT\s*\(\s*0x`},
		{"SQLI-060", "MongoDB $where", `\$where\s*:`},
		{"SQLI-061", "MongoDB $ne", `\$ne\s*:`},
		{"SQLI-062", "MongoDB $gt", `\$gt\s*:`},
		{"SQLI-063", "MongoDB $regex", `\$regex\s*:`},
	}
	for _, s := range sqli {
		e.addSignature(&Signature{ID: s.id, Name: s.name, Category: "sqli", Severity: SeverityCritical, Pattern: s.pattern, Targets: injectionTargets, Enabled: true, Score: 1.0, MITRE: "T1190"})
	}

	// ═══════════════════════════════════════════════════════════════
	// XSS (30 patterns)
	// ═══════════════════════════════════════════════════════════════
	xss := []struct{ id, name, pattern string }{
		{"XSS-001", "Script tag", `<script[^>]*>`},
		{"XSS-002", "Script close", `</script>`},
		{"XSS-003", "JavaScript protocol", `javascript\s*:`},
		{"XSS-004", "VBScript protocol", `vbscript\s*:`},
		{"XSS-005", "Data URI HTML", `data\s*:\s*text/html`},
		{"XSS-010", "Event handler", `\bon\w+\s*=`},
		{"XSS-011", "onerror", `onerror\s*=`},
		{"XSS-012", "onload", `onload\s*=`},
		{"XSS-013", "onclick", `onclick\s*=`},
		{"XSS-020", "IMG onerror", `<img[^>]+onerror`},
		{"XSS-021", "SVG onload", `<svg[^>]*onload`},
		{"XSS-022", "BODY onload", `<body[^>]*onload`},
		{"XSS-023", "IFRAME injection", `<iframe[^>]+src`},
		{"XSS-030", "HTML entity encoding", `&#x?[0-9a-f]+;`},
		{"XSS-031", "Unicode encoding", `\\u00[0-9a-f]{2}`},
		{"XSS-032", "URL encoded script", `%3c%2f?script`},
		{"XSS-040", "document.cookie", `document\.cookie`},
		{"XSS-041", "document.write", `document\.write`},
		{"XSS-042", "document.location", `document\.location`},
		{"XSS-043", "window.location", `window\.location`},
		{"XSS-044", "innerHTML", `\.innerHTML\s*=`},
		{"XSS-046", "eval()", `eval\s*\(`},
		{"XSS-047", "setTimeout string", `setTimeout\s*\(\s*['"\x60]`},
		{"XSS-048", "setInterval string", `setInterval\s*\(\s*['"\x60]`},
		{"XSS-049", "Function constructor", `new\s+Function\s*\(`},
		{"XSS-050", "CSS expression", `expression\s*\(`},
		{"XSS-051", "CSS url() javascript", `url\s*\(\s*javascript`},
	}
	for _, s := range xss {
		e.addSignature(&Signature{ID: s.id, Name: s.name, Category: "xss", Severity: SeverityHigh, Pattern: s.pattern, Targets: injectionTargets, Enabled: true, Score: 0.9, MITRE: "T1059.007"})
	}

	// ═══════════════════════════════════════════════════════════════
	// RCE (25 patterns)
	// ═══════════════════════════════════════════════════════════════
	rce := []struct{ id, name, pattern string }{
		{"RCE-001", "Command chaining", `;\s*(ls|dir|cat|type|whoami|id|pwd|uname)`},
		{"RCE-002", "Pipe command", `\|\s*(ls|dir|cat|type|whoami|id|pwd|uname)`},
		{"RCE-003", "Backtick execution", "`[^`]+`"},
		{"RCE-004", "Command substitution", `\$\([^)]+\)`},
		{"RCE-005", "AND chain", `&&\s*(ls|dir|cat|type|whoami|id|pwd)`},
		{"RCE-010", "Remote download", `\b(wget|curl)\s+[^\s]+`},
		{"RCE-011", "Netcat reverse shell", `\bnc\s+-[a-z]*\s+`},
		{"RCE-012", "Bash interactive", `\bbash\s+-[ic]`},
		{"RCE-013", "Shell path", `/bin/(sh|bash|dash|zsh)`},
		{"RCE-014", "Python exec", `\bpython[23]?\s+-c`},
		{"RCE-015", "Perl exec", `\bperl\s+-e`},
		{"RCE-016", "Ruby exec", `\bruby\s+-e`},
		{"RCE-017", "PHP exec", `\bphp\s+-r`},
		{"RCE-018", "Node.js exec", `\bnode\s+-e`},
		{"RCE-019", "PowerShell", `\bpowershell`},
		{"RCE-020", "Bash TCP device", `/dev/tcp/`},
		{"RCE-021", "Named pipe", `mkfifo`},
		{"RCE-030", "PHP serialized", `O:\d+:"[^"]+"`},
		{"RCE-031", "Java serialized", `rO0ABX`},
		{"RCE-032", "Python pickle", `__reduce__`},
		{"RCE-040", "Template expression", `\{\{\s*[^}]+\s*\}\}`},
		{"RCE-041", "Expression language", `\$\{[^}]+\}`},
		{"RCE-042", "Ruby expression", `#\{[^}]+\}`},
		{"RCE-044", "Spring EL", `\$\{T\(java`},
	}
	for _, s := range rce {
		e.addSignature(&Signature{ID: s.id, Name: s.name, Category: "rce", Severity: SeverityCritical, Pattern: s.pattern, Targets: injectionTargets, Enabled: true, Score: 1.0, MITRE: "T1059"})
	}

	// ═══════════════════════════════════════════════════════════════
	// PATH TRAVERSAL (20 patterns)
	// ═══════════════════════════════════════════════════════════════
	pathTraversal := []struct{ id, name, pattern string }{
		{"PATH-001", "Directory traversal", `\.\.[\\/]`},
		{"PATH-002", "URL encoded traversal", `\.\.%2[fF]`},
		{"PATH-003", "URL encoded backslash", `\.\.%5[cC]`},
		{"PATH-005", "Overlong UTF-8", `\.\.%c0%af`},
		{"PATH-007", "Double URL encoding", `\.\.%252[fF]`},
		{"PATH-010", "/etc/passwd", `/etc/passwd`},
		{"PATH-011", "/etc/shadow", `/etc/shadow`},
		{"PATH-012", "/etc/hosts", `/etc/hosts`},
		{"PATH-013", "/proc/self", `/proc/self`},
		{"PATH-014", "/var/log", `/var/log`},
		{"PATH-015", "SSH private key", `\.ssh/id_rsa`},
		{"PATH-016", "Bash history", `\.bash_history`},
		{"PATH-017", ".env file", `\.env`},
		{"PATH-018", ".git/config", `\.git/config`},
		{"PATH-020", "Windows win.ini", `win\.ini`},
		{"PATH-021", "Windows boot.ini", `boot\.ini`},
		{"PATH-030", "Null byte", `%00`},
		{"PATH-043", "PHP filter wrapper", `php://filter`},
		{"PATH-044", "PHP input wrapper", `php://input`},
		{"PATH-046", "PHAR wrapper", `phar://`},
	}
	for _, s := range pathTraversal {
		e.addSignature(&Signature{ID: s.id, Name: s.name, Category: "path_traversal", Severity: SeverityHigh, Pattern: s.pattern, Targets: []string{"path", "query"}, Enabled: true, Score: 0.9, MITRE: "T1083"})
	}

	// ═══════════════════════════════════════════════════════════════
	// XXE (10 patterns)
	// ═══════════════════════════════════════════════════════════════
	xxe := []struct{ id, name, pattern string }{
		{"XXE-001", "XML entity declaration", `<!DOCTYPE[^>]+ENTITY`},
		{"XXE-002", "External entity", `<!ENTITY\s+[^>]+SYSTEM`},
		{"XXE-003", "Public entity", `<!ENTITY\s+[^>]+PUBLIC`},
		{"XXE-004", "Parameter entity", `<!ENTITY\s+%\s+`},
		{"XXE-005", "File protocol", `SYSTEM\s+["']file:`},
		{"XXE-006", "HTTP entity", `SYSTEM\s+["']https?:`},
	}
	for _, s := range xxe {
		e.addSignature(&Signature{ID: s.id, Name: s.name, Category: "xxe", Severity: SeverityCritical, Pattern: s.pattern, Targets: []string{"body"}, Enabled: true, Score: 1.0, MITRE: "T1190"})
	}

	// ═══════════════════════════════════════════════════════════════
	// SSRF (15 patterns)
	// ═══════════════════════════════════════════════════════════════
	ssrf := []struct{ id, name, pattern string }{
		{"SSRF-001", "Localhost IP", `127\.0\.0\.1`},
		{"SSRF-003", "Localhost hostname", `localhost`},
		{"SSRF-004", "Link-local address", `169\.254\.`},
		{"SSRF-005", "GCP metadata", `metadata\.google`},
		{"SSRF-006", "AWS metadata", `169\.254\.169\.254`},
		{"SSRF-007", "IPv6 localhost", `\[::1\]`},
		{"SSRF-008", "Hex localhost", `0x7f000001`},
		{"SSRF-010", "File protocol", `file://`},
		{"SSRF-011", "Dict protocol", `dict://`},
		{"SSRF-012", "Gopher protocol", `gopher://`},
		{"SSRF-013", "FTP protocol", `ftp://`},
		{"SSRF-015", "Octal localhost", `0177\.0\.0\.1`},
	}
	for _, s := range ssrf {
		e.addSignature(&Signature{ID: s.id, Name: s.name, Category: "ssrf", Severity: SeverityHigh, Pattern: s.pattern, Targets: allTargets, Enabled: true, Score: 0.8, MITRE: "T1090"})
	}
	// REQ SVALINN-WAF-SSRF002-UAFP-001: SSRF-002 used to share allTargets
	// (including user_agent) with a bare `0\.0\.0\.0` pattern. Chrome/Chromium/
	// Edge's frozen UA version format ("Chrome/120.0.0.0") always contains
	// that literal substring, so this alone (score 0.8 == a common
	// block_threshold) 403'd ordinary browsers -- confirmed against 18 days
	// of shield.svalinn.id production logs (185/4426 blocked requests).
	// Fixed two ways: (1) the digit/dot boundary guard below stops matching
	// a trailing ".0.0.0" inside a larger version number like "120.0.0.0"
	// while still matching a real "0.0.0.0" (RE2 has no lookaround, so this
	// uses consuming character classes, not `(?<!...)`/`(?!...)` -- those
	// would fail regexp.Compile and addSignature would silently drop the
	// signature entirely, turning a false positive into a silent false
	// negative); (2) user_agent is dropped from this signature's targets,
	// since a real SSRF payload is attacker-controlled input the server
	// dereferences (path/query/body), not something that legitimately
	// appears in a client's own User-Agent string. Only a LEADING boundary
	// is enforced -- the Chrome FP is caused entirely by what precedes
	// "0.0.0.0" (the trailing "2" in "120"), so a trailing boundary buys no
	// FP reduction while losing real SSRF-bypass forms like the wildcard-DNS
	// technique "0.0.0.0.nip.io" or the trailing-dot FQDN "http://0.0.0.0./"
	// (Opus judge review, REQ SVALINN-WAF-SSRF002-UAFP-001 follow-up).
	e.addSignature(&Signature{ID: "SSRF-002", Name: "All interfaces", Category: "ssrf", Severity: SeverityHigh, Pattern: `(?:^|[^0-9.])0\.0\.0\.0`, Targets: []string{"path", "query", "body"}, Enabled: true, Score: 0.8, MITRE: "T1090"})

	// ═══════════════════════════════════════════════════════════════
	// CRLF/Header Injection (7 patterns)
	// ═══════════════════════════════════════════════════════════════
	crlf := []struct{ id, name, pattern string }{
		{"CRLF-001", "URL encoded CRLF", `%0[dD]%0[aA]`},
		{"CRLF-002", "CRLF sequence", `\r\n`},
		{"CRLF-003", "URL encoded LF", `%0[aA]`},
		{"CRLF-004", "URL encoded CR", `%0[dD]`},
		{"CRLF-006", "Cookie injection", `Set-Cookie:`},
		{"CRLF-007", "Location header", `Location:`},
	}
	for _, s := range crlf {
		e.addSignature(&Signature{ID: s.id, Name: s.name, Category: "crlf", Severity: SeverityMedium, Pattern: s.pattern, Targets: allTargets, Enabled: true, Score: 0.7, MITRE: "T1220"})
	}

	// ═══════════════════════════════════════════════════════════════
	// SCANNERS (20 patterns)
	// ═══════════════════════════════════════════════════════════════
	scanners := []struct{ id, name, pattern string }{
		{"SCAN-001", "SQLMap", `sqlmap`},
		{"SCAN-002", "Nikto", `nikto`},
		{"SCAN-003", "Nessus", `nessus`},
		{"SCAN-005", "Nmap", `nmap`},
		{"SCAN-006", "Masscan", `masscan`},
		{"SCAN-007", "OWASP ZAP", `zap`},
		{"SCAN-008", "Burp Suite", `burp`},
		{"SCAN-009", "Acunetix", `acunetix`},
		{"SCAN-011", "DirBuster", `dirbuster`},
		{"SCAN-012", "GoBuster", `gobuster`},
		{"SCAN-013", "FFUF", `ffuf`},
		{"SCAN-014", "WFuzz", `wfuzz`},
		{"SCAN-015", "Nuclei", `nuclei`},
		{"SCAN-017", "WPScan", `wpscan`},
		{"SCAN-019", "Hydra", `hydra`},
		{"SCAN-030", "Git disclosure", `\.git/HEAD`},
		{"SCAN-031", "SVN disclosure", `\.svn/entries`},
		{"SCAN-032", "htaccess probe", `\.htaccess`},
		{"SCAN-033", "WP config probe", `wp-config\.php`},
		{"SCAN-034", "PHPInfo probe", `phpinfo\(\)`},
	}
	for _, s := range scanners {
		e.addSignature(&Signature{ID: s.id, Name: s.name, Category: "scanner", Severity: SeverityMedium, Pattern: s.pattern, Targets: []string{"user_agent", "path"}, Enabled: true, Score: 0.5, MITRE: "T1046"})
	}

	// ═══════════════════════════════════════════════════════════════
	// LOG4J/LOG INJECTION (10 patterns)
	// ═══════════════════════════════════════════════════════════════
	log4j := []struct{ id, name, pattern string }{
		{"LOG-001", "JNDI lookup", `\$\{jndi:`},
		{"LOG-002", "Obfuscated JNDI", `\$\{j\$\{[^}]*\}ndi`},
		{"LOG-003", "Log4j lower", `\$\{lower:`},
		{"LOG-004", "Log4j upper", `\$\{upper:`},
		{"LOG-005", "Log4j env", `\$\{env:`},
		{"LOG-006", "Log4j sys", `\$\{sys:`},
		{"LOG-007", "Log4j base64", `\$\{base64:`},
		{"LOG-008", "Log4j date", `\$\{date:`},
		{"LOG-009", "LDAP protocol", `ldap://`},
		{"LOG-010", "RMI protocol", `rmi://`},
	}
	for _, s := range log4j {
		e.addSignature(&Signature{ID: s.id, Name: s.name, Category: "log4j", Severity: SeverityCritical, Pattern: s.pattern, Targets: injectionTargets, Enabled: true, Score: 1.0, MITRE: "T1190"})
	}

	// ═══════════════════════════════════════════════════════════════
	// PROTOTYPE POLLUTION (6 patterns)
	// ═══════════════════════════════════════════════════════════════
	proto := []struct{ id, name, pattern string }{
		{"PROTO-001", "__proto__ pollution", `__proto__`},
		{"PROTO-002", "Constructor pollution", `constructor\s*\[`},
		{"PROTO-003", "Prototype pollution", `prototype\s*\[`},
		{"PROTO-004", "Bracket __proto__", `\["__proto__"\]`},
		{"PROTO-005", "Bracket constructor", `\["constructor"\]`},
	}
	for _, s := range proto {
		e.addSignature(&Signature{ID: s.id, Name: s.name, Category: "prototype_pollution", Severity: SeverityHigh, Pattern: s.pattern, Targets: allTargets, Enabled: true, Score: 0.8, MITRE: "T1059"})
	}

	// ═══════════════════════════════════════════════════════════════
	// WAF BYPASS (7 patterns)
	// ═══════════════════════════════════════════════════════════════
	wafBypass := []struct{ id, name, pattern string }{
		{"WAFB-001", "Unicode normalization", `\\u(?:feff|0000|00a0)`},
		{"WAFB-004", "HTTP request smuggling", `Content-Length\s*:\s*\d+\s*\r?\n\s*Content-Length`},
		// REQ SVALINN-WAF-WAFB005-PLAINWORD-001: the old pattern
		// `s[e3]l[e3]c[t7]|u[n7][i1][o0]n` used character classes to detect
		// digit-substituted leetspeak, but a character class always matches
		// its own literal member too -- so plain "select"/"union" matched
		// this "leet speak evasion" signature despite containing no
		// obfuscation at all, defeating half its own purpose. Explicitly
		// enumerated below to every non-literal digit-substitution
		// combination (7 for "select", 7 for "union" -- 2^3 combinations
		// each, minus the all-literal spelling), so the plain English words
		// no longer match while every partial-or-full leetspeak form still
		// does. (?i) is applied to the whole pattern by addSignature, so
		// case variants like "S3LECT" still match without listing them here.
		{"WAFB-005", "Leet speak evasion", `(?:s3lect|sel3ct|selec7|s3l3ct|s3lec7|sel3c7|s3l3c7|u7ion|un1on|uni0n|u71on|u7i0n|un10n|u710n)`},
		{"WAFB-007", "Null byte extension bypass", `%00.*?\.(php|asp|jsp)`},
	}
	for _, s := range wafBypass {
		e.addSignature(&Signature{ID: s.id, Name: s.name, Category: "waf_bypass", Severity: SeverityHigh, Pattern: s.pattern, Targets: allTargets, Enabled: true, Score: 0.9, MITRE: "T1027"})
	}

	// ═══════════════════════════════════════════════════════════════
	// API ABUSE (6 patterns)
	// ═══════════════════════════════════════════════════════════════
	apiAbuse := []struct{ id, name, pattern string }{
		{"API-001", "GraphQL introspection", `(?:query|mutation)\s*\{\s*__schema`},
		{"API-002", "JWT token", `eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.`},
		{"API-003", "JWT algorithm none", `"alg"\s*:\s*"(?:none|None|NONE)"`},
		{"API-004", "Mass assignment", `(?:admin|role|isAdmin)\s*[=:]\s*(?:true|1|admin)`},
		{"API-005", "HTTP parameter pollution", `([&?])(\w+)=([^&]*)\&\2=`},
	}
	for _, s := range apiAbuse {
		e.addSignature(&Signature{ID: s.id, Name: s.name, Category: "api_abuse", Severity: SeverityHigh, Pattern: s.pattern, Targets: allTargets, Enabled: true, Score: 0.8, MITRE: "T1190"})
	}

	// ═══════════════════════════════════════════════════════════════
	// CLOUD/CONTAINER ATTACKS (12 patterns)
	// ═══════════════════════════════════════════════════════════════
	cloud := []struct{ id, name, pattern string }{
		{"CLOUD-001", "Cloud metadata SSRF", `169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com`},
		{"CLOUD-002", "Metadata header injection", `(?:X-Forwarded-For|Host)\s*:\s*169\.254\.\d+\.\d+`},
		{"CLOUD-003", "Kubernetes API abuse", `/api/v1/namespaces/.*/pods/.*/exec`},
		{"CLOUD-004", "K8s pod exec", `/api/v1/.*pods.*/(?:exec|portforward|attach)`},
		{"CLOUD-005", "Docker socket abuse", `/var/run/docker\.sock`},
		{"CLOUD-006", "Container escape attempt", `/proc/(?:\d+)/(?:root|mounts|cmdline)`},
		{"CLOUD-015", "kubectl command", `kubectl\s+(?:exec|cp|port-forward)`},
		{"CLOUD-016", "K8s exec API", `/api/v1/namespaces/.*/pods/.*/exec`},
		{"CLOUD-017", "ServiceAccount token", `serviceaccount.*token`},
	}
	for _, s := range cloud {
		e.addSignature(&Signature{ID: s.id, Name: s.name, Category: "cloud", Severity: SeverityCritical, Pattern: s.pattern, Targets: allTargets, Enabled: true, Score: 1.0, MITRE: "T1611"})
	}

	// ═══════════════════════════════════════════════════════════════
	// C2/EGRESS INDICATORS (5 patterns)
	// ═══════════════════════════════════════════════════════════════
	c2 := []struct{ id, name, pattern string }{
		{"C2-001", "Cloud C2 channel", `(?:hooks\.slack\.com|discord\.com/api/webhooks|api\.telegram\.org/bot)`},
		{"C2-003", "DNS over HTTPS C2", `/dns-query|application/dns-message|cloudflare-dns\.com/dns-query`},
		{"C2-004", "Dead drop resolver", `(?:pastebin\.com|gist\.githubusercontent\.com)/[a-zA-Z0-9]+`},
		{"C2-005", "Tunnel service C2", `ngrok\.io|localtunnel\.me|serveo\.net`},
	}
	for _, s := range c2 {
		e.addSignature(&Signature{ID: s.id, Name: s.name, Category: "c2", Severity: SeverityHigh, Pattern: s.pattern, Targets: allTargets, Enabled: true, Score: 0.9, MITRE: "T1071"})
	}

	// ═══════════════════════════════════════════════════════════════
	// ADVANCED EVASION (15 patterns)
	// ═══════════════════════════════════════════════════════════════
	evasion := []struct{ id, name, pattern string }{
		{"EVADE-001", "H2.CL Smuggling", `Content-Length:\s*0\s*[\r\n]+GET\s+/\w+\s+HTTP/1\.1`},
		{"EVADE-002", "H2.TE Smuggling", `Transfer-Encoding:\s*chunked\s*[\r\n]+0`},
		{"EVADE-005", "Encoded CRLF", `%0[dD]%0[aA]|\\r\\n`},
		{"EVADE-006", "Control character", `[\x00-\x1F]`},
		{"EVADE-007", "Unicode escape", `%u[0-9A-F]{4}`},
		{"EVADE-008", "Overlong UTF-8", `%c0%af|%e0%80%af`},
		{"EVADE-011", "CL-TE desync", `Content-Length:\s*\d+\s*\r?\n\s*Transfer-Encoding:\s*chunked`},
		{"EVADE-012", "TE-CL desync", `Transfer-Encoding:\s*chunked\s*\r?\n\s*Content-Length:\s*\d+`},
		{"EVADE-013", "IP rotation attempt", `X-Forwarded-For:\s*(?:\d{1,3}\.){3}\d{1,3}(?:\s*,\s*(?:\d{1,3}\.){3}\d{1,3}){3,}`},
		{"EVADE-019", "X-Real-IP spoofing", `X-Real-IP:\s*(?:\d{1,3}\.){3}\d{1,3}`},
		{"EVADE-021", "Automation tool", `selenium|webdriver|phantomjs|puppeteer|headless.*chrome`},
		{"EVADE-022", "Scripted client", `User-Agent:.*(?:curl|wget|python-requests|httpie)`},
	}
	for _, s := range evasion {
		e.addSignature(&Signature{ID: s.id, Name: s.name, Category: "evasion", Severity: SeverityCritical, Pattern: s.pattern, Targets: allTargets, Enabled: true, Score: 0.9, MITRE: "T1027"})
	}

	// ═══════════════════════════════════════════════════════════════
	// NEXT-GEN BYPASS (10 patterns)
	// ═══════════════════════════════════════════════════════════════
	nextGen := []struct{ id, name, pattern string }{
		{"NGBYP-002", "H2C upgrade smuggling", `Upgrade:\s*h2c`},
		{"NGBYP-004", "Duplicate Transfer-Encoding", `(Transfer-Encoding:\s*\w+\s*[\r\n]+){2,}`},
		{"NGBYP-005", "ES6 Unicode escape", `\\u\{[0-9A-Fa-f]{1,6}\}`},
		{"NGBYP-007", "Cyrillic homoglyph", `[\x{0400}-\x{04FF}].*(?:select|union|script)`},
		{"NGBYP-009", "Double URL encoding", `%25[0-9A-Fa-f]{2}`},
		{"NGBYP-011", "fromCharCode obfuscation", `String\.fromCharCode\s*\(\s*\d+(?:\s*,\s*\d+){3,}`},
		{"NGBYP-015", "EBCDIC charset abuse", `charset\s*=\s*(?:IBM037|cp037|ebcdic)`},
		{"NGBYP-017", "Comment-split keywords", `SEL/\*\*/ECT|UN/\*\*/ION`},
	}
	for _, s := range nextGen {
		e.addSignature(&Signature{ID: s.id, Name: s.name, Category: "next_gen_bypass", Severity: SeverityCritical, Pattern: s.pattern, Targets: allTargets, Enabled: true, Score: 0.95, MITRE: "T1027"})
	}

	// ═══════════════════════════════════════════════════════════════
	// SUPPLY CHAIN ATTACKS (8 patterns)
	// ═══════════════════════════════════════════════════════════════
	supplyChain := []struct{ id, name, pattern string }{
		{"SUPPLY-001", "Unpinned GitHub Action", `uses:\s*\w+/\w+@(?:main|master|HEAD)`},
		{"SUPPLY-002", "Secret exfil in workflow", `GITHUB_TOKEN.*curl.*-d|secrets\.\w+.*https?://`},
		{"SUPPLY-004", "Binary download Dockerfile", `curl\s+-[oO]\s*/(?:bin|usr/bin)/\w+\s+http`},
		{"SUPPLY-007", "Compromised CDN", `polyfill\.io|cdn\.polyfill\.io`},
		{"SUPPLY-008", "Base64 eval obfuscation", `eval\s*\(\s*atob\s*\(|btoa\s*\(.*eval`},
		{"SUPPLY-010", "Suspicious npm hook", `"(?:preinstall|postinstall)":\s*"(?:curl|wget|node\s+-e)`},
		{"SUPPLY-012", "Dangerous require", `require\s*\(\s*['"](?:child_process|fs|net)['"]\s*\).*(?:exec|spawn)`},
	}
	for _, s := range supplyChain {
		e.addSignature(&Signature{ID: s.id, Name: s.name, Category: "supply_chain", Severity: SeverityCritical, Pattern: s.pattern, Targets: allTargets, Enabled: true, Score: 1.0, MITRE: "T1195"})
	}

	// ═══════════════════════════════════════════════════════════════
	// AUTH BYPASS (7 patterns)
	// ═══════════════════════════════════════════════════════════════
	authBypass := []struct{ id, name, pattern string }{
		{"AUTH-001", "SQL admin bypass", `admin['"]?\s*--`},
		{"AUTH-002", "MySQL admin bypass", `admin'?\s*#`},
		{"AUTH-003", "Classic tautology", `'\s*or\s*'?1'?\s*=\s*'?1`},
		{"AUTH-004", "Empty string tautology", `'\s*or\s*''='`},
		{"AUTH-006", "Password tautology", `password\s*=\s*password`},
		{"AUTH-007", "Boolean bypass", `1'\s*or\s*'1'\s*=\s*'1`},
	}
	for _, s := range authBypass {
		e.addSignature(&Signature{ID: s.id, Name: s.name, Category: "auth_bypass", Severity: SeverityCritical, Pattern: s.pattern, Targets: allTargets, Enabled: true, Score: 1.0, MITRE: "T1110"})
	}
}

func (e *Engine) Reload(path string) error {
	e.lock.Lock()
	e.signatures = make([]*Signature, 0)
	e.byCategory = make(map[string][]*Signature)
	e.byID = make(map[string]*Signature)
	e.lock.Unlock()
	if err := e.loadSignatures(path); err != nil {
		e.loadDefaultSignatures()
		e.rebuildPrefilters()
		return err
	}
	e.rebuildPrefilters()
	return nil
}

// EvolvedRule represents a custom rule from evolved-rules.json
type EvolvedRule struct {
	RuleID      string `json:"rule_id"`
	Name        string `json:"name"`
	Pattern     string `json:"pattern"`
	MatchTarget string `json:"match_target"`
	Action      string `json:"action"`
	Score       int    `json:"score"`
	Rationale   string `json:"rationale"`
}

// LoadEvolvedRules loads custom rules from evolved-rules.json and adds them to the engine
func (e *Engine) LoadEvolvedRules(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}

	var rules []EvolvedRule
	if err := json.Unmarshal(data, &rules); err != nil {
		return 0, err
	}

	loaded := 0
	for _, rule := range rules {
		// Map match_target to WAF targets
		targets := []string{"path"}
		switch rule.MatchTarget {
		case "path":
			targets = []string{"path"}
		case "query":
			targets = []string{"query"}
		case "body":
			targets = []string{"body"}
		case "header":
			targets = []string{"user_agent"}
		case "all":
			targets = []string{"path", "query", "body", "user_agent"}
		}

		// Map action to severity
		severity := SeverityHigh
		if rule.Action == "BLOCK" {
			severity = SeverityCritical
		}

		sig := &Signature{
			ID:       "EVOL-" + rule.RuleID,
			Name:     rule.Name,
			Category: "evolved",
			Severity: severity,
			Pattern:  rule.Pattern,
			Targets:  targets,
			Enabled:  true,
			Score:    float64(rule.Score) / 100.0,
			MITRE:    "T1190",
		}

		if err := e.addSignature(sig); err == nil {
			loaded++
		}
	}
	e.rebuildPrefilters()

	return loaded, nil
}

// GetEvolvedRulesCount returns the number of evolved rules loaded
func (e *Engine) GetEvolvedRulesCount() int {
	e.lock.RLock()
	defer e.lock.RUnlock()
	return len(e.byCategory["evolved"])
}
