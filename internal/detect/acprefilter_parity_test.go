package detect

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aegis/svalinn/internal/literalextract"
)

/*
REQ SVALINN-DETECTPREFILTER-001 -- differential parity tests.

The reference implementation is the detector with its prefilter disabled
(prefilter = nil), which reproduces the exact pre-REQ code path: every
pattern evaluated directly. Any input where prefilter-on and prefilter-off
disagree is a false negative (or false positive) introduced by this REQ.

These tests are the ones that must kill the three deliberate mutants:
  1. Iter() instead of IterOverlapping()   (overlapping literals dropped)
  2. no Unicode case fold before AC search (homoglyph bypass)
  3. no non-ASCII guard in extraction      (homoglyph bypass, other direction)
*/

// --- canonicalisation -------------------------------------------------
//
// Both the shuffled evaluation order (SVALINN-SCANBUDGET-001) and Go's
// randomized map iteration make raw result comparison meaningless, so
// results are reduced to an order-insensitive canonical form. Match COUNTS
// and match CONTENT are both preserved -- only ordering is normalized away.

func canonStrings(in []string) string {
	cp := append([]string(nil), in...)
	sort.Strings(cp)
	return strings.Join(cp, ",")
}

func canonEvidence(ev []map[string]any) string {
	parts := make([]string, 0, len(ev))
	for _, e := range ev {
		keys := make([]string, 0, len(e))
		for k := range e {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b strings.Builder
		for _, k := range keys {
			switch v := e[k].(type) {
			case []string:
				fmt.Fprintf(&b, "%s=[%s];", k, canonStrings(v))
			default:
				fmt.Fprintf(&b, "%s=%v;", k, v)
			}
		}
		parts = append(parts, b.String())
	}
	sort.Strings(parts)
	return strings.Join(parts, "|")
}

func canonEvasion(r *EvasionResult) string {
	return fmt.Sprintf("det=%v conf=%.6f tech=%s mitre=%s ev=%s",
		r.Detected, r.Confidence, canonStrings(r.Techniques), canonStrings(r.MitreIDs), canonEvidence(r.Evidence))
}

func canonAD(r *ADAttackResult) string {
	return fmt.Sprintf("det=%v conf=%.6f sev=%s atk=%s mitre=%s ev=%s",
		r.Detected, r.Confidence, r.Severity, canonStrings(r.Attacks), canonStrings(r.MitreIDs), canonEvidence(r.Evidence))
}

func canonNetwork(r *NetworkAttackResult) string {
	return fmt.Sprintf("det=%v conf=%.6f atk=%s mitre=%s ev=%s",
		r.Detected, r.Confidence, canonStrings(r.Attacks), canonStrings(r.MitreIDs), canonEvidence(r.Evidence))
}

func canonExploitation(r *ExploitationResult) string {
	return fmt.Sprintf("det=%v conf=%.6f types=%s mitre=%s ev=%s",
		r.Detected, r.Confidence, canonStrings(r.Types), canonStrings(r.MitreIDs), canonEvidence(r.Evidence))
}

// analyzeBothWays runs every touched detector twice over data -- once with
// the prefilter active, once with it disabled -- and returns (with, without)
// canonical results keyed by detector name. Fresh detectors each time so
// accumulated stats can never leak between the two runs.
func analyzeBothWays(data string) (map[string]string, map[string]string) {
	with := map[string]string{}
	without := map[string]string{}

	ev := NewEvasionDetector(EvasionConfig{Enabled: true})
	with["evasion"] = canonEvasion(ev.Analyze(data))
	ev2 := NewEvasionDetector(EvasionConfig{Enabled: true})
	ev2.prefilter = nil
	without["evasion"] = canonEvasion(ev2.Analyze(data))

	ad := NewADAttackDetector(ADAttackConfig{Enabled: true})
	with["ad_attack"] = canonAD(ad.Analyze(data))
	ad2 := NewADAttackDetector(ADAttackConfig{Enabled: true})
	ad2.prefilter = nil
	without["ad_attack"] = canonAD(ad2.Analyze(data))

	na := NewNetworkAttackDetector(NetworkAttackConfig{Enabled: true})
	with["network_attack"] = canonNetwork(na.Analyze(data))
	na2 := NewNetworkAttackDetector(NetworkAttackConfig{Enabled: true})
	na2.prefilter = nil
	without["network_attack"] = canonNetwork(na2.Analyze(data))

	ex := NewExploitationDetector(ExploitationConfig{Enabled: true})
	with["exploitation"] = canonExploitation(ex.Analyze(data))
	ex2 := NewExploitationDetector(ExploitationConfig{Enabled: true})
	ex2.prefilter = nil
	without["exploitation"] = canonExploitation(ex2.Analyze(data))

	return with, without
}

func assertParity(t *testing.T, label, data string) {
	t.Helper()
	with, without := analyzeBothWays(data)
	for name := range without {
		if with[name] != without[name] {
			t.Errorf("PREFILTER PARITY BREAK in %s [%s]\ninput:       %q\nwith filter: %s\nwithout:     %s",
				name, label, data, with[name], without[name])
		}
	}
}

// --- corpus -----------------------------------------------------------

// homoglyph builds a copy of s with every ASCII 's' replaced by U+017F and
// every 'k' by U+212A. Go's (?i) folds both back to ASCII, so the real
// regexes still match -- but an ASCII-only Aho-Corasick pass would not find
// the literal unless FoldForASCIISearch runs first. Constructed from code
// points, never typed glyphs.
func homoglyph(s string) string {
	r := strings.NewReplacer(
		"s", string(rune(0x017F)), "S", string(rune(0x017F)),
		"k", string(rune(0x212A)), "K", string(rune(0x212A)),
	)
	return r.Replace(s)
}

func parityCorpus() []struct{ name, data string } {
	base := []struct{ name, data string }{
		{"empty", ""},
		{"benign short", "hello world"},
		{"benign prose", strings.Repeat("the quick brown fox jumps over the lazy dog. ", 40)},
		{"amsi", "call to AmsiScanBuffer detected"},
		{"amsi lowercase", "call to amsiscanbuffer detected"},
		{"etw", "EtwEventWrite patched"},
		{"unhook", "NtProtectVirtualMemory then GetModuleHandle for ntdll"},
		{"sandbox", "IsDebuggerPresent and QueryPerformanceCounter and VMware"},
		{"syscall case sensitive", "NtCreateThreadEx NtAllocateVirtualMemory"},
		{"dcsync", "mimikatz lsadump::dcsync /domain"},
		{"golden ticket", "kerberos::golden krbtgt forged"},
		{"bloodhound", "Invoke-BloodHound and SharpHound collectors"},
		{"ldap", "ldapsearch objectClass=* servicePrincipalName=*"},
		{"arp", "arp spoof detected, gratuitous arp reply is-at"},
		{"dns tunnel", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com dnscat iodine"},
		{"smb relay", "ntlm relay via responder and impacket ntlmrelayx"},
		{"pth", "sekurlsa::pth mimikatz pass the hash"},
		{"kirbi", "ticket saved as ticket.kirbi"},
		{"heap spray", "0c0c0c0c0d0d0d0d41414141"},
		{"rop", "pop eax ; ret 0x10 ; jmp esp"},
		{"shellcode", "xor eax, eax then push 0x41414141"},
		{"injection", "VirtualAllocEx WriteProcessMemory CreateRemoteThread"},
		{"escalation", "AdjustTokenPrivileges SeDebugPrivilege"},
		{"mixed", "AmsiScanBuffer krbtgt arp spoof VirtualAlloc 0c0c0c0c"},
		{"overlap-ish", "syscall syscall stub sysenter"},
		{"punctuation soup", "!@#$%^&*()_+-=[]{}|;':\",./<>?"},
		{"nulls and controls", "a\x00b\x01c\x7f"},
	}

	out := make([]struct{ name, data string }, 0, len(base)*3)
	for _, c := range base {
		out = append(out, c)
		// Homoglyph variants: these are the inputs that catch a missing fold.
		out = append(out, struct{ name, data string }{c.name + " [homoglyph]", homoglyph(c.data)})
		// Embedded in benign filler, so position never matters.
		out = append(out, struct{ name, data string }{
			c.name + " [embedded]",
			strings.Repeat("filler ", 50) + c.data + strings.Repeat(" trailing", 50)})
	}
	return out
}

func TestACPrefilterParity_Corpus(t *testing.T) {
	for _, c := range parityCorpus() {
		assertParity(t, c.name, c.data)
	}
}

// TestACPrefilterParity_HomoglyphDetectionSurvives is the sharp end of
// pitfall #2, stated as a detection requirement rather than a parity one:
// the homoglyph payload MUST still be detected, not merely "detected the
// same way twice". If the fold is removed, the prefilter skips the AMSI
// patterns and this detector goes silent on a real evasion payload.
func TestACPrefilterParity_HomoglyphDetectionSurvives(t *testing.T) {
	payload := homoglyph("AmsiScanBuffer")

	// Sanity: the real regex genuinely matches the homoglyph payload, so a
	// miss really would be a bypass and not just an unmatched string.
	if !regexp.MustCompile(`(?i)AmsiScanBuffer`).MatchString(payload) {
		t.Fatalf("precondition failed: (?i)AmsiScanBuffer does not match %q", payload)
	}

	d := NewEvasionDetector(EvasionConfig{Enabled: true})
	got := d.Analyze(payload)
	if !got.Detected {
		t.Errorf("homoglyph AMSI payload %q went UNDETECTED with the prefilter "+
			"enabled -- this is a silent detector bypass (missing Unicode "+
			"case fold before the ASCII Aho-Corasick search)", payload)
	}
}

// TestACPrefilterParity_NonASCIILiteralPatternAlwaysEvaluated covers
// pitfall #3 at the integration level: a pattern whose required literal is
// non-ASCII must be routed to always-evaluate, never prefiltered against an
// ASCII-only automaton.
func TestACPrefilterParity_NonASCIILiteralPatternAlwaysEvaluated(t *testing.T) {
	cyr := string(rune(0x0430)) // CYRILLIC SMALL LETTER A
	pat := regexp.MustCompile("(?i)p" + cyr + "rol" + cyr + "xx")

	if lits := literalextract.Required(pat.String()); lits != nil {
		t.Fatalf("non-ASCII pattern yielded literals %v; guard did not fire", lits)
	}

	g := literalextract.NewGroups(map[string][]*regexp.Regexp{
		"c": {pat, regexp.MustCompile(`(?i)AmsiScanBuffer`)},
	})
	cand := g.Candidates("totally unrelated benign text")
	if cand == nil {
		t.Fatal("expected a built prefilter")
	}
	if !cand[0] {
		t.Error("pattern with a non-ASCII required literal must always be evaluated")
	}
}

// TestACPrefilterComposesWithScanBudget pins the SVALINN-SCANBUDGET-001
// interaction: an already-expired deadline must still yield no matches even
// with the prefilter marking patterns as candidates, i.e. the prefilter did
// not become a way to bypass the budget.
func TestACPrefilterComposesWithScanBudget(t *testing.T) {
	patterns := []*regexp.Regexp{regexp.MustCompile(`(?i)AmsiScanBuffer`)}
	cand := []bool{true}

	expired := time.Now().Add(-time.Second)
	if got := checkPatternsFilteredWithDeadline("AmsiScanBuffer", patterns, cand, expired); len(got) != 0 {
		t.Errorf("expired deadline still produced matches %v; budget bypassed", got)
	}

	// And a mismatched cand length must fail open to full evaluation.
	future := time.Now().Add(time.Minute)
	if got := checkPatternsFilteredWithDeadline("AmsiScanBuffer", patterns, []bool{false, false}, future); len(got) == 0 {
		t.Error("mismatched candidate slice must fail open to full evaluation, not skip everything")
	}

	// A candidate slice that says "skip" must actually skip.
	if got := checkPatternsFilteredWithDeadline("AmsiScanBuffer", patterns, []bool{false}, future); len(got) != 0 {
		t.Errorf("candidate=false should have skipped evaluation, got %v", got)
	}
}
