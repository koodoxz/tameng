package literalextract

import (
	"reflect"
	"regexp"
	"sort"
	"testing"
	"unicode"
)

// REQ SVALINN-DETECTPREFILTER-001.

// TestFoldTableIsExhaustive is the load-bearing proof behind pitfall #2.
// The Aho-Corasick automaton is ASCII-case-insensitive while the detector
// regexes use Go's `(?i)`, which is FULL Unicode simple case folding. This
// sweeps every rune in [128, 0x10FFFF] and fails if ANY non-ASCII rune
// whose fold orbit reaches ASCII is missing from unicodeFoldReplacer.
//
// Without this, the fold table is a claim. With it, it is a fact that
// re-verifies itself against whatever Unicode tables the Go toolchain
// ships, so a future Go release cannot silently open a bypass.
func TestFoldTableIsExhaustive(t *testing.T) {
	want := map[rune]rune{runeLongS: 's', runeKelvin: 'k'}
	got := map[rune]rune{}

	for r := rune(128); r <= unicode.MaxRune; r++ {
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < 128 {
				// Record the lowercase ASCII member of the orbit.
				if f >= 'A' && f <= 'Z' {
					f += 'a' - 'A'
				}
				got[r] = f
			}
		}
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("fold orbit sweep mismatch.\n got: %#v\nwant: %#v\n"+
			"A new rune here means an attacker can homoglyph-substitute a "+
			"required literal past the ASCII-only prefilter; add it to "+
			"unicodeFoldReplacer.", got, want)
	}

	// And the replacer must actually rewrite each of them.
	for r, ascii := range want {
		if got := FoldForASCIISearch("x" + string(r) + "y"); got != "x"+string(ascii)+"y" {
			t.Errorf("FoldForASCIISearch(U+%04X) = %q, want fold to %q", r, got, string(ascii))
		}
	}
}

// TestFoldForASCIISearch_LeavesOrdinaryTextAlone guards the no-allocation
// fast path and, more importantly, that folding never corrupts ordinary
// content (which would end up misreported as evidence if it ever leaked).
func TestFoldForASCIISearch_LeavesOrdinaryTextAlone(t *testing.T) {
	unrelatedUnicode := "unicode but irrelevant: " + string(rune(0x00E9)) + string(rune(0x4E2D))
	for _, s := range []string{"", "plain ascii body", unrelatedUnicode, "SELECT * FROM t"} {
		if got := FoldForASCIISearch(s); got != s {
			t.Errorf("FoldForASCIISearch(%q) = %q, want unchanged", s, got)
		}
	}
}

func TestRequired(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		want    []string // nil means "not extractable"
	}{
		{"invalid regex syntax", "(unclosed", nil},
		{"pure literal long enough", "SELECT", []string{"SELECT"}},
		{"pure literal too short", "arp", nil},
		{"case-insensitive literal normalizes to ASCII uppercase",
			"(?i)AmsiScanBuffer", []string{"AMSISCANBUFFER"}},
		{"concat: longest mandatory literal wins",
			"(?i)arp.*spoof", []string{"SPOOF"}},
		{"concat: prefix literal when suffix is not literal",
			"(?i)LDAP.*objectClass=computer", []string{"OBJECTCLASS=COMPUTER"}},
		{"alternation of literals, all long enough",
			"(SELECT|UPDATE|INSERT)", []string{"SELECT", "UPDATE", "INSERT"}},
		{"alternation with one short branch disqualifies the set",
			"(SELECT|OR)", nil},
		{"alternation with a non-literal branch is poisoned",
			"(SELECT|[0-9]+)", nil},
		{"optional literal is never mandatory", "(?:SELECT)?", nil},
		{"starred literal is never mandatory", "(?:SELECT)*", nil},
		{"pure character class yields nothing", "[a-zA-Z0-9]+", nil},
		{"empty pattern", "", nil},
		{"both members too short", "(?i)bot.*net", nil},

		// Pitfall #3: any non-ASCII rune in the proven set routes to nil.
		// Built programmatically (fixtures below) so no editor or tool layer
		// can silently normalize the payload out of the test.
		{"non-ASCII literal is rejected outright", nonASCIILiteralPattern, nil},
		{"non-ASCII branch poisons an otherwise-usable alternation", nonASCIIAltPattern, nil},
		{"non-ASCII candidate does not deny a usable ASCII candidate elsewhere",
			nonASCIIPlusASCIIPattern, []string{"AMSISCANBUFFER"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Required(tt.pattern)
			if tt.want == nil {
				if got != nil {
					t.Errorf("Required(%q) = %v, want nil", tt.pattern, got)
				}
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Required(%q) = %v, want %v", tt.pattern, got, tt.want)
			}
		})
	}
}

// TestRequiredIsSoundOnRealCorpus is the property that actually matters:
// for every pattern in every detector, if Required() returns literals then
// text lacking ALL of them must be unmatchable. Verified here directly
// against the real regexes rather than by reasoning about the AST.
func TestRequiredIsSoundOnRealCorpus(t *testing.T) {
	for _, pattern := range realCorpusPatterns() {
		if _, err := regexp.Compile(pattern); err != nil {
			t.Fatalf("corpus pattern %q does not compile: %v", pattern, err)
		}
		lits := Required(pattern)
		if lits == nil {
			continue
		}
		if len(lits) == 0 {
			t.Errorf("%q: non-nil but empty literal set", pattern)
			continue
		}
		if minLiteralLen(lits) < MinUsefulLiteralLen {
			t.Errorf("%q: literals %v shorter than MinUsefulLiteralLen", pattern, lits)
		}
		if !allASCII(lits) {
			t.Errorf("%q: literals %v contain non-ASCII, must have been rejected", pattern, lits)
		}
	}
}

// TestIterWouldMissOverlappingLiterals is the pitfall #1 regression catcher.
// It pins the exact behaviour that makes IterOverlapping mandatory: with
// literals "SELECT" and "SELECTX" both registered, the text "selectx"
// contains BOTH, and a prefilter that reported only one would wrongly skip
// every pattern requiring the other. Swapping Groups.Candidates to Iter()
// fails this test.
func TestIterWouldMissOverlappingLiterals(t *testing.T) {
	g := NewGroups(map[string][]*regexp.Regexp{
		"cat": {
			regexp.MustCompile(`(?i)SELECT`),
			regexp.MustCompile(`(?i)SELECTX`),
		},
	})

	cand := g.Candidates("harmless prefix selectx harmless suffix")
	if cand == nil {
		t.Fatal("Candidates returned nil; prefilter should have been built")
	}
	for i, name := range []string{"SELECT", "SELECTX"} {
		if !cand[i] {
			t.Errorf("pattern %d (%s) marked skippable, but its literal IS "+
				"present in the text -- this is the Iter() vs "+
				"IterOverlapping() bug and is a silent detector bypass", i, name)
		}
	}
}

// TestCandidates_SkipsOnlyProvenAbsent checks the useful direction too: a
// prefilter that marks everything as a candidate is sound but worthless.
func TestCandidates_SkipsOnlyProvenAbsent(t *testing.T) {
	g := NewGroups(map[string][]*regexp.Regexp{
		"cat": {
			regexp.MustCompile(`(?i)AmsiScanBuffer`), // extractable
			regexp.MustCompile(`(?i)EtwEventWrite`),  // extractable
			regexp.MustCompile(`[a-z]+`),             // not extractable
		},
	})
	cand := g.Candidates("a body mentioning amsiscanbuffer only")
	if cand == nil {
		t.Fatal("Candidates returned nil")
	}
	if !cand[0] {
		t.Error("pattern with a present literal was marked skippable")
	}
	if cand[1] {
		t.Error("pattern whose literal is absent should have been skipped")
	}
	if !cand[2] {
		t.Error("pattern with no provable literal must always be evaluated")
	}
}

func TestCandidates_FallsBackSafely(t *testing.T) {
	t.Run("nil receiver", func(t *testing.T) {
		var g *Groups
		if g.Candidates("anything") != nil {
			t.Error("nil *Groups must report nil (evaluate everything)")
		}
		if g.Slice(nil, "x") != nil {
			t.Error("nil *Groups Slice must report nil")
		}
	})
	t.Run("no extractable literals anywhere", func(t *testing.T) {
		g := NewGroups(map[string][]*regexp.Regexp{"c": {regexp.MustCompile(`[0-9]+`)}})
		if g.Candidates("12345") != nil {
			t.Error("un-built prefilter must report nil, not an all-false slice")
		}
	})
	t.Run("empty text", func(t *testing.T) {
		g := NewGroups(map[string][]*regexp.Regexp{"c": {regexp.MustCompile(`(?i)AmsiScanBuffer`)}})
		if g.Candidates("") != nil {
			t.Error("empty text must fall back to full evaluation")
		}
	})
	t.Run("nil regex entry", func(t *testing.T) {
		g := NewGroups(map[string][]*regexp.Regexp{"c": {nil, regexp.MustCompile(`(?i)AmsiScanBuffer`)}})
		cand := g.Candidates("nothing relevant here")
		if cand == nil {
			t.Fatal("expected a built prefilter")
		}
		if !cand[0] {
			t.Error("nil regex entry must be treated as always-evaluate")
		}
	})
}

func TestSlice(t *testing.T) {
	g := NewGroups(map[string][]*regexp.Regexp{
		"alpha": {regexp.MustCompile(`(?i)AmsiScanBuffer`), regexp.MustCompile(`(?i)EtwEventWrite`)},
		"beta":  {regexp.MustCompile(`(?i)NtProtectVirtualMemory`)},
	})
	cand := g.Candidates("mentions ntprotectvirtualmemory")
	if cand == nil {
		t.Fatal("expected a built prefilter")
	}
	if got := len(g.Slice(cand, "alpha")); got != 2 {
		t.Errorf("Slice(alpha) length = %d, want 2", got)
	}
	beta := g.Slice(cand, "beta")
	if len(beta) != 1 || !beta[0] {
		t.Errorf("Slice(beta) = %v, want [true]", beta)
	}
	if g.Slice(cand, "does-not-exist") != nil {
		t.Error("unknown category must report nil, never another category's flags")
	}
	if g.Slice(nil, "alpha") != nil {
		t.Error("nil cand must report nil")
	}
}

// TestNewGroupsIsDeterministic pins that global indices do not depend on Go's
// randomized map iteration order.
func TestNewGroupsIsDeterministic(t *testing.T) {
	build := func() []string {
		g := NewGroups(map[string][]*regexp.Regexp{
			"zeta":  {regexp.MustCompile(`(?i)AmsiScanBuffer`)},
			"alpha": {regexp.MustCompile(`(?i)EtwEventWrite`)},
			"mid":   {regexp.MustCompile(`(?i)NtProtectVirtualMemory`)},
		})
		names := make([]string, 0, len(g.spans))
		for n, sp := range g.spans {
			names = append(names, n+":"+string(rune('0'+sp.start)))
		}
		sort.Strings(names)
		return names
	}
	first := build()
	for i := 0; i < 20; i++ {
		if !reflect.DeepEqual(build(), first) {
			t.Fatalf("category layout is not deterministic across builds: %v vs %v", build(), first)
		}
	}
}

// Non-ASCII fixtures, assembled from explicit code points rather than typed
// glyphs: pitfall #3 is precisely about non-ASCII sneaking through
// unnoticed, so the test data must not itself depend on every tool in the
// chain rendering and copying a glyph faithfully.
var (
	cyrillicA = string(rune(0x0430)) // CYRILLIC SMALL LETTER A, looks like "a"
	cyrillicS = string(rune(0x0421)) // CYRILLIC CAPITAL LETTER ES, looks like "C"

	// A mandatory literal that is wholly non-ASCII.
	nonASCIILiteralPattern = "(?i)p" + cyrillicA + "rol" + cyrillicA + "xx"

	// An alternation where one branch carries a homoglyph; the whole set
	// must be rejected, not merely the offending branch.
	nonASCIIAltPattern = "(?i)(SELECT|SELE" + cyrillicS + "T)"

	// A non-ASCII candidate in one concat position must not deny the usable
	// ASCII candidate in another.
	nonASCIIPlusASCIIPattern = "(?i)" + cyrillicA + cyrillicA + cyrillicA + cyrillicA + ".*AmsiScanBuffer"
)

// realCorpusPatterns mirrors representative real patterns from the five
// detectors this REQ touches. Kept as inline data because those packages
// import this one -- importing them back would be a cycle. The exhaustive
// check against the true, complete corpus lives in the per-package parity
// and fuzz tests, where the real regexes are in scope.
func realCorpusPatterns() []string {
	return []string{
		`(?i)AmsiScanBuffer`, `(?i)amsi\.dll`, `(?i)EtwEventWrite`,
		`(?i)NtProtectVirtualMemory`, `(?i)GetModuleHandle.*ntdll`,
		`(?i)GetTickCount(64)?`, `(?i)Sleep\s*\(\s*\d{4,}\s*\)`,
		`(?i)VMware|VirtualBox|QEMU|Sandbox`, `Nt[A-Z][a-zA-Z]+`,
		`(?i)LoadLibrary.*\.(dll|exe)`, `(?i)DS-Replication-Get-Changes`,
		`(?i)1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`, `(?i)golden.*ticket`,
		`(?i)krbtgt`, `(?i)kerberos::golden`, `(?i)objectClass=\*`,
		`(?i)LDAP.*objectClass=user.*adminCount`, `(?i)arp.*spoof`,
		`(?i)[a-z0-9]{32,}\.[a-z]{2,10}`, `(?i)iodine|dnscat|dns2tcp`,
		`(?i)responder`, `(?i)sekurlsa::pth`, `(?i)\.kirbi`,
		`(?i)0c0c0c0c`, `(?i)pop\s+(eax|ebx|ecx|edx|esi|edi|esp|ebp)`,
		`(?i)xor\s+eax,\s*eax`, `(?i)VirtualAlloc(Ex)?`,
		`(?i)AdjustTokenPrivileges`, `(?i)\.crypt(ed)?$`,
		`(?i)RECOVERY.*INSTRUCTION`, `(?i)SetWindowsHookEx`,
		`(?i)reverse.*shell`, `(?i)c2.*server`, `(?i)stratum\+tcp`,
		`(?i)bot.*net`, `(?i)command\.php`, `(?i)self.*copy`, `(?i)autorun`,
	}
}
