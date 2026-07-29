package detect

import "testing"

// REQ SVALINN-EVASION-NTPATTERN-FP-001
//
// The directSyscall category's generic Nt[A-Z][a-zA-Z]+ pattern was compiled
// with (?i), making it case-insensitive. Real Windows Nt*/Zw* syscall names
// always use exact PascalCase (NtWriteVirtualMemory, NtCreateThreadEx), so
// case-insensitivity only widened the pattern to match "nt" + any two letters
// anywhere, case-insensitive -- one of the most common trigrams in ordinary
// English and hostnames. An internal adversarial-testing tool's own honest,
// non-evasive self-identifying User-Agent ("ScanBot/1.0
// (+https://scanner.contoso.example; Security Research by Contoso Labs)")
// tripped this at confidence 90 (two matches: "ntoso" in "contoso.example"
// and again in "Contoso Labs", each worth the default SyscallThreshold of
// 45), even though the UA contains no real evasion technique.

func newTestEvasionDetector() *EvasionDetector {
	return NewEvasionDetector(EvasionConfig{Enabled: true})
}

func TestEvasionDetector_DoesNotFlagHonestScannerUserAgent(t *testing.T) {
	d := newTestEvasionDetector()

	ua := "ScanBot/1.0 (+https://scanner.contoso.example; Security Research by Contoso Labs)"
	result := d.Analyze(ua)

	if result.Detected {
		t.Errorf("Analyze(honest scanner UA) detected=true, techniques=%v, confidence=%v -- want no detection on this honest, non-evasive UA",
			result.Techniques, result.Confidence)
	}
}

func TestEvasionDetector_StillDetectsRealSyscallEvasion(t *testing.T) {
	d := newTestEvasionDetector()

	// A real, exact-case Nt* syscall name not covered by any of the other
	// literal patterns in the directSyscall category -- this is the
	// regression guard proving the fix doesn't just delete the whole check.
	payload := "shellcode calls NtUnmapViewOfSection to evade EDR hooks"
	result := d.Analyze(payload)

	if !result.Detected {
		t.Fatal("Analyze(real Nt* syscall payload) detected=false -- want detection preserved")
	}
	found := false
	for _, tech := range result.Techniques {
		if tech == "directSyscall" {
			found = true
		}
	}
	if !found {
		t.Errorf("techniques=%v, want \"directSyscall\" among them", result.Techniques)
	}
}

func TestEvasionDetector_StillDetectsKnownNamedSyscalls(t *testing.T) {
	d := newTestEvasionDetector()

	// The explicit literal patterns in directSyscall must be unaffected by
	// this fix -- only the generic wildcard sub-pattern changed.
	result := d.Analyze("NtAllocateVirtualMemory followed by NtCreateThreadEx")
	if !result.Detected {
		t.Fatal("known named Nt* syscalls no longer detected")
	}
}

func TestEvasionDetector_CommonEnglishWordsDoNotFalsePositive(t *testing.T) {
	d := newTestEvasionDetector()

	benign := []string{
		"want to continue browsing",
		"Content-Type: application/json",
		"planted a garden",
		"component library",
	}
	for _, s := range benign {
		if result := d.Analyze(s); result.Detected {
			t.Errorf("Analyze(%q) detected=true, techniques=%v -- want clean", s, result.Techniques)
		}
	}
}
