package literalextract

import "testing"

// Coverage for helper edge cases the real corpus never reaches.
// REQ SVALINN-DETECTPREFILTER-001.

func TestMinLiteralLen(t *testing.T) {
	tests := []struct {
		lits []string
		want int
	}{
		{nil, 0},
		{[]string{}, 0},
		{[]string{"a"}, 1},
		{[]string{"abc", "de", "fghij"}, 2},
		{[]string{"same", "size"}, 4},
	}
	for _, tt := range tests {
		if got := minLiteralLen(tt.lits); got != tt.want {
			t.Errorf("minLiteralLen(%v) = %d, want %d", tt.lits, got, tt.want)
		}
	}
}

func TestAllASCII(t *testing.T) {
	if !allASCII(nil) {
		t.Error("allASCII(nil) should be true (vacuously)")
	}
	if !allASCII([]string{"plain", "ascii"}) {
		t.Error("allASCII on pure ASCII should be true")
	}
	if allASCII([]string{"ok", "n" + string(rune(0x00F6))}) {
		t.Error("allASCII must reject a set containing any non-ASCII rune")
	}
	// Boundary: 0x7F is ASCII, 0x80 is not.
	if !allASCII([]string{string(rune(0x7F))}) {
		t.Error("U+007F is ASCII and must be accepted")
	}
	if allASCII([]string{string(rune(0x80))}) {
		t.Error("U+0080 is not ASCII and must be rejected")
	}
}
