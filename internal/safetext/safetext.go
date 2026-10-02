// Package safetext cleans strings that arrived over the network before they
// reach a terminal.
//
// A scanned service is untrusted input. It can put ANSI escape sequences in its
// banner, in a TLS certificate subject, or in a PTR record, and the normal
// report prints those bytes straight to the operator's terminal, where they
// move the cursor, recolour output, clear the screen or overwrite lines that
// were already printed. Wrapping every network-derived field through Sanitize
// closes that off.
package safetext

import "strings"

// Sanitize removes control characters from s.
//
// Horizontal tabs survive because they are harmless and appear in real banners.
// Everything else in the C0 range, DEL and the C1 range goes: those are what an
// escape sequence is built from. Valid UTF-8 beyond that is left alone, so a
// service that answers in Chinese or with an emoji still reads correctly, and
// invalid UTF-8 is replaced by the decoder's U+FFFD rather than passed through.
func Sanitize(s string) string {
	if isClean(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if isControl(r) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// isClean reports whether s needs no work, which is the common case: most
// fields a scan produces are plain ASCII.
func isClean(s string) bool {
	for _, r := range s {
		if isControl(r) {
			return false
		}
	}
	return true
}

func isControl(r rune) bool {
	switch {
	case r == '\t':
		return false
	case r < 0x20, r == 0x7f: // C0 controls and DEL: ESC, CR, NUL, backspace
		return true
	case r >= 0x80 && r <= 0x9f: // C1 controls: CSI is 0x9B
		return true
	}
	return false
}
