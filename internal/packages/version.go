package packages

import "strings"

// CompareVersions orders two package versions the way dpkg and rpm mostly
// agree on: the epoch first ("2:" beats none), then runs of digits as
// numbers and other runs as text, with "~" before anything (a pre-release).
// It returns -1, 0 or 1.
func CompareVersions(a, b string) int {
	ea, ra := splitEpoch(a)
	eb, rb := splitEpoch(b)
	if c := compareSegment(ea, eb); c != 0 {
		return c
	}
	return compareSegment(ra, rb)
}

func splitEpoch(v string) (epoch, rest string) {
	if e, r, ok := strings.Cut(v, ":"); ok && e != "" && isDigits(e) {
		return e, r
	}
	return "0", v
}

func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

// order is dpkg's: "~" first, then the end of the string, then letters,
// then everything else.
func order(c byte, end bool) int {
	switch {
	case end:
		return 0
	case c == '~':
		return -1
	case isAlpha(c):
		return int(c)
	}
	return int(c) + 256
}

func compareSegment(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		// Text runs.
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			ca, cb := order(byteAt(a, i), i >= len(a)), order(byteAt(b, j), j >= len(b))
			if ca != cb {
				if ca < cb {
					return -1
				}
				return 1
			}
			i++
			j++
		}
		// Number runs.
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		si, sj := i, j
		for i < len(a) && isDigit(a[i]) {
			i++
		}
		for j < len(b) && isDigit(b[j]) {
			j++
		}
		na, nb := a[si:i], b[sj:j]
		if len(na) != len(nb) {
			if len(na) < len(nb) {
				return -1
			}
			return 1
		}
		if c := strings.Compare(na, nb); c != 0 {
			return c
		}
	}
	return 0
}

func byteAt(s string, i int) byte {
	if i < len(s) {
		return s[i]
	}
	return 0
}
