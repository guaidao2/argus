// Version comparison for version-following checks: OpenSSH below 9.8, vsftpd
// exactly 2.3.4, Apache httpd 2.4.49 or 2.4.50. A large share of real findings
// are "the version in the banner falls in this range", and a regular
// expression alone cannot express it.
//
// The comparison is deliberately shallow rather than a full semver
// implementation, because banners do not carry semver: they carry things like
// "8.9p1", "1.3.5a", "2.3.4-rc1" and "1.3.5-3ubuntu0.4".

package detect

import (
	"fmt"
	"strconv"
	"strings"
)

// versionOp is a comparison operator in an affected range.
type versionOp string

const (
	opLT versionOp = "<"
	opLE versionOp = "<="
	opGT versionOp = ">"
	opGE versionOp = ">="
	opEQ versionOp = "=="
	opNE versionOp = "!="
)

var versionOps = []versionOp{opLE, opGE, opNE, opLT, opGT, opEQ}

type versionConstraint struct {
	op      versionOp
	version string
}

// parseVersionRange parses an affected range such as ">=8.5p1 <9.8",
// "==2.3.4" or "1.3.5". Constraints are separated by spaces or commas and are
// combined with AND. A bare version means equality.
func parseVersionRange(spec string) ([]versionConstraint, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("empty version range")
	}
	var out []versionConstraint
	for _, part := range strings.FieldsFunc(spec, func(r rune) bool {
		return r == ' ' || r == ',' || r == '\t'
	}) {
		c := versionConstraint{op: opEQ}
		for _, op := range versionOps {
			if strings.HasPrefix(part, string(op)) {
				c.op = op
				part = strings.TrimSpace(strings.TrimPrefix(part, string(op)))
				break
			}
		}
		if part == "" {
			return nil, fmt.Errorf("version range %q has an operator without a version", spec)
		}
		c.version = part
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("version range %q is empty", spec)
	}
	return out, nil
}

// satisfiesRange reports whether a detected version falls in the range.
func satisfiesRange(version string, constraints []versionConstraint) bool {
	if version == "" {
		return false
	}
	for _, c := range constraints {
		cmp := compareVersions(version, c.version)
		ok := false
		switch c.op {
		case opLT:
			ok = cmp < 0
		case opLE:
			ok = cmp <= 0
		case opGT:
			ok = cmp > 0
		case opGE:
			ok = cmp >= 0
		case opEQ:
			ok = cmp == 0
		case opNE:
			ok = cmp != 0
		}
		if !ok {
			return false
		}
	}
	return true
}

// compareVersions orders two version strings, returning -1, 0 or 1.
//
// It splits each version into runs of digits and runs of letters, comparing
// digit runs numerically and letter runs lexically. Separators (dot, dash,
// underscore, plus) only delimit runs, so "8.9p1" becomes [8, 9, "p", 1] and
// compares as a person would read it. When one version runs out of components
// first and everything so far was equal, the shorter one is the smaller:
// "9.8" is below "9.8p1".
//
// This is not semver. "2.3.4-rc1" compares *above* "2.3.4" here, whereas semver
// says a pre-release is below its release. For a version-following check that
// difference only matters for pre-release banners, and the alternative -
// guessing which suffixes mean "not yet released" - introduces its own errors.
func compareVersions(a, b string) int {
	ta, tb := versionTokens(a), versionTokens(b)
	for i := 0; i < len(ta) && i < len(tb); i++ {
		ca, cb := ta[i], tb[i]
		if ca.num != nil && cb.num != nil {
			switch {
			case *ca.num < *cb.num:
				return -1
			case *ca.num > *cb.num:
				return 1
			}
			continue
		}
		// A numeric component outranks a textual one at the same position, so
		// "1.3.5" is below "1.3.5a".
		if ca.num != nil {
			return -1
		}
		if cb.num != nil {
			return 1
		}
		if ca.text != cb.text {
			if ca.text < cb.text {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(ta) < len(tb):
		return -1
	case len(ta) > len(tb):
		return 1
	}
	return 0
}

type versionToken struct {
	num  *int64
	text string
}

func versionTokens(v string) []versionToken {
	var out []versionToken
	runes := []rune(strings.TrimSpace(v))
	i := 0
	for i < len(runes) {
		r := runes[i]
		switch {
		case r >= '0' && r <= '9':
			j := i
			for j < len(runes) && runes[j] >= '0' && runes[j] <= '9' {
				j++
			}
			n, err := strconv.ParseInt(string(runes[i:j]), 10, 64)
			if err != nil {
				// A run too long for int64: fall back to comparing it as text
				// so an absurd build number cannot panic a scan.
				out = append(out, versionToken{text: string(runes[i:j])})
			} else {
				out = append(out, versionToken{num: &n})
			}
			i = j
		case isVersionLetter(r):
			j := i
			for j < len(runes) && isVersionLetter(runes[j]) {
				j++
			}
			out = append(out, versionToken{text: strings.ToLower(string(runes[i:j]))})
			i = j
		default:
			// Separators and anything else only delimit components.
			i++
		}
	}
	return out
}

func isVersionLetter(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}
