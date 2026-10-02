package detect

import "testing"

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"8.9p1", "8.5p1", 1},
		{"8.5p1", "8.9p1", -1},
		{"8.9p1", "8.9p1", 0},
		// Numeric components compare by value, not lexically.
		{"1.24.0", "1.9.0", 1},
		{"1.9.0", "1.24.0", -1},
		{"2.4.50", "2.4.49", 1},
		// A shorter version that is a prefix of a longer one is smaller.
		{"9.8", "9.8p1", -1},
		{"9.7p1", "9.8", -1},
		// A trailing letter sorts above the bare number.
		{"1.3.5", "1.3.5a", -1},
		// Distribution suffixes do not confuse the ordering.
		{"8.9p1-3ubuntu0.4", "8.5p1", 1},
		{"8.9p1-3ubuntu0.4", "9.8", -1},
		{"2.3.4", "2.3.4", 0},
		{"2.30", "2.9", 1},
	}
	for _, tc := range cases {
		if got := compareVersions(tc.a, tc.b); got != tc.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestParseAndSatisfyRange(t *testing.T) {
	cases := []struct {
		rangeSpec string
		version   string
		want      bool
	}{
		{">=8.5p1 <9.8", "8.9p1", true},
		{">=8.5p1 <9.8", "9.8", false},
		{">=8.5p1 <9.8", "9.9p1", false},
		{">=8.5p1 <9.8", "8.4", false},
		{">=8.5p1, <9.8", "8.9p1", true},
		{"==2.3.4", "2.3.4", true},
		{"==2.3.4", "2.3.5", false},
		{"2.3.4", "2.3.4", true},
		{"<9.8", "9.7", true},
		{"!=9.8", "9.7", true},
		{"!=9.8", "9.8", false},
		{">1.0", "", false},
		{">=8.5p1 <9.8", "8.9p1-3ubuntu0.4", true},
	}
	for _, tc := range cases {
		cons, err := parseVersionRange(tc.rangeSpec)
		if err != nil {
			t.Fatalf("parseVersionRange(%q): %v", tc.rangeSpec, err)
		}
		if got := satisfiesRange(tc.version, cons); got != tc.want {
			t.Errorf("satisfiesRange(%q, %q) = %v, want %v", tc.version, tc.rangeSpec, got, tc.want)
		}
	}
}

func TestParseVersionRangeRejectsJunk(t *testing.T) {
	for _, bad := range []string{"", "   ", ">=", ">= <9"} {
		if _, err := parseVersionRange(bad); err == nil {
			t.Errorf("parseVersionRange(%q) should fail", bad)
		}
	}
}

// TestVersionFollowingCheck is the capability the user asked for: a finding
// decided by comparing the version from a banner against a range, on a single
// probe with no protocol state.
func TestVersionFollowingCheck(t *testing.T) {
	db := NewDB()
	doc := `
apiVersion: argus.fingerprint/v1
id: versioned
rules:
  - id: ssh-version-range
    kind: check
    ports: [22]
    probes:
      - id: banner
        send: ""
        read_timeout: 2s
    matches:
      - id: affected
        pattern: 'SSH-2\.0-OpenSSH_'
        fields:
          version: '[Oo]penSSH_([0-9][^\s\r\n]*)'
        affected:
          range: ">=8.5p1 <9.8"
        finding:
          title: "OpenSSH in the affected range"
          severity: high
`
	if _, err := db.AddYAML([]byte(doc), "test"); err != nil {
		t.Fatal(err)
	}
	var rule *Rule
	for _, r := range db.Rules() {
		if r.ID == "ssh-version-range" {
			rule = r
		}
	}
	if rule == nil {
		t.Fatal("rule not loaded")
	}

	cases := []struct {
		banner string
		fires  bool
	}{
		{"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n", true},
		{"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n", true},
		{"SSH-2.0-OpenSSH_9.8\r\n", false},
		{"SSH-2.0-OpenSSH_9.9p1 Debian-3\r\n", false},
		{"SSH-2.0-OpenSSH_8.4p1 Raspbian-5\r\n", false},
		{"SSH-2.0-OpenSSH_7.4\r\n", false},
		// A banner with no version at all must not fire: an unknown version is
		// not evidence.
		{"SSH-2.0-OpenSSH_\r\n", false},
		{"220 ftp ready\r\n", false},
	}
	for _, tc := range cases {
		_, matched := matchRule(rule, []byte(tc.banner))
		if (matched != nil) != tc.fires {
			t.Errorf("banner %q: fired=%v, want %v", tc.banner, matched != nil, tc.fires)
		}
	}
}

func TestAffectedSchemaValidation(t *testing.T) {
	cases := map[string]string{
		"affected without a range": `
apiVersion: argus.fingerprint/v1
id: bad
rules:
  - id: r
    kind: check
    ports: [1]
    probes: [{id: p, send: ""}]
    matches:
      - id: m
        pattern: 'x'
        affected: {field: version}
        finding: {title: t}
`,
		"affected on an unknown field": `
apiVersion: argus.fingerprint/v1
id: bad
rules:
  - id: r
    kind: check
    ports: [1]
    probes: [{id: p, send: ""}]
    matches:
      - id: m
        pattern: 'x'
        affected: {field: produkt, range: ">1"}
        finding: {title: t}
`,
		"affected with a broken range": `
apiVersion: argus.fingerprint/v1
id: bad
rules:
  - id: r
    kind: check
    ports: [1]
    probes: [{id: p, send: ""}]
    matches:
      - id: m
        pattern: 'x'
        affected: {range: ">="}
        finding: {title: t}
`,
	}
	for name, doc := range cases {
		if _, err := NewDB().AddYAML([]byte(doc), "test"); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
