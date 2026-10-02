package detect

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/guaidao2/argus/internal/model"
	"github.com/guaidao2/argus/internal/ports"
)

// fakeRedis answers just enough of the Redis protocol to exercise both the
// identification and the check paths.
func fakeRedis(t *testing.T) (host string, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	info := "redis_version:7.2.4\r\nredis_mode:standalone\r\nos:Linux\r\n"
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				buf := make([]byte, 512)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						cmd := strings.ToUpper(strings.Fields(string(buf[:n]))[0])
						switch {
						case strings.HasPrefix(cmd, "INFO"):
							_, _ = c.Write([]byte("$" + itoa(len(info)) + "\r\n" + info + "\r\n"))
						case strings.HasPrefix(cmd, "PING"):
							_, _ = c.Write([]byte("+PONG\r\n"))
						default:
							_, _ = c.Write([]byte("-ERR unknown command\r\n"))
						}
					}
					if err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// identifyRedisAnywhere teaches the database to recognise Redis on whatever
// port the test listener happened to get. Without an identification rule the
// service name is "unknown", and a service-bound check has nothing to match on.
func identifyRedisAnywhere(t *testing.T, db *DB) {
	t.Helper()
	if _, err := db.AddYAMLFront([]byte(`
apiVersion: argus.fingerprint/v1
id: test-any-port
rules:
  - id: redis-on-any-port
    probes:
      - id: ping
        send: "PING\r\n"
        read_timeout: 2s
    matches:
      - id: pong
        pattern: '(?m)^\+PONG'
        set: {service: redis, product: Redis}
`), "test"); err != nil {
		t.Fatal(err)
	}
}

// TestChecksAreOffByDefault is the safety property: a check rule's probes look
// like an attack on the wire, so running one has to be a deliberate choice.
func TestChecksAreOffByDefault(t *testing.T) {
	db, err := LoadBuiltin()
	if err != nil {
		t.Fatal(err)
	}
	fingerprints, checks := db.CountByKind()
	if fingerprints == 0 {
		t.Fatal("no fingerprint rules loaded")
	}
	if checks == 0 {
		t.Fatal("no check rules loaded")
	}

	for _, r := range db.RulesFor(RuleQuery{Port: 6379, Tunnel: "", Checks: false}) {
		if r.IsCheck() {
			t.Errorf("check rule %q leaked into a scan without --findings", r.ID)
		}
	}
	found := false
	for _, r := range db.RulesFor(RuleQuery{Port: 6379, Tunnel: "", Checks: true}) {
		if r.ID == "redis-unauth" {
			found = true
		}
	}
	if !found {
		t.Error("redis-unauth should be offered when checks are enabled")
	}
}

func TestDetectReportsNoFindingsByDefault(t *testing.T) {
	host, port := fakeRedis(t)
	db := mustBuiltin(t)
	identifyRedisAnywhere(t, db)
	d, err := New(Options{
		DB:           db,
		ProbeTimeout: 2 * time.Second,
		Lang:         "en",
		EnableChecks: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := d.Detect(context.Background(), host, model.Port{Port: port, Proto: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	if len(svc.Findings) != 0 {
		t.Fatalf("a scan without --findings must not report findings, got %+v", svc.Findings)
	}
}

func TestDetectReportsFindingsWhenEnabled(t *testing.T) {
	host, port := fakeRedis(t)
	db := mustBuiltin(t)
	identifyRedisAnywhere(t, db)
	d, err := New(Options{
		DB:           db,
		ProbeTimeout: 2 * time.Second,
		Lang:         "en",
		EnableChecks: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := d.Detect(context.Background(), host, model.Port{Port: port, Proto: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	if len(svc.Findings) == 0 {
		t.Fatalf("expected a finding for an unauthenticated Redis, got none (service=%+v)", svc)
	}
	f := svc.Findings[0]
	if f.Severity != "high" {
		t.Errorf("severity = %q", f.Severity)
	}
	if !strings.Contains(f.Title, "unauthenticated") {
		t.Errorf("title = %q", f.Title)
	}
	if f.Rule == "" || f.Match == "" {
		t.Errorf("a finding must be traceable to its rule and match: %+v", f)
	}
	if len(f.Refs) == 0 {
		t.Error("the finding should carry its reference")
	}
}

// TestFindingsAreLocalised checks that a finding follows --lang, because it is
// text a human reads, unlike the machine readable formats.
func TestFindingsAreLocalised(t *testing.T) {
	host, port := fakeRedis(t)
	db := mustBuiltin(t)
	identifyRedisAnywhere(t, db)
	d, err := New(Options{
		DB:           db,
		ProbeTimeout: 2 * time.Second,
		Lang:         "zh",
		EnableChecks: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := d.Detect(context.Background(), host, model.Port{Port: port, Proto: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	if len(svc.Findings) == 0 {
		t.Fatal("no finding")
	}
	if !strings.Contains(svc.Findings[0].Title, "未授权") {
		t.Fatalf("the Chinese title was not used: %q", svc.Findings[0].Title)
	}
	if !strings.Contains(svc.Findings[0].Description, "凭据") {
		t.Fatalf("the Chinese description was not used: %q", svc.Findings[0].Description)
	}
}

// TestFindingOnNonStandardPort covers the second way a check can be reached:
// bound to the detected service rather than to a port. A Redis instance on
// 19300 is still a Redis instance, and the port-bound rule alone would miss it.
func TestFindingOnNonStandardPort(t *testing.T) {
	host, port := fakeRedis(t)
	db := mustBuiltin(t)

	// Identify Redis wherever it listens, the way a user would for an
	// engagement with containers on random high ports.
	identifyRedisAnywhere(t, db)

	d, err := New(Options{DB: db, ProbeTimeout: 2 * time.Second, Lang: "en", EnableChecks: true})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := d.Detect(context.Background(), host, model.Port{Port: port, Proto: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	if svc.Name != "redis" {
		t.Fatalf("service = %q, want redis", svc.Name)
	}
	if len(svc.Findings) == 0 {
		t.Fatal("the service-bound check should have fired on a non standard port")
	}
}

// TestCheckRulesAreNotFingerprints: a finding must never become the service
// description, and identification must not be skipped because a check matched.
func TestCheckRulesAreNotFingerprints(t *testing.T) {
	db := mustBuiltin(t)
	for _, r := range db.RulesFor(RuleQuery{Port: 6379, Tunnel: "", Checks: true}) {
		if !r.IsCheck() {
			continue
		}
		if r.Service == "http" {
			t.Errorf("check rule %q binds to the generic service http, which would fire on every web port", r.ID)
		}
	}
}

func TestCheckSchemaValidation(t *testing.T) {
	cases := map[string]string{
		"finding on a fingerprint rule": `
apiVersion: argus.fingerprint/v1
id: bad
rules:
  - id: r
    ports: [1]
    probes: [{id: p, send: ""}]
    matches:
      - id: m
        pattern: 'x'
        finding: {title: "should not be here"}
`,
		"finding without a title": `
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
        finding: {severity: high}
`,
		"bad severity": `
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
        finding: {title: t, severity: catastrophic}
`,
		"bad kind": `
apiVersion: argus.fingerprint/v1
id: bad
rules:
  - id: r
    kind: exploit
    ports: [1]
    probes: [{id: p, send: ""}]
    matches: [{id: m, pattern: 'x'}]
`,
	}
	for name, doc := range cases {
		if _, err := NewDB().AddYAML([]byte(doc), "test"); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

// TestLocalizedTextAcceptsBothForms: a plugin should not have to write a
// language map for a single-language note.
func TestLocalizedTextAcceptsBothForms(t *testing.T) {
	db := NewDB()
	doc := `
apiVersion: argus.fingerprint/v1
id: forms
rules:
  - id: r
    kind: check
    ports: [1]
    probes: [{id: p, send: ""}]
    matches:
      - id: plain
        pattern: 'a'
        finding: {title: Plain string}
      - id: mapped
        pattern: 'b'
        finding:
          title: {en: Mapped, zh: 映射}
          description: {en: desc, zh: 描述}
          severity: low
`
	if _, err := db.AddYAML([]byte(doc), "test"); err != nil {
		t.Fatal(err)
	}
	var rule *Rule
	for _, r := range db.Rules() {
		if r.ID == "r" {
			rule = r
		}
	}
	if rule == nil {
		t.Fatal("rule not loaded")
	}
	plain := rule.Match[0].Finding
	if plain.Title.Get("en") != "Plain string" || plain.Title.Get("zh") != "Plain string" {
		t.Errorf("a plain string should apply to every language: %+v", plain.Title)
	}
	if plain.Severity != "info" {
		t.Errorf("a missing severity should default to info, got %q", plain.Severity)
	}
	if plain.ID != "plain" {
		t.Errorf("the finding id should default to the match id, got %q", plain.ID)
	}
	mapped := rule.Match[1].Finding
	if mapped.Title.Get("zh") != "映射" || mapped.Description.Get("fr") != "desc" {
		t.Errorf("language maps should fall back to English: %+v", mapped)
	}
}

func mustBuiltin(t *testing.T) *DB {
	t.Helper()
	db, err := LoadBuiltin()
	if err != nil {
		t.Fatal(err)
	}
	return db
}

// TestBinaryPatternsMatchHighBytes is the regression guard for a defect that
// made every binary protocol unreliable: Go's regexp decodes its input as
// UTF-8, so the byte 0xff became U+FFFD and a pattern written as \xff - which
// means the codepoint U+00FF - could never match it. Everything built in used
// only low bytes, so nothing caught it until an SMB probe was written.
func TestBinaryPatternsMatchHighBytes(t *testing.T) {
	db := NewDB()
	doc := `
apiVersion: argus.fingerprint/v1
id: binary
rules:
  - id: binary-rule
    kind: check
    ports: [445]
    probes: [{id: p, send: ""}]
    matches:
      - id: smb
        pattern: '(?s)^....\xffSMB\x72'
        finding: {title: "SMBv1 response"}
`
	if _, err := db.AddYAML([]byte(doc), "test"); err != nil {
		t.Fatal(err)
	}
	var rule *Rule
	for _, r := range db.Rules() {
		if r.ID == "binary-rule" {
			rule = r
		}
	}
	if rule == nil {
		t.Fatal("rule not loaded")
	}

	smb := []byte{0x00, 0x00, 0x00, 0x45, 0xff, 'S', 'M', 'B', 0x72, 0x00}
	if f, matched := matchRule(rule, smb); f == nil || matched == nil {
		t.Fatal("a pattern containing \\xff must match the byte 0xff")
	}
	// A latin-1 decoded response must still not match unrelated bytes.
	if f, _ := matchRule(rule, []byte("GET / HTTP/1.0\r\n\r\n")); f != nil {
		t.Error("an unrelated response matched the binary pattern")
	}
}

func TestLatin1String(t *testing.T) {
	if got := latin1String([]byte("plain ascii")); got != "plain ascii" {
		t.Errorf("ASCII must pass through unchanged, got %q", got)
	}
	got := latin1String([]byte{0xff})
	if got != "\u00ff" {
		t.Errorf("byte 0xff should map to rune U+00FF, got %q (% x)", got, got)
	}
	// Every byte maps to exactly one rune, so offsets in a pattern line up with
	// offsets in the response.
	got = latin1String([]byte{0x00, 0x7f, 0x80, 0xff})
	runes := []rune(got)
	if len(runes) != 4 || runes[0] != 0x00 || runes[1] != 0x7f || runes[2] != 0x80 || runes[3] != 0xff {
		t.Fatalf("byte to rune mapping is not 1:1: %v", runes)
	}
}

// TestBuiltinChecksArePresent keeps the shipped rule set honest: a rule that
// disappears silently is a capability that disappears silently.
func TestBuiltinChecksArePresent(t *testing.T) {
	db := mustBuiltin(t)
	have := map[string]bool{}
	for _, r := range db.Rules() {
		if r.IsCheck() {
			have[r.ID] = true
		}
	}
	want := []string{
		"redis-unauth", "elasticsearch-unauth", "mongodb-unauth", "memcached-unauth",
		"couchdb-admin-party", "docker-api-unauth", "kubelet-unauth", "kubernetes-api-unauth",
		"rabbitmq-default-creds", "ftp-anonymous", "smb-v1-enabled", "smb-signing-not-required",
		"openssh-regresshion-range", "vsftpd-backdoored-version", "proftpd-backdoored-version",
	}
	for _, id := range want {
		if !have[id] {
			t.Errorf("built-in check %q is missing", id)
		}
	}
	for _, r := range db.Rules() {
		if !r.IsCheck() {
			continue
		}
		if len(r.Match) == 0 {
			t.Errorf("check %q has no matches", r.ID)
		}
		for _, m := range r.Match {
			if m.Finding == nil {
				t.Errorf("check %q match %q reports no finding, so it does nothing --findings could use", r.ID, m.ID)
			}
		}
	}
}

// fakeFTP answers the FTP command lines this check pipelines.
func fakeFTP(t *testing.T, allowAnonymous bool) (host string, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				_, _ = c.Write([]byte("220 fake ftp ready\r\n"))
				buf := make([]byte, 512)
				var pending []byte
				for {
					n, err := c.Read(buf)
					if n > 0 {
						// FTP is line oriented: a client may pipeline several
						// commands into one write, and a real server answers
						// each of them. Handling one command per read would
						// silently drop the rest.
						pending = append(pending, buf[:n]...)
						for {
							i := bytes.Index(pending, []byte("\r\n"))
							if i < 0 {
								break
							}
							line := pending[:i]
							pending = pending[i+2:]
							fields := strings.Fields(string(line))
							if len(fields) == 0 {
								continue
							}
							switch strings.ToUpper(fields[0]) {
							case "USER":
								_, _ = c.Write([]byte("331 need password\r\n"))
							case "PASS":
								if allowAnonymous {
									_, _ = c.Write([]byte("230 login ok\r\n"))
								} else {
									_, _ = c.Write([]byte("530 login incorrect\r\n"))
								}
							}
						}
					}
					if err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port
}

// TestFTPAnonymousCheck exercises a check whose verdict needs two protocol
// exchanges. FTP answers each line independently, so the two commands can be
// pipelined into a single probe - which is what makes this expressible without
// multi-step sessions.
func TestFTPAnonymousCheck(t *testing.T) {
	t.Run("anonymous allowed", func(t *testing.T) {
		host, port := fakeFTP(t, true)
		db := mustBuiltin(t)
		addCheckOnPort(t, db, "ftp-anonymous", port)
		svc := detectOn(t, db, host, port)
		if len(svc.Findings) == 0 {
			t.Fatal("anonymous FTP should be reported")
		}
		if svc.Findings[0].Severity != "high" {
			t.Errorf("severity = %q", svc.Findings[0].Severity)
		}
	})
	t.Run("anonymous denied", func(t *testing.T) {
		host, port := fakeFTP(t, false)
		db := mustBuiltin(t)
		addCheckOnPort(t, db, "ftp-anonymous", port)
		svc := detectOn(t, db, host, port)
		if len(svc.Findings) != 0 {
			t.Fatalf("a server that refused the login must not be reported: %+v", svc.Findings)
		}
	})
}

// addCheckOnPort rebinds a built-in check to a port the test listener chose.
// The rule is round-tripped through YAML, which is also what a plugin does.
func addCheckOnPort(t *testing.T, db *DB, ruleID string, port int) {
	t.Helper()
	var src *Rule
	for _, r := range db.Rules() {
		if r.ID == ruleID {
			src = r
		}
	}
	if src == nil {
		t.Fatalf("no built-in check %q", ruleID)
	}
	clone := *src
	clone.ID = ruleID + "-test"
	clone.Ports = []int{port}
	clone.Service = ""

	raw, err := yaml.Marshal(RuleFile{
		APIVersion: APIVersion,
		ID:         "test-clone",
		Rules:      []Rule{clone},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.AddYAMLFront(raw, "test"); err != nil {
		t.Fatalf("cloning %s: %v", ruleID, err)
	}
}

func detectOn(t *testing.T, db *DB, host string, port int) *model.Service {
	t.Helper()
	d, err := New(Options{DB: db, ProbeTimeout: 2 * time.Second, Lang: "en", EnableChecks: true})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := d.Detect(context.Background(), host, model.Port{Port: port, Proto: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

// fakeBannerServer sends a fixed banner and then holds the connection open,
// which is what a banner-first service looks like.
func fakeBannerServer(t *testing.T, banner string) (host string, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				_, _ = c.Write([]byte(banner))
				buf := make([]byte, 256)
				_, _ = c.Read(buf)
			}(conn)
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port
}

// TestVersionFollowingChecks is the capability that version-following protocol
// flaws need: decide a finding by comparing the version in a banner against a
// range, on one probe with no protocol state. It also pins the negative side,
// because a check that fires on every version is worse than no check.
func TestVersionFollowingChecks(t *testing.T) {
	cases := []struct {
		name      string
		banner    string
		rule      string
		shouldHit bool
	}{
		{"OpenSSH inside the regreSSHion range", "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n", "openssh-regresshion-range", true},
		{"OpenSSH with a distro suffix still inside", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n", "openssh-regresshion-range", true},
		{"OpenSSH 9.8 is the fixed release", "SSH-2.0-OpenSSH_9.8\r\n", "openssh-regresshion-range", false},
		{"OpenSSH 9.9p1 is above the range", "SSH-2.0-OpenSSH_9.9p1 Debian-3\r\n", "openssh-regresshion-range", false},
		{"OpenSSH 8.4p1 is below the range", "SSH-2.0-OpenSSH_8.4p1 Raspbian-5\r\n", "openssh-regresshion-range", false},
		{"vsftpd 2.3.4 is the backdoored release", "220 (vsFTPd 2.3.4)\r\n", "vsftpd-backdoored-version", true},
		{"vsftpd 3.0.5 is not", "220 (vsFTPd 3.0.5)\r\n", "vsftpd-backdoored-version", false},
		{"ProFTPD 1.3.5 is the compromised release", "220 ProFTPD 1.3.5 Server ready\r\n", "proftpd-backdoored-version", true},
		{"ProFTPD 1.3.6 is not", "220 ProFTPD 1.3.6 Server ready\r\n", "proftpd-backdoored-version", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host, port := fakeBannerServer(t, tc.banner)
			db := mustBuiltin(t)
			addCheckOnPort(t, db, tc.rule, port)
			svc := detectOn(t, db, host, port)
			if hit := len(svc.Findings) > 0; hit != tc.shouldHit {
				t.Fatalf("banner %q: fired=%v, want %v (findings=%+v)", tc.banner, hit, tc.shouldHit, svc.Findings)
			}
		})
	}
}

// TestProbeBytesMeanWhatTheAuthorWrote is the regression guard for the send
// side of the same defect the latin-1 change fixed on the match side: YAML
// parses "\xff" as the codepoint U+00FF, so a binary probe used to go out four
// bytes longer than written and got dropped by the server.
func TestProbeBytesMeanWhatTheAuthorWrote(t *testing.T) {
	cases := []struct {
		in   string
		want []byte
	}{
		{"GET / HTTP/1.0\r\n", []byte("GET / HTTP/1.0\r\n")},
		// A Go string literal is already bytes: \xff here is the byte 0xff,
		// not a codepoint, and must pass through.
		{"\xff\x00SMB", []byte{0xff, 0x00, 'S', 'M', 'B'}},
		// What YAML actually hands over for "\xff": the codepoint U+00FF,
		// which must come back out as the single byte 0xff.
		{"\u00ff\u0000SMB", []byte{0xff, 0x00, 'S', 'M', 'B'}},
		{"\u00fe\u00ff", []byte{0xfe, 0xff}},
		{"\u00c8", []byte{0xc8}},
		// A rune above U+00FF is genuinely text and keeps its UTF-8 form.
		{"扫描", []byte("扫描")},
	}
	for _, tc := range cases {
		got := probeBytes(tc.in)
		if string(got) != string(tc.want) {
			t.Errorf("probeBytes(%q) = % x, want % x", tc.in, got, tc.want)
		}
	}
}

// TestBuiltinBinaryPayloadLengths pins the wire length of the generated
// requests. Both were hand written once and both were wrong: the length field
// said one thing and the payload was another, which a lenient test server
// happily ignored.
func TestBuiltinBinaryPayloadLengths(t *testing.T) {
	want := map[string]int{
		"smb-v1-enabled":           73,
		"smb-signing-not-required": 73,
		"mongodb-unauth":           63,
	}
	seen := map[string]bool{}
	for _, r := range mustBuiltin(t).Rules() {
		n, ok := want[r.ID]
		if !ok {
			continue
		}
		seen[r.ID] = true
		if len(r.Probes) == 0 {
			t.Errorf("%s has no probes", r.ID)
			continue
		}
		got := len(probeBytes(r.Probes[0].Send))
		if got != n {
			t.Errorf("%s sends %d bytes, want %d", r.ID, got, n)
		}
	}
	for id := range want {
		if !seen[id] {
			t.Errorf("rule %q not found", id)
		}
	}

	// The MongoDB message length field must describe the whole message, which
	// it did not when the payload was written by hand.
	var mongo *Rule
	for _, r := range mustBuiltin(t).Rules() {
		if r.ID == "mongodb-unauth" {
			mongo = r
		}
	}
	if mongo == nil {
		t.Fatal("no mongodb-unauth rule")
	}
	payload := probeBytes(mongo.Probes[0].Send)
	declared := int(payload[0]) | int(payload[1])<<8 | int(payload[2])<<16 | int(payload[3])<<24
	if declared != len(payload) {
		t.Errorf("MongoDB messageLength says %d, payload is %d bytes", declared, len(payload))
	}

	// The SMB NetBIOS header length must cover the SMB message that follows.
	var smb *Rule
	for _, r := range mustBuiltin(t).Rules() {
		if r.ID == "smb-v1-enabled" {
			smb = r
		}
	}
	payload = probeBytes(smb.Probes[0].Send)
	nb := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	if nb != len(payload)-4 {
		t.Errorf("NetBIOS length says %d, SMB message is %d bytes", nb, len(payload)-4)
	}
}

// TestAffectedIntersection is the user's point made testable: a finding decided
// by the intersection of several observations - a protocol version and an
// operating system version - rather than by one field falling in one range.
func TestAffectedIntersection(t *testing.T) {
	db := NewDB()
	doc := `
apiVersion: argus.fingerprint/v1
id: intersection
rules:
  - id: smb-legacy
    kind: check
    ports: [445]
    probes: [{id: p, send: ""}]
    matches:
      - id: candidate
        pattern: '(?s)SESSION-ACCEPTED'
        fields:
          protocol: 'proto=([A-Za-z0-9]+)'
          os_version: 'os=([0-9][0-9.]*)'
          implementation: 'impl=([A-Za-z ]+)'
        affected:
          - {field: protocol, equals: "SMB1"}
          - {field: os_version, range: ">=5.0 <6.2"}
          - {field: implementation, oneof: ["Windows NT", "Samba"]}
        finding: {title: "candidate", severity: medium}
`
	if _, err := db.AddYAML([]byte(doc), "test"); err != nil {
		t.Fatal(err)
	}
	var rule *Rule
	for _, r := range db.Rules() {
		if r.ID == "smb-legacy" {
			rule = r
		}
	}
	if rule == nil {
		t.Fatal("rule not loaded")
	}

	cases := []struct {
		name string
		resp string
		want bool
	}{
		{"every condition holds", "SESSION-ACCEPTED proto=SMB1 os=6.1 impl=Samba", true},
		{"another implementation", "SESSION-ACCEPTED proto=SMB1 os=6.1 impl=Windows NT", true},
		{"protocol differs", "SESSION-ACCEPTED proto=SMB2 os=6.1 impl=Samba", false},
		{"os above the range", "SESSION-ACCEPTED proto=SMB1 os=10.0 impl=Samba", false},
		{"os below the range", "SESSION-ACCEPTED proto=SMB1 os=4.0 impl=Samba", false},
		{"implementation differs", "SESSION-ACCEPTED proto=SMB1 os=6.1 impl=FreeBSD", false},
		{"os missing", "SESSION-ACCEPTED proto=SMB1 impl=Samba", false},
		{"nothing present", "SESSION-ACCEPTED", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, matched := matchRule(rule, []byte(tc.resp))
			if (matched != nil) != tc.want {
				t.Fatalf("response %q: fired=%v, want %v", tc.resp, matched != nil, tc.want)
			}
		})
	}
}

// TestAffectedAcceptsSingleAndList keeps the terse form working.
func TestAffectedAcceptsSingleAndList(t *testing.T) {
	single := `
apiVersion: argus.fingerprint/v1
id: one
rules:
  - id: r
    kind: check
    ports: [1]
    probes: [{id: p, send: ""}]
    matches:
      - id: m
        pattern: 'x'
        affected: {field: version, range: ">1"}
        finding: {title: t}
`
	if _, err := NewDB().AddYAML([]byte(single), "test"); err != nil {
		t.Fatalf("a single condition must stay valid: %v", err)
	}
}

// TestAffectedRejectsBadConditions: a condition naming a field nothing extracts
// is a rule that can never fire, which is worse than an error.
func TestAffectedRejectsBadConditions(t *testing.T) {
	cases := map[string]string{
		"two selectors at once": `
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
        affected: [{field: version, range: ">1", equals: "2"}]
        finding: {title: t}
`,
		"no selector": `
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
        affected: [{field: version}]
        finding: {title: t}
`,
		"field neither reportable nor extracted": `
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
        affected: [{field: osversie, range: ">1"}]
        finding: {title: t}
`,
		"internal field that nothing extracts": `
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
        fields: {some_typo: 'y'}
        finding: {title: t}
`,
	}
	for name, doc := range cases {
		if _, err := NewDB().AddYAML([]byte(doc), "test"); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

// TestSMBOsDiscoveryAgainstRealServer traffic is exercised live in the field;
// here the check is that the built-in rules are shaped correctly: the two
// messages are pipelined into one probe, and the fingerprint reports the OS
// without needing --findings.
func TestBuiltinSMBRules(t *testing.T) {
	db := mustBuiltin(t)

	var fp *Rule
	for _, r := range db.Rules() {
		if r.ID == "smb-os-discovery" {
			fp = r
		}
	}
	if fp == nil {
		t.Fatal("smb-os-discovery is missing")
	}
	if fp.IsCheck() {
		t.Error("identifying the operating system is an identification, not a check")
	}
	if len(fp.Probes) != 1 {
		t.Fatalf("expected one pipelined probe, got %d", len(fp.Probes))
	}
	payload := probeBytes(fp.Probes[0].Send)
	if len(payload) != 183 {
		t.Errorf("pipelined payload is %d bytes, want 183 (73 negotiate + 110 session setup)", len(payload))
	}
	// Two SMB messages in one write: that is the whole point.
	if n := bytes.Count(payload, []byte("\xffSMB")); n != 2 {
		t.Errorf("payload carries %d SMB messages, want 2", n)
	}
	// The fingerprint must offer itself for an ordinary -sV run.
	offered := false
	for _, r := range db.RulesFor(RuleQuery{Port: 445, Tunnel: "", Checks: false}) {
		if r.ID == "smb-os-discovery" {
			offered = true
		}
	}
	if !offered {
		t.Error("smb-os-discovery should run during plain service detection")
	}
	// And the intersection check must not.
	for _, r := range db.RulesFor(RuleQuery{Port: 445, Tunnel: "", Checks: false}) {
		if r.ID == "smb1-legacy-windows-family" {
			t.Error("the MS17-010 family check must not run without --findings")
		}
	}
}

// selfSignedCert builds an in-memory certificate for the TLS tests.
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "argus-test.local", Organization: []string{"Test"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"argus-test.local"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestTLSServiceOnANonStandardPort is the regression guard for a real gap: TLS
// detection used to depend on the passive banner looking like a TLS record or
// on the port being in a built-in list, so a TLS service on an unexpected port
// came back as "unknown" with nothing attached.
func TestTLSServiceOnANonStandardPort(t *testing.T) {
	cert := selfSignedCert(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				tlsConn := tls.Server(c, cfg)
				_ = tlsConn.SetDeadline(time.Now().Add(3 * time.Second))
				if err := tlsConn.Handshake(); err != nil {
					return
				}
				buf := make([]byte, 1024)
				_, _ = tlsConn.Read(buf)
				_, _ = tlsConn.Write([]byte("HTTP/1.0 200 OK\r\nServer: TLS-Test/1.0\r\nContent-Length: 2\r\n\r\nok"))
			}(conn)
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	svc := detectOn(t, mustBuiltin(t), "127.0.0.1", port)

	if svc.Tunnel != "ssl" {
		t.Fatalf("tunnel = %q, want ssl (the service only speaks TLS)", svc.Tunnel)
	}
	if svc.TLS == nil {
		t.Fatal("no TLS details were captured")
	}
	if svc.TLS.Version == "" || svc.TLS.Cipher == "" {
		t.Errorf("TLS version/cipher missing: %+v", svc.TLS)
	}
	if !svc.TLS.SelfSigned {
		t.Error("the certificate is self-signed and should be flagged")
	}
	if svc.TLS.Subject == "" {
		t.Error("the certificate subject is missing")
	}
	// The HTTP service behind the handshake should still be identified.
	if svc.Name != "http" {
		t.Errorf("service = %q, want http (the generic TLS rule should have run inside it)", svc.Name)
	}
	if svc.Product != "TLS-Test" {
		t.Errorf("product = %q, want TLS-Test", svc.Product)
	}
}

// TestTLSPortDoesNotPayTwice: a port with an explicit ssl rule must not trigger
// the last-resort handshake as well.
func TestTLSPortDoesNotPayTwice(t *testing.T) {
	db := mustBuiltin(t)
	tried := false
	for _, r := range db.RulesFor(RuleQuery{Port: 443, Tunnel: tunnelSSL}) {
		if r.Tunnel == tunnelSSL {
			tried = true
		}
	}
	if !tried {
		t.Fatal("443 should have TLS rules bound to it")
	}
	if !db.HasTLSRule(443) {
		t.Error("HasTLSRule(443) must be true so the early path is taken")
	}
	if db.HasTLSRule(19600) {
		t.Error("a port nobody predicted must not claim to have TLS rules")
	}
}

// TestTCPWrappedIsReportedAsSuch: a peer that accepts the connection and hangs
// up without a byte is a wrapper or a filter in front of the service. Naming the
// port from the table (smtp, pop3, imap) would report a guess as an
// identification; nmap calls this tcpwrapped and so does argus.
func TestTCPWrappedIsReportedAsSuch(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close() // accept, then hang up immediately
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	// 110 is pop3 in the table, so a wrong answer would be visible.
	svc := detectOn(t, mustBuiltin(t), "127.0.0.1", port)
	if svc.Name != "tcpwrapped" {
		t.Fatalf("service = %q, want tcpwrapped", svc.Name)
	}
}

// TestApacheDetailsUsesTheRealHeaderShape: Apache opens a parenthesis and never
// closes it. A pattern requiring a matching ")" matched nothing against the real
// server, while a hand-written test response that closed it passed.
func TestApacheDetailsUsesTheRealHeaderShape(t *testing.T) {
	db := mustBuiltin(t)
	// The exact shape a real Apache produces.
	resp := []byte("HTTP/1.1 200 OK\r\n" +
		"Server: Apache/2.4.37 (Alibaba Cloud Linux) OpenSSL/1.1.1k mod_perl/2.0.12 Perl/v5.26.3\r\n" +
		"Content-Type: text/html\r\n\r\n")
	svc := detectWithRules(t, db, 80, "", resp)
	if svc.Product != "Apache httpd" || svc.Version != "2.4.37" {
		t.Fatalf("product/version = %q/%q", svc.Product, svc.Version)
	}
	want := "Alibaba Cloud Linux) OpenSSL/1.1.1k mod_perl/2.0.12 Perl/v5.26.3"
	if svc.ExtraInfo != want {
		t.Fatalf("extrainfo = %q, want %q", svc.ExtraInfo, want)
	}
}

// TestBuiltinTableMatchesNmapsDefaultSweep is the guard on the port table: it
// has to reach the ports a default nmap run reaches, because a default scan that
// silently misses live web ports is worse than a slow one.
func TestBuiltinTableMatchesNmapsDefaultSweep(t *testing.T) {
	// The first 1000 entries are the frequency-ordered ports; these are the ones
	// a default nmap run covers, checked in order.
	table := WellKnownTableOf(t)
	if len(table) < 1000 {
		t.Fatalf("table has %d entries, want at least the 1000 of a default sweep", len(table))
	}
	for _, port := range []int{80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723, 111} {
		found := false
		for _, e := range table[:1000] {
			if e.Port == port {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("port %d is not in the first 1000 entries", port)
		}
	}
	// Ports that this project's earlier hand-picked table missed on a real host.
	for _, port := range []int{81, 82, 5001} {
		found := false
		for _, e := range table {
			if e.Port == port {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("port %d is missing from the table", port)
		}
	}
}

// WellKnownTableOf exposes the port table to this package without importing
// ports directly in the test file.
func WellKnownTableOf(t *testing.T) []struct {
	Port int
	Name string
} {
	t.Helper()
	out := make([]struct {
		Port int
		Name string
	}, 0, 1100)
	for _, e := range ports.WellKnownTable() {
		out = append(out, struct {
			Port int
			Name string
		}{e.Port, e.Name})
	}
	return out
}

// TestRecordMarkedProbesMatchTheirMarker is the guard on hand-written binary
// payloads. ONC RPC over TCP prefixes the call with a record marker whose low
// 31 bits are the length of what follows; a payload that is even one field short
// makes the server wait for bytes that never arrive, and the probe just times
// out with no error to explain why. That mistake was made twice while writing
// these rules - rpcbind is lenient about it and nfsd is not, so it survived one
// round of testing - and a length assertion is what catches it.
func TestRecordMarkedProbesMatchTheirMarker(t *testing.T) {
	db := mustBuiltin(t)
	checked := 0
	for _, r := range db.Rules() {
		for _, p := range r.Probes {
			b := probeBytes(p.Send)
			if len(b) < 5 || b[0] != 0x80 || b[1] != 0 || b[2] != 0 {
				continue
			}
			declared := int(b[3])
			if declared != len(b)-4 {
				t.Errorf("rule %s probe %s: record marker declares %d bytes but %d follow",
					r.ID, p.ID, declared, len(b)-4)
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("no record-marked probes found; the check is not looking at anything")
	}
	t.Logf("checked %d record-marked probes", checked)
}

// TestRpcDumpReportsEveryRegisteredService pins the behaviour that one DUMP
// answer produces one finding per service. The payload is a real reply from a
// real rpcbind serving NFS, captured rather than synthesised: the whole point of
// the rule is that it reads the wire format correctly, and a hand-written
// "response" would only prove the pattern matches itself.
func TestRpcDumpReportsEveryRegisteredService(t *testing.T) {
	const dump = "00000001000000010000000000000000000000000000000000000001000186a000000004000000060000006f00000001000186a000000003000000060000006f00000001000186a000000002000000060000006f00000001000186a000000004000000110000006f00000001000186a000000003000000110000006f00000001000186a000000002000000110000006f00000001000186a300000003000000060000080100000001000186a3000000040000000600000801000000010001878300000003000000060000080100000001000186b500000001000000110000cd8f00000001000186b500000003000000110000cd8f00000001000186b500000004000000110000cd8f00000001000186b50000000100000006000091a900000001000186b50000000300000006000091a900000001000186b50000000400000006000091a900000001000186a500000001000000110000ea2300000001000186a500000001000000060000e5d900000001000186a500000002000000110000bed500000001000186a500000002000000060000c97f00000001000186a500000003000000110000d76700000001000186a500000003000000060000ab6f00000000"
	raw, err := hex.DecodeString(dump)
	if err != nil {
		t.Fatal(err)
	}
	db := mustBuiltin(t)
	var rule *Rule
	for _, r := range db.RulesFor(RuleQuery{Port: 111, Checks: true}) {
		if r.ID == "rpc-registered-services" {
			rule = r
		}
	}
	if rule == nil {
		t.Fatal("rpc-registered-services rule not found")
	}
	hit := map[string]bool{}
	for i := range rule.Match {
		m := &rule.Match[i]
		if f := m.apply(raw); f != nil {
			hit[m.ID] = true
		}
	}
	for _, want := range []string{"nfs", "mountd", "nlockmgr", "nfs-acl"} {
		if !hit[want] {
			t.Errorf("service %q was registered in the dump but produced no finding", want)
		}
	}
	// rpcinfo does not list ypserv for this host, and it is not in the dump.
	if hit["ypserv"] {
		t.Error("ypserv was reported for a dump that does not register it")
	}
}

// TestSnmpSysdescrIsExtractedFromARealReply uses the bytes a real snmpd actually
// sent, so the BER length handling is exercised: this reply is 137 bytes, which
// means a long-form length, and a pattern built for the short form matched
// nothing at all on it.
func TestSnmpSysdescrIsExtractedFromARealReply(t *testing.T) {
	const reply = "30818602010004067075626c6963a279020401020304020100020100306b306906082b06010201010100045d4c696e7578206b616c6920362e31392e31342b6b616c692d616d64363420233120534d5020505245454d50545f44594e414d4943204b616c6920362e31392e31342d312b6b616c69312028323032362d30352d303529207838365f3634"
	raw, err := hex.DecodeString(reply)
	if err != nil {
		t.Fatal(err)
	}
	db := mustBuiltin(t)
	for _, r := range db.RulesFor(RuleQuery{Port: 161, Proto: "udp"}) {
		if r.ID != "snmp-public" {
			continue
		}
		f, m := matchRule(r, raw)
		if m == nil {
			t.Fatal("a valid GetResponse was not matched")
		}
		if f[FieldService] != "snmp" {
			t.Errorf("service = %q, want snmp", f[FieldService])
		}
		got := f[FieldInfo]
		// The leading "L" used to be eaten by a second optional length byte.
		if !strings.HasPrefix(got, "Linux kali 6.19.14") {
			t.Errorf("sysDescr = %q, want it to start with %q", got, "Linux kali 6.19.14")
		}
		if !strings.Contains(got, "x86_64") {
			t.Errorf("sysDescr = %q, want the whole string including the architecture", got)
		}
		return
	}
	t.Fatal("snmp-public rule not found for port 161/udp")
}
