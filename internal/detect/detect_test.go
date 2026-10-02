package detect

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/guaidao2/argus/internal/model"
)

func TestBuiltinRulesLoad(t *testing.T) {
	db, err := LoadBuiltin()
	if err != nil {
		t.Fatalf("LoadBuiltin: %v", err)
	}
	if len(db.Rules()) == 0 {
		t.Fatal("no rules loaded")
	}
	for _, r := range db.Rules() {
		if r.ID == "" {
			t.Fatal("rule without id")
		}
		if len(r.Match) == 0 {
			t.Fatalf("rule %s has no matches", r.ID)
		}
	}
}

func TestRuleOverrideReplacesOldRule(t *testing.T) {
	db := NewDB()
	first := []byte(`
apiVersion: argus.fingerprint/v1
id: test
rules:
  - id: something
    ports: [1234]
    probes: [{id: p, send: ""}]
    matches: [{id: m, pattern: 'one', set: {service: one}}]
`)
	if _, err := db.AddYAML(first, "test1"); err != nil {
		t.Fatalf("first load: %v", err)
	}
	second := []byte(`
apiVersion: argus.fingerprint/v1
id: test
rules:
  - id: something
    ports: [1234]
    probes: [{id: p, send: ""}]
    matches: [{id: m, pattern: 'two', set: {service: two}}]
`)
	replaced, err := db.AddYAML(second, "test2")
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	if len(replaced) != 1 || replaced[0] != "something" {
		t.Fatalf("expected the rule to be reported as replaced, got %v", replaced)
	}
	rules := db.RulesFor(RuleQuery{Port: 1234, Tunnel: "", Checks: false})
	if len(rules) != 1 {
		t.Fatalf("expected exactly one rule for the port, got %d", len(rules))
	}
	if f, _ := matchRule(rules[0], []byte("two")); f == nil || f[FieldService] != "two" {
		t.Fatalf("the new rule did not win: %v", f)
	}
}

func TestAddYAMLRejectsBadInput(t *testing.T) {
	cases := map[string]string{
		"newer api version": `
apiVersion: argus.fingerprint/v9
id: bad
rules: []
`,
		"unknown match field": `
apiVersion: argus.fingerprint/v1
id: bad
rules:
  - id: r
    probes: [{id: p, send: ""}]
    matches: [{id: m, pattern: 'x', set: {nonsense: y}}]
`,
		"invalid regex": `
apiVersion: argus.fingerprint/v1
id: bad
rules:
  - id: r
    probes: [{id: p, send: ""}]
    matches: [{id: m, pattern: '([', set: {}}]
`,
		"no matches": `
apiVersion: argus.fingerprint/v1
id: bad
rules:
  - id: r
    probes: [{id: p, send: ""}]
`,
	}
	for name, doc := range cases {
		if _, err := NewDB().AddYAML([]byte(doc), "test"); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestSSHBannerExtraction(t *testing.T) {
	db, err := LoadBuiltin()
	if err != nil {
		t.Fatalf("LoadBuiltin: %v", err)
	}
	resp := []byte("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n")
	svc := detectWithRules(t, db, 22, "", resp)
	if svc.Name != "ssh" {
		t.Errorf("service = %q, want ssh", svc.Name)
	}
	if svc.Product != "OpenSSH" {
		t.Errorf("product = %q, want OpenSSH", svc.Product)
	}
	if svc.Version != "8.9p1" {
		t.Errorf("version = %q, want 8.9p1", svc.Version)
	}
	if svc.OSType != "Ubuntu-3ubuntu0.4" {
		t.Errorf("ostype = %q, want Ubuntu-3ubuntu0.4", svc.OSType)
	}
}

func TestHTTPResponseExtraction(t *testing.T) {
	db, err := LoadBuiltin()
	if err != nil {
		t.Fatalf("LoadBuiltin: %v", err)
	}
	resp := []byte("HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html\r\n\r\n")
	svc := detectWithRules(t, db, 80, "", resp)
	if svc.Name != "http" || svc.Product != "nginx" || svc.Version != "1.24.0" {
		t.Fatalf("got service=%q product=%q version=%q", svc.Name, svc.Product, svc.Version)
	}
}

func TestGarbageIsNotIdentified(t *testing.T) {
	db, err := LoadBuiltin()
	if err != nil {
		t.Fatalf("LoadBuiltin: %v", err)
	}
	resp := []byte("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f")
	for _, r := range db.RulesFor(RuleQuery{Port: 9999, Tunnel: "", Checks: false}) {
		if f, _ := matchRule(r, resp); f != nil {
			t.Fatalf("binary noise matched rule %s/%v", r.ID, f)
		}
	}
}

// detectWithRules runs the database against a synthetic response.
func detectWithRules(t *testing.T, db *DB, port int, tunnel string, resp []byte) *model.Service {
	t.Helper()
	for _, r := range db.RulesFor(RuleQuery{Port: port, Tunnel: tunnel}) {
		f, _ := matchRule(r, resp)
		if f == nil {
			continue
		}
		return buildService(r, f, resp)
	}
	t.Fatalf("no rule matched the synthetic response on port %d", port)
	return nil
}

// TestDetectEndToEnd runs the detector against a real listening socket.
func TestDetectEndToEnd(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, 1024)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\nContent-Length: 2\r\n\r\nok"))
			}(conn)
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	d, err := New(Options{ProbeTimeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	svc, err := d.Detect(context.Background(), "127.0.0.1", model.Port{Port: port, Proto: "tcp"})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if svc == nil {
		t.Fatal("Detect returned no service")
	}
	if svc.Name != "http" || !strings.Contains(svc.Product, "nginx") {
		t.Fatalf("got service=%q product=%q version=%q", svc.Name, svc.Product, svc.Version)
	}
}

func TestIsTLSRecord(t *testing.T) {
	if !isTLSRecord([]byte{22, 3, 1, 0}) {
		t.Error("valid TLS record not recognised")
	}
	if isTLSRecord([]byte("GET / HTTP/1.0")) {
		t.Error("HTTP request misidentified as TLS")
	}
	if isTLSRecord(nil) {
		t.Error("empty buffer misidentified as TLS")
	}
}

func TestCleanBanner(t *testing.T) {
	got := cleanBanner([]byte("HTTP/1.1 200 OK\r\nServer: nginx\n\n\x00\x01binary"))
	if strings.Contains(got, "\n") || strings.Contains(got, "\x00") {
		t.Fatalf("banner was not sanitised: %q", got)
	}
	if !strings.HasPrefix(got, "HTTP/1.1 200 OK Server: nginx") {
		t.Fatalf("unexpected banner: %q", got)
	}
}
