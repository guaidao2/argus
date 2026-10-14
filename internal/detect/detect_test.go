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

// TestPluginRulesAreIndexedLikeBuiltins pins down how a plugin rule is filed in
// the database, because the ways it can go wrong are all silent:
//
//   - a plugin check that binds to a service must be reachable when that service
//     is identified, on whatever port it was identified on (a rule that is never
//     reached looks exactly like a rule that did not match);
//   - it must NOT be handed to every port in the scan just because it has no
//     port list, which is what "no ports means everywhere" would do to it;
//   - a rule with no bindings at all must keep meaning "every open port",
//     including a fingerprint from a plugin, since a fingerprint has no service
//     index to be reached through and dropping it from the generic list would
//     make it dead rather than narrow.
func TestPluginRulesAreIndexedLikeBuiltins(t *testing.T) {
	db := NewDB()
	if _, err := db.AddYAMLFront([]byte(`
apiVersion: argus.fingerprint/v1
id: test-indexing
rules:
  - id: plugin-everywhere
    probes: [{id: p, send: ""}]
    matches: [{id: m, pattern: 'anywhere', set: {service: anything}}]
  - id: plugin-by-service
    kind: check
    service: redis
    probes: [{id: p, send: ""}]
    matches: [{id: m, pattern: 'service', set: {service: redis}}]
  - id: plugin-by-port-and-service
    kind: check
    ports: [19300]
    service: redis
    probes: [{id: p, send: ""}]
    matches: [{id: m, pattern: 'both', set: {service: redis}}]
`), "test"); err != nil {
		t.Fatal(err)
	}

	seen := func(q RuleQuery) map[string]bool {
		out := map[string]bool{}
		for _, r := range db.RulesFor(q) {
			out[r.ID] = true
		}
		return out
	}

	// The service binding is what makes a rule reachable on a port nobody
	// predicted, and both the service-bound and the port-bound rule answer to it.
	byService := seen(RuleQuery{Port: 45678, Proto: "tcp", Checks: true, Service: "redis"})
	for _, want := range []string{"plugin-by-service", "plugin-by-port-and-service", "plugin-everywhere"} {
		if !byService[want] {
			t.Errorf("rule %q is not selected for service redis on port 45678: %v", want, byService)
		}
	}

	// Without an identified service, a service-bound check has nothing to match
	// on -- and it must not fall back to being a rule about every port.
	unbound := seen(RuleQuery{Port: 45678, Proto: "tcp", Checks: true})
	if unbound["plugin-by-service"] {
		t.Error("a check bound only to a service was handed to a port where that service was never identified")
	}
	if !unbound["plugin-everywhere"] {
		t.Error("a rule with no port and no service binding must still apply to every port")
	}
	if unbound["plugin-by-port-and-service"] {
		t.Error("a rule bound to port 19300 was selected for port 45678")
	}

	// Port bindings keep working, with and without an identified service.
	pinned := seen(RuleQuery{Port: 19300, Proto: "tcp", Checks: true})
	if !pinned["plugin-by-port-and-service"] {
		t.Error("a rule bound to port 19300 was not selected for port 19300")
	}

	// And checks stay off unless they were asked for.
	off := seen(RuleQuery{Port: 19300, Proto: "tcp", Service: "redis"})
	if off["plugin-by-port-and-service"] || off["plugin-by-service"] {
		t.Error("a check rule ran without checks being enabled")
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
