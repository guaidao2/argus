package hackreason

import (
	"strings"
	"testing"
)

func TestBuiltinKBLoads(t *testing.T) {
	kb, err := LoadBuiltin()
	if err != nil {
		t.Fatalf("LoadBuiltin: %v", err)
	}
	if kb.Count() < 20 {
		t.Fatalf("the knowledge base looks truncated: %d entries", kb.Count())
	}
	for _, e := range kb.Entries() {
		if e.ID == "" {
			t.Error("entry without an id")
		}
		if len(e.Title) == 0 {
			t.Errorf("entry %s has no title", e.ID)
		}
		if e.Title["en"] == "" {
			t.Errorf("entry %s has no English title, which is the fallback", e.ID)
		}
		if len(e.Points["en"]) == 0 {
			t.Errorf("entry %s has no English points", e.ID)
		}
		if len(e.Ports) == 0 && e.Service == "" {
			t.Errorf("entry %s can never match: no ports and no service", e.ID)
		}
	}
}

// TestLookupByPort covers the common case: the port identifies the service.
func TestLookupByPort(t *testing.T) {
	kb, err := LoadBuiltin()
	if err != nil {
		t.Fatal(err)
	}
	notes := kb.Lookup("tcp", 445, "microsoft-ds", "en")
	if len(notes) == 0 {
		t.Fatal("port 445 has no notes")
	}
	if notes[0].ID != "smb" {
		t.Fatalf("first note = %q, want smb", notes[0].ID)
	}
	if len(notes[0].Points) == 0 || len(notes[0].Tools) == 0 {
		t.Fatalf("the smb note is incomplete: %+v", notes[0])
	}
}

// TestPortBoundEntriesDoNotMatchByService is the regression guard for a real
// bug: entries that declare ports used to also match on the generic service
// name, so a single open web port produced a wall of Elasticsearch, Consul and
// Jenkins advice that had nothing to do with the target.
func TestPortBoundEntriesDoNotMatchByService(t *testing.T) {
	kb, err := LoadBuiltin()
	if err != nil {
		t.Fatal(err)
	}
	notes := kb.Lookup("tcp", 18080, "http", "en")
	for _, n := range notes {
		if n.ID == "elasticsearch" || n.ID == "kibana" || n.ID == "consul" ||
			n.ID == "jenkins" || n.ID == "grafana" || n.ID == "gitlab" {
			t.Fatalf("entry %q fired on port 18080 purely because the service is http", n.ID)
		}
	}
	if len(notes) == 0 {
		t.Fatal("the generic http note should still match port 18080")
	}
}

// TestServiceOnlyEntriesMatchAnyPort covers the other half: an entry with no
// port list is a claim about the service everywhere it runs.
func TestServiceOnlyEntriesMatchAnyPort(t *testing.T) {
	kb := New()
	_, err := kb.AddYAML([]byte(`
apiVersion: argus.hackreason/v1
id: test
entries:
  - id: ssh-anywhere
    service: ssh
    title: {en: SSH, zh: SSH}
    points: {en: [check it], zh: [检查]}
`), "test")
	if err != nil {
		t.Fatal(err)
	}
	if notes := kb.Lookup("tcp", 22222, "ssh", "en"); len(notes) != 1 {
		t.Fatalf("a service-bound entry should match on any port, got %d notes", len(notes))
	}
	if notes := kb.Lookup("tcp", 22222, "http", "en"); len(notes) != 0 {
		t.Fatalf("a service-bound entry must not match another service, got %d notes", len(notes))
	}
}

func TestLocalisationAndFallback(t *testing.T) {
	kb, err := LoadBuiltin()
	if err != nil {
		t.Fatal(err)
	}
	en := kb.Lookup("tcp", 445, "microsoft-ds", "en")
	zh := kb.Lookup("tcp", 445, "microsoft-ds", "zh")
	if len(en) == 0 || len(zh) == 0 {
		t.Fatal("missing notes")
	}
	if en[0].Title == zh[0].Title {
		t.Errorf("the Chinese title was not used: %q", zh[0].Title)
	}
	if !strings.ContainsAny(zh[0].Title, "文件共享") {
		t.Errorf("unexpected Chinese title: %q", zh[0].Title)
	}
	// An unsupported language falls back to English rather than rendering
	// nothing.
	fr := kb.Lookup("tcp", 445, "microsoft-ds", "fr")
	if len(fr) == 0 || fr[0].Title != en[0].Title {
		t.Errorf("a missing translation should fall back to English, got %q", fr[0].Title)
	}
}

func TestProtoScoping(t *testing.T) {
	kb, err := LoadBuiltin()
	if err != nil {
		t.Fatal(err)
	}
	if notes := kb.Lookup("udp", 53, "domain", "en"); len(notes) == 0 {
		t.Error("udp/53 should have notes")
	}
	if notes := kb.Lookup("tcp", 53, "domain", "en"); len(notes) != 0 {
		t.Errorf("the udp/53 notes must not fire on tcp/53, got %d", len(notes))
	}
}

func TestAddYAMLValidation(t *testing.T) {
	cases := map[string]string{
		"bad api version": `
apiVersion: argus.hackreason/v9
id: x
entries: [{id: a, ports: [1], title: {en: t}}]
`,
		"missing id": `
apiVersion: argus.hackreason/v1
id: x
entries: [{ports: [1], title: {en: t}}]
`,
		"missing title": `
apiVersion: argus.hackreason/v1
id: x
entries: [{id: a, ports: [1]}]
`,
		"no matcher": `
apiVersion: argus.hackreason/v1
id: x
entries: [{id: a, title: {en: t}}]
`,
	}
	for name, doc := range cases {
		if _, err := New().AddYAML([]byte(doc), "test"); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestAddYAMLFrontWins(t *testing.T) {
	kb, err := LoadBuiltin()
	if err != nil {
		t.Fatal(err)
	}
	doc := []byte(`
apiVersion: argus.hackreason/v1
id: plugin
entries:
  - id: plugin-note
    ports: [445]
    title: {en: "Plugin note", zh: "插件提示"}
    points: {en: [plugin rule fired], zh: [插件规则命中]}
`)
	if _, err := kb.AddYAMLFront(doc, "plugin:test"); err != nil {
		t.Fatal(err)
	}
	notes := kb.Lookup("tcp", 445, "microsoft-ds", "en")
	if len(notes) == 0 || notes[0].ID != "plugin-note" {
		t.Fatalf("a plugin entry must be shown first, got %+v", notes)
	}
}

func TestReplacedEntryIsReported(t *testing.T) {
	kb := New()
	doc := []byte(`
apiVersion: argus.hackreason/v1
id: x
entries: [{id: only, ports: [1], title: {en: a}, points: {en: [p]}}]
`)
	if _, err := kb.AddYAML(doc, "test"); err != nil {
		t.Fatal(err)
	}
	replaced, err := kb.AddYAML(doc, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(replaced) != 1 || replaced[0] != "only" {
		t.Fatalf("replaced = %v", replaced)
	}
	if kb.Count() != 1 {
		t.Fatalf("Count() = %d, want 1", kb.Count())
	}
}

func TestNilKBLookupIsSafe(t *testing.T) {
	var kb *KB
	if notes := kb.Lookup("tcp", 445, "", "en"); notes != nil {
		t.Fatal("a nil knowledge base must return nothing")
	}
	if kb.Count() != 0 {
		t.Fatal("a nil knowledge base has no entries")
	}
}
