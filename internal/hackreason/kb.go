// Package hackreason holds the offensive-security notes argus can attach to
// an open port.
//
// The knowledge base is plain YAML so that it can be extended by plugins
// without recompiling. Every entry is bilingual; the requested language is
// preferred and English is the fallback.
//
// Scope: these are reconnaissance checklists with tool names and references,
// not exploit payloads. That keeps the tool useful in an authorised test and
// keeps the project distributable.
package hackreason

import (
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/guaidao2/argus/internal/model"
)

//go:embed data/*.yaml
var dataFS embed.FS

// APIVersion is the schema version understood by this build.
const APIVersion = "argus.hackreason/v1"

// Localized is a map of language code to text.
type Localized map[string]string

// LocalizedList is a map of language code to a list of strings.
type LocalizedList map[string][]string

// Entry is one offensive-security note.
//
// Matching rules:
//   - Ports only: the note applies to exactly those ports.
//   - Service with no ports: the note applies wherever that service runs.
//   - Service with AnyPort: the note applies to that service on any port, which
//     is what "HTTP on 41395" needs. Without this, a service discovered on a
//     non standard port would get no guidance at all.
type Entry struct {
	ID      string        `yaml:"id"`
	Ports   []int         `yaml:"ports"`
	Proto   string        `yaml:"proto"`
	Service string        `yaml:"service"`
	AnyPort bool          `yaml:"any_port"`
	Title   Localized     `yaml:"title"`
	Points  LocalizedList `yaml:"points"`
	Tools   []string      `yaml:"tools"`
	Refs    []string      `yaml:"refs"`
}

// File is the top level document.
type File struct {
	APIVersion  string  `yaml:"apiVersion"`
	ID          string  `yaml:"id"`
	Description string  `yaml:"description"`
	Entries     []Entry `yaml:"entries"`
}

// KB is a loaded knowledge base.
type KB struct {
	entries   []*Entry
	byPort    map[int][]*Entry
	byService map[string][]*Entry
}

// New returns an empty knowledge base.
func New() *KB {
	return &KB{byPort: map[int][]*Entry{}, byService: map[string][]*Entry{}}
}

// LoadBuiltin loads the embedded knowledge base.
func LoadBuiltin() (*KB, error) {
	kb := New()
	entries, err := fs.ReadDir(dataFS, "data")
	if err != nil {
		return nil, fmt.Errorf("embedded hack-reason data is missing: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".yaml") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		raw, err := dataFS.ReadFile("data/" + name)
		if err != nil {
			return nil, err
		}
		if _, err := kb.AddYAML(raw, "builtin:"+name); err != nil {
			return nil, err
		}
	}
	return kb, nil
}

// AddYAML merges one document into the built-in knowledge base. Entries
// sharing an id are replaced, and the replaced ids are returned.
func (kb *KB) AddYAML(raw []byte, source string) (replaced []string, err error) {
	return kb.addDocuments(raw, source, false)
}

// AddYAMLFront is the plugin entry point: plugin notes are shown before the
// built-in ones for the same port.
func (kb *KB) AddYAMLFront(raw []byte, source string) (replaced []string, err error) {
	return kb.addDocuments(raw, source, true)
}

func (kb *KB) addDocuments(raw []byte, source string, front bool) (replaced []string, err error) {
	var f File
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", source, err)
	}
	if f.APIVersion != "" && f.APIVersion != APIVersion {
		return nil, fmt.Errorf("%s: unsupported apiVersion %q (this build understands %s)", source, f.APIVersion, APIVersion)
	}
	for i := range f.Entries {
		e := &f.Entries[i]
		if e.ID == "" {
			return nil, fmt.Errorf("%s: entry %d has no id", source, i)
		}
		if len(e.Title) == 0 {
			return nil, fmt.Errorf("%s: entry %q has no title", source, e.ID)
		}
		if len(e.Ports) == 0 && e.Service == "" {
			return nil, fmt.Errorf("%s: entry %q has neither ports nor a service", source, e.ID)
		}
		if e.Proto == "" {
			e.Proto = "tcp"
		}
		if kb.contains(e.ID) {
			replaced = append(replaced, e.ID)
			kb.remove(e.ID)
		}
		if front {
			kb.entries = append([]*Entry{e}, kb.entries...)
			for _, p := range e.Ports {
				kb.byPort[p] = append([]*Entry{e}, kb.byPort[p]...)
			}
			if e.Service != "" && (len(e.Ports) == 0 || e.AnyPort) {
				k := strings.ToLower(e.Service)
				kb.byService[k] = append([]*Entry{e}, kb.byService[k]...)
			}
			continue
		}
		kb.entries = append(kb.entries, e)
		for _, p := range e.Ports {
			kb.byPort[p] = append(kb.byPort[p], e)
		}
		// Service matching is only indexed for entries that ask for it: either
		// they have no port list at all, or they declare any_port. An entry
		// bound to ports is a claim about those ports, and letting it fire on
		// every port that happens to run "http" produced a wall of irrelevant
		// notes on a single open web port.
		if e.Service != "" && (len(e.Ports) == 0 || e.AnyPort) {
			kb.byService[strings.ToLower(e.Service)] = append(kb.byService[strings.ToLower(e.Service)], e)
		}
	}
	return replaced, nil
}

func (kb *KB) contains(id string) bool {
	for _, e := range kb.entries {
		if e.ID == id {
			return true
		}
	}
	return false
}

func (kb *KB) remove(id string) {
	keep := kb.entries[:0:0]
	for _, e := range kb.entries {
		if e.ID != id {
			keep = append(keep, e)
		}
	}
	kb.entries = keep
	for port, list := range kb.byPort {
		out := list[:0:0]
		for _, e := range list {
			if e.ID != id {
				out = append(out, e)
			}
		}
		if len(out) == 0 {
			delete(kb.byPort, port)
		} else {
			kb.byPort[port] = out
		}
	}
	for svc, list := range kb.byService {
		out := list[:0:0]
		for _, e := range list {
			if e.ID != id {
				out = append(out, e)
			}
		}
		if len(out) == 0 {
			delete(kb.byService, svc)
		} else {
			kb.byService[svc] = out
		}
	}
}

// Count returns the number of entries. A nil knowledge base is valid and
// empty, which keeps the callers free of nil checks.
func (kb *KB) Count() int {
	if kb == nil {
		return 0
	}
	return len(kb.entries)
}

// Lookup returns the notes that apply to a port, localised to lang. A service
// name match is more specific than a port match, so those come first.
func (kb *KB) Lookup(proto string, port int, service string, lang string) []model.HackNote {
	if kb == nil {
		return nil
	}
	var (
		out  []model.HackNote
		seen = map[string]bool{}
	)
	add := func(list []*Entry) {
		for _, e := range list {
			if seen[e.ID] || !protoMatches(e.Proto, proto) {
				continue
			}
			seen[e.ID] = true
			out = append(out, e.localize(lang))
		}
	}
	add(kb.byPort[port])
	// Service-bound entries (no port list, or any_port) apply to any port
	// running that service.
	if service != "" {
		add(kb.byService[strings.ToLower(service)])
	}
	return out
}

// Entries returns every entry in load order.
func (kb *KB) Entries() []*Entry {
	if kb == nil {
		return nil
	}
	return append([]*Entry(nil), kb.entries...)
}

func protoMatches(entryProto, portProto string) bool {
	if entryProto == "" || portProto == "" {
		return true
	}
	return strings.EqualFold(entryProto, portProto)
}

func (e *Entry) localize(lang string) model.HackNote {
	pick := func(m Localized) string {
		if v := m[lang]; v != "" {
			return v
		}
		return m["en"]
	}
	pickList := func(m LocalizedList) []string {
		if v, ok := m[lang]; ok && len(v) > 0 {
			return v
		}
		return m["en"]
	}
	return model.HackNote{
		ID:     e.ID,
		Title:  pick(e.Title),
		Points: pickList(e.Points),
		Tools:  e.Tools,
		Refs:   e.Refs,
	}
}
