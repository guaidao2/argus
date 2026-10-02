package plugins

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/guaidao2/argus/internal/version"
)

// APIVersion is the plugin schema this build understands. It is declared in
// every plugin so that a document written for a newer argus is rejected
// instead of being silently misread.
const APIVersion = "argus.plugin/v1"

// Document is one plugin file.
type Document struct {
	APIVersion      string            `yaml:"apiVersion"`
	Name            string            `yaml:"name"`
	Version         string            `yaml:"version"`
	Author          string            `yaml:"author"`
	License         string            `yaml:"license"`
	Description     string            `yaml:"description"`
	ArgusMinVersion string            `yaml:"argus_min_version"`
	Vars            map[string]string `yaml:"vars"`
	// Fingerprints and HackReasons keep their raw YAML so that each subsystem
	// can compile them with its own schema and error messages. They are value
	// nodes: yaml.v3 does not populate a *yaml.Node field.
	Fingerprints yaml.Node `yaml:"fingerprints"`
	HackReasons  yaml.Node `yaml:"hack_reasons"`

	// Source is the file the document came from.
	Source string `yaml:"-"`
}

// ParseDocument decodes and validates one plugin document. running is the
// argus version doing the loading, used for the argus_min_version check.
func ParseDocument(raw []byte, source, running string) (*Document, error) {
	var doc Document
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", source, err)
	}
	doc.Source = source
	if doc.APIVersion == "" {
		return nil, fmt.Errorf("%s: missing apiVersion, expected %s", source, APIVersion)
	}
	if doc.APIVersion != APIVersion {
		return nil, fmt.Errorf("%s: unsupported apiVersion %q (this build understands %s)", source, doc.APIVersion, APIVersion)
	}
	if doc.Name == "" {
		return nil, fmt.Errorf("%s: plugin has no name", source)
	}
	if doc.ArgusMinVersion != "" && version.Compare(running, doc.ArgusMinVersion) < 0 {
		return nil, fmt.Errorf("%s: plugin %s needs argus >= %s, running %s", source, doc.Name, doc.ArgusMinVersion, running)
	}
	if doc.Fingerprints.Kind == 0 && doc.HackReasons.Kind == 0 {
		return nil, fmt.Errorf("%s: plugin %s defines neither fingerprints nor hack_reasons", source, doc.Name)
	}
	return &doc, nil
}

// Data is one embedded document handed to a subsystem.
type Data struct {
	Source string
	Raw    []byte
}

// SkipInfo describes a file that was found under a registered path but is not
// a plugin document.
type SkipInfo struct {
	Path   string
	Reason string
}

// Bundle is the result of loading a set of plugins.
type Bundle struct {
	Docs         []*Document
	Fingerprints []Data
	HackReasons  []Data
	Vars         map[string]string
	Names        []string

	// Missing and Changed list registered plugins whose state drifted from
	// the registry.
	Missing []Record
	Changed []Record
	// Skipped lists files under a directory that were not plugin documents. A
	// pack directory legitimately holds a README, a schema or a values file
	// next to its plugins, so those are reported rather than fatal.
	Skipped []SkipInfo
}

// IsEmpty reports whether the bundle carries no data at all.
func (b *Bundle) IsEmpty() bool {
	return b == nil || (len(b.Fingerprints) == 0 && len(b.HackReasons) == 0)
}

func (b *Bundle) add(doc *Document) error {
	fps, err := nodeDocs(&doc.Fingerprints)
	if err != nil {
		return fmt.Errorf("%s: fingerprints: %w", doc.Source, err)
	}
	hrs, err := nodeDocs(&doc.HackReasons)
	if err != nil {
		return fmt.Errorf("%s: hack_reasons: %w", doc.Source, err)
	}
	b.Docs = append(b.Docs, doc)
	b.Names = append(b.Names, doc.Name)
	for _, raw := range fps {
		b.Fingerprints = append(b.Fingerprints, Data{Source: doc.Source, Raw: raw})
	}
	for _, raw := range hrs {
		b.HackReasons = append(b.HackReasons, Data{Source: doc.Source, Raw: raw})
	}
	if b.Vars == nil {
		b.Vars = map[string]string{}
	}
	for k, v := range doc.Vars {
		if _, exists := b.Vars[k]; !exists {
			b.Vars[k] = v
		}
	}
	return nil
}

// nodeDocs converts an embedded YAML node into standalone documents.
func nodeDocs(n *yaml.Node) ([][]byte, error) {
	if n == nil || n.Kind == 0 {
		return nil, nil
	}
	// A document node wraps the real value.
	if n.Kind == yaml.DocumentNode && len(n.Content) == 1 {
		n = n.Content[0]
	}
	if n.Kind == yaml.AliasNode && n.Alias != nil {
		n = n.Alias
	}
	switch n.Kind {
	case yaml.MappingNode:
		raw, err := yaml.Marshal(n)
		if err != nil {
			return nil, err
		}
		return [][]byte{raw}, nil
	case yaml.SequenceNode:
		out := make([][]byte, 0, len(n.Content))
		for _, item := range n.Content {
			raw, err := yaml.Marshal(item)
			if err != nil {
				return nil, err
			}
			out = append(out, raw)
		}
		return out, nil
	}
	return nil, errors.New("expected a mapping or a sequence of mappings")
}

// LoadRegistered loads every enabled plugin in the registry.
//
// Missing and changed plugins are collected in the bundle so the caller can
// warn about them; with strict set, they become errors instead.
func LoadRegistered(reg *Registry, strict bool) (*Bundle, error) {
	b := &Bundle{}
	if reg == nil {
		return b, nil
	}
	for _, rec := range reg.Plugins {
		if !rec.Enabled {
			continue
		}
		state, err := Status(rec)
		switch {
		case err != nil:
			return nil, fmt.Errorf("cannot inspect plugin %s (%s): %w", rec.Name, rec.Path, err)
		case state == StateMissing:
			b.Missing = append(b.Missing, rec)
			continue
		case state == StateChanged:
			b.Changed = append(b.Changed, rec)
		}
		if err := b.loadOne(rec); err != nil {
			return nil, err
		}
	}
	if strict && (len(b.Missing) > 0 || len(b.Changed) > 0) {
		return b, errors.New("strict plugin mode: a registered plugin is missing or changed")
	}
	return b, nil
}

// LoadPath loads plugins from an explicit path (file or directory), bypassing
// the registry. It is what --plugin-dir uses.
func LoadPath(path string) (*Bundle, error) {
	b := &Bundle{}
	if err := b.collect(path, version.Version); err != nil {
		return nil, err
	}
	return b, nil
}

// collect reads every plugin document under path into the bundle.
//
// When path is a single file the user named it explicitly, so a file that is
// not a plugin document is an error. When path is a directory the files are
// whatever happens to live there, so a non-plugin file is reported in Skipped
// and the rest still loads.
func (b *Bundle) collect(path, running string) error {
	files, err := PluginFiles(path)
	if err != nil {
		return err
	}
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	singleFile := !fi.IsDir()

	for _, f := range files {
		raw, err := readPluginFile(f)
		if err != nil {
			if singleFile {
				return fmt.Errorf("cannot read plugin %s: %w", f, err)
			}
			b.Skipped = append(b.Skipped, SkipInfo{Path: f, Reason: err.Error()})
			continue
		}
		doc, err := ParseDocument(raw, f, running)
		if err != nil {
			if singleFile {
				return err
			}
			b.Skipped = append(b.Skipped, SkipInfo{Path: f, Reason: err.Error()})
			continue
		}
		if err := b.add(doc); err != nil {
			return err
		}
	}
	if len(b.Docs) == 0 {
		return fmt.Errorf("no usable plugin documents in %s", path)
	}
	return nil
}

func (b *Bundle) loadOne(rec Record) error {
	if err := b.collect(rec.Path, version.Version); err != nil {
		return fmt.Errorf("plugin %s: %w", rec.Name, err)
	}
	return nil
}

// Inspect validates a path the user wants to register, and returns the summary
// that goes into the registry plus the files under it that were not plugin
// documents.
func Inspect(path string) (rec Record, skipped []SkipInfo, err error) {
	fi, err := os.Stat(path)
	if err != nil {
		return Record{}, nil, err
	}
	kind := "file"
	if fi.IsDir() {
		kind = "dir"
	}

	b := &Bundle{}
	if err := b.collect(path, version.Version); err != nil {
		return Record{}, b.Skipped, err
	}

	hash, err := HashPath(path)
	if err != nil {
		return Record{}, b.Skipped, err
	}

	// A directory is one package, so name it after the directory: that is what
	// the user typed, and it is what --unregister-plugin has to match.
	name := filepath.Base(path)
	if kind == "file" {
		name = b.Docs[0].Name
	}

	var vers, descs []string
	for _, doc := range b.Docs {
		if doc.Version != "" {
			vers = append(vers, doc.Version)
		}
		if doc.Description != "" {
			descs = append(descs, doc.Description)
		}
	}
	if kind == "dir" {
		descs = append([]string{fmt.Sprintf("%d document(s): %s", len(b.Docs), strings.Join(b.Names, ", "))}, descs...)
	}

	return Record{
		Name:         name,
		Path:         path,
		Kind:         kind,
		Hash:         hash,
		RegisteredAt: nowUTC(),
		Enabled:      true,
		Version:      joinNonEmpty(uniqueStrings(vers), ", "),
		Description:  joinNonEmpty(descs, " | "),
	}, b.Skipped, nil
}

func joinNonEmpty(list []string, sep string) string {
	out := ""
	for _, s := range list {
		if s == "" {
			continue
		}
		if out != "" {
			out += sep
		}
		out += s
	}
	return out
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// nowUTC keeps timestamps in the registry comparable across time zones.
func nowUTC() time.Time { return time.Now().UTC() }
