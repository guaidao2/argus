// Package plugins implements the YAML plugin registry.
//
// argus never executes plugin code. A plugin is a YAML document that declares
// fingerprint rules and hack-reason notes; the registry only records where
// those documents live. The interesting part is what happens when reality
// drifts: a registered path disappears, or its content changes after
// registration. Both are reported, and argus keeps running without plugins
// instead of failing the whole scan.
package plugins

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/guaidao2/argus/internal/config"
)

// RegistryVersion is the on-disk schema version of the registry file.
const RegistryVersion = 1

// Plugin extensions scanned inside a registered directory.
var pluginExtensions = []string{".yaml", ".yml"}

// maxPluginBytes bounds a single plugin document. A plugin is a local file, but
// the path lives in the registry, which may not be under the user's control
// (argus is routinely run as root), and reading an unbounded file into memory
// on every scan is a cheap denial of service.
const maxPluginBytes = 16 << 20

// readPluginFile reads a plugin document, refusing anything implausibly large.
func readPluginFile(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Size() > maxPluginBytes {
		return nil, fmt.Errorf("%s is %d bytes, over the %d byte plugin limit", path, fi.Size(), maxPluginBytes)
	}
	return os.ReadFile(path)
}

// Record is one registered plugin.
type Record struct {
	Name         string    `yaml:"name"`
	Path         string    `yaml:"path"`
	Kind         string    `yaml:"kind"` // file | dir
	Hash         string    `yaml:"sha256"`
	RegisteredAt time.Time `yaml:"registered_at"`
	Enabled      bool      `yaml:"enabled"`
	Version      string    `yaml:"version,omitempty"`
	Description  string    `yaml:"description,omitempty"`
}

// Registry is the persistent plugin list.
type Registry struct {
	Version int      `yaml:"version"`
	Plugins []Record `yaml:"plugins"`
	// path remembers where the registry was loaded from so Save can write
	// back to the same place.
	path string `yaml:"-"`
}

// Load reads the registry. A missing file yields an empty registry, which is
// not an error: a first run has nothing registered yet.
func Load(path string) (*Registry, error) {
	reg := &Registry{Version: RegistryVersion, path: path}
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return reg, nil
		}
		return nil, fmt.Errorf("cannot read the plugin registry %s: %w", path, err)
	}
	if err := yaml.Unmarshal(raw, reg); err != nil {
		return nil, fmt.Errorf("plugin registry %s is not valid YAML: %w", path, err)
	}
	reg.path = path
	if reg.Version == 0 {
		reg.Version = RegistryVersion
	}
	if reg.Version > RegistryVersion {
		return nil, fmt.Errorf("plugin registry %s was written by a newer argus (version %d)", path, reg.Version)
	}
	return reg, nil
}

// Path returns where the registry lives.
func (r *Registry) Path() string { return r.path }

// Save writes the registry atomically.
func (r *Registry) Save() error {
	if r.path == "" {
		return errors.New("plugin registry has no path")
	}
	r.Version = RegistryVersion
	raw, err := yaml.Marshal(r)
	if err != nil {
		return err
	}
	header := "# argus plugin registry - managed by --register-plugin / --unregister-plugin\n"
	return config.WriteFileAtomic(r.path, append([]byte(header), raw...), 0o600)
}

// Find resolves a user reference: an exact name, an exact path, or a path that
// matches a registered entry.
func (r *Registry) Find(ref string) ([]Record, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, errors.New("empty plugin reference")
	}
	var out []Record
	for _, rec := range r.Plugins {
		if strings.EqualFold(rec.Name, ref) || config.SameFile(rec.Path, ref) {
			out = append(out, rec)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no registered plugin matches %q", ref)
	}
	return out, nil
}

// Upsert registers a plugin. When an entry with the same name exists it is
// replaced, and the old record is returned so the caller can report the change
// of path.
func (r *Registry) Upsert(rec Record) (updated bool, previous Record) {
	for i := range r.Plugins {
		if strings.EqualFold(r.Plugins[i].Name, rec.Name) {
			previous = r.Plugins[i]
			r.Plugins[i] = rec
			return true, previous
		}
	}
	// Same path registered under a different name: treat it as an update too,
	// otherwise the same file would be loaded twice.
	for i := range r.Plugins {
		if config.SameFile(r.Plugins[i].Path, rec.Path) {
			previous = r.Plugins[i]
			r.Plugins[i] = rec
			return true, previous
		}
	}
	r.Plugins = append(r.Plugins, rec)
	return false, Record{}
}

// Remove drops the given records and reports how many were removed.
func (r *Registry) Remove(recs []Record) int {
	if len(recs) == 0 {
		return 0
	}
	drop := map[string]bool{}
	for _, rec := range recs {
		drop[strings.ToLower(rec.Name)+"|"+rec.Path] = true
	}
	kept := r.Plugins[:0:0]
	removed := 0
	for _, rec := range r.Plugins {
		if drop[strings.ToLower(rec.Name)+"|"+rec.Path] {
			removed++
			continue
		}
		kept = append(kept, rec)
	}
	r.Plugins = kept
	return removed
}

// RemoveAll empties the registry.
func (r *Registry) RemoveAll() int {
	n := len(r.Plugins)
	r.Plugins = nil
	return n
}

// State describes whether a registered plugin is still usable.
type State string

const (
	// StateOK means the plugin is present and matches its recorded hash.
	StateOK State = "ok"
	// StateMissing means the path no longer exists.
	StateMissing State = "missing"
	// StateChanged means the content differs from the recorded hash.
	StateChanged State = "changed"
)

// Status checks one record against the filesystem.
func Status(rec Record) (State, error) {
	if _, err := os.Stat(rec.Path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return StateMissing, nil
		}
		return StateMissing, err
	}
	if rec.Hash == "" {
		return StateOK, nil
	}
	hash, err := HashPath(rec.Path)
	if err != nil {
		return StateChanged, err
	}
	if hash != rec.Hash {
		return StateChanged, nil
	}
	return StateOK, nil
}

// HashPath fingerprints a plugin file, or a directory of plugin files, so that
// later modifications are detectable. For directories the file names are part
// of the digest, so renaming a file counts as a change.
func HashPath(path string) (string, error) {
	files, err := PluginFiles(path)
	if err != nil {
		return "", err
	}
	sum := sha256.New()
	for _, f := range files {
		raw, err := readPluginFile(f)
		if err != nil {
			return "", fmt.Errorf("cannot hash %s: %w", f, err)
		}
		inner := sha256.Sum256(raw)
		fmt.Fprintf(sum, "%s:%s\n", filepath.Base(f), hex.EncodeToString(inner[:]))
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}

// PluginFiles returns every plugin document under a path. A file must have a
// YAML extension; a directory is walked recursively, because plugin packs are
// routinely organised as web/, database/, cloud/.
//
// Hidden files and hidden directories are skipped, so a .git or an editor
// backup inside a registered directory cannot break it.
func PluginFiles(path string) ([]string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		if !hasPluginExtension(path) {
			return nil, fmt.Errorf("%s is not a .yaml or .yml file", path)
		}
		return []string{path}, nil
	}

	var out []string
	walkErr := filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if p != path && strings.HasPrefix(name, ".") {
				return fs.SkipDir
			}
			return nil
		}
		if strings.HasPrefix(name, ".") {
			return nil
		}
		if hasPluginExtension(name) {
			out = append(out, p)
		}
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil, fmt.Errorf("no plugin files (*.yaml, *.yml) in %s", path)
	}
	return out, nil
}

func hasPluginExtension(name string) bool {
	lower := strings.ToLower(name)
	for _, ext := range pluginExtensions {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}
