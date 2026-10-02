package plugins

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guaidao2/argus/internal/version"
)

const goodPlugin = `
apiVersion: argus.plugin/v1
name: example
version: 1.2.3
author: tester
license: MIT
argus_min_version: 0.1.0
description: an example plugin
vars:
  key: value
fingerprints:
  apiVersion: argus.fingerprint/v1
  id: example-fp
  rules:
    - id: example-rule
      ports: [1234]
      probes: [{id: p, send: ""}]
      matches: [{id: m, pattern: 'x', set: {service: exam} }]
hack_reasons:
  apiVersion: argus.hackreason/v1
  id: example-hr
  entries:
    - id: example-note
      ports: [1234]
      title: {en: Example, zh: 示例}
      points: {en: [one], zh: [一]}
`

func write(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func TestInspectAndRegistryLifecycle(t *testing.T) {
	dir := t.TempDir()
	path := write(t, dir, "example.yaml", goodPlugin)

	rec, _, err := Inspect(path)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if rec.Name != "example" || rec.Kind != "file" || rec.Hash == "" {
		t.Fatalf("Inspect returned %+v", rec)
	}
	if rec.Version != "1.2.3" {
		t.Errorf("version not captured: %+v", rec)
	}
	if !rec.Enabled {
		t.Error("newly registered plugins must be enabled")
	}

	regPath := filepath.Join(dir, "plugins.yaml")
	reg, err := Load(regPath)
	if err != nil {
		t.Fatalf("Load of a missing registry should be empty, got %v", err)
	}
	if len(reg.Plugins) != 0 {
		t.Fatal("a fresh registry must be empty")
	}

	updated, previous := reg.Upsert(rec)
	if updated || previous.Name != "" {
		t.Fatalf("first registration should not be an update: %v %v", updated, previous)
	}
	if err := reg.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Re-registering the same name from a different path updates in place.
	moved := write(t, dir, "moved.yaml", goodPlugin)
	rec2, _, err := Inspect(moved)
	if err != nil {
		t.Fatal(err)
	}
	updated, previous = reg.Upsert(rec2)
	if !updated || previous.Path != path {
		t.Fatalf("re-registration should update the record: updated=%v previous=%+v", updated, previous)
	}
	if len(reg.Plugins) != 1 {
		t.Fatalf("registry should still hold one plugin, got %d", len(reg.Plugins))
	}
	if reg.Plugins[0].Path != moved {
		t.Fatalf("the new path must win, got %s", reg.Plugins[0].Path)
	}
	if err := reg.Save(); err != nil {
		t.Fatalf("Save after update: %v", err)
	}

	// Reloading from disk must reproduce the same state.
	reloaded, err := Load(regPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.Plugins) != 1 || reloaded.Plugins[0].Path != moved {
		t.Fatalf("reloaded registry = %+v", reloaded.Plugins)
	}
	if state, _ := Status(reloaded.Plugins[0]); state != StateOK {
		t.Fatalf("state = %v", state)
	}

	// Removing by name empties the registry.
	found, err := reloaded.Find("example")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if n := reloaded.Remove(found); n != 1 {
		t.Fatalf("Remove removed %d records", n)
	}
	if len(reloaded.Plugins) != 0 {
		t.Fatal("registry should be empty after removal")
	}
	if _, err := reloaded.Find("example"); err == nil {
		t.Error("Find should fail for an unknown reference")
	}
}

func TestStatusDetectsMissingAndChanged(t *testing.T) {
	dir := t.TempDir()
	path := write(t, dir, "p.yaml", goodPlugin)
	rec, _, err := Inspect(path)
	if err != nil {
		t.Fatal(err)
	}

	if state, _ := Status(rec); state != StateOK {
		t.Fatalf("state = %v, want ok", state)
	}

	// A modification after registration is reported, without failing.
	write(t, dir, "p.yaml", goodPlugin+"\n# touched\n")
	if state, _ := Status(rec); state != StateChanged {
		t.Fatalf("state = %v, want changed", state)
	}

	// Deleting the file is reported as missing.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if state, _ := Status(rec); state != StateMissing {
		t.Fatalf("state = %v, want missing", state)
	}
}

func TestHashPathCoversDirectoryContents(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "a.yaml", goodPlugin)
	write(t, dir, "b.yml", goodPlugin)
	write(t, dir, "ignored.txt", "not a plugin")

	hash1, err := HashPath(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Touching an unrelated file must not change the hash.
	write(t, dir, "ignored.txt", "still not a plugin")
	hash2, err := HashPath(dir)
	if err != nil {
		t.Fatal(err)
	}
	if hash1 != hash2 {
		t.Error("the hash should ignore non-plugin files")
	}
	// Changing a plugin file must change it.
	write(t, dir, "b.yml", goodPlugin+"\n# changed\n")
	hash3, err := HashPath(dir)
	if err != nil {
		t.Fatal(err)
	}
	if hash3 == hash1 {
		t.Error("changing a plugin file must change the directory hash")
	}
	if len(hash1) != hex.EncodedLen(32) {
		t.Errorf("hash length = %d, want a hex encoded sha256", len(hash1))
	}
}

func TestPluginFilesRejectsNonYAML(t *testing.T) {
	dir := t.TempDir()
	path := write(t, dir, "readme.txt", "hello")
	if _, err := PluginFiles(path); err == nil {
		t.Error("a non-YAML file must be rejected")
	}
	empty := t.TempDir()
	if _, err := PluginFiles(empty); err == nil {
		t.Error("an empty directory must be rejected")
	}
}

func TestParseDocumentValidation(t *testing.T) {
	cases := map[string]string{
		"missing apiVersion": `
name: x
fingerprints: {apiVersion: argus.fingerprint/v1, id: a, rules: []}
`,
		"newer apiVersion": `
apiVersion: argus.plugin/v2
name: x
fingerprints: {apiVersion: argus.fingerprint/v1, id: a, rules: []}
`,
		"missing name": `
apiVersion: argus.plugin/v1
fingerprints: {apiVersion: argus.fingerprint/v1, id: a, rules: []}
`,
		"future argus": `
apiVersion: argus.plugin/v1
name: x
argus_min_version: 99.0.0
fingerprints: {apiVersion: argus.fingerprint/v1, id: a, rules: []}
`,
		"no content": `
apiVersion: argus.plugin/v1
name: x
`,
	}
	for name, doc := range cases {
		if _, err := ParseDocument([]byte(doc), "test", version.Version); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if _, err := ParseDocument([]byte(goodPlugin), "test", version.Version); err != nil {
		t.Fatalf("a valid plugin was rejected: %v", err)
	}
}

func TestLoadRegisteredReportsDrift(t *testing.T) {
	dir := t.TempDir()
	path := write(t, dir, "p.yaml", goodPlugin)
	rec, _, err := Inspect(path)
	if err != nil {
		t.Fatal(err)
	}
	reg := &Registry{Version: RegistryVersion, Plugins: []Record{rec}}

	bundle, err := LoadRegistered(reg, false)
	if err != nil {
		t.Fatalf("LoadRegistered: %v", err)
	}
	if len(bundle.Fingerprints) != 1 || len(bundle.HackReasons) != 1 {
		t.Fatalf("bundle = %d fingerprints, %d hack reasons", len(bundle.Fingerprints), len(bundle.HackReasons))
	}
	if bundle.Vars["key"] != "value" {
		t.Errorf("plugin vars were not captured: %v", bundle.Vars)
	}
	if len(bundle.Names) != 1 || bundle.Names[0] != "example" {
		t.Errorf("names = %v", bundle.Names)
	}

	// Missing plugin: reported, not fatal, and no data loaded.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	bundle, err = LoadRegistered(reg, false)
	if err != nil {
		t.Fatalf("a missing plugin must not be fatal: %v", err)
	}
	if len(bundle.Missing) != 1 {
		t.Fatalf("missing = %+v", bundle.Missing)
	}
	if !bundle.IsEmpty() {
		t.Error("a missing plugin must contribute no rules")
	}

	// Strict mode turns the same situation into an error.
	if _, err := LoadRegistered(reg, true); err == nil {
		t.Error("strict mode must fail on a missing plugin")
	}
}

func TestDisabledPluginsAreSkipped(t *testing.T) {
	dir := t.TempDir()
	path := write(t, dir, "p.yaml", goodPlugin)
	rec, _, err := Inspect(path)
	if err != nil {
		t.Fatal(err)
	}
	rec.Enabled = false
	reg := &Registry{Version: RegistryVersion, Plugins: []Record{rec}}
	bundle, err := LoadRegistered(reg, false)
	if err != nil {
		t.Fatal(err)
	}
	if !bundle.IsEmpty() {
		t.Error("a disabled plugin must not be loaded")
	}
}

func TestLoadPathMultiDocument(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "one.yaml", goodPlugin)
	write(t, dir, "two.yaml", goodPlugin)
	bundle, err := LoadPath(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.Fingerprints) != 2 || len(bundle.HackReasons) != 2 {
		t.Fatalf("bundle = %d/%d", len(bundle.Fingerprints), len(bundle.HackReasons))
	}
}

func TestRegistryRefusesNewerVersion(t *testing.T) {
	dir := t.TempDir()
	path := write(t, dir, "plugins.yaml", "version: 99\nplugins: []\n")
	if _, err := Load(path); err == nil {
		t.Fatal("a registry from a newer argus must be refused")
	}
}

func TestRecordTimestampsAreUTC(t *testing.T) {
	dir := t.TempDir()
	path := write(t, dir, "p.yaml", goodPlugin)
	rec, _, err := Inspect(path)
	if err != nil {
		t.Fatal(err)
	}
	if loc := rec.RegisteredAt.Location(); loc != time.UTC {
		t.Fatalf("registered_at should be UTC, got %v", loc)
	}
}

// TestPluginFilesWalksSubdirectories is the fix for a real gap: a pack
// organised as web/, db/, cloud/ used to register successfully while loading
// only the files sitting in the top level, with no warning at all.
func TestPluginFilesWalksSubdirectories(t *testing.T) {
	dir := t.TempDir()
	for _, sub := range []string{"web", filepath.Join("db", "nested"), ".hidden"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write(t, dir, "top.yaml", goodPlugin)
	write(t, filepath.Join(dir, "web"), "a.yaml", goodPlugin)
	write(t, filepath.Join(dir, "db", "nested"), "b.yml", goodPlugin)
	write(t, filepath.Join(dir, ".hidden"), "c.yaml", goodPlugin)
	write(t, dir, ".dotfile.yaml", goodPlugin)
	write(t, dir, "notes.md", "not a plugin")

	files, err := PluginFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 3 {
		t.Fatalf("expected 3 plugin files (top, web/a, db/nested/b), got %d: %v", len(files), files)
	}
	for _, f := range files {
		if strings.Contains(f, ".hidden") || strings.Contains(f, ".dotfile") {
			t.Errorf("hidden files must be skipped, got %s", f)
		}
	}
}

func TestDirectoryRegistrationUsesTheDirectoryName(t *testing.T) {
	root := t.TempDir()
	pack := filepath.Join(root, "redteam-pack")
	if err := os.MkdirAll(pack, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, pack, "one.yaml", goodPlugin)
	if err := os.MkdirAll(filepath.Join(pack, "web"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(pack, "web"), "two.yaml", goodPlugin)

	rec, skipped, err := Inspect(pack)
	if err != nil {
		t.Fatal(err)
	}
	if len(skipped) != 0 {
		t.Fatalf("nothing should be skipped: %+v", skipped)
	}
	// The name has to be something the user can type back into
	// --unregister-plugin, so it is the directory name, not a document name
	// with a document count glued on.
	if rec.Name != "redteam-pack" {
		t.Fatalf("record name = %q, want the directory name", rec.Name)
	}
	if rec.Kind != "dir" {
		t.Fatalf("kind = %q", rec.Kind)
	}
	if !strings.Contains(rec.Description, "2 document(s)") {
		t.Errorf("the description should summarise the pack: %q", rec.Description)
	}
	if strings.Contains(rec.Version, ", ") && strings.Count(rec.Version, "1.2.3") > 1 {
		t.Errorf("versions should be de-duplicated, got %q", rec.Version)
	}
}

// TestDirectorySkipsNonPluginFiles: a pack directory legitimately holds a
// README or a values file next to its plugins, so those are reported rather
// than fatal.
func TestDirectorySkipsNonPluginFiles(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "good.yaml", goodPlugin)
	write(t, dir, "values.yaml", "replicas: 3\nimage: nginx\n")

	rec, skipped, err := Inspect(dir)
	if err != nil {
		t.Fatalf("a mixed directory must still register: %v", err)
	}
	if rec.Name != filepath.Base(dir) {
		t.Fatalf("name = %q", rec.Name)
	}
	if len(skipped) != 1 || !strings.HasSuffix(skipped[0].Path, "values.yaml") {
		t.Fatalf("the non-plugin file should be reported, got %+v", skipped)
	}
	if skipped[0].Reason == "" {
		t.Error("a skip needs a reason")
	}
}

// TestSingleFileIsNotTolerant is the other half: when the user names one file
// explicitly, a file that is not a plugin is an error, not a quiet skip.
func TestSingleFileIsNotTolerant(t *testing.T) {
	dir := t.TempDir()
	path := write(t, dir, "not-a-plugin.yaml", "hello: world\n")
	if _, _, err := Inspect(path); err == nil {
		t.Fatal("naming a non-plugin file explicitly must fail")
	}
}

func TestDirectoryWithNothingUsableFails(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "a.yaml", "nope: true\n")
	write(t, dir, "b.yaml", "also: not a plugin\n")
	if _, _, err := Inspect(dir); err == nil {
		t.Fatal("a directory with no usable plugin documents must fail")
	}
}

// TestCollectKeepsPartialDirectory checks that one bad file does not take the
// rest of the pack down with it.
func TestCollectKeepsPartialDirectory(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "good.yaml", goodPlugin)
	write(t, dir, "broken.yaml", "apiVersion: argus.plugin/v1\nname: broken\nfingerprints: {apiVersion: argus.fingerprint/v1, id: x, rules: [{id: r, matches: [{id: m, pattern: '([', set: {}}]}]}}\n")

	b, err := LoadPath(dir)
	if err != nil {
		t.Fatalf("a broken sibling must not fail the pack: %v", err)
	}
	if len(b.Docs) != 1 {
		t.Fatalf("the good document should still load, got %d", len(b.Docs))
	}
	if len(b.Skipped) != 1 {
		t.Fatalf("the broken document should be reported, got %+v", b.Skipped)
	}
}
