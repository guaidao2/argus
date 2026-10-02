package plugins

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/guaidao2/argus/internal/detect"
	"github.com/guaidao2/argus/internal/hackreason"
	"github.com/guaidao2/argus/internal/version"
)

// TestShippedExamplesParse guards the documentation. Every example argus ships
// has to keep loading, and the guide's copy-pasteable blocks are extracted from
// the markdown so a stale example fails the build instead of misleading a user.
func TestShippedExamplesParse(t *testing.T) {
	examples := filepath.Join("..", "..", "examples")
	entries, err := os.ReadDir(examples)
	if err != nil {
		t.Fatalf("examples directory is missing: %v", err)
	}
	found := 0
	for _, e := range entries {
		if e.IsDir() || !hasPluginExtension(e.Name()) {
			continue
		}
		found++
		path := filepath.Join(examples, e.Name())
		rec, skipped, err := Inspect(path)
		if err != nil {
			t.Errorf("%s does not load: %v", e.Name(), err)
			continue
		}
		if len(skipped) != 0 {
			t.Errorf("%s: unexpected skips %+v", e.Name(), skipped)
		}
		if rec.Name == "" || rec.Hash == "" {
			t.Errorf("%s produced an incomplete record: %+v", e.Name(), rec)
		}
		// The whole point of an example is that its rules compile and its notes
		// are usable, so push them through the real subsystems too.
		if err := applyToSubsystems(path); err != nil {
			t.Errorf("%s: %v", e.Name(), err)
		}
	}
	if found == 0 {
		t.Fatal("no example plugins found")
	}
}

// TestGuideExamplesParse extracts the blocks the plugin guide marks as
// testable and runs them through the same validation a real plugin gets.
func TestGuideExamplesParse(t *testing.T) {
	guides := []string{
		filepath.Join("..", "..", "docs", "plugin-guide.md"),
		filepath.Join("..", "..", "docs", "plugin-guide.zh-CN.md"),
	}
	blocks := 0
	for _, guide := range guides {
		raw, err := os.ReadFile(guide)
		if err != nil {
			t.Fatalf("cannot read %s: %v", guide, err)
		}
		for i, block := range testableBlocks(string(raw)) {
			blocks++
			if _, err := ParseDocument([]byte(block), guide, version.Version); err != nil {
				t.Errorf("%s block %d does not parse: %v\n%s", guide, i+1, err, block)
				continue
			}
			if err := applyBlock(block); err != nil {
				t.Errorf("%s block %d is not usable: %v\n%s", guide, i+1, err, block)
			}
		}
	}
	if blocks == 0 {
		t.Fatal("no testable blocks found in the guides; the marker convention broke")
	}
}

// applyToSubsystems feeds a plugin file through the fingerprint and hack-reason
// schemas, which is where a bad regex or an unknown field would surface.
func applyToSubsystems(path string) error {
	bundle, err := LoadPath(path)
	if err != nil {
		return err
	}
	for _, data := range bundle.Fingerprints {
		if _, err := detect.NewDB().AddYAMLFront(data.Raw, data.Source); err != nil {
			return err
		}
	}
	for _, data := range bundle.HackReasons {
		if _, err := hackreason.New().AddYAMLFront(data.Raw, data.Source); err != nil {
			return err
		}
	}
	return nil
}

func applyBlock(block string) error {
	doc, err := ParseDocument([]byte(block), "guide", version.Version)
	if err != nil {
		return err
	}
	b := &Bundle{}
	if err := b.add(doc); err != nil {
		return err
	}
	for _, data := range b.Fingerprints {
		if _, err := detect.NewDB().AddYAMLFront(data.Raw, data.Source); err != nil {
			return err
		}
	}
	for _, data := range b.HackReasons {
		if _, err := hackreason.New().AddYAMLFront(data.Raw, data.Source); err != nil {
			return err
		}
	}
	return nil
}

var (
	testableMarker = regexp.MustCompile(`<!--\s*testable\s*-->`)
	yamlFence      = regexp.MustCompile("(?s)```yaml\\r?\\n(.*?)```")
)

// testableBlocks returns the fenced YAML blocks that follow a <!-- testable -->
// marker.
func testableBlocks(markdown string) []string {
	var out []string
	for _, m := range testableMarker.FindAllStringIndex(markdown, -1) {
		rest := markdown[m[1]:]
		fence := yamlFence.FindStringSubmatch(rest)
		// Only accept a fence that starts within a short distance of the
		// marker, so an unrelated block further down is not picked up.
		if fence == nil || len(fence[1]) == 0 {
			continue
		}
		if idx := strings.Index(rest, "```yaml"); idx > 200 {
			continue
		}
		out = append(out, fence[1])
	}
	return out
}
