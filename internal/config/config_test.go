package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestResolveDirHonoursEnv: ARGUS_CONFIG_DIR is the escape hatch that makes the
// state directory testable and lets argus live on a USB stick. It has to win
// over the platform convention, not merely be consulted.
func TestResolveDirHonoursEnv(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(EnvDirName, dir)
	if got := ResolveDir(); got != dir {
		t.Errorf("ResolveDir = %q, want the override %q", got, dir)
	}
	if got, want := RegistryPath(), filepath.Join(dir, "plugins.yaml"); got != want {
		t.Errorf("RegistryPath = %q, want %q", got, want)
	}
	if got, want := ConfigPath(), filepath.Join(dir, "config.yaml"); got != want {
		t.Errorf("ConfigPath = %q, want %q", got, want)
	}
}

// TestDirFollowsThePlatformConvention is the cross-platform contract. The
// directory must not be a hardcoded ~/.argus: on Windows state belongs under
// %AppData%, and on macOS under ~/Library/Application Support. Both come from
// os.UserConfigDir, so the assertions here are about using it at all, and about
// the last path element being the app name.
func TestDirFollowsThePlatformConvention(t *testing.T) {
	t.Setenv(EnvDirName, "")
	got := Dir()
	if filepath.Base(got) != AppDir {
		t.Errorf("Dir() = %q, want its last element to be %q", got, AppDir)
	}
	base, err := os.UserConfigDir()
	if err != nil || base == "" {
		// No convention available: the documented fallback is a dot directory
		// in the home directory, and then a bare relative name.
		if !strings.HasPrefix(got, ".") && !filepath.IsAbs(got) {
			t.Errorf("Dir() = %q, want the documented fallback when UserConfigDir fails", got)
		}
		return
	}
	if want := filepath.Join(base, AppDir); got != want {
		t.Errorf("Dir() = %q, want %q", got, want)
	}
	// The path has to be built with filepath, so it uses the platform's own
	// separator rather than a forward slash on Windows.
	if runtime.GOOS == "windows" && strings.Contains(got, "/") {
		t.Errorf("Dir() = %q, want backslash separators on Windows", got)
	}
}

// TestEnsureDirIsPrivate: the registry records paths the user registered, and on
// Unix the directory is created 0700 rather than world readable. Windows has no
// equivalent mode, so this only asserts creation succeeds there.
func TestEnsureDirIsPrivate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", AppDir)
	t.Setenv(EnvDirName, dir)
	if err := EnsureDir(); err != nil {
		t.Fatalf("EnsureDir: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("EnsureDir did not create a directory")
	}
	if runtime.GOOS != "windows" {
		if perm := info.Mode().Perm(); perm != 0o700 {
			t.Errorf("mode = %o, want 700", perm)
		}
	}
	// Calling it twice must be harmless: it is called on every plugin command.
	if err := EnsureDir(); err != nil {
		t.Errorf("EnsureDir is not idempotent: %v", err)
	}
}

// TestExpandPath covers the "~" handling. Both "~/" and "~\" are accepted, so a
// path pasted from either a Unix or a Windows shell works on either platform.
func TestExpandPath(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		t.Skip("no home directory in this environment")
	}
	sep := string(os.PathSeparator)

	for _, tc := range []struct {
		in   string
		want string
	}{
		{"~", home},
		{"~" + sep + "plugins", filepath.Join(home, "plugins")},
		{"~" + "/" + "plugins", filepath.Join(home, "plugins")},
	} {
		got, err := ExpandPath(tc.in)
		if err != nil {
			t.Errorf("ExpandPath(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ExpandPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	// A relative path is made absolute, and an absolute one is left alone.
	got, err := ExpandPath("relative/thing.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(got) {
		t.Errorf("ExpandPath did not return an absolute path: %q", got)
	}
	if _, err := ExpandPath(""); err == nil {
		t.Error("ExpandPath(\"\") should be an error")
	}
}

// TestExpandPathLeavesOtherTildesAlone: only "~" on its own and "~<sep>" mean
// home. "~user/file" is a different user's directory on Unix and "~backup.yaml"
// is an ordinary filename; expanding either would silently point at the wrong
// file. The name must survive verbatim.
func TestExpandPathLeavesOtherTildesAlone(t *testing.T) {
	for _, in := range []string{"~backup.yaml", "~user/file.yaml", "sub/~odd.yaml"} {
		got, err := ExpandPath(in)
		if err != nil {
			t.Errorf("ExpandPath(%q): %v", in, err)
			continue
		}
		if !strings.HasSuffix(filepath.ToSlash(got), in) {
			t.Errorf("ExpandPath(%q) = %q, want the tilde preserved in the name", in, got)
		}
	}
}
