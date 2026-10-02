// Package config resolves the on-disk location of argus state: the plugin
// registry and the optional config file.
//
// The directory follows each platform's convention instead of hardcoding
// ~/.argus, so the tool behaves natively everywhere:
//
//	Linux   $XDG_CONFIG_HOME/argus  or  ~/.config/argus
//	macOS   ~/Library/Application Support/argus
//	Windows %AppData%\argus
//
// Set ARGUS_CONFIG_DIR to relocate everything (useful for tests and for
// keeping a portable copy of argus on a USB stick).
package config

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// AppDir is the per-user directory name.
const AppDir = "argus"

// EnvDirName lets tests and power users relocate state.
const EnvDirName = "ARGUS_CONFIG_DIR"

// Dir returns the conventional state directory (without the env override).
func Dir() string {
	if d, err := os.UserConfigDir(); err == nil && d != "" {
		return filepath.Join(d, AppDir)
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, "."+AppDir)
	}
	return "." + AppDir
}

// ResolveDir returns the state directory, honouring ARGUS_CONFIG_DIR.
func ResolveDir() string {
	if v := os.Getenv(EnvDirName); v != "" {
		return v
	}
	return Dir()
}

// RegistryPath is the plugin registry file.
func RegistryPath() string { return filepath.Join(ResolveDir(), "plugins.yaml") }

// ConfigPath is the optional config file.
func ConfigPath() string { return filepath.Join(ResolveDir(), "config.yaml") }

// EnsureDir creates the state directory with owner-only permissions.
func EnsureDir() error {
	return os.MkdirAll(ResolveDir(), 0o700)
}

// WriteFileAtomic writes data through a temp file + rename so that a crash or
// a full disk never leaves a truncated registry behind.
func WriteFileAtomic(path string, data []byte, perm fs.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()

	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Insecure reports whether path can be modified by a user other than its
// owner. argus is frequently run as root (SYN scan, privileged ports), and
// loading configuration that a local unprivileged user can rewrite would be a
// local privilege-escalation path, so callers warn when this is true.
//
// On Windows the POSIX mode bits are meaningless, so it always returns false.
func Insecure(path string) bool {
	if runtime.GOOS == "windows" {
		return false
	}
	fi, err := os.Stat(path)
	if err != nil {
		return false
	}
	mode := fi.Mode().Perm()
	return mode&0o022 != 0
}

// SameFile reports whether two paths refer to the same file, tolerating
// non-existent paths by falling back to a lexical comparison of cleaned
// absolute paths.
func SameFile(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	fa, ea := os.Stat(a)
	fb, eb := os.Stat(b)
	if ea == nil && eb == nil {
		return os.SameFile(fa, fb)
	}
	aa, e1 := filepath.Abs(a)
	ab, e2 := filepath.Abs(b)
	if e1 != nil || e2 != nil {
		return filepath.Clean(a) == filepath.Clean(b)
	}
	return filepath.Clean(aa) == filepath.Clean(ab)
}

// ErrNoHome is returned when a path expansion needs a home directory that does
// not exist.
var ErrNoHome = errors.New("cannot determine user home directory")

// ExpandPath resolves a user-supplied path: "~" and "~/x" are expanded against
// the current user's home directory and the result is made absolute.
func ExpandPath(p string) (string, error) {
	if p == "" {
		return "", errors.New("empty path")
	}
	if p == "~" || strings.HasPrefix(p, "~/") || strings.HasPrefix(p, "~"+string(os.PathSeparator)) {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return "", ErrNoHome
		}
		if len(p) == 1 {
			p = home
		} else {
			p = filepath.Join(home, p[2:])
		}
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	// Resolve symlinks so that the registry records a stable identity.
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return resolved, nil
	}
	return abs, nil
}
