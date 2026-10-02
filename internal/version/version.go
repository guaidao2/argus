// Package version carries build metadata for argus.
//
// Version, Commit and Date are meant to be replaced at link time:
//
//	go build -ldflags "-X github.com/guaidao2/argus/internal/version.Version=1.0.0"
package version

import (
	"runtime"
	"runtime/debug"
	"strings"
)

// Name is the program name used in banners and reports.
const Name = "argus"

// Authors and License are surfaced by --version and the report header.
const (
	Authors  = "guaidao2 & coolmoon"
	License  = "MIT"
	Homepage = "https://github.com/guaidao2/argus"
)

// Injected via -ldflags. Keep the defaults sane for `go run`.
var (
	Version = "1.0.0"
	Commit  = "unknown"
	Date    = "unknown"
)

// Full returns a single line describing the build, e.g.
//
//	argus 0.1.0-dev a1b2c3d4e5f6 2025-01-01 go1.26.4 linux/amd64
func Full() string {
	parts := []string{Name + " " + Version}
	if c := revision(); c != "" {
		parts = append(parts, c)
	}
	if Date != "" && Date != "unknown" {
		parts = append(parts, Date)
	}
	parts = append(parts, runtime.Version(), runtime.GOOS+"/"+runtime.GOARCH)
	return strings.Join(parts, " ")
}

func revision() string {
	if Commit != "" && Commit != "unknown" {
		return short(Commit)
	}
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	for _, s := range bi.Settings {
		if s.Key == "vcs.revision" {
			return short(s.Value)
		}
	}
	return ""
}

func short(c string) string {
	if len(c) > 12 {
		return c[:12]
	}
	return c
}

// Compare compares two dotted version strings numerically, ignoring a leading
// "v" and any pre-release or build suffix. It returns -1, 0 or 1.
//
// It is deliberately simple: argus only needs "is the running build new enough
// for this plugin", not full semver ordering.
func Compare(a, b string) int {
	pa, pb := parseVer(a), parseVer(b)
	for i := 0; i < len(pa); i++ {
		switch {
		case pa[i] < pb[i]:
			return -1
		case pa[i] > pb[i]:
			return 1
		}
	}
	return 0
}

func parseVer(s string) [3]int {
	var out [3]int
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	if i := strings.IndexAny(s, "-+ "); i >= 0 {
		s = s[:i]
	}
	for i, part := range strings.Split(s, ".") {
		if i >= len(out) {
			break
		}
		n := 0
		for _, r := range part {
			if r < '0' || r > '9' {
				break
			}
			n = n*10 + int(r-'0')
		}
		out[i] = n
	}
	return out
}
