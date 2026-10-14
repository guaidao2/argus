package cli

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/guaidao2/argus/internal/i18n"
)

func newTestCatalog(t *testing.T) *i18n.Catalog {
	t.Helper()
	return i18n.New("en")
}

// fakeHTTP starts a listener that answers like a tiny web server and returns
// its port.
func fakeHTTP(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

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
	return ln.Addr().(*net.TCPAddr).Port
}

// run executes the CLI with captured output and an isolated state directory.
func run(t *testing.T, argv ...string) (code int, stdout, stderr string) {
	t.Helper()
	return runIn(t, t.TempDir(), argv...)
}

func TestRunVersionAndHelp(t *testing.T) {
	code, out, _ := run(t, "--version")
	if code != exitOK {
		t.Fatalf("--version exit code = %d", code)
	}
	for _, want := range []string{"argus", "Authors", "License: MIT", "guaidao2 & coolmoon"} {
		if !strings.Contains(out, want) {
			t.Errorf("--version output is missing %q:\n%s", want, out)
		}
	}

	code, out, _ = run(t, "--help")
	if code != exitOK {
		t.Fatalf("--help exit code = %d", code)
	}
	for _, want := range []string{"Usage:", "TARGET SPECIFICATION", "PLUGINS", "EXAMPLES", "--hack-reason", "--register-plugin"} {
		if !strings.Contains(out, want) {
			t.Errorf("--help output is missing %q", want)
		}
	}

	// Chinese help must be reachable only through an explicit choice.
	code, zh, _ := run(t, "--lang", "zh", "--help")
	if code != exitOK {
		t.Fatalf("--lang zh --help exit code = %d", code)
	}
	if !strings.Contains(zh, "用法：") || !strings.Contains(zh, "插件") {
		t.Errorf("Chinese help was not produced:\n%s", zh)
	}
}

func TestRunListLangs(t *testing.T) {
	code, out, _ := run(t, "--list-langs")
	if code != exitOK {
		t.Fatalf("exit code = %d", code)
	}
	if !strings.Contains(out, "en") || !strings.Contains(out, "zh") {
		t.Fatalf("--list-langs output = %q", out)
	}
}

func TestRunUsageErrors(t *testing.T) {
	if code, _, _ := run(t); code != exitUsage {
		t.Errorf("no arguments should be a usage error, got %d", code)
	}
	if code, _, _ := run(t, "--not-a-flag"); code != exitUsage {
		t.Errorf("an unknown flag should be a usage error, got %d", code)
	}
	if code, _, stderr := run(t, "-p", "not-a-port", "127.0.0.1"); code != exitUsage {
		t.Errorf("a bad port spec should be a usage error, got %d (%s)", code, stderr)
	}
	if code, _, _ := run(t, "--top-ports", "999999", "127.0.0.1"); code != exitUsage {
		t.Errorf("an oversized --top-ports should be a usage error, got %d", code)
	}
}

func TestRunScansLocalListener(t *testing.T) {
	port := fakeHTTP(t)
	code, out, stderr := run(t, "-sV", "-Pn", "-p", itoa(port), "127.0.0.1")
	if code != exitOK {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr)
	}
	for _, want := range []string{
		"Starting Argus",
		"Argus scan report for 127.0.0.1",
		"PORT",
		"open",
		"http",
		"nginx",
		"1.25.3",
		"Argus done:",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("scan output is missing %q:\n%s", want, out)
		}
	}
	if stderr != "" {
		t.Errorf("a clean scan should not write to stderr, got %q", stderr)
	}
}

func TestRunHackReasonIsOptIn(t *testing.T) {
	port := fakeHTTP(t)
	_, without, _ := run(t, "-Pn", "-p", itoa(port), "127.0.0.1")
	if strings.Contains(without, "hack-reason") {
		t.Error("hack-reason output must require --hack-reason")
	}
	_, with, _ := run(t, "-Pn", "--hack-reason", "-sV", "-p", itoa(port), "127.0.0.1")
	if !strings.Contains(with, "hack-reason") {
		t.Errorf("--hack-reason produced no notes:\n%s", with)
	}
}

func TestRunWritesOutputFiles(t *testing.T) {
	port := fakeHTTP(t)
	dir := t.TempDir()
	base := filepath.Join(dir, "scan")

	code, _, stderr := run(t, "-Pn", "-sV", "-p", itoa(port), "127.0.0.1", "-oA", base)
	if code != exitOK {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr)
	}
	for _, name := range []string{".nmap", ".xml", ".json"} {
		path := base + name
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("expected %s: %v", path, err)
		}
		if info.Size() == 0 {
			t.Errorf("%s is empty", path)
		}
	}

	raw, err := os.ReadFile(base + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Scanner string `json:"scanner"`
		Hosts   []struct {
			Ports []struct {
				Port  int    `json:"port"`
				State string `json:"state"`
			} `json:"ports"`
		} `json:"hosts"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("the generated JSON is invalid: %v", err)
	}
	if doc.Scanner != "argus" || len(doc.Hosts) != 1 {
		t.Fatalf("unexpected JSON: %+v", doc)
	}
	found := false
	for _, p := range doc.Hosts[0].Ports {
		if p.Port == port && p.State == "open" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the scanned port is missing from the JSON: %+v", doc.Hosts[0].Ports)
	}
}

func TestRunOutputAllDoesNotSwallowTargets(t *testing.T) {
	// Regression: "-oA base 127.0.0.1" once treated "base" as a scan target.
	port := fakeHTTP(t)
	dir := t.TempDir()
	code, out, stderr := run(t, "-Pn", "-p", itoa(port), "-oA", filepath.Join(dir, "x"), "127.0.0.1")
	if code != exitOK {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr)
	}
	if !strings.Contains(out, "127.0.0.1") {
		t.Errorf("the target address was lost:\n%s", out)
	}
}

func TestRunMissingPluginWarnsAndContinues(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "plugin.yaml")
	if err := os.WriteFile(path, []byte(samplePlugin), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARGUS_CONFIG_DIR", dir)

	if code, _, stderr := runIn(t, dir, "--register-plugin", path); code != exitOK {
		t.Fatalf("--register-plugin exit code = %d (%s)", code, stderr)
	}
	port := fakeHTTP(t)

	// With the plugin present the rule wins.
	_, out, _ := runIn(t, dir, "-Pn", "-sV", "-p", itoa(port), "127.0.0.1")
	if !strings.Contains(out, "PluginMarker") {
		t.Errorf("the plugin rule did not fire:\n%s", out)
	}

	// Remove the plugin: argus must warn, keep running and fall back.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	code, out, stderr := runIn(t, dir, "-Pn", "-sV", "-p", itoa(port), "127.0.0.1")
	if code != exitOK {
		t.Fatalf("a missing plugin must not change the exit code, got %d", code)
	}
	if !strings.Contains(stderr, "is gone from disk") {
		t.Errorf("expected a warning about the missing plugin, got %q", stderr)
	}
	if strings.Contains(out, "PluginMarker") {
		t.Error("a missing plugin must not contribute rules")
	}

	// --strict-plugins turns the same state into a failure.
	if code, _, _ := runIn(t, dir, "--strict-plugins", "-Pn", "-p", itoa(port), "127.0.0.1"); code != exitError {
		t.Errorf("--strict-plugins exit code = %d, want %d", code, exitError)
	}
}

func TestRunPluginListAndUnregister(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "plugin.yaml")
	if err := os.WriteFile(path, []byte(samplePlugin), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := runIn(t, dir, "--register-plugin", path); code != exitOK {
		t.Fatalf("register failed")
	}
	code, out, _ := runIn(t, dir, "--list-plugins")
	if code != exitOK || !strings.Contains(out, "sample-plugin") || !strings.Contains(out, "ok") {
		t.Fatalf("--list-plugins output = %q (code %d)", out, code)
	}
	if code, out, _ := runIn(t, dir, "--unregister-plugin", "sample-plugin"); code != exitOK {
		t.Fatalf("unregister failed: %s", out)
	}
	if code, out, _ := runIn(t, dir, "--list-plugins"); code != exitOK || !strings.Contains(out, "no plugins registered") {
		t.Fatalf("registry should be empty, got %q", out)
	}
	if code, _, _ := runIn(t, dir, "--unregister-plugin", "sample-plugin"); code != exitError {
		t.Errorf("unregistering an unknown plugin should fail, got %d", code)
	}
}

func TestRunPluginDirBypassesRegistry(t *testing.T) {
	dir := t.TempDir()
	pluginDir := t.TempDir()
	path := filepath.Join(pluginDir, "plugin.yaml")
	if err := os.WriteFile(path, []byte(samplePlugin), 0o600); err != nil {
		t.Fatal(err)
	}
	port := fakeHTTP(t)
	_, out, _ := runIn(t, dir, "-Pn", "-sV", "-p", itoa(port), "--plugin-dir", pluginDir, "127.0.0.1")
	if !strings.Contains(out, "PluginMarker") {
		t.Errorf("--plugin-dir did not load the plugin:\n%s", out)
	}
	// --no-plugins wins over everything else.
	_, out, _ = runIn(t, dir, "-Pn", "-sV", "-p", itoa(port), "--plugin-dir", pluginDir, "--no-plugins", "127.0.0.1")
	if strings.Contains(out, "PluginMarker") {
		t.Error("--no-plugins should disable plugin loading")
	}
}

func TestRunInputList(t *testing.T) {
	port := fakeHTTP(t)
	dir := t.TempDir()
	list := filepath.Join(dir, "hosts.txt")
	content := "# a comment\n127.0.0.1\n\n"
	if err := os.WriteFile(list, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, stderr := run(t, "-Pn", "-p", itoa(port), "-iL", list)
	if code != exitOK {
		t.Fatalf("exit code = %d (%s)", code, stderr)
	}
	if !strings.Contains(out, "127.0.0.1") {
		t.Errorf("the input list was not used:\n%s", out)
	}
}

func TestRunOutputToStdoutWithDash(t *testing.T) {
	port := fakeHTTP(t)
	code, out, stderr := run(t, "-Pn", "-p", itoa(port), "--jsonl", "-oJ", "-", "127.0.0.1")
	if code != exitOK {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr)
	}
	// The JSON host line and the normal report share stdout, so look for the
	// JSON object shape rather than parsing the whole stream.
	if !strings.Contains(out, `"type":"host"`) {
		t.Errorf("-oJ - should stream JSON to stdout:\n%s", out)
	}
	if !strings.Contains(out, "PORT") {
		t.Errorf("the normal report should still appear:\n%s", out)
	}
}

func TestRunResolveAllAndExclude(t *testing.T) {
	code, _, stderr := run(t, "-Pn", "-p", "80", "--exclude", "127.0.0.1", "127.0.0.1")
	if code != exitUsage {
		t.Fatalf("excluding the only target should be a usage error, got %d (%s)", code, stderr)
	}
}

// runIn runs the CLI with an explicit state directory.
func runIn(t *testing.T, configDir string, argv ...string) (code int, stdout, stderr string) {
	t.Helper()
	t.Setenv("ARGUS_CONFIG_DIR", configDir)
	var out, errBuf bytes.Buffer
	code = Run(argv, strings.NewReader(""), &out, &errBuf)
	return code, out.String(), errBuf.String()
}

func itoa(n int) string { return strconv.Itoa(n) }

const samplePlugin = `
apiVersion: argus.plugin/v1
name: sample-plugin
version: 9.9.9
author: tester
license: MIT
description: a plugin used by the CLI tests
fingerprints:
  apiVersion: argus.fingerprint/v1
  id: sample-fp
  rules:
    - id: sample-marker
      probes:
        - id: get
          send: "GET / HTTP/1.0\r\nHost: {{host}}\r\n\r\n"
          read_timeout: 3s
      matches:
        - id: marker
          pattern: '(?i)^HTTP/1\.[01] 200'
          set: {service: sample-http, product: PluginMarker, version: 9.9.9}
hack_reasons:
  apiVersion: argus.hackreason/v1
  id: sample-hr
  entries:
    - id: sample-note
      ports: [1]
      title: {en: Sample, zh: 示例}
      points: {en: [sample point], zh: [示例要点]}
`

// TestRunAutoScanType covers --scan-type auto: argus probes the environment at
// startup and picks, then says what it picked. The choice must be stated, not
// implied, because connect and SYN do not produce equivalent result sets.
func TestRunAutoScanType(t *testing.T) {
	port := fakeHTTP(t)

	// A loopback target always ends up on connect, whether or not the raw
	// socket could be opened, and the report must say why.
	code, out, stderr := run(t, "-Pn", "--scan-type", "auto", "-p", itoa(port), "127.0.0.1")
	if code != exitOK {
		t.Fatalf("auto scan exit code = %d, stderr = %s", code, stderr)
	}
	if !strings.Contains(out, "Scan technique: TCP connect (auto-selected:") {
		t.Errorf("auto should explain its choice:\n%s", out)
	}
	// Which reason is given depends on the platform, not on the flag: a build
	// with no raw socket support at all, a socket it may not open, or a target
	// that is local. Checking against the catalog rather than against one
	// platform's wording is what keeps this test honest everywhere, and it is
	// also what made it fail on Windows until now.
	tr := newTestCatalog(t)
	explained := false
	for _, key := range []string{"reason.local_targets", "reason.syn_privileges", "reason.syn_unsupported"} {
		if strings.Contains(out, tr.T(key)) {
			explained = true
		}
	}
	if !explained {
		t.Errorf("the reason is missing:\n%s", out)
	}
}

func TestRunRejectsUnknownScanType(t *testing.T) {
	code, _, stderr := run(t, "--scan-type", "bogus", "-p", "80", "127.0.0.1")
	if code != exitUsage {
		t.Fatalf("an unknown --scan-type should be a usage error, got %d", code)
	}
	if !strings.Contains(stderr, "bogus") {
		t.Errorf("the error should name the bad value, got %q", stderr)
	}
}

// TestRunExplicitSYNSaysWhyNot is the explicit-request counterpart: asking for
// SYN against a local target must not silently pretend to be a SYN scan.
func TestRunExplicitSYNSaysWhyNot(t *testing.T) {
	port := fakeHTTP(t)
	code, out, stderr := run(t, "-Pn", "-sS", "-p", itoa(port), "127.0.0.1")
	if code != exitOK {
		t.Skipf("SYN scan unavailable here: %s", stderr)
	}
	if !strings.Contains(out, "Scan technique: TCP connect (these targets are local addresses)") {
		t.Errorf("-sS against loopback must report connect and say why:\n%s", out)
	}
}

// fakeRedisListener answers the Redis protocol on a random port so the check
// path can be exercised end to end.
func fakeRedisListener(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	info := "redis_version:7.2.4\r\nredis_mode:standalone\r\n"
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				buf := make([]byte, 512)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						cmd := strings.ToUpper(strings.Fields(string(buf[:n]))[0])
						switch {
						case strings.HasPrefix(cmd, "INFO"):
							_, _ = c.Write([]byte("$" + strconv.Itoa(len(info)) + "\r\n" + info + "\r\n"))
						case strings.HasPrefix(cmd, "PING"):
							_, _ = c.Write([]byte("+PONG\r\n"))
						default:
							_, _ = c.Write([]byte("-ERR unknown command\r\n"))
						}
					}
					if err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestRunFindingsAreOptIn(t *testing.T) {
	port := fakeRedisListener(t)
	dir := t.TempDir()
	pluginPath := filepath.Join(dir, "redis-any-port.yaml")
	if err := os.WriteFile(pluginPath, []byte(redisAnyPortPlugin), 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"-Pn", "-sV", "--plugin-dir", pluginPath, "-p", itoa(port), "127.0.0.1"}

	// Identification only: the service is named, nothing is concluded.
	code, out, stderr := run(t, args...)
	if code != exitOK {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr)
	}
	if !strings.Contains(out, "redis") {
		t.Fatalf("the plugin should have identified Redis:\n%s", out)
	}
	if strings.Contains(out, "check:") {
		t.Errorf("a scan without --findings must not report findings:\n%s", out)
	}

	// With --findings the check runs.
	code, out, stderr = run(t, append(append([]string{}, args...), "--findings")...)
	if code != exitOK {
		t.Fatalf("--findings exit code = %d, stderr = %s", code, stderr)
	}
	if !strings.Contains(out, "check: Redis: unauthenticated access [HIGH]") {
		t.Errorf("the finding is missing:\n%s", out)
	}
}

func TestRunFindingsAppearInJSONAndXML(t *testing.T) {
	port := fakeRedisListener(t)
	dir := t.TempDir()
	pluginPath := filepath.Join(dir, "redis-any-port.yaml")
	if err := os.WriteFile(pluginPath, []byte(redisAnyPortPlugin), 0o600); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(dir, "scan")
	code, _, stderr := run(t, "-Pn", "-sV", "--findings", "--plugin-dir", pluginPath,
		"-p", itoa(port), "127.0.0.1", "-oA", base)
	if code != exitOK {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr)
	}

	raw, err := os.ReadFile(base + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Hosts []struct {
			Ports []struct {
				Findings []struct {
					Severity string `json:"severity"`
				} `json:"findings"`
			} `json:"ports"`
		} `json:"hosts"`
		Summary struct {
			Findings int `json:"findings"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Summary.Findings != 1 {
		t.Fatalf("summary.findings = %d", doc.Summary.Findings)
	}
	if len(doc.Hosts[0].Ports[0].Findings) != 1 || doc.Hosts[0].Ports[0].Findings[0].Severity != "high" {
		t.Fatalf("findings = %+v", doc.Hosts[0].Ports[0].Findings)
	}

	xmlRaw, err := os.ReadFile(base + ".xml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(xmlRaw), "<script") {
		t.Error("the XML should carry findings as script elements")
	}
}

const redisAnyPortPlugin = `
apiVersion: argus.plugin/v1
name: redis-any-port
version: 1.0.0
description: identify Redis wherever it listens
fingerprints:
  apiVersion: argus.fingerprint/v1
  id: redis-any-port
  rules:
    - id: redis-on-any-port
      probes:
        - id: ping
          send: "PING\r\n"
          read_timeout: 2s
      matches:
        - id: pong
          pattern: '(?m)^\+PONG'
          set: {service: redis, product: Redis}
`

// TestRunAppendOutputKeepsStructuredFilesParseable: appending a second XML or
// JSON document produces a file no parser will read, so those two formats are
// rewritten with a warning while the text formats still append.
func TestRunAppendOutputKeepsStructuredFilesParseable(t *testing.T) {
	port := fakeHTTP(t)
	dir := t.TempDir()
	base := filepath.Join(dir, "scan")
	args := []string{"-Pn", "-p", itoa(port), "127.0.0.1", "-oA", base}

	if code, _, stderr := run(t, args...); code != exitOK {
		t.Fatalf("first run failed: %d %s", code, stderr)
	}
	code, _, stderr := run(t, append(append([]string{}, args...), "--append-output")...)
	if code != exitOK {
		t.Fatalf("second run failed: %d %s", code, stderr)
	}
	if !strings.Contains(stderr, "cannot be appended to") {
		t.Errorf("the user should be told the structured formats were rewritten, got %q", stderr)
	}

	xmlRaw, err := os.ReadFile(base + ".xml")
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(xmlRaw), "<nmaprun"); n != 1 {
		t.Errorf("the XML file holds %d documents, want 1", n)
	}
	jsonRaw, err := os.ReadFile(base + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(jsonRaw, &doc); err != nil {
		t.Errorf("the JSON file no longer parses as one document: %v", err)
	}

	// The text format still appends, which is what --append-output is for.
	normalRaw, err := os.ReadFile(base + ".nmap")
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(normalRaw), "scan report"); n != 2 {
		t.Errorf("normal output holds %d reports, want 2 (append should work)", n)
	}
}

// TestRunJSONLAppends: JSON Lines is one document per line, so appending is
// valid there and must not be disabled.
func TestRunJSONLAppends(t *testing.T) {
	port := fakeHTTP(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "scan.jsonl")
	args := []string{"-Pn", "-p", itoa(port), "--jsonl", "-oJ", path, "127.0.0.1"}
	if code, _, stderr := run(t, args...); code != exitOK {
		t.Fatalf("first run failed: %d %s", code, stderr)
	}
	if code, _, stderr := run(t, append(append([]string{}, args...), "--append-output")...); code != exitOK {
		t.Fatalf("second run failed: %d %s", code, stderr)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := 0
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			t.Fatalf("line %d is not valid JSON: %v", lines+1, err)
		}
		lines++
	}
	if lines != 4 {
		t.Errorf("JSONL holds %d lines, want 4 (two runs of host + summary)", lines)
	}
}

// TestRunReportsLatencyWithPn: -Pn skips host discovery, so nothing had
// measured a round trip by the time the host line was built, and the latency
// was left at zero. "Host is up (0.00000s latency)" reads as a perfect network
// rather than as a number nobody took - nmap reports the real figure. The port
// probes do measure round trips, so that is what gets reported now.
func TestRunReportsLatencyWithPn(t *testing.T) {
	port := fakeHTTP(t)
	code, out, stderr := run(t, "-Pn", "-p", itoa(port), "127.0.0.1")
	if code != exitOK {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr)
	}
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "Host is up") {
			continue
		}
		if strings.Contains(line, "0.00000s") {
			t.Errorf("-Pn printed a zero latency although the port probe measured one: %q", line)
		}
		return
	}
	t.Fatalf("no \"Host is up\" line in the output:\n%s", out)
}
