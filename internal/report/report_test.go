package report

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"
	"time"

	"github.com/guaidao2/argus/internal/i18n"
	"github.com/guaidao2/argus/internal/model"
)

func fixture() *model.Result {
	start := time.Date(2025, 3, 4, 5, 6, 7, 0, time.UTC)
	return &model.Result{
		Args:         "argus -sV -p 22,80,8080 192.0.2.10",
		Start:        start,
		End:          start.Add(1500 * time.Millisecond),
		ScanType:     "connect",
		Protocols:    []string{"tcp"},
		NumServices:  3,
		ServicesSpec: "22,80,8080/tcp",
		Targets:      []string{"192.0.2.10"},
		PluginNames:  []string{"example"},
		Hosts: []model.Host{
			{
				Address:  "192.0.2.10",
				AddrType: "ipv4",
				Status:   "up",
				Reason:   model.ReasonSynAck,
				Latency:  1234 * time.Microsecond,
				SRTT:     1200 * time.Microsecond,
				RTTVar:   100 * time.Microsecond,
				Timeout:  3 * time.Second,
				Start:    start,
				End:      start.Add(time.Second),
				Ports: []model.Port{
					{
						Port: 22, Proto: "tcp", State: model.StateOpen, Reason: model.ReasonSynAck,
						Service: &model.Service{
							Name: "ssh", Product: "OpenSSH", Version: "8.9p1",
							ExtraInfo: "Ubuntu 3", OSType: "Ubuntu Linux", Method: "probed", Conf: 10,
							CPEs: []string{"cpe:/a:openbsd:openssh"},
							Hack: []model.HackNote{{
								ID: "ssh", Title: "SSH remote administration",
								Points: []string{"Check the auth methods"}, Tools: []string{"ssh-audit"},
								Refs: []string{"https://example.invalid/ssh"},
							}},
						},
					},
					{
						Port: 80, Proto: "tcp", State: model.StateOpen, Reason: model.ReasonSynAck,
						Service: &model.Service{Name: "http", Product: "nginx", Version: "1.24.0", Method: "probed", Conf: 10},
					},
					{Port: 8080, Proto: "tcp", State: model.StateClosed, Reason: model.ReasonConnRefused},
					{Port: 8443, Proto: "tcp", State: model.StateFiltered, Reason: model.ReasonNoResponse},
				},
			},
			{
				Address:     "192.0.2.11",
				AddrType:    "ipv4",
				Status:      "down",
				Reason:      model.ReasonNoResponse,
				ScanSkipped: true,
			},
		},
	}
}

func opts(lang string, hack bool) Options {
	return Options{Tr: i18n.New(lang), HackReason: hack}
}

func TestNormalOutputStructure(t *testing.T) {
	var buf bytes.Buffer
	if err := Normal(&buf, fixture(), opts("en", false)); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	for _, want := range []string{
		"Starting Argus",
		"Argus scan report for 192.0.2.10",
		"Host is up (0.00123s latency).",
		"Not shown: 1 closed tcp port (conn-refused), 1 filtered tcp port (no-response)",
		"PORT",
		"22/tcp",
		"OpenSSH 8.9p1 (Ubuntu 3; Ubuntu Linux)",
		"nginx 1.24.0",
		"Argus done: 2 IP addresses (1 host up) scanned in 1.50 seconds",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("normal output is missing %q\n---\n%s", want, out)
		}
	}
	// Hosts reported down do not get a full report block, exactly like nmap;
	// they are summarised in one notice line instead.
	if strings.Contains(out, "Argus scan report for 192.0.2.11") {
		t.Error("a host that was reported down should not get a report block")
	}
	if !strings.Contains(out, "Note: 1 host(s) seem down") {
		t.Errorf("the down hosts should be summarised:\n%s", out)
	}
	// Closed and filtered ports never appear as port lines.
	if strings.Contains(out, "8080/tcp") || strings.Contains(out, "8443/tcp") {
		t.Error("non-open ports must be collapsed into the Not shown line")
	}
}

func TestNormalOutputChinese(t *testing.T) {
	var buf bytes.Buffer
	if err := Normal(&buf, fixture(), opts("zh", false)); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"启动 Argus",
		"Argus 扫描报告 192.0.2.10",
		"主机在线",
		"端口",
		"状态",
		"服务",
		"版本",
		"Argus 完成：扫描 2 个 IP 地址（1 台主机在线）",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("Chinese output is missing %q\n---\n%s", want, out)
		}
	}
	if strings.Contains(out, "PORT") {
		t.Error("the English column header leaked into Chinese output")
	}
}

func TestNormalOutputHackReasonAndReason(t *testing.T) {
	o := opts("en", true)
	o.ShowReason = true
	var buf bytes.Buffer
	if err := Normal(&buf, fixture(), o); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	if !strings.Contains(out, "REASON") {
		t.Error("--reason should add a REASON column")
	}
	if !strings.Contains(out, "syn-ack") {
		t.Error("the reason value is missing")
	}
	if !strings.Contains(out, "| hack-reason: SSH remote administration") {
		t.Errorf("the hack-reason block is malformed:\n%s", out)
	}
	if !strings.Contains(out, "|_refs: https://example.invalid/ssh") {
		t.Errorf("the last detail line should use the |_ prefix:\n%s", out)
	}
	// The block uses nmap's pipe prefix exactly once per line.
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "|") && !strings.HasPrefix(line, "| ") && !strings.HasPrefix(line, "|_") {
			t.Errorf("malformed detail line: %q", line)
		}
	}
}

func TestNormalHackReasonIsOptIn(t *testing.T) {
	var buf bytes.Buffer
	if err := Normal(&buf, fixture(), opts("en", false)); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "hack-reason") {
		t.Error("hack-reason notes must only appear with --hack-reason")
	}
}

func TestNormalVerboseShowsDownHosts(t *testing.T) {
	o := opts("en", false)
	o.Verbose = 1
	var buf bytes.Buffer
	if err := Normal(&buf, fixture(), o); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "Argus scan report for 192.0.2.11") {
		t.Error("-v should report down hosts individually")
	}
	if !strings.Contains(out, "Host seems down.") {
		t.Error("the down host needs its status line")
	}
	if strings.Contains(out, "Note: 1 host(s) seem down") {
		t.Error("with -v the summary notice should not be duplicated")
	}
}

func TestNormalShowsOpenOnlyFiltering(t *testing.T) {
	res := fixture()
	res.Hosts[0].Ports = []model.Port{
		{Port: 8080, Proto: "tcp", State: model.StateClosed, Reason: model.ReasonConnRefused},
	}
	var buf bytes.Buffer
	if err := Normal(&buf, res, opts("en", false)); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "PORT") {
		t.Errorf("a host with no open ports should not print a table:\n%s", out)
	}
	if !strings.Contains(out, "Not shown: 1 closed tcp port") {
		t.Errorf("the summary line is missing:\n%s", out)
	}
}

func TestNormalInterrupted(t *testing.T) {
	res := fixture()
	res.Interrupted = true
	var buf bytes.Buffer
	if err := Normal(&buf, res, opts("en", false)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "QUITTING!") {
		t.Error("an interrupted scan should say so")
	}
}

func TestXMLLooksLikeNmap(t *testing.T) {
	var buf bytes.Buffer
	if err := XML(&buf, fixture(), opts("en", false)); err != nil {
		t.Fatal(err)
	}
	raw := buf.String()
	if !strings.HasPrefix(raw, xml.Header) {
		t.Error("the XML declaration is missing")
	}
	if !strings.Contains(raw, "<!DOCTYPE nmaprun>") {
		t.Error("the nmap DOCTYPE is missing")
	}

	type portState struct {
		State  string `xml:"state,attr"`
		Reason string `xml:"reason,attr"`
	}
	type service struct {
		Name    string `xml:"name,attr"`
		Product string `xml:"product,attr"`
		Version string `xml:"version,attr"`
		OSType  string `xml:"ostype,attr"`
		Method  string `xml:"method,attr"`
	}
	type port struct {
		Protocol string    `xml:"protocol,attr"`
		PortID   int       `xml:"portid,attr"`
		State    portState `xml:"state"`
		Service  *service  `xml:"service"`
	}
	var doc struct {
		XMLName xml.Name `xml:"nmaprun"`
		Scanner string   `xml:"scanner,attr"`
		Version string   `xml:"version,attr"`
		Args    string   `xml:"args,attr"`
		Hosts   []struct {
			Status struct {
				State  string `xml:"state,attr"`
				Reason string `xml:"reason,attr"`
			} `xml:"status"`
			Address struct {
				Addr     string `xml:"addr,attr"`
				AddrType string `xml:"addrtype,attr"`
			} `xml:"address"`
			Ports struct {
				ExtraPorts []struct {
					State string `xml:"state,attr"`
					Count int    `xml:"count,attr"`
				} `xml:"extraports"`
				Ports []port `xml:"port"`
			} `xml:"ports"`
		} `xml:"host"`
		RunStats struct {
			Hosts struct {
				Up    int `xml:"up,attr"`
				Down  int `xml:"down,attr"`
				Total int `xml:"total,attr"`
			} `xml:"hosts"`
		} `xml:"runstats"`
	}
	if err := xml.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("the XML does not parse: %v\n%s", err, raw)
	}
	if doc.Scanner != "argus" || doc.Version == "" || doc.Args == "" {
		t.Fatalf("nmaprun attributes are wrong: %+v", doc)
	}
	if len(doc.Hosts) != 2 {
		t.Fatalf("expected two hosts, got %d", len(doc.Hosts))
	}
	up := doc.Hosts[0]
	if up.Status.State != "up" || up.Address.Addr != "192.0.2.10" || up.Address.AddrType != "ipv4" {
		t.Fatalf("host 0 = %+v", up)
	}
	if len(up.Ports.Ports) != 4 {
		t.Fatalf("host 0 should expose all four ports in XML, got %d", len(up.Ports.Ports))
	}
	if n := len(up.Ports.ExtraPorts); n != 2 {
		t.Fatalf("expected two extraports groups, got %d", n)
	}
	ssh := up.Ports.Ports[0]
	if ssh.PortID != 22 || ssh.State.State != "open" || ssh.Service == nil {
		t.Fatalf("port 0 = %+v", ssh)
	}
	if ssh.Service.Product != "OpenSSH" || ssh.Service.Version != "8.9p1" || ssh.Service.OSType != "Ubuntu Linux" {
		t.Fatalf("service = %+v", ssh.Service)
	}
	if doc.RunStats.Hosts.Up != 1 || doc.RunStats.Hosts.Down != 1 || doc.RunStats.Hosts.Total != 2 {
		t.Fatalf("runstats = %+v", doc.RunStats.Hosts)
	}
}

func TestJSONDocument(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, FormatJSON, fixture(), opts("en", true)); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Scanner        string   `json:"scanner"`
		ElapsedSeconds float64  `json:"elapsed_seconds"`
		ScanType       string   `json:"scan_type"`
		Plugins        []string `json:"plugins"`
		Hosts          []struct {
			Address string `json:"address"`
			Status  string `json:"status"`
			Ports   []struct {
				Port    int    `json:"port"`
				State   string `json:"state"`
				Service *struct {
					Name string `json:"name"`
				} `json:"service"`
				Hack []struct {
					ID string `json:"id"`
				} `json:"hack_reason"`
			} `json:"ports"`
		} `json:"hosts"`
		Summary struct {
			HostsUp   int `json:"hosts_up"`
			OpenPorts int `json:"open_ports"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("the JSON does not parse: %v", err)
	}
	if doc.Scanner != "argus" || doc.ScanType != "connect" {
		t.Fatalf("doc = %+v", doc)
	}
	if len(doc.Plugins) != 1 || doc.Plugins[0] != "example" {
		t.Errorf("plugins = %v", doc.Plugins)
	}
	if len(doc.Hosts) != 1 {
		t.Fatalf("a down host that was skipped should not appear in JSON, got %d hosts", len(doc.Hosts))
	}
	if doc.Summary.HostsUp != 1 || doc.Summary.OpenPorts != 2 {
		t.Fatalf("summary = %+v", doc.Summary)
	}
	if len(doc.Hosts[0].Ports[0].Hack) != 1 {
		t.Error("hack-reason notes should be in the JSON when enabled")
	}
	if doc.ElapsedSeconds != 1.5 {
		t.Errorf("elapsed_seconds = %v", doc.ElapsedSeconds)
	}
}

func TestJSONLines(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, FormatJSONL, fixture(), opts("en", false)); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected one host line plus a summary line, got %d:\n%s", len(lines), buf.String())
	}
	for i, line := range lines {
		var probe map[string]any
		if err := json.Unmarshal([]byte(line), &probe); err != nil {
			t.Fatalf("line %d is not valid JSON: %v", i, err)
		}
		if probe["type"] == nil {
			t.Fatalf("line %d has no type field", i)
		}
	}
	var summary map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &summary); err != nil {
		t.Fatal(err)
	}
	if summary["type"] != "summary" {
		t.Fatalf("last line = %v", summary["type"])
	}
}

// TestMachineFormatsAreLanguageNeutral pins the decision that XML and JSON do
// not follow --lang: parsers must not care which language a human asked for.
func TestMachineFormatsAreLanguageNeutral(t *testing.T) {
	var en, zh bytes.Buffer
	if err := XML(&en, fixture(), opts("en", false)); err != nil {
		t.Fatal(err)
	}
	if err := XML(&zh, fixture(), opts("zh", false)); err != nil {
		t.Fatal(err)
	}
	strip := func(s string) string {
		if i := strings.Index(s, "<nmaprun"); i > 0 {
			return s[i:]
		}
		return s
	}
	if strip(en.String()) != strip(zh.String()) {
		t.Error("the XML body must not change with --lang")
	}
	if strings.Contains(zh.String(), "启动") {
		t.Error("translated text leaked into the XML")
	}
}

func TestDisplayWidthAndPadding(t *testing.T) {
	if got := displayWidth("PORT"); got != 4 {
		t.Errorf("displayWidth(PORT) = %d", got)
	}
	if got := displayWidth("端口"); got != 4 {
		t.Errorf("displayWidth(端口) = %d, CJK glyphs are double width", got)
	}
	if got := padRight("端口", 8); displayWidth(got) != 8 {
		t.Errorf("padRight(端口, 8) has width %d", displayWidth(got))
	}
	if got := padRight("abcdefghij", 4); got != "abcdefghij" {
		t.Errorf("padRight must not truncate, got %q", got)
	}
}

func TestLatencySecondsFormatting(t *testing.T) {
	cases := map[time.Duration]string{
		0:                       "0.00000",
		1234 * time.Microsecond: "0.00123",
		150 * time.Millisecond:  "0.15000",
		2500 * time.Millisecond: "2.5000",
	}
	for d, want := range cases {
		if got := latencySeconds(d); got != want {
			t.Errorf("latencySeconds(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestRenderRejectsUnknownFormat(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, "yaml", fixture(), Options{}); err == nil {
		t.Fatal("expected an error for an unknown format")
	}
}

func TestNilCatalogFallsBackToEnglish(t *testing.T) {
	var buf bytes.Buffer
	if err := Normal(&buf, fixture(), Options{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "Argus scan report for") {
		t.Error("a nil catalog should fall back to English")
	}
}

// TestTechniqueLineNamesWhatActuallyRan covers the rule that matters: a report
// that does not state the probe technique cannot be compared with anything,
// because a connect scan completes a handshake (which the application can log)
// and a SYN scan does not.
func TestTechniqueLineNamesWhatActuallyRan(t *testing.T) {
	tr := i18n.New("en")
	cases := []struct {
		name string
		info HeaderInfo
		want string
	}{
		{
			name: "no result yet",
			info: HeaderInfo{},
			want: "",
		},
		{
			name: "plain connect",
			info: HeaderInfo{ScanType: model.TechniqueConnect, Techniques: []string{model.TechniqueConnect}},
			want: "Scan technique: TCP connect (full handshake)",
		},
		{
			name: "plain syn",
			info: HeaderInfo{
				ScanType:   model.TechniqueSYN,
				Techniques: []string{model.TechniqueSYN},
			},
			want: "Scan technique: SYN scan (raw sockets, half open)",
		},
		{
			name: "syn with loopback targets mixed in",
			info: HeaderInfo{
				ScanType:       model.TechniqueSYN,
				Techniques:     []string{model.TechniqueConnect, model.TechniqueSYN},
				TechniqueMixed: true,
			},
			want: "Scan technique: SYN scan (raw sockets, half open); loopback and local addresses are probed with TCP connect",
		},
		{
			name: "syn asked for, every target local",
			info: HeaderInfo{
				ScanType:   model.TechniqueConnect,
				Techniques: []string{model.TechniqueConnect},
				Note:       "these targets are local addresses",
			},
			want: "Scan technique: TCP connect (these targets are local addresses)",
		},
		{
			name: "syn unavailable, explicit fallback",
			info: HeaderInfo{
				ScanType:   model.TechniqueConnect,
				Techniques: []string{model.TechniqueConnect},
				Note:       "no raw socket privileges",
			},
			want: "Scan technique: TCP connect (no raw socket privileges)",
		},
		{
			name: "auto picked syn",
			info: HeaderInfo{
				ScanType:   model.TechniqueSYN,
				Techniques: []string{model.TechniqueSYN},
				Auto:       true,
			},
			want: "Scan technique: SYN scan (raw sockets, half open; auto-selected)",
		},
		{
			name: "auto picked connect after probing",
			info: HeaderInfo{
				ScanType:   model.TechniqueConnect,
				Techniques: []string{model.TechniqueConnect},
				Auto:       true,
				Note:       "no raw socket privileges",
			},
			want: "Scan technique: TCP connect (auto-selected: no raw socket privileges)",
		},
		{
			name: "auto picked syn, but the targets are local",
			info: HeaderInfo{
				ScanType:   model.TechniqueConnect,
				Techniques: []string{model.TechniqueConnect},
				Auto:       true,
				Note:       "these targets are local addresses",
			},
			want: "Scan technique: TCP connect (auto-selected: these targets are local addresses)",
		},
		{
			name: "auto with a genuine mix",
			info: HeaderInfo{
				ScanType:       model.TechniqueSYN,
				Techniques:     []string{model.TechniqueConnect, model.TechniqueSYN},
				TechniqueMixed: true,
				Auto:           true,
			},
			want: "Scan technique: SYN scan (raw sockets, auto-selected); loopback and local addresses are probed with TCP connect",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := techniqueLine(tr, tc.info); got != tc.want {
				t.Fatalf("techniqueLine() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestTechniqueLineIsLocalised(t *testing.T) {
	zh := i18n.New("zh")
	got := techniqueLine(zh, HeaderInfo{
		ScanType:   model.TechniqueSYN,
		Techniques: []string{model.TechniqueSYN},
	})
	if !strings.Contains(got, "扫描技术") {
		t.Fatalf("Chinese technique line = %q", got)
	}
	// The auto-selected variants must be translated too.
	if got := techniqueLine(zh, HeaderInfo{
		ScanType:   model.TechniqueConnect,
		Techniques: []string{model.TechniqueConnect},
		Auto:       true,
		Note:       "这些目标是本机地址",
	}); !strings.Contains(got, "自动选择") {
		t.Fatalf("Chinese auto technique line = %q", got)
	}
}

// TestHeaderPrintsTechniqueBeforeResults makes sure the mode is stated up front
// rather than buried after the findings.
func TestHeaderPrintsTechniqueBeforeResults(t *testing.T) {
	var buf bytes.Buffer
	n := NewNormalWriter(&buf, opts("en", false))
	n.Header(HeaderInfo{
		Start:      time.Now(),
		ScanType:   model.TechniqueSYN,
		Techniques: []string{model.TechniqueSYN},
	})
	n.Host(fixture().Hosts[0])
	n.Flush()

	out := buf.String()
	techIdx := strings.Index(out, "Scan technique:")
	portIdx := strings.Index(out, "22/tcp")
	if techIdx < 0 {
		t.Fatalf("no technique line:\n%s", out)
	}
	if portIdx >= 0 && techIdx > portIdx {
		t.Errorf("the technique must be stated before the findings:\n%s", out)
	}
}

func TestXMLCarriesPerHostTechnique(t *testing.T) {
	res := fixture()
	res.ScanType = model.TechniqueSYN
	res.RequestedScanType = model.TechniqueSYN
	res.TechniqueMixed = true
	res.Hosts[0].Technique = model.TechniqueSYN
	res.Hosts[0].Ports[0].Technique = model.TechniqueSYN

	var buf bytes.Buffer
	if err := XML(&buf, res, opts("en", false)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `type="syn"`) {
		t.Errorf("scaninfo should name the technique that ran:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), `technique="syn"`) {
		t.Errorf("the host should carry its technique:\n%s", buf.String())
	}
	// The argus extension must not stop the document from parsing.
	var doc struct {
		Hosts []struct {
			Technique string `xml:"technique,attr"`
		} `xml:"host"`
	}
	if err := xml.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("the XML no longer parses: %v", err)
	}
	if len(doc.Hosts) == 0 || doc.Hosts[0].Technique != model.TechniqueSYN {
		t.Fatalf("technique did not survive the round trip: %+v", doc.Hosts)
	}
}

func TestJSONCarriesTechnique(t *testing.T) {
	res := fixture()
	res.ScanType = model.TechniqueSYN
	res.RequestedScanType = model.TechniqueSYN
	res.TechniqueMixed = true
	res.TechniqueAuto = true
	res.Hosts[0].Technique = model.TechniqueSYN
	res.Hosts[0].Ports[0].Technique = model.TechniqueSYN

	var buf bytes.Buffer
	if err := Render(&buf, FormatJSON, res, opts("en", false)); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		ScanType       string `json:"scan_type"`
		Requested      string `json:"requested_scan_type"`
		TechniqueMixed bool   `json:"technique_mixed"`
		TechniqueAuto  bool   `json:"technique_auto"`
		Hosts          []struct {
			Technique string `json:"technique"`
			Ports     []struct {
				Technique string `json:"technique"`
			} `json:"ports"`
		} `json:"hosts"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.ScanType != model.TechniqueSYN || doc.Requested != model.TechniqueSYN ||
		!doc.TechniqueMixed || !doc.TechniqueAuto {
		t.Fatalf("scan level fields = %+v", doc)
	}
	if doc.Hosts[0].Technique != model.TechniqueSYN || doc.Hosts[0].Ports[0].Technique != model.TechniqueSYN {
		t.Fatalf("host/port technique missing: %+v", doc.Hosts[0])
	}
}

// TestTechniqueOmittedWhenUnknown keeps the JSON clean for results that never
// went through the engine.
func TestTechniqueOmittedWhenUnknown(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, FormatJSON, fixture(), opts("en", false)); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), `"technique": ""`) {
		t.Error("an empty technique should be omitted, not emitted as an empty string")
	}
}

// withFinding returns a fixture whose first port carries a check finding.
func withFinding() *model.Result {
	res := fixture()
	res.Hosts[0].Ports[0].Service.Findings = []model.Finding{{
		ID:          "unauth",
		Title:       "Redis: unauthenticated access",
		Severity:    "high",
		Description: "The server answered INFO without credentials.",
		Refs:        []string{"https://example.invalid/redis"},
		Rule:        "redis-unauth",
		Match:       "unauth",
	}}
	return res
}

func TestNormalRendersFindings(t *testing.T) {
	var buf bytes.Buffer
	if err := Normal(&buf, withFinding(), opts("en", false)); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "| check: Redis: unauthenticated access [HIGH]") {
		t.Errorf("the finding header is missing or malformed:\n%s", out)
	}
	if !strings.Contains(out, "| The server answered INFO without credentials.") {
		t.Errorf("the finding description is missing:\n%s", out)
	}
	if !strings.Contains(out, "https://example.invalid/redis") {
		t.Errorf("the finding reference is missing:\n%s", out)
	}
	// The pipe block still ends with exactly one |_ line.
	if strings.Count(out, "\n|_") != 1 {
		t.Errorf("a detail block should end with exactly one |_ line:\n%s", out)
	}
	// A finding must never be mistaken for the service description.
	if strings.Contains(out, "check: Redis") && strings.Contains(out, "open  ssh     Redis") {
		t.Error("the finding leaked into the VERSION column")
	}
}

func TestNormalFindingsAreLocalised(t *testing.T) {
	var buf bytes.Buffer
	if err := Normal(&buf, withFinding(), opts("zh", false)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "检测：") {
		t.Errorf("the Chinese finding label is missing:\n%s", buf.String())
	}
}

// TestXMLFindingsUseScriptElements pins the compatibility decision: findings go
// out as nmap <script> elements so the tooling that already parses NSE output
// picks them up unchanged.
func TestXMLFindingsUseScriptElements(t *testing.T) {
	var buf bytes.Buffer
	if err := XML(&buf, withFinding(), opts("en", false)); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Hosts []struct {
			Ports struct {
				Ports []struct {
					PortID  int `xml:"portid,attr"`
					Scripts []struct {
						ID     string `xml:"id,attr"`
						Output string `xml:"output,attr"`
					} `xml:"script"`
				} `xml:"port"`
			} `xml:"ports"`
		} `xml:"host"`
	}
	if err := xml.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("the XML does not parse: %v", err)
	}
	scripts := doc.Hosts[0].Ports.Ports[0].Scripts
	if len(scripts) != 1 {
		t.Fatalf("expected one script element, got %d", len(scripts))
	}
	if scripts[0].ID != "redis-unauth:unauth" {
		t.Errorf("script id = %q, want rule:match", scripts[0].ID)
	}
	for _, want := range []string{"Redis: unauthenticated access", "[high]", "https://example.invalid/redis"} {
		if !strings.Contains(scripts[0].Output, want) {
			t.Errorf("script output is missing %q: %q", want, scripts[0].Output)
		}
	}
	// Findings must be language neutral in machine readable output.
	var zh bytes.Buffer
	if err := XML(&zh, withFinding(), opts("zh", false)); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(zh.String(), "检测：") {
		t.Error("translated text leaked into the XML")
	}
}

func TestJSONCarriesFindings(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, FormatJSON, withFinding(), opts("en", false)); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Hosts []struct {
			Ports []struct {
				Findings []struct {
					ID       string   `json:"id"`
					Severity string   `json:"severity"`
					Rule     string   `json:"rule"`
					Refs     []string `json:"refs"`
				} `json:"findings"`
			} `json:"ports"`
		} `json:"hosts"`
		Summary struct {
			Findings int `json:"findings"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Summary.Findings != 1 {
		t.Errorf("summary.findings = %d", doc.Summary.Findings)
	}
	f := doc.Hosts[0].Ports[0].Findings
	if len(f) != 1 || f[0].Severity != "high" || f[0].Rule != "redis-unauth" || len(f[0].Refs) != 1 {
		t.Fatalf("findings = %+v", f)
	}
}

func TestNoFindingsMeansNoScriptElements(t *testing.T) {
	var buf bytes.Buffer
	if err := XML(&buf, fixture(), opts("en", false)); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "<script") {
		t.Error("a scan without findings must not emit script elements")
	}
	var j bytes.Buffer
	if err := Render(&j, FormatJSON, fixture(), opts("en", false)); err != nil {
		t.Fatal(err)
	}
	// summary.findings is always present and reads 0; what must be absent is a
	// findings array on a port.
	var doc struct {
		Hosts []struct {
			Ports []struct {
				Keys map[string]any `json:",inline"`
			} `json:"ports"`
		} `json:"hosts"`
		Summary struct {
			Findings int `json:"findings"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(j.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Summary.Findings != 0 {
		t.Errorf("summary.findings = %d, want 0", doc.Summary.Findings)
	}
	if strings.Contains(j.String(), `"findings": [`) {
		t.Error("a scan without findings should not emit a findings array")
	}
}
