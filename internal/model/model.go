// Package model defines the scan result vocabulary shared by the scanner, the
// service detector and the reporters.
package model

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// State is an nmap port state. The wire values are intentionally identical to
// nmap's so that -oX/-oJ output stays consumable by existing tooling; they are
// never translated.
type State string

const (
	StateOpen           State = "open"
	StateClosed         State = "closed"
	StateFiltered       State = "filtered"
	StateUnfiltered     State = "unfiltered"
	StateOpenFiltered   State = "open|filtered"
	StateClosedFiltered State = "closed|filtered"
)

// Probe techniques. The values match nmap's scaninfo type attribute, because
// TCP connect and SYN scans do not produce equivalent result sets and a report
// that does not say which one ran is a report nobody can reason about.
const (
	TechniqueSYN     = "syn"
	TechniqueConnect = "connect"
	TechniqueUDP     = "udp"
)

// AllStates lists every known state in report order.
var AllStates = []State{
	StateOpen,
	StateClosed,
	StateFiltered,
	StateUnfiltered,
	StateOpenFiltered,
	StateClosedFiltered,
}

// Order gives a stable display order: open first, then the rest.
func (s State) Order() int {
	switch s {
	case StateOpen:
		return 0
	case StateOpenFiltered:
		return 1
	case StateUnfiltered:
		return 2
	case StateClosed:
		return 3
	case StateClosedFiltered:
		return 4
	case StateFiltered:
		return 5
	}
	return 9
}

// Reason explains why a port ended up in a state. Values mirror nmap's
// --reason vocabulary.
type Reason string

const (
	ReasonSynAck        Reason = "syn-ack"            // TCP handshake completed
	ReasonConnRefused   Reason = "conn-refused"       // RST on connect
	ReasonReset         Reason = "reset"              // RST without a listener handshake
	ReasonNoResponse    Reason = "no-response"        // nothing came back
	ReasonUDPResponse   Reason = "udp-response"       // any UDP reply
	ReasonLocalhost     Reason = "localhost-response" // target is loopback
	ReasonHostUnreach   Reason = "host-unreach"       // host unreachable ICMP/error
	ReasonNetUnreach    Reason = "net-unreach"        // network unreachable
	ReasonAdminProhibit Reason = "admin-prohibited"
	ReasonProtoResponse Reason = "proto-response" // version probe replied
	ReasonEchoReply     Reason = "echo-reply"     // ICMP echo reply
	ReasonPortUnreach   Reason = "port-unreach"   // ICMP port unreachable (UDP closed)
	ReasonUserSet       Reason = "user-set"       // -Pn forced the host online
)

// HackNote is one offensive-security angle attached to an open port.
type HackNote struct {
	ID     string   `json:"id" yaml:"id"`
	Title  string   `json:"title" yaml:"title"`
	Points []string `json:"points,omitempty" yaml:"points,omitempty"`
	Tools  []string `json:"tools,omitempty" yaml:"tools,omitempty"`
	Refs   []string `json:"refs,omitempty" yaml:"refs,omitempty"`
}

// TLSInfo summarises a TLS handshake observed on a port.
type TLSInfo struct {
	Version     string    `json:"version,omitempty" yaml:"version,omitempty"`
	Cipher      string    `json:"cipher,omitempty" yaml:"cipher,omitempty"`
	ALPN        string    `json:"alpn,omitempty" yaml:"alpn,omitempty"`
	Subject     string    `json:"subject,omitempty" yaml:"subject,omitempty"`
	Issuer      string    `json:"issuer,omitempty" yaml:"issuer,omitempty"`
	NotBefore   time.Time `json:"not_before,omitempty" yaml:"not_before,omitempty"`
	NotAfter    time.Time `json:"not_after,omitempty" yaml:"not_after,omitempty"`
	DNSNames    []string  `json:"dns_names,omitempty" yaml:"dns_names,omitempty"`
	SelfSigned  bool      `json:"self_signed,omitempty" yaml:"self_signed,omitempty"`
	Expired     bool      `json:"expired,omitempty" yaml:"expired,omitempty"`
	Fingerprint string    `json:"fingerprint,omitempty" yaml:"fingerprint,omitempty"`
}

// Finding is a conclusion a check rule reached about a port: unauthenticated
// access, an exposed administrative interface, a build with a known problem.
//
// It is kept separate from the Service fields on purpose. "nginx 1.24.0" is an
// observation; "the index list is readable without credentials" is a judgement,
// and the two must not be conflated in a report.
type Finding struct {
	ID          string   `json:"id" yaml:"id"`
	Title       string   `json:"title" yaml:"title"`
	Severity    string   `json:"severity,omitempty" yaml:"severity,omitempty"`
	Description string   `json:"description,omitempty" yaml:"description,omitempty"`
	Refs        []string `json:"refs,omitempty" yaml:"refs,omitempty"`
	// Rule and Match name where this came from, so a false positive can be
	// traced back to a specific rule in a specific plugin.
	Rule  string `json:"rule,omitempty" yaml:"rule,omitempty"`
	Match string `json:"match,omitempty" yaml:"match,omitempty"`
}

// HighestSeverity returns the most severe finding in a list, or "".
func HighestSeverity(findings []Finding) string {
	best := -1
	out := ""
	for _, f := range findings {
		for i, s := range severityOrder {
			if f.Severity == s {
				if best < 0 || i < best {
					best, out = i, s
				}
				break
			}
		}
	}
	return out
}

// severityOrder lists severities most severe first, matching the plugin schema.
var severityOrder = []string{"critical", "high", "medium", "low", "info"}

// Service is what running on a port, nmap-<service> style.
type Service struct {
	Name      string     `json:"name,omitempty" yaml:"name,omitempty"`
	Product   string     `json:"product,omitempty" yaml:"product,omitempty"`
	Version   string     `json:"version,omitempty" yaml:"version,omitempty"`
	ExtraInfo string     `json:"extrainfo,omitempty" yaml:"extrainfo,omitempty"`
	OSType    string     `json:"ostype,omitempty" yaml:"ostype,omitempty"`
	Device    string     `json:"devicetype,omitempty" yaml:"devicetype,omitempty"`
	Tunnel    string     `json:"tunnel,omitempty" yaml:"tunnel,omitempty"` // "ssl" for TLS-wrapped services
	Method    string     `json:"method,omitempty" yaml:"method,omitempty"` // probed | table
	Conf      int        `json:"conf,omitempty" yaml:"conf,omitempty"`
	CPEs      []string   `json:"cpe,omitempty" yaml:"cpe,omitempty"`
	Banner    string     `json:"banner,omitempty" yaml:"banner,omitempty"`
	Rule      string     `json:"rule,omitempty" yaml:"rule,omitempty"` // fingerprint rule id that matched
	TLS       *TLSInfo   `json:"tls,omitempty" yaml:"tls,omitempty"`
	Hack      []HackNote `json:"hack_reason,omitempty" yaml:"hack_reason,omitempty"`
	// Findings come from check rules and only exist when --findings is on.
	Findings []Finding `json:"findings,omitempty" yaml:"findings,omitempty"`
}

// FullName returns "ssl/http" when the service is TLS wrapped.
func (s *Service) FullName() string {
	if s == nil {
		return ""
	}
	if s.Tunnel != "" && s.Name != "" {
		return s.Tunnel + "/" + s.Name
	}
	return s.Name
}

// VersionString renders the nmap VERSION column, e.g.
// "OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)".
func (s *Service) VersionString() string {
	if s == nil {
		return ""
	}
	var b strings.Builder
	for _, part := range []string{s.Product, s.Version} {
		if part != "" {
			if b.Len() > 0 {
				b.WriteByte(' ')
			}
			b.WriteString(part)
		}
	}
	extra := s.ExtraInfo
	var paren []string
	if extra != "" {
		paren = append(paren, extra)
	}
	if s.OSType != "" && s.OSType != extra {
		paren = append(paren, s.OSType)
	}
	if s.Device != "" {
		paren = append(paren, s.Device)
	}
	if len(paren) > 0 {
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		b.WriteString("(" + strings.Join(paren, "; ") + ")")
	}
	return b.String()
}

// Port is a single scanned port.
type Port struct {
	Port   int    `json:"port" yaml:"port"`
	Proto  string `json:"protocol" yaml:"protocol"` // tcp | udp
	State  State  `json:"state" yaml:"state"`
	Reason Reason `json:"reason,omitempty" yaml:"reason,omitempty"`
	TTL    int    `json:"reason_ttl,omitempty" yaml:"reason_ttl,omitempty"`
	// Technique is how this particular port was probed, which is not always
	// the scan-wide technique: loopback and local targets are always probed
	// with a connect scan.
	Technique string   `json:"technique,omitempty" yaml:"technique,omitempty"`
	Service   *Service `json:"service,omitempty" yaml:"service,omitempty"`
}

// ID renders "22/tcp".
func (p Port) ID() string { return fmt.Sprintf("%d/%s", p.Port, p.Proto) }

// Host is one scanned host.
type Host struct {
	Address   string        `json:"address" yaml:"address"`
	AddrType  string        `json:"addrtype,omitempty" yaml:"addrtype,omitempty"`
	Hostnames []string      `json:"hostnames,omitempty" yaml:"hostnames,omitempty"`
	Status    string        `json:"status" yaml:"status"` // up | down
	Reason    Reason        `json:"reason,omitempty" yaml:"reason,omitempty"`
	Technique string        `json:"technique,omitempty" yaml:"technique,omitempty"`
	Latency   time.Duration `json:"-" yaml:"-"`
	Start     time.Time     `json:"-" yaml:"-"`
	End       time.Time     `json:"-" yaml:"-"`
	SRTT      time.Duration `json:"-" yaml:"-"`
	RTTVar    time.Duration `json:"-" yaml:"-"`
	Timeout   time.Duration `json:"-" yaml:"-"`
	Ports     []Port        `json:"ports,omitempty" yaml:"ports,omitempty"`
	// ScanSkipped marks hosts that were reported down and therefore not port
	// scanned.
	ScanSkipped bool `json:"-" yaml:"-"`
}

// LatencySeconds is the host discovery round trip in seconds.
func (h Host) LatencySeconds() float64 { return h.Latency.Seconds() }

// Up reports whether the host answered discovery.
func (h Host) Up() bool { return h.Status == "up" }

// SortPorts orders ports by state then port number.
func (h *Host) SortPorts() {
	sort.SliceStable(h.Ports, func(i, j int) bool {
		a, b := h.Ports[i], h.Ports[j]
		if a.State.Order() != b.State.Order() {
			return a.State.Order() < b.State.Order()
		}
		if a.Proto != b.Proto {
			return a.Proto < b.Proto
		}
		return a.Port < b.Port
	})
}

// ExtraPorts aggregates the ports that the normal report collapses into the
// "Not shown: ..." line, mirroring nmap's extraports element.
type ExtraPorts struct {
	State   State
	Proto   string
	Count   int
	Reasons map[Reason]int
}

// Extras returns the non-open port groups sorted by descending count. Groups
// are split by protocol as well as state, because nmap reports them that way.
func (h Host) Extras() []ExtraPorts {
	type key struct {
		state State
		proto string
	}
	groups := map[key]*ExtraPorts{}
	for _, p := range h.Ports {
		if p.State == StateOpen {
			continue
		}
		k := key{p.State, p.Proto}
		g := groups[k]
		if g == nil {
			g = &ExtraPorts{State: p.State, Proto: p.Proto, Reasons: map[Reason]int{}}
			groups[k] = g
		}
		g.Count++
		if p.Reason != "" {
			g.Reasons[p.Reason]++
		}
	}
	out := make([]ExtraPorts, 0, len(groups))
	for _, g := range groups {
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		if out[i].State.Order() != out[j].State.Order() {
			return out[i].State.Order() < out[j].State.Order()
		}
		return out[i].Proto < out[j].Proto
	})
	return out
}

// TopReasons returns the reason counts of a group, most frequent first.
func (e ExtraPorts) TopReasons() []Reason {
	type kv struct {
		r     Reason
		count int
	}
	list := make([]kv, 0, len(e.Reasons))
	for r, c := range e.Reasons {
		list = append(list, kv{r, c})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].count != list[j].count {
			return list[i].count > list[j].count
		}
		return list[i].r < list[j].r
	})
	out := make([]Reason, 0, len(list))
	for _, item := range list {
		out = append(out, item.r)
	}
	return out
}

// OpenPorts returns only the open ports, sorted.
func (h Host) OpenPorts() []Port {
	out := make([]Port, 0, len(h.Ports))
	for _, p := range h.Ports {
		if p.State == StateOpen {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Proto != out[j].Proto {
			return out[i].Proto < out[j].Proto
		}
		return out[i].Port < out[j].Port
	})
	return out
}

// Result is one complete scan run.
type Result struct {
	Args  string    `json:"args" yaml:"args"`
	Start time.Time `json:"-" yaml:"-"`
	End   time.Time `json:"-" yaml:"-"`
	// ScanType is the technique that actually ran, which is what goes into
	// nmap's scaninfo/@type. RequestedScanType records what the user asked for;
	// when the two differ, a fallback happened and the report must say so.
	ScanType          string `json:"scan_type" yaml:"scan_type"`
	RequestedScanType string `json:"requested_scan_type,omitempty" yaml:"requested_scan_type,omitempty"`
	// TechniqueMixed is set when different targets were probed with different
	// techniques inside one scan (loopback and local addresses always use a
	// connect scan).
	TechniqueMixed bool `json:"technique_mixed,omitempty" yaml:"technique_mixed,omitempty"`
	// TechniqueAuto is set when the user asked argus to choose the technique.
	TechniqueAuto bool `json:"technique_auto,omitempty" yaml:"technique_auto,omitempty"`
	// TechniqueNote explains, in the report language, why the technique that
	// ran is not the strongest one available. Presentation only.
	TechniqueNote string   `json:"-" yaml:"-"`
	Protocols     []string `json:"protocols" yaml:"protocols"`
	NumServices   int      `json:"num_services" yaml:"num_services"`
	ServicesSpec  string   `json:"services_spec" yaml:"services_spec"`
	Targets       []string `json:"targets" yaml:"targets"`
	Verbose       int      `json:"-" yaml:"-"`
	Debug         int      `json:"-" yaml:"-"`
	Hosts         []Host   `json:"hosts" yaml:"hosts"`
	Interrupted   bool     `json:"interrupted,omitempty" yaml:"interrupted,omitempty"`
	PluginsLoaded int      `json:"plugins_loaded,omitempty" yaml:"plugins_loaded,omitempty"`
	PluginNames   []string `json:"plugins,omitempty" yaml:"plugins,omitempty"`
}

// Elapsed is the wall clock duration of the scan.
func (r *Result) Elapsed() time.Duration {
	if r.End.IsZero() {
		return time.Since(r.Start)
	}
	return r.End.Sub(r.Start)
}

// Counts returns (up, down, total).
func (r *Result) Counts() (int, int, int) {
	up, down := 0, 0
	for _, h := range r.Hosts {
		if h.Up() {
			up++
		} else {
			down++
		}
	}
	return up, down, len(r.Hosts)
}
