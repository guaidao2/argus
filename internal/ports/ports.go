// Package ports parses port specifications and owns the built-in service
// table used for the SERVICE column and for --top-ports.
package ports

import (
	_ "embed"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// Protocol names used throughout argus.
const (
	TCP = "tcp"
	UDP = "udp"
)

const (
	minPort = 1
	maxPort = 65535
)

//go:embed data/services.yaml
var servicesYAML []byte

// Target is one port to scan.
type Target struct {
	Port  int    `json:"port" yaml:"port"`
	Proto string `json:"protocol" yaml:"protocol"`
}

// ID renders "22/tcp".
func (t Target) ID() string { return strconv.Itoa(t.Port) + "/" + t.Proto }

// WellKnown is one entry of the built-in service table.
type WellKnown struct {
	Port    int
	Proto   string
	Name    string
	Rank    int // 1-based position in the table; lower is more common
	Aliases []string
}

type tableFile struct {
	Entries []struct {
		Port    int      `yaml:"port"`
		Name    string   `yaml:"name"`
		Aliases []string `yaml:"aliases"`
	} `yaml:"entries"`
}

var (
	tableOnce sync.Once
	byTarget  map[Target]WellKnown
	byName    map[string][]int
	ranked    []WellKnown
	tableErr  error
)

func load() {
	tableOnce.Do(func() {
		var f tableFile
		if err := yaml.Unmarshal(servicesYAML, &f); err != nil {
			tableErr = fmt.Errorf("built-in service table is invalid: %w", err)
			return
		}
		byTarget = make(map[Target]WellKnown, len(f.Entries))
		byName = make(map[string][]int, len(f.Entries)*2)
		ranked = make([]WellKnown, 0, len(f.Entries))
		index := map[Target]int{}

		for _, e := range f.Entries {
			if e.Port < minPort || e.Port > maxPort {
				continue
			}
			key := Target{Port: e.Port, Proto: TCP}
			if at, dup := index[key]; dup {
				// The first occurrence keeps its (better) rank; later
				// duplicates only contribute extra aliases.
				wk := ranked[at]
				wk.Aliases = appendUnique(wk.Aliases, e.Aliases...)
				if wk.Name == "" {
					wk.Name = e.Name
				}
				ranked[at] = wk
				byTarget[key] = wk
				continue
			}
			wk := WellKnown{
				Port:    e.Port,
				Proto:   TCP,
				Name:    e.Name,
				Rank:    len(ranked) + 1,
				Aliases: appendUnique(nil, e.Aliases...),
			}
			index[key] = len(ranked)
			ranked = append(ranked, wk)
			byTarget[key] = wk
		}

		for _, wk := range ranked {
			for _, n := range append([]string{wk.Name}, wk.Aliases...) {
				n = strings.ToLower(strings.TrimSpace(n))
				if n == "" {
					continue
				}
				if !containsInt(byName[n], wk.Port) {
					byName[n] = append(byName[n], wk.Port)
				}
			}
		}
		for n := range byName {
			sort.Ints(byName[n])
		}
	})
}

func appendUnique(dst []string, src ...string) []string {
	for _, s := range src {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		dup := false
		for _, d := range dst {
			if strings.EqualFold(d, s) {
				dup = true
				break
			}
		}
		if !dup {
			dst = append(dst, s)
		}
	}
	return dst
}

func containsInt(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// ServiceName returns the well-known service name of a port, or "".
// UDP lookups fall back to the TCP table because the well-known names are
// shared for most ports.
func ServiceName(proto string, port int) string {
	load()
	if wk, ok := byTarget[Target{Port: port, Proto: proto}]; ok {
		return wk.Name
	}
	if proto == UDP {
		if wk, ok := byTarget[Target{Port: port, Proto: TCP}]; ok {
			return wk.Name
		}
	}
	return ""
}

// DisplayName is the value shown in the SERVICE column.
func DisplayName(proto string, port int) string {
	if n := ServiceName(proto, port); n != "" {
		return n
	}
	return "unknown"
}

// LookupPort resolves a service name or alias to its port numbers.
func LookupPort(name string) []int {
	load()
	out := byName[strings.ToLower(strings.TrimSpace(name))]
	return append([]int(nil), out...)
}

// Top returns the first n entries of the built-in table in frequency order.
// n <= 0 or n > TopSize() returns the whole table.
func Top(n int) []Target {
	load()
	if n <= 0 || n > len(ranked) {
		n = len(ranked)
	}
	out := make([]Target, 0, n)
	for _, wk := range ranked[:n] {
		out = append(out, Target{Port: wk.Port, Proto: TCP})
	}
	return out
}

// TopSize is the number of entries in the built-in table.
func TopSize() int {
	load()
	return len(ranked)
}

// WellKnownTable returns a copy of the ranked table (used by tests and by the
// --list-ports style diagnostics).
func WellKnownTable() []WellKnown {
	load()
	return append([]WellKnown(nil), ranked...)
}

// TableError reports a corrupt embedded table; it is always nil in practice.
func TableError() error {
	load()
	return tableErr
}

// All returns every port of a protocol.
func All(proto string) []Target {
	out := make([]Target, 0, maxPort)
	for p := minPort; p <= maxPort; p++ {
		out = append(out, Target{Port: p, Proto: proto})
	}
	return out
}

// ParseOptions tweaks ParseSpec.
type ParseOptions struct {
	// DefaultProto is the protocol for entries without a T:/U: prefix.
	DefaultProto string
	// UDP additionally emits the UDP side of every TCP port selected.
	UDP bool
	// All means the user asked for every port (e.g. -p-).
	All bool
}

// ParseSpec turns an nmap-style port specification into concrete scan targets.
//
// Accepted forms (case insensitive, comma separated):
//
//	22,80,443      single ports
//	1-1024         ranges; "1024-" and "-1024" are also valid
//	-  or  *       every port
//	T:80,U:53      explicit protocol
//	ssh,http       well-known service names and aliases
func ParseSpec(spec string, opts ParseOptions) ([]Target, error) {
	load()
	if tableErr != nil {
		return nil, tableErr
	}
	def := strings.ToLower(opts.DefaultProto)
	if def != TCP && def != UDP {
		def = TCP
	}

	var out []Target
	seen := map[Target]bool{}
	push := func(pr string, p int) {
		if p < minPort || p > maxPort {
			return
		}
		t := Target{Port: p, Proto: pr}
		if seen[t] {
			return
		}
		seen[t] = true
		out = append(out, t)
	}

	if opts.All {
		for p := minPort; p <= maxPort; p++ {
			push(def, p)
			if opts.UDP && def == TCP {
				push(UDP, p)
			}
		}
		return out, nil
	}

	for _, raw := range strings.Split(spec, ",") {
		tok := strings.TrimSpace(raw)
		if tok == "" {
			continue
		}
		proto := def
		explicit := false
		if len(tok) > 2 && tok[1] == ':' {
			switch tok[0] {
			case 'T', 't':
				proto, explicit, tok = TCP, true, tok[2:]
			case 'U', 'u':
				proto, explicit, tok = UDP, true, tok[2:]
			}
		}
		// Optional trailing protocol, as in "80-82/tcp" or "53/udp".
		if i := strings.LastIndex(tok, "/"); i > 0 {
			switch strings.ToLower(tok[i+1:]) {
			case TCP:
				proto, explicit, tok = TCP, true, tok[:i]
			case UDP:
				proto, explicit, tok = UDP, true, tok[:i]
			default:
				return nil, fmt.Errorf("unknown protocol %q in %q", tok[i+1:], raw)
			}
		}
		emit := func(p int) {
			push(proto, p)
			if opts.UDP && !explicit && proto == TCP {
				push(UDP, p)
			}
		}

		switch {
		case tok == "-" || tok == "*":
			for p := minPort; p <= maxPort; p++ {
				emit(p)
			}
		default:
			if lo, hi, ok := parseRangeToken(tok); ok {
				if hi < lo {
					lo, hi = hi, lo
				}
				// Silently clamping would hide a typo such as 80-70000.
				if lo < minPort || hi > maxPort {
					return nil, fmt.Errorf("port range %d-%d is outside 1-65535", lo, hi)
				}
				for p := lo; p <= hi; p++ {
					emit(p)
				}
				continue
			}
			if n, err := strconv.Atoi(tok); err == nil {
				if n < minPort || n > maxPort {
					return nil, fmt.Errorf("port %d out of range 1-65535", n)
				}
				emit(n)
				continue
			}
			ps := LookupPort(tok)
			if len(ps) == 0 {
				return nil, fmt.Errorf("unknown port or service name %q", tok)
			}
			for _, p := range ps {
				emit(p)
			}
		}
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("no ports selected")
	}
	return out, nil
}

// parseRangeToken recognises "a-b", "a-" and "-b". Service names containing a
// dash (ms-sql-s) fail the numeric check and are handled as names by the
// caller.
func parseRangeToken(tok string) (lo, hi int, ok bool) {
	i := strings.Index(tok, "-")
	if i < 0 {
		return 0, 0, false
	}
	left, right := tok[:i], tok[i+1:]
	if strings.Contains(left, "-") || strings.Contains(right, "-") {
		return 0, 0, false
	}
	if left == "" {
		lo = minPort
	} else {
		n, err := strconv.Atoi(left)
		if err != nil {
			return 0, 0, false
		}
		lo = n
	}
	if right == "" {
		hi = maxPort
	} else {
		n, err := strconv.Atoi(right)
		if err != nil {
			return 0, 0, false
		}
		hi = n
	}
	return lo, hi, true
}

// Sort orders targets by protocol then port number.
func Sort(ts []Target) {
	sort.Slice(ts, func(i, j int) bool {
		if ts[i].Proto != ts[j].Proto {
			return ts[i].Proto < ts[j].Proto
		}
		return ts[i].Port < ts[j].Port
	})
}

// Subtract removes every port in exclude from in.
func Subtract(in, exclude []Target) []Target {
	if len(exclude) == 0 {
		return in
	}
	drop := make(map[Target]bool, len(exclude))
	for _, t := range exclude {
		drop[t] = true
	}
	out := in[:0:0]
	for _, t := range in {
		if !drop[t] {
			out = append(out, t)
		}
	}
	return out
}

// Spec renders a target list back into a compact specification string
// ("22,80,443,8000-8100/tcp"). Used for the XML scaninfo element.
func Spec(ts []Target) string {
	if len(ts) == 0 {
		return ""
	}
	byProto := map[string][]int{}
	for _, t := range ts {
		byProto[t.Proto] = append(byProto[t.Proto], t.Port)
	}
	protos := make([]string, 0, len(byProto))
	for p := range byProto {
		protos = append(protos, p)
	}
	sort.Strings(protos)
	parts := make([]string, 0, len(protos))
	for _, p := range protos {
		list := byProto[p]
		sort.Ints(list)
		var chunks []string
		start, prev := list[0], list[0]
		flush := func(from, to int) {
			if from == to {
				chunks = append(chunks, strconv.Itoa(from))
			} else {
				chunks = append(chunks, strconv.Itoa(from)+"-"+strconv.Itoa(to))
			}
		}
		for _, n := range list[1:] {
			if n == prev+1 {
				prev = n
				continue
			}
			flush(start, prev)
			start, prev = n, n
		}
		flush(start, prev)
		parts = append(parts, strings.Join(chunks, ",")+"/"+p)
	}
	return strings.Join(parts, ",")
}
