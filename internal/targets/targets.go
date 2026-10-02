// Package targets expands target specifications (addresses, CIDR blocks,
// ranges and host names) into concrete scan targets.
package targets

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/guaidao2/argus/internal/safetext"
)

// DefaultMaxHosts caps how many addresses a single expansion may produce, so
// that a typo like 10.0.0.0/8 fails fast instead of scanning for a week.
const DefaultMaxHosts = 1 << 20 // 1,048,576

// Target is one address to scan.
type Target struct {
	Addr netip.Addr
	// Hostname is set when the user named the target instead of giving an
	// address directly.
	Hostname string
}

// String renders the address in its canonical form.
func (t Target) String() string { return t.Addr.String() }

// Is4 reports whether the target is IPv4.
func (t Target) Is4() bool { return t.Addr.Is4() }

// Options controls expansion.
type Options struct {
	// NoDNS forbids every name lookup, including resolving targets given as
	// host names and reverse lookups.
	NoDNS bool
	// MaxHosts overrides DefaultMaxHosts.
	MaxHosts int
	// Resolver is used for name lookups; nil means net.DefaultResolver.
	Resolver *net.Resolver
}

func (o Options) maxHosts() int {
	if o.MaxHosts > 0 {
		return o.MaxHosts
	}
	return DefaultMaxHosts
}

func (o Options) resolver() *net.Resolver {
	if o.Resolver != nil {
		return o.Resolver
	}
	return net.DefaultResolver
}

// ErrTooLarge is returned when a specification would expand to more addresses
// than the configured limit.
type ErrTooLarge struct {
	Spec string
	Size uint64
	Max  int
}

func (e *ErrTooLarge) Error() string {
	return fmt.Sprintf("%s would expand to %d addresses (limit %d); narrow the specification or split it", e.Spec, e.Size, e.Max)
}

// Expand turns one specification into targets and appends them to dst.
func Expand(ctx context.Context, spec string, opts Options, dst []Target) ([]Target, error) {
	s := strings.TrimSpace(spec)
	if s == "" {
		return dst, nil
	}

	// IPv4 ranges contain a dash; IPv6 addresses never do.
	if strings.Contains(s, "-") && !strings.Contains(s, "/") {
		ts, handled, err := expandIPv4Range(s, opts)
		if err != nil {
			return dst, err
		}
		if handled {
			return append(dst, ts...), nil
		}
	}

	if strings.Contains(s, "/") {
		prefix, err := netip.ParsePrefix(s)
		if err != nil {
			return dst, fmt.Errorf("invalid network %q: %w", s, err)
		}
		ts, err := expandPrefix(s, prefix, opts)
		if err != nil {
			return dst, err
		}
		return append(dst, ts...), nil
	}

	if addr, err := netip.ParseAddr(s); err == nil {
		return append(dst, Target{Addr: addr.Unmap()}), nil
	}

	if !looksLikeHostname(s) {
		return dst, fmt.Errorf("unrecognised target %q", s)
	}
	if opts.NoDNS {
		return dst, fmt.Errorf("cannot resolve %q: --no-dns is set", s)
	}
	ips, err := opts.resolver().LookupNetIP(ctx, "ip", s)
	if err != nil {
		return dst, fmt.Errorf("cannot resolve %q: %w", s, err)
	}
	if len(ips) == 0 {
		return dst, fmt.Errorf("cannot resolve %q: no addresses returned", s)
	}
	for _, ip := range ips {
		dst = append(dst, Target{Addr: ip.Unmap(), Hostname: s})
	}
	return dst, nil
}

// expandIPv4Range handles 10.0.0.1-50 and 10.0.0.1-10.0.2.7. handled is false
// when the specification is not a range at all.
func expandIPv4Range(spec string, opts Options) (out []Target, handled bool, err error) {
	parts := strings.SplitN(spec, "-", 2)
	left, right := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])

	start, perr := netip.ParseAddr(left)
	if perr != nil || !start.Is4() {
		return nil, false, nil
	}

	var end netip.Addr
	if !strings.Contains(right, ".") {
		// Short form: only the last octet varies.
		n, aerr := strconv.Atoi(right)
		if aerr != nil {
			return nil, false, nil
		}
		if n < 0 || n > 255 {
			return nil, true, fmt.Errorf("invalid range end %q in %q", right, spec)
		}
		b := start.As4()
		b[3] = byte(n)
		end = netip.AddrFrom4(b)
	} else {
		a, aerr := netip.ParseAddr(right)
		if aerr != nil || !a.Is4() {
			return nil, false, nil
		}
		end = a
	}

	if end.Less(start) {
		start, end = end, start
	}
	span := addrSpan(start, end)
	if span > uint64(opts.maxHosts()) {
		return nil, true, &ErrTooLarge{Spec: spec, Size: span, Max: opts.maxHosts()}
	}
	for a := start; a.IsValid() && !end.Less(a); a = a.Next() {
		out = append(out, Target{Addr: a})
	}
	return out, true, nil
}

func addrSpan(start, end netip.Addr) uint64 {
	s, e := start.As4(), end.As4()
	var sv, ev uint64
	for i := 0; i < 4; i++ {
		sv = sv<<8 | uint64(s[i])
		ev = ev<<8 | uint64(e[i])
	}
	return ev - sv + 1
}

func expandPrefix(spec string, prefix netip.Prefix, opts Options) ([]Target, error) {
	prefix = prefix.Masked()
	bits := prefix.Addr().BitLen()
	hostBits := bits - prefix.Bits()
	if hostBits < 0 {
		return nil, fmt.Errorf("invalid network %q", spec)
	}
	if hostBits > 32 {
		return nil, &ErrTooLarge{Spec: spec, Size: 1 << 32, Max: opts.maxHosts()}
	}
	size := uint64(1) << uint(hostBits)
	if size > uint64(opts.maxHosts()) {
		return nil, &ErrTooLarge{Spec: spec, Size: size, Max: opts.maxHosts()}
	}

	// nmap skips the network and broadcast address of IPv4 subnets, except
	// for /31 and /32 where neither exists.
	skipEnds := prefix.Addr().Is4() && prefix.Bits() < 31

	count := int(size)
	if skipEnds {
		if count <= 2 {
			return nil, nil
		}
		count -= 2
	}
	out := make([]Target, 0, count)
	addr := prefix.Addr()
	if skipEnds {
		addr = addr.Next()
	}
	for i := 0; i < count; i++ {
		if !addr.IsValid() {
			break
		}
		out = append(out, Target{Addr: addr})
		addr = addr.Next()
	}
	return out, nil
}

// Parse expands a list of specifications and de-duplicates the result.
func Parse(ctx context.Context, specs []string, opts Options) ([]Target, error) {
	var out []Target
	for _, spec := range specs {
		// A single argument may itself be a comma separated list.
		for _, part := range strings.Split(spec, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			var err error
			out, err = Expand(ctx, part, opts, out)
			if err != nil {
				return nil, fmt.Errorf("invalid target %q: %w", part, err)
			}
		}
	}
	return Dedup(out), nil
}

// Dedup removes duplicate addresses, keeping the first occurrence, and sorts
// the result so a scan is reproducible.
func Dedup(in []Target) []Target {
	seen := make(map[netip.Addr]bool, len(in))
	out := make([]Target, 0, len(in))
	for _, t := range in {
		if t.Addr.IsValid() && !seen[t.Addr] {
			seen[t.Addr] = true
			out = append(out, t)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Addr.Less(out[j].Addr) })
	return out
}

// Subtract removes every address present in exclude.
func Subtract(in, exclude []Target) []Target {
	if len(exclude) == 0 {
		return in
	}
	drop := make(map[netip.Addr]bool, len(exclude))
	for _, t := range exclude {
		drop[t.Addr] = true
	}
	out := in[:0:0]
	for _, t := range in {
		if !drop[t.Addr] {
			out = append(out, t)
		}
	}
	return out
}

// ReverseLookup returns the PTR name of an address, or "" when unavailable.
func ReverseLookup(ctx context.Context, addr netip.Addr, resolver *net.Resolver) string {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	names, err := resolver.LookupAddr(ctx, addr.String())
	if err != nil || len(names) == 0 {
		return ""
	}
	// A PTR record is attacker-influenced if the resolver is, so it is cleaned
	// before it can reach a terminal.
	return safetext.Sanitize(strings.TrimSuffix(names[0], "."))
}

// ErrNoTargets is returned by callers when the specification list is empty.
var ErrNoTargets = errors.New("no targets given")

func looksLikeHostname(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-' || r == '.' || r == '_':
		default:
			return false
		}
	}
	return strings.ContainsAny(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
}
