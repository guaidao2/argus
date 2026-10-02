// Package scan implements the scanning engine: host discovery, the TCP
// connect scanner (default), the UDP scanner and the Linux SYN scanner.
package scan

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"
	"golang.org/x/time/rate"

	"github.com/guaidao2/argus/internal/model"
	"github.com/guaidao2/argus/internal/ports"
	"github.com/guaidao2/argus/internal/targets"
)

// ScanType selects the probe implementation.
type ScanType string

const (
	// ScanConnect performs a full TCP handshake with a regular socket. It
	// needs no privileges and is the default.
	ScanConnect ScanType = "connect"
	// ScanSYN sends a bare SYN and inspects the reply. It needs CAP_NET_RAW
	// and is only implemented on Linux; argus never silently downgrades.
	ScanSYN ScanType = "syn"
	// ScanAuto asks the CLI to pick between the two at startup, once the
	// capability detection has run. The engine itself never accepts it: by the
	// time an Engine exists the technique is already decided.
	ScanAuto ScanType = "auto"
)

// Sentinel errors the CLI turns into localised messages with hints.
var (
	ErrSYNUnsupported = errors.New("syn scan unsupported on this platform")
	ErrSYNPrivileges  = errors.New("syn scan requires raw socket privileges")
	ErrSYNIPv6        = errors.New("syn scan supports IPv4 targets only")
	// ErrSYNNoReply means the raw socket opened but the loopback preflight got
	// nothing back: the send path works, the receive path does not.
	ErrSYNNoReply = errors.New("syn scan raw socket received no reply")
)

// synPreflightTimeout bounds the whole preflight, which runs three loopback
// probes in parallel.
const synPreflightTimeout = 5 * time.Second

// Detector identifies the service behind an open port.
type Detector interface {
	// Detect inspects one open port. A nil Service without an error means
	// nothing was recognised.
	Detect(ctx context.Context, host string, port model.Port) (*model.Service, error)
	// Name identifies the detector in debug output.
	Name() string
}

// Options configures an Engine.
type Options struct {
	Targets []targets.Target
	Ports   []ports.Target

	ScanType ScanType
	Timing   Timing

	// Pn disables host discovery.
	Pn bool
	// DiscoveryTimeout bounds a host discovery probe.
	DiscoveryTimeout time.Duration
	// NoDNS disables reverse lookups.
	NoDNS bool
	// ResolveAll forces a reverse lookup for every host.
	ResolveAll bool
	// Sequential disables port order randomisation.
	Sequential bool

	// ProxyURL routes TCP connect probes through a SOCKS5 proxy.
	ProxyURL string

	// HostTimeout bounds the whole scan of one host. Zero disables it.
	HostTimeout time.Duration

	Detector      Detector
	DetectTimeout time.Duration

	OpenOnly     bool
	HostParallel int

	OnHost     func(model.Host)
	OnProgress func(done, total int)
	Debugf     func(format string, args ...any)
	// Enrich runs on every host before it is stored and delivered, which is
	// where the CLI attaches hack-reason notes so that the streamed output and
	// the final result agree.
	Enrich func(h *model.Host)
}

// Engine scans ports.
type Engine struct {
	opts    Options
	limiter *rateLimiter
	dialer  *net.Dialer
	proxy   proxy.ContextDialer
	syn     *synScanner

	rnd     *lockedRand
	total   int64
	done    atomic.Int64
	started time.Time
}

// New validates options and prepares an engine.
func New(opts Options) (*Engine, error) {
	if len(opts.Targets) == 0 {
		return nil, targets.ErrNoTargets
	}
	if opts.ScanType == "" {
		opts.ScanType = ScanConnect
	}
	switch opts.ScanType {
	case ScanConnect, ScanSYN:
	default:
		return nil, fmt.Errorf("unknown scan type %q", opts.ScanType)
	}
	if opts.HostParallel <= 0 {
		opts.HostParallel = 4
	}
	if opts.DiscoveryTimeout <= 0 {
		opts.DiscoveryTimeout = 3 * time.Second
	}
	if opts.DetectTimeout <= 0 {
		opts.DetectTimeout = 5 * time.Second
	}
	opts.Timing.Clamp()

	e := &Engine{
		opts:    opts,
		dialer:  &net.Dialer{},
		rnd:     newLockedRand(),
		started: time.Now(),
	}
	e.limiter = newRateLimiter(opts.Timing.MaxRate)
	if opts.ProxyURL != "" {
		d, err := proxyDialer(opts.ProxyURL)
		if err != nil {
			return nil, err
		}
		e.proxy = d
	}
	if opts.ScanType == ScanSYN {
		s, err := newSYNScanner(opts.Debugf)
		if err != nil {
			return nil, err
		}
		// Capability detection happens here, before any scan packet is sent.
		// Discovering mid-scan that the replies never arrive would waste the
		// part of the scan that already ran and produce a plausible looking but
		// wrong result set.
		pctx, cancel := context.WithTimeout(context.Background(), synPreflightTimeout)
		err = s.preflight(pctx, synPreflightProbeTimeout)
		cancel()
		if err != nil {
			s.Close()
			return nil, err
		}
		e.syn = s
	}
	return e, nil
}

// synPreflightProbeTimeout is the per-probe budget during preflight. Loopback
// answers in microseconds, so this only matters when something is wrong.
const synPreflightProbeTimeout = 1500 * time.Millisecond

// Close releases engine resources.
func (e *Engine) Close() {
	if e.syn != nil {
		e.syn.Close()
	}
}

func (e *Engine) debugf(format string, args ...any) {
	if e.opts.Debugf != nil {
		e.opts.Debugf(format, args...)
	}
}

// Result wiring -------------------------------------------------------------

type hostOut struct {
	idx  int
	host model.Host
}

// Run scans every target, calling OnHost once per host in target order.
// Cancelling ctx stops the scan early; whatever was finished is returned.
func (e *Engine) Run(ctx context.Context) *model.Result {
	res := &model.Result{
		Start:        e.started,
		ScanType:     string(e.opts.ScanType),
		NumServices:  len(e.opts.Ports),
		ServicesSpec: ports.Spec(e.opts.Ports),
	}
	for _, t := range e.opts.Targets {
		res.Targets = append(res.Targets, t.Addr.String())
	}
	protos := map[string]bool{}
	for _, p := range e.opts.Ports {
		protos[p.Proto] = true
	}
	for p := range protos {
		res.Protocols = append(res.Protocols, p)
	}

	n := len(e.opts.Targets)
	e.total = int64(n) * int64(len(e.opts.Ports))
	e.done.Store(0)

	hosts := make([]model.Host, n)
	out := make(chan hostOut, n)

	// Emitter: delivers hosts to OnHost in target order so that output is
	// deterministic no matter how the workers interleave.
	emitDone := make(chan struct{})
	go func() {
		defer close(emitDone)
		pending := make(map[int]model.Host, e.opts.HostParallel)
		for next := 0; next < n; next++ {
			for {
				h, ok := pending[next]
				if ok {
					delete(pending, next)
					if e.opts.Enrich != nil {
						e.opts.Enrich(&h)
					}
					hosts[next] = h
					if e.opts.OnHost != nil {
						e.opts.OnHost(h)
					}
					break
				}
				o, more := <-out
				if !more {
					return
				}
				pending[o.idx] = o.host
			}
		}
	}()

	sem := make(chan struct{}, e.opts.HostParallel)
	var wg sync.WaitGroup
	for i, t := range e.opts.Targets {
		wg.Add(1)
		go func(i int, t targets.Target) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if ctx.Err() != nil {
				out <- hostOut{idx: i, host: model.Host{Address: t.Addr.String(), Status: "down", ScanSkipped: true}}
				return
			}
			h := e.scanHost(ctx, t)
			out <- hostOut{idx: i, host: h}
		}(i, t)
	}
	wg.Wait()
	close(out)
	<-emitDone

	res.End = time.Now()
	res.Hosts = hosts
	// Remember whether one scan used more than one technique, so the report can
	// say "loopback targets were probed with TCP connect" instead of claiming a
	// uniformity that did not exist.
	techniques := map[string]bool{}
	for _, h := range hosts {
		if h.Technique != "" {
			techniques[h.Technique] = true
		}
	}
	res.TechniqueMixed = len(techniques) > 1
	// ScanType is what actually ran, which is not always what was asked for.
	switch len(techniques) {
	case 0:
		res.ScanType = string(e.opts.ScanType)
	case 1:
		for tech := range techniques {
			res.ScanType = tech
		}
	default:
		// Mixed: report the technique the user actually requested as the
		// headline, and let the per-host/per-port fields carry the detail.
		res.ScanType = string(e.opts.ScanType)
	}
	if ctx.Err() != nil {
		res.Interrupted = true
	}
	return res
}

// probeBudget is how many probe slots a host gets.
func (e *Engine) probeBudget(count int) int {
	parallel := e.opts.Timing.MaxParallel
	if e.opts.Timing.MinRate > 0 {
		// Raise concurrency so the requested floor is reachable: assume a
		// probe occupies a slot for roughly 250ms.
		if want := e.opts.Timing.MinRate / 4; want > parallel {
			parallel = want
		}
	}
	// --min-parallelism is a floor, not a suggestion: asking for more
	// concurrency than the timing template defaults to must raise it, which is
	// what nmap users expect from the flag.
	if e.opts.Timing.MinParallel > parallel {
		parallel = e.opts.Timing.MinParallel
	}
	if parallel > hardMaxParallel {
		parallel = hardMaxParallel
	}
	if parallel > count {
		parallel = count
	}
	if parallel < 1 {
		parallel = 1
	}
	return parallel
}

// scanHost runs discovery and the port scan for a single host.
func (e *Engine) scanHost(ctx context.Context, t targets.Target) model.Host {
	if e.opts.HostTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, e.opts.HostTimeout)
		defer cancel()
	}
	h := model.Host{
		Address:  t.Addr.String(),
		AddrType: addrType(t.Addr),
		Start:    time.Now(),
		Status:   "up",
	}
	if t.Hostname != "" {
		h.Hostnames = appendUniqueString(h.Hostnames, t.Hostname)
	}

	var seed time.Duration
	if !e.opts.Pn {
		up, latency, reason := e.discover(ctx, t)
		h.Latency = latency
		h.Reason = reason
		seed = latency
		if !up {
			h.Status = "down"
			h.ScanSkipped = true
			h.End = time.Now()
			return h
		}
	} else {
		h.Reason = model.ReasonUserSet
	}

	tracker := NewRTTTracker(seed)

	if e.opts.ResolveAll && !e.opts.NoDNS && len(h.Hostnames) == 0 {
		rctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		if name := targets.ReverseLookup(rctx, t.Addr, nil); name != "" {
			h.Hostnames = appendUniqueString(h.Hostnames, name)
		}
		cancel()
	}

	var tcpPorts, udpPorts []ports.Target
	for _, p := range e.opts.Ports {
		switch p.Proto {
		case ports.UDP:
			udpPorts = append(udpPorts, p)
		default:
			tcpPorts = append(tcpPorts, p)
		}
	}

	var scanned []model.Port
	if len(tcpPorts) > 0 {
		h.Technique = e.techniqueFor(t.Addr)
		scanned = append(scanned, e.scanTCP(ctx, t.Addr, tcpPorts, tracker)...)
	}
	if len(udpPorts) > 0 {
		udpOut := e.scanUDP(ctx, t.Addr, udpPorts, tracker)
		// scanTCP runs detection itself before returning; the UDP path has to
		// ask for it. Detection runs first because the results are copied into
		// the report by value: appending before the detector fills them in
		// would copy the empty versions.
		e.finishPorts(ctx, t.Addr, udpPorts, udpOut, tracker)
		scanned = append(scanned, udpOut...)
	}

	if e.opts.OpenOnly {
		open := scanned[:0:0]
		for _, p := range scanned {
			if p.State == model.StateOpen {
				open = append(open, p)
			}
		}
		scanned = open
	}

	srtt, rttvar, _, samples := tracker.Stats()
	h.SRTT = srtt
	h.RTTVar = rttvar
	// -Pn skips host discovery, so nothing measured a round trip before the
	// ports were probed and Latency stayed zero. Reporting "0.00000s latency"
	// for that reads as a perfect network rather than as a number nobody took;
	// the port probes did measure one, so report that instead.
	if h.Latency == 0 && samples > 0 && srtt > 0 {
		h.Latency = srtt
	}
	h.Ports = scanned
	h.SortPorts()
	h.End = time.Now()
	if e.opts.HostTimeout > 0 && ctx.Err() != nil {
		e.debugf("host %s hit the %s host timeout; results are partial", t.Addr, e.opts.HostTimeout)
	}
	return h
}

// delayLimiter builds the --scan-delay pacer. nmap's meaning is "minimum time
// between probes to the same host", so each host gets its own limiter.
func (e *Engine) delayLimiter() *rate.Limiter {
	if e.opts.Timing.Delay <= 0 {
		return nil
	}
	return rate.NewLimiter(rate.Every(e.opts.Timing.Delay), 1)
}

// pace waits for the --scan-delay pacer, if one is configured.
func pace(ctx context.Context, lim *rate.Limiter) bool {
	if lim == nil {
		return true
	}
	return lim.Wait(ctx) == nil
}

// scanTCP probes every TCP port of one host with a bounded worker pool.
func (e *Engine) scanTCP(ctx context.Context, addr netip.Addr, list []ports.Target, tracker *RTTTracker) []model.Port {
	order := make([]ports.Target, len(list))
	copy(order, list)
	if !e.opts.Sequential {
		e.rnd.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
	}

	out := make([]model.Port, len(order))
	parallel := e.probeBudget(len(order))
	delay := e.delayLimiter()
	// One technique for the whole host: the choice depends on the address, not
	// on the port.
	technique := e.techniqueFor(addr)
	e.debugf("host %s: scanning %d tcp ports with %d parallel probes (%s)",
		addr, len(order), parallel, technique)

	jobs := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < parallel; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				p := order[i]
				if !pace(ctx, delay) {
					out[i] = model.Port{Port: p.Port, Proto: p.Proto, State: model.StateFiltered,
						Reason: model.ReasonNoResponse, Technique: technique}
					continue
				}
				if ctx.Err() != nil {
					out[i] = model.Port{Port: p.Port, Proto: p.Proto, State: model.StateFiltered,
						Reason: model.ReasonNoResponse, Technique: technique}
					continue
				}
				out[i] = e.probeWithRetries(ctx, addr, p, tracker)
				out[i].Technique = technique
				e.tickProgress()
			}
		}()
	}
	for i := range order {
		select {
		case jobs <- i:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			e.finishPorts(ctx, addr, order, out, tracker)
			return out
		}
	}
	close(jobs)
	wg.Wait()
	e.finishPorts(ctx, addr, order, out, tracker)
	return out
}

// finishPorts runs service detection on the open ports of a host.
func (e *Engine) finishPorts(ctx context.Context, addr netip.Addr, order []ports.Target, out []model.Port, tracker *RTTTracker) {
	if e.opts.Detector == nil {
		return
	}
	var idx []int
	for i := range out {
		// UDP ports reach the detector too. SNMP and the other datagram
		// services only answer on datagrams, and a service nobody can name is
		// a service nobody checks.
		if out[i].State == model.StateOpen {
			idx = append(idx, i)
		}
	}
	if len(idx) == 0 {
		return
	}
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for _, i := range idx {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			dctx, cancel := context.WithTimeout(ctx, e.opts.DetectTimeout)
			defer cancel()
			svc, err := e.opts.Detector.Detect(dctx, addr.String(), out[i])
			if err != nil {
				e.debugf("detect %s:%d failed: %v", addr, out[i].Port, err)
				return
			}
			if svc != nil {
				out[i].Service = svc
			}
		}(i)
	}
	wg.Wait()
}

// scanUDP probes every UDP port of one host.
//
// UDP does not retry on silence: a silent UDP port is genuinely
// open|filtered, and repeating the probe would only waste time.
func (e *Engine) scanUDP(ctx context.Context, addr netip.Addr, list []ports.Target, tracker *RTTTracker) []model.Port {
	out := make([]model.Port, len(list))
	parallel := e.probeBudget(len(list))
	if parallel > 64 {
		parallel = 64
	}
	delay := e.delayLimiter()
	e.debugf("host %s: scanning %d udp ports with %d parallel probes", addr, len(list), parallel)

	jobs := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < parallel; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				p := list[i]
				if !pace(ctx, delay) {
					out[i] = model.Port{Port: p.Port, Proto: p.Proto,
						State: model.StateOpenFiltered, Reason: model.ReasonNoResponse,
						Technique: model.TechniqueUDP}
					continue
				}
				if ctx.Err() != nil {
					out[i] = model.Port{Port: p.Port, Proto: p.Proto,
						State: model.StateOpenFiltered, Reason: model.ReasonNoResponse,
						Technique: model.TechniqueUDP}
					continue
				}
				timeout := tracker.Timeout(udpBaseTimeout(e.opts.Timing), e.opts.Timing.MaxTimeout)
				st, rs, rtt := e.udpProbe(ctx, addr, p.Port, timeout)
				if rtt > 0 {
					tracker.Observe(rtt, 0)
				}
				out[i] = model.Port{Port: p.Port, Proto: p.Proto, State: st, Reason: rs,
					Technique: model.TechniqueUDP}
				e.tickProgress()
			}
		}()
	}
	for i := range list {
		select {
		case jobs <- i:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return out
		}
	}
	close(jobs)
	wg.Wait()
	return out
}

// udpBaseTimeout raises the floor for UDP: services answer on their own
// schedule, and a one second deadline produces nothing but open|filtered.
func udpBaseTimeout(t Timing) time.Duration {
	const floor = 2 * time.Second
	if t.InitialTimeout > floor {
		return t.InitialTimeout
	}
	return floor
}

// probeWithRetries retries only when a probe timed out with no answer.
func (e *Engine) probeWithRetries(ctx context.Context, addr netip.Addr, p ports.Target, tracker *RTTTracker) model.Port {
	attempts := e.opts.Timing.MaxRetries + 1
	if attempts < 1 {
		attempts = 1
	}
	var (
		state  = model.StateFiltered
		reason = model.ReasonNoResponse
	)
	for attempt := 0; attempt < attempts; attempt++ {
		if ctx.Err() != nil {
			break
		}
		if e.limiter != nil {
			if err := e.limiter.wait(ctx); err != nil {
				break
			}
		}
		timeout := jitteredTimeout(tracker.Timeout(e.opts.Timing.InitialTimeout, e.opts.Timing.MaxTimeout), e.rnd.Float64)
		var rtt time.Duration
		switch p.Proto {
		case ports.UDP:
			state, reason, rtt = e.udpProbe(ctx, addr, p.Port, timeout)
		default:
			if e.syn != nil {
				state, reason, rtt = e.synProbe(ctx, addr, p.Port, timeout)
			} else {
				state, reason, rtt = e.connectProbe(ctx, addr, p.Port, timeout)
			}
		}
		if rtt > 0 {
			tracker.Observe(rtt, 0)
		}
		if reason != model.ReasonNoResponse {
			break
		}
	}
	return model.Port{Port: p.Port, Proto: p.Proto, State: state, Reason: reason}
}

// synProbe wraps the raw socket prober. Loopback and local addresses go
// through a connect probe instead, because the kernel already owns that path
// and a forged SYN/ACK there proves less than a real handshake.
func (e *Engine) synProbe(ctx context.Context, addr netip.Addr, port int, timeout time.Duration) (model.State, model.Reason, time.Duration) {
	if e.techniqueFor(addr) == model.TechniqueConnect {
		st, rs, rtt := e.connectProbe(ctx, addr, port, timeout)
		if st == model.StateOpen {
			rs = model.ReasonLocalhost
		}
		return st, rs, rtt
	}
	return e.syn.probe(ctx, addr, port, timeout)
}

// techniqueFor reports how a given target is actually probed. It is the single
// source of truth for that decision: the probe path and the reported technique
// both come from here, so they cannot drift apart.
func (e *Engine) techniqueFor(addr netip.Addr) string {
	if e.syn == nil {
		return model.TechniqueConnect
	}
	if addr.IsLoopback() || isLocalAddr(addr) || !addr.Is4() {
		// A half-open scan of the machine itself, or over IPv6, is not
		// something this build can honestly claim to do.
		return model.TechniqueConnect
	}
	return model.TechniqueSYN
}

// Techniques reports which probe techniques will actually be used for the
// configured targets, sorted, plus whether more than one is involved.
//
// It is derived from the targets rather than from the request on purpose: a
// "syn" scan of 127.0.0.1 will use a connect probe for every target, and the
// report has to say connect, not syn.
func (e *Engine) Techniques() (techniques []string, mixed bool) {
	seen := map[string]bool{}
	for _, t := range e.opts.Targets {
		seen[e.techniqueFor(t.Addr)] = true
	}
	for tech := range seen {
		techniques = append(techniques, tech)
	}
	sort.Strings(techniques)
	return techniques, len(techniques) > 1
}

func (e *Engine) tickProgress() {
	d := e.done.Add(1)
	if e.opts.OnProgress != nil {
		e.opts.OnProgress(int(d), int(e.total))
	}
}

// helpers ------------------------------------------------------------------

// netipToTCP renders an address and port as a dial target.
func netipToTCP(addr netip.Addr, port int) string {
	return net.JoinHostPort(addr.String(), strconv.Itoa(port))
}

func addrType(a netip.Addr) string {
	if a.Is4() {
		return "ipv4"
	}
	return "ipv6"
}

func appendUniqueString(list []string, v string) []string {
	for _, s := range list {
		if strings.EqualFold(s, v) {
			return list
		}
	}
	return append(list, v)
}

var localAddrsOnce sync.Once
var localAddrSet map[netip.Addr]bool

func isLocalAddr(a netip.Addr) bool {
	localAddrsOnce.Do(func() {
		localAddrSet = map[netip.Addr]bool{}
		addrs, err := net.InterfaceAddrs()
		if err != nil {
			return
		}
		for _, ia := range addrs {
			var ip net.IP
			switch v := ia.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil {
				continue
			}
			if a, ok := netip.AddrFromSlice(ip); ok {
				localAddrSet[a.Unmap()] = true
			}
		}
	})
	return localAddrSet[a.Unmap()]
}

// proxyDialer builds a SOCKS5 dialer from a URL such as
// socks5://user:pass@127.0.0.1:1080. A bare host:port is accepted too.
func proxyDialer(raw string) (proxy.ContextDialer, error) {
	spec := raw
	if !strings.Contains(spec, "://") {
		spec = "socks5://" + spec
	}
	u, err := url.Parse(spec)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL %q: %w", raw, err)
	}
	switch strings.ToLower(u.Scheme) {
	case "socks5", "socks5h", "socks":
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q (only socks5 is supported)", u.Scheme)
	}
	var auth *proxy.Auth
	if u.User != nil {
		pw, _ := u.User.Password()
		auth = &proxy.Auth{User: u.User.Username(), Password: pw}
	}
	addr := u.Host
	if u.Port() == "" {
		addr = net.JoinHostPort(u.Hostname(), "1080")
	}
	d, err := proxy.SOCKS5("tcp", addr, auth, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("cannot set up the SOCKS5 proxy: %w", err)
	}
	cd, ok := d.(proxy.ContextDialer)
	if !ok {
		return nil, errors.New("proxy dialer does not support contexts")
	}
	return cd, nil
}

// rateLimiter wraps a token bucket. A nil receiver is valid and never blocks.
type rateLimiter struct {
	lim *rate.Limiter
}

func newRateLimiter(maxRate int) *rateLimiter {
	if maxRate <= 0 {
		return &rateLimiter{}
	}
	burst := maxRate / 10
	if burst < 1 {
		burst = 1
	}
	if burst > 1000 {
		burst = 1000
	}
	return &rateLimiter{lim: rate.NewLimiter(rate.Limit(maxRate), burst)}
}

func (r *rateLimiter) wait(ctx context.Context) error {
	if r == nil || r.lim == nil {
		return nil
	}
	return r.lim.Wait(ctx)
}

// lockedRand is a mutex-protected source of randomness. The scanner already
// coordinates with channels, so a single lock here is cheaper than a pool.
type lockedRand struct {
	mu sync.Mutex
	r  *rand.Rand
}

func newLockedRand() *lockedRand {
	return &lockedRand{r: rand.New(rand.NewSource(time.Now().UnixNano()))}
}

func (l *lockedRand) Float64() float64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.r.Float64()
}

func (l *lockedRand) Intn(n int) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.r.Intn(n)
}

func (l *lockedRand) Uint32() uint32 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.r.Uint32()
}

func (l *lockedRand) Shuffle(n int, swap func(i, j int)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.r.Shuffle(n, swap)
}
