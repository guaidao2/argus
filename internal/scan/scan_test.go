package scan

import (
	"encoding/hex"
	"errors"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/guaidao2/argus/internal/model"
	"github.com/guaidao2/argus/internal/targets"
)

func TestUDPPayloadsAreValidHex(t *testing.T) {
	if len(udpHexPayloads) == 0 {
		t.Fatal("no binary UDP payloads registered")
	}
	for port, h := range udpHexPayloads {
		raw, err := hex.DecodeString(h)
		if err != nil {
			t.Errorf("port %d payload is not valid hex: %v", port, err)
			continue
		}
		if len(raw) == 0 || len(raw) > 512 {
			t.Errorf("port %d payload has a suspicious length %d", port, len(raw))
		}
	}
	for port, text := range udpTextPayloads {
		if len(text) == 0 {
			t.Errorf("port %d has an empty text payload", port)
		}
	}
}

func TestUDPPayloadSelection(t *testing.T) {
	if got := udpPayload(53); len(got) == 0 || got[0] != 0x12 {
		t.Errorf("DNS probe looks wrong: %x", got)
	}
	if got := udpPayload(123); len(got) != 48 || got[0] != 0x1b {
		t.Errorf("NTP probe should be a 48 byte client request: %d bytes, first %#x", len(got), got[0])
	}
	if got := udpPayload(11211); string(got) != "stats\r\n" {
		t.Errorf("memcached probe = %q", got)
	}
	if got := udpPayload(1); got != nil {
		t.Errorf("an unknown port should have no specific payload, got %x", got)
	}
}

func TestTimingTemplates(t *testing.T) {
	for level := 0; level <= 5; level++ {
		tpl := TimingTemplate(level)
		if tpl.Template != level {
			t.Errorf("TimingTemplate(%d).Template = %d", level, tpl.Template)
		}
		clamped := tpl
		clamped.Clamp()
		if clamped.InitialTimeout <= 0 || clamped.MaxTimeout < clamped.InitialTimeout {
			t.Errorf("template %d has nonsensical timeouts: %+v", level, clamped)
		}
		if clamped.MaxParallel < 1 || clamped.MaxParallel > hardMaxParallel {
			t.Errorf("template %d parallelism out of range: %d", level, clamped.MaxParallel)
		}
		if clamped.MaxRetries < 0 {
			t.Errorf("template %d has negative retries", level)
		}
	}
	// The paranoid template must be slower than the insane one.
	if TimingTemplate(0).InitialTimeout <= TimingTemplate(5).InitialTimeout {
		t.Error("T0 should be more patient than T5")
	}
	if TimingTemplate(0).MaxParallel > TimingTemplate(5).MaxParallel {
		t.Error("T0 should be less parallel than T5")
	}
	// Out of range levels fall back to normal.
	if TimingTemplate(9).Template != 3 {
		t.Error("an unknown -T level should fall back to normal")
	}
}

func TestTimingClampBounds(t *testing.T) {
	tpl := Timing{MaxParallel: 100000, MinParallel: 50000, MaxRetries: -3, InitialTimeout: -1, MaxTimeout: 0}
	tpl.Clamp()
	if tpl.MaxParallel != hardMaxParallel {
		t.Errorf("MaxParallel = %d, want %d", tpl.MaxParallel, hardMaxParallel)
	}
	if tpl.MinParallel > tpl.MaxParallel {
		t.Errorf("MinParallel %d exceeds MaxParallel %d", tpl.MinParallel, tpl.MaxParallel)
	}
	if tpl.MaxRetries != 0 {
		t.Errorf("MaxRetries = %d", tpl.MaxRetries)
	}
	if tpl.InitialTimeout <= 0 || tpl.MaxTimeout < tpl.InitialTimeout {
		t.Errorf("timeouts were not repaired: %+v", tpl)
	}
}

func TestRTTTrackerAdaptsToSlowTargets(t *testing.T) {
	base := 100 * time.Millisecond
	max := 3 * time.Second

	fresh := NewRTTTracker(0)
	if got := fresh.Timeout(base, max); got != base {
		t.Errorf("without samples the timeout should be the base value, got %v", got)
	}

	// A fast LAN target keeps the timeout near the floor.
	fast := NewRTTTracker(0)
	for i := 0; i < 5; i++ {
		fast.Observe(2*time.Millisecond, 64)
	}
	if got := fast.Timeout(base, max); got != base {
		t.Errorf("a fast target should stay at the floor, got %v", got)
	}

	// A slow target raises it, and it never exceeds the ceiling.
	slow := NewRTTTracker(0)
	for i := 0; i < 5; i++ {
		slow.Observe(800*time.Millisecond, 64)
	}
	got := slow.Timeout(base, max)
	if got <= base {
		t.Errorf("a slow target should raise the timeout above %v, got %v", base, got)
	}
	if got > max {
		t.Errorf("timeout %v exceeds the ceiling %v", got, max)
	}

	// The ceiling wins even with an extreme measurement.
	extreme := NewRTTTracker(0)
	extreme.Observe(30*time.Second, 0)
	if got := extreme.Timeout(base, max); got != max {
		t.Errorf("timeout %v should be clamped to %v", got, max)
	}

	srtt, rttvar, ttl, samples := slow.Stats()
	if samples != 5 || srtt == 0 || rttvar == 0 || ttl != 64 {
		t.Errorf("Stats() = %v %v %d %d", srtt, rttvar, ttl, samples)
	}
}

func TestClassifyDialError(t *testing.T) {
	cases := []struct {
		err    error
		state  model.State
		reason model.Reason
	}{
		{syscall.ECONNREFUSED, model.StateClosed, model.ReasonConnRefused},
		{syscall.ECONNRESET, model.StateClosed, model.ReasonReset},
		{syscall.EHOSTUNREACH, model.StateFiltered, model.ReasonHostUnreach},
		{syscall.ENETUNREACH, model.StateFiltered, model.ReasonNetUnreach},
		{syscall.EACCES, model.StateFiltered, model.ReasonAdminProhibit},
		{errors.New("dial tcp: connection refused"), model.StateClosed, model.ReasonConnRefused},
		{errors.New("dial tcp: network is unreachable"), model.StateFiltered, model.ReasonNoResponse},
		{errors.New("something else"), model.StateFiltered, model.ReasonNoResponse},
	}
	for _, tc := range cases {
		state, reason := classifyDialError(tc.err)
		if state != tc.state || reason != tc.reason {
			t.Errorf("classifyDialError(%v) = (%s, %s), want (%s, %s)", tc.err, state, reason, tc.state, tc.reason)
		}
	}
	if state, reason := classifyDialError(nil); state != model.StateOpen || reason != model.ReasonSynAck {
		t.Errorf("nil error should mean open/syn-ack, got (%s, %s)", state, reason)
	}
}

func TestNetipToTCP(t *testing.T) {
	if got := netipToTCP(netip.MustParseAddr("192.0.2.1"), 22); got != "192.0.2.1:22" {
		t.Errorf("IPv4 = %q", got)
	}
	if got := netipToTCP(netip.MustParseAddr("2001:db8::1"), 443); got != "[2001:db8::1]:443" {
		t.Errorf("IPv6 must be bracketed, got %q", got)
	}
}

func TestAddrType(t *testing.T) {
	if got := addrType(netip.MustParseAddr("192.0.2.1")); got != "ipv4" {
		t.Errorf("got %q", got)
	}
	if got := addrType(netip.MustParseAddr("2001:db8::1")); got != "ipv6" {
		t.Errorf("got %q", got)
	}
}

func TestUDPBaseTimeoutFloor(t *testing.T) {
	if got := udpBaseTimeout(Timing{InitialTimeout: 250 * time.Millisecond}); got != 2*time.Second {
		t.Errorf("UDP needs a higher floor, got %v", got)
	}
	if got := udpBaseTimeout(Timing{InitialTimeout: 10 * time.Second}); got != 10*time.Second {
		t.Errorf("an explicit longer timeout must win, got %v", got)
	}
}

func TestRateLimiterDisabled(t *testing.T) {
	var nilLimiter *rateLimiter
	if err := nilLimiter.wait(nil); err != nil {
		t.Errorf("a nil limiter must not block: %v", err)
	}
	off := newRateLimiter(0)
	if off.lim != nil {
		t.Error("a zero rate should not create a token bucket")
	}
	if err := off.wait(nil); err != nil {
		t.Errorf("a disabled limiter must not block: %v", err)
	}
	on := newRateLimiter(100)
	if on.lim == nil {
		t.Fatal("a positive rate should create a token bucket")
	}
}

func TestProbeBudgetRespectsTiming(t *testing.T) {
	e := &Engine{opts: Options{Timing: TimingTemplate(3)}}
	e.opts.Timing.Clamp()
	if got := e.probeBudget(1000); got != e.opts.Timing.MaxParallel {
		t.Errorf("probeBudget = %d, want %d", got, e.opts.Timing.MaxParallel)
	}
	if got := e.probeBudget(3); got != 3 {
		t.Errorf("probeBudget must not exceed the port count, got %d", got)
	}
	e.opts.Timing.MaxParallel = 100000
	e.opts.Timing.Clamp()
	if got := e.probeBudget(100000); got != hardMaxParallel {
		t.Errorf("probeBudget = %d, want the hard ceiling %d", got, hardMaxParallel)
	}
}

// TestProbeBudgetHonoursMinParallelism guards against --min-parallelism being
// accepted and then ignored, which is worse than not offering it.
func TestProbeBudgetHonoursMinParallelism(t *testing.T) {
	tpl := TimingTemplate(3)
	tpl.MinParallel = tpl.MaxParallel * 4
	tpl.Clamp()
	if tpl.MinParallel <= tpl.MaxParallel {
		t.Fatalf("Clamp must not silently cap --min-parallelism: min=%d max=%d", tpl.MinParallel, tpl.MaxParallel)
	}
	e := &Engine{opts: Options{Timing: tpl}}
	if got := e.probeBudget(10000); got != tpl.MinParallel {
		t.Fatalf("probeBudget = %d, want the --min-parallelism floor %d", got, tpl.MinParallel)
	}

	// A min above the hard ceiling is still capped.
	over := Timing{MinParallel: 100000, MaxParallel: 4}
	over.Clamp()
	if over.MinParallel != hardMaxParallel {
		t.Fatalf("MinParallel = %d, want the hard ceiling %d", over.MinParallel, hardMaxParallel)
	}
}

func TestJitteredTimeoutStaysCloseToBase(t *testing.T) {
	base := time.Second
	rnd := func() float64 { return 0.5 }
	got := jitteredTimeout(base, rnd)
	if got != base {
		t.Errorf("with 0.5 jitter the timeout should be unchanged, got %v", got)
	}
	for i := 0; i < 100; i++ {
		f := float64(i) / 100
		got := jitteredTimeout(base, func() float64 { return f })
		if got < base*8/10 || got > base*11/10 {
			t.Fatalf("jitter went too far: %v", got)
		}
	}
	if jitteredTimeout(0, rnd) != 0 {
		t.Error("a zero timeout must stay zero")
	}
}

// TestTechniqueForIsTheSingleSourceOfTruth pins how a target maps to a probe
// technique. The probe path and the reported technique both read this method,
// so they cannot disagree about what actually ran.
func TestTechniqueForIsTheSingleSourceOfTruth(t *testing.T) {
	connectOnly := &Engine{opts: Options{Timing: TimingTemplate(3)}}
	if got := connectOnly.techniqueFor(netip.MustParseAddr("192.0.2.1")); got != model.TechniqueConnect {
		t.Errorf("without a raw socket everything is connect, got %q", got)
	}

	syn := &Engine{opts: Options{Timing: TimingTemplate(3)}, syn: &synScanner{}}
	if got := syn.techniqueFor(netip.MustParseAddr("192.0.2.1")); got != model.TechniqueSYN {
		t.Errorf("a routable IPv4 target should use SYN, got %q", got)
	}
	// Loopback and this machine's own addresses are probed with connect: the
	// kernel owns that path and a forged SYN there proves less.
	if got := syn.techniqueFor(netip.MustParseAddr("127.0.0.1")); got != model.TechniqueConnect {
		t.Errorf("loopback should use connect, got %q", got)
	}
	if got := syn.techniqueFor(netip.MustParseAddr("::1")); got != model.TechniqueConnect {
		t.Errorf("IPv6 loopback should use connect, got %q", got)
	}
	// IPv6 has no SYN implementation in this build.
	if got := syn.techniqueFor(netip.MustParseAddr("2001:db8::1")); got != model.TechniqueConnect {
		t.Errorf("IPv6 should use connect, got %q", got)
	}
}

// TestTechniquesIsDerivedFromTargets checks that the headline technique comes
// from what will actually run, not from what was requested: claiming a SYN
// scan while every probe is a connect would be exactly the kind of quiet lie
// the report is supposed to avoid.
func TestTechniquesIsDerivedFromTargets(t *testing.T) {
	opts := Options{
		ScanType: ScanSYN,
		Timing:   TimingTemplate(3),
		Targets: []targets.Target{
			{Addr: netip.MustParseAddr("192.0.2.1")},
			{Addr: netip.MustParseAddr("192.0.2.2")},
		},
	}
	syn := &Engine{opts: opts, syn: &synScanner{}}
	got, mixed := syn.Techniques()
	if len(got) != 1 || got[0] != model.TechniqueSYN || mixed {
		t.Fatalf("an all-routable SYN scan = %v mixed=%v", got, mixed)
	}

	// A single loopback target turns the whole run into connect.
	loopback := &Engine{opts: Options{
		ScanType: ScanSYN,
		Timing:   TimingTemplate(3),
		Targets:  []targets.Target{{Addr: netip.MustParseAddr("127.0.0.1")}},
	}, syn: &synScanner{}}
	got, mixed = loopback.Techniques()
	if len(got) != 1 || got[0] != model.TechniqueConnect || mixed {
		t.Fatalf("an all-loopback SYN scan must report connect, got %v mixed=%v", got, mixed)
	}

	// Both kinds at once is a genuine mix.
	both := &Engine{opts: Options{
		ScanType: ScanSYN,
		Timing:   TimingTemplate(3),
		Targets: []targets.Target{
			{Addr: netip.MustParseAddr("192.0.2.1")},
			{Addr: netip.MustParseAddr("127.0.0.1")},
		},
	}, syn: &synScanner{}}
	got, mixed = both.Techniques()
	if len(got) != 2 || !mixed {
		t.Fatalf("a mixed scan should report both techniques, got %v mixed=%v", got, mixed)
	}
	if got[0] != model.TechniqueConnect || got[1] != model.TechniqueSYN {
		t.Fatalf("techniques should be sorted, got %v", got)
	}
}
