package scan

import (
	"sync"
	"time"
)

// hardMaxParallel caps concurrency regardless of what the user asks for, to
// stay well inside default file-descriptor limits.
const hardMaxParallel = 512

// Timing is the resolved set of performance knobs.
//
// The templates are approximations of nmap's -T levels. They are tuned for a
// connect scanner whose per-probe cost is a real socket, so the retry counts
// are lower than nmap's: nmap's values assume its own RTT estimation loop.
type Timing struct {
	Template       int
	InitialTimeout time.Duration
	MaxTimeout     time.Duration
	MaxRetries     int
	MinParallel    int
	MaxParallel    int
	Delay          time.Duration
	MinRate        int
	MaxRate        int
}

// TimingTemplate returns the preset for a -T level (0-5). Out-of-range values
// fall back to the normal template.
func TimingTemplate(t int) Timing {
	switch t {
	case 0: // paranoid
		return Timing{Template: 0, InitialTimeout: 300 * time.Second, MaxTimeout: 300 * time.Second,
			MaxRetries: 3, MinParallel: 1, MaxParallel: 1, Delay: 5 * time.Minute}
	case 1: // sneaky
		return Timing{Template: 1, InitialTimeout: 15 * time.Second, MaxTimeout: 45 * time.Second,
			MaxRetries: 3, MinParallel: 1, MaxParallel: 1, Delay: 15 * time.Second}
	case 2: // polite
		return Timing{Template: 2, InitialTimeout: 10 * time.Second, MaxTimeout: 30 * time.Second,
			MaxRetries: 3, MinParallel: 1, MaxParallel: 1, Delay: 400 * time.Millisecond}
	case 4: // aggressive
		return Timing{Template: 4, InitialTimeout: 500 * time.Millisecond, MaxTimeout: 2 * time.Second,
			MaxRetries: 2, MinParallel: 16, MaxParallel: 128}
	case 5: // insane
		return Timing{Template: 5, InitialTimeout: 250 * time.Millisecond, MaxTimeout: time.Second,
			MaxRetries: 1, MinParallel: 64, MaxParallel: 512}
	default: // 3, normal
		return Timing{Template: 3, InitialTimeout: time.Second, MaxTimeout: 3 * time.Second,
			MaxRetries: 3, MinParallel: 8, MaxParallel: 32}
	}
}

// Clamp keeps the parallel settings inside the supported range.
//
// MinParallel is deliberately allowed to exceed MaxParallel: nmap users read
// --min-parallelism as "use at least this much concurrency", so asking for
// more than the timing template's default has to actually raise it. The engine
// takes the larger of the two.
func (t *Timing) Clamp() {
	if t.MaxParallel <= 0 {
		t.MaxParallel = 32
	}
	if t.MaxParallel > hardMaxParallel {
		t.MaxParallel = hardMaxParallel
	}
	if t.MinParallel <= 0 {
		t.MinParallel = 1
	}
	if t.MinParallel > hardMaxParallel {
		t.MinParallel = hardMaxParallel
	}
	if t.MaxRetries < 0 {
		t.MaxRetries = 0
	}
	if t.InitialTimeout <= 0 {
		t.InitialTimeout = time.Second
	}
	if t.MaxTimeout < t.InitialTimeout {
		t.MaxTimeout = t.InitialTimeout
	}
}

// RTTTracker is a per-host round trip estimator using the RFC 6298 update
// rules. It lets a probe timeout adapt to a slow target instead of either
// wasting time on a fast LAN or producing false "filtered" results on a slow
// WAN link.
type RTTTracker struct {
	mu      sync.Mutex
	srtt    time.Duration
	rttvar  time.Duration
	samples int
	ttl     int
}

// NewRTTTracker returns a tracker with an optional seed sample (usually the
// host discovery round trip).
func NewRTTTracker(seed time.Duration) *RTTTracker {
	tr := &RTTTracker{}
	if seed > 0 {
		tr.Observe(seed, 0)
	}
	return tr
}

// Observe records a new round trip measurement.
func (t *RTTTracker) Observe(rtt time.Duration, ttl int) {
	if rtt <= 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if ttl > 0 {
		t.ttl = ttl
	}
	if t.samples == 0 {
		t.srtt = rtt
		t.rttvar = rtt / 2
	} else {
		delta := t.srtt - rtt
		if delta < 0 {
			delta = -delta
		}
		t.rttvar = (3*t.rttvar + delta) / 4
		t.srtt = (7*t.srtt + rtt) / 8
	}
	t.samples++
}

// Timeout returns the probe timeout to use for this host.
func (t *RTTTracker) Timeout(base, max time.Duration) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.samples == 0 {
		return base
	}
	est := t.srtt + 4*t.rttvar
	if est < base {
		est = base
	}
	if est > max {
		est = max
	}
	return est
}

// Stats returns (srtt, rttvar, ttl, samples).
func (t *RTTTracker) Stats() (time.Duration, time.Duration, int, int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.srtt, t.rttvar, t.ttl, t.samples
}

// jitteredTimeout adds a small random spread so that a whole subnet does not
// retry in lockstep and self-synchronise its timeouts.
func jitteredTimeout(d time.Duration, rnd func() float64) time.Duration {
	if d <= 0 {
		return d
	}
	scale := 0.9 + 0.2*rnd()
	return time.Duration(float64(d) * scale)
}
