package scan

import (
	"context"
	"net/netip"
	"time"

	"github.com/guaidao2/argus/internal/model"
	"github.com/guaidao2/argus/internal/targets"
)

// discoveryPorts are the TCP ports used for host discovery. A completed
// handshake and a RST both prove the host is reachable, which is why a closed
// port is a perfectly good liveness signal.
var discoveryPorts = []int{80, 443, 22}

// discover decides whether a host is up.
//
// ICMP echo is deliberately not used: it needs raw privileges on every
// platform and is filtered far more often than TCP, so a TCP ping is both
// cheaper and more reliable. Use -Pn to skip discovery entirely.
func (e *Engine) discover(ctx context.Context, t targets.Target) (bool, time.Duration, model.Reason) {
	local := t.Addr.IsLoopback() || isLocalAddr(t.Addr)

	up, rtt, reason := e.tcpPing(ctx, t.Addr)
	if local {
		// A loopback or local address is reachable by definition. Probing it
		// anyway gives a realistic round trip time for the report, but the
		// verdict must not depend on a service happening to listen.
		return true, rtt, model.ReasonLocalhost
	}
	if !up {
		return false, 0, model.ReasonNoResponse
	}
	return true, rtt, reason
}

// tcpPing probes the discovery ports in parallel and reports the fastest
// answer.
func (e *Engine) tcpPing(ctx context.Context, addr netip.Addr) (bool, time.Duration, model.Reason) {
	type answer struct {
		up     bool
		rtt    time.Duration
		reason model.Reason
	}

	pingCtx, cancel := context.WithTimeout(ctx, e.opts.DiscoveryTimeout)
	defer cancel()

	results := make(chan answer, len(discoveryPorts))
	for _, port := range discoveryPorts {
		go func(port int) {
			st, _, rtt := e.connectProbe(pingCtx, addr, port, e.opts.DiscoveryTimeout)
			switch st {
			case model.StateOpen:
				results <- answer{up: true, rtt: rtt, reason: model.ReasonSynAck}
			case model.StateClosed:
				results <- answer{up: true, rtt: rtt, reason: model.ReasonReset}
			default:
				results <- answer{}
			}
		}(port)
	}

	best := answer{}
	for i := 0; i < len(discoveryPorts); i++ {
		r := <-results
		if !r.up {
			continue
		}
		if !best.up || (r.rtt > 0 && (best.rtt == 0 || r.rtt < best.rtt)) {
			best = r
		}
	}
	if !best.up {
		return false, 0, model.ReasonNoResponse
	}
	return true, best.rtt, best.reason
}
