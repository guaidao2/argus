package scan

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"time"

	"github.com/guaidao2/argus/internal/model"
)

// connectProbe performs a full TCP handshake. It is the default technique: no
// privileges, works through SOCKS5 proxies and behaves the same everywhere.
func (e *Engine) connectProbe(ctx context.Context, addr netip.Addr, port int, timeout time.Duration) (model.State, model.Reason, time.Duration) {
	target := netipToTCP(addr, port)

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	var (
		conn net.Conn
		err  error
	)
	if e.proxy != nil {
		conn, err = e.proxy.DialContext(dialCtx, "tcp", target)
	} else {
		d := *e.dialer
		d.Timeout = timeout
		conn, err = d.DialContext(dialCtx, "tcp", target)
	}
	rtt := time.Since(start)

	if err == nil {
		_ = conn.Close()
		return model.StateOpen, model.ReasonSynAck, rtt
	}
	state, reason := classifyDialError(err)
	if reason == model.ReasonNoResponse {
		// A timeout measures the deadline, not the network.
		rtt = 0
	}
	return state, reason, rtt
}

// classifyDialError maps a dial failure onto an nmap-style state/reason pair.
func classifyDialError(err error) (model.State, model.Reason) {
	switch {
	case err == nil:
		return model.StateOpen, model.ReasonSynAck
	case errors.Is(err, syscall.ECONNREFUSED):
		return model.StateClosed, model.ReasonConnRefused
	case errors.Is(err, syscall.ECONNRESET):
		return model.StateClosed, model.ReasonReset
	case errors.Is(err, syscall.EHOSTUNREACH):
		return model.StateFiltered, model.ReasonHostUnreach
	case errors.Is(err, syscall.ENETUNREACH):
		return model.StateFiltered, model.ReasonNetUnreach
	case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM):
		return model.StateFiltered, model.ReasonAdminProhibit
	case errors.Is(err, context.DeadlineExceeded):
		return model.StateFiltered, model.ReasonNoResponse
	case errors.Is(err, context.Canceled):
		return model.StateFiltered, model.ReasonNoResponse
	}

	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return model.StateFiltered, model.ReasonNoResponse
	}

	// Last resort: Windows and a few proxies surface these as plain strings.
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "refused"):
		return model.StateClosed, model.ReasonConnRefused
	case strings.Contains(msg, "host is down"), strings.Contains(msg, "host unreachable"),
		strings.Contains(msg, "network is unreachable"):
		return model.StateFiltered, model.ReasonNoResponse
	}
	return model.StateFiltered, model.ReasonNoResponse
}
