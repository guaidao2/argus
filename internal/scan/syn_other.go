//go:build !linux

package scan

import (
	"context"
	"net/netip"
	"time"

	"github.com/guaidao2/argus/internal/model"
)

// SYN scanning needs raw sockets. On Linux argus implements them in pure Go;
// on Windows it would need Npcap and on macOS BPF. Rather than pull a driver
// dependency into a static binary, argus refuses the request with a clear
// error. It never silently downgrades to a connect scan: the user asked for a
// half-open scan and must know they did not get one.
type synScanner struct {
	debugf func(string, ...any)
}

func newSYNScanner(debugf func(string, ...any)) (*synScanner, error) {
	return nil, ErrSYNUnsupported
}

func (s *synScanner) preflight(ctx context.Context, timeout time.Duration) error {
	return ErrSYNUnsupported
}

func (s *synScanner) probe(ctx context.Context, addr netip.Addr, port int, timeout time.Duration) (model.State, model.Reason, time.Duration) {
	return model.StateFiltered, model.ReasonNoResponse, 0
}

func (s *synScanner) Close() {}
