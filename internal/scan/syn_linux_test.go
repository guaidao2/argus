//go:build linux

package scan

import (
	"context"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/guaidao2/argus/internal/model"
)

// rawSocketOrSkip builds a SYN scanner, skipping the test when the environment
// cannot provide a raw socket (no privileges, restricted namespace).
func rawSocketOrSkip(t *testing.T) *synScanner {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("raw sockets need privileges")
	}
	s, err := newSYNScanner(t.Logf)
	if err != nil {
		t.Skipf("no raw socket in this environment: %v", err)
	}
	return s
}

// TestSYNScannerCloseIsFast is a regression guard. close(2) does not wake a
// thread parked in recvfrom, so a blocking reader made Close take about 16
// seconds: every SYN scan hung for that long after finishing. The receive
// timeout is what fixes it, and this test is what keeps it fixed.
func TestSYNScannerCloseIsFast(t *testing.T) {
	s := rawSocketOrSkip(t)

	done := make(chan struct{})
	go func() {
		s.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Close blocked: the receive path is not honouring the shutdown flag")
	}
}

// TestSYNPreflightSucceedsOnLoopback pins the property the whole preflight
// design rests on: the raw socket can both send and receive on loopback, so
// loopback is a valid capability target and no packet has to leave the machine
// to find out whether a SYN scan will work.
func TestSYNPreflightSucceedsOnLoopback(t *testing.T) {
	s := rawSocketOrSkip(t)
	defer s.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.preflight(ctx, 1500*time.Millisecond); err != nil {
		t.Fatalf("preflight must pass on a working raw socket, got %v", err)
	}
}

// TestSYNProbeLoopbackStates checks that the probe interprets real replies
// correctly: a closed loopback port answers with a RST.
func TestSYNProbeLoopbackStates(t *testing.T) {
	s := rawSocketOrSkip(t)
	defer s.Close()

	state, reason, rtt := s.probe(context.Background(), netip.MustParseAddr("127.0.0.1"), 1, 1500*time.Millisecond)
	if state != model.StateClosed || reason != model.ReasonReset {
		t.Fatalf("a closed loopback port should be closed/reset, got %s/%s", state, reason)
	}
	if rtt <= 0 {
		t.Fatalf("a real reply must produce a round trip time, got %v", rtt)
	}
}

// TestSYNPreflightFailsWithoutReply covers the case the preflight exists for:
// a socket that opens but never hears anything back. A cancelled context
// reproduces it without needing a broken firewall.
func TestSYNPreflightFailsWithoutReply(t *testing.T) {
	s := rawSocketOrSkip(t)
	defer s.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.preflight(ctx, 50*time.Millisecond); err != ErrSYNNoReply {
		t.Fatalf("preflight should report ErrSYNNoReply, got %v", err)
	}
}

// TestSYNScannerSurvivesNilDebugf guards the constructor: callers may pass no
// logger, and the probe path logs.
func TestSYNScannerSurvivesNilDebugf(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("raw sockets need privileges")
	}
	s, err := newSYNScanner(nil)
	if err != nil {
		t.Skipf("no raw socket in this environment: %v", err)
	}
	defer s.Close()
	s.probe(context.Background(), netip.MustParseAddr("127.0.0.1"), 1, 200*time.Millisecond)
}
