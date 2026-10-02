//go:build linux

package scan

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"github.com/guaidao2/argus/internal/model"
)

// The Linux SYN scanner is implemented in pure Go on top of an
// AF_INET/SOCK_RAW/IPPROTO_TCP socket, so the released binary stays static and
// dependency free (no libpcap, no cgo). It needs CAP_NET_RAW.
//
// A raw socket sees every TCP segment on the wire, so replies are matched back
// to their probe by sequence number plus the source address/port pair.

type synProbeKey struct {
	addr netip.Addr
	port int
}

type synPending struct {
	key synProbeKey
	ch  chan model.State
}

type synScanner struct {
	fd     int
	debugf func(string, ...any)
	seq    *lockedRand

	mu     sync.Mutex
	bySeq  map[uint32]*synPending
	byAddr map[synProbeKey]*synPending
	srcIP  map[netip.Addr]netip.Addr

	closeOnce sync.Once
	done      chan struct{}
	wg        sync.WaitGroup
}

// receiveTimeout bounds a single recvfrom call. close(2) does NOT wake a
// thread parked in recvfrom, so a blocking receive would leave Close() hanging
// until something else happened to unblock it - measured at ~16 seconds in
// practice. With a receive timeout the reader wakes up on its own and notices
// the shutdown flag.
const receiveTimeout = 200 * time.Millisecond

func newSYNScanner(debugf func(string, ...any)) (*synScanner, error) {
	if debugf == nil {
		debugf = func(string, ...any) {}
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSYNPrivileges, err)
	}
	// A large receive buffer keeps the raw socket from dropping the replies
	// of an aggressive scan.
	_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 1<<20)
	tv := syscall.NsecToTimeval(receiveTimeout.Nanoseconds())
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	s := &synScanner{
		fd:     fd,
		debugf: debugf,
		seq:    newLockedRand(),
		bySeq:  make(map[uint32]*synPending, 1024),
		byAddr: make(map[synProbeKey]*synPending, 1024),
		srcIP:  make(map[netip.Addr]netip.Addr, 64),
		done:   make(chan struct{}),
	}
	s.wg.Add(1)
	go s.receiveLoop()
	return s, nil
}

// Close stops the receiver and releases the socket.
func (s *synScanner) Close() {
	s.closeOnce.Do(func() {
		close(s.done)
		_ = syscall.Close(s.fd)
		s.wg.Wait()
	})
}

func (s *synScanner) register(seq uint32, p *synPending) {
	s.mu.Lock()
	s.bySeq[seq] = p
	s.byAddr[p.key] = p
	s.mu.Unlock()
}

func (s *synScanner) unregister(seq uint32, p *synPending) {
	s.mu.Lock()
	if cur, ok := s.bySeq[seq]; ok && cur == p {
		delete(s.bySeq, seq)
	}
	if cur, ok := s.byAddr[p.key]; ok && cur == p {
		delete(s.byAddr, p.key)
	}
	s.mu.Unlock()
}

// preflightPorts are loopback ports used to verify the raw socket end to end.
// Almost every host has these closed, so a RST is the expected answer; a
// listener on one of them would give a SYN/ACK, which proves just as much.
var preflightPorts = []int{1, 9, 45678}

// Preflight proves that the raw socket both sends and receives before a single
// scan packet goes out.
//
// Opening the socket is not enough. A container with a restricted network
// namespace, a local firewall or an unusual BPF filter can leave a raw socket
// that transmits happily and never receives, and that would silently turn
// every scanned port into a false "filtered". Catching it here means the user
// gets an error instead of a plausible looking wrong answer.
//
// The probes go to 127.0.0.1, so nothing leaves the machine.
func (s *synScanner) preflight(ctx context.Context, timeout time.Duration) error {
	loopback := netip.MustParseAddr("127.0.0.1")
	answers := make(chan bool, len(preflightPorts))
	for _, port := range preflightPorts {
		go func(port int) {
			state, _, _ := s.probe(ctx, loopback, port, timeout)
			answers <- state != model.StateFiltered
		}(port)
	}
	for range preflightPorts {
		if <-answers {
			return nil
		}
	}
	return ErrSYNNoReply
}

// probe sends a SYN and interprets the answer.
func (s *synScanner) probe(ctx context.Context, addr netip.Addr, port int, timeout time.Duration) (model.State, model.Reason, time.Duration) {
	src, err := s.sourceFor(addr)
	if err != nil {
		s.debugf("syn: cannot determine the source address for %s: %v", addr, err)
		return model.StateFiltered, model.ReasonNoResponse, 0
	}

	seq := s.seq.Uint32()
	srcPort := 1024 + int(s.seq.Uint32()%64000)
	p := &synPending{key: synProbeKey{addr: addr, port: port}, ch: make(chan model.State, 1)}
	s.register(seq, p)
	defer s.unregister(seq, p)

	pkt := buildSYNPacket(src, addr, srcPort, port, seq)
	sa := &syscall.SockaddrInet4{}
	addr4 := addr.As4()
	copy(sa.Addr[:], addr4[:])

	start := time.Now()
	if err := syscall.Sendto(s.fd, pkt, 0, sa); err != nil {
		s.debugf("syn: send to %s:%d failed: %v", addr, port, err)
		return model.StateFiltered, model.ReasonNoResponse, 0
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case st := <-p.ch:
		rtt := time.Since(start)
		switch st {
		case model.StateOpen:
			return model.StateOpen, model.ReasonSynAck, rtt
		case model.StateClosed:
			return model.StateClosed, model.ReasonReset, rtt
		}
		return st, model.ReasonNoResponse, rtt
	case <-timer.C:
		return model.StateFiltered, model.ReasonNoResponse, 0
	case <-ctx.Done():
		return model.StateFiltered, model.ReasonNoResponse, 0
	case <-s.done:
		return model.StateFiltered, model.ReasonNoResponse, 0
	}
}

// sourceFor asks the kernel which source address it would use for a target.
func (s *synScanner) sourceFor(dst netip.Addr) (netip.Addr, error) {
	s.mu.Lock()
	cached, ok := s.srcIP[dst]
	s.mu.Unlock()
	if ok {
		return cached, nil
	}
	// Dialing a UDP socket performs a route lookup without sending anything.
	c, err := net.Dial("udp4", net.JoinHostPort(dst.String(), "9"))
	if err != nil {
		return netip.Addr{}, err
	}
	defer c.Close()
	la, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok {
		return netip.Addr{}, errors.New("unexpected local address type")
	}
	ip, ok := netip.AddrFromSlice(la.IP)
	if !ok {
		return netip.Addr{}, errors.New("unexpected local address family")
	}
	ip = ip.Unmap()
	s.mu.Lock()
	s.srcIP[dst] = ip
	s.mu.Unlock()
	return ip, nil
}

func (s *synScanner) receiveLoop() {
	defer s.wg.Done()
	buf := make([]byte, 65536)
	for {
		n, _, err := syscall.Recvfrom(s.fd, buf, 0)
		if err != nil {
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			// Shutdown first: after Close the fd is gone and every call fails.
			select {
			case <-s.done:
				return
			default:
			}
			// The receive timeout firing is the normal idle case; just go
			// round again so the shutdown flag is re-checked.
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
				continue
			}
			time.Sleep(time.Millisecond)
			continue
		}
		s.handlePacket(buf[:n])
	}
}

func (s *synScanner) handlePacket(pkt []byte) {
	if len(pkt) < 20 {
		return
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl+20 {
		return
	}
	if pkt[9] != 6 { // IPPROTO_TCP
		return
	}
	tcp := pkt[ihl:]
	doff := int(tcp[12]>>4) * 4
	if doff < 20 || len(tcp) < doff {
		return
	}
	flags := tcp[13]
	srcPort := int(binary.BigEndian.Uint16(tcp[0:2]))
	ack := binary.BigEndian.Uint32(tcp[8:12])

	if pkt[0]>>4 != 4 {
		return
	}
	// The reply's source address and port are the target we asked about; the
	// destination port is our own forged source port and carries no information.
	srcIP := netip.AddrFrom4([4]byte(pkt[12:16]))
	key := synProbeKey{addr: srcIP, port: srcPort}

	switch {
	case flags&0x12 == 0x12: // SYN|ACK: the port is open
		s.deliver(ack-1, key, model.StateOpen)
	case flags&0x04 != 0: // RST: the port is closed
		seq := binary.BigEndian.Uint32(tcp[4:8])
		s.deliver(ack-1, key, model.StateClosed)
		s.deliver(seq, key, model.StateClosed)
	}
}

func (s *synScanner) deliver(seq uint32, key synProbeKey, st model.State) {
	if seq == 0 {
		return
	}
	s.mu.Lock()
	p := s.bySeq[seq]
	if p != nil && p.key != key {
		p = nil
	}
	if p == nil {
		p = s.byAddr[key]
	}
	s.mu.Unlock()
	if p == nil {
		return
	}
	select {
	case p.ch <- st:
	default:
	}
}

// buildSYNPacket returns a 20-byte TCP header with the SYN flag set and a
// correct checksum. The kernel prepends the IP header for IPPROTO_TCP raw
// sockets.
func buildSYNPacket(src, dst netip.Addr, srcPort, dstPort int, seq uint32) []byte {
	pkt := make([]byte, 20)
	binary.BigEndian.PutUint16(pkt[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(pkt[2:4], uint16(dstPort))
	binary.BigEndian.PutUint32(pkt[4:8], seq)
	pkt[12] = 5 << 4 // data offset: 5 32-bit words
	pkt[13] = 0x02   // SYN
	binary.BigEndian.PutUint16(pkt[14:16], 64240)
	binary.BigEndian.PutUint16(pkt[16:18], tcpChecksum(src, dst, pkt))
	return pkt
}

func tcpChecksum(src, dst netip.Addr, segment []byte) uint16 {
	s, d := src.As4(), dst.As4()
	pseudo := make([]byte, 0, 12+len(segment))
	pseudo = append(pseudo, s[:]...)
	pseudo = append(pseudo, d[:]...)
	pseudo = append(pseudo, 0, 6) // zero, protocol TCP
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(segment)))
	pseudo = append(pseudo, l[:]...)

	sum := onesComplementSum(pseudo) + onesComplementSum(segment)
	return ^foldSum(sum)
}

func onesComplementSum(b []byte) uint32 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	return sum
}

func foldSum(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(sum)
}
