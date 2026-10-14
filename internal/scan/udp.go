package scan

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/guaidao2/argus/internal/model"
)

// udpProbe sends a service-appropriate payload and waits for any reply.
//
// The connected UDP socket lets the kernel hand us the ICMP port-unreachable
// error that Linux reports as ECONNREFUSED, which is what distinguishes
// "closed" from "open|filtered" without needing a raw socket. On systems that
// do not surface that error a silent port stays open|filtered, which is
// exactly what nmap reports in the same situation.
func (e *Engine) udpProbe(ctx context.Context, addr netip.Addr, port int, timeout time.Duration) (model.State, model.Reason, time.Duration) {
	return e.udpProbeWith(ctx, addr, port, timeout, udpPayload(port))
}

// udpProbeWith is udpProbe with the payload chosen by the caller.
//
// Whether a silent UDP port is silent because the service has nothing to say or
// because it could not decode what it was sent is the whole question the payload
// answers, so it is worth being able to pose it directly -- against a port a
// test can actually bind.
func (e *Engine) udpProbeWith(ctx context.Context, addr netip.Addr, port int, timeout time.Duration, payload []byte) (model.State, model.Reason, time.Duration) {
	target := netipToTCP(addr, port)

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := e.dialer.DialContext(dialCtx, "udp", target)
	if err != nil {
		st, rs := classifyDialError(err)
		return st, rs, 0
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Always send something, even a zero length datagram: a port that receives
	// nothing at all answers nothing, so the probe would learn nothing and
	// every silent port would look identical.
	if payload == nil {
		payload = []byte{0}
	}
	if _, werr := conn.Write(payload); werr != nil {
		if errors.Is(werr, syscall.ECONNREFUSED) {
			return model.StateClosed, model.ReasonPortUnreach, 0
		}
		st, rs := classifyDialError(werr)
		return st, rs, 0
	}

	buf := make([]byte, 4096)
	start := time.Now()
	n, rerr := conn.Read(buf)
	rtt := time.Since(start)
	if rerr == nil && n > 0 {
		return model.StateOpen, model.ReasonUDPResponse, rtt
	}
	if rerr != nil {
		switch {
		case errors.Is(rerr, syscall.ECONNREFUSED):
			return model.StateClosed, model.ReasonPortUnreach, 0
		case errors.Is(rerr, syscall.EHOSTUNREACH):
			return model.StateFiltered, model.ReasonHostUnreach, 0
		case errors.Is(rerr, syscall.ENETUNREACH):
			return model.StateFiltered, model.ReasonNetUnreach, 0
		}
		var ne net.Error
		if errors.As(rerr, &ne) && ne.Timeout() {
			return model.StateOpenFiltered, model.ReasonNoResponse, 0
		}
	}
	return model.StateOpenFiltered, model.ReasonNoResponse, 0
}

// udpPayload returns a payload likely to trigger a reply on well-known UDP
// services. nmap ships a much larger nmap-payloads file; these are the probes
// that matter most during a first pass.
func udpPayload(port int) []byte {
	if h, ok := udpHexPayloads[port]; ok {
		if b, err := hex.DecodeString(h); err == nil {
			return b
		}
	}
	if t, ok := udpTextPayloads[port]; ok {
		return []byte(t)
	}
	return nil
}

// udpTextPayloads are plain ASCII probes.
var udpTextPayloads = map[int]string{
	11211: "stats\r\n",
	1900: "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 1\r\n" +
		"ST: ssdp:all\r\n\r\n",
	27015: "\xff\xff\xff\xffTSource Engine Query\x00",
}

// udpHexPayloads are binary probes. Every entry must be valid hex; the test
// suite decodes all of them.
var udpHexPayloads = map[int]string{
	// Portmap/rpcbind DUMP: an RPC call for program 100000, version 2,
	// procedure 4, with AUTH_NULL credentials and verifier. 40 bytes, and UDP
	// carries no record marker.
	//
	// This port used to send a single 0x00 byte, which a portmapper drops
	// without a word because it cannot decode it: the reply never came, the
	// port was classified open|filtered, and detection only runs on open ports,
	// so no fingerprint or check for 111 could ever be reached over UDP. A real
	// call is what makes the port answer.
	111: "000000010000000000000002000186a0000000020000000400000000000000000000000000000000",
	// DNS standard query (RD set) for www.example.com A.
	53: "12340100000100000000000003777777076578616d706c6503636f6d0000010001",
	// mDNS query for "localhost" A.
	5353: "000000000001000000000000096c6f63616c686f73740000010001",
	// NTPv3 client request: 48 bytes, first byte 0x1b (LI 0, VN 3, mode 3).
	123: "1b" +
		"0000000000000000000000000000000000000000000000000000000000000000" +
		"000000000000000000000000000000",
	// SNMPv1 get-request, sysDescr.0, community "public" (43 bytes).
	//
	// It has to be sysDescr.0 (1.3.6.1.2.1.1.1.0) and not a prefix of it: a
	// prefix answers noSuchName, which still proves the community string works
	// but carries no information, and sysDescr alone usually names the operating
	// system and its version. Verified against a real snmpd, byte for byte
	// against what net-snmp's snmpget puts on the wire.
	161: "302902010004067075626c6963a01c020401020304020100020100300e300c06082b060102010101000500",
	// NetBIOS name service query for the wildcard name "*" (50 bytes).
	137: "000000100001000000000000" + "20434b" +
		"414141414141414141414141414141414141414141414141414141414141" +
		"0000200001",
	// IKEv1 main-mode SA proposal: ISAKMP header only, 28 bytes.
	500: "00000000000000000000000000000000" + "01100200" + "00000000" + "0000001c",
	// TFTP read request for a file that does not exist: a reply means "open".
	69: "0001616263006e65746173636969",
}
