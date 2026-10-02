package detect

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/guaidao2/argus/internal/model"
	"github.com/guaidao2/argus/internal/version"
)

// dial opens a plain or TLS connection to a port.
func (d *Detector) dial(ctx context.Context, host string, port int, proto string, tunnel string) (net.Conn, error) {
	network := "tcp"
	if proto == "udp" {
		network = "udp"
	}
	dialer := &net.Dialer{Timeout: d.probeTimeout}
	raw, err := dialer.DialContext(ctx, network, net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	if network == "udp" || tunnel != tunnelSSL {
		return raw, nil
	}
	cfg := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	}
	// Go omits SNI for IP literals, which is what we want.
	cfg.ServerName = host
	tc := tls.Client(raw, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return tc, nil
}

// runProbe performs one probe interaction on a fresh connection.
func (d *Detector) runProbe(ctx context.Context, host string, mport model.Port, tunnel string, p Probe) []byte {
	port := mport.Port
	proto := mport.Proto
	if proto == "" {
		proto = "tcp"
	}
	budget := d.probeTimeout + p.ReadTimeout
	cctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	conn, err := d.dial(cctx, host, port, proto, tunnel)
	if err != nil {
		d.debugf("probe %s:%d (%s) dial failed: %v", host, port, p.ID, err)
		return nil
	}
	defer conn.Close()

	if p.Wait > 0 {
		select {
		case <-time.After(p.Wait):
		case <-cctx.Done():
			return nil
		}
	}
	if p.Send != "" {
		_ = conn.SetWriteDeadline(time.Now().Add(p.ReadTimeout))
		if _, err := conn.Write(probeBytes(d.expand(p.Send, host, port))); err != nil {
			d.debugf("probe %s:%d (%s) write failed: %v", host, port, p.ID, err)
			return nil
		}
	}
	data, _ := readResponse(conn, p.ReadTimeout, p.ReadBytes)
	return data
}

// probeBytes converts the string a probe declares into the bytes to put on the
// wire.
//
// YAML has no byte string type: "\xff" is parsed as the codepoint U+00FF, which
// then encodes to the two UTF-8 bytes 0xC3 0xBF. A protocol author writes \xff
// to mean the single byte 0xff, and every built-in binary probe meant exactly
// that, so a request built this way went out longer than it claimed and the
// server dropped it.
//
// So: a string that is not valid UTF-8 is already a byte string and is passed
// through untouched; otherwise every rune that fits in a byte becomes that byte,
// and runes above U+00FF (real text) keep their UTF-8 encoding.
func probeBytes(s string) []byte {
	if !utf8.ValidString(s) {
		return []byte(s)
	}
	out := make([]byte, 0, len(s))
	for _, r := range s {
		if r > 0xff {
			out = append(out, string(r)...)
			continue
		}
		out = append(out, byte(r))
	}
	return out
}

// readResponse reads until the deadline, the byte limit or EOF. After the
// first chunk a short grace period is used so a chatty server does not hold
// the probe open for the full timeout.
//
// closedEarly reports that the peer accepted the connection and closed it
// without sending a byte, which is the signature of a TCP wrapper or a filter
// answering ahead of the service.
func readResponse(conn net.Conn, timeout time.Duration, limit int) (data []byte, closedEarly bool) {
	if limit <= 0 {
		limit = 8192
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	var out []byte
	tmp := make([]byte, 4096)
	deadline := time.Now().Add(timeout)
	for len(out) < limit {
		_ = conn.SetReadDeadline(deadline)
		n, err := conn.Read(tmp)
		if n > 0 {
			out = append(out, tmp[:n]...)
		}
		if err != nil {
			if len(out) == 0 && errors.Is(err, io.EOF) {
				return nil, true
			}
			break
		}
		deadline = time.Now().Add(200 * time.Millisecond)
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out, false
}

// expand substitutes the placeholders available inside probe payloads.
func (d *Detector) expand(tmpl, host string, port int) string {
	out := strings.NewReplacer(
		"{{host}}", host,
		"{{port}}", strconv.Itoa(port),
		"{{agent}}", d.agent,
		"{{argus_version}}", version.Version,
	).Replace(tmpl)
	for k, v := range d.vars {
		out = strings.ReplaceAll(out, "{{var:"+k+"}}", v)
	}
	return out
}
