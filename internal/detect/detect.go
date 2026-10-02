package detect

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"strings"
	"time"

	"github.com/guaidao2/argus/internal/i18n"
	"github.com/guaidao2/argus/internal/model"
	"github.com/guaidao2/argus/internal/ports"
	"github.com/guaidao2/argus/internal/safetext"
)

// Options configures a Detector.
type Options struct {
	// DB is the fingerprint database. When nil the built-in rules are loaded.
	DB *DB
	// ProbeTimeout bounds a single connection attempt.
	ProbeTimeout time.Duration
	// UserAgent is substituted into {{agent}} inside probe payloads.
	UserAgent string
	// Vars are extra substitutions available as {{var:NAME}}.
	Vars map[string]string
	// Lang selects the language of reported findings.
	Lang string
	// EnableChecks allows kind: check rules to run. Their probes are
	// recognisable as an attack on the wire, so this is off unless the user
	// asked for --findings.
	EnableChecks bool
	// Debugf receives diagnostics.
	Debugf func(format string, args ...any)
}

// Detector identifies services using the fingerprint database.
type Detector struct {
	db           *DB
	probeTimeout time.Duration
	agent        string
	vars         map[string]string
	lang         string
	checks       bool
	debugf       func(string, ...any)
}

// New builds a detector.
func New(opts Options) (*Detector, error) {
	db := opts.DB
	if db == nil {
		var err error
		if db, err = LoadBuiltin(); err != nil {
			return nil, err
		}
	}
	if opts.ProbeTimeout <= 0 {
		opts.ProbeTimeout = 3 * time.Second
	}
	agent := opts.UserAgent
	if agent == "" {
		agent = "Argus"
	}
	debugf := opts.Debugf
	if debugf == nil {
		debugf = func(string, ...any) {}
	}
	lang := opts.Lang
	if lang == "" {
		lang = i18n.DefaultLang
	}
	return &Detector{
		db:           db,
		probeTimeout: opts.ProbeTimeout,
		agent:        agent,
		vars:         opts.Vars,
		lang:         lang,
		checks:       opts.EnableChecks,
		debugf:       debugf,
	}, nil
}

// Name implements scan.Detector.
func (d *Detector) Name() string { return "probes" }

// DB exposes the rule database so plugins can extend it.
func (d *Detector) DB() *DB { return d.db }

// Detect inspects one open port.
//
// Order of operations:
//  1. one passive read, which is enough for banner-first services (SSH, FTP,
//     SMTP, VNC, MySQL) and tells us whether the port speaks TLS;
//  2. TLS-wrapped probes when the port looks like TLS;
//  3. plaintext probes;
//  4. the port table name as a last resort.
func (d *Detector) Detect(ctx context.Context, host string, port model.Port) (*model.Service, error) {
	svc := d.identify(ctx, host, port)
	if d.checks {
		d.runChecks(ctx, host, port, svc)
	}
	return svc, nil
}

// identify answers "what is this?". It never reports a finding.
// tunnelSSL marks a rule or connection as TLS wrapped.
const tunnelSSL = "ssl"

// isUDP reports whether a port is on the datagram side.
func isUDP(p model.Port) bool { return p.Proto == "udp" }

// identify answers "what is this?". It never reports a finding.
func (d *Detector) identify(ctx context.Context, host string, port model.Port) *model.Service {
	// A UDP service never volunteers a banner, so there is nothing to read
	// before probing it; skipping the passive read saves the wait.
	var passive []byte
	closedEarly := false
	if !isUDP(port) {
		passive, closedEarly = d.passiveBanner(ctx, host, port.Port)
	}

	tlsRecord := isTLSRecord(passive)
	triedTLS := isUDP(port) // TLS over UDP is not something this build does
	if !isUDP(port) && (tlsRecord || d.db.HasTLSRule(port.Port)) {
		triedTLS = true
		if svc := d.try(ctx, host, port, tunnelSSL, passive); svc != nil {
			return svc
		}
		if tlsRecord {
			// The port really is TLS but no rule matched; report what the
			// handshake told us rather than the bare port name.
			if info, ok := d.handshake(ctx, host, port.Port); ok {
				return &model.Service{
					Name:   portTableName(port),
					Method: "probed",
					Conf:   5,
					Tunnel: tunnelSSL,
					TLS:    info,
				}
			}
		}
	}

	if !tlsRecord {
		if svc := d.try(ctx, host, port, "", passive); svc != nil {
			return svc
		}
	}

	// Nothing answered in the clear. A service that waits for a ClientHello is
	// invisible to plaintext probes wherever it lives, and TLS is not confined
	// to 8443. One handshake attempt is cheap and turns "unknown" into a tunnel
	// with the certificate attached. Only open ports reach this code, so a full
	// port sweep does not pay for it.
	if !triedTLS && !tlsRecord {
		if svc := d.try(ctx, host, port, tunnelSSL, passive); svc != nil {
			return svc
		}
	}

	// The peer accepted the connection and closed it immediately. That is a TCP
	// wrapper or a filter in front of the service, not the service itself, and
	// nmap reports it as tcpwrapped. Naming the port from the table instead
	// (smtp, pop3) would dress a guess up as an identification.
	if closedEarly {
		return &model.Service{Name: "tcpwrapped", Method: "probed", Conf: 10}
	}

	return &model.Service{
		Name:   portTableName(port),
		Method: "table",
		Conf:   3,
	}
}

// runChecks answers "is anything wrong with it?" and appends the conclusions to
// the service.
//
// Checks run in their own pass rather than competing with the fingerprint
// rules. Identification and judgement are different questions about the same
// port: a fingerprint rule that wins the "first match" race must not stop a
// check from running, and a check must never overwrite what the port is.
func (d *Detector) runChecks(ctx context.Context, host string, port model.Port, svc *model.Service) {
	tunnel := ""
	if svc.Tunnel == tunnelSSL {
		tunnel = tunnelSSL
	}

	// A check is reached by the port it is bound to, or by the service the
	// identification pass just recognised. The second is what makes a Redis
	// instance on an unexpected port still get checked.
	var rules []*Rule
	for _, r := range d.db.RulesFor(RuleQuery{
		Port: port.Port, Proto: port.Proto, Tunnel: tunnel,
		Checks: true, Service: svc.Name,
	}) {
		if r.IsCheck() {
			rules = append(rules, r)
		}
	}

	for _, r := range rules {
		for _, p := range r.Probes {
			resp := d.runProbe(ctx, host, port, tunnel, p)
			if len(resp) == 0 {
				continue
			}
			// Every match that hits is reported, not only the first. One
			// response can carry several independent facts - an RPC DUMP answer
			// names every registered service at once - and collapsing them into
			// one conclusion loses most of what the probe was sent for. A rule
			// whose matches are alternatives (vulnerable against patched) still
			// produces a single hit, because only one of them can match.
			for i := range r.Match {
				matched := &r.Match[i]
				if matched.Finding == nil {
					continue
				}
				if f := matched.apply(resp); f == nil {
					continue
				}
				f := matched.Finding
				// The finding text comes from a local YAML file, so it is
				// trusted, but the reference URLs are printed verbatim and a
				// malformed one could still carry an escape sequence.
				refs := make([]string, 0, len(f.Refs))
				for _, ref := range f.Refs {
					refs = append(refs, safetext.Sanitize(ref))
				}
				svc.Findings = append(svc.Findings, model.Finding{
					ID:          f.ID,
					Title:       f.Title.Get(d.lang),
					Severity:    f.Severity,
					Description: f.Description.Get(d.lang),
					Refs:        refs,
					Rule:        r.ID,
					Match:       matched.ID,
				})
				d.debugf("check %s:%d -> rule %s/%s severity=%s title=%q",
					host, port.Port, r.ID, matched.ID, f.Severity, f.Title.Get("en"))
			}
			break // first probe that answered is the one we read
		}
	}
}

// passiveBanner opens a connection and reads whatever the server volunteers.
// closedEarly reports a peer that hung up without sending anything.
func (d *Detector) passiveBanner(ctx context.Context, host string, port int) (banner []byte, closedEarly bool) {
	cctx, cancel := context.WithTimeout(ctx, d.probeTimeout)
	defer cancel()
	conn, err := d.dial(cctx, host, port, "tcp", "")
	if err != nil {
		return nil, false
	}
	defer conn.Close()
	// Banner-first protocols answer immediately; a short deadline keeps the
	// cost low for the silent ones.
	return readResponse(conn, 700*time.Millisecond, 2048)
}

// try runs the rules for a connection type against a port. passive is the
// banner already read by Detect; it lets every banner-first rule share a
// single read instead of opening one connection each.
func (d *Detector) try(ctx context.Context, host string, mport model.Port, tunnel string, passive []byte) *model.Service {
	port := mport.Port
	rules := d.db.RulesFor(RuleQuery{Port: port, Proto: mport.Proto, Tunnel: tunnel, Checks: d.checks})
	var tlsInfo *model.TLSInfo

	if tunnel == tunnelSSL {
		info, ok := d.handshake(ctx, host, port)
		if !ok {
			return nil
		}
		tlsInfo = info
	}

	for _, r := range rules {
		if r.IsCheck() {
			continue
		}
		for _, p := range r.Probes {
			var resp []byte
			if tunnel == "" && p.Send == "" && len(passive) > 0 {
				resp = passive
			} else {
				resp = d.runProbe(ctx, host, mport, tunnel, p)
			}
			if len(resp) == 0 {
				continue
			}
			fields, matched := matchRule(r, resp)
			if fields == nil {
				continue
			}
			svc := buildService(r, fields, resp)
			svc.Tunnel = tunnel
			svc.TLS = tlsInfo
			if svc.Name == "" {
				svc.Name = portsDisplayName(port)
			}
			matchID := ""
			if matched != nil {
				matchID = matched.ID
			}
			d.debugf("detect %s:%d -> rule %s/%s service=%s product=%s version=%s",
				host, port, r.ID, matchID, svc.Name, svc.Product, svc.Version)
			return svc
		}
	}

	if tlsInfo != nil {
		return &model.Service{
			Name:   portsDisplayName(port),
			Method: "probed",
			Conf:   5,
			Tunnel: tunnelSSL,
			TLS:    tlsInfo,
		}
	}
	return nil
}

// matchRule returns the extracted fields and the match that produced them, so
// the caller can also pick up a finding.
func matchRule(r *Rule, resp []byte) (Fields, *Match) {
	for i := range r.Match {
		m := &r.Match[i]
		if f := m.apply(resp); f != nil {
			return f, m
		}
	}
	return nil, nil
}

func buildService(r *Rule, f Fields, resp []byte) *model.Service {
	svc := &model.Service{Method: "probed", Rule: r.ID, Conf: r.Conf}
	// Everything here was matched out of a response from the target, so it is
	// untrusted: sanitising it is what stops a hostile service from driving the
	// operator's terminal with escape sequences hidden in its banner.
	svc.Name = safetext.Sanitize(f[FieldService])
	svc.Product = safetext.Sanitize(f[FieldProduct])
	svc.Version = safetext.Sanitize(f[FieldVersion])
	svc.ExtraInfo = safetext.Sanitize(f[FieldInfo])
	svc.OSType = safetext.Sanitize(f[FieldOSType])
	if svc.OSType == "" {
		svc.OSType = safetext.Sanitize(f[FieldOS])
	}
	svc.Device = safetext.Sanitize(f[FieldDevice])
	if host := safetext.Sanitize(f[FieldHost]); host != "" {
		if svc.ExtraInfo == "" {
			svc.ExtraInfo = host
		} else {
			svc.ExtraInfo += ", " + host
		}
	}
	if cpe := f[FieldCPE]; cpe != "" {
		for _, part := range strings.Split(cpe, ",") {
			if p := safetext.Sanitize(strings.TrimSpace(part)); p != "" {
				svc.CPEs = append(svc.CPEs, p)
			}
		}
	}
	svc.Banner = cleanBanner(resp)
	return svc
}

// cleanBanner renders a response as a short printable single line.
func cleanBanner(resp []byte) string {
	const max = 200
	b := make([]byte, 0, len(resp))
	for _, c := range resp {
		if c == '\r' || c == '\n' || c == '\t' {
			b = append(b, ' ')
			continue
		}
		if c < 32 || c > 126 {
			b = append(b, '.')
			continue
		}
		b = append(b, c)
	}
	s := strings.TrimSpace(strings.Join(strings.Fields(string(b)), " "))
	if len(s) > max {
		s = s[:max] + "..."
	}
	return s
}

func portTableName(p model.Port) string { return portsDisplayName(p.Port) }

// portsDisplayName is indirected so the import stays in one place.
func portsDisplayName(port int) string { return ports.DisplayName("tcp", port) }

// isTLSRecord reports whether the bytes look like the start of a TLS
// handshake (record type 22 = handshake, version 3.x).
func isTLSRecord(b []byte) bool {
	return len(b) >= 3 && b[0] == 22 && b[1] == 3 && b[2] <= 4
}

// handshake performs a TLS handshake and extracts what it reveals.
func (d *Detector) handshake(ctx context.Context, host string, port int) (*model.TLSInfo, bool) {
	cctx, cancel := context.WithTimeout(ctx, d.probeTimeout)
	defer cancel()
	conn, err := d.dial(cctx, host, port, "tcp", tunnelSSL)
	if err != nil {
		return nil, false
	}
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, false
	}
	cs := tlsConn.ConnectionState()
	info := &model.TLSInfo{
		Version: tlsVersionName(cs.Version),
		Cipher:  tls.CipherSuiteName(cs.CipherSuite),
		ALPN:    cs.NegotiatedProtocol,
	}
	if len(cs.PeerCertificates) > 0 {
		cert := cs.PeerCertificates[0]
		info.Subject = safetext.Sanitize(cert.Subject.String())
		info.Issuer = safetext.Sanitize(cert.Issuer.String())
		info.NotBefore = cert.NotBefore
		info.NotAfter = cert.NotAfter
		for _, name := range cert.DNSNames {
			info.DNSNames = append(info.DNSNames, safetext.Sanitize(name))
		}
		info.SelfSigned = cert.Subject.String() == cert.Issuer.String()
		info.Expired = time.Now().After(cert.NotAfter)
		info.Fingerprint = sha256Hex(cert.Raw)
	}
	return info, true
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLSv1.3"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS10:
		return "TLSv1.0"
	case tls.VersionSSL30:
		return "SSLv3"
	}
	return "unknown"
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
