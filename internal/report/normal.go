package report

import (
	"bufio"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/guaidao2/argus/internal/i18n"
	"github.com/guaidao2/argus/internal/model"
	"github.com/guaidao2/argus/internal/version"
)

// NormalWriter renders nmap-style human readable output incrementally, so a
// long scan shows results as they arrive instead of buffering everything until
// the end. It is safe for a single producer: the scan engine delivers hosts in
// target order.
type NormalWriter struct {
	bw     *bufio.Writer
	opts   Options
	header bool
}

// NewNormalWriter wraps w.
func NewNormalWriter(w io.Writer, opts Options) *NormalWriter {
	return &NormalWriter{bw: bufio.NewWriter(w), opts: opts}
}

// HeaderInfo is what the header needs before a Result exists, because the
// header is printed as soon as the scan starts rather than after it finishes.
type HeaderInfo struct {
	Start time.Time
	// ScanType is the technique named in the report headline.
	ScanType string
	// Techniques is every probe technique the configured targets will use,
	// sorted. A single "syn" scan of loopback targets yields just "connect".
	Techniques     []string
	TechniqueMixed bool
	// Auto is set when the user asked argus to choose the technique.
	Auto bool
	// Note explains why the technique is not the strongest available, already
	// localised. Empty means there is nothing to explain.
	Note string
}

// Header prints the "Starting Argus ..." banner and the scan technique line.
func (n *NormalWriter) Header(info HeaderInfo) {
	if n.header {
		return
	}
	n.header = true
	tr := n.opts.tr()
	fmt.Fprintln(n.bw, tr.T("report.starting", version.Version, version.Authors,
		version.Homepage, info.Start.Local().Format("2006-01-02 15:04:05 MST")))
	if line := techniqueLine(tr, info); line != "" {
		fmt.Fprintln(n.bw, line)
	}
}

// techniqueLine states which probe technique produced the results.
//
// This matters more than it looks. A connect scan completes a handshake, which
// the application can log, and it is answered differently by some stateful
// firewalls and IDS; a SYN scan does neither. The same host scanned both ways
// can legitimately report different port sets, so a report that does not name
// the technique is a report nobody can compare with anything.
func techniqueLine(tr *i18n.Catalog, info HeaderInfo) string {
	if info.ScanType == "" && len(info.Techniques) == 0 {
		return ""
	}
	has := func(tech string) bool {
		for _, t := range info.Techniques {
			if t == tech {
				return true
			}
		}
		return false
	}

	switch {
	case has(model.TechniqueSYN) && has(model.TechniqueConnect):
		// Both ran: the usual reason is loopback or local targets, which a raw
		// socket cannot usefully probe.
		if info.Auto {
			return tr.T("report.technique_auto_mixed")
		}
		return tr.T("report.technique_syn_mixed")
	case has(model.TechniqueSYN):
		if info.Auto {
			return tr.T("report.technique_auto_syn")
		}
		return tr.T("report.technique_syn")
	case info.Note != "":
		// A connect scan ran where a SYN scan was wanted or expected; say why.
		if info.Auto {
			return tr.T("report.technique_auto_note", info.Note)
		}
		return tr.T("report.technique_note", info.Note)
	default:
		return tr.T("report.technique_connect")
	}
}

// Host prints one host block. Hosts that were reported down get a one line
// notice only with -v, matching nmap: a scan of a /24 must not drown in
// "Host seems down" blocks.
func (n *NormalWriter) Host(h model.Host) {
	if h.ScanSkipped && !h.Up() && n.opts.Verbose <= 0 {
		return
	}
	writeHost(n.bw, h, n.opts)
}

// Footer prints the summary and the interruption notice.
func (n *NormalWriter) Footer(res *model.Result) {
	tr := n.opts.tr()
	if n.opts.Verbose <= 0 {
		down := 0
		for _, h := range res.Hosts {
			if !h.Up() {
				down++
			}
		}
		if down > 0 {
			fmt.Fprintln(n.bw)
			fmt.Fprintln(n.bw, tr.T("report.down_summary", down))
		}
	}
	// The notice goes first, the way nmap prints it, so "partial results
	// below" still describes what follows it.
	if res.Interrupted {
		fmt.Fprintln(n.bw, tr.T("report.interrupted"))
	}
	fmt.Fprintln(n.bw, summaryLine(tr, res))
}

// Flush empties the buffer.
func (n *NormalWriter) Flush() error { return n.bw.Flush() }

// Normal writes the whole result in one go.
func Normal(w io.Writer, res *model.Result, opts Options) error {
	n := NewNormalWriter(w, opts)

	techniques := map[string]bool{}
	for _, h := range res.Hosts {
		if h.Technique != "" {
			techniques[h.Technique] = true
		}
	}
	set := make([]string, 0, len(techniques))
	for tech := range techniques {
		set = append(set, tech)
	}
	sort.Strings(set)

	n.Header(HeaderInfo{
		Start:          res.Start,
		ScanType:       res.ScanType,
		Techniques:     set,
		TechniqueMixed: res.TechniqueMixed,
		Auto:           res.TechniqueAuto,
		Note:           res.TechniqueNote,
	})
	for _, h := range res.Hosts {
		n.Host(h)
	}
	n.Footer(res)
	return n.Flush()
}

func writeHost(bw *bufio.Writer, h model.Host, opts Options) {
	tr := opts.tr()

	if len(h.Hostnames) > 0 {
		fmt.Fprintln(bw, tr.T("report.host_header", h.Hostnames[0], h.Address))
	} else {
		fmt.Fprintln(bw, tr.T("report.report_for", h.Address))
	}

	if !h.Up() {
		fmt.Fprintln(bw, tr.T("report.host_down"))
		if opts.Verbose > 0 {
			fmt.Fprintln(bw, tr.T("report.host_down_hint"))
		}
		fmt.Fprintln(bw)
		return
	}

	fmt.Fprintln(bw, tr.T("report.host_up", latencySeconds(h.Latency)))

	if extras := h.Extras(); len(extras) > 0 {
		parts := make([]string, 0, len(extras))
		for _, e := range extras {
			reasons := make([]string, 0, 3)
			for i, r := range e.TopReasons() {
				if i == 3 {
					break
				}
				reasons = append(reasons, string(r))
			}
			key := "report.extraports"
			if e.Count == 1 {
				key = "report.extraports_one"
			}
			parts = append(parts, tr.T(key, e.Count,
				StateLabel(tr, e.State), e.Proto, strings.Join(reasons, ", ")))
		}
		fmt.Fprintln(bw, tr.T("report.not_shown", strings.Join(parts, ", ")))
	}

	open := h.OpenPorts()
	if len(open) == 0 {
		fmt.Fprintln(bw)
		return
	}

	// Column widths follow the widest cell so that long service names such as
	// microsoft-ds do not collide with the VERSION column, and so the Chinese
	// headers stay aligned (CJK glyphs count as two cells).
	portW := maxInt(displayWidth(tr.T("report.col_port"))+1, 8)
	for _, p := range open {
		portW = maxInt(portW, displayWidth(p.ID())+1)
	}
	stateW := maxInt(displayWidth(tr.T("report.col_state"))+1, 6)
	svcW := displayWidth(tr.T("report.col_service")) + 1
	for _, p := range open {
		svcW = maxInt(svcW, displayWidth(serviceColumn(p))+1)
	}
	reasonW := 0
	if opts.ShowReason {
		reasonW = displayWidth("no-response") + 1
	}

	header := padRight(tr.T("report.col_port"), portW) +
		padRight(tr.T("report.col_state"), stateW) +
		padRight(tr.T("report.col_service"), svcW)
	if opts.ShowReason {
		header += padRight("REASON", reasonW)
	}
	header += tr.T("report.col_version")
	fmt.Fprintln(bw, strings.TrimRight(header, " "))

	for _, p := range open {
		stateText := string(p.State)
		stateCell := paint(opts.Color, stateColor(p.State), stateText)
		pad := stateW - displayWidth(stateText)
		if pad < 1 {
			pad = 1
		}
		line := padRight(p.ID(), portW) + stateCell + strings.Repeat(" ", pad) +
			padRight(serviceColumn(p), svcW)
		if opts.ShowReason {
			line += padRight(string(p.Reason), reasonW)
		}
		line += versionColumn(p)
		fmt.Fprintln(bw, strings.TrimRight(line, " "))
		writePortDetails(bw, p, opts)
	}
	fmt.Fprintln(bw)
}

// writePortDetails emits the indented detail block that follows a port line,
// using nmap's pipe prefix convention: every line starts with "| ", the last
// one with "|_" to mark the end of the block.
func writePortDetails(bw *bufio.Writer, p model.Port, opts Options) {
	lines := detailLines(p, opts)
	for i, line := range lines {
		prefix := "| "
		if i == len(lines)-1 {
			prefix = "|_"
		}
		fmt.Fprintln(bw, prefix+strings.ReplaceAll(line, "\n", "\n"+prefix))
	}
}

// detailLines builds the detail block: hack-reason notes first, then the TLS
// facts that only appear with -v.
func detailLines(p model.Port, opts Options) []string {
	tr := opts.tr()
	if p.Service == nil {
		return nil
	}
	var lines []string

	// Findings come first: "this port is reachable without credentials" matters
	// more than any advice about what to look at.
	for _, f := range p.Service.Findings {
		severity := strings.ToUpper(f.Severity)
		if severity == "" {
			severity = "INFO"
		}
		lines = append(lines, tr.T("report.finding", f.Title, severity))
		if f.Description != "" {
			lines = append(lines, f.Description)
		}
		if len(f.Refs) > 0 {
			lines = append(lines, tr.T("report.finding_refs", strings.Join(f.Refs, " ")))
		}
	}

	if opts.HackReason {
		for _, note := range p.Service.Hack {
			lines = append(lines, tr.T("report.hack_reason", note.Title))
			lines = append(lines, note.Points...)
			if len(note.Tools) > 0 {
				lines = append(lines, tr.T("report.hack_tools", strings.Join(note.Tools, ", ")))
			}
			if len(note.Refs) > 0 {
				lines = append(lines, tr.T("report.hack_refs", strings.Join(note.Refs, " ")))
			}
		}
	}

	if opts.Verbose > 0 && p.Service.TLS != nil {
		lines = append(lines, tlsLines(p.Service.TLS, tr)...)
	}
	if opts.Verbose > 1 && p.Service.Banner != "" {
		lines = append(lines, tr.T("report.service_banner", p.Service.Banner))
	}
	return lines
}

func tlsLines(tls *model.TLSInfo, tr *i18n.Catalog) []string {
	var out []string
	if tls.Version != "" || tls.Cipher != "" {
		out = append(out, strings.TrimSpace(tls.Version+" "+tls.Cipher))
	}
	if tls.ALPN != "" {
		out = append(out, "alpn: "+tls.ALPN)
	}
	if tls.Subject != "" {
		out = append(out, tr.T("report.tls_cert_subject", tls.Subject))
	}
	if tls.Issuer != "" {
		out = append(out, tr.T("report.tls_cert_issuer", tls.Issuer))
	}
	if !tls.NotBefore.IsZero() {
		out = append(out, tr.T("report.tls_not_valid_before", tls.NotBefore.UTC().Format("2006-01-02 15:04:05")))
	}
	if !tls.NotAfter.IsZero() {
		out = append(out, tr.T("report.tls_not_valid_after", tls.NotAfter.UTC().Format("2006-01-02 15:04:05")))
	}
	if len(tls.DNSNames) > 0 {
		out = append(out, tr.T("report.tls_san", strings.Join(tls.DNSNames, ", ")))
	}
	if tls.SelfSigned {
		out = append(out, tr.T("report.tls_self_signed"))
	}
	if tls.Expired {
		out = append(out, tr.T("report.tls_expired"))
	}
	return out
}

// summaryLine is the "Argus done: ..." trailer.
func summaryLine(tr *i18n.Catalog, res *model.Result) string {
	up, _, total := res.Counts()
	addrNoun := countUnit(tr, total, "unit.ip_address", "unit.ip_addresses")
	hostNoun := countUnit(tr, up, "unit.host", "unit.hosts")
	return tr.T("report.done", total, addrNoun, up, hostNoun, res.Elapsed().Seconds())
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
