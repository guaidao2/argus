package report

import (
	"encoding/json"
	"io"
	"time"

	"github.com/guaidao2/argus/internal/model"
	"github.com/guaidao2/argus/internal/version"
)

// The JSON view is defined separately from model.Result so the wire format is
// stable and explicit: timings become milliseconds, durations become seconds,
// and every optional block is omitempty.

type jsonDoc struct {
	Scanner        string      `json:"scanner"`
	Version        string      `json:"version"`
	Args           string      `json:"args"`
	Start          time.Time   `json:"start"`
	End            time.Time   `json:"end"`
	ElapsedSeconds float64     `json:"elapsed_seconds"`
	ScanType       string      `json:"scan_type"`
	RequestedScan  string      `json:"requested_scan_type,omitempty"`
	TechniqueMixed bool        `json:"technique_mixed,omitempty"`
	TechniqueAuto  bool        `json:"technique_auto,omitempty"`
	Protocols      []string    `json:"protocols"`
	NumServices    int         `json:"num_services"`
	Targets        []string    `json:"targets"`
	Interrupted    bool        `json:"interrupted,omitempty"`
	Plugins        []string    `json:"plugins,omitempty"`
	Hosts          []jsonHost  `json:"hosts"`
	Summary        jsonSummary `json:"summary"`
}

type jsonSummary struct {
	HostsUp   int `json:"hosts_up"`
	HostsDown int `json:"hosts_down"`
	HostsTota int `json:"hosts_total"`
	OpenPorts int `json:"open_ports"`
	Findings  int `json:"findings"`
}

type jsonHost struct {
	Address   string     `json:"address"`
	AddrType  string     `json:"addrtype,omitempty"`
	Hostnames []string   `json:"hostnames,omitempty"`
	Status    string     `json:"status"`
	Reason    string     `json:"reason,omitempty"`
	Technique string     `json:"technique,omitempty"`
	LatencyMS float64    `json:"latency_ms"`
	Ports     []jsonPort `json:"ports,omitempty"`
}

type jsonPort struct {
	Port      int              `json:"port"`
	Protocol  string           `json:"protocol"`
	State     string           `json:"state"`
	Reason    string           `json:"reason,omitempty"`
	Technique string           `json:"technique,omitempty"`
	Service   *jsonService     `json:"service,omitempty"`
	Findings  []model.Finding  `json:"findings,omitempty"`
	Hack      []model.HackNote `json:"hack_reason,omitempty"`
}

type jsonService struct {
	Name      string         `json:"name,omitempty"`
	Product   string         `json:"product,omitempty"`
	Version   string         `json:"version,omitempty"`
	ExtraInfo string         `json:"extrainfo,omitempty"`
	OSType    string         `json:"ostype,omitempty"`
	Tunnel    string         `json:"tunnel,omitempty"`
	Method    string         `json:"method,omitempty"`
	Conf      int            `json:"conf,omitempty"`
	CPE       []string       `json:"cpe,omitempty"`
	Banner    string         `json:"banner,omitempty"`
	TLS       *model.TLSInfo `json:"tls,omitempty"`
}

// JSON writes the result as a single document, or as JSON Lines with one host
// object per line followed by a summary line when jsonl is true.
func JSON(w io.Writer, res *model.Result, opts Options, jsonl bool) error {
	if jsonl {
		return jsonLines(w, res, opts)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(buildDoc(res, opts))
}

func jsonLines(w io.Writer, res *model.Result, opts Options) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	for _, h := range res.Hosts {
		if h.ScanSkipped && !h.Up() {
			continue
		}
		line := struct {
			Type string `json:"type"`
			jsonHost
		}{
			Type:     "host",
			jsonHost: convertJSONHost(h, opts),
		}
		if err := enc.Encode(line); err != nil {
			return err
		}
	}
	up, down, total := res.Counts()
	summary := struct {
		Type string `json:"type"`
		jsonSummary
		Args    string  `json:"args"`
		Elapsed float64 `json:"elapsed_seconds"`
	}{
		Type:        "summary",
		jsonSummary: buildSummary(res, up, down, total),
		Args:        res.Args,
		Elapsed:     res.Elapsed().Seconds(),
	}
	return enc.Encode(summary)
}

func buildDoc(res *model.Result, opts Options) jsonDoc {
	doc := jsonDoc{
		Scanner:        version.Name,
		Version:        version.Version,
		Args:           res.Args,
		Start:          res.Start,
		End:            res.End,
		ElapsedSeconds: res.Elapsed().Seconds(),
		ScanType:       res.ScanType,
		RequestedScan:  res.RequestedScanType,
		TechniqueMixed: res.TechniqueMixed,
		TechniqueAuto:  res.TechniqueAuto,
		Protocols:      res.Protocols,
		NumServices:    res.NumServices,
		Targets:        res.Targets,
		Interrupted:    res.Interrupted,
		Plugins:        res.PluginNames,
	}
	for _, h := range res.Hosts {
		if h.ScanSkipped && !h.Up() {
			continue
		}
		doc.Hosts = append(doc.Hosts, convertJSONHost(h, opts))
	}
	up, down, total := res.Counts()
	doc.Summary = buildSummary(res, up, down, total)
	return doc
}

func buildSummary(res *model.Result, up, down, total int) jsonSummary {
	open, findings := 0, 0
	for _, h := range res.Hosts {
		for _, p := range h.Ports {
			if p.State == model.StateOpen {
				open++
			}
			if p.Service != nil {
				findings += len(p.Service.Findings)
			}
		}
	}
	return jsonSummary{
		HostsUp: up, HostsDown: down, HostsTota: total,
		OpenPorts: open, Findings: findings,
	}
}

func convertJSONHost(h model.Host, opts Options) jsonHost {
	out := jsonHost{
		Address:   h.Address,
		AddrType:  h.AddrType,
		Hostnames: h.Hostnames,
		Status:    h.Status,
		Reason:    string(h.Reason),
		Technique: h.Technique,
		LatencyMS: float64(h.Latency.Nanoseconds()) / 1e6,
	}
	for _, p := range h.Ports {
		jp := jsonPort{
			Port:      p.Port,
			Protocol:  p.Proto,
			State:     string(p.State),
			Reason:    string(p.Reason),
			Technique: p.Technique,
		}
		if p.Service != nil {
			jp.Service = &jsonService{
				Name:      p.Service.Name,
				Product:   p.Service.Product,
				Version:   p.Service.Version,
				ExtraInfo: p.Service.ExtraInfo,
				OSType:    p.Service.OSType,
				Tunnel:    p.Service.Tunnel,
				Method:    p.Service.Method,
				Conf:      p.Service.Conf,
				CPE:       p.Service.CPEs,
				Banner:    p.Service.Banner,
				TLS:       p.Service.TLS,
			}
			jp.Findings = p.Service.Findings
			if opts.HackReason {
				jp.Hack = p.Service.Hack
			}
		}
		out.Ports = append(out.Ports, jp)
	}
	return out
}
