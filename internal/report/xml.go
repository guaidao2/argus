package report

import (
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/guaidao2/argus/internal/model"
	"github.com/guaidao2/argus/internal/ports"
	"github.com/guaidao2/argus/internal/version"
)

// The XML format mirrors nmap's DTD (xmloutputversion 1.05) closely enough
// that consumers written against nmap keep working: Metasploit's db_import,
// Faraday and most report generators parse <nmaprun> documents.
//
// Only the element and attribute names are fixed; nothing here is translated,
// so machine readable output stays stable across --lang values.

type xmlNmapRun struct {
	XMLName          xml.Name      `xml:"nmaprun"`
	Scanner          string        `xml:"scanner,attr"`
	Args             string        `xml:"args,attr"`
	Start            int64         `xml:"start,attr"`
	StartStr         string        `xml:"startstr,attr"`
	Version          string        `xml:"version,attr"`
	XMLOutputVersion string        `xml:"xmloutputversion,attr"`
	ScanInfo         []xmlScanInfo `xml:"scaninfo"`
	Verbose          xmlLevel      `xml:"verbose"`
	Debugging        xmlLevel      `xml:"debugging"`
	Hosts            []xmlHost     `xml:"host"`
	RunStats         xmlRunStats   `xml:"runstats"`
}

type xmlScanInfo struct {
	Type        string `xml:"type,attr"`
	Protocol    string `xml:"protocol,attr"`
	NumServices int    `xml:"numservices,attr"`
	Services    string `xml:"services,attr"`
}

type xmlLevel struct {
	Level int `xml:"level,attr"`
}

type xmlHost struct {
	StartTime int64 `xml:"starttime,attr"`
	EndTime   int64 `xml:"endtime,attr"`
	// Technique is an argus extension, not part of nmap's DTD. It records how
	// this host was actually probed, because a single scan can mix SYN and
	// connect when loopback or local addresses are involved. Parsers that do
	// not know the attribute ignore it.
	Technique string        `xml:"technique,attr,omitempty"`
	Status    xmlStatus     `xml:"status"`
	Address   xmlAddress    `xml:"address"`
	Hostnames *xmlHostnames `xml:"hostnames,omitempty"`
	Ports     *xmlPorts     `xml:"ports,omitempty"`
	Times     xmlTimes      `xml:"times"`
}

type xmlStatus struct {
	State     string `xml:"state,attr"`
	Reason    string `xml:"reason,attr"`
	ReasonTTL int    `xml:"reason_ttl,attr"`
}

type xmlAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type xmlHostnames struct {
	Hostname []xmlHostname `xml:"hostname"`
}

type xmlHostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type xmlPorts struct {
	ExtraPorts []xmlExtraPorts `xml:"extraports"`
	Port       []xmlPort       `xml:"port"`
}

type xmlExtraPorts struct {
	State        string            `xml:"state,attr"`
	Count        int               `xml:"count,attr"`
	ExtraReasons []xmlExtraReasons `xml:"extrareasons"`
}

type xmlExtraReasons struct {
	Reason string `xml:"reason,attr"`
	Count  int    `xml:"count,attr"`
	Proto  string `xml:"proto,attr,omitempty"`
}

type xmlPort struct {
	Protocol string      `xml:"protocol,attr"`
	PortID   int         `xml:"portid,attr"`
	State    xmlStatus   `xml:"state"`
	Service  *xmlService `xml:"service,omitempty"`
	// Script carries check findings using nmap's own <script> element, so the
	// consumers that already understand NSE output (Metasploit's db_import,
	// Faraday, report generators) pick findings up without special casing.
	Scripts []xmlScript `xml:"script,omitempty"`
}

type xmlScript struct {
	ID     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
}

type xmlService struct {
	Name      string   `xml:"name,attr,omitempty"`
	Product   string   `xml:"product,attr,omitempty"`
	Version   string   `xml:"version,attr,omitempty"`
	ExtraInfo string   `xml:"extrainfo,attr,omitempty"`
	OSType    string   `xml:"ostype,attr,omitempty"`
	DevType   string   `xml:"devicetype,attr,omitempty"`
	Tunnel    string   `xml:"tunnel,attr,omitempty"`
	Method    string   `xml:"method,attr,omitempty"`
	Conf      int      `xml:"conf,attr,omitempty"`
	CPE       []string `xml:"cpe"`
}

type xmlTimes struct {
	SRTT   int64 `xml:"srtt,attr"`
	RTTVar int64 `xml:"rttvar,attr"`
	To     int64 `xml:"to,attr"`
}

type xmlRunStats struct {
	Finished xmlFinished `xml:"finished"`
	Hosts    xmlHosts    `xml:"hosts"`
}

type xmlFinished struct {
	Time    int64   `xml:"time,attr"`
	TimeStr string  `xml:"timestr,attr"`
	Elapsed float64 `xml:"elapsed,attr"`
	Summary string  `xml:"summary,attr"`
	Exit    string  `xml:"exit,attr"`
}

type xmlHosts struct {
	Up    int `xml:"up,attr"`
	Down  int `xml:"down,attr"`
	Total int `xml:"total,attr"`
}

// XML writes an nmap-compatible document.
func XML(w io.Writer, res *model.Result, opts Options) error {
	doc := xmlNmapRun{
		Scanner:          version.Name,
		Args:             res.Args,
		Start:            res.Start.Unix(),
		StartStr:         res.Start.Local().Format(time.ANSIC),
		Version:          version.Version,
		XMLOutputVersion: "1.05",
		Verbose:          xmlLevel{Level: res.Verbose},
		Debugging:        xmlLevel{Level: res.Debug},
	}
	for _, proto := range res.Protocols {
		doc.ScanInfo = append(doc.ScanInfo, xmlScanInfo{
			Type:        res.ScanType,
			Protocol:    proto,
			NumServices: res.NumServices,
			Services:    res.ServicesSpec,
		})
	}

	for _, h := range res.Hosts {
		doc.Hosts = append(doc.Hosts, convertHost(h))
	}

	up, down, total := res.Counts()
	elapsed := res.Elapsed().Seconds()
	exit := "success"
	if res.Interrupted {
		exit = "interrupted"
	}
	doc.RunStats = xmlRunStats{
		Finished: xmlFinished{
			Time:    res.End.Unix(),
			TimeStr: res.End.Local().Format(time.ANSIC),
			Elapsed: elapsed,
			Summary: fmt.Sprintf("Argus done: %d IP address(es) (%d host(s) up) scanned in %.2f seconds", total, up, elapsed),
			Exit:    exit,
		},
		Hosts: xmlHosts{Up: up, Down: down, Total: total},
	}

	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	if _, err := io.WriteString(w, "<!DOCTYPE nmaprun>\n"); err != nil {
		return err
	}
	if _, err := io.WriteString(w, fmt.Sprintf("<!-- generated by %s (%s), a nmap-compatible scanner -->\n", version.Name, version.Homepage)); err != nil {
		return err
	}

	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return err
	}
	if err := enc.Flush(); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\n")
	return err
}

func convertHost(h model.Host) xmlHost {
	out := xmlHost{
		StartTime: h.Start.Unix(),
		EndTime:   h.End.Unix(),
		Technique: h.Technique,
		Status: xmlStatus{
			State:     h.Status,
			Reason:    string(h.Reason),
			ReasonTTL: 0,
		},
		Address: xmlAddress{Addr: h.Address, AddrType: h.AddrType},
		Times: xmlTimes{
			SRTT:   h.SRTT.Microseconds(),
			RTTVar: h.RTTVar.Microseconds(),
			To:     h.Timeout.Microseconds(),
		},
	}
	if len(h.Hostnames) > 0 {
		hn := &xmlHostnames{}
		for _, name := range h.Hostnames {
			hn.Hostname = append(hn.Hostname, xmlHostname{Name: name, Type: "PTR"})
		}
		out.Hostnames = hn
	}
	if len(h.Ports) > 0 {
		p := &xmlPorts{}
		for _, e := range h.Extras() {
			xp := xmlExtraPorts{State: string(e.State), Count: e.Count}
			for _, r := range e.TopReasons() {
				xp.ExtraReasons = append(xp.ExtraReasons, xmlExtraReasons{
					Reason: string(r),
					Count:  e.Reasons[r],
					Proto:  e.Proto,
				})
			}
			p.ExtraPorts = append(p.ExtraPorts, xp)
		}
		for _, port := range h.Ports {
			p.Port = append(p.Port, xmlPort{
				Protocol: port.Proto,
				PortID:   port.Port,
				State: xmlStatus{
					State:     string(port.State),
					Reason:    string(port.Reason),
					ReasonTTL: port.TTL,
				},
				Service: convertService(port),
				Scripts: convertScripts(port),
			})
		}
		out.Ports = p
	}
	return out
}

// convertScripts renders findings the way nmap renders script output: one
// <script> element per finding, with the human readable text in @output.
func convertScripts(p model.Port) []xmlScript {
	if p.Service == nil || len(p.Service.Findings) == 0 {
		return nil
	}
	out := make([]xmlScript, 0, len(p.Service.Findings))
	for _, f := range p.Service.Findings {
		var b strings.Builder
		fmt.Fprintf(&b, "%s [%s]", f.Title, f.Severity)
		if f.Description != "" {
			b.WriteString("\n" + f.Description)
		}
		for _, ref := range f.Refs {
			b.WriteString("\n" + ref)
		}
		id := f.Rule
		if f.Match != "" {
			id += ":" + f.Match
		}
		if id == "" {
			id = f.ID
		}
		out = append(out, xmlScript{ID: id, Output: b.String()})
	}
	return out
}

func convertService(p model.Port) *xmlService {
	if p.Service == nil {
		return nil
	}
	s := &xmlService{
		Name:      p.Service.Name,
		Product:   p.Service.Product,
		Version:   p.Service.Version,
		ExtraInfo: p.Service.ExtraInfo,
		OSType:    p.Service.OSType,
		DevType:   p.Service.Device,
		Tunnel:    p.Service.Tunnel,
		Method:    p.Service.Method,
		Conf:      p.Service.Conf,
		CPE:       p.Service.CPEs,
	}
	if s.Name == "" {
		s.Name = ports.DisplayName(p.Proto, p.Port)
	}
	return s
}
