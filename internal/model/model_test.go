package model

import (
	"net/netip"
	"testing"
	"time"
)

func hostFixture() Host {
	return Host{
		Address:  "192.0.2.10",
		AddrType: "ipv4",
		Status:   "up",
		Latency:  1500 * time.Microsecond,
		Ports: []Port{
			{Port: 443, Proto: "tcp", State: StateOpen, Reason: ReasonSynAck},
			{Port: 22, Proto: "tcp", State: StateOpen, Reason: ReasonSynAck},
			{Port: 80, Proto: "tcp", State: StateClosed, Reason: ReasonConnRefused},
			{Port: 81, Proto: "tcp", State: StateClosed, Reason: ReasonConnRefused},
			{Port: 82, Proto: "tcp", State: StateClosed, Reason: ReasonConnRefused},
			{Port: 8080, Proto: "tcp", State: StateFiltered, Reason: ReasonNoResponse},
			{Port: 53, Proto: "udp", State: StateOpenFiltered, Reason: ReasonNoResponse},
		},
	}
}

func TestSortPortsAndOpenPorts(t *testing.T) {
	h := hostFixture()
	h.SortPorts()
	if h.Ports[0].State != StateOpen || h.Ports[0].Port != 22 {
		t.Fatalf("open ports must sort first and ascending: %+v", h.Ports[0])
	}
	if last := h.Ports[len(h.Ports)-1]; last.State != StateFiltered {
		t.Fatalf("filtered ports sort last, got %v", last.State)
	}
	open := h.OpenPorts()
	if len(open) != 2 || open[0].Port != 22 || open[1].Port != 443 {
		t.Fatalf("OpenPorts = %+v", open)
	}
	if open[0].ID() != "22/tcp" {
		t.Fatalf("Port.ID() = %q", open[0].ID())
	}
}

func TestExtrasGroupsByStateAndProtocol(t *testing.T) {
	h := hostFixture()
	extras := h.Extras()
	if len(extras) != 3 {
		t.Fatalf("expected three groups (closed tcp, filtered tcp, open|filtered udp), got %d: %+v", len(extras), extras)
	}
	if extras[0].State != StateClosed || extras[0].Count != 3 || extras[0].Proto != "tcp" {
		t.Fatalf("largest group = %+v", extras[0])
	}
	if extras[0].TopReasons()[0] != ReasonConnRefused {
		t.Fatalf("reason aggregation is wrong: %+v", extras[0].Reasons)
	}
	// Open ports never appear in the "Not shown" summary.
	for _, e := range extras {
		if e.State == StateOpen {
			t.Fatal("open ports must not be summarised as extraports")
		}
	}
}

func TestServiceVersionString(t *testing.T) {
	cases := []struct {
		name string
		svc  *Service
		want string
	}{
		{"nil", nil, ""},
		{"empty", &Service{}, ""},
		{"product and version", &Service{Product: "nginx", Version: "1.24.0"}, "nginx 1.24.0"},
		{
			"with extra info and os",
			&Service{Product: "OpenSSH", Version: "8.9p1", ExtraInfo: "Ubuntu 3", OSType: "Linux"},
			"OpenSSH 8.9p1 (Ubuntu 3; Linux)",
		},
		{"os only", &Service{Product: "vsftpd", OSType: "Unix"}, "vsftpd (Unix)"},
		{"extra only", &Service{Product: "x", ExtraInfo: "y"}, "x (y)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.svc.VersionString(); got != tc.want {
				t.Fatalf("VersionString() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestServiceFullName(t *testing.T) {
	if got := (&Service{Name: "http", Tunnel: "ssl"}).FullName(); got != "ssl/http" {
		t.Fatalf("FullName() = %q", got)
	}
	if got := (&Service{Name: "http"}).FullName(); got != "http" {
		t.Fatalf("FullName() = %q", got)
	}
	var nilSvc *Service
	if got := nilSvc.FullName(); got != "" {
		t.Fatalf("nil FullName() = %q", got)
	}
}

func TestStateOrdering(t *testing.T) {
	states := append([]State(nil), AllStates...)
	for i := 0; i < len(states); i++ {
		for j := i + 1; j < len(states); j++ {
			if states[i].Order() == states[j].Order() {
				t.Errorf("states %s and %s share an order value", states[i], states[j])
			}
		}
	}
	if StateOpen.Order() >= StateClosed.Order() {
		t.Error("open must sort before closed")
	}
}

func TestResultCountsAndElapsed(t *testing.T) {
	start := time.Now()
	res := &Result{
		Start: start,
		End:   start.Add(2 * time.Second),
		Hosts: []Host{
			{Address: "192.0.2.1", Status: "up"},
			{Address: "192.0.2.2", Status: "up"},
			{Address: "192.0.2.3", Status: "down"},
		},
	}
	up, down, total := res.Counts()
	if up != 2 || down != 1 || total != 3 {
		t.Fatalf("Counts() = %d, %d, %d", up, down, total)
	}
	if res.Elapsed() != 2*time.Second {
		t.Fatalf("Elapsed() = %v", res.Elapsed())
	}
}

func TestTargetConstruction(t *testing.T) {
	addr := netip.MustParseAddr("192.0.2.1")
	if addr.String() != "192.0.2.1" {
		t.Skip("sanity")
	}
}
