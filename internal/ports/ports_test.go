package ports

import (
	"strings"
	"testing"
)

func TestTableIsValid(t *testing.T) {
	if err := TableError(); err != nil {
		t.Fatalf("embedded service table: %v", err)
	}
	table := WellKnownTable()
	if len(table) < 50 {
		t.Fatalf("service table looks truncated: %d entries", len(table))
	}
	seen := map[int]bool{}
	for i, wk := range table {
		if wk.Port < 1 || wk.Port > 65535 {
			t.Errorf("entry %d has out of range port %d", i, wk.Port)
		}
		if seen[wk.Port] {
			t.Errorf("port %d appears twice: the frequency ranking would be ambiguous", wk.Port)
		}
		seen[wk.Port] = true
		if wk.Rank != i+1 {
			t.Errorf("entry %d has rank %d, want %d", i, wk.Rank, i+1)
		}
	}
}

func TestServiceNameAndLookup(t *testing.T) {
	cases := map[int]string{
		22:    "ssh",
		80:    "http",
		443:   "https",
		445:   "microsoft-ds",
		3306:  "mysql",
		11211: "memcache",
	}
	for port, want := range cases {
		if got := ServiceName(TCP, port); got != want {
			t.Errorf("ServiceName(tcp, %d) = %q, want %q", port, got, want)
		}
	}
	if got := DisplayName(TCP, 60123); got != "unknown" {
		t.Errorf("DisplayName for an unknown port = %q, want unknown", got)
	}
	// UDP falls back to the TCP table because the well-known names are shared.
	if got := ServiceName(UDP, 53); got != "domain" {
		t.Errorf("ServiceName(udp, 53) = %q, want domain", got)
	}
	if got := LookupPort("ssh"); len(got) != 1 || got[0] != 22 {
		t.Errorf("LookupPort(ssh) = %v, want [22]", got)
	}
	if got := LookupPort("no-such-service"); len(got) != 0 {
		t.Errorf("LookupPort for an unknown name = %v, want empty", got)
	}
}

func TestParseSpec(t *testing.T) {
	newOpts := func(proto string) ParseOptions { return ParseOptions{DefaultProto: proto} }

	t.Run("single ports", func(t *testing.T) {
		got, err := ParseSpec("22,80,443", newOpts(TCP))
		if err != nil {
			t.Fatal(err)
		}
		want := []int{22, 80, 443}
		if len(got) != len(want) {
			t.Fatalf("got %v", got)
		}
		for i, p := range got {
			if p.Port != want[i] || p.Proto != TCP {
				t.Fatalf("got %v", got)
			}
		}
	})

	t.Run("ranges", func(t *testing.T) {
		for _, spec := range []string{"80-82", "80-82/tcp"} {
			got, err := ParseSpec(spec, newOpts(TCP))
			if err != nil {
				t.Fatalf("%s: %v", spec, err)
			}
			if len(got) != 3 || got[0].Port != 80 || got[2].Port != 82 {
				t.Fatalf("%s: got %v", spec, got)
			}
		}
		open, err := ParseSpec("65000-", newOpts(TCP))
		if err != nil {
			t.Fatal(err)
		}
		if len(open) != 536 || open[0].Port != 65000 || open[len(open)-1].Port != 65535 {
			t.Fatalf("open ended range: %d entries, first %d, last %d", len(open), open[0].Port, open[len(open)-1].Port)
		}
		low, err := ParseSpec("-3", newOpts(TCP))
		if err != nil {
			t.Fatal(err)
		}
		if len(low) != 3 || low[0].Port != 1 {
			t.Fatalf("leading range: %v", low)
		}
	})

	t.Run("all ports", func(t *testing.T) {
		got, err := ParseSpec("-", newOpts(TCP))
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 65535 {
			t.Fatalf("- produced %d ports, want 65535", len(got))
		}
		explicit, err := ParseSpec("", ParseOptions{DefaultProto: TCP, All: true})
		if err != nil {
			t.Fatal(err)
		}
		if len(explicit) != 65535 {
			t.Fatalf("All produced %d ports", len(explicit))
		}
	})

	t.Run("service names and protocol prefixes", func(t *testing.T) {
		got, err := ParseSpec("ssh,T:443,U:53", newOpts(TCP))
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 3 {
			t.Fatalf("got %v", got)
		}
		if got[0].Port != 22 || got[0].Proto != TCP {
			t.Errorf("ssh should resolve to 22/tcp, got %v", got[0])
		}
		if got[2].Port != 53 || got[2].Proto != UDP {
			t.Errorf("U:53 should be 53/udp, got %v", got[2])
		}
	})

	t.Run("udp side duplication", func(t *testing.T) {
		got, err := ParseSpec("53,161", ParseOptions{DefaultProto: TCP, UDP: true})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 4 {
			t.Fatalf("--udp should add the UDP side: got %v", got)
		}
	})

	t.Run("deduplicates", func(t *testing.T) {
		got, err := ParseSpec("80,80,80-81", newOpts(TCP))
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 {
			t.Fatalf("got %v", got)
		}
	})

	t.Run("errors", func(t *testing.T) {
		for _, spec := range []string{"not-a-service", "0", "65536", "80-70000"} {
			if _, err := ParseSpec(spec, newOpts(TCP)); err == nil {
				t.Errorf("%q should be rejected", spec)
			}
		}
	})
}

func TestTop(t *testing.T) {
	if Top(10)[0].Port != 80 {
		t.Fatalf("the most common port should be 80, got %d", Top(10)[0].Port)
	}
	if len(Top(10)) != 10 {
		t.Fatalf("Top(10) returned %d entries", len(Top(10)))
	}
	if len(Top(0)) != TopSize() {
		t.Fatalf("Top(0) should return the whole table")
	}
	if got := Top(100); len(got) != 100 {
		t.Fatalf("Top(100) returned %d entries", len(got))
	}
	for _, target := range Top(100) {
		if target.Proto != TCP {
			t.Fatalf("top ports must be TCP, got %v", target)
		}
	}
}

func TestSubtractAndSort(t *testing.T) {
	all, err := ParseSpec("22,80,443", ParseOptions{DefaultProto: TCP})
	if err != nil {
		t.Fatal(err)
	}
	drop, err := ParseSpec("80", ParseOptions{DefaultProto: TCP})
	if err != nil {
		t.Fatal(err)
	}
	got := Subtract(all, drop)
	if len(got) != 2 {
		t.Fatalf("got %v", got)
	}
	Sort(got)
	if got[0].Port != 22 || got[1].Port != 443 {
		t.Fatalf("after Sort: %v", got)
	}
}

func TestSpecRendering(t *testing.T) {
	list, err := ParseSpec("22,80,443,7000-7002", ParseOptions{DefaultProto: TCP})
	if err != nil {
		t.Fatal(err)
	}
	got := Spec(list)
	for _, want := range []string{"22", "80", "443", "7000-7002", "/tcp"} {
		if !strings.Contains(got, want) {
			t.Errorf("Spec() = %q, missing %q", got, want)
		}
	}
	if Spec(nil) != "" {
		t.Error("Spec(nil) should be empty")
	}
}
