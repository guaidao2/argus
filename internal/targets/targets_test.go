package targets

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

func mustParse(t *testing.T, specs []string, opts Options) []Target {
	t.Helper()
	got, err := Parse(context.Background(), specs, opts)
	if err != nil {
		t.Fatalf("Parse(%v): %v", specs, err)
	}
	return got
}

func addrs(list []Target) []string {
	out := make([]string, 0, len(list))
	for _, t := range list {
		out = append(out, t.Addr.String())
	}
	return out
}

func TestParseSingleAddress(t *testing.T) {
	got := mustParse(t, []string{"192.0.2.10"}, Options{})
	if len(got) != 1 || got[0].String() != "192.0.2.10" {
		t.Fatalf("got %v", addrs(got))
	}
	// IPv6 targets work and are not Unmap()ed into IPv4.
	v6 := mustParse(t, []string{"2001:db8::1"}, Options{})
	if len(v6) != 1 || v6[0].String() != "2001:db8::1" {
		t.Fatalf("got %v", addrs(v6))
	}
	// The IPv4-mapped form is normalised.
	mapped := mustParse(t, []string{"::ffff:192.0.2.10"}, Options{})
	if mapped[0].String() != "192.0.2.10" {
		t.Fatalf("got %v", addrs(mapped))
	}
}

func TestParseCIDRSkipsNetworkAndBroadcast(t *testing.T) {
	got := mustParse(t, []string{"192.0.2.0/24"}, Options{})
	if len(got) != 254 {
		t.Fatalf("/24 produced %d addresses, want 254", len(got))
	}
	if got[0].String() != "192.0.2.1" {
		t.Errorf("first address = %s, want 192.0.2.1", got[0])
	}
	if got[len(got)-1].String() != "192.0.2.254" {
		t.Errorf("last address = %s, want 192.0.2.254", got[len(got)-1])
	}

	// /31 and /32 have no network or broadcast address to skip.
	host := mustParse(t, []string{"192.0.2.7/32"}, Options{})
	if len(host) != 1 || host[0].String() != "192.0.2.7" {
		t.Fatalf("/32: %v", addrs(host))
	}
	pair := mustParse(t, []string{"192.0.2.4/31"}, Options{})
	if len(pair) != 2 {
		t.Fatalf("/31: %v", addrs(pair))
	}
}

func TestParseIPv4Ranges(t *testing.T) {
	short := mustParse(t, []string{"10.0.0.1-4"}, Options{})
	if want := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"}; !equal(addrs(short), want) {
		t.Fatalf("short range = %v, want %v", addrs(short), want)
	}
	long := mustParse(t, []string{"10.0.0.254-10.0.1.1"}, Options{})
	if want := []string{"10.0.0.254", "10.0.0.255", "10.0.1.0", "10.0.1.1"}; !equal(addrs(long), want) {
		t.Fatalf("long range = %v, want %v", addrs(long), want)
	}
	// Reversed bounds are tolerated and sorted.
	rev := mustParse(t, []string{"10.0.0.5-3"}, Options{})
	if want := []string{"10.0.0.3", "10.0.0.4", "10.0.0.5"}; !equal(addrs(rev), want) {
		t.Fatalf("reversed range = %v, want %v", addrs(rev), want)
	}
}

func TestParseRejectsOversizedSpecifications(t *testing.T) {
	_, err := Parse(context.Background(), []string{"10.0.0.0/8"}, Options{MaxHosts: 1024})
	var tooLarge *ErrTooLarge
	if !errors.As(err, &tooLarge) {
		t.Fatalf("expected ErrTooLarge, got %v", err)
	}
	if tooLarge.Size != 1<<24 {
		t.Errorf("reported size = %d, want %d", tooLarge.Size, 1<<24)
	}

	_, err = Parse(context.Background(), []string{"2001:db8::/64"}, Options{})
	if !errors.As(err, &tooLarge) {
		t.Fatalf("a /64 should be refused, got %v", err)
	}
}

func TestParseDeduplicatesAndSorts(t *testing.T) {
	got := mustParse(t, []string{"192.0.2.3", "192.0.2.1", "192.0.2.3", "192.0.2.1-2"}, Options{})
	want := []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}
	if !equal(addrs(got), want) {
		t.Fatalf("got %v, want %v", addrs(got), want)
	}
}

func TestCommaSeparatedArgument(t *testing.T) {
	got := mustParse(t, []string{"192.0.2.1,192.0.2.2"}, Options{})
	if len(got) != 2 {
		t.Fatalf("got %v", addrs(got))
	}
}

func TestSubtract(t *testing.T) {
	in := mustParse(t, []string{"192.0.2.0/29"}, Options{})
	ex := mustParse(t, []string{"192.0.2.2", "192.0.2.4"}, Options{})
	got := Subtract(in, ex)
	for _, target := range got {
		if target.String() == "192.0.2.2" || target.String() == "192.0.2.4" {
			t.Fatalf("%s should have been excluded", target)
		}
	}
	if len(got) != len(in)-2 {
		t.Fatalf("got %d targets, want %d", len(got), len(in)-2)
	}
}

func TestNoDNSRefusesNames(t *testing.T) {
	_, err := Parse(context.Background(), []string{"localhost"}, Options{NoDNS: true})
	if err == nil {
		t.Fatal("--no-dns must refuse to resolve a host name")
	}
}

func TestUnrecognisedTarget(t *testing.T) {
	_, err := Parse(context.Background(), []string{"not a target!"}, Options{})
	if err == nil {
		t.Fatal("expected an error")
	}
}

func TestExpandAppendsToExistingSlice(t *testing.T) {
	first := []Target{{Addr: netip.MustParseAddr("192.0.2.1")}}
	got, err := Expand(context.Background(), "192.0.2.2", Options{}, first)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("Expand should append, got %v", addrs(got))
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
