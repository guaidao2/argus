package cli

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/guaidao2/argus/internal/model"
	"github.com/guaidao2/argus/internal/scan"
)

func TestNormalizeArgs(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "long options pass through",
			in:   []string{"--service", "--lang", "zh", "10.0.0.1"},
			want: []string{"--service", "--lang", "zh", "10.0.0.1"},
		},
		{
			name: "nmap service flags",
			in:   []string{"-sV", "-sU", "-Pn", "10.0.0.1"},
			want: []string{"--service", "--udp", "--pn", "10.0.0.1"},
		},
		{
			name: "scan type shorthands",
			in:   []string{"-sS", "-sT"},
			want: []string{"--scan-type=syn", "--scan-type=connect"},
		},
		{
			name: "attached port value",
			in:   []string{"-p22,80", "10.0.0.1"},
			want: []string{"--ports=22,80", "10.0.0.1"},
		},
		{
			name: "separate port value",
			in:   []string{"-p", "22,80", "10.0.0.1"},
			want: []string{"--ports=22,80", "10.0.0.1"},
		},
		{
			name: "all ports",
			in:   []string{"-p-"},
			want: []string{"--ports=-"},
		},
		{
			name: "timing",
			in:   []string{"-T4"},
			want: []string{"--timing=4"},
		},
		{
			// Regression: "-oA out" used to be read as "-o" with the value "A",
			// which turned "out" into a scan target.
			name: "output-all with a separate value",
			in:   []string{"-oA", "out", "10.0.0.1"},
			want: []string{"--output-all=out", "10.0.0.1"},
		},
		{
			name: "output-all with an attached value",
			in:   []string{"-oAout"},
			want: []string{"--output-all=out"},
		},
		{
			name: "xml output",
			in:   []string{"-oX", "r.xml"},
			want: []string{"--output-xml=r.xml"},
		},
		{
			name: "input list",
			in:   []string{"-iL", "hosts.txt"},
			want: []string{"--input-list=hosts.txt"},
		},
		{
			name: "verbosity clusters",
			in:   []string{"-vv"},
			want: []string{"--verbose", "--verbose"},
		},
		{
			name: "double dash stops rewriting",
			in:   []string{"--", "-p"},
			want: []string{"--", "-p"},
		},
		{
			name: "negative looking targets are untouched after --",
			in:   []string{"--lang", "zh", "10.0.0.0/24"},
			want: []string{"--lang", "zh", "10.0.0.0/24"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeArgs(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("normalizeArgs(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestParseRoundTrip makes sure the normalised arguments actually parse into
// the options struct.
func TestParseRoundTrip(t *testing.T) {
	fs, opt := newFlagSet(newTestCatalog(t))
	argv := normalizeArgs([]string{"-sV", "-Pn", "-p", "22,80", "-T4", "10.0.0.1"})
	if err := parse(fs, opt, argv); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !opt.Service {
		t.Error("-sV did not set Service")
	}
	if !opt.Pn {
		t.Error("-Pn did not set Pn")
	}
	if opt.Ports != "22,80" {
		t.Errorf("Ports = %q", opt.Ports)
	}
	if opt.Timing != 4 {
		t.Errorf("Timing = %d", opt.Timing)
	}
	if len(opt.Targets) != 1 || opt.Targets[0] != "10.0.0.1" {
		t.Errorf("Targets = %v", opt.Targets)
	}
	if !opt.Changed("ports") || opt.Changed("top-ports") {
		t.Errorf("Changed tracking is wrong: %v", opt.changed)
	}
}

func TestParseOutputAllDoesNotEatTargets(t *testing.T) {
	fs, opt := newFlagSet(newTestCatalog(t))
	argv := normalizeArgs([]string{"-oA", "base", "10.0.0.1", "10.0.0.2"})
	if err := parse(fs, opt, argv); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if opt.OutputAll != "base" {
		t.Fatalf("OutputAll = %q", opt.OutputAll)
	}
	if len(opt.Targets) != 2 {
		t.Fatalf("Targets = %v, want two addresses", opt.Targets)
	}
}

func TestParseErrorsOnUnknownOption(t *testing.T) {
	fs, opt := newFlagSet(newTestCatalog(t))
	if err := parse(fs, opt, []string{"--definitely-not-an-option"}); err == nil {
		t.Fatal("expected an error for an unknown option")
	}
}

func TestIsSYNUnavailable(t *testing.T) {
	for _, err := range []error{
		scan.ErrSYNUnsupported,
		scan.ErrSYNPrivileges,
		scan.ErrSYNNoReply,
		fmt.Errorf("wrapped: %w", scan.ErrSYNPrivileges),
	} {
		if !isSYNUnavailable(err) {
			t.Errorf("%v should count as SYN unavailable", err)
		}
	}
	if isSYNUnavailable(errors.New("something else")) {
		t.Error("a plain scan error must not trigger a technique fallback")
	}
	if isSYNUnavailable(nil) {
		t.Error("nil is not a SYN availability problem")
	}
}

func TestTechniquesHeadline(t *testing.T) {
	if got := techniquesHeadline([]string{model.TechniqueSYN}, scan.ScanSYN); got != model.TechniqueSYN {
		t.Errorf("a single technique is the headline, got %q", got)
	}
	if got := techniquesHeadline([]string{model.TechniqueConnect, model.TechniqueSYN}, scan.ScanSYN); got != model.TechniqueSYN {
		t.Errorf("a mixed scan is headlined by what was requested, got %q", got)
	}
	if got := techniquesHeadline(nil, scan.ScanConnect); got != model.TechniqueConnect {
		t.Errorf("with no hosts the request is the headline, got %q", got)
	}
}
