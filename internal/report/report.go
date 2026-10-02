// Package report renders scan results.
//
// Three formats are supported:
//
//   - normal: nmap-style human output (-oN)
//   - XML: nmap-compatible nmaprun documents (-oX) so the results can be
//     imported by existing tooling such as Metasploit's db_import or Faraday
//   - JSON / JSON Lines (-oJ) for scripting
//
// Machine readable formats are language neutral: element and attribute names
// stay in English so parsers keep working regardless of --lang. Only the
// hack-reason text follows the requested language.
package report

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/guaidao2/argus/internal/i18n"
	"github.com/guaidao2/argus/internal/model"
	"github.com/guaidao2/argus/internal/ports"
)

// Options controls rendering.
type Options struct {
	Tr         *i18n.Catalog
	Color      bool
	ShowReason bool
	HackReason bool
	Verbose    int
}

func (o Options) tr() *i18n.Catalog {
	if o.Tr == nil {
		return i18n.New(i18n.DefaultLang)
	}
	return o.Tr
}

// Format identifies an output format.
type Format string

const (
	FormatNormal Format = "normal"
	FormatXML    Format = "xml"
	FormatJSON   Format = "json"
	FormatJSONL  Format = "jsonl"
)

// Render writes a result in the requested format.
func Render(w io.Writer, format Format, res *model.Result, opts Options) error {
	switch format {
	case FormatNormal:
		return Normal(w, res, opts)
	case FormatXML:
		return XML(w, res, opts)
	case FormatJSON, FormatJSONL:
		return JSON(w, res, opts, format == FormatJSONL)
	}
	return fmt.Errorf("unknown output format %q", format)
}

// ---------------------------------------------------------------- utilities

// stateKey maps a port state to its localised noun.
func stateKey(s model.State) string {
	switch s {
	case model.StateOpen:
		return "unit.open"
	case model.StateClosed:
		return "unit.closed"
	case model.StateFiltered:
		return "unit.filtered"
	case model.StateUnfiltered:
		return "unit.unfiltered"
	case model.StateOpenFiltered:
		return "unit.open_filtered"
	case model.StateClosedFiltered:
		return "unit.closed_filtered"
	}
	return "unit.filtered"
}

// StateLabel returns the localised name of a port state.
func StateLabel(tr *i18n.Catalog, s model.State) string {
	if tr == nil {
		return string(s)
	}
	return tr.T(stateKey(s))
}

// serviceColumn is what goes in the SERVICE column.
func serviceColumn(p model.Port) string {
	if p.Service != nil {
		if name := p.Service.FullName(); name != "" {
			return name
		}
	}
	return ports.DisplayName(p.Proto, p.Port)
}

// versionColumn renders the VERSION column.
func versionColumn(p model.Port) string {
	if p.Service == nil {
		return ""
	}
	return p.Service.VersionString()
}

// ------------------------------------------------------------------- colours

const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiCyan   = "\033[36m"
	ansiGray   = "\033[90m"
)

// stateColor picks a colour for a port state.
func stateColor(s model.State) string {
	switch s {
	case model.StateOpen:
		return ansiGreen
	case model.StateClosed:
		return ansiRed
	case model.StateOpenFiltered, model.StateClosedFiltered:
		return ansiYellow
	case model.StateFiltered:
		return ansiGray
	}
	return ""
}

// paint wraps s in an ANSI colour when colour output is enabled.
func paint(enabled bool, color, s string) string {
	if !enabled || color == "" || s == "" {
		return s
	}
	return color + s + ansiReset
}

// ------------------------------------------------------------------ widths

// displayWidth counts terminal cells, treating CJK ranges as double width so
// that the Chinese column headers stay aligned.
func displayWidth(s string) int {
	w := 0
	for _, r := range s {
		w += runeWidth(r)
	}
	return w
}

func runeWidth(r rune) int {
	switch {
	case r == 0:
		return 0
	case r < 32 || (r >= 0x7f && r < 0xa0):
		return 0
	case r >= 0x1100 && r <= 0x115f,
		r >= 0x2e80 && r <= 0x303e,
		r >= 0x3041 && r <= 0x33ff,
		r >= 0x3400 && r <= 0x4dbf,
		r >= 0x4e00 && r <= 0x9fff,
		r >= 0xa000 && r <= 0xa4cf,
		r >= 0xac00 && r <= 0xd7a3,
		r >= 0xf900 && r <= 0xfaff,
		r >= 0xfe30 && r <= 0xfe6f,
		r >= 0xff00 && r <= 0xff60,
		r >= 0xffe0 && r <= 0xffe6,
		r >= 0x20000 && r <= 0x3fffd:
		return 2
	}
	return 1
}

// padRight pads s with spaces to the given display width.
func padRight(s string, width int) string {
	pad := width - displayWidth(s)
	if pad <= 0 {
		return s
	}
	return s + strings.Repeat(" ", pad)
}

// duration renders a latency the way nmap does: seconds with enough decimals
// to stay informative on a LAN, where a scan completes in microseconds.
func latencySeconds(d time.Duration) string {
	sec := d.Seconds()
	switch {
	case sec == 0:
		return "0.00000"
	case sec < 0.0001:
		return fmt.Sprintf("%.5f", sec)
	case sec < 1:
		return fmt.Sprintf("%.5f", sec)
	default:
		return fmt.Sprintf("%.4f", sec)
	}
}

// count formats a number with its unit noun, keeping the noun count for the
// languages that need it (Chinese does not, and uses the same word).
func countUnit(tr *i18n.Catalog, n int, singular, plural string) string {
	if n == 1 {
		return tr.T(singular)
	}
	return tr.T(plural)
}
