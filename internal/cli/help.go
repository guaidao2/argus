package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/guaidao2/argus/internal/i18n"
	"github.com/guaidao2/argus/internal/version"
)

type helpFlag struct {
	names string // rendered verbatim: options are never translated
	key   string // locale key for the description
}

type helpSection struct {
	titleKey string
	flags    []helpFlag
}

func helpSections() []helpSection {
	return []helpSection{
		{
			titleKey: "help.section.targets",
			flags: []helpFlag{
				{"<target ...>", "flag.targets.positional"},
				{"-iL, --input-list FILE", "flag.input_list"},
				{"--exclude LIST", "flag.exclude"},
				{"--exclude-file FILE", "flag.exclude_file"},
				{"-n, --no-dns", "flag.no_dns"},
				{"-R, --resolve-all", "flag.resolve_all"},
			},
		},
		{
			titleKey: "help.section.scan",
			flags: []helpFlag{
				{"-p, --ports SPEC", "flag.ports"},
				{"--top-ports N", "flag.top_ports"},
				{"-F, --fast", "flag.fast"},
				{"--exclude-ports SPEC", "flag.exclude_ports"},
				{"-sS, -sT, --scan-type TYPE", "flag.scan_type"},
				{"--fallback-connect", "flag.fallback_connect"},
				{"-sU, --udp", "flag.udp"},
				{"-Pn", "flag.pn"},
				{"-r, --sequential", "flag.sequential"},
			},
		},
		{
			titleKey: "help.section.detect",
			flags: []helpFlag{
				{"-sV, --service", "flag.service"},
				{"--banner", "flag.banner"},
				{"--findings", "flag.findings"},
				{"--probe-timeout DUR", "flag.probe_timeout"},
				{"--proxy URL", "flag.proxy"},
			},
		},
		{
			titleKey: "help.section.timing",
			flags: []helpFlag{
				{"-T, --timing 0..5", "flag.timing"},
				{"--min-rate N", "flag.min_rate"},
				{"--max-rate N", "flag.max_rate"},
				{"--min-parallelism N", "flag.min_parallel"},
				{"--max-parallelism N", "flag.max_parallel"},
				{"--max-retries N", "flag.max_retries"},
				{"--host-timeout DUR", "flag.host_timeout"},
				{"--timeout DUR", "flag.timeout"},
				{"--scan-delay DUR", "flag.scan_delay"},
			},
		},
		{
			titleKey: "help.section.output",
			flags: []helpFlag{
				{"-oN, --output-normal FILE", "flag.output_normal"},
				{"-oX, --output-xml FILE", "flag.output_xml"},
				{"-oJ, --output-json FILE", "flag.output_json"},
				{"-oA, --output-all BASE", "flag.output_all"},
				{"--jsonl", "flag.jsonl"},
				{"--append-output", "flag.append"},
				{"--open", "flag.open_only"},
				{"--reason", "flag.reason"},
				{"--hack-reason", "flag.hack_reason"},
				{"-v, --verbose", "flag.verbose"},
				{"-d, --debug", "flag.debug"},
				{"--no-color", "flag.no_color"},
				{"--stats-every DUR", "flag.stats_every"},
			},
		},
		{
			titleKey: "help.section.plugins",
			flags: []helpFlag{
				{"--register-plugin PATH", "flag.register_plugin"},
				{"--unregister-plugin REF", "flag.unregister_plugin"},
				{"--unregister-all", "flag.unregister_plugin"},
				{"--list-plugins", "flag.list_plugins"},
				{"--plugin-dir PATH", "flag.plugin_dir"},
				{"--no-plugins", "flag.no_plugins"},
				{"--plugin-var K=V", "flag.plugin_var"},
				{"--strict-plugins", "flag.strict_plugins"},
			},
		},
		{
			titleKey: "help.section.misc",
			flags: []helpFlag{
				{"--lang LANG", "flag.lang"},
				{"--list-langs", "flag.list_langs"},
				{"-h, --help", "flag.help"},
				{"-V, --version", "flag.version"},
			},
		},
	}
}

// examples are literal command lines, identical in every language.
var examples = []string{
	"argus 10.0.0.1",
	"argus -sV -p 22,80,443 10.0.0.0/24",
	"argus -sS -T4 -p- --open 10.0.0.5",
	"argus --top-ports 100 --hack-reason 10.0.0.1",
	"argus -oA scan1 10.0.0.1 10.0.0.2",
	"argus --lang zh -sV --hack-reason 10.0.0.1",
	"argus --register-plugin ./my-plugin.yaml",
	"argus --list-plugins",
}

// writeHelp renders the localised help text.
func writeHelp(w io.Writer, tr *i18n.Catalog, prog string) error {
	var b strings.Builder

	fmt.Fprintf(&b, "%s %s ( %s )\n", version.Name, version.Version, version.Homepage)
	fmt.Fprintf(&b, "%s\n\n", tr.T("app.tagline"))
	fmt.Fprintf(&b, "%s\n\n", tr.T("help.usage", prog))
	fmt.Fprintf(&b, "%s\n\n", tr.T("app.description"))

	for _, section := range helpSections() {
		fmt.Fprintf(&b, "%s\n", tr.T(section.titleKey))
		for _, f := range section.flags {
			name := f.names
			if displayWidth(name) > 30 {
				fmt.Fprintf(&b, "  %s\n%-32s%s\n", name, "", tr.T(f.key))
				continue
			}
			fmt.Fprintf(&b, "  %-30s %s\n", name, tr.T(f.key))
		}
		b.WriteString("\n")
	}

	fmt.Fprintf(&b, "%s\n", tr.T("help.examples"))
	for _, ex := range examples {
		fmt.Fprintf(&b, "  %s\n", ex)
	}
	b.WriteString("\n")

	langs := make([]string, 0, len(i18n.Supported()))
	for _, code := range i18n.Supported() {
		langs = append(langs, fmt.Sprintf("%s (%s)", code, i18n.LanguageName(code)))
	}
	fmt.Fprintf(&b, "%s\n", tr.T("help.langs_available", strings.Join(langs, ", ")))
	fmt.Fprintf(&b, "%s %s\n", tr.T("app.authors")+":", version.Authors)
	fmt.Fprintf(&b, "%s %s\n", tr.T("app.license")+":", version.License)
	fmt.Fprintf(&b, "%s\n", tr.T("app.legal"))

	_, err := io.WriteString(w, b.String())
	return err
}

func writeVersion(w io.Writer) error {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", version.Full())
	fmt.Fprintf(&b, "%s: %s\n", "Authors", version.Authors)
	fmt.Fprintf(&b, "%s: %s\n", "License", version.License)
	fmt.Fprintf(&b, "%s: %s\n", "Homepage", version.Homepage)
	_, err := io.WriteString(w, b.String())
	return err
}

// displayWidth counts terminal cells (CJK glyphs are double width).
func displayWidth(s string) int {
	w := 0
	for _, r := range s {
		switch {
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
			w += 2
		default:
			w++
		}
	}
	return w
}
