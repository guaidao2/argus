package cli

import (
	"strings"
	"time"

	"github.com/spf13/pflag"

	"github.com/guaidao2/argus/internal/i18n"
)

// Options is the fully parsed command line.
type Options struct {
	// Meta
	Lang        string
	ListLangs   bool
	ShowHelp    bool
	ShowVersion bool

	// Targets
	Targets     []string
	InputList   string
	Excludes    []string
	ExcludeFile string
	NoDNS       bool
	ResolveAll  bool

	// Ports and technique
	Ports        string
	TopPorts     int
	TopPortsSet  bool
	Fast         bool
	ExcludePorts string
	Sequential   bool
	ScanType     string
	// FallbackConnect allows a requested SYN scan to be replaced by a connect
	// scan when the SYN scan cannot run, and makes the report say so.
	FallbackConnect bool
	Pn              bool
	UDP             bool

	// Service detection
	Service      bool
	Banner       bool
	Findings     bool
	ProbeTimeout time.Duration

	// Timing
	Timing      int
	MinRate     int
	MaxRate     int
	MinParallel int
	MaxParallel int
	MaxRetries  int
	HostTimeout time.Duration
	Timeout     time.Duration
	ScanDelay   time.Duration

	// Output
	OutputNormal string
	OutputXML    string
	OutputJSON   string
	OutputAll    string
	Append       bool
	JSONL        bool
	OpenOnly     bool
	Reason       bool
	HackReason   bool
	Verbose      int
	Debug        int
	NoColor      bool
	StatsEvery   time.Duration

	// Plugins
	RegisterPlugin   string
	UnregisterPlugin string
	UnregisterAll    bool
	ListPlugins      bool
	PluginDir        string
	NoPlugins        bool
	PluginVars       []string
	StrictPlugins    bool

	// Proxy
	Proxy string

	// changed tracks which flags the user actually set.
	changed map[string]bool
}

// Changed reports whether a flag was given on the command line.
func (o *Options) Changed(name string) bool { return o.changed[name] }

// newFlagSet defines every option. The usage strings come from tr, which is
// why the flag set is rebuilt once the output language is known.
func newFlagSet(tr *i18n.Catalog) (*pflag.FlagSet, *Options) {
	opt := &Options{}
	fs := pflag.NewFlagSet("argus", pflag.ContinueOnError)
	fs.SetOutput(discard{})
	fs.SortFlags = false

	// ------------------------------------------------------------- meta
	fs.StringVar(&opt.Lang, "lang", "", tr.T("flag.lang"))
	fs.BoolVar(&opt.ListLangs, "list-langs", false, tr.T("flag.list_langs"))
	fs.BoolVarP(&opt.ShowHelp, "help", "h", false, tr.T("flag.help"))
	fs.BoolVarP(&opt.ShowVersion, "version", "V", false, tr.T("flag.version"))

	// ---------------------------------------------------------- targets
	fs.StringVarP(&opt.InputList, "input-list", "i", "", tr.T("flag.input_list"))
	fs.StringSliceVar(&opt.Excludes, "exclude", nil, tr.T("flag.exclude"))
	fs.StringVar(&opt.ExcludeFile, "exclude-file", "", tr.T("flag.exclude_file"))
	fs.BoolVarP(&opt.NoDNS, "no-dns", "n", false, tr.T("flag.no_dns"))
	fs.BoolVarP(&opt.ResolveAll, "resolve-all", "R", false, tr.T("flag.resolve_all"))

	// --------------------------------------------------- technique/ports
	fs.StringVarP(&opt.Ports, "ports", "p", "", tr.T("flag.ports"))
	fs.IntVar(&opt.TopPorts, "top-ports", 0, tr.T("flag.top_ports"))
	fs.BoolVarP(&opt.Fast, "fast", "F", false, tr.T("flag.fast"))
	fs.StringVar(&opt.ExcludePorts, "exclude-ports", "", tr.T("flag.exclude_ports"))
	fs.BoolVarP(&opt.Sequential, "sequential", "r", false, tr.T("flag.sequential"))
	fs.StringVarP(&opt.ScanType, "scan-type", "s", "connect", tr.T("flag.scan_type"))
	fs.BoolVar(&opt.FallbackConnect, "fallback-connect", false, tr.T("flag.fallback_connect"))
	fs.BoolVar(&opt.Pn, "pn", false, tr.T("flag.pn"))
	fs.BoolVar(&opt.UDP, "udp", false, tr.T("flag.udp"))

	// ------------------------------------------------- service detection
	fs.BoolVar(&opt.Service, "service", false, tr.T("flag.service"))
	fs.BoolVar(&opt.Banner, "banner", false, tr.T("flag.banner"))
	fs.BoolVar(&opt.Findings, "findings", false, tr.T("flag.findings"))
	fs.DurationVar(&opt.ProbeTimeout, "probe-timeout", 3*time.Second, tr.T("flag.probe_timeout"))

	// ------------------------------------------------------------ timing
	fs.IntVarP(&opt.Timing, "timing", "T", 3, tr.T("flag.timing"))
	fs.IntVar(&opt.MinRate, "min-rate", 0, tr.T("flag.min_rate"))
	fs.IntVar(&opt.MaxRate, "max-rate", 0, tr.T("flag.max_rate"))
	fs.IntVar(&opt.MinParallel, "min-parallelism", 0, tr.T("flag.min_parallel"))
	fs.IntVar(&opt.MaxParallel, "max-parallelism", 0, tr.T("flag.max_parallel"))
	fs.IntVar(&opt.MaxRetries, "max-retries", -1, tr.T("flag.max_retries"))
	fs.DurationVar(&opt.HostTimeout, "host-timeout", 0, tr.T("flag.host_timeout"))
	fs.DurationVar(&opt.Timeout, "timeout", 0, tr.T("flag.timeout"))
	fs.DurationVar(&opt.ScanDelay, "scan-delay", 0, tr.T("flag.scan_delay"))

	// ------------------------------------------------------------ output
	fs.StringVarP(&opt.OutputNormal, "output-normal", "o", "", tr.T("flag.output_normal"))
	fs.StringVar(&opt.OutputXML, "output-xml", "", tr.T("flag.output_xml"))
	fs.StringVar(&opt.OutputJSON, "output-json", "", tr.T("flag.output_json"))
	fs.StringVar(&opt.OutputAll, "output-all", "", tr.T("flag.output_all"))
	fs.BoolVar(&opt.Append, "append-output", false, tr.T("flag.append"))
	fs.BoolVar(&opt.JSONL, "jsonl", false, tr.T("flag.jsonl"))
	fs.BoolVar(&opt.OpenOnly, "open", false, tr.T("flag.open_only"))
	fs.BoolVar(&opt.Reason, "reason", false, tr.T("flag.reason"))
	fs.BoolVar(&opt.HackReason, "hack-reason", false, tr.T("flag.hack_reason"))
	fs.CountVarP(&opt.Verbose, "verbose", "v", tr.T("flag.verbose"))
	fs.CountVarP(&opt.Debug, "debug", "d", tr.T("flag.debug"))
	fs.BoolVar(&opt.NoColor, "no-color", false, tr.T("flag.no_color"))
	fs.DurationVar(&opt.StatsEvery, "stats-every", 2*time.Second, tr.T("flag.stats_every"))

	// ----------------------------------------------------------- plugins
	fs.StringVar(&opt.RegisterPlugin, "register-plugin", "", tr.T("flag.register_plugin"))
	fs.StringVar(&opt.UnregisterPlugin, "unregister-plugin", "", tr.T("flag.unregister_plugin"))
	fs.BoolVar(&opt.UnregisterAll, "unregister-all", false, tr.T("flag.unregister_plugin"))
	fs.BoolVar(&opt.ListPlugins, "list-plugins", false, tr.T("flag.list_plugins"))
	fs.StringVar(&opt.PluginDir, "plugin-dir", "", tr.T("flag.plugin_dir"))
	fs.BoolVar(&opt.NoPlugins, "no-plugins", false, tr.T("flag.no_plugins"))
	fs.StringArrayVar(&opt.PluginVars, "plugin-var", nil, tr.T("flag.plugin_var"))
	fs.BoolVar(&opt.StrictPlugins, "strict-plugins", false, tr.T("flag.strict_plugins"))

	// ------------------------------------------------------------ proxy
	fs.StringVar(&opt.Proxy, "proxy", "", tr.T("flag.proxy"))

	return fs, opt
}

// parse consumes argv (already normalised) and records which flags were set.
func parse(fs *pflag.FlagSet, opt *Options, argv []string) error {
	if err := fs.Parse(argv); err != nil {
		return err
	}
	opt.changed = map[string]bool{}
	fs.Visit(func(f *pflag.Flag) { opt.changed[f.Name] = true })
	opt.Targets = fs.Args()
	return nil
}

// shortOptionAliases maps nmap-style single dash options onto their long
// equivalents. Muscle memory matters for this audience, so -sV, -Pn, -T4 and
// friends keep working.
var shortOptionAliases = map[string]string{
	"-sV":  "--service",
	"-sC":  "--service",
	"-sU":  "--udp",
	"-sS":  "--scan-type=syn",
	"-sT":  "--scan-type=connect",
	"-Pn":  "--pn",
	"-F":   "--fast",
	"-r":   "--sequential",
	"-V":   "--version",
	"-h":   "--help",
	"-d":   "--debug",
	"-dd":  "--debug --debug",
	"-vv":  "--verbose --verbose",
	"-vvv": "--verbose --verbose --verbose",
}

// shortValueOptions are single dash options that take a value. Order matters:
// the longer spellings are matched first so that -oX is not read as -o plus
// the value "X".
var shortValueOptions = []struct{ short, long string }{
	{"-oN", "--output-normal"},
	{"-oX", "--output-xml"},
	{"-oJ", "--output-json"},
	{"-oA", "--output-all"},
	{"-iL", "--input-list"},
	{"-p", "--ports"},
	{"-T", "--timing"},
	{"-o", "--output-normal"},
}

func lookupShortValue(short string) (string, bool) {
	for _, o := range shortValueOptions {
		if o.short == short {
			return o.long, true
		}
	}
	return "", false
}

// normalizeArgs rewrites nmap-style short options into long ones so that the
// flag package can handle them. Targets and anything after "--" are passed
// through untouched.
func normalizeArgs(argv []string) []string {
	out := make([]string, 0, len(argv))
	for i := 0; i < len(argv); i++ {
		arg := argv[i]
		if arg == "--" {
			out = append(out, argv[i:]...)
			break
		}
		if len(arg) < 2 || arg[0] != '-' {
			out = append(out, arg)
			continue
		}
		if alias, ok := shortOptionAliases[arg]; ok {
			out = append(out, strings.Fields(alias)...)
			continue
		}
		if strings.HasPrefix(arg, "--") {
			out = append(out, arg)
			continue
		}

		// -p80,443 / -T4 / -oXresults.xml
		matched := false
		for _, opt := range shortValueOptions {
			// An exact match must fall through to the lookup below, otherwise
			// a shorter alias would swallow it: "-oA r" would be read as
			// "-o" with the value "A" and then "r" would become a target.
			if arg == opt.short {
				break
			}
			if !strings.HasPrefix(arg, opt.short) {
				continue
			}
			value := strings.TrimPrefix(arg[len(opt.short):], "=")
			out = append(out, opt.long+"="+value)
			matched = true
			break
		}
		if matched {
			continue
		}

		// -p 80,443 / -T 4 / -oX results.xml
		if long, ok := lookupShortValue(arg); ok {
			if i+1 < len(argv) {
				out = append(out, long+"="+argv[i+1])
				i++
				continue
			}
			out = append(out, long)
			continue
		}
		out = append(out, arg)
	}
	return out
}

// discard is an io.Writer that drops pflag's own error output; argus renders
// its own localised messages.
type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
