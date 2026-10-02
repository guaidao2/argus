// Package cli parses the command line, wires the subsystems together and
// renders the result.
package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/guaidao2/argus/internal/config"
	"github.com/guaidao2/argus/internal/detect"
	"github.com/guaidao2/argus/internal/hackreason"
	"github.com/guaidao2/argus/internal/i18n"
	"github.com/guaidao2/argus/internal/model"
	"github.com/guaidao2/argus/internal/plugins"
	"github.com/guaidao2/argus/internal/ports"
	"github.com/guaidao2/argus/internal/report"
	"github.com/guaidao2/argus/internal/scan"
	"github.com/guaidao2/argus/internal/targets"
)

// Exit codes, documented in the README because scripting against a scanner
// depends on them.
const (
	exitOK          = 0
	exitError       = 1
	exitUsage       = 2
	exitInterrupted = 130
)

const progName = "argus"

// Run is the whole program. It returns the process exit code.
func Run(argv []string, stdin io.Reader, stdout, stderr io.Writer) int {
	english := i18n.New(i18n.DefaultLang)

	fs, opt := newFlagSet(english)
	if err := parse(fs, opt, normalizeArgs(argv)); err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		fmt.Fprintln(stderr, english.T("err.usage", progName))
		return exitUsage
	}

	// Language resolution needs the config file, which itself is parsed
	// without any localisation.
	fileCfg := loadFileConfig()
	lang, unknown := i18n.Resolve(opt.Lang, fileCfg.Lang)
	tr := i18n.New(lang)
	log := &Logger{Tr: tr, W: stderr, Verbose: opt.Verbose, Debug: opt.Debug}
	if unknown != "" {
		log.Warn("err.unknown_lang", unknown, strings.Join(i18n.Supported(), ", "))
	}

	switch {
	case opt.ShowVersion:
		if err := writeVersion(stdout); err != nil {
			fmt.Fprintf(stderr, "%v\n", err)
			return exitError
		}
		return exitOK
	case opt.ListLangs:
		for _, code := range i18n.Supported() {
			fmt.Fprintf(stdout, "%s\t%s\n", code, i18n.LanguageName(code))
		}
		return exitOK
	case opt.ShowHelp:
		if err := writeHelp(stdout, tr, progName); err != nil {
			fmt.Fprintf(stderr, "%v\n", err)
			return exitError
		}
		return exitOK
	}

	if handled, code := pluginOps(opt, log, stdout); handled {
		return code
	}

	if len(opt.Targets) == 0 && opt.InputList == "" {
		log.Errorf("err.no_targets")
		fmt.Fprintln(stderr, tr.T("err.usage", progName))
		return exitUsage
	}

	return runScan(argv, opt, tr, log, stdin, stdout, stderr)
}

// fileConfig is the optional config file holding defaults the user does not
// want to repeat on every command line.
type fileConfig struct {
	Lang string `yaml:"lang"`
}

func loadFileConfig() fileConfig {
	var cfg fileConfig
	raw, err := os.ReadFile(config.ConfigPath())
	if err != nil {
		return cfg
	}
	_ = yaml.Unmarshal(raw, &cfg)
	return cfg
}

// runScan is the normal scanning path.
func runScan(argv []string, opt *Options, tr *i18n.Catalog, log *Logger, stdin io.Reader, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	targetList, err := collectTargets(ctx, opt, stdin)
	if err != nil {
		if errors.Is(err, targets.ErrNoTargets) {
			log.Errorf("err.no_targets")
			fmt.Fprintln(stderr, tr.T("err.usage", progName))
			return exitUsage
		}
		log.Errorf("err.bad_target", targetSpecForError(opt), err)
		return exitUsage
	}
	if len(targetList) == 0 {
		log.Errorf("err.no_targets_after_exclude")
		return exitUsage
	}

	portList, err := collectPorts(opt, tr)
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return exitUsage
	}

	timing := buildTiming(opt)

	// ------------------------------------------------------------- plugins
	db, err := detect.LoadBuiltin()
	if err != nil {
		log.Errorf("err.scan_failed", err)
		return exitError
	}
	kb, err := hackreason.LoadBuiltin()
	if err != nil {
		log.Errorf("err.scan_failed", err)
		return exitError
	}

	vars := map[string]string{}
	var pluginNames []string
	if !opt.NoPlugins {
		bundle, err := loadPlugins(opt, log)
		if err != nil {
			log.Errorf("%v", err)
			return exitError
		}
		if bundle != nil {
			pluginNames = bundle.Names
			if err := applyBundle(bundle, db, kb, vars, log); err != nil {
				log.Errorf("%v", err)
				return exitError
			}
			if len(bundle.Fingerprints) > 0 || len(bundle.HackReasons) > 0 {
				log.Info("info.plugins_loaded", len(bundle.Names), len(db.Rules()), kb.Count())
			}
		}
	}
	applyPluginVars(opt, vars, log, len(pluginNames))

	// ------------------------------------------------------------ detector
	var detector scan.Detector
	if opt.Service || opt.Banner || opt.Findings {
		d, err := detect.New(detect.Options{
			DB:           db,
			ProbeTimeout: opt.ProbeTimeout,
			Vars:         vars,
			Lang:         tr.Lang(),
			EnableChecks: opt.Findings,
			Debugf:       log.Debugf,
		})
		if err != nil {
			log.Errorf("%v", err)
			return exitError
		}
		detector = d
	}

	// -------------------------------------------------------------- output
	nopts := report.Options{
		Tr:         tr,
		Color:      !opt.NoColor && os.Getenv("NO_COLOR") == "" && isTerminal(stdout),
		ShowReason: opt.Reason,
		HackReason: opt.HackReason,
		Verbose:    opt.Verbose,
	}

	normalOut := stdout
	var closers []func() error
	normalPath := opt.OutputNormal
	if normalPath == "" && opt.OutputAll != "" {
		// nmap's -oA writes base.nmap, base.xml and base.gnmap.
		normalPath = opt.OutputAll + ".nmap"
	}
	if normalPath != "" && normalPath != "-" {
		w, closeFn, err := writerFor(normalPath, opt.Append, stdout)
		if err != nil {
			log.Errorf("%v", err)
			return exitError
		}
		closers = append(closers, closeFn)
		normalOut = io.MultiWriter(stdout, w)
	}
	defer func() {
		for _, c := range closers {
			_ = c()
		}
	}()

	normalW := report.NewNormalWriter(normalOut, nopts)

	// -------------------------------------------------------------- engine
	var scanned, totalPorts atomic.Int64
	totalPorts.Store(int64(len(targetList)) * int64(len(portList)))

	progressDone := make(chan struct{})
	progressActive := opt.StatsEvery > 0 && isTerminal(stderr)
	if progressActive {
		go progressLoop(tr, stderr, opt.StatsEvery, &scanned, &totalPorts, progressDone)
	}

	requestedScan := scan.ScanType(opt.ScanType)
	switch requestedScan {
	case scan.ScanConnect, scan.ScanSYN, scan.ScanAuto:
	default:
		log.Errorf("err.bad_scan_type", opt.ScanType)
		return exitUsage
	}
	// Silently falling back to the normal template would let someone believe
	// they were running a faster or stealthier template than they were.
	if opt.Timing < 0 || opt.Timing > 5 {
		log.Errorf("err.bad_timing", opt.Timing)
		return exitUsage
	}
	autoSelect := requestedScan == scan.ScanAuto

	buildEngine := func(scanType scan.ScanType) (*scan.Engine, error) {
		return scan.New(scan.Options{
			Targets:          targetList,
			Ports:            portList,
			ScanType:         scanType,
			Timing:           timing,
			Pn:               opt.Pn,
			HostTimeout:      opt.HostTimeout,
			DiscoveryTimeout: maxDuration(timing.InitialTimeout, 3*time.Second),
			NoDNS:            opt.NoDNS,
			ResolveAll:       opt.ResolveAll,
			Sequential:       opt.Sequential,
			ProxyURL:         opt.Proxy,
			Detector:         detector,
			DetectTimeout:    detectTimeout(opt),
			OpenOnly:         opt.OpenOnly,
			OnProgress: func(done, total int) {
				scanned.Store(int64(done))
				totalPorts.Store(int64(total))
			},
			Enrich: func(h *model.Host) {
				enrichHost(h, kb, opt, tr.Lang())
			},
			OnHost: func(h model.Host) {
				normalW.Host(h)
				_ = normalW.Flush()
			},
			Debugf: log.Debugf,
		})
	}

	// Capability detection has already run inside scan.New by the time it
	// returns: either the raw socket is open and preflighted, or the error says
	// why it could not be. Everything left here turns that answer into a
	// decision, and it happens before a single scan packet is sent.
	var (
		engine        *scan.Engine
		effectiveScan scan.ScanType
		fallbackNote  string
	)
	if autoSelect {
		engine, err = buildEngine(scan.ScanSYN)
		switch {
		case err == nil:
			effectiveScan = scan.ScanSYN
		case isSYNUnavailable(err):
			// Asked to choose, and SYN cannot run here: pick connect and say
			// why, without dressing it up as a warning the user caused.
			fallbackNote = synUnavailableReason(tr, err)
			effectiveScan = scan.ScanConnect
			engine, err = buildEngine(effectiveScan)
			if err == nil {
				log.Info("info.scan_type_auto", "TCP connect", fallbackNote)
			}
		}
	} else {
		effectiveScan = requestedScan
		engine, err = buildEngine(effectiveScan)
		if err != nil && effectiveScan == scan.ScanSYN && opt.FallbackConnect && isSYNUnavailable(err) {
			fallbackNote = synUnavailableReason(tr, err)
			log.Warn("warn.scan_type_fallback", fallbackNote)
			effectiveScan = scan.ScanConnect
			engine, err = buildEngine(effectiveScan)
		}
	}
	if err != nil {
		close(progressDone)
		return reportEngineError(err, log)
	}
	defer engine.Close()

	// The header is printed before the scan starts so that streamed results
	// appear underneath it, exactly like nmap, and so the technique is stated
	// before any port is reported.
	scanStart := time.Now()
	techniques, techniqueMixed := engine.Techniques()
	note := fallbackNote
	// A SYN scan was wanted (explicitly or by auto) but every target is local.
	wantSYN := requestedScan == scan.ScanSYN || requestedScan == scan.ScanAuto
	if note == "" && wantSYN && !hasTechnique(techniques, model.TechniqueSYN) {
		note = tr.T("reason.local_targets")
	}
	normalW.Header(report.HeaderInfo{
		Start:          scanStart,
		ScanType:       techniquesHeadline(techniques, effectiveScan),
		Techniques:     techniques,
		TechniqueMixed: techniqueMixed,
		Auto:           autoSelect,
		Note:           note,
	})
	_ = normalW.Flush()

	if opt.Proxy != "" {
		log.Warn("warn.proxy_tcp_only")
	}
	if opt.Findings {
		_, checks := db.CountByKind()
		log.Info("info.checks_enabled", checks)
	}
	if len(targetList) > 256 {
		log.Warn("warn.many_targets", len(targetList))
	}

	res := engine.Run(ctx)
	res.Start = scanStart
	res.RequestedScanType = string(requestedScan)
	res.TechniqueAuto = autoSelect
	res.TechniqueNote = note
	normalW.Footer(res)

	close(progressDone)
	if progressActive {
		fmt.Fprint(stderr, "\r\033[K")
	}

	res.Args = strings.Join(append([]string{progName}, argv...), " ")
	res.Verbose = opt.Verbose
	res.Debug = opt.Debug
	res.PluginNames = pluginNames

	if err := normalW.Flush(); err != nil {
		log.Errorf("%v", err)
		return exitError
	}
	if err := writeStructuredOutputs(opt, res, nopts, stdout, log); err != nil {
		log.Errorf("%v", err)
		return exitError
	}

	if res.Interrupted {
		return exitInterrupted
	}
	return exitOK
}

// applyBundle merges plugin documents into the fingerprint and hack-reason
// databases.
func applyBundle(bundle *plugins.Bundle, db *detect.DB, kb *hackreason.KB, vars map[string]string, log *Logger) error {
	for _, d := range bundle.Fingerprints {
		replaced, err := db.AddYAMLFront(d.Raw, d.Source)
		if err != nil {
			return err
		}
		for _, id := range replaced {
			log.Warn("warn.plugin_override", d.Source, "fingerprint", id)
		}
	}
	for _, d := range bundle.HackReasons {
		replaced, err := kb.AddYAMLFront(d.Raw, d.Source)
		if err != nil {
			return err
		}
		for _, id := range replaced {
			log.Warn("warn.plugin_override", d.Source, "hack-reason", id)
		}
	}
	for k, v := range bundle.Vars {
		if _, exists := vars[k]; !exists {
			vars[k] = v
		}
	}
	return nil
}

func reportEngineError(err error, log *Logger) int {
	switch {
	case errors.Is(err, scan.ErrSYNUnsupported):
		log.Errorf("err.syn_platform", runtime.GOOS, runtime.GOARCH)
		log.Errorf("err.syn_platform_hint")
	case errors.Is(err, scan.ErrSYNPrivileges):
		log.Errorf("err.syn_privileges", err)
		log.Errorf("err.syn_privileges_hint")
	case errors.Is(err, scan.ErrSYNNoReply):
		log.Errorf("err.syn_no_reply")
		log.Errorf("err.syn_no_reply_hint")
	default:
		log.Errorf("err.scan_failed", err)
	}
	return exitError
}

// hasTechnique reports whether a technique is in the set a scan will use.
func hasTechnique(techniques []string, want string) bool {
	for _, t := range techniques {
		if t == want {
			return true
		}
	}
	return false
}

// techniquesHeadline picks the technique named in the header when more than one
// is in play. When they all agree there is nothing to pick.
func techniquesHeadline(techniques []string, effective scan.ScanType) string {
	if len(techniques) == 1 {
		return techniques[0]
	}
	return string(effective)
}

// isSYNUnavailable reports whether an error means "a SYN scan cannot run here",
// as opposed to something going wrong with the scan itself.
func isSYNUnavailable(err error) bool {
	return errors.Is(err, scan.ErrSYNUnsupported) ||
		errors.Is(err, scan.ErrSYNPrivileges) ||
		errors.Is(err, scan.ErrSYNNoReply)
}

// synUnavailableReason turns the preflight failure into a short phrase for the
// fallback warning.
func synUnavailableReason(tr *i18n.Catalog, err error) string {
	switch {
	case errors.Is(err, scan.ErrSYNUnsupported):
		return tr.T("reason.syn_unsupported")
	case errors.Is(err, scan.ErrSYNPrivileges):
		return tr.T("reason.syn_privileges")
	case errors.Is(err, scan.ErrSYNNoReply):
		return tr.T("reason.syn_no_reply")
	}
	return err.Error()
}

// enrichHost attaches the localized hack-reason notes to every open port.
func enrichHost(h *model.Host, kb *hackreason.KB, opt *Options, lang string) {
	if !opt.HackReason || kb == nil {
		return
	}
	for i := range h.Ports {
		p := &h.Ports[i]
		if p.State != model.StateOpen {
			continue
		}
		svcName := ""
		if p.Service != nil {
			svcName = p.Service.Name
		}
		notes := kb.Lookup(p.Proto, p.Port, svcName, lang)
		if len(notes) == 0 {
			continue
		}
		if p.Service == nil {
			p.Service = &model.Service{
				Name:   ports.DisplayName(p.Proto, p.Port),
				Method: "table",
				Conf:   3,
			}
		}
		p.Service.Hack = notes
	}
}

// buildTiming merges -T with the explicit overrides.
func buildTiming(opt *Options) scan.Timing {
	t := scan.TimingTemplate(opt.Timing)
	if opt.Changed("min-rate") {
		t.MinRate = opt.MinRate
	}
	if opt.Changed("max-rate") {
		t.MaxRate = opt.MaxRate
	}
	if opt.Changed("max-retries") {
		t.MaxRetries = opt.MaxRetries
	}
	if opt.Changed("min-parallelism") {
		t.MinParallel = opt.MinParallel
	}
	if opt.Changed("max-parallelism") {
		t.MaxParallel = opt.MaxParallel
	}
	if opt.Changed("timeout") && opt.Timeout > 0 {
		t.InitialTimeout = opt.Timeout
		t.MaxTimeout = opt.Timeout * 3
	}
	if opt.Changed("scan-delay") {
		t.Delay = opt.ScanDelay
	}
	t.Clamp()
	return t
}

// detectTimeout bounds service detection for one port.
func detectTimeout(opt *Options) time.Duration {
	if opt.ProbeTimeout > 0 {
		return opt.ProbeTimeout*3 + time.Second
	}
	return 5 * time.Second
}

func collectTargets(ctx context.Context, opt *Options, stdin io.Reader) ([]targets.Target, error) {
	specs := append([]string{}, opt.Targets...)
	if opt.InputList != "" {
		lines, err := readTargetFile(opt.InputList, stdin)
		if err != nil {
			return nil, err
		}
		specs = append(specs, lines...)
	}
	if len(specs) == 0 {
		return nil, targets.ErrNoTargets
	}

	topt := targets.Options{NoDNS: opt.NoDNS}
	list, err := targets.Parse(ctx, specs, topt)
	if err != nil {
		return nil, err
	}

	excludeSpecs := append([]string{}, opt.Excludes...)
	if opt.ExcludeFile != "" {
		lines, err := readTargetFile(opt.ExcludeFile, stdin)
		if err != nil {
			return nil, err
		}
		excludeSpecs = append(excludeSpecs, lines...)
	}
	if len(excludeSpecs) > 0 {
		ex, err := targets.Parse(ctx, excludeSpecs, topt)
		if err != nil {
			return nil, err
		}
		list = targets.Subtract(list, ex)
	}
	return list, nil
}

// readTargetFile reads a target list, one entry per line, ignoring blanks and
// '#' comments. A path of "-" reads standard input.
func readTargetFile(path string, stdin io.Reader) ([]string, error) {
	var r io.Reader
	if path == "-" {
		r = stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("cannot read %s: %w", path, err)
		}
		defer f.Close()
		r = f
	}
	var out []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, part := range strings.Split(line, ",") {
			if p := strings.TrimSpace(part); p != "" {
				out = append(out, p)
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", path, err)
	}
	return out, nil
}

func collectPorts(opt *Options, tr *i18n.Catalog) ([]ports.Target, error) {
	popts := ports.ParseOptions{DefaultProto: ports.TCP, UDP: opt.UDP}
	var list []ports.Target

	switch {
	case opt.Ports != "":
		parsed, err := ports.ParseSpec(opt.Ports, popts)
		if err != nil {
			return nil, fmt.Errorf("%s", tr.T("err.bad_ports", opt.Ports, err))
		}
		list = parsed
	case opt.Changed("top-ports"):
		if opt.TopPorts <= 0 {
			return nil, fmt.Errorf("%s", tr.T("err.bad_ports", "--top-ports", errors.New("expected a positive number")))
		}
		if opt.TopPorts > ports.TopSize() {
			return nil, fmt.Errorf("%s", tr.T("err.top_ports_too_large", opt.TopPorts, ports.TopSize()))
		}
		list = withUDPSide(ports.Top(opt.TopPorts), opt.UDP)
	case opt.Fast:
		list = withUDPSide(ports.Top(100), opt.UDP)
	default:
		list = withUDPSide(ports.Top(0), opt.UDP)
	}

	if opt.ExcludePorts != "" {
		ex, err := ports.ParseSpec(opt.ExcludePorts, ports.ParseOptions{DefaultProto: ports.TCP})
		if err != nil {
			return nil, fmt.Errorf("%s", tr.T("err.bad_ports", opt.ExcludePorts, err))
		}
		list = ports.Subtract(list, ex)
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("%s", tr.T("err.no_ports"))
	}
	return list, nil
}

func withUDPSide(list []ports.Target, udp bool) []ports.Target {
	if !udp {
		return list
	}
	out := append([]ports.Target(nil), list...)
	for _, t := range list {
		if t.Proto == ports.TCP {
			out = append(out, ports.Target{Port: t.Port, Proto: ports.UDP})
		}
	}
	return out
}

// loadPlugins resolves the plugin sources for this run.
func loadPlugins(opt *Options, log *Logger) (*plugins.Bundle, error) {
	if opt.PluginDir != "" {
		path, err := config.ExpandPath(opt.PluginDir)
		if err != nil {
			return nil, err
		}
		return plugins.LoadPath(path)
	}

	regPath := config.RegistryPath()
	reg, err := plugins.Load(regPath)
	if err != nil {
		return nil, err
	}
	warnInsecureRegistry(log, regPath)

	bundle, err := plugins.LoadRegistered(reg, opt.StrictPlugins)
	if bundle != nil {
		for _, rec := range bundle.Missing {
			log.Warn("warn.plugin_missing", rec.Name, rec.Path)
		}
		if len(bundle.Missing) > 0 {
			log.Warn("warn.plugin_fallback")
		}
		for _, rec := range bundle.Changed {
			log.Warn("warn.plugin_changed", rec.Name, rec.Path)
		}
		for _, s := range bundle.Skipped {
			log.Info("info.plugin_skipped", s.Path, s.Reason)
		}
	}
	if err != nil {
		if opt.StrictPlugins {
			log.Warn("warn.plugin_strict")
		}
		return bundle, err
	}
	return bundle, nil
}

func applyPluginVars(opt *Options, vars map[string]string, log *Logger, pluginCount int) {
	if len(opt.PluginVars) == 0 {
		return
	}
	if pluginCount == 0 {
		log.Warn("warn.plugin_var_no_plugin")
	}
	for _, kv := range opt.PluginVars {
		key, value, ok := strings.Cut(kv, "=")
		if !ok {
			log.Warn("warn.plugin_var_malformed", kv)
			continue
		}
		vars[strings.TrimSpace(key)] = value
	}
}

func writeStructuredOutputs(opt *Options, res *model.Result, nopts report.Options, stdout io.Writer, log *Logger) error {
	xmlPath, jsonPath := opt.OutputXML, opt.OutputJSON
	if opt.OutputAll != "" {
		if xmlPath == "" {
			xmlPath = opt.OutputAll + ".xml"
		}
		if jsonPath == "" {
			jsonPath = opt.OutputAll + ".json"
		}
	}
	if xmlPath != "" {
		// Appending a second XML document produces a file no parser will read,
		// so --append-output is ignored for this format and the user is told,
		// rather than being left with something that silently fails to load.
		if opt.Append {
			log.Warn("warn.append_unsupported", "XML", xmlPath)
		}
		w, closeFn, err := writerFor(xmlPath, false, stdout)
		if err != nil {
			return err
		}
		if err := report.XML(w, res, nopts); err != nil {
			_ = closeFn()
			return err
		}
		if err := closeFn(); err != nil {
			return err
		}
	}
	if jsonPath != "" {
		format := report.FormatJSON
		if opt.JSONL {
			format = report.FormatJSONL
		}
		// JSON Lines is one document per line, so appending stays valid there.
		// A single JSON document does not.
		appendJSON := opt.Append
		if opt.Append && format == report.FormatJSON {
			log.Warn("warn.append_unsupported", "JSON", jsonPath)
			appendJSON = false
		}
		w, closeFn, err := writerFor(jsonPath, appendJSON, stdout)
		if err != nil {
			return err
		}
		if err := report.Render(w, format, res, nopts); err != nil {
			_ = closeFn()
			return err
		}
		if err := closeFn(); err != nil {
			return err
		}
	}
	return nil
}

// writerFor resolves an output path. "-" means the process stdout, which is
// how tools in a pipeline expect to consume nmap-style output.
func writerFor(path string, appendMode bool, stdout io.Writer) (io.Writer, func() error, error) {
	if path == "-" {
		return stdout, func() error { return nil }, nil
	}
	f, err := openOutput(path, appendMode)
	if err != nil {
		return nil, nil, err
	}
	return f, f.Close, nil
}

func openOutput(path string, appendMode bool) (*os.File, error) {
	flags := os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	if appendMode {
		flags = os.O_CREATE | os.O_WRONLY | os.O_APPEND
	}
	f, err := os.OpenFile(path, flags, 0o644)
	if err != nil {
		return nil, fmt.Errorf("cannot open output file %s: %w", path, err)
	}
	return f, nil
}

func progressLoop(tr *i18n.Catalog, w io.Writer, every time.Duration, scanned, total *atomic.Int64, stop <-chan struct{}) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			d, tt := scanned.Load(), total.Load()
			if tt == 0 {
				continue
			}
			fmt.Fprintf(w, "\r%s\033[K", tr.T("info.progress", d, tt, d*100/tt))
		}
	}
}

// isTerminal reports whether w looks like an interactive terminal. It tests
// the character device bit, which works on every platform without cgo.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

// targetSpecForError renders the first target specification for a message.
func targetSpecForError(opt *Options) string {
	if len(opt.Targets) > 0 {
		return opt.Targets[0]
	}
	return opt.InputList
}
