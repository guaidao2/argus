package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/guaidao2/argus/internal/config"
	"github.com/guaidao2/argus/internal/plugins"
)

// pluginOps handles the plugin management commands. handled is false when the
// invocation was a normal scan.
func pluginOps(opt *Options, log *Logger, stdout io.Writer) (handled bool, code int) {
	switch {
	case opt.RegisterPlugin != "":
		return true, registerPlugin(opt, log, stdout)
	case opt.UnregisterAll:
		return true, unregisterAll(log, stdout)
	case opt.UnregisterPlugin != "":
		return true, unregisterPlugin(opt.UnregisterPlugin, log, stdout)
	case opt.ListPlugins:
		return true, listPlugins(log, stdout)
	}
	return false, exitOK
}

func registerPlugin(opt *Options, log *Logger, stdout io.Writer) int {
	if opt.UnregisterPlugin != "" || opt.ListPlugins {
		log.Errorf("err.plugin_mode_conflict")
		return exitUsage
	}
	path, err := config.ExpandPath(opt.RegisterPlugin)
	if err != nil {
		log.Errorf("err.plugin_no_path", opt.RegisterPlugin)
		return exitError
	}
	if _, err := os.Stat(path); err != nil {
		log.Errorf("err.plugin_no_path", path)
		return exitError
	}

	rec, skipped, err := plugins.Inspect(path)
	if err != nil {
		log.Errorf("err.plugin_bad", path, err)
		return exitError
	}
	// Files in a pack directory that are not plugin documents are reported
	// here rather than silently ignored: the user is standing right here and
	// this is the moment the mistake is cheap to fix.
	for _, s := range skipped {
		log.Warn("warn.plugin_skipped", s.Path, s.Reason)
	}

	regPath := config.RegistryPath()
	if err := config.EnsureDir(); err != nil {
		log.Errorf("err.plugin_registry_write", err)
		return exitError
	}
	reg, err := plugins.Load(regPath)
	if err != nil {
		log.Errorf("err.plugin_registry_read", err)
		return exitError
	}
	warnInsecureRegistry(log, regPath)

	updated, previous := reg.Upsert(rec)
	if err := reg.Save(); err != nil {
		log.Errorf("err.plugin_registry_write", err)
		return exitError
	}

	if updated {
		if previous.Path != rec.Path {
			log.Notice("info.plugin_updated", rec.Name, previous.Path, rec.Path)
		} else {
			log.Notice("info.plugin_registered", rec.Name, rec.Path)
		}
	} else {
		log.Notice("info.plugin_registered", rec.Name, rec.Path)
	}
	log.Info("info.state_dir", config.ResolveDir())
	return exitOK
}

func unregisterPlugin(ref string, log *Logger, stdout io.Writer) int {
	regPath := config.RegistryPath()
	reg, err := plugins.Load(regPath)
	if err != nil {
		log.Errorf("err.plugin_registry_read", err)
		return exitError
	}
	matches, err := reg.Find(ref)
	if err != nil {
		log.Errorf("err.plugin_not_found", ref)
		return exitError
	}
	if len(matches) > 1 {
		names := make([]string, 0, len(matches))
		for _, m := range matches {
			names = append(names, m.Name+" ("+m.Path+")")
		}
		log.Errorf("err.plugin_ambiguous", ref, strings.Join(names, ", "))
		return exitError
	}
	removed := reg.Remove(matches)
	if removed == 0 {
		log.Notice("info.plugin_none_removed")
		return exitOK
	}
	if err := reg.Save(); err != nil {
		log.Errorf("err.plugin_registry_write", err)
		return exitError
	}
	log.Notice("info.plugin_unregistered", matches[0].Name, matches[0].Path)
	return exitOK
}

func unregisterAll(log *Logger, stdout io.Writer) int {
	regPath := config.RegistryPath()
	reg, err := plugins.Load(regPath)
	if err != nil {
		log.Errorf("err.plugin_registry_read", err)
		return exitError
	}
	n := reg.RemoveAll()
	if err := reg.Save(); err != nil {
		log.Errorf("err.plugin_registry_write", err)
		return exitError
	}
	if n == 0 {
		log.Notice("info.plugin_none_removed")
		return exitOK
	}
	log.Notice("info.plugin_unregistered_all", n)
	return exitOK
}

func listPlugins(log *Logger, stdout io.Writer) int {
	regPath := config.RegistryPath()
	reg, err := plugins.Load(regPath)
	if err != nil {
		log.Errorf("err.plugin_registry_read", err)
		return exitError
	}
	tr := log.Tr
	if len(reg.Plugins) == 0 {
		fmt.Fprintln(stdout, tr.T("info.plugins_none"))
		fmt.Fprintln(stdout, tr.T("info.state_dir", config.ResolveDir()))
		return exitOK
	}

	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, tr.T("info.registry_table_header"))
	missing := 0
	for _, rec := range reg.Plugins {
		state, err := plugins.Status(rec)
		label := tr.T("info.registry_state_ok")
		switch {
		case err != nil || state == plugins.StateMissing:
			label = tr.T("info.registry_state_missing")
			missing++
		case state == plugins.StateChanged:
			label = tr.T("info.registry_state_changed")
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			rec.Name, rec.Kind, label, rec.Path, rec.RegisteredAt.Local().Format("2006-01-02 15:04"))
	}
	tw.Flush()

	if missing > 0 {
		log.Warn("warn.plugin_missing_summary", missing)
		log.Warn("warn.plugin_fallback")
	}
	log.Info("info.state_dir", config.ResolveDir())
	return exitOK
}

// warnInsecureRegistry flags a registry that other local users could rewrite.
// argus is routinely run as root, and the registry points at plugin data that
// root then loads, so this is a real privilege escalation path.
func warnInsecureRegistry(log *Logger, path string) {
	if !config.Insecure(path) {
		return
	}
	log.Warn("warn.registry_insecure", path, log.Tr.T("warn.registry_insecure_root"))
}
