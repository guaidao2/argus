package cli

import (
	"fmt"
	"io"

	"github.com/guaidao2/argus/internal/i18n"
)

// Logger writes localised diagnostics to stderr. Keeping every message on
// stderr means stdout stays pipeable: `argus ... | jq` must never see a
// warning mixed into the JSON.
type Logger struct {
	Tr      *i18n.Catalog
	W       io.Writer
	Verbose int
	Debug   int
}

// Warn always prints, prefixed like nmap's warnings.
func (l *Logger) Warn(key string, args ...any) {
	if l == nil || l.W == nil {
		return
	}
	fmt.Fprintf(l.W, "%s%s\n", l.Tr.T("prefix.warning"), l.Tr.T(key, args...))
}

// Info prints only when -v was given.
func (l *Logger) Info(key string, args ...any) {
	if l == nil || l.W == nil || l.Verbose <= 0 {
		return
	}
	fmt.Fprintf(l.W, "%s\n", l.Tr.T(key, args...))
}

// Notice prints unconditionally: used for the direct output of plugin
// management commands, which are the whole point of the invocation.
func (l *Logger) Notice(key string, args ...any) {
	if l == nil || l.W == nil {
		return
	}
	fmt.Fprintf(l.W, "%s\n", l.Tr.T(key, args...))
}

// Debugf prints only when -d was given. It matches scan.Options.Debugf.
func (l *Logger) Debugf(format string, args ...any) {
	if l == nil || l.W == nil || l.Debug <= 0 {
		return
	}
	fmt.Fprintf(l.W, "%s%s\n", l.Tr.T("prefix.debug"), fmt.Sprintf(format, args...))
}

// Errorf prints a localised error line.
func (l *Logger) Errorf(key string, args ...any) {
	if l == nil || l.W == nil {
		return
	}
	fmt.Fprintf(l.W, "%s%s\n", l.Tr.T("prefix.error"), l.Tr.T(key, args...))
}
