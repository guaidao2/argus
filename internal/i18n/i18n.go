package i18n

import (
	"embed"
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed locales/*.yaml
var localeFS embed.FS

// DefaultLang is the language used when nothing else is specified. Argus is
// English-first: Chinese requires an explicit --lang zh (or ARGUS_LANG=zh).
const DefaultLang = "en"

type localeFile struct {
	Code     string            `yaml:"code"`
	Name     string            `yaml:"name"`
	Messages map[string]string `yaml:"messages"`
}

// Catalog holds one language plus the English fallback.
type Catalog struct {
	lang     string
	messages map[string]string
	fallback map[string]string
}

var (
	catalogs = map[string]map[string]string{}
	names    = map[string]string{}
)

func init() {
	entries, err := localeFS.ReadDir("locales")
	if err != nil {
		panic("i18n: embedded locales missing: " + err.Error())
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		raw, err := localeFS.ReadFile("locales/" + e.Name())
		if err != nil {
			panic("i18n: cannot read " + e.Name() + ": " + err.Error())
		}
		var lf localeFile
		if err := yaml.Unmarshal(raw, &lf); err != nil {
			panic("i18n: invalid locale " + e.Name() + ": " + err.Error())
		}
		code, _ := Normalize(lf.Code)
		if code == "" {
			panic("i18n: locale " + e.Name() + " has no code")
		}
		if _, dup := catalogs[code]; dup {
			panic("i18n: duplicate locale code " + code)
		}
		catalogs[code] = lf.Messages
		names[code] = lf.Name
	}
	if _, ok := catalogs[DefaultLang]; !ok {
		panic("i18n: default locale " + DefaultLang + " is missing")
	}
}

// Supported lists the available locale codes, default first.
func Supported() []string {
	out := []string{DefaultLang}
	rest := make([]string, 0, len(catalogs))
	for code := range catalogs {
		if code != DefaultLang {
			rest = append(rest, code)
		}
	}
	sort.Strings(rest)
	return append(out, rest...)
}

// LanguageName returns the human readable name of a locale code.
func LanguageName(code string) string {
	if n, ok := names[code]; ok {
		return n
	}
	return code
}

// Normalize maps a user-supplied or environment language tag onto a supported
// locale code. It accepts full tags such as "zh-CN" or "zh_CN.UTF-8" and
// reduces them to the base language ("zh").
//
// ok is false for tags argus does not ship; the caller should warn and use
// DefaultLang. Only Simplified Chinese is provided, so every zh* variant maps
// to "zh".
func Normalize(tag string) (code string, ok bool) {
	t := strings.ToLower(strings.TrimSpace(tag))
	if t == "" {
		return DefaultLang, true
	}
	// Strip POSIX locale suffixes: zh_CN.UTF-8@modifier
	if i := strings.IndexAny(t, ".@"); i >= 0 {
		t = t[:i]
	}
	t = strings.ReplaceAll(t, "_", "-")
	base := t
	if i := strings.Index(t, "-"); i >= 0 {
		base = t[:i]
	}
	switch base {
	case "en":
		return "en", true
	case "zh", "cn", "zh-hans", "zh-hant", "zh-cn", "zh-tw", "zh-hk":
		return "zh", true
	}
	return DefaultLang, false
}

// New builds the catalog for lang. Unknown languages silently yield English;
// use Normalize first if you want to warn about it.
func New(lang string) *Catalog {
	code, ok := Normalize(lang)
	if !ok {
		code = DefaultLang
	}
	if _, known := catalogs[code]; !known {
		code = DefaultLang
	}
	return &Catalog{
		lang:     code,
		messages: catalogs[code],
		fallback: catalogs[DefaultLang],
	}
}

// Lang returns the resolved locale code.
func (c *Catalog) Lang() string { return c.lang }

// T looks up key, formats it with args, and falls back to English and then to
// the raw key so a missing translation degrades to something readable instead
// of an empty string.
func (c *Catalog) T(key string, args ...any) string {
	s, ok := c.messages[key]
	if !ok {
		if s, ok = c.fallback[key]; !ok {
			s = key
		}
	}
	if len(args) == 0 {
		return s
	}
	return fmt.Sprintf(s, args...)
}

// Has reports whether the current locale defines key.
func (c *Catalog) Has(key string) bool {
	_, ok := c.messages[key]
	return ok
}

// Resolve picks the output language. Priority:
//
//  1. --lang flag
//  2. ARGUS_LANG
//  3. language from the config file
//  4. LC_ALL, then LANG
//  5. English
//
// The process locale (LANG/LC_ALL) is deliberately not consulted: argus is
// English-first and Chinese requires an explicit choice. A scanner whose output
// language changes because someone exported LANG is a scanner whose output
// nobody can parse reliably.
//
// It returns the resolved code and, when the highest-priority non-empty
// candidate was unsupported, the offending tag so the caller can warn.
func Resolve(flagLang, fileLang string) (code string, unknown string) {
	candidates := []string{
		flagLang,
		os.Getenv("ARGUS_LANG"),
		fileLang,
	}
	for _, cand := range candidates {
		if strings.TrimSpace(cand) == "" {
			continue
		}
		code, ok := Normalize(cand)
		if !ok {
			return DefaultLang, cand
		}
		return code, ""
	}
	return DefaultLang, ""
}
