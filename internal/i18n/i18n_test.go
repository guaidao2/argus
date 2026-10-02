package i18n

import (
	"strings"
	"testing"
)

func TestNormalize(t *testing.T) {
	cases := map[string]struct {
		code string
		ok   bool
	}{
		"":            {DefaultLang, true},
		"en":          {"en", true},
		"EN":          {"en", true},
		"en-US":       {"en", true},
		"en_US.UTF-8": {"en", true},
		"zh":          {"zh", true},
		"zh-CN":       {"zh", true},
		"zh_CN.UTF-8": {"zh", true},
		"zh-Hans":     {"zh", true},
		"zh-TW":       {"zh", true},
		"cn":          {"zh", true},
		"fr":          {DefaultLang, false},
		"de-DE":       {DefaultLang, false},
	}
	for in, want := range cases {
		got, ok := Normalize(in)
		if got != want.code || ok != want.ok {
			t.Errorf("Normalize(%q) = (%q, %v), want (%q, %v)", in, got, ok, want.code, want.ok)
		}
	}
}

// TestResolveIgnoresProcessLocale pins the English-first decision: argus must
// not switch language because the environment happens to be localised.
func TestResolveIgnoresProcessLocale(t *testing.T) {
	t.Setenv("LANG", "zh_CN.UTF-8")
	t.Setenv("LC_ALL", "zh_CN.UTF-8")
	t.Setenv("ARGUS_LANG", "")

	if code, unknown := Resolve("", ""); code != "en" || unknown != "" {
		t.Fatalf("Resolve with a Chinese process locale = (%q, %q), want (en, \"\")", code, unknown)
	}
	if code, _ := Resolve("zh", ""); code != "zh" {
		t.Fatalf("--lang zh should win, got %q", code)
	}
	if code, _ := Resolve("", "zh"); code != "zh" {
		t.Fatalf("the config file should be honoured, got %q", code)
	}
	if code, unknown := Resolve("fr", ""); code != "en" || unknown != "fr" {
		t.Fatalf("an unsupported language should be reported, got (%q, %q)", code, unknown)
	}
}

func TestArgusLangEnvironment(t *testing.T) {
	t.Setenv("ARGUS_LANG", "zh")
	if code, _ := Resolve("", ""); code != "zh" {
		t.Fatalf("ARGUS_LANG should be honoured, got %q", code)
	}
}

// TestCatalogsHaveTheSameKeys is the guard that keeps a translation honest: a
// key added to English but not to Chinese would silently fall back and stay
// unnoticed.
func TestCatalogsHaveTheSameKeys(t *testing.T) {
	en := catalogs["en"]
	zh := catalogs["zh"]
	if len(en) == 0 || len(zh) == 0 {
		t.Fatal("locales did not load")
	}
	for key := range en {
		if _, ok := zh[key]; !ok {
			t.Errorf("missing zh translation for %q", key)
		}
	}
	for key := range zh {
		if _, ok := en[key]; !ok {
			t.Errorf("zh has a key English does not: %q", key)
		}
	}
}

// TestFormatArgumentsMatch checks that both languages use the same number of
// verbs, because T() formats with the arguments the Go code supplies.
func TestFormatArgumentsMatch(t *testing.T) {
	countVerbs := func(s string) int {
		n := 0
		for i := 0; i < len(s); i++ {
			if s[i] != '%' {
				continue
			}
			if i+1 < len(s) && s[i+1] == '%' {
				i++
				continue
			}
			n++
		}
		return n
	}
	for key, enText := range catalogs["en"] {
		zhText, ok := catalogs["zh"][key]
		if !ok {
			continue
		}
		if a, b := countVerbs(enText), countVerbs(zhText); a != b {
			t.Errorf("%s: en has %d format verbs, zh has %d", key, a, b)
		}
	}
}

func TestTranslationAndFallback(t *testing.T) {
	zh := New("zh")
	if got := zh.Lang(); got != "zh" {
		t.Fatalf("Lang() = %q", got)
	}
	if got := zh.T("app.authors"); got != "作者" {
		t.Errorf("zh app.authors = %q", got)
	}
	if got := zh.T("report.host_down"); !strings.Contains(got, "主机") {
		t.Errorf("zh report.host_down = %q", got)
	}

	en := New("en")
	if got := en.T("app.authors"); got != "Authors" {
		t.Errorf("en app.authors = %q", got)
	}

	// An unknown key degrades to the key itself rather than an empty string.
	if got := en.T("does.not.exist"); got != "does.not.exist" {
		t.Errorf("missing key = %q", got)
	}

	// Formatting works and the language is selected at call time.
	if got := zh.T("report.extraports", 3, "关闭", "tcp", "conn-refused"); !strings.Contains(got, "3") {
		t.Errorf("formatted zh message = %q", got)
	}
}

func TestSupportedList(t *testing.T) {
	got := Supported()
	if len(got) < 2 || got[0] != DefaultLang {
		t.Fatalf("Supported() = %v, the default language must come first", got)
	}
	found := false
	for _, code := range got {
		if code == "zh" {
			found = true
		}
	}
	if !found {
		t.Fatalf("Supported() = %v, missing zh", got)
	}
	if LanguageName("zh") == "" || LanguageName("zz") != "zz" {
		t.Error("LanguageName should fall back to the code")
	}
}
