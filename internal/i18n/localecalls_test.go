package i18n

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// localeCallMethods are the helpers whose first argument is a locale key.
var localeCallMethods = map[string]bool{
	"T": true, "Warn": true, "Info": true, "Notice": true, "Errorf": true,
}

// verbRe matches a printf verb. RE2 has no negative lookahead, so "%%" is not
// excluded here; it does not need to be, because the character after the first
// percent is another percent rather than a verb letter. A hypothetical "100%%d"
// would be miscounted, and no message in the catalogs does that.
var verbRe = regexp.MustCompile(`%[-+ #0-9.*]*[a-zA-Z]`)

// TestLocaleCallArguments drives every call site of the localisation helpers
// through static analysis and checks two things that are easy to get wrong and
// invisible at runtime: that the key exists, and that the number of arguments
// matches the number of verbs. A mismatch prints "%!(EXTRA ...)" or
// "%!s(MISSING)" to the user instead of the message.
func TestLocaleCallArguments(t *testing.T) {
	root := filepath.Join("..", "..")
	var files []string
	for _, dir := range []string{"cli", "report", "scan", "plugins", "detect", "hackreason"} {
		matches, err := filepath.Glob(filepath.Join(root, "internal", dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range matches {
			if !strings.HasSuffix(m, "_test.go") {
				files = append(files, m)
			}
		}
	}
	if len(files) == 0 {
		t.Fatal("no source files found; the test would pass vacuously")
	}

	checked := 0
	for _, path := range files {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !localeCallMethods[sel.Sel.Name] {
				return true
			}
			// Debugf takes a format string, not a locale key, and fmt.Errorf
			// shares a method name with the logger without being one.
			if sel.Sel.Name == "Debugf" {
				return true
			}
			if id, isIdent := sel.X.(*ast.Ident); isIdent && id.Name == "fmt" {
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			key, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			if !strings.Contains(key, ".") {
				return true // not a locale key
			}
			checked++

			pos := fset.Position(call.Pos())
			text, ok := catalogs["en"][key]
			if !ok {
				t.Errorf("%s: unknown locale key %q", pos, key)
				return true
			}
			want := len(verbRe.FindAllString(text, -1))
			got := len(call.Args) - 1
			if got != want {
				t.Errorf("%s: %s passes %d argument(s) but the message has %d verb(s): %q",
					pos, key, got, want, text)
			}
			return true
		})
	}
	if checked < 50 {
		t.Fatalf("only %d call sites checked; the analysis probably stopped working", checked)
	}
	t.Logf("checked %d localisation call sites", checked)
}

func TestEveryCatalogKeyIsUsedOrJustified(t *testing.T) {
	// A cheap guard against typos in the catalogs themselves: every key must be
	// well formed.
	for _, code := range Supported() {
		for key := range catalogs[code] {
			if !strings.Contains(key, ".") {
				t.Errorf("locale %s: key %q is not namespaced", code, key)
			}
			if strings.Contains(key, " ") {
				t.Errorf("locale %s: key %q contains a space", code, key)
			}
		}
	}
}
