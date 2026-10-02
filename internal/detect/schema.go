// Package detect identifies the service behind an open port.
//
// Detection is data driven: the rules live in YAML (see data/fingerprints and
// the plugin system), so fingerprints can be extended without touching Go
// code. The engine runs probes, matches the response with a regular
// expression and extracts named fields (product, version, os, ...).
package detect

import (
	"embed"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

//go:embed data/fingerprints/*.yaml data/checks/*.yaml
var fingerprintFS embed.FS

// builtinDirs are read in order, so fingerprints are registered before checks.
var builtinDirs = []string{"data/fingerprints", "data/checks"}

// APIVersion is the schema version understood by this build. Plugins declare
// it so a newer plugin fails loudly instead of being misread.
const APIVersion = "argus.fingerprint/v1"

// RuleFile is the top level document of a fingerprint file.
type RuleFile struct {
	APIVersion  string `yaml:"apiVersion"`
	ID          string `yaml:"id"`
	Description string `yaml:"description"`
	Rules       []Rule `yaml:"rules"`
}

// Rule kinds.
const (
	// KindFingerprint identifies what a service is. These run whenever service
	// detection is on.
	KindFingerprint = "fingerprint"
	// KindCheck decides something about a service: unauthenticated access,
	// exposed configuration, a vulnerable build. Its probes are recognisable as
	// intrusive on the wire, so a check rule only runs when the user asks for it
	// with --findings.
	KindCheck = "check"
)

// Rule is one fingerprint or check: a set of probes plus the matches to try
// against their responses.
type Rule struct {
	ID    string `yaml:"id"`
	Desc  string `yaml:"description"`
	Kind  string `yaml:"kind"` // "" means fingerprint
	Ports []int  `yaml:"ports"`
	// Service binds a check rule to a detected service rather than to a port,
	// so a Redis instance listening on 19300 is still checked. Only useful for
	// services with a distinctive name: binding to "http" would run the check
	// on every web port.
	Service string `yaml:"service"`
	// Proto is the transport the rule speaks: "tcp" (the default) or "udp".
	// Service detection used to be TCP-only, which left SNMP and every other
	// UDP service unidentifiable.
	Proto  string  `yaml:"proto"`
	Tunnel string  `yaml:"tunnel"` // "" for plaintext, "ssl" for TLS-wrapped
	Conf   int     `yaml:"conf"`
	Probes []Probe `yaml:"probes"`
	Match  []Match `yaml:"matches"`
}

// IsCheck reports whether this rule only runs when checks are enabled.
func (r *Rule) IsCheck() bool { return r.Kind == KindCheck }

// Probe is one interaction with the port.
type Probe struct {
	ID          string        `yaml:"id"`
	Desc        string        `yaml:"description"`
	Send        string        `yaml:"send"`
	ReadTimeout time.Duration `yaml:"read_timeout"`
	ReadBytes   int           `yaml:"read_bytes"`
	// Wait is an extra delay before reading, for servers that need a moment.
	Wait time.Duration `yaml:"wait"`
}

// Match decides whether a response identifies the service (and how to extract
// fields from it) and, for a check rule, whether it carried a finding.
type Match struct {
	ID      string            `yaml:"id"`
	Desc    string            `yaml:"description"`
	Pattern string            `yaml:"pattern"`
	Set     map[string]string `yaml:"set"`
	Fields  map[string]string `yaml:"fields"`
	Conf    int               `yaml:"conf"`
	// Finding turns this match into a reported finding when the pattern hits.
	// Only meaningful on a "check" rule.
	Finding *FindingSpec `yaml:"finding"`
	// Affected restricts the match to an intersection of conditions on the
	// extracted fields: a version range, an exact value, or membership in a
	// set. That is how "an SMBv1 response with a Windows version in this range"
	// is written, and no regular expression can say it.
	Affected AffectedList `yaml:"affected"`

	re          *regexp.Regexp
	fieldRe     map[string]*regexp.Regexp
	affectedSet []affectedCondition
}

// AffectedSpec is one condition in an identity intersection.
//
// Exactly one of Range, Equals or OneOf must be given:
//
//   - field: os_version
//     range: ">=5.0 <6.2"        version range, compared as versions
//   - field: implementation
//     equals: "Windows NT"       exact value, case insensitive
//   - field: family
//     oneof: ["SMB1", "SMB2"]    value present in a set
type AffectedSpec struct {
	// Field names the extracted field to test. Defaults to "version".
	Field string `yaml:"field"`
	// Range is a version range such as ">=8.5p1 <9.8" or "==2.3.4".
	Range string `yaml:"range"`
	// Equals compares the value for equality, case insensitively.
	Equals string `yaml:"equals"`
	// OneOf matches when the value equals any of these, case insensitively.
	OneOf []string `yaml:"oneof"`
}

// AffectedList is a single condition or an intersection of several. All of them
// must hold for the match to fire, which is how "an SMBv1 response *and* a
// Windows version in this range" is written.
type AffectedList []AffectedSpec

// UnmarshalYAML accepts either one condition or a list of them, so the common
// single-condition case stays terse.
func (l *AffectedList) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.MappingNode:
		var one AffectedSpec
		if err := node.Decode(&one); err != nil {
			return err
		}
		*l = AffectedList{one}
		return nil
	case yaml.SequenceNode:
		var many []AffectedSpec
		if err := node.Decode(&many); err != nil {
			return err
		}
		*l = AffectedList(many)
		return nil
	}
	return fmt.Errorf("expected a condition or a list of conditions")
}

// affectedCondition is a compiled AffectedSpec.
type affectedCondition struct {
	field  string
	cons   []versionConstraint
	equals string
	oneOf  map[string]bool
}

func (c affectedCondition) satisfied(fields Fields) bool {
	value := fields[c.field]
	if value == "" {
		// An unknown value cannot satisfy anything: "we could not read it" is
		// not evidence of anything.
		return false
	}
	switch {
	case c.cons != nil:
		return satisfiesRange(value, c.cons)
	case c.oneOf != nil:
		return c.oneOf[strings.ToLower(value)]
	default:
		return strings.EqualFold(value, c.equals)
	}
}

func compileAffected(specs AffectedList, declared map[string]bool, source, ruleID, matchID string) ([]affectedCondition, error) {
	var out []affectedCondition
	for i, spec := range specs {
		where := fmt.Sprintf("%s: rule %q match %q affected condition %d", source, ruleID, matchID, i+1)
		set := 0
		if spec.Range != "" {
			set++
		}
		if spec.Equals != "" {
			set++
		}
		if len(spec.OneOf) > 0 {
			set++
		}
		if set != 1 {
			return nil, fmt.Errorf("%s must set exactly one of range, equals or oneof", where)
		}
		cond := affectedCondition{field: spec.Field}
		if cond.field == "" {
			cond.field = FieldVersion
		}
		if !knownFields[cond.field] && !declared[cond.field] {
			return nil, fmt.Errorf("%s names field %q, which is neither a reportable field nor extracted by this match", where, cond.field)
		}
		switch {
		case spec.Range != "":
			cons, err := parseVersionRange(spec.Range)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", where, err)
			}
			cond.cons = cons
		case len(spec.OneOf) > 0:
			cond.oneOf = make(map[string]bool, len(spec.OneOf))
			for _, v := range spec.OneOf {
				cond.oneOf[strings.ToLower(strings.TrimSpace(v))] = true
			}
		default:
			cond.equals = spec.Equals
		}
		out = append(out, cond)
	}
	return out, nil
}

// Severity levels, most severe first.
var severities = []string{"critical", "high", "medium", "low", "info"}

// FindingSpec is the conclusion a check rule reports when it fires.
type FindingSpec struct {
	// ID defaults to the match id and is only for stable references.
	ID          string        `yaml:"id"`
	Title       LocalizedText `yaml:"title"`
	Severity    string        `yaml:"severity"`
	Description LocalizedText `yaml:"description"`
	Refs        []string      `yaml:"refs"`
}

// LocalizedText accepts either a plain string or a language map:
//
//	title: Plain text
//	title: {en: Plain text, zh: 中文}
type LocalizedText map[string]string

// UnmarshalYAML implements yaml.Unmarshaler.
func (t *LocalizedText) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		if node.Value == "" {
			return nil
		}
		*t = LocalizedText{"en": node.Value}
		return nil
	case yaml.MappingNode:
		m := map[string]string{}
		if err := node.Decode(&m); err != nil {
			return err
		}
		*t = m
		return nil
	}
	return fmt.Errorf("expected a string or a language map such as {en: ..., zh: ...}")
}

// Get returns the text for lang, falling back to English and then to any value.
func (t LocalizedText) Get(lang string) string {
	if v := t[lang]; v != "" {
		return v
	}
	if v := t["en"]; v != "" {
		return v
	}
	for _, v := range t {
		if v != "" {
			return v
		}
	}
	return ""
}

// IsZero reports whether no text was provided.
func (t LocalizedText) IsZero() bool { return len(t) == 0 }

// Service field names accepted in Set/Fields and named capture groups.
// "os" and "ostype" are aliases of the same field; nmap's XML spells it
// ostype, which is why that one is canonical.
const (
	FieldService = "service"
	FieldProduct = "product"
	FieldVersion = "version"
	FieldInfo    = "info"
	FieldOS      = "os"
	FieldOSType  = "ostype"
	FieldDevice  = "device"
	FieldCPE     = "cpe"
	FieldHost    = "hostname"
)

var knownFields = map[string]bool{
	FieldService: true, FieldProduct: true, FieldVersion: true,
	FieldInfo: true, FieldOS: true, FieldOSType: true, FieldDevice: true,
	FieldCPE: true, FieldHost: true,
}

// DB holds the compiled rules.
type DB struct {
	byID      map[string]*Rule
	rules     []*Rule
	generic   []*Rule
	byPort    map[int][]*Rule
	byService map[string][]*Rule
}

// NewDB returns an empty database.
func NewDB() *DB {
	return &DB{
		byID:      map[string]*Rule{},
		byPort:    map[int][]*Rule{},
		byService: map[string][]*Rule{},
	}
}

// LoadBuiltin builds the database from the embedded fingerprint and check
// files.
func LoadBuiltin() (*DB, error) {
	db := NewDB()
	for _, dir := range builtinDirs {
		entries, err := fs.ReadDir(fingerprintFS, dir)
		if err != nil {
			return nil, fmt.Errorf("embedded rules are missing from %s: %w", dir, err)
		}
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".yaml") {
				names = append(names, e.Name())
			}
		}
		sort.Strings(names)
		for _, name := range names {
			raw, err := fingerprintFS.ReadFile(dir + "/" + name)
			if err != nil {
				return nil, err
			}
			if _, err := db.AddYAML(raw, "builtin:"+dir+"/"+name); err != nil {
				return nil, err
			}
		}
	}
	return db, nil
}

// AddYAML compiles and registers the rules of one document, appending them to
// the end of the rule order. The built-in database is loaded this way, so the
// embedded files keep the precedence their order implies.
func (db *DB) AddYAML(raw []byte, source string) (replaced []string, err error) {
	return db.addDocuments(raw, source, false)
}

// AddYAMLFront is the plugin entry point. Plugin rules are placed ahead of the
// built-in ones so that a user-supplied fingerprint actually gets a chance to
// match: a rule that is tried after the built-in fallback would never fire.
func (db *DB) AddYAMLFront(raw []byte, source string) (replaced []string, err error) {
	return db.addDocuments(raw, source, true)
}

func (db *DB) addDocuments(raw []byte, source string, front bool) (replaced []string, err error) {
	var f RuleFile
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", source, err)
	}
	if f.APIVersion != "" && f.APIVersion != APIVersion {
		return nil, fmt.Errorf("%s: unsupported apiVersion %q (this build understands %s)", source, f.APIVersion, APIVersion)
	}
	for i := range f.Rules {
		r := &f.Rules[i]
		if err := compileRule(r, source); err != nil {
			return nil, err
		}
		if r.ID == "" {
			return nil, fmt.Errorf("%s: rule %d has no id", source, i)
		}
		if len(r.Probes) == 0 {
			// A rule with no explicit probe still reads the passive banner.
			r.Probes = []Probe{{ID: "banner", Send: ""}}
		}
		if len(r.Match) == 0 {
			return nil, fmt.Errorf("%s: rule %q defines no matches", source, r.ID)
		}
		if _, dup := db.byID[r.ID]; dup {
			replaced = append(replaced, r.ID)
			db.removeRule(r.ID)
		}
		db.byID[r.ID] = r
		if front {
			db.rules = append([]*Rule{r}, db.rules...)
			if len(r.Ports) == 0 {
				db.generic = append([]*Rule{r}, db.generic...)
			}
			for _, p := range r.Ports {
				db.byPort[p] = append([]*Rule{r}, db.byPort[p]...)
			}
			continue
		}
		db.rules = append(db.rules, r)
		if len(r.Ports) == 0 {
			db.generic = append(db.generic, r)
		}
		for _, p := range r.Ports {
			db.byPort[p] = append(db.byPort[p], r)
		}
		if r.Service != "" {
			key := strings.ToLower(r.Service)
			db.byService[key] = append(db.byService[key], r)
		}
	}
	return replaced, nil
}

func (db *DB) removeRule(id string) {
	out := db.rules[:0:0]
	for _, r := range db.rules {
		if r.ID != id {
			out = append(out, r)
		}
	}
	db.rules = out
	gen := db.generic[:0:0]
	for _, r := range db.generic {
		if r.ID != id {
			gen = append(gen, r)
		}
	}
	db.generic = gen
	for svc, list := range db.byService {
		kept := list[:0:0]
		for _, r := range list {
			if r.ID != id {
				kept = append(kept, r)
			}
		}
		if len(kept) == 0 {
			delete(db.byService, svc)
		} else {
			db.byService[svc] = kept
		}
	}
	for port, list := range db.byPort {
		kept := list[:0:0]
		for _, r := range list {
			if r.ID != id {
				kept = append(kept, r)
			}
		}
		if len(kept) == 0 {
			delete(db.byPort, port)
		} else {
			db.byPort[port] = kept
		}
	}
}

// Rules returns every registered rule, in registration order.
func (db *DB) Rules() []*Rule { return db.rules }

// RuleQuery selects the rules that apply to one port.
type RuleQuery struct {
	Port   int
	Proto  string // tcp or udp; empty means tcp
	Tunnel string // "" or "ssl"
	// Checks enables kind: check rules. Their probes look like an attack on the
	// wire, so running them is a deliberate choice.
	Checks bool
	// Service also matches rules bound to a detected service name, which is how
	// a check still runs on a port nobody predicted.
	Service string
}

// RulesFor returns the rules that apply to a query. Rules bound to the port come
// first, service-bound rules next, and rules with no binding at all last.
func (db *DB) RulesFor(q RuleQuery) []*Rule {
	proto := strings.ToLower(q.Proto)
	if proto == "" {
		proto = "tcp"
	}
	var out []*Rule
	seen := map[string]bool{}
	add := func(list []*Rule) {
		for _, r := range list {
			if r.Tunnel != q.Tunnel || r.Proto != proto || seen[r.ID] {
				continue
			}
			if r.IsCheck() && !q.Checks {
				continue
			}
			seen[r.ID] = true
			out = append(out, r)
		}
	}
	add(db.byPort[q.Port])
	if q.Service != "" {
		add(db.byService[strings.ToLower(q.Service)])
	}
	add(db.generic)
	return out
}

// CountByKind returns how many rules of each kind are loaded.
func (db *DB) CountByKind() (fingerprints, checks int) {
	for _, r := range db.rules {
		if r.IsCheck() {
			checks++
		} else {
			fingerprints++
		}
	}
	return fingerprints, checks
}

// HasTLSRule reports whether any applicable TLS rule is bound to the port,
// which is used to decide whether a TLS handshake is worth attempting.
func (db *DB) HasTLSRule(port int) bool {
	for _, r := range db.byPort[port] {
		if r.Tunnel == "ssl" && r.Proto == "tcp" {
			return true
		}
	}
	return false
}

func compileRule(r *Rule, source string) error {
	if r.Conf == 0 {
		r.Conf = 10
	}
	switch strings.ToLower(r.Proto) {
	case "":
		r.Proto = "tcp"
	case "tcp", "udp":
		r.Proto = strings.ToLower(r.Proto)
	default:
		return fmt.Errorf("%s: rule %q has unsupported proto %q (expected tcp or udp)", source, r.ID, r.Proto)
	}
	switch r.Kind {
	case "", KindFingerprint:
		r.Kind = KindFingerprint
	case KindCheck:
	default:
		return fmt.Errorf("%s: rule %q has unsupported kind %q (expected %q or %q)",
			source, r.ID, r.Kind, KindFingerprint, KindCheck)
	}
	switch r.Tunnel {
	case "", "ssl":
	default:
		return fmt.Errorf("%s: rule %q has unsupported tunnel %q", source, r.ID, r.Tunnel)
	}
	for pi := range r.Probes {
		p := &r.Probes[pi]
		if p.ReadBytes <= 0 {
			p.ReadBytes = 8192
		}
		if p.ReadTimeout <= 0 {
			p.ReadTimeout = 3 * time.Second
		}
	}
	for mi := range r.Match {
		m := &r.Match[mi]
		if m.Pattern == "" {
			return fmt.Errorf("%s: rule %q match %q has no pattern", source, r.ID, m.ID)
		}
		re, err := regexp.Compile(m.Pattern)
		if err != nil {
			return fmt.Errorf("%s: rule %q match %q has an invalid pattern: %w", source, r.ID, m.ID, err)
		}
		m.re = re
		// A field that an affected condition names may be an internal variable:
		// os_version carries the value that is compared, and is never reported.
		// Anything else must be a reportable field, so a typo still fails.
		internal := map[string]bool{}
		for _, spec := range m.Affected {
			if spec.Field != "" {
				internal[spec.Field] = true
			}
		}
		declared := map[string]bool{}
		for name := range m.Fields {
			declared[name] = true
		}

		if len(m.Fields) > 0 {
			m.fieldRe = make(map[string]*regexp.Regexp, len(m.Fields))
			for name, pat := range m.Fields {
				if !knownFields[name] && !internal[name] {
					return fmt.Errorf("%s: rule %q match %q uses unknown field %q (not a reportable field, and not referenced by an affected condition)", source, r.ID, m.ID, name)
				}
				cre, err := regexp.Compile(pat)
				if err != nil {
					return fmt.Errorf("%s: rule %q match %q field %q is invalid: %w", source, r.ID, m.ID, name, err)
				}
				m.fieldRe[name] = cre
			}
		}
		for name := range m.Set {
			if !knownFields[name] {
				return fmt.Errorf("%s: rule %q match %q sets unknown field %q", source, r.ID, m.ID, name)
			}
		}
		if m.Conf == 0 {
			m.Conf = r.Conf
		}
		if len(m.Affected) > 0 {
			conds, err := compileAffected(m.Affected, declared, source, r.ID, m.ID)
			if err != nil {
				return err
			}
			m.affectedSet = conds
		}
		if m.Finding != nil {
			if r.Kind != KindCheck {
				return fmt.Errorf("%s: rule %q match %q declares a finding but the rule kind is %q, not %q",
					source, r.ID, m.ID, r.Kind, KindCheck)
			}
			if m.Finding.Title.IsZero() {
				return fmt.Errorf("%s: rule %q match %q has a finding without a title", source, r.ID, m.ID)
			}
			if m.Finding.Severity == "" {
				m.Finding.Severity = "info"
			}
			if !isSeverity(m.Finding.Severity) {
				return fmt.Errorf("%s: rule %q match %q has severity %q, expected one of %s",
					source, r.ID, m.ID, m.Finding.Severity, strings.Join(severities, ", "))
			}
			if m.Finding.ID == "" {
				m.Finding.ID = m.ID
			}
		}
	}
	return nil
}

func isSeverity(s string) bool {
	for _, want := range severities {
		if s == want {
			return true
		}
	}
	return false
}

// latin1String maps every byte to the rune with the same value.
//
// Go's regexp decodes its input as UTF-8, so a byte such as 0xFF becomes
// U+FFFD and a pattern like \xff - which means the *codepoint* U+00FF - can
// never match it. That silently broke every binary protocol: an SMB negotiate
// response, a chunk of a TLS record, anything with high bytes in it. Matching
// against a latin-1 decoding makes \xNN mean "the byte NN", which is what a
// protocol fingerprint author expects.
//
// Pure ASCII responses, which are the majority, skip the conversion entirely.
func latin1String(b []byte) string {
	for _, c := range b {
		if c >= 0x80 {
			runes := make([]rune, len(b))
			for i, c := range b {
				runes[i] = rune(c)
			}
			return string(runes)
		}
	}
	return string(b)
}

// Fields is the extracted field set for one match.
type Fields map[string]string

// apply evaluates the match against a response and returns the extracted
// fields, or nil when the pattern does not match.
func (m *Match) apply(resp []byte) Fields {
	if m.re == nil {
		return nil
	}
	text := latin1String(resp)
	loc := m.re.FindStringSubmatchIndex(text)
	if loc == nil {
		return nil
	}
	out := Fields{}
	for k, v := range m.Set {
		out[k] = v
	}
	// Named capture groups of the main pattern.
	for i, name := range m.re.SubexpNames() {
		if name == "" || i == 0 {
			continue
		}
		if !knownFields[name] {
			continue
		}
		if 2*i+1 <= len(loc) && loc[2*i] >= 0 {
			out[name] = text[loc[2*i]:loc[2*i+1]]
		}
	}
	// Field specific probes run over the whole response and take the first
	// capture group, or the whole match when the pattern has no group.
	for name, re := range m.fieldRe {
		sm := re.FindStringSubmatch(text)
		if sm == nil {
			continue
		}
		if len(sm) > 1 && sm[1] != "" {
			out[name] = sm[1]
		} else {
			out[name] = sm[0]
		}
	}

	// The conditions are part of the match, not post-processing: a rule for
	// "OpenSSH below 9.8" must simply not fire on 9.9, and a rule that needs
	// both a protocol and a version must not fire when only one of them holds.
	for _, cond := range m.affectedSet {
		if !cond.satisfied(out) {
			return nil
		}
	}
	return out
}
