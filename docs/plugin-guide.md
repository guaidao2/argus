# Writing an argus plugin

[中文版](plugin-guide.zh-CN.md)

A plugin adds service fingerprints and offensive-security notes to argus
without recompiling it. This guide documents the schema that this build
actually understands — every example in it is parsed by the test suite, so it
cannot drift away from the code.

---

## 1. What a plugin is

A plugin is **one YAML document**. argus parses it and does nothing else with
it: there is no plugin code, no scripting language and no way for a plugin to
execute anything. The worst a hostile plugin can do is give you wrong
fingerprints.

A plugin can contribute two things, in any combination:

| Section | What it does |
| --- | --- |
| `fingerprints` | Probe open ports and identify what is answering |
| `hack_reasons` | Attach reconnaissance checklists to ports or services |

## 2. Files, directories and packs

```bash
argus --register-plugin ./my-plugin.yaml       # one file
argus --register-plugin ./my-pack/             # a directory = one pack
argus --plugin-dir ./my-pack/ -sV 10.0.0.1     # one run, ignore the registry
```

A directory is registered as a single entry named after the directory, and is
walked **recursively**:

```
my-pack/
├── top.yaml             loaded
├── web/a.yaml           loaded
├── db/nested/b.yaml     loaded
├── .hidden/c.yaml       skipped (hidden)
└── values.yaml          reported, not fatal (not a plugin document)
```

Rules for what gets read:

- Only `*.yaml` and `*.yml`. Hidden files and hidden directories are ignored,
  so a `.git` inside a pack cannot break it.
- In a **directory**, a file that is not a plugin document is reported (at
  registration with a warning, during a scan with `-v`) and the rest still
  loads. Real packs keep a README or a values file next to the plugins.
- When you name a **single file**, a file that is not a plugin document is a
  hard error. You named it; argus will not quietly skip it.
- A directory with no usable documents at all is an error.

Registration remembers the absolute path (symlinks resolved) and the SHA-256 of
the contents. If the plugin disappears or changes afterwards, see the "Soft
failure" section of the main README.

## 3. The document envelope

```yaml
apiVersion: argus.plugin/v1     # required, exactly this value
name: my-plugin                 # required
version: 1.0.0                  # optional, informational
author: you                     # optional
license: MIT                    # optional
description: what it is         # optional
argus_min_version: 1.0.0        # optional, refuses to load on older builds
vars:                           # optional, usable as {{var:NAME}}
  status_path: /status

fingerprints: { ... }           # at least one of these two
hack_reasons: { ... }
```

Field notes:

- `apiVersion` is checked, not guessed at. A document written for a newer
  schema is rejected with a message saying which version this build understands.
- `argus_min_version` uses a simple dotted comparison (`1.10.0` > `1.9.0`).
  Pre-release suffixes are ignored.
- `vars` values are substituted into probe payloads. `--plugin-var key=value`
  on the command line overrides anything declared here, which is how one pack
  serves several environments.

## 4. Fingerprints

<!-- testable -->
```yaml
apiVersion: argus.plugin/v1
name: my-app-fingerprints
version: 1.0.0
argus_min_version: 1.0.0
vars:
  status_path: /status

fingerprints:
  apiVersion: argus.fingerprint/v1
  id: my-fingerprints
  description: optional
  rules:
    - id: my-rule
      description: optional
      ports: [9000, 9001]     # omit to try on every open port
      tunnel: ""              # "" for plaintext, "ssl" for TLS
      conf: 10                # confidence, 0-10, default 10
      probes:
        - id: get-status
          send: "GET {{var:status_path}} HTTP/1.0\r\nHost: {{host}}\r\nUser-Agent: {{agent}}/{{argus_version}}\r\n\r\n"
          read_timeout: 3s
          read_bytes: 8192
      matches:
        - id: json-service
          pattern: '(?is)"service"\s*:\s*\{'
          set:
            service: my-app
            product: My App
          fields:
            version: '"version"\s*:\s*"([^"]+)"'
```

### How a rule is evaluated

1. argus opens **one connection per probe** (probes never share a connection),
   optionally does a TLS handshake first when `tunnel: ssl`, sends `send`, then
   reads until `read_timeout`, `read_bytes` or EOF.
2. Every `matches` entry is tried in order against the response. The **first**
   one whose `pattern` matches wins and the rule stops.
3. If no rule matched, the port table name is used and the port is still
   reported as open.

Rules are tried in this order:

1. Rules that name the port (`ports: [9000]`).
2. Rules with no `ports`, which apply everywhere.
3. Plugin rules before built-in rules, so your rule gets a chance to win.

A probe with an empty `send` only reads: that is how banner-first protocols
(SSH, FTP, SMTP, VNC, MySQL) are identified. The passive read is shared between
banner rules, so it costs one connection, not one per rule.

### Probe fields

| Field | Default | Meaning |
| --- | --- | --- |
| `send` | `""` | Bytes to send. Empty means "just listen". |
| `read_timeout` | `3s` | Give up reading after this. |
| `read_bytes` | `8192` | Stop reading once this much has arrived. |
| `wait` | `0` | Pause before reading, for servers that need a moment. |

After the first chunk arrives, argus waits at most 200 ms for more before
closing, so a chatty server cannot hold a probe open for the whole timeout.

### Placeholders in `send`

| Placeholder | Value |
| --- | --- |
| `{{host}}` | Target address, as scanned |
| `{{port}}` | Target port |
| `{{agent}}` | User agent (`argus` by default) |
| `{{argus_version}}` | Running argus version |
| `{{var:NAME}}` | A `vars` entry, or `--plugin-var NAME=...` |

### Match fields

| Field | Meaning |
| --- | --- |
| `pattern` | Go regular expression (RE2). Must match for the rule to fire. |
| `set` | Constant values assigned to result fields. |
| `fields` | `field: regex` pairs run over the whole response; the first capture group (or the whole match) is used. |
| `conf` | Confidence for this match; defaults to the rule's `conf`. |

A named capture group in `pattern` whose name is a known field is extracted too.
Precedence: `set` first, then named groups, then `fields` — later ones win.

### The extractable fields

| Field | Becomes |
| --- | --- |
| `service` | The SERVICE column, e.g. `http` |
| `product` | First part of VERSION, e.g. `nginx` |
| `version` | Second part of VERSION, e.g. `1.24.0` |
| `info` | Parenthesised extra info |
| `os` / `ostype` | Parenthesised OS hint (both spellings work) |
| `device` | Parenthesised device hint |
| `cpe` | Comma separated CPEs, into the XML |
| `hostname` | Appended to the extra info |

Anything else is rejected at load time with the field name in the message — a
typo fails loudly instead of being ignored.

### TLS-wrapped services

`tunnel: ssl` makes argus complete a TLS handshake first (with SNI when the
target is a name, and ALPN offering `h2`/`http/1.1`) and then run the probe
inside it. The handshake also yields the certificate, which lands in the report
with `-v` and in `-oX`/`-oJ` always. Detection of a TLS port happens
automatically when the passive read looks like a TLS record or the port has an
`ssl` rule bound to it — you do not need to configure it.

## 5. Checks and findings

A `kind: check` rule reaches a **conclusion** instead of an identification:
"this port is reachable without credentials" rather than "this is nginx".
Findings are reported separately from the service description, because
"nginx 1.24.0" is an observation and "the index list is readable without
credentials" is a judgement.

```yaml
<!-- testable -->
apiVersion: argus.plugin/v1
name: my-checks
version: 1.0.0

fingerprints:
  apiVersion: argus.fingerprint/v1
  id: my-checks
  rules:
    - id: my-service-unauthenticated
      description: The service answers administrative requests without credentials
      kind: check
      ports: [9000]
      service: my-service
      probes:
        - id: probe
          send: "GET /admin/status HTTP/1.0\r\nHost: {{host}}\r\n\r\n"
          read_timeout: 3s
          read_bytes: 8192
      matches:
        - id: unauth
          pattern: '(?im)^HTTP/1\.[01] 200\b.*server_status'
          finding:
            title:
              en: "My Service: unauthenticated admin access"
              zh: "My Service：管理接口未授权访问"
            severity: high
            description:
              en: "The status endpoint answered without credentials, so administrative data is readable by anyone who can reach the port."
              zh: "状态端点在无凭据情况下作出了响应，任何能访问该端口的人都能读取管理数据。"
            refs:
              - "https://example.invalid/docs/security"
          set: {service: my-service, product: My Service}
```

### When a check runs

**Only with `--findings`.** A check probe is recognisable as an intrusion on the
wire — it requests an administrative endpoint, sends a database command, or
tries default credentials — so argus will not send one just because you asked
for service detection. Without the flag, `kind: check` rules are not even
offered to the detector.

A check is reached two ways, and both are evaluated:

| Binding | Fires when |
| --- | --- |
| `ports: [...]` | The scanned port is in the list, service unknown or not. |
| `service: X` | The identification pass recognised service X, whatever port it is on. |

The second is what makes a Redis instance on port 19300 still get checked. It
only works for services with a distinctive name, though: binding a check to
`http` would run it on every web port in the scan. argus rejects a few obviously
generic bindings, and the built-in checks only bind where the name is specific
(`redis`, `memcached`, `mongodb`, `couchdb`).

Note the consequence for unusual ports: if nothing identified the service, a
service-bound check has nothing to match on either. If you are scanning a range
where a service may hide on random ports, add an identification rule with no
`ports` (see section 5) alongside the check.

### Two exchanges in one probe

A probe sends once and reads once, but that does not restrict you to a single
protocol exchange. Line oriented protocols answer each line independently, so
several commands can be pipelined into one write:

```yaml
probes:
  - id: anonymous-login
    send: "USER anonymous\r\nPASS anonymous@example.com\r\n"
```

The response then carries both answers, and the pattern demands both of them:

```yaml
pattern: '(?s)331 [^\r\n]*\r\n230 '
```

Requiring the `331` before the `230` is what separates "our PASS was accepted"
from a `230` that some other part of the session produced. Without it the check
degenerates into a grep.

This is how the built-in anonymous FTP check works, and it is the widest
"multi step" flow a declarative probe can express today: a real two-session
flow (log in, then use the session) needs the state machine described in
section 8.

### Matching binary responses

Patterns are matched against a **latin-1 decoding** of the response, so `\xNN`
means *the byte NN*, and offsets count bytes. A protocol fingerprint can
therefore be written the way the wire format reads:

```yaml
pattern: '(?s)^....\xffSMB\x72\x00\x00\x00\x00.{23}\x11[\x00-\x05]'
```

That is the built-in SMBv1 check: a four byte NetBIOS header, the `\xffSMB`
signature, NEGOTIATE (0x72), success status, a fixed 23 byte tail, WordCount
0x11, and then a dialect index below 6 — an index of 0xffff would mean no
dialect in common, which is what a server with SMBv1 switched off answers.

Pure ASCII responses skip the conversion, so the common case costs nothing.

### Finding fields

| Field | Required | Meaning |
| --- | --- | --- |
| `title` | yes | One line naming the finding. |
| `severity` | no | `critical`, `high`, `medium`, `low` or `info`. Defaults to `info`. |
| `description` | no | Why it matters, and what it implies. |
| `refs` | no | References: vendor documentation, an advisory, a technique id. |
| `id` | no | Stable id; defaults to the match id. |

`title` and `description` accept either a plain string or a language map
(`{en: ..., zh: ...}`). A plain string is used for every language. English is
the fallback when a translation is missing.

A `finding` on a rule whose `kind` is not `check` is rejected at load time, and
so is a finding without a title or with an unknown severity. Severity levels are
matched against the fixed list above, so a typo fails loudly.

### Version-following checks

A large share of real findings are "the version in the banner falls inside this
range" — OpenSSH below 9.8, vsftpd exactly 2.3.4, httpd 2.4.49 or 2.4.50. No
regular expression can express that, and no protocol state is needed either: one
banner is enough. `affected` adds the missing comparison.

```yaml
<!-- testable -->
apiVersion: argus.plugin/v1
name: my-version-checks
version: 1.0.0

fingerprints:
  apiVersion: argus.fingerprint/v1
  id: my-version-checks
  rules:
    - id: my-daemon-range
      description: A daemon version inside a known affected range
      kind: check
      ports: [9000]
      probes:
        - id: banner
          send: ""
          read_timeout: 3s
          read_bytes: 512
      matches:
        - id: affected
          pattern: '(?i)example-daemon'
          fields:
            version: '(?i)example-daemon[ /]([0-9][^\s\r\n]*)'
          affected:
            range: ">=1.2.0 <1.4.7"
          finding:
            title:
              en: "Example daemon: version in an affected range"
              zh: "Example daemon：版本位于受影响区间"
            severity: medium
            description:
              en: "The banner reports a version between 1.2.0 and 1.4.6. This is a version match rather than a confirmation."
              zh: "banner 报告的版本位于 1.2.0 至 1.4.6 之间。这是版本匹配，而非确认。"
```

| Field | Meaning |
| --- | --- |
| `field` | Which extracted field holds the version. Defaults to `version`. |
| `range` | One or more constraints, ANDed, separated by spaces or commas: `">=8.5p1 <9.8"`, `"==2.3.4"`, `"1.3.5"`. |

Operators are `<`, `<=`, `>`, `>=`, `==`, `!=`. A bare version means equality.
An unknown field or an unparseable range fails at load time.

**How versions are compared.** Each version is split into runs of digits and
runs of letters; separators only delimit runs. Digits compare numerically, so
`1.24.0` is above `1.9.0`, and a trailing letter sorts above the bare number, so
`1.3.5` is below `1.3.5a`. When one version is a prefix of the other, the
shorter one is smaller: `9.8` is below `9.8p1`. Distribution suffixes do not
confuse it: `8.9p1-3ubuntu0.4` compares above `8.5p1` and below `9.8`.

This is **not** semver, deliberately: banners are not semver. `2.3.4-rc1`
compares above `2.3.4` here, where semver would say below, because guessing
which suffixes mean "not yet released" introduces more errors than it removes.

**A version match is not a confirmation.** Distributions routinely backport a
security fix without changing the version string, so a version inside a range is
a reason to look, not a verdict. Write the finding text so a reader cannot miss
that, and keep the severity honest: the built-in version checks are `medium`
even where the underlying flaw is critical. An `affected` match also fails
closed — if the version could not be extracted at all, the rule does not fire,
because an unknown version is not evidence.

### Intersections: protocol version and operating system version

Many findings are not "this one field falls in a range" but "these observations
hold at the same time". MS17-010 is the canonical case: an SMBv1 response **and**
an operating system version in the affected family. Either signal alone is
noise; together they are worth looking at.

`affected` takes a list, and every condition in it must hold:

```yaml
<!-- testable -->
apiVersion: argus.plugin/v1
name: my-intersection
version: 1.0.0

fingerprints:
  apiVersion: argus.fingerprint/v1
  id: my-intersection
  rules:
    - id: legacy-smb-candidate
      kind: check
      ports: [445]
      probes:
        - id: negotiate
          send: "\x00\x00\x00\x45\xffSMB\x72"
          read_timeout: 4s
      matches:
        - id: candidate
          pattern: '(?s)\\xffSMB'
          fields:
            protocol: '(\xffSMB|\xfeSMB)'
            os_version: 'Windows ([0-9][0-9.]*)'
            implementation: '(Samba|Windows NT|Windows 2000)'
          affected:
            - {field: protocol, equals: "\xffSMB"}
            - {field: os_version, range: ">=5.0 <6.2"}
            - {field: implementation, oneof: ["Windows NT", "Samba"]}
          finding:
            title:
              en: "SMBv1 on a legacy Windows version"
              zh: "SMBv1 且 Windows 版本较旧"
            severity: medium
            description:
              en: "Two observations hold at once. This is an intersection, not a confirmation."
              zh: "两个观察同时成立。这是交集，不是确认。"
```

| Selector | Meaning |
| --- | --- |
| `range: ">=5.0 <6.2"` | The value is a version and falls in the range. |
| `equals: "SMB1"` | The value equals this, case insensitively. |
| `oneof: [a, b]` | The value equals one of these, case insensitively. |

A condition naming a field that nothing extracts is rejected at load time,
because such a rule can never fire. A condition on a field that came back empty
does not fire either: an unread value is not evidence.

**Getting several signals out of one probe.** A probe still sends once and
reads once, but several protocol exchanges can be pipelined into that one write
when each answers independently. FTP allows it for `USER`/`PASS`; SMB allows it
too, which is what makes the SMB check above possible:

```yaml
send: "<NEGOTIATE message><SESSION SETUP message>"
```

The server answers both, and one read returns the two responses: the first
carries the dialect (the protocol version), the second the `NativeOS` string
(the operating system version). That is how the built-in
`smb1-legacy-windows-family` check gets both halves of its intersection from a
single probe.

The session setup uses an empty account and the empty-password LM response,
which is what a null session is. A server that requires credentials answers
with an error, the pattern does not match, and nothing is reported — a false
negative rather than a false positive, which is the right way round for this.

Fields that only exist to be compared are allowed: `os_version` above is
extracted but never reported. A field name that is neither reportable nor
referenced by a condition is still an error, so typos keep failing loudly.

### How findings are reported

- **Normal output** follows nmap's script convention, inside the port's block:

  ```
  6379/tcp open  redis   Redis 7.2.4
  | check: Redis: unauthenticated access [HIGH]
  | The server answered INFO without credentials, so any client that can reach the port can read its configuration and keys.
  |_refs: https://redis.io/docs/latest/operate/oss_and_stack/management/security/
  ```

- **XML** uses nmap's own `<script id="rule:match" output="...">` element, so
  the tooling that already parses NSE output (Metasploit's `db_import`, Faraday,
  report generators) picks findings up without special casing.
- **JSON** puts them in `findings[]` on the port, and counts them in
  `summary.findings`.
- Machine readable output is never translated, so a finding's title and
  description stay in the language they were authored in for XML and JSON.

### What a finding is not

A finding is a pattern match, not a proof. `--findings` narrows the gap by
requiring an explicit opt-in and by keeping conclusions separate from
identifications, but a rule that matches on `200 OK` alone will produce false
positives on a service that answers `200 OK` to everything. Every built-in check
therefore matches on content that only appears in a successful response — an
index list, a pod list, a version field — and never on the status code alone.
Hold user-written checks to the same standard, and verify a finding before it
goes into a report.

## 6. Hack reasons

<!-- testable -->
```yaml
apiVersion: argus.plugin/v1
name: my-app-notes
version: 1.0.0

hack_reasons:
  apiVersion: argus.hackreason/v1
  id: my-notes
  entries:
    - id: my-service
      ports: [9000, 9001]     # applies to these ports
      service: my-app         # ...and to this service
      any_port: true          # ...even on a non standard port
      proto: tcp              # default tcp
      title:
        en: My service
        zh: 我的服务
      points:
        en: ["Check the admin endpoint"]
        zh: ["检查管理端点"]
      tools: [curl]
      refs: ["https://example.invalid/docs"]
```

Three matching modes, and the distinction matters:

| Declaration | Fires when |
| --- | --- |
| `ports: [...]` | The scanned port is in the list. |
| `service: X` with no `ports` | The detected service is X, on any port. |
| `service: X` plus `any_port: true` | The detected service is X, on any port, even though ports are listed. |

Without `any_port`, a `ports` list is a claim about those ports only. This is
deliberate: letting every entry that mentions `service: http` fire on every open
web port produced a wall of irrelevant advice on a single port.

`title` and `points` are language maps. English is the fallback when the
requested language is missing. `tools` and `refs` are not translated.

## 7. Debugging a plugin

```bash
# Load without touching the registry, and watch what the detector does.
argus --plugin-dir ./my-pack -d -Pn -sV -p 9000 10.0.0.1

# Check a plugin is valid before registering it.
argus --register-plugin ./my-pack

# See what is registered and whether it still matches its hash.
argus --list-plugins
```

`-d` prints which rule matched which port:

```
DEBUG: detect 10.0.0.1:9000 -> rule my-rule/json-service service=my-app product=My App version=2.1.0
```

Common failures:

| Message | Cause |
| --- | --- |
| `missing apiVersion, expected argus.plugin/v1` | The `apiVersion` line is absent or misspelled. |
| `unsupported apiVersion` | Written for a newer schema than this build knows. |
| `needs argus >= X` | `argus_min_version` is higher than the running build. |
| `sets unknown field "produkt"` | A typo in `set` or `fields`. |
| `has an invalid pattern` | The regex does not compile (RE2, no lookahead/backreference). |
| `defines no matches` | A rule with `matches:` missing or empty. |
| `declares a finding but the rule kind is "fingerprint"` | A `finding:` needs `kind: check`. |
| `has a finding without a title` | Every finding needs a `title`. |
| `has severity "catastrophic"` | Severity must be critical/high/medium/low/info. |
| `defines neither fingerprints nor hack_reasons` | Nothing to contribute. |
| `no usable plugin documents in <path>` | A pack where every file was skipped. |

## 8. What a plugin cannot do

These are deliberate limits, not gaps waiting to be filled. They follow from
one decision: **a plugin is data, never code**.

- **No state between probes.** Each probe opens its own connection. A rule
  cannot log in and then use that session for a second request, so
  authentication-then-check and challenge-response flows are out of reach.
- **No computation.** No arithmetic, no hashing, no loops, no conditionals.
  Anything that needs to compute a value from a response cannot be expressed.
- **No timing or concurrency logic.** No race conditions, no blind timing
  checks.
- **No file or network access beyond the scanned port.** A plugin cannot read
  files, call out to another host, or act as a proxy.
- **No conclusion that needs computation or state.** A `kind: check` rule can
  report a finding, but only one whose verdict is "the response contained this
  pattern". A conclusion that requires combining two responses, or computing a
  value from one, cannot be expressed.

Within those limits you can express a great deal: version and build
fingerprinting, default-configuration detection, unauthenticated-access
detection, information disclosure, and any single-request check whose verdict
is "did the response contain this pattern".

## 9. Complete example

See [`examples/example-plugin.yaml`](../examples/example-plugin.yaml) — a
working plugin with a fingerprint and a bilingual note, parsed by the test
suite on every build.
