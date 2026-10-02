# Argus

**A modern port scanner built for offensive security.**

Authors: **guaidao2 & coolmoon** · License: MIT · Single static binary · Cross-platform

Argus is a TCP/UDP port scanner written in Go. It ships as one static binary
with no runtime dependencies, produces nmap-style output (including
nmap-compatible XML that existing tooling can import), identifies services from
a YAML fingerprint database, and can be extended with YAML plugins that you
register once and reuse.

[中文文档](README.zh-CN.md)

---

## Why another scanner

- **One static binary.** `CGO_ENABLED=0`, no libpcap, no Npcap, no driver. Copy
  it to a jump host and run it.
- **nmap-compatible output.** `-oX` emits an `nmaprun` document with nmap's
  element and attribute names, so `msf db_import`, Faraday and most report
  pipelines can consume it unchanged. `-oJ` gives you structured output for
  `jq`.
- **Capability detection before the first packet.** A SYN scan opens the raw
  socket and proves it can both send *and* receive — against loopback, so
  nothing leaves the machine — before a single target is touched. Finding out
  mid-scan that replies never arrive would waste the part that already ran and
  hand you a confident, wrong result set.
- **The report states the technique.** TCP connect and SYN do not produce
  equivalent result sets: a connect scan completes a handshake, which the
  application can log and a stateful firewall may answer differently. Every
  report says which one ran, per host and per port, including when one scan
  used both.
- **Data-driven detection.** Service fingerprints live in YAML, not in Go code.
  The embedded database covers the services you meet first, and anything it
  misses is a plugin away.
- **Plugins you can trust to fail softly.** A registered plugin that has been
  deleted warns and drops out; it never takes your scan down with it.
- **`--findings`.** Opt-in checks that reach a conclusion rather than an
  identification — unauthenticated access, exposed administrative interfaces,
  default credentials — reported separately from the service description, in
  nmap's own `<script>` element for XML consumers.
- **`--hack-reason`.** Attach the reconnaissance angles that matter for each
  detected port, in English or Chinese, from a bilingual knowledge base.
- **Bilingual, English first.** Chinese requires `--lang zh`. Your interface
  language is never decided for you by `LANG`.
- **No telemetry.** Argus never phones home and never uploads results. Nothing
  in this repository opens a socket that is not the scan itself.

## Install

```bash
# From source (Go 1.24+)
go install github.com/guaidao2/argus/cmd/argus@latest

# Or build a static binary
make build

# Cross compile for every supported platform into ./dist
make cross
```

## Quick start

```bash
argus 10.0.0.1                             # the built-in common port table
argus -sV -p 22,80,443 10.0.0.0/24         # service and version detection
argus -sS -T4 -p- --open 10.0.0.5          # Linux SYN scan, fast, all ports
argus --top-ports 100 --hack-reason 10.0.0.1
argus -oA scan1 10.0.0.1 10.0.0.2          # scan1.nmap, scan1.xml, scan1.json
argus --lang zh -sV --hack-reason 10.0.0.1
```

Example output:

```
$ argus -Pn -sV --hack-reason --reason -p 22,80,443 192.0.2.10
Starting Argus 1.0.0 ( https://github.com/guaidao2/argus ) at 2025-04-01 09:12:44 UTC
Argus scan report for 192.0.2.10
Host is up (0.00231s latency).
Not shown: 1 closed tcp port (conn-refused)
PORT      STATE SERVICE REASON      VERSION
22/tcp    open  ssh     syn-ack     OpenSSH 8.9p1 (Ubuntu-3ubuntu0.4)
| hack-reason: SSH remote administration
| Enumerate the auth methods the server allows; password auth reopens credential attacks that key-only hosts do not have
| Look for reused or default credentials, and for keys without a passphrase in reachable home directories
| tools: ssh-audit, nxc, hydra, ssh-keygen
|_refs: https://attack.mitre.org/techniques/T1021/004/
80/tcp    open  http    syn-ack     nginx 1.24.0
| hack-reason: HTTP application
| ...

Argus done: 1 IP address (1 host up) scanned in 1.24 seconds
```

## What argus does and does not do

Being explicit about the edges matters more than a feature list.

| Area | Status |
| --- | --- |
| TCP connect scan | Default. No privileges, works through SOCKS5, identical on every platform. |
| TCP SYN scan | Linux only, implemented in pure Go over `AF_INET/SOCK_RAW`. Needs `root` or `CAP_NET_RAW`, and passes a loopback preflight before the scan starts. **Argus never silently falls back to connect** — you get an error, or an explicitly requested `--fallback-connect`. |
| UDP scan | Works without privileges on Linux: the connected socket surfaces the ICMP port-unreachable error, so `closed` is distinguishable from `open\|filtered`. On platforms that swallow that error, silent ports stay `open\|filtered`, which is what nmap reports there too. |
| Host discovery | TCP ping to 80/443/22. A RST proves the host is up just as well as a handshake. ICMP echo is deliberately not used: it needs raw privileges everywhere and is filtered more often than TCP. `-Pn` skips discovery. |
| OS detection | Not implemented. |
| Idle/zombie scan, FTP bounce, decoys | Not implemented, and not planned: they are rarely worth the complexity in practice. |
| IPv6 | Supported for connect and UDP scans. The SYN scanner is IPv4 only and says so. |
| nmap NSE scripts | Not compatible. Argus uses its own YAML probe schema; the model is closer to `nmap-service-probes`. |

The built-in port table follows the same published scan statistics as nmap's
default top-1000 sweep, and its service names are IANA registrations, so a
default `argus` run reaches the same ports a default `nmap` run does — verified
against `nmap-services`: 1000 of 1000, and `--top-ports 100` matches nmap's top
100 exactly. Past those 1000 ports the table keeps ports argus adds for
offensive-security work (OT protocols, container and queue APIs, database
ports).

Other deliberate differences from nmap: `-oG` (grepable) is not implemented; use
`-oJ`. The default retry count is lower than nmap's because nmap's values are
tuned around its own RTT estimation loop.

## Language

Argus is English-first. It will **not** switch to Chinese because your shell
exports `LANG=zh_CN.UTF-8` — a scanner whose output language depends on the
environment is a scanner whose output nobody can parse reliably.

Resolution order:

1. `--lang zh`
2. `ARGUS_LANG=zh`
3. `lang:` in `config.yaml` (see *State directory*)
4. English

`--list-langs` prints what is available. Machine-readable output (`-oX`, `-oJ`)
is language neutral by design: element names, attribute names and state values
stay English so parsers keep working.

## Output

| Flag | Format |
| --- | --- |
| `-oN/--output-normal FILE` | nmap-style human output. Always also written to stdout; use `-` for stdout only. |
| `-oX/--output-xml FILE` | nmap-compatible `nmaprun` XML (`xmloutputversion 1.05`). |
| `-oJ/--output-json FILE` | JSON. Add `--jsonl` for one host per line plus a summary line. |
| `-oA/--output-all BASE` | All three: `BASE.nmap`, `BASE.xml`, `BASE.json`. |

Progress and warnings always go to stderr, so `argus ... | jq` is safe.

Exit codes: `0` success, `1` runtime error, `2` usage error, `130` interrupted
(`Ctrl-C` still prints the partial results it has).

## Scan technique

```bash
argus -sT -p 80 10.0.0.1                  # connect (default)
argus -sS -p 80 10.0.0.1                  # SYN, Linux, needs CAP_NET_RAW
argus --scan-type auto -p 80 10.0.0.1      # let argus pick at startup
```

To run SYN scans without being root:

```bash
sudo setcap cap_net_raw+ep "$(command -v argus)"
```

### Capability detection runs before the scan

Opening the raw socket is not proof that a SYN scan will work. A container with
a restricted network namespace, a local firewall or an unusual BPF filter can
leave you with a socket that transmits happily and never receives, and that
would turn every scanned port into a false `filtered`. So argus preflights the
socket: three SYNs to loopback ports that are almost always closed, which must
come back as RST or SYN/ACK. Nothing leaves the machine to find out.

If the preflight fails you get an error naming the reason, not a scan that
looks plausible and is wrong. Finding this out halfway through would waste the
part that already ran.

### How the technique is chosen

| Situation | What runs |
| --- | --- |
| `-sS`, socket and preflight fine, routable IPv4 targets | SYN |
| `--scan-type auto`, socket and preflight fine | SYN |
| `--scan-type auto`, SYN unavailable | TCP connect, and the report says the technique was auto-selected and why |
| `-sS`, loopback or one of this machine's own addresses | TCP connect for those targets, and the report says so |
| `-sS`, IPv6 target | TCP connect for that target, and the report says so |
| `-sS` unavailable (no privileges, non-Linux, preflight fails) | an error, with the reason and a fix |
| `-sS` unavailable **and** `--fallback-connect` | TCP connect, warned on stderr and stated in the report |

`--scan-type auto` is for "use the best technique that works here, I do not
care which": argus probes at startup and picks. `--fallback-connect` is for "I
want SYN, but if you really cannot, carry on" — it only applies to an explicit
`-sS`.

Both are opt-in, and neither is the default, on purpose. A connect scan
completes a handshake and leaves application logs; a SYN scan does neither.
Swapping one for the other without being asked would be a nasty surprise in an
engagement where staying quiet is the whole point.

### The technique is part of the result

Because the two techniques are not interchangeable, the mode is written into
every output, and a scan that used both says so:

```
Starting Argus 1.0.0 ( https://github.com/guaidao2/argus ) at 2025-04-01 09:12:44 UTC
Scan technique: SYN scan (raw sockets, half open); loopback and local addresses are probed with TCP connect
```

`-oX` carries it as `scaninfo/@type` plus a per-host `technique` attribute
(non-standard, and ignored by parsers that do not know it); `-oJ` carries
`scan_type`, `requested_scan_type`, `technique_mixed` and a `technique` field on
every host and every port.

## Service and version detection

`-sV` runs YAML fingerprints: connect, send a probe, match the response with a
regular expression, extract named fields.

```bash
argus -sV -p 22,80,443,6379,3306 10.0.0.1
argus -sV -sU -p U:161,U:111 10.0.0.1     # datagram services
```

Built-in rules cover SSH, FTP, SMTP/POP3/IMAP, HTTP/HTTPS, MySQL/MariaDB,
PostgreSQL, MongoDB, Redis, Memcached, Elasticsearch, VNC, Telnet, RDP, RTSP,
X11 and a generic fallback. TLS-wrapped ports get a handshake: version, cipher,
ALPN and certificate details (subject, issuer, validity, SANs, self-signed and
expired flags) — shown with `-v`, always present in `-oX`/`-oJ`.

Datagram services are identified too, which they have to be: SNMP and ONC RPC
are UDP-first, and a service nobody can name is a service nobody checks. Rules
declare `proto: udp`, and a UDP port that was found open reaches the detector
just as a TCP one does.

```
161/udp open  snmp    SNMP agent (Linux 6.19.14+kali-amd64 #1 SMP ... x86_64)
111/tcp open  rpcbind ONC RPC portmapper
2049/tcp open nfs     NFS 3
```

SNMP is asked for `sysDescr.0` with the community `public`, which on a default
agent answers with the operating system and its version. ONC RPC is asked to
`DUMP` its registry — one call, the same one `rpcinfo -p` makes — which names
every service registered with the portmapper, including the ones on ports no
table can reach.

## Checks and findings

```bash
argus -sV --findings 10.0.0.1
```

`--findings` runs the `kind: check` rules: they request an administrative
endpoint, send a database command or try default credentials, and report what
they conclude, separately from what the port is.

```
6379/tcp open  redis   Redis 7.2.4
| check: Redis: unauthenticated access [HIGH]
| The server answered INFO without credentials, so any client that can reach the port can read its configuration and keys.
|_refs: https://redis.io/docs/latest/operate/oss_and_stack/management/security/
```

It is **off by default** on purpose. A check probe is recognisable as an
intrusion on the wire, so argus will not send one just because you asked for
service detection. Findings travel in `-oX` as nmap `<script>` elements (which
Metasploit's `db_import` and Faraday already understand) and in `-oJ` as
`findings[]`, and they are counted in `summary.findings`.

A check reports every match that hits, not only the first, because one answer
can carry several independent facts: a single RPC `DUMP` reply names every
service registered with the portmapper, and each becomes its own finding.

Built-in checks cover unauthenticated access to Redis, Elasticsearch, MongoDB,
Memcached, CouchDB, the Docker daemon API, the Kubelet API and the Kubernetes
API server; RabbitMQ's default management credentials; anonymous FTP; SNMP
answering the default `public` and `private` community strings; the RPC
services registered with the portmapper (NFS, mountd, NIS, the lock manager and
the rest, each with what to do about it); two SMB hardening findings (SMBv1
still enabled, signing not required); and three
version-following checks (OpenSSH in the CVE-2024-6387 range, vsftpd 2.3.4,
ProFTPD 1.3.5).

Version-following checks compare the version from a banner against a range, so
they need no protocol state — just one probe:

```yaml
matches:
  - id: affected
    fields: {version: '(?i)vsftpd[ /]([0-9][^\s]*)'}
    affected: {range: "==2.3.4"}
    finding: {title: "vsftpd 2.3.4 backdoor", severity: high}
```

They are worded, and severitied, as a version **match** rather than a
confirmation: distributions backport fixes without changing the version string.

`affected` also takes a **list**, and every condition in it must hold — which is
how an intersection is written, such as "an SMBv1 response *and* a Windows
kernel version in the affected family". Several signals can come out of one
probe when the protocol answers each message independently: the SMB rules
pipeline NEGOTIATE and SESSION SETUP into a single write, so one read returns
the dialect (protocol version) and the `NativeOS` string (operating system
version). Against a real Samba host that reports `Windows 6.1`:

```
445/tcp open  microsoft-ds SMB (Samba 4.24.3-Debian-4.24.3+dfsg-1; 6.1)
| check: SMB: SMBv1 with a Windows version in the MS17-010 family [MEDIUM]
| The host answered SMBv1 and reported a Windows kernel version between 5.0
| and 6.1 ... This is an intersection of two observations, not a confirmation:
| patching does not change the kernel version, so a fully patched host looks
| identical. Use nmap's smb-vuln-ms17-010 or Metasploit to confirm.
```

The SMB findings are deliberately worded as hardening, not as proof of
MS17-010: patching MS17-010 does **not** disable SMBv1, so a fully patched host
answers the SMBv1 negotiate exactly the same way. Confirming MS17-010 itself
needs a stateful four-step SMB exchange, which a declarative probe cannot
express — use nmap's `smb-vuln-ms17-010` or Metasploit for that. Writing your own is
documented in [docs/plugin-guide.md](docs/plugin-guide.md#5-checks-and-findings).

A finding is a pattern match, not a proof: verify before it goes into a report.
Every built-in check matches on content that only appears in a successful
response, never on the status code alone.

## Plugins

A plugin is a YAML document. Argus never executes plugin code — the worst a
malicious plugin can do is feed you wrong fingerprints.

The full schema, every field, the matching rules, a debugging guide and the
current limits are documented in **[docs/plugin-guide.md](docs/plugin-guide.md)**
(every example in it is parsed by the test suite).

```yaml
apiVersion: argus.plugin/v1
name: my-fingerprints
version: 1.0.0
author: you
license: MIT
argus_min_version: 0.1.0
description: extra service fingerprints

fingerprints:
  apiVersion: argus.fingerprint/v1
  id: my-fingerprints
  rules:
    - id: my-app
      ports: [9000]
      probes:
        - id: get
          send: "GET /status HTTP/1.0\r\nHost: {{host}}\r\n\r\n"
          read_timeout: 3s
      matches:
        - id: my-app-server
          pattern: '(?im)^Server:\s*(?P<product>[\w.-]+)/(?P<version>[\w.-]+)'
          set: {service: http}

hack_reasons:
  apiVersion: argus.hackreason/v1
  id: my-notes
  entries:
    - id: my-app-note
      ports: [9000]
      service: http
      any_port: true
      title:
        en: "My application"
        zh: "我的应用"
      points:
        en: ["Check the admin endpoint on /admin"]
        zh: ["检查 /admin 管理端点"]
      tools: [curl]
      refs: ["https://example.invalid/docs"]
```

Register it once; argus remembers where it lives:

```bash
argus --register-plugin ./my-fingerprints.yaml
argus --list-plugins
argus --unregister-plugin my-fingerprints
argus --unregister-all
```

Registry semantics:

- The path is resolved to an absolute path (symlinks included) and its SHA-256
  is recorded at registration time.
- Registering the same name again **updates** the record: the new path wins.
- If the file is deleted later, argus warns, continues without that plugin and
  **keeps the exit code unchanged**. Repair it by registering a new path, or
  make it fatal with `--strict-plugins`.
- If the content changed after registration, argus warns and loads it anyway
  (`--strict-plugins` refuses instead).
- Plugin rules take precedence over the built-in database, so your fingerprint
  actually gets a chance to match. Overriding a built-in rule id is reported.
- `--plugin-dir PATH` loads plugins for one run and ignores the registry;
  `--no-plugins` disables plugin loading entirely.
- The registry file is written atomically (temp file + rename), so an
  interrupted write cannot corrupt it.

### Plugin matching rules for hack-reason notes

- `ports: [...]` — applies to those ports only.
- `service: X` and no `ports` — applies wherever service X runs.
- `service: X` plus `any_port: true` — applies to X on any port, which is what
  an HTTP server on 41395 needs.

## `--hack-reason`

`--hack-reason` annotates every open port with the reconnaissance angles worth
checking, drawn from a bilingual YAML knowledge base. It is **off by default**
and only ever runs when you ask for it.

Scope, on purpose: these are checklists with tool names and references, not
exploit payloads. That keeps the tool useful in an authorised engagement and
keeps the project distributable. Everything is data; add or replace entries
with a plugin.

## State directory

The registry and optional config file live in the platform's conventional
location:

| Platform | Path |
| --- | --- |
| Linux | `$XDG_CONFIG_HOME/argus` or `~/.config/argus` |
| macOS | `~/Library/Application Support/argus` |
| Windows | `%AppData%\argus` |

Override with `ARGUS_CONFIG_DIR` (handy for a portable copy on a USB stick).
`config.yaml` currently supports one key:

```yaml
lang: zh
```

## Proxy

```bash
argus --proxy socks5://127.0.0.1:1080 -sV -p 445 10.10.10.20
```

SOCKS5 is used for TCP connect probes, which is what pivoting through a
compromised host requires. SYN and UDP probes always go direct, and argus says
so rather than silently ignoring the flag.

## Legal

Only scan systems you own or have explicit written authorization to test.
Unauthorized port scanning is illegal in many jurisdictions. Argus is provided
under the MIT license, without warranty of any kind.

## Development

```bash
make            # fmt, vet, test, build
make test-race
make cover
make cross      # static binaries for linux/darwin/windows
```

Layout:

```
cmd/argus              entry point
internal/cli           flag parsing, orchestration, plugin commands
internal/scan          engine: connect, Linux SYN, UDP, discovery, timing
internal/detect        service detection: probes, TLS, YAML fingerprints
internal/hackreason    bilingual offensive-security knowledge base
internal/plugins       plugin registry and document validation
internal/report        normal, nmap-compatible XML, JSON renderers
internal/ports         port specifications and the built-in service table
internal/targets       target specifications (addresses, CIDR, ranges, names)
internal/i18n          message catalogs and language resolution
internal/model         result types shared across the pipeline
```

`make check-fmt` and `go vet ./...` are expected to be clean. The plugin guide
lives in `docs/` and its copy-pasteable examples are extracted and validated by
`internal/plugins/document_test.go`, so documentation cannot drift from the
schema.

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2025 guaidao2 & coolmoon.
