# 🛡️ netmon.py — Cybersecurity Network Monitor

[![License: Unlicense](https://img.shields.io/badge/license-Unlicense-blue.svg)](https://unlicense.org/)
[![Version](https://img.shields.io/badge/version-1.4.0-brightgreen.svg)](#-version-history)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)

I used to rely heavily on `netstat` for a quick pulse on what my machines were doing. But modern operating systems run so many background processes that filtering through the noise has become a real headache.

**netmon.py** is a clear, actionable look at your system's network activity — a context-rich upgrade to `netstat` that does the heavy lifting for you.

*(Note: the foundational code was prototyped with AI assistance and the v1.1 hardening pass was done with [Claude](https://www.anthropic.com/claude) acting as a security engineer.)*

---

## ✨ Features

* **Real-time process mapping** — every TCP/UDP connection linked to its PID, name, full executable path, user, and SHA-256 hash.
* **Authenticode signature verification** (Windows) — every running executable is checked via batched `Get-AuthenticodeSignature`. Binaries from a known-good publisher (Microsoft, Mozilla, Google, Anthropic, NVIDIA, Apple, Adobe, ASUS, Epic, Ollama, Python, GitHub, JetBrains, …) are flagged `trusted`.
* **Multi-signal risk scoring** — `path × signature × port × geo × VT × beacon × C2-fingerprint`. A signed Anthropic binary in `%AppData%` is fine; an unsigned binary in `%AppData%\Temp` talking to a Tor exit on port 1337 is HIGH. **Any unsigned executable with an ESTABLISHED connection to a public IP is automatically HIGH** (the `UNSIGNED_OUTBOUND_C2` flag — added in v1.2 after a real C2 binary slipped through v1.1).
* **Optional packet capture (`--capture`)** — wraps Windows `pktmon` or Linux `tcpdump` (both ship with the OS — no extra install). The capture is parsed in-process by a pure-Python pcap/pcap-ng reader (no `scapy`/`tshark` required) and yields:
  * DNS queries (which domains were resolved)
  * TLS **SNI hostnames** — the *real* destination of HTTPS traffic, even when the IP alone is opaque
  * Plaintext HTTP requests / responses (method, host, path, status)
  * Per-packet hex+ASCII previews (first 200 bytes of every TCP payload)
* **Port-agnostic protocol detection** — TLS and HTTP are recognized by their byte signature (`0x16 0x03` for TLS Client Hello, method/`HTTP/` prefix for HTTP), so traffic on non-standard ports (8080, 6822, dev servers, etc.) is parsed correctly instead of being lumped into raw TCP.
* **Multi-layer-capture dedup** — pktmon captures every packet at up to 9 stack components (NDIS / WFP / TCP/IP / ALE); identical events within 100 ms are collapsed into one record so the DNS log shows real query counts, not pktmon artifacts. Genuine resolver retries (>100 ms apart) are preserved.
* **DNS heuristics** — when `--capture` is on, every captured query is run through 4 detectors: DGA-like names (Shannon entropy + vowel ratio), suspicious TLDs (`.tk .xyz .top .click ...`), invalid label characters (semicolons, homoglyphs), and high-retry NXDOMAIN bursts (resolver beacon signal). Findings appear in their own HTML section AND elevate the risk of the connection that issued them.
* **Save full capture (`--save-capture PATH`)** — writes the raw pcap to your chosen path (open it in Wireshark for full inspection) AND embeds a browsable packet log in the HTML report. The HTML now ships with a **"Load packets" button**: when a process row is selected, clicking the button renders an inline hex+ASCII view of every captured payload for that process (xxd-style, with timestamp / direction / protocol-guess badge — `TLS-CH`, `HTTP-REQ`, `SSH`, `RAW`, etc.). No need to fire up Wireshark for routine triage. Disk-usage warning + explicit `yes` confirmation required (or pass `--yes` for non-interactive).
* **Tor exit-node detection** (opt-in via `--scan-tor`) — pulls the public Tor exit list (no auth, no key, daily refresh, size-capped) and flags any remote IP that matches. Off by default in v1.2 because many ISPs SNI-filter `torproject.org`, which produced a confusing warning on every run.
* **Beacon detection** — flags processes that open many distinct local sockets to the same remote at low-jitter intervals, a classic C2 pattern.
* **Self-contained HTML5 report (`--html`)** — single file, embedded CSS/JS, dark theme, color-coded risk pills, sortable columns, search box. Features:
  * **Sticky section nav** — a TOC at the top of every report links to each section (Connections / Capture / DNS / Logs / Persistence / Web shells) with **finding-count badges** that go **red** when any HIGH-severity entry exists. Click a link → smooth-scroll directly to the section. No more "scroll past 100 rows to reach Logs".
  * **Row-number column** that renumbers visible rows on every filter / sort change, plus a persistent **"Showing X of Y" counter pill** that turns amber when a filter is active. An accidentally-active filter is impossible to miss.
  * **Pkts column** — when packet capture data exists, every connection row shows captured-payload count + bytes (e.g. `12 · 17.6 KB`). Hover the process name to see traffic availability **before** clicking the row to drill down.
  * **Status filter row** — `All / Established / Listening / TIME_WAIT / CLOSE_WAIT / SYN_SENT / FIN_WAIT / Other`. Default view shows ESTABLISHED only (the most useful triage subset; passive listener noise hidden).
  * **Clickable stat tiles** — "Unsigned binaries", "Tor exits", "External peers", "Exposed: any iface", "Exposed: LAN", "VT malicious", "Unique processes" all filter the table when clicked.
  * **Per-process drill-down** — every process name is rendered as a clickable link (`proc-link`). Click it to filter the DNS / TLS / HTTP / TCP-flow / packet logs to that process's local ports, and (if data exists) auto-scroll to the packet log. Click again or "Clear" to deselect.
  * **Filters compose intelligently** — clicking a risk button or stat tile resets the status filter so you never miss a HIGH-risk LISTEN row because the default is "ESTABLISHED only". When any explicit filter is active, the noisy-Microsoft hide is auto-released.
  * **Three hide-by-default toggles** — *Show Microsoft & system processes* (Windows-only), *Show netmon-generated events* (connections owned by netmon's own process tree), and *Show events generated by netmon.py* (log entries from netmon's PowerShell child calls). Each toggle's label includes the count being hidden.
  * **Section-level finding-count badges** in every collapsible — `Persistence mechanisms [2 recent]`, `Web shells [3 hits]`, `Event logs [9 HIGH]` — so you see the bottom line without expanding anything.
  * **Empty-state callouts** when a section has zero findings (e.g. "Persistence: not enumerated — pass `--persistence`") instead of the section silently disappearing.
  * **Floating back-to-top button** after 400px scroll.
  * **VirusTotal hash links** — every SHA-256 is clickable, opening `virustotal.com/gui/file/<hash>` in a new tab (no account required).
* **Listener exposure highlighting** — rows for sockets bound to `0.0.0.0` / `[::]` (reachable from any host that can reach yours — internet-facing on a public-IP machine) glow **red**; rows bound to a specific LAN interface (reachable from the local subnet) glow **amber**; loopback-only listeners stay neutral. Two dedicated stat tiles count each tier and filter the table to that exposure level when clicked. The Remote cell text replaces the bare "(listening)" with a description like "exposed on ANY IPv4 interface" or "loopback only (this host)".
* **Optional VirusTotal integration (`--vt-api-key`)** — annotates each row with detection counts and feeds the result into the risk score.
* **Geo / ASN enrichment** over **HTTPS** via `ipwho.is`, with an `ipwhois` RDAP fallback.
* **CSV export** — full untruncated schema for downstream analysis.
* **Smart noise suppression** — designed so the operator's first view shows host activity, not the monitor's footprint:
  * PowerShell ScriptBlock events (EID 4104) from netmon's own child cmdlets (`Get-AuthenticodeSignature`, `Get-ScheduledTask`, `Get-WinEvent`, etc.) are tagged `severity=SELF` and hidden by default. Toggle reveals them. Cuts log noise from ~1800 entries/3 min to ~10 on a typical Windows desktop.
  * Security log 4624 / 4672 events are classified by **subject SID** and **Logon Type**: `4672` for SYSTEM/LocalService/NetworkService (every service start) → LOW `SPECIAL_PRIV_SYSTEM`; `4672` for a real user → MED `SPECIAL_PRIV`. `4624` Logon Type 5 (service) → LOW; Type 10 (RDP) → MED; Type 3 (network) → context-dependent.
  * PowerShell profile compile events get the `PS_PROFILE_LOAD` kind so analysts immediately recognize "the profile compiled on session start" vs arbitrary script activity. Offensive-pattern detection still runs first — a malicious profile body still fires HIGH.
  * Connections owned by netmon's own process tree (the running `python.exe` plus `pktmon` / `tcpdump` / PowerShell sig-verifier children) are tagged and hidden by default in the HTML connection table.
* **NXDOMAIN-aware DNS retry detection** — `FlowAnalyzer` tracks per-name DNS response codes. A name queried 20+ times where ≥50% of responses are NXDOMAIN fires `DNS_HIGH_RETRY_NXDOMAIN_<count>` at HIGH severity (classic beacon-DGA pattern). A name queried 20+ times with mostly NOERROR responses (legitimate short-TTL CDN re-resolution) stays at plain `DNS_HIGH_RETRY` — LOW, informational.
* **PowerShell profile enumeration** — `--persistence` now lists every `profile.ps1` / `Microsoft.PowerShell_profile.ps1` on the host (Windows PS 5.1 + PS 7 paths; POSIX PS 7 paths on Linux/macOS) as persistence artifacts. Anything in a profile auto-runs on every PowerShell launch — a textbook persistence channel.
* **Production-hardened** — input validation everywhere, bounds-checked binary parsers, capped resource use, structured logging, proper exit codes, signal handling. See [Security model](#-security-model) below.

---

## ⚙️ Installation

You'll need **Python 3.9+** and admin/root privileges (`sudo` or *Run as Administrator*) to inspect system-level processes, run packet capture, or check Authenticode signatures of protected binaries.

### Quick install (any OS)

```bash
git clone https://github.com/Ozear/netmon.py.git
cd netmon.py
pip install psutil requests rich ipwhois
```

That's it — three files (`netmon.py`, `README.md`, `LICENSE`) and four dependencies. Nothing else to set up.

### Windows specifics

1. Install Python 3.9+ from the official installer — check **"Add Python to PATH"**.
2. Open Command Prompt or PowerShell **as Administrator**.
3. `pip install psutil requests rich ipwhois`

### Linux specifics (PEP 668)

Modern Linux distros block `pip install` outside a virtualenv. Pick one:

```bash
# Recommended: virtualenv
python3 -m venv .venv
source .venv/bin/activate
pip install psutil requests rich ipwhois

# Alternative (use with care): override PEP 668
sudo pip install psutil requests rich ipwhois --break-system-packages
```

`sudo` resets the environment, so when running with elevated privileges in a venv, point at the venv's Python explicitly:

```bash
sudo ./.venv/bin/python netmon.py -t 30 --html report.html
```

---

## 🚀 Usage

```bash
# 🎯 Easiest — QUICK triage in ONE flag (recommended first run). Safe on a
# possibly-compromised host: uses ONE trusted intel host (abuse.ch C2 feed) +
# GeoIP, but NO Tor fetch and NO VirusTotal API calls (SHA-256s still render as
# click-through VT links). Add --offline for zero external calls.
# Equivalent to: -t 60 --capture --persistence --hash-tasks --scan-webroots --logs 3 --threat-intel
python netmon.py --tr            # alias: --quick-triage

# DEEP triage on a TRUSTED analysis host — adds Tor-exit detection, the
# abuse.ch Feodo C2 IP feed, and VirusTotal (when $VT_API_KEY is set):
python netmon.py --dtr           # alias: --deep-triage

# Same, but stretch the capture / log window (better for slow beacons):
python netmon.py --tr -t 240 --logs 10

# Quick monitor (15-second snapshot + HTML dashboard, no capture / no logs)
python netmon.py -t 30 --html report.html

# Full power (admin/root): packet capture + VT enrichment + verbose logging
python netmon.py -t 60 --capture --html report.html -vv

# Air-gapped / privacy mode — no third-party network calls at all
python netmon.py --offline --html report.html
```

> **Tip:** `--tr` (`--quick-triage`) is the shortest **safe** way to get a complete *local* report — it makes no Tor / threat-intel / VirusTotal-API calls, so it's appropriate even on a possibly-compromised host. On a **trusted** analysis box, `--dtr` (`--deep-triage`) additionally arms Tor-exit detection, the abuse.ch C2 feed, and VirusTotal (with `$VT_API_KEY`). **Any explicit flag you also pass wins** — e.g. `--tr -t 240 --scan-tor`.

### Command-line options

| Flag | Default | What it does |
|---|---|---|
| **`--quick-triage`** / **`--tr`** | *(off)* | **🎯 One-flag QUICK triage — safe on a possibly-compromised host.** Activates `-t 60`, `--capture`, `--yes`, `--persistence`, `--hash-tasks`, `--scan-webroots`, `--logs 3`, `--threat-intel`, plus a live progress display. Uses **one** trusted intel host (the abuse.ch Feodo C2 feed) + GeoIP; makes **no** Tor fetch and **no** VirusTotal API calls (SHA-256s still link to VirusTotal). `--offline` removes all external calls. `--full-triage` is a kept-for-compat alias. Recommended starting point for any host triage. |
| **`--deep-triage`** / **`--dtr`** | *(off)* | **One-flag DEEP triage — for a TRUSTED analysis host.** Everything `--quick-triage` does, plus a longer window (`-t 120`) and all external intel: `--scan-tor`, the abuse.ch Feodo C2 IP feed (`--threat-intel`), and VirusTotal when `$VT_API_KEY` is set. |
| `--threat-intel` | *(off)* | Fetch + use a free, open, no-auth botnet-C2 IP blocklist (abuse.ch Feodo Tracker — a single trusted host) → flags `C2_FEED_MATCH` (HIGH). Auto-enabled by `--deep-triage`. Honors `--offline`. |
| `-t`, `--time` | `15` | Monitoring duration in seconds (1 – 86400). |
| `--html [PATH]` | **on** | Self-contained HTML report. ON by default — writes `./reports/netmon-<TS>.html` (timestamped, never overwrites prior runs). Pass an explicit path to override or `--no-html` to disable. |
| `--text [PATH]` | **on** | Plain-text report (cat / grep / less friendly fixed-width columns). ON by default — writes `./reports/netmon-<TS>.txt`. Disable with `--no-text`. |
| `-o`, `--output`, `--csv [PATH]` | *(off)* | CSV machine-readable export. **Opt-in**. Pass `--csv` (no value) for an auto-named file in `./reports/`, or `-o foo.csv` for an explicit path. |
| `--json [PATH]` | *(off)* | JSON output — single object with the full schema (connections, persistence, logs, web-shell findings, flow summary, DNS findings). SIEM-friendly. PATH optional. |
| `--ndjson [PATH]` | *(off)* | Newline-delimited JSON — one JSON object per line. Streams cleanly into Splunk HEC, ELK, etc. |
| `--no-html` / `--no-text` | *(off)* | Disable the corresponding report (each is on by default). |
| `--capture` | *(off)* | Capture packets via `pktmon` / `tcpdump`. **Saves the pcap by default** to `./reports/netmon-<TS>.pcap` so the HTML's "Load packets" feature works. Requires admin/root. |
| `--capture-fly` | *(off)* | Capture packets but **don't save** the pcap — ephemeral capture used purely for in-memory flow analysis. Smaller footprint when you don't need to drill into bytes later. |
| `--save-capture [PATH]` | *(off)* | Explicitly choose a pcap path (overrides the `--capture` default location). Implies `--capture`. Prompts for confirmation (disk-usage warning) unless `--yes`. |
| `--yes` | *(off)* | Auto-confirm prompts (e.g. for `--save-capture`). For non-interactive / scripted use. `--tr` sets this automatically. |
| **`--persistence`** | *(off)* | Enumerate host persistence mechanisms: cron, systemd unit files, registry Run keys, Windows scheduled tasks + services, macOS launchd, SSH `authorized_keys`, **PowerShell profiles** (Windows + POSIX PS 7). Recently-modified entries are flagged as IoCs. |
| **`--hash-tasks`** | *(off)* | For every persistence entry, extract its binary path, compute SHA-256, and (when `--vt-api-key` is set) look it up in VirusTotal. The HTML hash becomes a click-through to `virustotal.com/gui/file/<hash>` so analysts can triage in one click. Implies `--persistence`. |
| **`--scan-webroots`** | *(off)* | Walk webroot directories (`/var/www`, `/srv/http`, `C:\inetpub\wwwroot`, `htdocs`, etc.) and flag files matching web-shell signatures (Weevely, China Chopper, eval/base64 patterns). |
| `--webroots PATHS` | *(auto)* | Override the default webroot list with comma-separated paths. Use when your stack puts content somewhere non-standard. |
| **`--logs MINUTES`** | *(off)* | Tail the last N minutes of host event logs. Linux: `/var/log/{auth,syslog,apache,nginx,mysql,audit,fail2ban,crowdsec}`. Windows: Security / System / PowerShell Operational / Defender event logs (read in parallel). PII (passwords, tokens, JWTs, certs, emails) is scrubbed before rendering. Includes brute-force-then-success correlation. |
| `--diff OLD.json NEW.json` | *(off)* | **No live monitor.** Diff two prior `--json` outputs and produce an HTML showing new / gone flows + risk transitions. Great for "what changed since last run?" |
| `--vt-api-key` | `$VT_API_KEY` | VirusTotal API key. **Prefer the env var** — passing on the CLI exposes the key in process listings (`ps`, Task Manager). |
| `--offline` | *(off)* | Skip GeoIP / threat-intel network calls. |
| `--scan-tor` | *(off)* | Fetch the Tor exit-list and flag connections to Tor exits. Opt-in because many ISPs SNI-filter `torproject.org`. |
| `--no-signing` | *(off)* | Skip Authenticode signature verification. |
| `--no-crowdsec` | *(off)* | Skip CrowdSec local-LAPI integration (Linux only — auto-detected from `/etc/crowdsec/local_api_credentials.yaml`). |
| `--no-firewall` | *(off)* | Skip the firewall-state snapshot (ufw / nftables / iptables / Windows Firewall profile). |
| `-v`, `-vv` |  | Increase logging verbosity (info / debug). |
| `--version` |  | Print version and exit. |
| `-h`, `--help` |  | Show help. |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Generic failure |
| `64` | CLI usage error |
| `77` | Missing privileges for a requested capability |
| `130` | Interrupted by SIGINT (Ctrl+C) |

---

## 🦠 VirusTotal: free, but registration required

VirusTotal does **not** offer a true anonymous API endpoint — even the free tier requires a (free) account at <https://www.virustotal.com> to obtain a key. netmon.py handles this two ways:

* **Without a key** — the HTML report makes every SHA-256 a clickable link to `virustotal.com/gui/file/<hash>`, which works without an account. One-click triage.
* **With `--vt-api-key`** — netmon.py queries the file-hash endpoint for every unique binary, caches results, and integrates `vt_malicious` / `vt_suspicious` counts into the CSV, the HTML, and the risk score (`VT_MALICIOUS_*` flags). The free tier permits 4 lookups/min and 500/day — adequate for typical triage.

```bash
# Recommended — env var, won't leak via process listing
$env:VT_API_KEY = "your-key-here"     # PowerShell
export VT_API_KEY=your-key-here       # bash
python netmon.py --html report.html
```

---

## 📊 Output

By default a single run produces **two** files plus a terminal display:

* **Terminal table** — color-coded risk pills, signing status, **local IP:port**, remote address, geo / org, flags. Local-only and loopback destinations are clearly labeled (`loopback (this host)`, `private LAN (192.168.0.0/16)`, etc.) instead of empty GeoIP fields.
* **HTML report** (default ON, `--no-html` to disable) — dashboard with stat tiles, sortable/filterable table, packet-capture summary, dedicated columns for `Local` and `Remote`, hash links to VirusTotal.
* **Plain-text report** (default ON, `--no-text` to disable) — fixed-width-column ASCII designed for `cat report.txt` on Linux and Notepad on Windows. Greppable, awkable, sortable. Same data as HTML, no formatting.
* **CSV export** (`--csv`, opt-in) — full machine-readable schema: `timestamp, pid, app, user, path, hash, local, remote, status, country, country_code, org, asn, hostname, is_tor, signature_status, signature_publisher, signature_trusted, vt_malicious, vt_suspicious, risk, flags`.

### Output organization

All artifacts from a single run land in `./reports/` (auto-created with mode 0700 on POSIX), each timestamped so reruns never overwrite:

```
reports/
  netmon-20260502-154533.html          # default
  netmon-20260502-154533.txt           # default
  netmon-20260502-154533.csv           # only if --csv
  netmon-20260502-154533.pcap          # only if --save-capture
  netmon-20260502-160102.html          # next run — old reports preserved
  netmon-20260502-160102.txt
```

Every artifact from one run shares the same `<TS>` basename so the HTML report links to *its own* pcap, never a stale one. If `./reports/` isn't writable (read-only deploy), netmon.py falls back to `<system-tempdir>/netmon-reports/` and warns. Pass an explicit path to any flag to override.

### Why the local IP:port matters

Triage starts with "which process did this and from which interface?" netmon.py now shows the **local** end of every connection in every output (terminal, HTML, text, CSV). Combined with the process name, PID, and signature, you can answer:

* "Is this connection coming from my real LAN interface, my VirtualBox host-only adapter, or a wildcard listener?"
* "Why is this socket talking to itself? (loopback IPC between two of my own processes)"
* "Is something binding to `0.0.0.0:445` that shouldn't be?"

Loopback / private-LAN / link-local destinations skip the third-party GeoIP lookup entirely and instead show a descriptive label, so you'll never see an empty Geo column for an IP that physically can't be geolocated.

---

## 🔒 Security model

v1.1+ was put through a static analysis pass (SAST) — every input boundary has been hardened against the kinds of attacks that matter for a *security tool* (one nobody wants to silently fail when looking at a compromised host). v1.2 extended the same discipline to the new HTTP request/response parser (size-capped headers, ASCII-only field extraction, CRLF stripping) and to the embedded packet-preview JSON island (`</` escaped to `<\/` so a captured payload can't break out of the `<script>` tag).

* **Pcap / pcap-ng parser** treats input as hostile binary data. Every length field is bounded; oversized records, malformed magic, truncated streams, infinite-loop pointer chains, and 4 GB allocation tricks are rejected before allocation.
* **HTML output** has every interpolated value escaped (`html.escape`); SHA-256 hashes are validated as `[0-9a-f]{64}` before becoming clickable links; URLs are `urllib.parse.quote`d; `target="_blank"` links carry `rel="noopener noreferrer"`.
* **PowerShell stdin** path validation: paths containing `\n`, `\r`, `|`, or NUL are rejected before being piped to `Get-AuthenticodeSignature` — defends against newline-injection in attacker-controlled filenames.
* **Tor exit list** is fetched with `stream=True` + 8 MB cap + per-line `inet_pton` validation, so a poisoned upstream can't DoS the cache.
* **GeoIP** uses `https://ipwho.is` (HTTPS, no key) instead of cleartext `http://ip-api.com`.
* **VT API key** is encouraged via `$VT_API_KEY` env var; CLI usage triggers a warning about process-listing exposure.
* **File hashing** is TOCTOU-safe: open then `os.fstat`, refuse non-regular files, 2 GB sanity cap.
* **Cache directory** is per-user with mode `0700` so other local users can't seed it on a multi-tenant host.
* **Resource caps**: `MAX_PCAP_BYTES=256MB`, `MAX_PACKET_SIZE=65535`, `MAX_CONN_HISTORY=50K`, `MAX_FIRST_SEEN=250K`. Long runs on noisy hosts no longer leak memory.
* **Quality gates** (run during development, not shipped): `ruff`, `bandit`, and `pytest` (**267 tests** as of v1.3) pass with zero findings on a clean checkout. Tests cover risk-model regressions (System32 lsass, unsigned-C2 detection, IPv6 parsing, direction-aware risk, web-shell-spawn, …), pcap parser fuzz/hostile-input, HTML XSS resistance, JSON-data-island script-closer escaping, CLI parsing, port-agnostic protocol detection, multi-layer dedup, the JS-newline-bug regression, JA3 fingerprint extraction, log-reader PII scrubbing, persistence-scanner shape, the NXDOMAIN-aware DNS-retry classifier, the SID/Logon-Type-aware Security-event classifier, the PowerShell-ScriptBlock noise filter, the netmon-self auto-hide row classes, and the HTML UX features (TOC nav, row numbering, X-of-Y counter, Pkts column, empty-state callouts).

---

## 🛡 Antivirus / EDR false-positive notice

> **For IT teams, AV analysts, and auditors:** netmon.py is a defensive
> security / threat-hunting tool. The source is single-file Python with no
> obfuscation, no encoded blobs, and no compiled extensions — every line is
> auditable.

If a real-time AV or EDR product flags `netmon.py` (or a release artifact),
the cause is almost always one of the following. **Each item is detection
content, not malicious behavior.**

1. **Defensive-detection regex patterns in source.** The `WEBSHELL_SIGNATURES`,
   `SUSPICIOUS_CMDLINE_PATTERNS`, and `WEBSHELL_SCAN_EXTENSIONS` tables contain
   regex patterns describing PHP/ASP/JSP web shells, reverse-shell command
   lines, encoded PowerShell loaders, certutil/bitsadmin dropper invocations,
   and similar IoCs. Signature engines that pattern-match on tokens like
   `eval\s*\(\s*base64_decode\s*\(` or `bash -i >& /dev/tcp/` may flag the
   file the same way they flag YARA-rules repos or ClamAV signature files.
   These are **the patterns netmon.py looks FOR in third-party content** —
   they never describe what netmon.py itself does.

2. **String literals naming offensive tools.** Comments, dict labels, and
   risk-flag identifiers reference *"Cobalt Strike"*, *"Sliver"*,
   *"Meterpreter"*, *"Empire"*, *"Metasploit"*, *"Mimikatz"*, *"Weevely"*,
   *"China Chopper"*, *"Tor"*, *"4444"*, *"1337"*, *"31337"*, *"6667"*, etc.
   These exist for **documentation and risk-flag labelling** so analysts
   reading the report understand what was detected. ML / heuristic engines
   that score files by suspicious-string density may flag this.

3. **Suspicious-port / suspicious-path lookup tables.** `SUSPICIOUS_PORTS`
   maps Metasploit's default reverse-shell port (4444), backdoor leetspeak
   ports (1337, 31337), IRC C2 (6667), Tor relay (9001), etc. to human
   labels. `HIGH_RISK_PATH_FRAGMENTS` includes `\AppData\Local\Temp\`,
   `\Users\Public\`, `/tmp/`, `/dev/shm/`, `/var/tmp/`. These exist so
   netmon.py can **flag third-party processes binding those ports / running
   from those paths**. Static analyzers may match them as if they were
   payload destinations.

4. **Broad host-reconnaissance behaviour at runtime.** netmon.py enumerates
   live sockets, processes, file hashes, command lines, parent PIDs,
   systemd cgroups, Windows registry Run keys, scheduled tasks, services,
   cron jobs, SSH `authorized_keys`, web-server logs, and Windows event
   logs. Each operation is legitimate sysadmin work; combined they
   superficially resemble post-compromise reconnaissance. Behaviour-based
   EDR may score the pattern as suspicious.

5. **PowerShell subprocess invocation (Windows).** Authenticode signature
   verification, `Get-ScheduledTask`, `Get-NetFirewallProfile`, and
   `Get-WinEvent` are all called via `powershell -NoProfile -NonInteractive
   -Command …`. ML engines that score on "Python interpreter spawning
   `powershell.exe`" may flag this pattern even though every command is
   read-only and listed in the source.

### What netmon.py does **not** do

Concise list to hand to a vendor / IR team / auditor:

- **No code execution** beyond `subprocess.run(…)` calls to documented OS
  binaries: `pktmon`, `tcpdump`, `dpkg`, `rpm`, `pacman`, `apk`, `codesign`,
  `spctl`, `powershell`, `systemctl`, `reg query`, `ufw`, `nft`,
  `iptables-save`, `schtasks`/`Get-ScheduledTask`, `Get-WinEvent`, `log show`
  (macOS). Every one is `check=False`, `capture_output=True`, with bounded
  timeouts and validated input.
- **No outbound network calls except** (a) `ipwho.is` (HTTPS GeoIP, no key),
  (b) the abuse.ch **Feodo Tracker** botnet-C2 IP feed (`feodotracker.abuse.ch`,
  no key — only with `--threat-intel` / `--quick-triage` / `--deep-triage`),
  (c) `virustotal.com` (only with `--vt-api-key`), (d) the Tor exit-list (only
  with `--scan-tor`), and (e) the local CrowdSec LAPI on `127.0.0.1:8080` if
  running. All of these are disabled by `--offline`. The optional, off-by-default
  `--alert-webhook` (`$NETMON_WEBHOOK`, hidden from `--help`) additionally POSTs a
  HIGH/CRITICAL findings summary to a URL **you** supply.
- **No file writes** other than to user-specified `./reports/` output paths
  (HTML / TXT / CSV / JSON / NDJSON / PCAP). No registry writes, no
  scheduled-task creation, no service install, no startup-folder drops,
  no `authorized_keys` edits.
- **No process injection, no DLL side-loading, no privilege escalation, no
  persistence mechanism, no anti-debug, no anti-VM, no UAC bypass, no
  encrypted payload, no compiled blob.**
- **No telemetry.** The tool never reports back to the author or any
  upstream service.

### How to clear a false positive

1. **VirusTotal** — submit the exact hash you have. The maintainer also
   uploads each release; you can check engine-by-engine results at
   `https://www.virustotal.com/gui/file/<SHA-256>`.
2. **Microsoft Defender** — submit at
   <https://www.microsoft.com/en-us/wdsi/filesubmission> with category
   *"Incorrect detection"* and a link to this README.
3. **Other vendors** — most have an analogous false-positive portal
   (Symantec, McAfee, Sophos, ESET, Bitdefender, CrowdStrike, SentinelOne,
   etc.). A short submission text that works in nearly every form:
   > Single-file Python network-monitoring and host-triage tool.
   > Source: <https://github.com/Ozear/netmon.py>. The pattern strings in
   > source (`WEBSHELL_SIGNATURES`, `SUSPICIOUS_CMDLINE_PATTERNS`,
   > `KNOWN_BAD_JA3`) are detection rules that the tool looks for in
   > third-party content, not malicious payloads. Tool is open-source under
   > The Unlicense.
4. **Authenticode-signed Windows builds** — when a signed `.exe` build is
   published, it carries a publisher signature. Verify with
   `Get-AuthenticodeSignature .\netmon.exe` before clearing.
5. **Local allowlist** — if your environment requires it, allowlist the
   SHA-256 (printed by netmon's own self-hash on `--version`) or pin the
   path. Avoid blanket allowlists of `python.exe` — keep them tool-scoped.

### Provenance / verification

- **Public repository:** <https://github.com/Ozear/netmon.py>
- **License:** [The Unlicense](https://unlicense.org/) (public domain)
- **Author:** Ozear AL_Zadjali — contact on the repo
- **Reproducibility:** netmon.py is one Python file plus a small test suite.
  `pytest` exercises **267 cases** including XSS-resistance, hostile-input
  parsing, risk-model regressions, the noise-suppression filters, and
  the HTML UX rendering paths. There is no build step, no binary, no
  installer — what you read in `netmon.py` is exactly what runs on your
  host.

---

## 📚 Version history

| Version | Notes |
|---|---|
| **v1.4.0** *(main, current)* | **Triage & trust overhaul; major false-positive reduction.** New `--quick-triage`/`--tr` (renames `--full-triage`; local-only + the single-host abuse.ch Feodo **C2 feed** — ~7,600 IPs, tiered (curated currently-active → CRITICAL, historical → HIGH); no Tor / no VT-API) and `--deep-triage`/`--dtr` (adds Tor + VirusTotal). **CRITICAL** risk tier driven by *confirmed-bad* evidence; **unsigned-alone demoted to require corroboration** (kills the dominant false positive — `EpicGamesLauncher`-style HIGHs); `REVERSE_SHELL_LIKELY` gated to non-web ports; `IMPOSTOR_SYSTEM_BIN` exact-path anchor (no `…\Public\Windows\System32` bypass). **Security:** diff-report stored-XSS, CSV formula injection, poisonable cache dir, PII-scrub gaps (token tails / `Authorization` / secrets). **Detection:** direction port-magnitude coin-flip removed; exact/word-boundary publisher + package trust match; IPv6 extension-header parsing; DGA rewrite (vowel/digit ratio, not entropy — catches `mfsj3kr2x9`, clears `stackoverflow`); bare `powershell -e` encoded-command; timezone-aware log timestamps; `extract_binary_path` for non-`.exe` droppers; suspicious-port pruning. **Parsers:** DNS-name length budget, pcap-ng section reset, JA3 bounds. **Perf/UX:** live progress display, `(pid, create_time)` metadata cache + parallel hash pre-warm (responsive 15 s loop). **Coverage & limitations panel**; expanded Linux persistence (LD_PRELOAD, profile.d, init.d, shell-rc, systemd timers). `ruff`-clean. |
| **v1.3.0** *(prior release)* | **Linux server parity + production threat-hunting features.** Linux package-manager trust (`dpkg`/`rpm`/`pacman`/`apk` owning-package + integrity → `PACKAGE_TAMPERED`). macOS `codesign` signature checker. **Direction-aware risk model** — `UNSIGNED_OUTBOUND_C2` now gated on OUTBOUND direction so inbound `sshd` sessions stop tripping it; new `INBOUND_SESSION` / `INBOUND_FROM_TOR` flags. **Server-binary registry** (sshd, apache2, nginx, postgres, redis, …) with expected-port detection → `IMPOSTOR_LISTEN_PORT`. **Reverse-shell heuristic** (`REVERSE_SHELL_LIKELY`) — server-role binary making outbound to public IP. **CrowdSec local-LAPI integration** with auto-credential pickup → `CROWDSEC_BANNED`. **systemd unit attribution** via `/proc/<pid>/cgroup` (new Service column). **Firewall snapshot** (ufw / nftables / iptables / Windows Firewall profile) → per-port allow/deny annotation. **TCP session age** column (`3.2s` / `4h 22m` / `2d 1h`). **`--capture` saves by default** (was ephemeral in v1.2); new `--capture-fly` for ephemeral-only runs. Bug fix: removed the v1.2 hard-coded port-53/80/443 filter so Load Packets works for SSH/MySQL/etc. **Production-threat-hunting additions:** `--logs N` host event-log review (Linux `/var/log/{auth,syslog,apache,nginx,mysql,audit,fail2ban,crowdsec}` + Windows Security/System/PowerShell/Defender event logs) with PII scrubbing + brute-force-then-success correlation. `--persistence` enumerates cron / systemd / registry Run / scheduled tasks / launchd / ssh `authorized_keys`. `--scan-webroots` walks webroot directories for `WEBSHELL_SIGNATURES` (Weevely, China Chopper, eval/base64). `WEB_SHELL_SPAWN` (apache2 → bash etc.), `WEBUSER_OUTBOUND` (www-data dialing out), `DOH_FROM_NON_BROWSER`, `SUSPICIOUS_CMDLINE_*` (PowerShell encoded, certutil-download, reverse-shell one-liners, long base64), `SCTP_UNUSUAL` + `UNIX_SOCKET_DOCKER` (non-TCP/UDP transports enumerated via `/proc/net/sctp` and psutil), `JA3_C2_*` (TLS Client Hello fingerprint matched against bundled C2 list), `ICMP_TUNNEL_LIKELY`. New outputs: `--json` / `--ndjson` (SIEM-ready schema), `--diff old.json new.json` (new/gone flows + risk transitions). **`--full-triage` / `--tr`** convenience flag activates the canonical triage set (`-t 30 --capture --persistence --hash-tasks --scan-webroots --logs 3`); explicit flags override defaults. **`--hash-tasks`** computes SHA-256 of every persistence-entry binary and turns it into a click-through VirusTotal link in the HTML. **HTML UX overhaul** — sticky TOC nav with finding-count badges (red for HIGH), row-number column that renumbers on filter / sort, persistent "Showing X of Y" counter pill (amber when filtered), Pkts column with byte tooltip when capture data exists, process-cell hover tooltip showing packet availability, empty-state callouts for absent sections, floating back-to-top button. **Smart noise suppression** — three hide-by-default toggles: Microsoft / System processes, netmon-generated connections, and netmon-generated log events; PowerShell ScriptBlock events from netmon's own cmdlets are tagged `severity=SELF` and kept for audit; Security log 4624/4672 classified by SID + Logon Type so SCM service starts stop firing MED on every service launch; `PS_PROFILE_LOAD` kind for 4104 events whose Path field points at a profile (offensive patterns still promoted to HIGH). **NXDOMAIN-aware DNS retry** — `FlowAnalyzer` tracks per-name RCODE; `DNS_HIGH_RETRY_NXDOMAIN_*` at HIGH for beacon-DGA patterns, plain `DNS_HIGH_RETRY` at LOW for legitimate short-TTL CDN re-resolution. **PowerShell profile enumeration** in `--persistence` (Windows PS 5.1 + PS 7 + POSIX PS 7 paths). HTML report adds sticky drill-down indicator, Direction / Service / Age columns, "Collapse by PID" stat tile, and dedicated sections for log findings / persistence / web-shell findings. **Load-Packets bug fix** — switched to row-level `data-local-port` attribute so firewall-state annotations no longer break per-process packet filtering. CSV gains `transport`, `cmdline`, `ppid`, `parent_app`, `ja3`, `direction`, `systemd_unit`, `session_age_s`, `crowdsec`, `firewall`. Test suite expanded to **267 cases**. |
| **v1.2.0** | **C2 detection fix** — unsigned binary + ESTABLISHED + public IP now correctly reaches HIGH (was LOW in v1.1, missed a real C2). **Status filter row** (Established / Listening / TIME_WAIT / CLOSE_WAIT / SYN_SENT / FIN_WAIT / Other) — default view shows ESTABLISHED only. **Per-process pcap drill-down** — click any row to filter the DNS / TLS / HTTP / TCP-flow logs to that process. **HTTP request/response parsing** for port-80 plaintext (with size caps and CRLF-injection guards). **Tor exit-list fetch is now opt-in** via `--scan-tor` (was default-on; SNI-filtering ISPs made the warning noisy). Risk-button / stat-tile clicks reset the status filter so searches always show all matching rows. |
| **v1.1.0** *(tag `v1.1.0`)* | SAST-hardened rewrite. Adds `--capture` (pktmon/tcpdump + pure-Python pcap parser), Authenticode signature verification, multi-signal risk scoring, Tor exit detection, beacon detection, HTML5 report, optional VirusTotal integration, HTTPS GeoIP via `ipwho.is`. Fixes the System32 IMPOSTOR_SYSTEM_BIN false positive, IPv6 port-parsing crash, and unbounded resource use. Full test suite + bandit/ruff config. |
| **v1.0** *(branch + tag `v1.0`)* | Original single-file netmon.py (~260 lines). `psutil` connection mapper, basic risk heuristics, rich terminal table, CSV export. Preserved on the [`v1.0`](../../tree/v1.0) branch and tag. |

To check out a previous release:

```bash
git checkout v1.1.0    # or v1.0
```

---

## ⚠️ Disclaimer

Built for educational and defensive purposes. Network monitors can capture sensitive system data — make sure you have explicit permission to run this on any machine or network you deploy it to. I am not responsible for any misuse or damage caused by this software.

## 📄 License

Released into the Public Domain via [The Unlicense](https://unlicense.org/). Use, modify, distribute, sell — no restrictions, attribution optional.
