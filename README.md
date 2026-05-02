# 🛡️ netmon.py — Cybersecurity Network Monitor

[![License: Unlicense](https://img.shields.io/badge/license-Unlicense-blue.svg)](https://unlicense.org/)
[![Version](https://img.shields.io/badge/version-1.1.0-brightgreen.svg)](#-version-history)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)

I used to rely heavily on `netstat` for a quick pulse on what my machines were doing. But modern operating systems run so many background processes that filtering through the noise has become a real headache.

**netmon.py** is a clear, actionable look at your system's network activity — a context-rich upgrade to `netstat` that does the heavy lifting for you.

*(Note: the foundational code was prototyped with AI assistance and the v1.1 hardening pass was done with [Claude](https://www.anthropic.com/claude) acting as a security engineer.)*

---

## ✨ Features

* **Real-time process mapping** — every TCP/UDP connection linked to its PID, name, full executable path, user, and SHA-256 hash.
* **Authenticode signature verification** (Windows) — every running executable is checked via batched `Get-AuthenticodeSignature`. Binaries from a known-good publisher (Microsoft, Mozilla, Google, Anthropic, NVIDIA, Apple, Adobe, ASUS, Epic, Ollama, Python, GitHub, JetBrains, …) are flagged `trusted`.
* **Multi-signal risk scoring** — `path × signature × port × geo × VT × beacon`. A signed Anthropic binary in `%AppData%` is fine; an unsigned binary in `%AppData%\Temp` talking to a Tor exit on port 1337 is HIGH.
* **Optional packet capture (`--capture`)** — wraps Windows `pktmon` or Linux `tcpdump` (both ship with the OS — no extra install). The capture is parsed in-process by a pure-Python pcap/pcap-ng reader (no `scapy`/`tshark` required) and yields:
  * DNS queries (which domains were resolved)
  * TLS **SNI hostnames** — the *real* destination of HTTPS traffic, even when the IP alone is opaque
* **DNS heuristics** — when `--capture` is on, every captured query is run through 4 detectors: DGA-like names (Shannon entropy + vowel ratio), suspicious TLDs (`.tk .xyz .top .click ...`), invalid label characters (semicolons, homoglyphs), and high-retry NXDOMAIN bursts (resolver beacon signal). Findings appear in their own HTML section AND elevate the risk of the connection that issued them.
* **Save full capture (`--save-capture PATH`)** — writes the raw pcap to your chosen path (open it in Wireshark for full inspection) AND embeds a browsable packet log in the HTML report (DNS query timestamps, TLS handshake list, top TCP flows by bytes). Disk-usage warning + explicit `yes` confirmation required (or pass `--yes` for non-interactive).
* **Tor exit-node detection** — pulls the public Tor exit list (no auth, no key, daily refresh, size-capped) and flags any remote IP that matches.
* **Beacon detection** — flags processes that open many distinct local sockets to the same remote at low-jitter intervals, a classic C2 pattern.
* **Self-contained HTML5 report (`--html`)** — single file, embedded CSS/JS, dark theme, color-coded risk pills, sortable columns, search box, **clickable stat tiles** that filter the table (click "Unsigned binaries" to see only unsigned, "Tor exits" for Tor traffic, "External peers" to hide loopback noise — filters layer with the risk buttons). On Windows, Microsoft- and System-process rows are hidden by default behind a checkbox toggle. Every SHA-256 is a clickable link to its VirusTotal page (works without an account).
* **Listener exposure highlighting** — rows for sockets bound to `0.0.0.0` / `[::]` (reachable from any host that can reach yours — internet-facing on a public-IP machine) glow **red**; rows bound to a specific LAN interface (reachable from the local subnet) glow **amber**; loopback-only listeners stay neutral. Two dedicated stat tiles count each tier and filter the table to that exposure level when clicked. The Remote cell text replaces the bare "(listening)" with a description like "exposed on ANY IPv4 interface" or "loopback only (this host)".
* **Optional VirusTotal integration (`--vt-api-key`)** — annotates each row with detection counts and feeds the result into the risk score.
* **Geo / ASN enrichment** over **HTTPS** via `ipwho.is`, with an `ipwhois` RDAP fallback.
* **CSV export** — full untruncated schema for downstream analysis.
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
# Quick triage (15-second monitor + HTML dashboard)
python netmon.py -t 30 --html report.html

# Full power (admin/root): packet capture + VT enrichment + verbose logging
python netmon.py -t 60 --capture --html report.html -vv

# Air-gapped / privacy mode — no third-party network calls at all
python netmon.py --offline --html report.html
```

### Command-line options

| Flag | Default | What it does |
|---|---|---|
| `-t`, `--time` | `15` | Monitoring duration in seconds (1 – 86400) |
| `--html [PATH]` | **on** | Self-contained HTML report. ON by default — writes `./reports/netmon-<TS>.html` (timestamped, never overwrites prior runs). Pass an explicit path to override or `--no-html` to disable. |
| `--text [PATH]` | **on** | Plain-text report (cat / grep / less friendly fixed-width columns). ON by default — writes `./reports/netmon-<TS>.txt`. Disable with `--no-text`. |
| `-o`, `--output`, `--csv [PATH]` | *(off)* | CSV machine-readable export. **Opt-in**. Pass `--csv` (no value) for an auto-named file in `./reports/`, or `-o foo.csv` for an explicit path. |
| `--no-html` / `--no-text` | *(off)* | Disable the corresponding report (each is on by default). |
| `--capture` | *(off)* | Capture packets via `pktmon` / `tcpdump`. Requires admin/root. |
| `--save-capture [PATH]` | *(off)* | Save the raw pcap and embed a browsable packet log in the HTML report. PATH is optional — bare `--save-capture` writes `reports/netmon-<TS>.pcap` next to the CSV/HTML from the same run. Implies `--capture`. Prompts for confirmation (disk-usage warning) unless `--yes`. |
| `--yes` | *(off)* | Auto-confirm prompts (e.g. for `--save-capture`). For non-interactive / scripted use. |
| `--vt-api-key` | `$VT_API_KEY` | VirusTotal API key. **Prefer the env var** — passing on the CLI exposes the key in process listings (`ps`, Task Manager). |
| `--offline` | *(off)* | Skip GeoIP / threat-intel network calls |
| `--no-signing` | *(off)* | Skip Authenticode signature verification |
| `-v`, `-vv` |  | Increase logging verbosity (info / debug) |
| `--version` |  | Print version and exit |
| `-h`, `--help` |  | Show help |

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

v1.1 was put through a static analysis pass (SAST) — every input boundary has been hardened against the kinds of attacks that matter for a *security tool* (one nobody wants to silently fail when looking at a compromised host).

* **Pcap / pcap-ng parser** treats input as hostile binary data. Every length field is bounded; oversized records, malformed magic, truncated streams, infinite-loop pointer chains, and 4 GB allocation tricks are rejected before allocation.
* **HTML output** has every interpolated value escaped (`html.escape`); SHA-256 hashes are validated as `[0-9a-f]{64}` before becoming clickable links; URLs are `urllib.parse.quote`d; `target="_blank"` links carry `rel="noopener noreferrer"`.
* **PowerShell stdin** path validation: paths containing `\n`, `\r`, `|`, or NUL are rejected before being piped to `Get-AuthenticodeSignature` — defends against newline-injection in attacker-controlled filenames.
* **Tor exit list** is fetched with `stream=True` + 8 MB cap + per-line `inet_pton` validation, so a poisoned upstream can't DoS the cache.
* **GeoIP** uses `https://ipwho.is` (HTTPS, no key) instead of cleartext `http://ip-api.com`.
* **VT API key** is encouraged via `$VT_API_KEY` env var; CLI usage triggers a warning about process-listing exposure.
* **File hashing** is TOCTOU-safe: open then `os.fstat`, refuse non-regular files, 2 GB sanity cap.
* **Cache directory** is per-user with mode `0700` so other local users can't seed it on a multi-tenant host.
* **Resource caps**: `MAX_PCAP_BYTES=256MB`, `MAX_PACKET_SIZE=65535`, `MAX_CONN_HISTORY=50K`, `MAX_FIRST_SEEN=250K`. Long runs on noisy hosts no longer leak memory.
* **Quality gates** (run during development, not shipped): `ruff`, `bandit`, and `pytest` (51 tests) pass with zero findings on a clean checkout.

---

## 📚 Version history

| Version | Notes |
|---|---|
| **v1.1.0** *(main, current)* | SAST-hardened rewrite. Adds `--capture` (pktmon/tcpdump + pure-Python pcap parser), Authenticode signature verification, multi-signal risk scoring, Tor exit detection, beacon detection, HTML5 report, optional VirusTotal integration, HTTPS GeoIP via `ipwho.is`. Fixes the System32 IMPOSTOR_SYSTEM_BIN false positive, IPv6 port-parsing crash, and unbounded resource use. Full test suite + bandit/ruff config. |
| **v1.0** *(branch + tag `v1.0`)* | Original single-file netmon.py (~260 lines). `psutil` connection mapper, basic risk heuristics, rich terminal table, CSV export. Preserved on the [`v1.0`](../../tree/v1.0) branch and tag. |

To check out the original v1.0:

```bash
git checkout v1.0
```

---

## ⚠️ Disclaimer

Built for educational and defensive purposes. Network monitors can capture sensitive system data — make sure you have explicit permission to run this on any machine or network you deploy it to. I am not responsible for any misuse or damage caused by this software.

## 📄 License

Released into the Public Domain via [The Unlicense](https://unlicense.org/). Use, modify, distribute, sell — no restrictions, attribution optional.
