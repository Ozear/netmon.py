"""
netmon.py — Cybersecurity Network Monitor (IOC focused).

Single-file tool. No extra installs beyond psutil/requests/rich/ipwhois.
Optional packet capture uses built-in OS tools (Windows pktmon, Linux tcpdump).

Usage:
    python netmon.py -t 30 --html report.html
    python netmon.py --capture --html report.html
    python netmon.py --vt-api-key <KEY> --html report.html
"""

import argparse
import csv
import ctypes
import hashlib
import html as html_mod
import json
import logging
import math
import os
import re
import shutil
import signal
import socket
import stat as stat_mod
import string
import struct
import subprocess
import sys
import tempfile
import time
import urllib.parse
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import ClassVar

import psutil
import requests
from rich import box
from rich.console import Console
from rich.markup import escape as rich_escape
from rich.table import Table
from rich.progress import (Progress, SpinnerColumn, BarColumn, TextColumn,
                           TimeRemainingColumn)

try:
    from ipwhois import IPWhois
    HAS_IPWHOIS = True
except ImportError:
    HAS_IPWHOIS = False


VERSION = "1.4.0-dev"

log = logging.getLogger("netmon")

# === Hard limits — defend against malicious / oversized input ===

MAX_PCAP_BYTES = 512 * 1024 * 1024       # never process > 512 MB of pcap (bumped in v1.3 — BUG-1 removes the port filter, so captures can be larger)
MAX_PACKET_SIZE = 65535 + 16             # snaplen + L2 header headroom
MAX_PCAPNG_BLOCK = 1 * 1024 * 1024       # 1 MB per block is more than generous
MAX_TOR_LIST_BYTES = 8 * 1024 * 1024     # Tor exit list is ~50 KB; cap at 8 MB
MAX_DNS_QDCOUNT = 64                     # legitimate queries have 1; cap to bound work
MAX_DNS_ANCOUNT = 256                    # legitimate responses rarely exceed a few dozen
MAX_DNS_NAME_DEPTH = 8                   # pointer chain depth
MAX_CONN_HISTORY = 50_000                # per-run cap on tracked unique connections
MAX_FIRST_SEEN = 250_000                 # per-run cap on tracked (pid, local, remote) tuples
SIG_CHECK_TIMEOUT = 60                   # PowerShell batch signing timeout (seconds)
HTTP_TIMEOUT = 8                         # default per-request HTTP timeout (seconds)
TOR_FETCH_TIMEOUT = 8

# Reject paths containing any of these characters before passing to PowerShell stdin.
# NTFS already prohibits these in filenames, but defense-in-depth.
PATH_FORBIDDEN_CHARS = ("\n", "\r", "|", "\x00")

# === DNS heuristics ===
# Cheap-to-register / abuse-prone TLDs frequently seen in malware C2.
# Source: spamhaus, abuse.ch, krebs reporting. Curated, not exhaustive.
SUSPICIOUS_TLDS = frozenset({
    "tk", "ml", "ga", "gq", "cf",            # ex-Freenom freebies
    "top", "xyz", "work", "click", "surf",
    "icu", "rest", "loan", "monster",
    "buzz", "men", "country",
    "zip", "mov",                            # 2023-vintage TLDs flagged by Google
    "bid", "stream", "trade", "review",
})
DNS_DGA_MIN_LABEL_LEN = 10                   # below this, entropy is unreliable
DNS_DGA_ENTROPY_THRESHOLD = 3.5              # bits/char; English ~2.5, random ~4.5+
DNS_HIGH_RETRY_THRESHOLD = 20                # repeated queries to same NXDOMAIN
DNS_INVALID_LABEL_CHARS = frozenset(";=&?@/\\<>\"'`(){}[]*")

# === Capture-save defaults ===
CAPTURE_WARN_THRESHOLD = 50 * 1024 * 1024    # warn user about saved pcap > 50 MB

# === Heuristic configuration ===

SUSPICIOUS_PORTS = {
    4444:  "Metasploit default reverse shell",
    1337:  "Common backdoor / leetspeak",
    31337: "Elite / classic backdoor",
    6667:  "IRC (legacy C2)",
    6668:  "IRC (legacy C2)",
    9001:  "Tor relay (ORPort)",
    9050:  "Tor SOCKS",
    9999:  "Common reverse-shell port",
}
# NOTE: 3333 (miner pool), 5555 (Android ADB) and 8333 (Bitcoin) were removed in
# v1.4 — they are legitimate for whole user populations, so as a lone signal they
# produced more false positives than value. Real miners/backdoors on those ports
# still surface via other signals (unsigned + outbound + beacon + C2 feed).

# Paths that are inherently suspicious (executables shouldn't normally run from here).
# NOTE: use regular strings with "\\" — raw strings can't end with a single backslash.
# Bandit B108 (insecure temp dir) is a false positive here: these strings are
# IOC-detection patterns we search FOR in process executable paths, not
# directories we open or write to.
HIGH_RISK_PATH_FRAGMENTS = [  # nosec B108 - IOC patterns, not used as actual paths
    "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup\\",
    "\\windows\\temp\\",
    "\\users\\public\\",
    "\\programdata\\temp\\",
    "\\$recycle.bin\\",
    "/tmp/",
    "/dev/shm/",
    "/var/tmp/",
]

# Paths that *might* be suspicious but are normal for many apps. Only flagged
# when combined with another signal (unsigned binary, weird port, etc).
SOFT_SUSPICIOUS_PATH_FRAGMENTS = [
    "\\appdata\\local\\",
    "\\appdata\\roaming\\",
    "\\downloads\\",
    "/Downloads/",
]

# System binaries that should ALWAYS live in specific locations.
SYSTEM_BINARY_LOCATIONS = {
    "svchost.exe":    ["\\windows\\system32\\", "\\windows\\syswow64\\"],
    "csrss.exe":      ["\\windows\\system32\\"],
    "lsass.exe":      ["\\windows\\system32\\"],
    "wininit.exe":    ["\\windows\\system32\\"],
    "smss.exe":       ["\\windows\\system32\\"],
    "winlogon.exe":   ["\\windows\\system32\\"],
    "services.exe":   ["\\windows\\system32\\"],
    "spoolsv.exe":    ["\\windows\\system32\\"],
    "explorer.exe":   ["\\windows\\"],
    "rundll32.exe":   ["\\windows\\system32\\", "\\windows\\syswow64\\"],
    "regsvr32.exe":   ["\\windows\\system32\\", "\\windows\\syswow64\\"],
    "powershell.exe": ["\\windows\\system32\\windowspowershell\\", "\\windows\\syswow64\\windowspowershell\\"],
    "cmd.exe":        ["\\windows\\system32\\", "\\windows\\syswow64\\"],
}

# Trusted code-signing publishers (substring match against subject CN/O).
TRUSTED_PUBLISHERS = [
    "Microsoft Corporation",
    "Microsoft Windows",
    "Mozilla Corporation",
    "Google LLC",
    "Anthropic",
    "NVIDIA Corporation",
    "Apple Inc.",
    "Adobe Inc.",
    "Adobe Systems",
    "ASUSTeK COMPUTER INC.",
    "ASUS",
    "Epic Games",
    "Ollama",
    "DeepCool",
    "Valve",
    "Discord",
    "Spotify",
    "Slack",
    "Zoom Video Communications",
    "Python Software Foundation",
    "OpenJS Foundation",  # Node.js
    "GitHub, Inc.",
    "JetBrains",
    "Docker Inc",
    "Oracle America",  # Java
    "VideoLAN",
    "Realtek",
    "Intel Corporation",
    "AMD Inc.",
    "Logitech",
    "Razer USA",
    "Steelseries",
]

# Public/well-known DNS resolvers. Ports 53 / DoH 443 to these are normal.
KNOWN_DNS_RESOLVERS = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112"}

# Tor exit-node list (refreshed daily, no auth required)
TOR_EXIT_LIST_URL = "https://check.torproject.org/torbulkexitlist"
TOR_CACHE_TTL = 86400  # 24h

# Botnet-C2 IP blocklist — abuse.ch Feodo Tracker. Free, no auth, open data,
# a single trusted host. Used ONLY by --deep-triage / --threat-intel so QUICK
# triage stays local-only on a possibly-compromised host. Same hostile-input
# discipline as the Tor list (cache TTL, size cap, per-line IP validation).
C2_FEED_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
# Broad historical list (~thousands of IPs) from the SAME host. The curated list
# above is tiny (it ages IPs out fast — often single digits), so this aggressive
# list is what gives real coverage. Matches here are HIGH (the IP was C2 but may
# be stale); a match on the curated list above is CRITICAL.
C2_FEED_AGGRESSIVE_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.txt"
C2_FEED_CACHE_TTL = 86400  # 24h


# === Pure-python pcap / pcap-ng reader ===

class PcapReader:
    """Reads classic libpcap and pcap-ng files. Yields (link_type, ts, packet_bytes).

    SECURITY: input is attacker-controlled binary data. Every length field is
    bounded against module-level limits before allocation. Truncated, malformed,
    or oversized records terminate the iterator without raising.
    """

    PCAP_MAGIC_LE = 0xa1b2c3d4
    PCAP_MAGIC_BE = 0xd4c3b2a1
    PCAPNG_SHB = 0x0A0D0D0A
    PCAPNG_IDB = 0x00000001
    PCAPNG_EPB = 0x00000006
    PCAPNG_SPB = 0x00000003

    def __init__(self, path, max_bytes=MAX_PCAP_BYTES):
        self.path = path
        self.max_bytes = max_bytes

    def __iter__(self):
        try:
            file_size = os.path.getsize(self.path)
        except OSError as e:
            log.warning("pcap: cannot stat %s: %s", self.path, e)
            return
        if file_size > self.max_bytes:
            log.warning("pcap: refusing to parse %d-byte file (max %d)", file_size, self.max_bytes)
            return

        with open(self.path, "rb") as f:
            magic = f.read(4)
            if len(magic) < 4:
                return
            f.seek(0)
            first_word = struct.unpack("<I", magic)[0]
            if first_word in (self.PCAP_MAGIC_LE, self.PCAP_MAGIC_BE):
                yield from self._read_classic(f)
            elif first_word == self.PCAPNG_SHB:
                yield from self._read_pcapng(f)
            else:
                raise ValueError(f"Unknown capture format magic: {first_word:#x}")

    def _read_classic(self, f):
        header = f.read(24)
        if len(header) < 24:
            return
        magic = struct.unpack("<I", header[:4])[0]
        endian = "<" if magic == self.PCAP_MAGIC_LE else ">"
        link_type = struct.unpack(endian + "I", header[20:24])[0]
        while True:
            rec = f.read(16)
            if len(rec) < 16:
                return
            ts_sec, ts_usec, incl_len, _orig_len = struct.unpack(endian + "IIII", rec)
            # Bound incl_len: a sane snaplen is well under 64 KB; reject anything bigger
            # to prevent malicious 4 GB allocations.
            if incl_len == 0 or incl_len > MAX_PACKET_SIZE:
                log.warning("pcap: skipping record with implausible incl_len=%d", incl_len)
                return
            data = f.read(incl_len)
            if len(data) < incl_len:
                return  # truncated file
            yield link_type, ts_sec + ts_usec / 1e6, data

    def _read_pcapng(self, f):
        link_types = {}  # interface_id -> link_type
        interface_count = 0
        while True:
            head = f.read(8)
            if len(head) < 8:
                return
            block_type, total_len = struct.unpack("<II", head)
            # Validate: block must be 32-bit aligned, between header overhead and our cap.
            if total_len < 12 or total_len > MAX_PCAPNG_BLOCK or total_len % 4 != 0:
                log.warning("pcapng: invalid block total_len=%d (type=%#x)", total_len, block_type)
                return
            body_len = total_len - 12
            body = f.read(body_len)
            if len(body) < body_len:
                return  # truncated
            trailer = f.read(4)
            if len(trailer) < 4:
                return
            if block_type == self.PCAPNG_SHB:
                # New section: interface IDs restart at 0 per the pcapng spec, so
                # reset the map or later sections resolve the wrong link type.
                # body[0:4] is byte-order magic; we assume little-endian.
                link_types.clear()
                interface_count = 0
                continue
            if block_type == self.PCAPNG_IDB:
                if len(body) < 2:
                    continue
                link_type = struct.unpack("<H", body[0:2])[0]
                link_types[interface_count] = link_type
                interface_count += 1
                continue
            if block_type == self.PCAPNG_EPB:
                if len(body) < 20:
                    continue
                iface_id, ts_high, ts_low, cap_len, _orig_len = struct.unpack("<IIIII", body[:20])
                if cap_len > MAX_PACKET_SIZE or cap_len > len(body) - 20:
                    log.warning("pcapng: EPB cap_len=%d out of range", cap_len)
                    continue
                ts = ((ts_high << 32) | ts_low) / 1e6
                packet = body[20:20 + cap_len]
                yield link_types.get(iface_id, 1), ts, packet
                continue
            if block_type == self.PCAPNG_SPB:
                if len(body) < 4:
                    continue
                _orig_len = struct.unpack("<I", body[:4])[0]
                packet = body[4:]
                if len(packet) > MAX_PACKET_SIZE:
                    continue
                yield link_types.get(0, 1), 0.0, packet
                continue


# === Flow analyzer (extract DNS queries, TLS SNI from captured packets) ===

class FlowAnalyzer:
    """Parses packets for layer-7 metadata: DNS queries, TLS SNI."""

    LINK_ETHERNET = 1
    LINK_RAW_IP = 101
    LINK_LINUX_SLL = 113
    LINK_LINUX_SLL2 = 276
    LINK_NULL = 0

    # Cap detail-record buffers so a multi-million-packet pcap can't OOM us
    # when --save-capture is in effect.
    MAX_DETAIL_RECORDS = 10_000

    # Per-packet preview capture: first N bytes of every TCP payload that
    # contains data. Lets the HTML "Load Packets" feature show inline hex/
    # ASCII for each flow without re-reading the .pcap. Capped to keep HTML
    # size bounded (5000 * 200 bytes ~ 2 MB JSON worst case).
    MAX_PACKET_PREVIEWS = 5_000
    PACKET_PREVIEW_BYTES = 200

    # Within this many seconds an identical (key) event is treated as the
    # same logical packet (pktmon captures every packet at up to ~9 layers,
    # all within the same microsecond). 0.1s is conservative — real retries
    # in TCP/DNS land happen with backoff measured in hundreds of ms minimum.
    DEDUP_WINDOW_SEC = 0.1

    def _is_duplicate(self, dedup_map, key, ts):
        """Return True if this event matches a recent identical one (same
        key within DEDUP_WINDOW_SEC). Updates the map either way."""
        last = dedup_map.get(key, -1e9)
        if ts - last < self.DEDUP_WINDOW_SEC:
            dedup_map[key] = ts
            return True
        dedup_map[key] = ts
        return False

    def __init__(self):
        self.dns_queries = []                  # list of (qname, qtype, ts)
        self.dns_responses = defaultdict(set)  # qname -> {ip, ip, ...}
        # v1.3: per-name RCODE histogram so the DNS-retry analyzer can
        # distinguish NXDOMAIN bursts (potential C2 beacon DGA) from
        # legitimate short-TTL resolutions (CDN PoP refresh, etc.).
        self.dns_rcode_counts = defaultdict(dict)  # qname -> {rcode: count}
        self.sni_by_peer = defaultdict(set)    # remote_ip -> {sni, sni}
        self.bytes_per_peer = Counter()        # remote_ip -> total bytes
        self.packets_per_peer = Counter()
        self.errors = 0

        # v1.3 — additional per-peer collections.
        self.ja3_by_peer = defaultdict(set)            # F-1.6: remote_ip -> {ja3hash}
        self.ja3_details = []                          # list of {ts, src, dst, ja3, ja3_hash, label}
        self.icmp_payload_total_by_peer = Counter()    # F-1.3
        self.icmp_packets_by_peer = Counter()
        self.icmp_findings = []                        # F-1.3 derived findings

        # Detailed records — only populated when capture detail is requested.
        # Each list capped at MAX_DETAIL_RECORDS to bound memory.
        self.dns_query_log = []      # list of dicts: {ts, qname, qtype, src, dst}
        self.tls_handshakes = []     # list of dicts: {ts, sni, src, dst}
        self.tcp_flow_log = {}       # 5-tuple -> {first_ts, last_ts, bytes, pkts}
        self.http_messages = []      # list of dicts: {ts, kind, src, dst, method/status, host, path}
        self.packet_previews = []    # list of dicts: {ts, src, dst, size, hex, ascii, proto}
        # Multi-layer-capture dedup: pktmon captures every packet at multiple
        # network-stack components (NDIS / WFP / TCP/IP / ALE), so a single
        # logical packet shows up 6-9 times in the pcap with the same source
        # port, destination, and content. We dedupe identical (key, ts-rounded)
        # within a small window so the user-facing tables count real events.
        self._dedup_dns = {}      # (src, dst, qname) -> last_seen_ts
        self._dedup_tls = {}      # (src, dst, sni) -> last_seen_ts
        self._dedup_http = {}     # (src, dst, kind, method_or_status, host, path) -> last_seen_ts
        self._dedup_pkt = {}      # (src, dst, hex) -> last_seen_ts

    def feed_pcap(self, path, max_bytes=MAX_PCAP_BYTES):
        reader = PcapReader(path, max_bytes=max_bytes)
        for link_type, ts, packet in reader:
            try:
                self._handle_packet(link_type, ts, packet)
            except (struct.error, ValueError, IndexError, OSError) as e:
                self.errors += 1
                log.debug("pcap parse error: %s", e)

    def _handle_packet(self, link_type, ts, packet):
        ip_packet, _ethertype = self._strip_l2(link_type, packet)
        if ip_packet is None:
            return
        ip_ver = ip_packet[0] >> 4
        if ip_ver == 4:
            self._handle_ipv4(ts, ip_packet)
        elif ip_ver == 6:
            self._handle_ipv6(ts, ip_packet)

    def _strip_l2(self, link_type, packet):
        if link_type == self.LINK_ETHERNET:
            if len(packet) < 14:
                return None, None
            ethertype = struct.unpack("!H", packet[12:14])[0]
            offset = 14
            # VLAN tag
            while ethertype == 0x8100 and len(packet) >= offset + 4:
                ethertype = struct.unpack("!H", packet[offset + 2:offset + 4])[0]
                offset += 4
            if ethertype not in (0x0800, 0x86DD):
                return None, None
            return packet[offset:], ethertype
        if link_type == self.LINK_RAW_IP:
            return packet, None
        if link_type == self.LINK_LINUX_SLL:
            if len(packet) < 16:
                return None, None
            ethertype = struct.unpack("!H", packet[14:16])[0]
            if ethertype not in (0x0800, 0x86DD):
                return None, None
            return packet[16:], ethertype
        if link_type == self.LINK_LINUX_SLL2:
            if len(packet) < 20:
                return None, None
            ethertype = struct.unpack("!H", packet[0:2])[0]
            if ethertype not in (0x0800, 0x86DD):
                return None, None
            return packet[20:], ethertype
        if link_type == self.LINK_NULL:
            if len(packet) < 4:
                return None, None
            family = struct.unpack("<I", packet[:4])[0]
            if family in (2,):
                return packet[4:], 0x0800
            if family in (24, 28, 30):
                return packet[4:], 0x86DD
            return None, None
        return None, None

    def _handle_ipv4(self, ts, ip):
        if len(ip) < 20:
            return
        ihl = (ip[0] & 0x0F) * 4
        proto = ip[9]
        src_ip = socket.inet_ntoa(ip[12:16])
        dst_ip = socket.inet_ntoa(ip[16:20])
        payload = ip[ihl:]
        self._handle_l4(ts, src_ip, dst_ip, proto, payload)

    IPV6_EXT_HEADERS = frozenset({0, 43, 44, 51, 60})  # HopByHop, Routing, Fragment, AH, DstOpts

    def _handle_ipv6(self, ts, ip):
        if len(ip) < 40:
            return
        nh = ip[6]
        src_ip = socket.inet_ntop(socket.AF_INET6, ip[8:24])
        dst_ip = socket.inet_ntop(socket.AF_INET6, ip[24:40])
        off = 40
        # v1.4 (F5): walk the extension-header chain to the real L4 header so
        # IPv6 TLS/DNS/HTTP — and evasion via a prepended Hop-by-Hop header —
        # is not dropped before inspection.
        hops = 0
        while nh in self.IPV6_EXT_HEADERS and hops < 8:
            if off + 2 > len(ip):
                return
            if nh == 44:  # Fragment: fixed 8 bytes; drop non-first fragments
                if (((ip[off + 2] << 8) | ip[off + 3]) & 0xFFF8) != 0:
                    return
                nxt, adv = ip[off], 8
            elif nh == 51:  # Authentication Header: (payload_len + 2) * 4 bytes
                nxt, adv = ip[off], (ip[off + 1] + 2) * 4
            else:           # HopByHop / Routing / DstOpts: (hdr_ext_len + 1) * 8
                nxt, adv = ip[off], (ip[off + 1] + 1) * 8
            off += adv
            nh = nxt
            hops += 1
            if off > len(ip):
                return
        self._handle_l4(ts, src_ip, dst_ip, nh, ip[off:])

    def _handle_l4(self, ts, src_ip, dst_ip, proto, payload):
        # v1.3 F-1.3: ICMP echo tunnel heuristic. We track per-peer total
        # packet count + accumulated payload bytes; in summary() we report a
        # finding for any peer with ≥50 echo packets AND avg payload >1000.
        # That signature catches stuff like ptunnel / icmpsh; legitimate
        # echos rarely have payloads beyond the canned 32-56 bytes.
        if proto in (1, 58):  # ICMP / ICMPv6
            if len(payload) < 4:
                return
            icmp_type = payload[0]
            # Only count Echo Request (8) / Echo Reply (0) / ICMPv6 Echo (128, 129)
            if icmp_type not in (0, 8, 128, 129):
                return
            peer = dst_ip if icmp_type in (8, 128) else src_ip
            data_len = max(0, len(payload) - 8)  # minus ICMP header
            self.icmp_packets_by_peer[peer] += 1
            self.icmp_payload_total_by_peer[peer] += data_len
            return
        if proto == 6:  # TCP
            if len(payload) < 20:
                return
            sport, dport = struct.unpack("!HH", payload[:4])
            data_offset = (payload[12] >> 4) * 4
            tcp_payload = payload[data_offset:]
            peer_ip = dst_ip if dport in (443, 80, 8443) else src_ip
            self.bytes_per_peer[peer_ip] += len(payload)
            self.packets_per_peer[peer_ip] += 1
            # Track per-flow stats (5-tuple, with src side normalized).
            flow_key = (src_ip, sport, dst_ip, dport, "TCP")
            flow = self.tcp_flow_log.get(flow_key)
            if flow is None and len(self.tcp_flow_log) < self.MAX_DETAIL_RECORDS:
                self.tcp_flow_log[flow_key] = {
                    "first_ts": ts, "last_ts": ts, "bytes": len(payload), "pkts": 1,
                }
            elif flow is not None:
                flow["last_ts"] = ts
                flow["bytes"] += len(payload)
                flow["pkts"] += 1
            src_key = f"{src_ip}:{sport}"
            dst_key = f"{dst_ip}:{dport}"

            # Capture a bounded per-packet preview (hex + ASCII of the first
            # PACKET_PREVIEW_BYTES of payload) so the HTML report can show
            # inline packet detail when the user clicks "Load Packets" for
            # a selected process. Dedup multi-layer captures by hex content.
            if tcp_payload and len(self.packet_previews) < self.MAX_PACKET_PREVIEWS:
                preview = tcp_payload[:self.PACKET_PREVIEW_BYTES]
                hex_str = preview.hex()
                pkt_key = (src_key, dst_key, hex_str)
                if not self._is_duplicate(self._dedup_pkt, pkt_key, ts):
                    ascii_repr = "".join(
                        chr(b) if 32 <= b < 127 else "." for b in preview
                    )
                    if self._looks_like_tls_client_hello(tcp_payload):
                        proto_guess = "TLS-CH"
                    elif self._looks_like_http_request(tcp_payload):
                        proto_guess = "HTTP-REQ"
                    elif self._looks_like_http_response(tcp_payload):
                        proto_guess = "HTTP-RSP"
                    elif len(tcp_payload) >= 3 and tcp_payload[0] == 0x16 and tcp_payload[1] == 0x03:
                        proto_guess = "TLS"
                    elif tcp_payload.startswith(b"SSH-"):
                        proto_guess = "SSH"
                    else:
                        proto_guess = "RAW"
                    self.packet_previews.append({
                        "ts": ts, "src": src_key, "dst": dst_key,
                        "size": len(tcp_payload),
                        "hex": hex_str, "ascii": ascii_repr,
                        "proto": proto_guess,
                    })

            # Detect TLS / HTTP by their actual byte signatures rather than by
            # port number — many services run TLS / HTTP on non-standard ports
            # (Game-Pass on 6822, dev servers on 8000/3000/3001, etc.).
            if tcp_payload:
                if self._looks_like_tls_client_hello(tcp_payload):
                    sni = self._extract_sni(tcp_payload)
                    # v1.3 F-1.6: extract JA3 fingerprint from the same Client
                    # Hello while we have the parsed payload at hand.
                    ja3_str, ja3_hash = self._extract_ja3(tcp_payload)
                    if ja3_hash:
                        self.ja3_by_peer[dst_ip].add(ja3_hash)
                        label = KNOWN_BAD_JA3.get(ja3_hash, "")
                        if len(self.ja3_details) < self.MAX_DETAIL_RECORDS:
                            self.ja3_details.append({
                                "ts": ts, "src": src_key, "dst": dst_key,
                                "sni": sni or "", "ja3": ja3_str,
                                "ja3_hash": ja3_hash, "label": label,
                            })
                    if sni:
                        self.sni_by_peer[dst_ip].add(sni)
                        tls_key = (src_key, dst_key, sni)
                        if (not self._is_duplicate(self._dedup_tls, tls_key, ts)
                                and len(self.tls_handshakes) < self.MAX_DETAIL_RECORDS):
                            self.tls_handshakes.append({
                                "ts": ts, "sni": sni,
                                "src": src_key, "dst": dst_key,
                            })
                elif self._looks_like_http_request(tcp_payload):
                    self._extract_http(ts, tcp_payload,
                                       src_ip, sport, dst_ip, dport,
                                       is_request=True)
                elif self._looks_like_http_response(tcp_payload):
                    self._extract_http(ts, tcp_payload,
                                       src_ip, sport, dst_ip, dport,
                                       is_request=False)
        elif proto == 17:  # UDP
            if len(payload) < 8:
                return
            sport, dport, _, _ = struct.unpack("!HHHH", payload[:8])
            udp_payload = payload[8:]
            peer_ip = dst_ip if dport in (443, 53) else src_ip
            self.bytes_per_peer[peer_ip] += len(payload)
            self.packets_per_peer[peer_ip] += 1
            if dport == 53 and udp_payload:
                qname, qtype = self._extract_dns_query(udp_payload)
                if qname:
                    src_key = f"{src_ip}:{sport}"
                    dst_key = f"{dst_ip}:{dport}"
                    dns_key = (src_key, dst_key, qname)
                    if not self._is_duplicate(self._dedup_dns, dns_key, ts):
                        self.dns_queries.append((qname, qtype, ts))
                        if len(self.dns_query_log) < self.MAX_DETAIL_RECORDS:
                            self.dns_query_log.append({
                                "ts": ts, "qname": qname, "qtype": qtype,
                                "src": src_key, "dst": dst_key,
                            })
            elif sport == 53 and udp_payload:
                self._extract_dns_response(udp_payload)

    # HTTP parsing security: data is attacker-controlled. We refuse to
    # accept oversized headers (1 KB) and reject embedded CR / LF / NUL
    # in any extracted field so the parsed strings can't smuggle HTML.
    _HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ",
                     b"PATCH ", b"CONNECT ", b"TRACE ")
    _MAX_HTTP_HEADER_BYTES = 1024

    @staticmethod
    def _looks_like_tls_client_hello(data):
        """Identify a TLS Client Hello by its on-the-wire signature.

        TLS record header: type(1) + version(2) + length(2). For a Client Hello:
          - type = 0x16 (Handshake)
          - version major = 0x03 (SSL 3.0+ / all TLS versions)
        Then the handshake header has type 0x01 (ClientHello).
        Matching by byte signature lets us catch TLS on any port — not just 443.
        """
        return (len(data) >= 6
                and data[0] == 0x16
                and data[1] == 0x03
                and data[5] == 0x01)

    @classmethod
    def _looks_like_http_request(cls, data):
        """An HTTP request starts with a method token + space."""
        if len(data) < 4:
            return False
        return any(data.startswith(m) for m in cls._HTTP_METHODS)

    @staticmethod
    def _looks_like_http_response(data):
        """An HTTP response starts with 'HTTP/<major>.<minor> '."""
        return (len(data) >= 8
                and data.startswith(b"HTTP/")
                and data[5:6].isdigit() and data[6:7] == b"."
                and data[7:8].isdigit())

    def _extract_http(self, ts, data, src_ip, sport, dst_ip, dport, is_request):
        """Parse a plaintext HTTP request or response line from a TCP payload.

        Only the first ~1 KB is inspected; long headers are truncated. Each
        extracted field is sanitized (printable ASCII only). Never raises.
        """
        if not data or len(self.http_messages) >= self.MAX_DETAIL_RECORDS:
            return
        head = data[:self._MAX_HTTP_HEADER_BYTES]
        # End of headers (CRLF CRLF) — beyond this we don't bother parsing.
        end = head.find(b"\r\n\r\n")
        if end != -1:
            head = head[:end]
        try:
            text = head.decode("latin-1", errors="replace")
        except UnicodeDecodeError:
            return
        lines = text.split("\r\n")
        if not lines:
            return
        first = lines[0]

        def _safe(s, n=200):
            # Restrict to printable ASCII + space, cap length. Defends against
            # CRLF / NUL / non-printable injection into the HTML report.
            return "".join(c for c in s if 32 <= ord(c) < 127)[:n]

        host = ""
        for line in lines[1:8]:  # only check the first few headers
            if line.lower().startswith("host:"):
                host = _safe(line[5:].strip(), 120)
                break

        src_key = f"{src_ip}:{sport}"
        dst_key = f"{dst_ip}:{dport}"
        if is_request:
            # Request line: "GET /path HTTP/1.1"
            if not any(first.startswith(m.decode()) for m in self._HTTP_METHODS):
                return
            parts = first.split(" ", 2)
            if len(parts) < 2:
                return
            method = _safe(parts[0], 12)
            path = _safe(parts[1], 200)
            key = (src_key, dst_key, "REQ", method, host, path)
            if self._is_duplicate(self._dedup_http, key, ts):
                return
            self.http_messages.append({
                "ts": ts, "kind": "REQ",
                "src": src_key, "dst": dst_key,
                "method": method, "path": path, "host": host, "status": "",
            })
        else:
            # Response status line: "HTTP/1.1 200 OK"
            if not first.startswith("HTTP/"):
                return
            parts = first.split(" ", 2)
            if len(parts) < 2:
                return
            status = _safe(parts[1] + " " + (parts[2] if len(parts) > 2 else ""), 60)
            key = (src_key, dst_key, "RSP", status, host, "")
            if self._is_duplicate(self._dedup_http, key, ts):
                return
            self.http_messages.append({
                "ts": ts, "kind": "RSP",
                "src": src_key, "dst": dst_key,
                "method": "", "path": "", "host": host, "status": status,
            })

    def _extract_sni(self, data):
        """Extract SNI hostname from a TLS Client Hello payload.

        SECURITY: every length field is bounded against the available payload
        and against an attacker-controlled extension table that could otherwise
        point arbitrarily far. Returns None on any inconsistency.
        """
        n = len(data)
        # TLS record header: type(1) version(2) length(2)
        if n < 5 or data[0] != 0x16:
            return None
        # Handshake header: type(1) length(3)
        if n < 9 or data[5] != 0x01:
            return None
        # Skip TLS record + handshake header + version(2) + random(32)
        idx = 5 + 4 + 2 + 32
        if idx >= n:
            return None
        # session_id
        sid_len = data[idx]
        idx += 1 + sid_len
        if idx + 2 > n:
            return None
        # cipher_suites
        cs_len = struct.unpack("!H", data[idx:idx + 2])[0]
        idx += 2 + cs_len
        if idx + 1 > n:
            return None
        # compression_methods
        cm_len = data[idx]
        idx += 1 + cm_len
        if idx + 2 > n:
            return None
        # extensions
        ext_total = struct.unpack("!H", data[idx:idx + 2])[0]
        idx += 2
        ext_end = min(idx + ext_total, n)
        while idx + 4 <= ext_end:
            ext_type, ext_len = struct.unpack("!HH", data[idx:idx + 4])
            idx += 4
            # Bound ext_len against remaining ext_end before any access.
            if ext_len > ext_end - idx:
                return None
            if ext_type == 0x0000 and ext_len >= 5:
                # SNI extension: list_len(2), name_type(1), name_len(2), name
                _list_len = struct.unpack("!H", data[idx:idx + 2])[0]
                name_type = data[idx + 2]
                if name_type == 0:
                    name_len = struct.unpack("!H", data[idx + 3:idx + 5])[0]
                    if name_len > ext_len - 5 or name_len > 255:
                        return None
                    name = data[idx + 5:idx + 5 + name_len]
                    try:
                        return name.decode("ascii", errors="replace")
                    except (UnicodeDecodeError, AttributeError):
                        return None
            idx += ext_len
        return None

    def _extract_ja3(self, data):
        """Extract the JA3 fingerprint (string + md5) from a TLS Client Hello
        record. Wraps `compute_ja3` after peeling the TLS record + handshake
        headers (5 + 4 bytes) so it matches the spec's "starts at ClientHello
        version" definition. Returns (ja3_str, ja3_hash) or (None, None).
        """
        n = len(data)
        if n < 9 or data[0] != 0x16 or data[5] != 0x01:
            return None, None
        return compute_ja3(data[9:])

    def _extract_dns_query(self, data):
        if len(data) < 12:
            return None, None
        qdcount = struct.unpack("!H", data[4:6])[0]
        # Cap qdcount to bound work — legitimate queries have qdcount=1.
        if qdcount < 1 or qdcount > MAX_DNS_QDCOUNT:
            return None, None
        idx = 12
        qname, idx = self._read_dns_name(data, idx)
        if qname is None or idx + 4 > len(data):
            return None, None
        qtype = struct.unpack("!H", data[idx:idx + 2])[0]
        return qname, qtype

    def _extract_dns_response(self, data):
        if len(data) < 12:
            return
        flags = struct.unpack("!H", data[2:4])[0]
        if not (flags & 0x8000):
            return  # not a response
        # v1.3: track RCODE so the DNS-retry heuristic can distinguish
        # NXDOMAIN bursts (potential C2 beacon) from legitimate short-TTL
        # re-resolution (CDN PoP, Windows Update etc.). RCODE = low nibble
        # of flags. 0 = NOERROR, 3 = NXDOMAIN.
        rcode = flags & 0x000F
        qdcount, ancount = struct.unpack("!HH", data[4:8])
        # Cap counts to defang malicious headers (uint16 max = 65535).
        if qdcount > MAX_DNS_QDCOUNT or ancount > MAX_DNS_ANCOUNT:
            return
        idx = 12
        qname = None
        for _ in range(qdcount):
            qname, idx = self._read_dns_name(data, idx)
            if qname is None or idx + 4 > len(data):
                return
            idx += 4
        # Record NXDOMAIN-per-name BEFORE walking ANSWERS (which may be empty
        # for NXDOMAIN). This lets the analyzer compute NXDOMAIN ratio.
        if qname:
            self.dns_rcode_counts[qname][rcode] = (
                self.dns_rcode_counts[qname].get(rcode, 0) + 1
            )
        for _ in range(ancount):
            _name, idx = self._read_dns_name(data, idx)
            if idx + 10 > len(data):
                return
            atype, _aclass, _ttl, rdlen = struct.unpack("!HHIH", data[idx:idx + 10])
            idx += 10
            if rdlen > 4096 or idx + rdlen > len(data):
                return
            rdata = data[idx:idx + rdlen]
            idx += rdlen
            if qname and atype == 1 and len(rdata) == 4:
                self.dns_responses[qname].add(socket.inet_ntoa(rdata))
            elif qname and atype == 28 and len(rdata) == 16:
                self.dns_responses[qname].add(socket.inet_ntop(socket.AF_INET6, rdata))

    def _read_dns_name(self, data, idx, depth=0, _start_idx=None):
        """Read a (possibly compressed) DNS name. Pointers must point strictly
        backward to prevent infinite loops on a hostile message."""
        if depth > MAX_DNS_NAME_DEPTH or idx < 0 or idx >= len(data):
            return None, idx
        labels = []
        total = 0  # RFC 1035: total decoded name length is bounded to 255 octets
        # When following a pointer, _start_idx is the offset of the pointer
        # itself; any new pointer must point strictly before _start_idx.
        anchor = _start_idx if _start_idx is not None else idx
        while idx < len(data):
            length = data[idx]
            if length == 0:
                idx += 1
                break
            if (length & 0xC0) == 0xC0:
                if idx + 2 > len(data):
                    return None, idx
                ptr = struct.unpack("!H", data[idx:idx + 2])[0] & 0x3FFF
                # Reject pointers that don't point strictly backward.
                if ptr >= anchor or ptr >= len(data):
                    return None, idx + 2
                advanced_idx = idx + 2
                rest, _ = self._read_dns_name(data, ptr, depth + 1, _start_idx=ptr)
                if rest:
                    labels.append(rest)
                idx = advanced_idx
                break
            if length > 63:  # DNS labels are max 63 octets
                return None, idx
            idx += 1
            if idx + length > len(data):
                return None, idx
            total += length + 1
            if total > 255:  # bound CPU on hostile compressed-name expansion
                return None, idx
            labels.append(data[idx:idx + length].decode("ascii", errors="replace"))
            idx += length
        return ".".join(labels) if labels else None, idx

    def hostname_for_ip(self, ip):
        """Returns set of SNI names + DNS-resolved names that point to this IP."""
        names = set(self.sni_by_peer.get(ip, set()))
        for qname, ips in self.dns_responses.items():
            if ip in ips:
                names.add(qname)
        return names

    def summary(self):
        # Derive ICMP-tunnel findings on demand (cheap; runs once per report).
        self._compute_icmp_findings()
        return {
            "dns_query_count": len(self.dns_queries),
            "unique_dns_names": len({q[0] for q in self.dns_queries}),
            "sni_peer_count": len(self.sni_by_peer),
            "unique_sni_names": len({s for v in self.sni_by_peer.values() for s in v}),
            "tracked_peer_count": len(self.bytes_per_peer),
            "parse_errors": self.errors,
            "ja3_unique": len({h for v in self.ja3_by_peer.values() for h in v}),
            "ja3_c2_matches": sum(1 for v in self.ja3_by_peer.values()
                                  for h in v if h in KNOWN_BAD_JA3),
            "icmp_tunnel_findings": len(self.icmp_findings),
        }

    def _compute_icmp_findings(self):
        """Materialize per-peer ICMP-tunnel findings using the thresholds in
        ICMP_TUNNEL_MIN_PACKETS / ICMP_TUNNEL_MIN_AVG_PAYLOAD."""
        self.icmp_findings = []
        for peer, pkts in self.icmp_packets_by_peer.items():
            if pkts < ICMP_TUNNEL_MIN_PACKETS:
                continue
            total = self.icmp_payload_total_by_peer.get(peer, 0)
            avg = total / pkts if pkts else 0
            if avg >= ICMP_TUNNEL_MIN_AVG_PAYLOAD:
                self.icmp_findings.append({
                    "peer": peer, "packets": pkts,
                    "avg_payload": round(avg, 1),
                    "total_payload": total,
                })


# === DNS analyzer (heuristics over captured DNS queries) ===

class DNSAnalyzer:
    """Heuristic detector over the FlowAnalyzer's DNS query log.

    Produces per-name flags. Designed to catch:
      - DGA-like names (high entropy, long random labels)
      - Suspicious / abuse-prone TLDs (.tk, .xyz, .top, etc.)
      - Invalid characters in labels (semicolons, etc. — typed garbage or
        homoglyph attacks)
      - High retry counts to NXDOMAIN names (resolver beacon signal)
    """

    def __init__(self, queries, rcode_counts=None):
        # queries: list of (qname, qtype, ts) from FlowAnalyzer
        # rcode_counts: optional dict[qname] -> {rcode: count} from
        # FlowAnalyzer.dns_rcode_counts; enables NXDOMAIN-aware HIGH_RETRY
        # classification. When None, falls back to count-only heuristic.
        self.queries = list(queries) if queries else []
        self.query_counts = Counter(q[0] for q in self.queries if q and q[0])
        self.rcode_counts = dict(rcode_counts) if rcode_counts else {}
        self.flags_by_name = defaultdict(list)  # qname -> [flag, flag, ...]

    @staticmethod
    def _shannon_entropy(s):
        if not s:
            return 0.0
        freq = Counter(s)
        n = len(s)
        return -sum((c / n) * math.log2(c / n) for c in freq.values())

    @classmethod
    def _is_dga_like(cls, label):
        """A label looks DGA-like if any of these fire:
          - high Shannon entropy (random-letter DGA, e.g. mfsj3kr2x9.com)
          - very low vowel ratio on a long label (keyboard-mash / consonant DGA)
        """
        if len(label) < DNS_DGA_MIN_LABEL_LEN:
            return False
        if "-" in label or "_" in label:
            return False
        if label.isdigit():
            return False
        lower = label.lower()
        vowels = sum(1 for c in lower if c in "aeiou")
        vowel_ratio = vowels / len(lower)
        digits = sum(1 for c in lower if c.isdigit())
        # v1.4 (F6/R8): dropped the fixed Shannon-entropy gate. It could never
        # fire for 10-11 char labels (max entropy log2(10)=3.32 < 3.5, missing
        # the code's own example `mfsj3kr2x9`) yet flagged long distinct-letter
        # brand SLDs like `stackoverflow` (entropy 3.55). Vowel ratio + digit
        # density separate real words from DGA far better.
        #
        # Signal 1: very few vowels for the length (random / consonant-mash).
        # Real words and brand SLDs almost always exceed ~18% vowels
        # (stackoverflow = 0.31, cloudfront = 0.30; mfsj3kr2x9 = 0.0).
        if vowel_ratio < 0.18:
            return True
        # Signal 2: several interspersed digits in an otherwise alphabetic label
        # (classic alphanumeric DGA). Skips version-like mostly-digit labels.
        if 3 <= digits < len(lower) and vowel_ratio < 0.30:
            return True
        return False

    def analyze(self):
        """Run all heuristics. Returns dict[qname] = list_of_flags."""
        for qname in self.query_counts:
            self._analyze_one(qname)
        return dict(self.flags_by_name)

    def _analyze_one(self, qname):
        if not qname:
            return
        lower = qname.lower().rstrip(".")
        # Reverse DNS queries are not interesting for this heuristic.
        if lower.endswith(".in-addr.arpa") or lower.endswith(".ip6.arpa"):
            return
        labels = [lab for lab in lower.split(".") if lab]
        if not labels:
            return

        # 1. Suspicious TLD
        tld = labels[-1]
        if tld in SUSPICIOUS_TLDS:
            self.flags_by_name[qname].append(f"DNS_SUSPICIOUS_TLD_{tld}")

        # 2. DGA-like SLD or any subdomain label
        sld = labels[-2] if len(labels) >= 2 else ""
        if self._is_dga_like(sld):
            self.flags_by_name[qname].append("DNS_DGA_LIKE")
        else:
            for label in labels[:-2]:
                if self._is_dga_like(label):
                    self.flags_by_name[qname].append("DNS_DGA_LIKE_SUBDOMAIN")
                    break

        # 3. Invalid characters in any label (defense vs typed garbage / homoglyph)
        for label in labels:
            if any(c in DNS_INVALID_LABEL_CHARS for c in label):
                self.flags_by_name[qname].append("DNS_INVALID_CHARS")
                break

        # 4. High retry count — NXDOMAIN-aware classification.
        #
        # The original v1.3 heuristic flagged ANY name queried 20+ times as
        # DNS_HIGH_RETRY, but legitimate short-TTL CDN re-resolutions (e.g.
        # Cloudflare/Edge update endpoints) routinely hit 20+ in a 30-second
        # capture. Now we look at the RCODE distribution:
        #   - high count + mostly NXDOMAIN (rcode=3) → DNS_HIGH_RETRY_NXDOMAIN
        #     (HIGH severity — classic beacon DGA pattern)
        #   - high count + mostly NOERROR → DNS_HIGH_RETRY (LOW severity — just
        #     a chatty short-TTL endpoint; informational, not alarming)
        #   - high count + no RCODE data (UDP responses lost / pure query log)
        #     → DNS_HIGH_RETRY (LOW — can't distinguish without responses)
        cnt = self.query_counts[qname]
        if cnt >= DNS_HIGH_RETRY_THRESHOLD:
            rcodes = self.rcode_counts.get(qname, {})
            total_responses = sum(rcodes.values())
            nxdomain_responses = rcodes.get(3, 0)
            if total_responses > 0 and nxdomain_responses / total_responses >= 0.5:
                self.flags_by_name[qname].append(
                    f"DNS_HIGH_RETRY_NXDOMAIN_{cnt}")
            else:
                self.flags_by_name[qname].append(f"DNS_HIGH_RETRY_{cnt}")

    def suspicious_summary(self):
        """Return rows for the HTML report: list of dicts."""
        rows = []
        flags = self.analyze()
        for qname, fl in flags.items():
            rows.append({
                "qname": qname,
                "count": self.query_counts.get(qname, 0),
                "flags": fl,
            })
        rows.sort(key=lambda r: (-len(r["flags"]), -r["count"], r["qname"]))
        return rows


# === Packet capture wrapper (pktmon / tcpdump) ===

class PacketCapture:
    """Wraps Windows pktmon or Linux tcpdump for the duration of the monitor."""

    def __init__(self, duration, console):
        self.duration = duration
        self.console = console
        self.tool = self._detect_tool()
        self.capture_path = None
        self.proc = None
        self._etl_path = None

    def _detect_tool(self):
        if sys.platform == "win32" and shutil.which("pktmon"):
            return "pktmon"
        if shutil.which("tcpdump"):
            return "tcpdump"
        return None

    def available(self):
        return self.tool is not None

    def start(self):
        if not self.tool:
            return False
        tmp = tempfile.mkdtemp(prefix="netmon_")
        if self.tool == "pktmon":
            self._etl_path = os.path.join(tmp, "capture.etl")
            self.capture_path = os.path.join(tmp, "capture.pcapng")
            try:
                # BUG-1 fix (v1.3): clear any pre-existing filter so we capture
                # traffic on ALL ports, not just 53/80/443. The Load Packets
                # feature was unusable for any service on a non-standard port
                # (sshd:22, mysql:3306, redis:6379, …). With --pkt-size 512
                # truncating each packet the storage cost stays bounded.
                subprocess.run(["pktmon", "filter", "remove"], capture_output=True, timeout=10, check=False)
                subprocess.run(
                    ["pktmon", "start", "--capture", "--file", self._etl_path,
                     "--pkt-size", "512", "--file-size", "512"],
                    capture_output=True, text=True, timeout=15, check=False,
                )
                return True
            except (OSError, subprocess.SubprocessError) as e:
                log.warning("pktmon start failed: %s", e)
                self.console.print(f"[yellow]Capture start failed:[/yellow] {e}")
                return False
        if self.tool == "tcpdump":
            self.capture_path = os.path.join(tmp, "capture.pcap")
            # BUG-1 fix (v1.3): no port filter — capture every TCP/UDP packet.
            # The Load Packets feature in the HTML now works for ALL services
            # (sshd, databases, custom apps) instead of just the v1.2 hard-
            # coded triple 53/80/443. Default snaplen 512 bounds per-pkt cost.
            cmd = [
                "tcpdump", "-i", "any", "-w", self.capture_path,
                "-G", str(self.duration), "-W", "1", "-s", "512", "-q", "-nn",
                "(tcp or udp)",
            ]
            try:
                self.proc = subprocess.Popen(
                    cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                return True
            except (OSError, subprocess.SubprocessError) as e:
                log.warning("tcpdump start failed: %s", e)
                self.console.print(f"[yellow]tcpdump failed:[/yellow] {e}")
                return False
        return False

    def stop(self):
        if not self.tool:
            return None
        if self.tool == "pktmon":
            try:
                subprocess.run(["pktmon", "stop"], capture_output=True, timeout=15, check=False)
                subprocess.run(
                    ["pktmon", "etl2pcap", self._etl_path, "--out", self.capture_path],
                    capture_output=True, timeout=30, check=False,
                )
                if os.path.exists(self.capture_path):
                    return self.capture_path
            except (OSError, subprocess.SubprocessError) as e:
                log.warning("pktmon stop/convert failed: %s", e)
                self.console.print(f"[yellow]pktmon stop/convert failed:[/yellow] {e}")
            return None
        if self.tool == "tcpdump":
            if self.proc:
                try:
                    self.proc.wait(timeout=self.duration + 5)
                except subprocess.TimeoutExpired:
                    self.proc.terminate()
                    self.proc.wait(timeout=5)
            return self.capture_path if os.path.exists(self.capture_path) else None
        return None


# === Code-signing verification (Windows Authenticode) ===

class SignatureChecker:
    """Authenticode signature results, cached per path. Batched via one PowerShell call."""

    SKIPPED: ClassVar[dict] = {"signed": False, "publisher": None, "status": "skipped", "trusted": False}
    UNKNOWN: ClassVar[dict] = {"signed": False, "publisher": None, "status": "unknown", "trusted": False}

    def __init__(self, enabled=True):
        self.enabled = enabled and sys.platform == "win32"
        self.cache = {}

    def get(self, path):
        if not self.enabled or not path or path in ("N/A", "Access Denied"):
            return dict(self.SKIPPED)
        return self.cache.get(path, dict(self.UNKNOWN))

    @staticmethod
    def _is_safe_path(path):
        """Reject paths containing characters that would break our stdin protocol.

        NTFS already prohibits these in filenames, but defense-in-depth: a path
        with embedded `\\n` would be split into two lines by PowerShell's
        ReadLine(), causing a phantom path to be checked.
        """
        if not path or len(path) > 4096:
            return False
        return not any(c in path for c in PATH_FORBIDDEN_CHARS)

    def batch_check(self, paths):
        """Verify many paths in a single PowerShell invocation."""
        if not self.enabled:
            return
        candidates = {p for p in paths if p and p not in ("N/A", "Access Denied")}
        unique = []
        for p in candidates:
            if p in self.cache:
                continue
            if not self._is_safe_path(p):
                log.warning("signing: refusing unsafe path %r", p)
                self.cache[p] = dict(self.UNKNOWN)
                continue
            try:
                if os.path.isfile(p):
                    unique.append(p)
            except OSError as e:
                log.debug("signing: stat failed for %s: %s", p, e)
        if not unique:
            return
        # Pass paths via stdin (length-safe, no shell parsing). The script reads
        # one path per line; `_is_safe_path` already rejected any embedded NL.
        ps_script = (
            "$ErrorActionPreference='SilentlyContinue';"
            "while(($line = [Console]::In.ReadLine()) -ne $null) {"
            "  if(-not $line){continue};"
            "  $s = Get-AuthenticodeSignature -LiteralPath $line;"
            "  $pub = '';"
            "  if($s.SignerCertificate){$pub = $s.SignerCertificate.Subject};"
            "  Write-Output ($line + '|' + $s.Status.ToString() + '|' + $pub)"
            "}"
        )
        try:
            out = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
                input="\n".join(unique) + "\n",
                capture_output=True, text=True, timeout=SIG_CHECK_TIMEOUT, check=False,
            )
            for line in (out.stdout or "").splitlines():
                parts = line.split("|", 2)
                if len(parts) < 3:
                    continue
                path, status, subject = parts
                publisher = self._extract_cn_or_o(subject)
                signed = status == "Valid"
                # v1.4 (F3): word-boundary prefix match, not substring-anywhere,
                # so "Discordia Labs" no longer matches "Discord" and an attacker
                # can't self-authorize with a CN that merely contains a trusted
                # token. (Bare-token list entries should become full legal names.)
                pub_l = (publisher or "").strip().lower()
                trusted = signed and any(
                    pub_l == tpl or (
                        pub_l.startswith(tpl) and len(pub_l) > len(tpl)
                        and not pub_l[len(tpl)].isalnum()
                    )
                    for tpl in (tp.lower() for tp in TRUSTED_PUBLISHERS)
                )
                self.cache[path] = {
                    "signed": signed, "publisher": publisher,
                    "status": status, "trusted": trusted,
                }
        except subprocess.TimeoutExpired:
            log.warning("signing: PowerShell batch timed out after %ds", SIG_CHECK_TIMEOUT)
        except (OSError, ValueError) as e:
            log.warning("signing: PowerShell batch failed: %s", e)
        # Anything still missing → unknown (avoids re-running on next call).
        for p in unique:
            self.cache.setdefault(p, dict(self.UNKNOWN))

    @staticmethod
    def _extract_cn_or_o(subject):
        if not subject:
            return None
        m = re.search(r"CN=([^,]+)", subject)
        if m:
            return m.group(1).strip().strip('"')
        m = re.search(r"O=([^,]+)", subject)
        if m:
            return m.group(1).strip().strip('"')
        return subject.strip()


# === Linux distro package-manager trust (T1-1) ===

# Linux packages whose presence in distro repos is a trust signal. Equivalent
# to Windows' TRUSTED_PUBLISHERS — owning-package match against this list lets
# the binary skip UNSIGNED_BINARY / UNSIGNED_OUTBOUND_C2 penalties.
TRUSTED_LINUX_PACKAGES = frozenset({
    # OpenSSH / shell access
    "openssh-server", "openssh-client", "openssh-sftp-server",
    # Web servers
    "apache2", "apache2-bin", "apache", "httpd", "nginx", "nginx-common",
    "lighttpd", "caddy",
    # Databases
    "postgresql", "postgresql-15", "postgresql-16", "mysql-server",
    "mariadb-server", "redis-server", "memcached", "mongodb-org-server",
    # Mail
    "dovecot-core", "postfix", "exim4", "exim4-daemon-light",
    # Network / file sharing
    "samba", "samba-common-bin", "smbd", "nmbd", "cups", "cups-daemon",
    # System / init
    "systemd", "systemd-sysv", "dbus", "dbus-daemon", "avahi-daemon",
    "chrony", "ntp", "openntpd",
    # Security tooling
    "crowdsec", "crowdsec-firewall-bouncer-iptables",
    "crowdsec-firewall-bouncer-nftables",
    "fail2ban", "ufw", "iptables", "nftables", "firewalld",
    # Container / virtualization
    "docker.io", "docker-ce", "containerd", "podman", "lxc", "lxd",
    "qemu-system-x86", "libvirt-daemon-system",
    # Languages / runtimes
    "python3", "python3-minimal", "perl-base", "ruby", "openjdk-17-jre-headless",
    # Core utilities
    "coreutils", "util-linux", "bash", "dash", "tar", "gzip", "less",
})


class LinuxPackageChecker:
    """Linux analogue of SignatureChecker. For each binary path:

    1. Resolves the owning package via dpkg / rpm / pacman / apk.
    2. Verifies integrity vs the package manifest. Mismatch → PACKAGE_TAMPERED.
    3. Maps to a trust verdict in the same shape as Windows Authenticode:
       {signed, publisher, status, trusted}.

    Cached per-path; only enabled on Linux.
    """

    SKIPPED: ClassVar[dict] = {"signed": False, "publisher": None, "status": "skipped", "trusted": False, "tampered": False}
    UNKNOWN: ClassVar[dict] = {"signed": False, "publisher": None, "status": "unknown", "trusted": False, "tampered": False}

    def __init__(self, enabled=True):
        self.enabled = enabled and sys.platform.startswith("linux")
        self.cache = {}
        self._distro = self._detect_distro() if self.enabled else None

    @staticmethod
    def _detect_distro():
        """Return one of 'debian' / 'rpm' / 'arch' / 'alpine' / None."""
        # Prefer the actual tool presence — some Debian-derived systems may have
        # rpm installed too, but dpkg is authoritative when /var/lib/dpkg exists.
        if shutil.which("dpkg") and os.path.isdir("/var/lib/dpkg"):
            return "debian"
        if shutil.which("rpm"):
            return "rpm"
        if shutil.which("pacman"):
            return "arch"
        if shutil.which("apk"):
            return "alpine"
        return None

    def get(self, path):
        if not self.enabled or not path or path in ("N/A", "Access Denied"):
            return dict(self.SKIPPED)
        return self.cache.get(path, dict(self.UNKNOWN))

    @staticmethod
    def _is_safe_path(path):
        if not path or len(path) > 4096:
            return False
        return not any(c in path for c in PATH_FORBIDDEN_CHARS)

    def batch_check(self, paths):
        """Resolve each unique path. We don't actually batch into one
        subprocess (the package tools take a path per invocation), but we do
        cache + skip duplicates."""
        if not self.enabled or not self._distro:
            return
        candidates = {p for p in paths if p and p not in ("N/A", "Access Denied")}
        for p in candidates:
            if p in self.cache:
                continue
            if not self._is_safe_path(p):
                log.warning("pkg-check: refusing unsafe path %r", p)
                self.cache[p] = dict(self.UNKNOWN)
                continue
            try:
                if not os.path.isfile(p):
                    self.cache[p] = dict(self.UNKNOWN)
                    continue
            except OSError:
                self.cache[p] = dict(self.UNKNOWN)
                continue
            self.cache[p] = self._lookup(p)

    def _lookup(self, path):
        try:
            if self._distro == "debian":
                return self._lookup_debian(path)
            if self._distro == "rpm":
                return self._lookup_rpm(path)
            if self._distro == "arch":
                return self._lookup_arch(path)
            if self._distro == "alpine":
                return self._lookup_alpine(path)
        except (OSError, subprocess.SubprocessError) as e:
            log.debug("pkg-check failed for %s: %s", path, e)
        return dict(self.UNKNOWN)

    def _run(self, cmd, timeout=10):
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False,
        )

    def _verdict(self, package, tampered):
        """Wrap a package-name + tampered-bool into the standard signature
        dict shape (signed/publisher/status/trusted) so the rest of the code
        path doesn't need to special-case Linux."""
        if not package:
            return {"signed": False, "publisher": None, "status": "unpackaged",
                    "trusted": False, "tampered": False}
        if tampered:
            return {"signed": True, "publisher": package, "status": "tampered",
                    "trusted": False, "tampered": True}
        trusted = package.lower() in TRUSTED_LINUX_PACKAGES
        return {"signed": True, "publisher": package,
                "status": f"pkg:{package}", "trusted": trusted, "tampered": False}

    def _lookup_debian(self, path):
        # dpkg -S returns "<pkg>: <path>"; multiple packages possible if file
        # belongs to several. We take the first.
        r = self._run(["dpkg", "-S", path])
        if r.returncode != 0 or not r.stdout.strip():
            return self._verdict(None, False)
        pkg = r.stdout.split(":", 1)[0].strip().split(",")[0].strip()
        if not pkg:
            return self._verdict(None, False)
        # Verify integrity. `dpkg -V <pkg>` prints nothing on clean, lines
        # like "??5?????? c /etc/foo" on mismatch (5 = md5 sum diff).
        verify = self._run(["dpkg", "-V", pkg], timeout=20)
        tampered = False
        for raw in (verify.stdout or "").splitlines():
            stripped = raw.rstrip()
            if not stripped:
                continue
            # Skip config files marked 'c' (operator-edited /etc/ is normal).
            cols = stripped.split()
            if len(cols) >= 2 and cols[1] == "c":
                continue
            # 5 in the first column = md5 mismatch on a non-config file.
            if cols and "5" in cols[0]:
                tampered = True
                break
        return self._verdict(pkg, tampered)

    def _lookup_rpm(self, path):
        r = self._run(["rpm", "-qf", "--queryformat", "%{NAME}", path])
        if r.returncode != 0 or not r.stdout.strip():
            return self._verdict(None, False)
        # "not owned by any package" message goes to stderr, returncode=1
        pkg = r.stdout.strip().split("\n")[0]
        if pkg.startswith("file ") and "not owned" in pkg:
            return self._verdict(None, False)
        verify = self._run(["rpm", "-V", pkg], timeout=20)
        tampered = False
        for raw in (verify.stdout or "").splitlines():
            stripped = raw.rstrip()
            if not stripped:
                continue
            cols = stripped.split()
            # Config files start with 'c'; skip them.
            if len(cols) >= 2 and cols[1] == "c":
                continue
            # First column "S.5...." — '5' anywhere in the verify flags = md5
            # mismatch on a non-config file.
            if cols and "5" in cols[0]:
                tampered = True
                break
        return self._verdict(pkg, tampered)

    def _lookup_arch(self, path):
        r = self._run(["pacman", "-Qo", path])
        if r.returncode != 0 or not r.stdout.strip():
            return self._verdict(None, False)
        # Output: "/usr/bin/sshd is owned by openssh 9.0p1-1"
        m = re.search(r"owned by (\S+)", r.stdout)
        if not m:
            return self._verdict(None, False)
        pkg = m.group(1)
        # pacman -Qkk verifies integrity; "0 altered files" = clean.
        verify = self._run(["pacman", "-Qkk", pkg], timeout=20)
        tampered = "altered" in (verify.stdout or "").lower() and " 0 " not in (verify.stdout or "")
        return self._verdict(pkg, tampered)

    def _lookup_alpine(self, path):
        r = self._run(["apk", "info", "--who-owns", path])
        if r.returncode != 0 or not r.stdout.strip():
            return self._verdict(None, False)
        # Output: "/usr/sbin/sshd is owned by openssh-server-9.7_p1-r4"
        m = re.search(r"owned by (\S+)", r.stdout)
        if not m:
            return self._verdict(None, False)
        pkg = m.group(1)
        # apk has no per-package verify equivalent that's quick + scriptable;
        # `apk audit --packages` is global. Skip tamper detection for Alpine
        # to avoid a multi-second wait per run.
        return self._verdict(pkg, False)


# === macOS code-signing checker (T1-4) ===

# Apple-shipped Authority subjects we trust outright. Apple Developer IDs
# also pass once the cert chain anchors to Apple Root CA.
TRUSTED_MACOS_SIGNERS = (
    "Software Signing",
    "Apple Mac OS Application Signing",
    "Developer ID Application: Mozilla Corporation",
    "Developer ID Application: Google",
    "Developer ID Application: Microsoft Corporation",
    "Developer ID Application: Anthropic",
    "Developer ID Application: GitHub",
    "Developer ID Application: JetBrains",
    "Developer ID Application: Docker",
    "Developer ID Application: Homebrew",
)


class MacOSSignatureChecker:
    """codesign / spctl wrapper for macOS, same shape as SignatureChecker."""

    SKIPPED: ClassVar[dict] = {"signed": False, "publisher": None, "status": "skipped", "trusted": False}
    UNKNOWN: ClassVar[dict] = {"signed": False, "publisher": None, "status": "unknown", "trusted": False}

    def __init__(self, enabled=True):
        self.enabled = enabled and sys.platform == "darwin" and bool(shutil.which("codesign"))
        self.cache = {}

    def get(self, path):
        if not self.enabled or not path or path in ("N/A", "Access Denied"):
            return dict(self.SKIPPED)
        return self.cache.get(path, dict(self.UNKNOWN))

    @staticmethod
    def _is_safe_path(path):
        if not path or len(path) > 4096:
            return False
        return not any(c in path for c in PATH_FORBIDDEN_CHARS)

    def batch_check(self, paths):
        if not self.enabled:
            return
        for p in {p for p in paths if p and p not in ("N/A", "Access Denied")}:
            if p in self.cache:
                continue
            if not self._is_safe_path(p):
                log.warning("codesign: refusing unsafe path %r", p)
                self.cache[p] = dict(self.UNKNOWN)
                continue
            try:
                if not os.path.isfile(p):
                    self.cache[p] = dict(self.UNKNOWN)
                    continue
            except OSError:
                self.cache[p] = dict(self.UNKNOWN)
                continue
            self.cache[p] = self._verify(p)

    def _verify(self, path):
        try:
            r = subprocess.run(
                ["codesign", "-dv", "--verbose=4", path],
                capture_output=True, text=True, timeout=10, check=False,
            )
            # codesign emits the cert chain on stderr; stdout is usually empty.
            text = (r.stderr or "") + "\n" + (r.stdout or "")
            if "not signed at all" in text or (r.returncode == 1 and "code object is not signed" in text):
                return {"signed": False, "publisher": None,
                        "status": "NotSigned", "trusted": False}
            authority = None
            for line in text.splitlines():
                if line.startswith("Authority="):
                    authority = line.split("=", 1)[1].strip()
                    break
            if not authority:
                return {"signed": False, "publisher": None,
                        "status": "unknown", "trusted": False}
            # Verify integrity (-v checks the signature seals the binary).
            verify = subprocess.run(
                ["codesign", "--verify", "--deep", path],
                capture_output=True, text=True, timeout=10, check=False,
            )
            if verify.returncode != 0:
                return {"signed": False, "publisher": authority,
                        "status": "InvalidSignature", "trusted": False}
            trusted = any(t in authority for t in TRUSTED_MACOS_SIGNERS)
            return {"signed": True, "publisher": authority,
                    "status": "Valid", "trusted": trusted}
        except (OSError, subprocess.SubprocessError) as e:
            log.debug("codesign failed for %s: %s", path, e)
            return dict(self.UNKNOWN)


# === Server-binary role registry (T1-3) ===
# Binaries that are EXPECTED to listen and accept inbound connections. When
# a process from this list has an inbound connection on (one of) its standard
# port(s), C2-style flags are suppressed.

SERVER_BINARY_ROLES = {
    # binary basename -> set of standard listen ports
    "sshd":             {22},
    "apache2":          {80, 443, 8080, 8443},
    "apache":           {80, 443, 8080, 8443},
    "httpd":            {80, 443, 8080, 8443},
    "nginx":            {80, 443, 8080, 8443},
    "lighttpd":         {80, 443},
    "caddy":            {80, 443, 2019},
    "postgres":         {5432},
    "postgresql":       {5432},
    "mysqld":           {3306},
    "mariadbd":         {3306},
    "redis-server":     {6379},
    "memcached":        {11211},
    "mongod":           {27017},
    "dovecot":          {110, 143, 993, 995},
    "postfix":          {25, 465, 587},
    "exim4":            {25, 465, 587},
    "smbd":             {139, 445},
    "nmbd":             {137, 138},
    "cupsd":            {631},
    "crowdsec":         {8080, 6060},
    "crowdsec-firewall-bouncer": set(),  # no listener role; out-of-band
    "systemd-resolved": {53, 5355},
    "systemd-networkd": set(),
    "avahi-daemon":     {5353},
    "chronyd":          {123, 323},
    "ntpd":             {123},
    "named":            {53},
    "unbound":          {53},
}


def _normalize_app_name(app_name):
    """Lowercase + strip a trailing '.exe' suffix without using rstrip
    (which would strip any characters in the set '.exe', mangling names
    like 'nginx' → 'ngin')."""
    if not app_name:
        return ""
    name = app_name.lower()
    if name.endswith(".exe"):
        name = name[:-4]
    return name


def is_server_binary(app_name):
    """Return True if the executable basename is a known server role."""
    return _normalize_app_name(app_name) in SERVER_BINARY_ROLES


def server_expected_port(app_name, port):
    """Return True if `port` is one of the server's known-good listen ports."""
    if not app_name or port is None:
        return False
    role = SERVER_BINARY_ROLES.get(_normalize_app_name(app_name))
    if role is None:
        return False
    return port in role


# === Direction classification (T1-2) ===

def _read_linux_ephemeral_range():
    """Read /proc/sys/net/ipv4/ip_local_port_range. Default if unreadable."""
    try:
        with open("/proc/sys/net/ipv4/ip_local_port_range") as f:
            parts = f.read().split()
            if len(parts) == 2:
                lo, hi = int(parts[0]), int(parts[1])
                if 1 <= lo <= 65535 and lo <= hi <= 65535:
                    return lo, hi
    except (OSError, ValueError):
        pass
    return 32768, 60999  # Linux default since ~2.6


# Cache the kernel's ephemeral range once per process — it's a sysctl, not
# something that changes during a run.
_EPHEMERAL_LO, _EPHEMERAL_HI = (
    _read_linux_ephemeral_range() if sys.platform.startswith("linux")
    else (49152, 65535)  # IANA / Windows default
)


def _is_ephemeral_port(port):
    if port is None:
        return False
    return _EPHEMERAL_LO <= port <= _EPHEMERAL_HI


def classify_direction(local, remote, status):
    """Return 'INBOUND' / 'OUTBOUND' / 'LOOPBACK' / 'LISTEN' / 'AMBIGUOUS' / None.

    Direction heuristic, tried in order:
      1. The side holding the ephemeral port (per the OS sysctl range) is the
         client; the other side is the server.
      2. Failing that, the side with a well-known port (< 1024) is the server.
      3. Tie-breaker: the larger port wins as the client side.

    The cascading rules let us classify both clear (sshd accepts inbound :22)
    and ambiguous (45000 → 443 on Windows where 45000 sits below the default
    ephemeral floor of 49152) cases without losing the v1.2 default for
    ordinary outbound HTTPS.
    """
    if not remote:
        return "LISTEN" if (status or "").upper() in ("LISTEN", "NONE") else None
    # Extract ports
    def _port(addr):
        if not addr:
            return None
        try:
            if addr.startswith("["):
                return int(addr.split("]:", 1)[1])
            return int(addr.rsplit(":", 1)[1])
        except (ValueError, IndexError):
            return None

    def _ip(addr):
        if not addr:
            return None
        if addr.startswith("["):
            return addr.split("]")[0][1:]
        parts = addr.rsplit(":", 1)
        return parts[0] if len(parts) == 2 else None

    remote_ip = _ip(remote)
    if remote_ip and (remote_ip.startswith("127.") or remote_ip == "::1"
                      or remote_ip.startswith("::ffff:127.")):
        return "LOOPBACK"

    lport = _port(local)
    rport = _port(remote)
    if lport is None or rport is None:
        return "AMBIGUOUS"
    l_eph = _is_ephemeral_port(lport)
    r_eph = _is_ephemeral_port(rport)
    if l_eph and not r_eph:
        return "OUTBOUND"
    if r_eph and not l_eph:
        return "INBOUND"
    # Cascade 2: well-known service port (< 1024). Whoever owns it is the server.
    if rport < 1024 <= lport:
        return "OUTBOUND"
    if lport < 1024 <= rport:
        return "INBOUND"
    # v1.4 (F1): removed the port-magnitude tiebreak. It mislabeled outbound-to-
    # high-port C2 (e.g. :50050) as INBOUND — suppressing UNSIGNED_OUTBOUND_C2 —
    # and inbound-from-low-ephemeral as OUTBOUND (false C2). When both ports sit
    # in the same window we genuinely cannot tell from ports alone → AMBIGUOUS
    # (which still allows the now-weak unsigned-outbound signal to surface it).
    return "AMBIGUOUS"


# === CrowdSec integration (T2-1) ===

class CrowdSecClient:
    """Query the local CrowdSec Local API for IP verdicts.

    Probes 127.0.0.1:8080 first (default LAPI port); if reachable and an API
    token is provided (--crowdsec-token, $CROWDSEC_LAPI_KEY, or auto-detected
    from /etc/crowdsec/local_api_credentials.yaml), looks up each public IP.

    No external network calls — CrowdSec runs on the same host.
    """

    DEFAULT_HOST = "127.0.0.1"
    DEFAULT_PORT = 8080

    def __init__(self, token=None, host=None, port=None, console=None):
        self.console = console
        self.host = host or self.DEFAULT_HOST
        self.port = port or self.DEFAULT_PORT
        self.token = token or os.environ.get("CROWDSEC_LAPI_KEY") or self._read_local_creds()
        self.cache = {}
        self.enabled = bool(self.token) and self._probe_heartbeat()

    def _read_local_creds(self):
        """Parse /etc/crowdsec/local_api_credentials.yaml for the password
        (used as the API key for the local LAPI). Best effort — file is root-
        only by default, so this works when netmon is invoked as root."""
        path = "/etc/crowdsec/local_api_credentials.yaml"
        try:
            if not os.path.isfile(path):
                return None
            with open(path) as f:
                for raw in f:
                    stripped = raw.strip()
                    # password: <hex>
                    m = re.match(r"^password:\s*(\S+)\s*$", stripped)
                    if m:
                        return m.group(1).strip().strip('"').strip("'")
        except OSError:
            return None
        return None

    def _probe_heartbeat(self):
        """Cheap one-shot probe — bail quickly if no CrowdSec listening."""
        try:
            r = requests.get(
                f"http://{self.host}:{self.port}/v1/heartbeat",
                headers={"X-Api-Key": self.token},
                timeout=2,
            )
            return r.status_code in (200, 401, 403)
        except requests.RequestException:
            return False

    def lookup(self, ip):
        """Return one of: 'clean' / 'ban' / 'captcha' / 'throttle' / None."""
        if not self.enabled or not ip:
            return None
        if ip in self.cache:
            return self.cache[ip]
        # Skip lookups for private / loopback IPs — CrowdSec wouldn't have
        # opinions about LAN endpoints anyway.
        if classify_local_ip(ip) is not None:
            self.cache[ip] = None
            return None
        try:
            r = requests.get(
                f"http://{self.host}:{self.port}/v1/decisions",
                headers={"X-Api-Key": self.token},
                params={"ip": ip},
                timeout=3,
            )
            if r.status_code != 200:
                self.cache[ip] = None
                return None
            decisions = r.json() or []
            if not decisions:
                self.cache[ip] = "clean"
                return "clean"
            # If any decision is active, take the strictest action.
            actions = {(d.get("type") or "").lower() for d in decisions}
            for verdict in ("ban", "captcha", "throttle"):
                if verdict in actions:
                    self.cache[ip] = verdict
                    return verdict
            self.cache[ip] = "ban"  # unknown action, treat conservatively
            return "ban"
        except (requests.RequestException, ValueError) as e:
            log.debug("crowdsec lookup failed for %s: %s", ip, e)
            self.cache[ip] = None
            return None


# === systemd unit attribution (T2-2) ===

def systemd_unit_for_pid(pid):
    """Resolve a PID to its owning systemd unit by reading /proc/<pid>/cgroup.

    Linux-only; returns None on other platforms or unmapped PIDs.

    Format (cgroup v2):
      0::/system.slice/sshd.service
      0::/user.slice/user-1000.slice/session-2.scope
    """
    if not sys.platform.startswith("linux") or not pid:
        return None
    try:
        with open(f"/proc/{int(pid)}/cgroup") as f:
            content = f.read()
    except (OSError, ValueError):
        return None
    # Look for system.slice/<unit>.service or user@*/app.slice/<unit>.service
    for line in content.splitlines():
        # Each line is "hierarchy:controller:path"
        parts = line.split(":", 2)
        if len(parts) != 3:
            continue
        path = parts[2]
        m = re.search(r"/([^/]+\.service)(?:/|$)", path)
        if m:
            return m.group(1)
        m = re.search(r"/([^/]+\.scope)(?:/|$)", path)
        if m:
            return m.group(1)
    return None


# === Firewall state inspection (T2-3) ===

class FirewallState:
    """Snapshot of the host firewall — per-port allow/deny verdict.

    Reads ufw / iptables-save / nft / Windows NetFirewallRule. Best-effort:
    a "no rules / accept-all" host returns 'allowed' for everything; a
    parse failure returns 'unknown'.
    """

    def __init__(self):
        self.backend = None
        # port -> 'allowed' / 'blocked' / 'lan-only'
        self.rules = {}
        # Map of allowed ports → human description (for display)
        self.descriptions = {}
        # Default chain policy (input). 'allow' if firewall is off / inactive.
        self.default_allow = True
        self._gather()

    def _gather(self):
        if sys.platform.startswith("linux"):
            self._gather_linux()
        elif sys.platform == "win32":
            self._gather_windows()

    def _gather_linux(self):
        # Try ufw first (it's a friendly wrapper on top of iptables/nftables).
        if shutil.which("ufw"):
            try:
                r = subprocess.run(["ufw", "status", "verbose"],
                                   capture_output=True, text=True, timeout=5, check=False)
                out = r.stdout or ""
                if "Status: active" in out:
                    self.backend = "ufw"
                    # Default policy line: "Default: deny (incoming), allow (outgoing), …"
                    if re.search(r"Default:.*deny \(incoming\)", out):
                        self.default_allow = False
                    # Rule lines: "22/tcp                     ALLOW       Anywhere"
                    for line in out.splitlines():
                        m = re.match(r"\s*(\d+)(?:/(tcp|udp))?\s+(ALLOW|DENY|LIMIT)\s+(.+)", line)
                        if m:
                            port = int(m.group(1))
                            verdict = m.group(3)
                            src = m.group(4).strip()
                            if verdict == "ALLOW":
                                # LAN-only if source is restricted to private range
                                lan_only = bool(re.search(
                                    r"(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|fc|fd|fe80:)",
                                    src.lower(),
                                ))
                                self.rules[port] = "lan-only" if lan_only else "allowed"
                                self.descriptions[port] = src
                            elif verdict == "DENY":
                                self.rules[port] = "blocked"
                                self.descriptions[port] = src
                    return
            except (OSError, subprocess.SubprocessError) as e:
                log.debug("ufw probe failed: %s", e)
        # Fall back to nftables / iptables-save: we don't fully parse them;
        # the default-deny / default-allow flag from the chain policies is
        # the most actionable signal.
        if shutil.which("nft"):
            try:
                r = subprocess.run(["nft", "list", "ruleset"],
                                   capture_output=True, text=True, timeout=5, check=False)
                out = r.stdout or ""
                if out.strip():
                    self.backend = "nft"
                    # Look for "policy drop" on chain input
                    if re.search(r"chain input\s*\{[^}]*policy drop", out, re.S | re.I):
                        self.default_allow = False
                    elif re.search(r"chain input\s*\{[^}]*policy accept", out, re.S | re.I):
                        self.default_allow = True
                    return
            except (OSError, subprocess.SubprocessError) as e:
                log.debug("nft probe failed: %s", e)
        if shutil.which("iptables-save"):
            try:
                r = subprocess.run(["iptables-save"],
                                   capture_output=True, text=True, timeout=5, check=False)
                out = r.stdout or ""
                if out.strip():
                    self.backend = "iptables"
                    # ":INPUT DROP [0:0]" vs ":INPUT ACCEPT [0:0]"
                    m = re.search(r"^:INPUT (\w+)", out, re.M)
                    if m:
                        self.default_allow = m.group(1).upper() == "ACCEPT"
                    return
            except (OSError, subprocess.SubprocessError) as e:
                log.debug("iptables-save probe failed: %s", e)

    def _gather_windows(self):
        """Use PowerShell Get-NetFirewallProfile to determine the default
        inbound action. Per-port rule enumeration is heavy and most users
        rely on the profile default."""
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                 "Get-NetFirewallProfile -Profile Domain,Private,Public | "
                 "Select-Object Name,Enabled,DefaultInboundAction | ConvertTo-Json -Compress"],
                capture_output=True, text=True, timeout=10, check=False,
            )
            if r.returncode != 0 or not r.stdout.strip():
                return
            self.backend = "netsh"
            data = json.loads(r.stdout)
            if isinstance(data, dict):
                data = [data]
            # If ANY active profile blocks inbound, treat default as deny.
            self.default_allow = True
            for profile in data:
                enabled = profile.get("Enabled") in (True, 1, "True")
                action = (profile.get("DefaultInboundAction") or "").lower()
                if enabled and action in ("block", "2"):
                    self.default_allow = False
                    break
        except (OSError, subprocess.SubprocessError, ValueError, json.JSONDecodeError) as e:
            log.debug("Windows firewall probe failed: %s", e)

    def verdict_for_port(self, port):
        """Return 'allowed' / 'blocked' / 'lan-only' / 'unknown' for the port."""
        if not self.backend:
            return "unknown"
        if port in self.rules:
            return self.rules[port]
        # No explicit rule — fall back to default chain policy.
        return "allowed" if self.default_allow else "blocked"


# === Threat intel: Tor exits, ipwhois enrichment ===

def _safe_cache_dir():
    """Return a per-user cache dir with mode 0700 (best effort).

    On a multi-user host, /tmp is world-writable; another local user could
    pre-create our cache dir and seed it with poisoned files. We use a
    user-specific subdirectory under the tempdir and chmod to 0700 on POSIX.
    """
    base = Path(tempfile.gettempdir()) / f"netmon_cache_{os.getuid() if hasattr(os, 'getuid') else os.getlogin()}"
    try:
        base.mkdir(mode=0o700, exist_ok=True)
        # Refuse a pre-seeded / symlinked / someone-else's directory — that is
        # exactly the poisoning this function exists to prevent. Fall back to a
        # fresh private mkdtemp we created ourselves.
        st = os.lstat(base)
        bad = stat_mod.S_ISLNK(st.st_mode) or not stat_mod.S_ISDIR(st.st_mode)
        if hasattr(os, "getuid") and st.st_uid != os.getuid():
            bad = True
        if bad:
            base = Path(tempfile.mkdtemp(prefix="netmon_cache_"))
    except OSError:
        try:
            base = Path(tempfile.mkdtemp(prefix="netmon_cache_"))
        except OSError:
            base = Path(tempfile.gettempdir())
    if hasattr(os, "chmod"):
        try:
            os.chmod(base, 0o700)
        except OSError:
            pass
    return base


def _is_valid_ip(s):
    """Return True iff s is a syntactically valid IPv4 or IPv6 address."""
    if not s or len(s) > 45:
        return False
    try:
        socket.inet_pton(socket.AF_INET, s)
        return True
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, s)
        return True
    except OSError:
        return False


def listener_exposure_level(local_addr):
    """Return the exposure SEVERITY of a listener for visual highlighting:
       'any'      — bound to 0.0.0.0 / [::] (reachable from any IP that can
                    reach this host: LAN + possibly internet) → RED
       'lan'      — bound to a specific LAN/link-local interface (reachable
                    from any host on that LAN segment) → AMBER
       'loopback' — bound to 127.x or ::1 (only this host can connect) → safe
       None       — not a listener (caller should skip)
    """
    if not local_addr:
        return None
    if local_addr.startswith("["):
        ip = local_addr.split("]")[0][1:]
    else:
        ip = local_addr.rsplit(":", 1)[0]
    if ip in ("0.0.0.0", "::", "[::]"):  # nosec B104 - exposure detection, not bind
        return "any"
    if ip.startswith("127.") or ip == "::1":
        return "loopback"
    if ip.startswith("169.254.") or ip.lower().startswith("fe80:"):
        return "lan"  # link-local is still LAN-reachable
    octets = ip.split(".")
    if len(octets) == 4:
        try:
            o0, o1 = int(octets[0]), int(octets[1])
            if o0 == 10 or (o0 == 172 and 16 <= o1 <= 31) or (o0 == 192 and o1 == 168):
                return "lan"
        except ValueError:
            pass
    if ip.lower().startswith(("fc", "fd")):
        return "lan"
    # Public IP bind on a listener — extremely unusual, treat as 'any'.
    return "any"


def describe_listener_exposure(local_addr):
    """Given a local listener address like '0.0.0.0:445' or '127.0.0.1:11434',
    return a short human label of which interfaces the socket is exposed on.

    The exposure level matters for triage: a listener on 0.0.0.0 is reachable
    from every IP that can reach the host (LAN + maybe internet), while a
    listener on 127.0.0.1 is reachable only from the host itself.
    """
    if not local_addr:
        return "listening"
    # Strip port; handle bracketed IPv6.
    if local_addr.startswith("["):
        ip = local_addr.split("]")[0][1:]
    else:
        ip = local_addr.rsplit(":", 1)[0]
    if ip in ("0.0.0.0",):  # nosec B104 - exposure description, not bind
        return "listening — exposed on ANY IPv4 interface"
    if ip in ("::", "[::]"):
        return "listening — exposed on ANY IPv6 interface"
    if ip.startswith("127.") or ip == "::1":
        return "listening — loopback only (this host)"
    if ip.startswith("169.254.") or ip.lower().startswith("fe80:"):
        return "listening — link-local interface only"
    octets = ip.split(".")
    if len(octets) == 4:
        try:
            o0, o1 = int(octets[0]), int(octets[1])
            if o0 == 10 or (o0 == 172 and 16 <= o1 <= 31) or (o0 == 192 and o1 == 168):
                return f"listening — LAN interface ({ip})"
        except ValueError:
            pass
    return f"listening — interface {ip}"


def _fmt_age(seconds):
    """Human-readable age string ('3.2s' / '4h 22m' / '2d 1h')."""
    try:
        s = float(seconds)
    except (TypeError, ValueError):
        return "—"
    if s < 0:
        s = 0.0
    if s < 60:
        return f"{s:.1f}s"
    if s < 3600:
        return f"{int(s // 60)}m {int(s % 60)}s"
    if s < 86400:
        return f"{int(s // 3600)}h {int((s % 3600) // 60)}m"
    return f"{int(s // 86400)}d {int((s % 86400) // 3600)}h"


# === v1.3: Suspicious command-line detection (F-5.1) ========================

# Patterns that indicate an attacker dropping a payload or executing
# obfuscated code on the host. Each entry: (regex, flag-suffix, severity).
SUSPICIOUS_CMDLINE_PATTERNS = [
    # PowerShell encoded / hidden execution. We allow ANY characters between
    # the binary name and the target flag (other flags/values) because real
    # cmdlines look like 'powershell.exe -nop -w hidden -enc AAAA'.
    # -EncodedCommand accepts ANY unambiguous prefix down to bare -e, so match
    # -e[a-z]* followed by a long base64 payload (v1.4 F8 — the old regex missed
    # the ubiquitous `powershell -e <b64>` / `-en` / `-enco` forms).
    (re.compile(r"(?i)\bpowershell(?:\.exe)?\b[^|;]*?\s-e[a-z]*\b\s+[A-Za-z0-9+/=]{16,}"),
     "PS_ENCODED",     "HIGH"),
    (re.compile(r"(?i)\bpowershell(?:\.exe)?\b[^|;]*?\s-w(?:indowstyle)?\s+hidden\b"),
     "PS_HIDDEN",      "HIGH"),
    (re.compile(r"(?i)(?:iex|invoke-expression)\s*\(\s*new-object\s+net\.webclient\)\."),
     "PS_DOWNLOAD",    "HIGH"),
    (re.compile(r"(?i)(?:iex|invoke-expression)\s*\(\s*\[?\s*system\.text\.encoding"),
     "PS_DECODE_EXEC", "HIGH"),
    (re.compile(r"(?i)\bfrombase64string\b"),
     "PS_FROMBASE64",  "HIGH"),
    # Living-off-the-land binaries used for download
    (re.compile(r"(?i)\bcertutil(?:\.exe)?\s+(?:-[a-z]+\s+)*-urlcache\b"),
     "CERTUTIL_DOWNLOAD", "HIGH"),
    (re.compile(r"(?i)\bbitsadmin(?:\.exe)?\s+(?:/[a-z]+\s+)*\b/transfer\b"),
     "BITSADMIN_TRANSFER", "HIGH"),
    (re.compile(r"(?i)\bmshta(?:\.exe)?\s+(?:javascript:|vbscript:|https?://)"),
     "MSHTA_HTTP",     "HIGH"),
    # Only flag rundll32 when paired with a suspicious indicator (URL / script
    # scheme / temp path) — the bare `dll,Export` form is normal Windows usage
    # and flagging it was a constant false positive (v1.4 R5).
    (re.compile(r"(?i)\brundll32(?:\.exe)?\s+.*(?:javascript:|vbscript:|https?://|\\appdata\\|\\windows\\temp\\|\\users\\public\\|/tmp/)"),
     "RUNDLL32_SUSPICIOUS", "MED"),
    (re.compile(r"(?i)\bregsvr32(?:\.exe)?\s+(?:/[a-z]+\s+)*/i:https?://"),
     "REGSVR32_HTTP",  "HIGH"),
    # Curl/wget piped into a shell — classic dropper
    (re.compile(r"(?i)\b(?:curl|wget)\s+[^|]+\|\s*(?:bash|sh|zsh|powershell)"),
     "DOWNLOAD_PIPE_SHELL", "HIGH"),
    (re.compile(r"(?i)\bbash\s+-c\s+[\"']\$\(\s*(?:curl|wget)\b"),
     "BASH_C_CURL",    "HIGH"),
    # Reverse shell one-liners
    (re.compile(r"(?i)\bbash\s+-i\s+>&\s+/dev/tcp/"),
     "BASH_REV_SHELL", "HIGH"),
    (re.compile(r"(?i)\bnc(?:at)?\s+(?:-[a-z]+\s+)*-e\s+(?:/bin/)?(?:bash|sh|cmd)"),
     "NC_REV_SHELL",   "HIGH"),
    (re.compile(r"(?i)python[23]?\s+-c\s+[\"'][^\"']*socket\.socket[^\"']*subprocess"),
     "PYTHON_REV_SHELL", "HIGH"),
    # Long base64 blob in cmdline (likely encoded payload)
    # Raised 200 -> 300 (v1.4 R5): Chrome/Electron --field-trial-handle and
    # similar handles are ~100-250 chars and were matching. Genuine encoded
    # payloads are typically longer; with the v1.4 corroboration rule a lone
    # LONG_BASE64 no longer reaches HIGH anyway.
    (re.compile(r"[A-Za-z0-9+/]{300,}={0,2}"),
     "LONG_BASE64",    "MED"),
    # WMI lateral movement
    (re.compile(r"(?i)\bwmic\s+.*\bprocess\s+call\s+create\b"),
     "WMIC_PROC_CREATE", "HIGH"),
    # Scheduled-task creation via cmdline
    (re.compile(r"(?i)\bschtasks(?:\.exe)?\s+(?:/[a-z]+\s+)*/create\b"),
     "SCHTASKS_CREATE", "MED"),
]


def analyze_cmdline(cmdline):
    """Return (highest_severity, [flags]) for a process cmdline. cmdline may
    be a list (from psutil) or a single string."""
    if not cmdline:
        return None, []
    if isinstance(cmdline, list):
        text = " ".join(cmdline)
    else:
        text = str(cmdline)
    if len(text) > 16384:
        text = text[:16384]  # bound regex work on pathological argv
    flags = []
    worst = None
    severity_rank = {"HIGH": 2, "MED": 1, "LOW": 0}
    for rx, suffix, sev in SUSPICIOUS_CMDLINE_PATTERNS:
        if rx.search(text):
            flags.append(f"SUSPICIOUS_CMDLINE_{suffix}")
            if worst is None or severity_rank[sev] > severity_rank[worst]:
                worst = sev
    return worst, flags


# === v1.3: Web-shell detection (F-2.x) ======================================

# Process names that constitute "web server runtime" — used by F-2.1 to
# detect spawn anomalies and F-2.5 to flag web-user outbound.
WEB_SERVER_PROCESSES = frozenset({
    "apache2", "apache", "httpd", "nginx", "lighttpd", "caddy",
    "php-fpm", "php-fpm7", "php-fpm8", "php-cgi", "php",
    "w3wp", "w3wp.exe",
    "node", "java", "tomcat", "catalina",
    "gunicorn", "uwsgi", "unicorn", "puma",
})

# Web-user accounts whose outbound network access is suspicious by default.
WEB_USER_ACCOUNTS = frozenset({
    "www-data", "apache", "nginx", "httpd", "_www", "_apache",
    "iusr", "iis apppool", "network service",
    "php-fpm", "tomcat", "jetty",
})

# Shells / interpreters / network tools that should NEVER be a child of a
# web server (F-2.1).
CHILD_PROCESS_BLOCKLIST = frozenset({
    "bash", "sh", "dash", "zsh", "ksh", "csh", "tcsh", "ash",
    "cmd.exe", "cmd", "powershell.exe", "powershell", "pwsh", "pwsh.exe",
    "nc", "ncat", "netcat", "socat",
    "curl", "wget", "rclone",
    "python", "python2", "python3", "perl", "ruby",
    "ssh", "scp", "sftp",
    "whoami", "id", "hostname", "uname",
})

# Regex signatures for known web-shell content. Mostly language-agnostic
# heuristics, plus a few specific-shell fingerprints (Weevely, China Chopper,
# B374K). Patterns are intentionally conservative — false positives on
# legitimate framework code are worse than missing one shell out of ten.
WEBSHELL_SIGNATURES = [
    # === PHP web shells ===
    (re.compile(rb"(?i)\beval\s*\(\s*base64_decode\s*\("),
     "PHP_EVAL_BASE64",  "HIGH"),
    (re.compile(rb"(?i)\beval\s*\(\s*gzinflate\s*\(\s*base64_decode"),
     "PHP_GZINFLATE_B64", "HIGH"),
    (re.compile(rb"(?i)\bassert\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\b"),
     "PHP_ASSERT_INPUT", "HIGH"),
    (re.compile(rb"(?i)\b(?:system|exec|shell_exec|passthru|popen)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\b"),
     "PHP_EXEC_INPUT",   "HIGH"),
    (re.compile(rb"(?i)\bpreg_replace\s*\([^)]*['\"]/e['\"]"),
     "PHP_PREG_E_FLAG",  "HIGH"),
    (re.compile(rb"(?i)\$_(?:GET|POST|REQUEST|COOKIE)\s*\[\s*['\"][a-z0-9_]{1,3}['\"]?\s*\]\s*\(\s*\$_"),
     "PHP_DYNAMIC_FN",   "HIGH"),
    # Weevely-specific marker: small alpha key + base64 in a header / GET arg
    (re.compile(rb"(?i)str_replace\s*\(\s*['\"]\\\\['\"].*?\)\s*\(\s*str_rot13"),
     "WEEVELY_LIKELY",   "HIGH"),
    # China Chopper one-liner
    (re.compile(rb"<%@\s*Page\s+Language=['\"][CcVv][^'\"]*['\"]\s*%>[\s\S]{0,200}Eval\s*\(\s*Request"),
     "CHINA_CHOPPER_ASP", "HIGH"),
    # === ASP/.NET web shells ===
    (re.compile(rb"(?i)<%[^%]{0,200}Eval\s*\(\s*Request\b"),
     "ASP_EVAL_REQUEST", "HIGH"),
    (re.compile(rb"(?i)System\.Diagnostics\.Process\.Start\s*\(\s*Request"),
     "ASPNET_PROC_REQ",  "HIGH"),
    # === JSP web shells ===
    (re.compile(rb"(?i)Runtime\.getRuntime\(\)\.exec\s*\(\s*request\.getParameter"),
     "JSP_RUNTIME_EXEC", "HIGH"),
    (re.compile(rb"(?i)new\s+ProcessBuilder\s*\(\s*request\.getParameter"),
     "JSP_PROC_BUILDER", "HIGH"),
    # === Generic ===
    (re.compile(rb"(?i)\bcmd=\s*[\"'].*?[&\";'].*?exec\b"),
     "GENERIC_CMD_EXEC", "MED"),
]

# Webroot directories scanned by --scan-webroots.
DEFAULT_WEBROOTS = [
    "/var/www/html", "/var/www", "/srv/http", "/srv/www",
    "/usr/share/nginx/html", "/usr/local/apache2/htdocs",
    "/usr/local/www/apache24/data",
    r"C:\inetpub\wwwroot",
    r"C:\xampp\htdocs", r"C:\wamp64\www",
]
# Extensions to scan; bounded so we don't crawl whole-disk static assets.
WEBSHELL_SCAN_EXTENSIONS = frozenset({
    ".php", ".php3", ".php4", ".php5", ".phtml", ".phar",
    ".asp", ".aspx", ".ashx", ".asmx", ".cer",
    ".jsp", ".jspx", ".jsf",
    ".cgi", ".pl", ".py",
})


class WebShellScanner:
    """Scan webroot directories for known shell-content signatures.

    Single-pass, bounded: per-file size cap, total-file cap, total-time cap.
    Designed to run during a normal monitor session in under a second on
    a typical webroot. NOT a replacement for a proper YARA scanner, but
    catches the loud, common patterns (Weevely, China Chopper, eval/base64).
    """

    MAX_FILE_BYTES = 1 * 1024 * 1024     # 1 MB per file
    MAX_FILES = 5000                     # never scan more files than this
    MAX_TIME_SECONDS = 30.0              # bail at 30s total

    def __init__(self, roots=None):
        self.roots = list(roots) if roots else list(DEFAULT_WEBROOTS)
        self.findings = []   # list of dicts: {path, mtime, flags}

    def scan(self):
        deadline = time.time() + self.MAX_TIME_SECONDS
        scanned = 0
        for root in self.roots:
            if scanned >= self.MAX_FILES or time.time() > deadline:
                break
            if not os.path.isdir(root):
                continue
            for dirpath, dirnames, filenames in os.walk(root):
                if scanned >= self.MAX_FILES or time.time() > deadline:
                    break
                # Skip large vendored / cache directories that explode walk time.
                dirnames[:] = [d for d in dirnames
                               if d not in ("node_modules", "vendor", ".git", "cache")]
                for name in filenames:
                    if scanned >= self.MAX_FILES or time.time() > deadline:
                        break
                    ext = os.path.splitext(name)[1].lower()
                    if ext not in WEBSHELL_SCAN_EXTENSIONS:
                        continue
                    path = os.path.join(dirpath, name)
                    scanned += 1
                    try:
                        st = os.stat(path)
                        if st.st_size > self.MAX_FILE_BYTES:
                            continue
                        with open(path, "rb") as f:
                            data = f.read(self.MAX_FILE_BYTES)
                    except OSError:
                        continue
                    flags = []
                    for rx, suffix, _sev in WEBSHELL_SIGNATURES:
                        if rx.search(data):
                            flags.append(f"WEBSHELL_SIGNATURE_{suffix}")
                    if flags:
                        self.findings.append({
                            "path": path,
                            "size": st.st_size,
                            "mtime": st.st_mtime,
                            "flags": flags,
                        })
        return self.findings


def is_web_server_process(app_name):
    """True iff app_name is a known web-server process."""
    if not app_name:
        return False
    return _normalize_app_name(app_name) in WEB_SERVER_PROCESSES


def is_web_user(username):
    """True iff username is one of the web-runtime user accounts. Matches
    case-insensitively and handles both 'IIS APPPOOL\\foo' and 'iis apppool'."""
    if not username:
        return False
    name = username.lower().strip()
    if name in WEB_USER_ACCOUNTS:
        return True
    # Windows IIS app-pool accounts like "IIS APPPOOL\\DefaultAppPool"
    if name.startswith("iis apppool"):
        return True
    if "\\" in name:
        domain, _, local = name.partition("\\")
        if domain == "iis apppool":
            return True
    return False


def is_blocklisted_child(app_name):
    """True iff app_name should NOT be spawned by a web server."""
    if not app_name:
        return False
    return _normalize_app_name(app_name) in CHILD_PROCESS_BLOCKLIST


# === v1.3: Persistence enumeration (F-4) ====================================

class PersistenceScanner:
    """Enumerate host persistence mechanisms (cron, systemd, registry Run,
    scheduled tasks, launchd, authorized_keys). Bounded — never traverses
    the whole filesystem, only known persistence paths."""

    # Anything modified within this window is flagged as "recent" — a likely
    # IoC if the operator wasn't expecting changes.
    RECENT_DAYS = 14

    def __init__(self):
        self.findings = []   # list of dicts: {kind, name, path, mtime, command, recent}

    def scan(self):
        if sys.platform.startswith("linux"):
            self._scan_linux()
        elif sys.platform == "win32":
            self._scan_windows()
        elif sys.platform == "darwin":
            self._scan_macos()
        # SSH key persistence checked on POSIX hosts
        if hasattr(os, "getuid"):
            self._scan_ssh_keys()
        # PowerShell profiles — cross-platform persistence mechanism (PS7
        # runs on Linux/macOS too). Anything in a profile runs on every
        # PowerShell launch, which makes them a textbook persistence channel.
        self._scan_ps_profiles()
        return self.findings

    def _is_recent(self, mtime):
        try:
            age_days = (time.time() - float(mtime)) / 86400
            return age_days <= self.RECENT_DAYS
        except (TypeError, ValueError):
            return False

    def _add(self, kind, name, path, command="", mtime=None):
        self.findings.append({
            "kind": kind,
            "name": name,
            "path": path,
            "command": command,
            "mtime": mtime,
            "recent": self._is_recent(mtime) if mtime is not None else False,
            # v1.3: filled in by hash_task_binaries() when --hash-tasks runs.
            "binary_path": None,
            "binary_hash": None,
            "vt":          None,
        })

    # --- Linux ---
    def _scan_linux(self):
        # 1. systemd unit-files (enabled only — disabled units don't run)
        if shutil.which("systemctl"):
            try:
                r = subprocess.run(
                    ["systemctl", "list-unit-files", "--state=enabled",
                     "--no-pager", "--no-legend", "--plain"],
                    capture_output=True, text=True, timeout=10, check=False,
                )
                for line in (r.stdout or "").splitlines():
                    parts = line.split()
                    if not parts:
                        continue
                    unit = parts[0]
                    # Look up unit file path + mtime
                    path = self._systemd_unit_path(unit)
                    mtime = None
                    if path:
                        try:
                            mtime = os.path.getmtime(path)
                        except OSError:
                            mtime = None
                    self._add("systemd", unit, path or "", mtime=mtime)
            except (OSError, subprocess.SubprocessError):
                pass
        # 2. crontabs — root + per-user
        for cron_dir in ("/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily",
                         "/etc/cron.weekly", "/etc/cron.monthly",
                         "/var/spool/cron/crontabs", "/var/spool/cron"):
            if not os.path.isdir(cron_dir):
                continue
            try:
                for name in os.listdir(cron_dir):
                    path = os.path.join(cron_dir, name)
                    try:
                        st = os.stat(path)
                    except OSError:
                        continue
                    if not stat_mod.S_ISREG(st.st_mode):
                        continue
                    # Read first line of cron job as the "command"
                    cmd = ""
                    try:
                        with open(path, errors="ignore") as f:
                            for line in f:
                                line = line.strip()
                                if line and not line.startswith("#"):
                                    cmd = line[:400]
                                    break
                    except OSError:
                        pass
                    self._add("cron", name, path, command=cmd, mtime=st.st_mtime)
            except OSError:
                continue
        # 3. rc-local / profile / shell-rc (legacy persistence)
        for path in ("/etc/rc.local", "/etc/profile", "/etc/bash.bashrc",
                     "/etc/zsh/zshrc"):
            if os.path.isfile(path):
                try:
                    self._add("rc", os.path.basename(path), path,
                              mtime=os.path.getmtime(path))
                except OSError:
                    pass
        # v1.4: LD_PRELOAD global preload file — a classic Linux rootkit /
        # persistence channel (every dynamically-linked binary loads it).
        if os.path.isfile("/etc/ld.so.preload"):
            try:
                with open("/etc/ld.so.preload", errors="ignore") as f:
                    cmd = f.read(400).strip()
                self._add("ld_preload", "ld.so.preload", "/etc/ld.so.preload",
                          command=cmd, mtime=os.path.getmtime("/etc/ld.so.preload"))
            except OSError:
                pass
        # v1.4: drop-in dirs that auto-run on shell login / boot.
        for ddir, kind in (("/etc/profile.d", "profile.d"), ("/etc/init.d", "initd")):
            if not os.path.isdir(ddir):
                continue
            try:
                for name in sorted(os.listdir(ddir)):
                    p = os.path.join(ddir, name)
                    try:
                        st = os.stat(p)
                    except OSError:
                        continue
                    if stat_mod.S_ISREG(st.st_mode):
                        self._add(kind, name, p, mtime=st.st_mtime)
            except OSError:
                pass
        # v1.4: systemd timers (scheduled persistence distinct from units).
        if shutil.which("systemctl"):
            try:
                r = subprocess.run(
                    ["systemctl", "list-timers", "--all", "--no-pager", "--no-legend"],
                    capture_output=True, text=True, timeout=10, check=False)
                for line in (r.stdout or "").splitlines():
                    for tok in line.split():
                        if tok.endswith(".timer"):
                            self._add("systemd_timer", tok, "")
                            break
            except (OSError, subprocess.SubprocessError):
                pass

    def _systemd_unit_path(self, unit):
        """Resolve a unit name to its file path via `systemctl show -p FragmentPath`."""
        try:
            r = subprocess.run(
                ["systemctl", "show", "-p", "FragmentPath", "--value", unit],
                capture_output=True, text=True, timeout=5, check=False,
            )
            p = (r.stdout or "").strip()
            return p if p else None
        except (OSError, subprocess.SubprocessError):
            return None

    # --- Windows ---
    def _scan_windows(self):
        # Scheduled tasks (JSON output, parsed in-process)
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                 "Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | "
                 "Select-Object TaskName, TaskPath, "
                 "@{N='Command';E={($_.Actions | ForEach-Object {$_.Execute + ' ' + $_.Arguments}) -join '; '}}, "
                 "@{N='LastRun';E={(Get-ScheduledTaskInfo $_).LastRunTime}}, "
                 "@{N='NextRun';E={(Get-ScheduledTaskInfo $_).NextRunTime}} | "
                 "ConvertTo-Json -Compress -Depth 3"],
                capture_output=True, text=True, timeout=30, check=False,
            )
            if r.stdout.strip():
                data = json.loads(r.stdout)
                if isinstance(data, dict):
                    data = [data]
                for t in data[:500]:   # cap
                    name = t.get("TaskName", "")
                    path = (t.get("TaskPath") or "") + name
                    cmd = (t.get("Command") or "").strip()
                    # No easy mtime for tasks; use NextRun as a proxy "recent"
                    self._add("sched_task", name, path, command=cmd, mtime=None)
        except (OSError, subprocess.SubprocessError, ValueError, json.JSONDecodeError):
            pass

        # Registry Run keys
        run_keys = [
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        ]
        for key in run_keys:
            try:
                r = subprocess.run(
                    ["reg", "query", key],
                    capture_output=True, text=True, timeout=10, check=False,
                )
                if r.returncode != 0:
                    continue
                for line in (r.stdout or "").splitlines():
                    # Format: "    Name    REG_SZ    Value"
                    m = re.match(r"\s+(\S+)\s+REG_(?:SZ|EXPAND_SZ)\s+(.+)$", line)
                    if m:
                        self._add("reg_run", m.group(1), key,
                                  command=m.group(2).strip()[:400], mtime=None)
            except (OSError, subprocess.SubprocessError):
                continue

        # Auto-start services
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                 "Get-CimInstance -ClassName Win32_Service | "
                 "Where-Object {$_.StartMode -eq 'Auto' -and $_.State -ne 'Running'} | "
                 "Select-Object Name, DisplayName, PathName | "
                 "ConvertTo-Json -Compress"],
                capture_output=True, text=True, timeout=30, check=False,
            )
            if r.stdout.strip():
                data = json.loads(r.stdout)
                if isinstance(data, dict):
                    data = [data]
                for s in data[:500]:
                    self._add("service", s.get("Name", ""), s.get("DisplayName", ""),
                              command=(s.get("PathName") or "").strip()[:400], mtime=None)
        except (OSError, subprocess.SubprocessError, ValueError, json.JSONDecodeError):
            pass

    # --- macOS ---
    def _scan_macos(self):
        for d in ("/Library/LaunchAgents", "/Library/LaunchDaemons",
                  os.path.expanduser("~/Library/LaunchAgents")):
            if not os.path.isdir(d):
                continue
            try:
                for name in os.listdir(d):
                    if not name.endswith(".plist"):
                        continue
                    path = os.path.join(d, name)
                    try:
                        mtime = os.path.getmtime(path)
                    except OSError:
                        mtime = None
                    self._add("launchd", name, path, mtime=mtime)
            except OSError:
                continue

    # --- SSH keys ---
    def _scan_ssh_keys(self):
        for home in self._candidate_homes():
            ak = os.path.join(home, ".ssh", "authorized_keys")
            if not os.path.isfile(ak):
                continue
            try:
                st = os.stat(ak)
            except OSError:
                continue
            try:
                with open(ak, errors="ignore") as f:
                    keys = [line.strip() for line in f
                            if line.strip() and not line.startswith("#")]
            except OSError:
                continue
            for key_line in keys:
                # Take the comment (last whitespace-separated chunk) as the "name"
                parts = key_line.split()
                comment = parts[-1] if len(parts) >= 3 else "(no-comment)"
                self._add("ssh_key", comment, ak,
                          command=(key_line[:60] + "…" if len(key_line) > 60 else key_line),
                          mtime=st.st_mtime)

    # --- PowerShell profile scan (cross-platform) ---
    def _scan_ps_profiles(self):
        """Enumerate every PowerShell profile file on the host.

        PS profiles are textbook persistence: anything in profile.ps1 runs
        on every PowerShell launch. We list them here so an analyst sees
        them alongside cron/registry-Run/scheduled-tasks. The first non-
        empty, non-comment line of each profile is shown as the 'command'
        so suspicious additions surface immediately.

        On Windows hosts both PS 5.1 paths and PS 7 paths are checked. On
        POSIX hosts only PS 7 paths are checked (PS 7 runs on Linux/macOS).
        """
        candidates = []
        home = os.path.expanduser("~")
        if sys.platform == "win32":
            ps_documents = os.path.join(home, "Documents")
            candidates.extend([
                # Windows PowerShell 5.1
                os.path.join(ps_documents, "WindowsPowerShell",
                             "profile.ps1"),
                os.path.join(ps_documents, "WindowsPowerShell",
                             "Microsoft.PowerShell_profile.ps1"),
                # PowerShell 7+
                os.path.join(ps_documents, "PowerShell", "profile.ps1"),
                os.path.join(ps_documents, "PowerShell",
                             "Microsoft.PowerShell_profile.ps1"),
                # All-users PS 5.1
                r"C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1",
                r"C:\Windows\System32\WindowsPowerShell\v1.0"
                r"\Microsoft.PowerShell_profile.ps1",
                # All-users PS 7
                r"C:\Program Files\PowerShell\7\profile.ps1",
                r"C:\Program Files\PowerShell\7"
                r"\Microsoft.PowerShell_profile.ps1",
            ])
        else:
            # PS 7 on POSIX uses XDG-like paths.
            candidates.extend([
                os.path.join(home, ".config", "powershell", "profile.ps1"),
                os.path.join(home, ".config", "powershell",
                             "Microsoft.PowerShell_profile.ps1"),
                "/usr/local/microsoft/powershell/7/profile.ps1",
                "/etc/powershell/profile.ps1",
            ])
        for path in candidates:
            if not os.path.isfile(path):
                continue
            try:
                st = os.stat(path)
            except OSError:
                continue
            # Capture the first 200 chars of the FIRST non-empty, non-comment
            # line so the analyst sees what the profile actually does. Suspicious
            # profile contents (Invoke-Expression, IEX, encoded base64) will
            # surface in the persistence section's flag column.
            first_real = ""
            try:
                with open(path, errors="ignore") as f:
                    for line in f:
                        s = line.strip()
                        if s and not s.startswith("#"):
                            first_real = s[:200]
                            break
            except OSError:
                pass
            self._add(
                "ps_profile",
                os.path.basename(path),
                path,
                command=first_real or "(empty profile)",
                mtime=st.st_mtime,
            )

    # Known executable suffixes — used by extract_binary_path to recognize
    # the end of an unquoted Windows path that includes spaces.
    _BIN_EXTENSIONS = (
        ".exe", ".dll", ".com", ".bat", ".cmd", ".ps1",
        ".py", ".sh", ".vbs", ".vbe", ".msi", ".jar",
    )

    @staticmethod
    def extract_binary_path(command):
        """Best-effort: pull the executable path out of a persistence-entry
        command string. Handles:
          "C:\\Program Files\\Foo\\bar.exe" /args
          'C:\\Foo\\bar.exe' /args
          C:\\Program Files\\Foo\\bar.exe /silent     (unquoted, has spaces)
          C:\\Foo\\bar.exe /args
          /usr/local/bin/foo --flag
          %SystemRoot%\\system32\\svchost.exe -k Net
        Returns the resolved absolute path (env vars expanded) or None.
        """
        if not command or not isinstance(command, str):
            return None
        s = command.strip()
        # Quoted path — take the contents between matching quotes.
        if s.startswith('"'):
            end = s.find('"', 1)
            if end > 1:
                cand = s[1:end]
            else:
                return None
        elif s.startswith("'"):
            end = s.find("'", 1)
            if end > 1:
                cand = s[1:end]
            else:
                return None
        else:
            # Unquoted. Default: first whitespace-delimited token.
            parts = s.split()
            if not parts:
                return None
            cand = parts[0]
            # Windows-path-with-spaces correction (e.g. scheduled-task action
            # `C:\Program Files\Adobe\Acrobat.exe /silent` arrives unquoted
            # from PowerShell). If the first token DOESN'T end with a known
            # executable extension AND looks like a Windows drive-letter path,
            # keep absorbing tokens until we hit one ending in `.exe`/`.dll`/…
            # or a token that looks like a CLI flag (`-`, `/x`).
            looks_winabs = (len(cand) >= 2 and cand[1] == ":") or cand.startswith("\\\\")
            if (looks_winabs
                    and not cand.lower().endswith(PersistenceScanner._BIN_EXTENSIONS)
                    and len(parts) > 1):
                for w in parts[1:]:
                    # CLI flag → end of path. Bound the look-like-flag length
                    # to avoid mistaking a directory name "-Recover-Old-State"
                    # for a flag.
                    if (w.startswith("-") or w.startswith("/")) and len(w) < 40:
                        break
                    # v1.4 (F13): stop as soon as the accumulated candidate is a
                    # real file — handles executables whose extension is outside
                    # _BIN_EXTENSIONS (.scr/.pif/.cpl/.msc/.wsf …) so we don't glue
                    # argument tokens onto the path and then fail to hash it.
                    try:
                        if os.path.isfile(cand):
                            break
                    except OSError:
                        pass
                    cand = cand + " " + w
                    if cand.lower().endswith(PersistenceScanner._BIN_EXTENSIONS):
                        break
        if not cand:
            return None
        # Expand env vars on Windows ($env or %VAR%); leave POSIX vars alone
        # since persistence files normally store absolute paths.
        try:
            cand = os.path.expandvars(cand)
            cand = os.path.expanduser(cand)
        except (TypeError, ValueError):
            return None
        # Sanity: must be at least one path separator OR an absolute path.
        if not (os.path.sep in cand or cand.startswith(("/", "\\"))
                or (len(cand) > 2 and cand[1] == ":")):
            return None
        # Bound length defensively before passing to filesystem.
        if len(cand) > 4096:
            return None
        return cand

    def _candidate_homes(self):
        homes = set()
        try:
            with open("/etc/passwd", errors="ignore") as f:
                for line in f:
                    parts = line.split(":")
                    if len(parts) >= 6 and parts[5].startswith("/"):
                        homes.add(parts[5])
        except OSError:
            pass
        # And the current user's home (covers macOS / non-passwd hosts)
        home = os.path.expanduser("~")
        if home and home != "~":
            homes.add(home)
        return sorted(homes)


# === v1.3: Host event log review (F-3, --logs N) ============================

class LogReader:
    """Tail-N-minutes log readers for Linux + Windows.

    Each `read_*` method returns a list of dicts:
      {timestamp, source, severity, event_id, user, src_ip, message}

    All readers honor a per-source size cap and total time budget so a giant
    log can't OOM us.
    """

    MAX_BYTES_PER_SOURCE = 50 * 1024 * 1024     # 50 MB per log file
    MAX_ENTRIES_PER_SOURCE = 5000               # cap collected entries
    MAX_TIME_SECONDS = 20.0                     # hard ceiling for the entire pass

    # Privacy: strings to scrub from collected log entries.
    SCRUB_PATTERNS = [
        re.compile(r"password=[^&\s]+",                    re.IGNORECASE),
        re.compile(r"passwd=[^&\s]+",                      re.IGNORECASE),
        # v1.4 S4: token value can contain +/= (base64) — [^\s&]+ stops leaking
        # the tail; added Authorization Basic/Bearer + api-key/secret/aws keys.
        re.compile(r"token=[^\s&]+",                       re.IGNORECASE),
        re.compile(r"\bauthorization:\s*(?:basic|bearer|negotiate)\s+\S+", re.IGNORECASE),
        re.compile(r"\b(?:api[_-]?key|secret|client_secret|aws_[a-z_]*key)\b\s*[=:]\s*\S+", re.IGNORECASE),
        re.compile(r"-----BEGIN [A-Z ]+-----[\s\S]+?-----END [A-Z ]+-----"),
        re.compile(r"\b[A-Za-z0-9._-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),  # emails
        re.compile(r"\bey[A-Za-z0-9_\-]{15,}\.[A-Za-z0-9_\-]{15,}\.[A-Za-z0-9_\-]{15,}\b"),  # JWT
    ]

    def __init__(self, minutes):
        self.minutes = max(1, min(int(minutes), 1440))
        self.cutoff = time.time() - self.minutes * 60
        self.entries = []
        self.deadline = time.time() + self.MAX_TIME_SECONDS
        self.sources_read = []
        # v1.3: track per-source access errors so the operator sees WHY a log
        # contributed zero entries — typically because the PowerShell session
        # lacks admin and Security log needs it. Saved as list of
        # (source, reason).
        self.sources_skipped = []

    def read_all(self):
        if sys.platform.startswith("linux"):
            self._read_linux()
        elif sys.platform == "win32":
            self._read_windows()
        elif sys.platform == "darwin":
            self._read_macos()
        # Sort newest-first
        self.entries.sort(key=lambda e: e.get("timestamp_unix", 0), reverse=True)
        return self.entries

    def _scrub(self, message):
        if not message:
            return ""
        for rx in self.SCRUB_PATTERNS:
            message = rx.sub("[REDACTED]", message)
        if len(message) > 800:
            message = message[:800] + "…"
        return message

    def _add(self, source, ts_unix, severity, event_id, user, src_ip, message):
        if ts_unix < self.cutoff:
            return
        # v1.3: severity='SELF' marks an event netmon itself generated
        # (PowerShell ScriptBlock compiles from our own child cmdlet calls).
        # Hidden by default in the HTML, surfaced via a toggle so analysts
        # can audit netmon's own runtime footprint on demand.
        is_self = (severity == "SELF")
        self.entries.append({
            "timestamp_unix": ts_unix,
            "timestamp": datetime.fromtimestamp(ts_unix).strftime("%Y-%m-%d %H:%M:%S"),
            "source": source,
            "severity": severity,
            "event_id": event_id,
            "user": user or "",
            "src_ip": src_ip or "",
            "message": self._scrub(message or ""),
            "is_netmon_self": is_self,
        })

    # --- Linux ---

    SYSLOG_RX = re.compile(
        # Sep 12 14:23:45 hostname program[pid]: message
        # or 2025-12-31T14:23:45+00:00 hostname program[pid]: message (RFC5424)
        r"^(?P<ts>\S+\s+\S+\s+\S+|\S+T\S+)\s+(?P<host>\S+)\s+(?P<prog>[^\[\]:]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
    )
    APACHE_COMMON_RX = re.compile(
        # 1.2.3.4 - - [01/Jan/2025:12:34:56 +0000] "POST /shell.php HTTP/1.1" 200 1234
        r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+'
        r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<proto>[^"]+)"\s+(?P<status>\d+)\s+(?P<size>\S+)'
    )
    SSH_FAIL_RX = re.compile(
        r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port"
    )
    SSH_OK_RX = re.compile(
        r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\S+) port"
    )

    def _read_linux(self):
        candidates = [
            ("auth",    ["/var/log/auth.log", "/var/log/secure"]),
            ("syslog",  ["/var/log/syslog", "/var/log/messages"]),
            ("apache",  ["/var/log/apache2/access.log", "/var/log/httpd/access_log"]),
            ("apache",  ["/var/log/apache2/error.log",  "/var/log/httpd/error_log"]),
            ("nginx",   ["/var/log/nginx/access.log"]),
            ("nginx",   ["/var/log/nginx/error.log"]),
            ("mysql",   ["/var/log/mysql/error.log", "/var/log/mysqld.log"]),
            ("audit",   ["/var/log/audit/audit.log"]),
            ("crowdsec",["/var/log/crowdsec.log"]),
            ("fail2ban",["/var/log/fail2ban.log"]),
        ]
        for source, paths in candidates:
            if time.time() > self.deadline:
                break
            for p in paths:
                if not os.path.isfile(p):
                    continue
                # Also consider rotated +.1 +.2.gz files whose mtime is in window
                self._read_linux_file(source, p)
                break  # only read one match per source

    def _read_linux_file(self, source, path):
        try:
            size = os.path.getsize(path)
        except OSError:
            return
        # Seek backwards from EOF to limit work for long log files.
        # We read at most MAX_BYTES_PER_SOURCE from the tail.
        offset = max(0, size - self.MAX_BYTES_PER_SOURCE)
        try:
            with open(path, "r", errors="ignore") as f:
                if offset:
                    f.seek(offset)
                    f.readline()  # discard partial first line
                count = 0
                for line in f:
                    if count >= self.MAX_ENTRIES_PER_SOURCE:
                        break
                    self._parse_linux_line(source, line)
                    count += 1
        except OSError:
            return
        self.sources_read.append((source, path))

    def _parse_linux_line(self, source, line):
        line = line.rstrip("\n")
        if not line:
            return
        # Apache/Nginx access log (Common / Combined Log Format)
        if source in ("apache", "nginx") and (line.startswith(("1", "2", "3")) or line[0].isdigit()):
            m = self.APACHE_COMMON_RX.match(line)
            if m:
                ts_unix = self._parse_apache_ts(m.group("ts"))
                if ts_unix is None:
                    return
                method = m.group("method")
                path = m.group("path")
                status = m.group("status")
                ip = m.group("ip")
                # Risk classification at parse time (lets correlation skip noise)
                sev = "LOW"
                ev = f"HTTP_{status}"
                if method == "POST" and any(path.lower().endswith(ext)
                                            for ext in (".php", ".aspx", ".asp", ".jsp")):
                    sev = "MED"
                    ev = "HTTP_POST_SCRIPT"
                if any(s in path for s in ("../", "%2e%2e", "etc/passwd", "/proc/")):
                    sev = "HIGH"
                    ev = "PATH_TRAVERSAL_ATTEMPT"
                if any(s in path.lower() for s in ("union+select", "union%20select", "' or '1'='1")):
                    sev = "HIGH"
                    ev = "SQLI_ATTEMPT"
                msg = f"{method} {path} → {status}"
                self._add(source, ts_unix, sev, ev, "", ip, msg)
                return
        # Syslog-style line
        m = self.SYSLOG_RX.match(line)
        if not m:
            return
        ts_unix = self._parse_syslog_ts(m.group("ts"))
        if ts_unix is None:
            return
        prog = m.group("prog") or ""
        message = m.group("msg") or ""
        # sshd Failed/Accepted
        if "ssh" in prog.lower():
            mf = self.SSH_FAIL_RX.search(message)
            if mf:
                self._add(source, ts_unix, "MED", "SSH_FAILED",
                          mf.group("user"), mf.group("ip"),
                          f"sshd: {message}")
                return
            mo = self.SSH_OK_RX.search(message)
            if mo:
                self._add(source, ts_unix, "LOW", "SSH_ACCEPTED",
                          mo.group("user"), mo.group("ip"),
                          f"sshd: {message}")
                return
        # sudo
        if prog.lower().startswith("sudo"):
            self._add(source, ts_unix, "MED", "SUDO", "", "",
                      f"{prog}: {message}")
            return
        # systemd unit failure
        if "systemd" in prog.lower() and ("Failed" in message or "failed" in message):
            self._add(source, ts_unix, "MED", "SYSTEMD_FAIL", "", "",
                      f"{prog}: {message}")
            return
        # Default — keep MED-or-higher only if the line has loud keywords
        loud = any(kw in message.lower() for kw in
                   ("error", "fail", "denied", "panic", "alert", "critical"))
        if loud:
            self._add(source, ts_unix, "LOW", prog or "msg", "", "", message)

    def _parse_syslog_ts(self, ts):
        # Try RFC5424 first — KEEP the timezone (v1.4 F9). The old code stripped
        # the offset and read the result as host-local, shifting every event on a
        # non-UTC host and silently dropping genuinely-recent ones.
        try:
            if "T" in ts:
                iso = ts.strip().replace("Z", "+00:00")
                # Truncate over-long fractional seconds (syslog can emit ns).
                m = re.match(r"(.*T\d{2}:\d{2}:\d{2})(\.\d+)?(.*)$", iso)
                if m:
                    iso = m.group(1) + (m.group(2) or "")[:7] + (m.group(3) or "")
                dt = datetime.fromisoformat(iso)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.timestamp()
        except (ValueError, TypeError):
            pass
        # BSD syslog: "Sep 12 14:23:45" — no year. Assume current year.
        try:
            year = datetime.now().year
            dt = datetime.strptime(f"{year} {ts}", "%Y %b %d %H:%M:%S")
            # If parsed timestamp is in the future, it's actually last year.
            if dt.timestamp() > time.time() + 3600:
                dt = dt.replace(year=year - 1)
            return dt.timestamp()
        except (ValueError, TypeError):
            return None

    def _parse_apache_ts(self, ts):
        # 01/Jan/2025:12:34:56 +0000 — keep the offset (v1.4 F9).
        try:
            return datetime.strptime(ts.strip(), "%d/%b/%Y:%H:%M:%S %z").timestamp()
        except (ValueError, TypeError):
            try:
                dt = datetime.strptime(ts.split(" ")[0], "%d/%b/%Y:%H:%M:%S")
                return dt.replace(tzinfo=timezone.utc).timestamp()
            except (ValueError, TypeError):
                return None

    # --- Windows ---

    # Event IDs we care about, keyed by log name.
    # NOTE: 4104 (PS_SCRIPT_BLOCK) was previously HIGH globally — that produced
    # a flood of false-positive HIGH alerts because the event fires for EVERY
    # PowerShell script block compile, including netmon's own internal cmdlet
    # calls (Get-AuthenticodeSignature, Get-ScheduledTask, Get-WinEvent…).
    # It's now LOW by default; _classify_ps_scriptblock() upgrades to HIGH on
    # genuine offensive-tradecraft patterns (FromBase64String, IEX, encoded
    # commands, Invoke-Mimikatz, AMSI bypass, etc.) and skips netmon-self
    # noise entirely.
    WIN_EVENT_IDS = {
        "Security": {
            4624: ("LOW",  "LOGON_SUCCESS"),
            4625: ("MED",  "LOGON_FAIL"),
            4672: ("MED",  "SPECIAL_PRIV"),
            4688: ("LOW",  "PROC_CREATE"),
            4697: ("HIGH", "SVC_INSTALL"),
            4698: ("HIGH", "SCHED_TASK_CREATE"),
            4720: ("HIGH", "USER_CREATE"),
            4732: ("HIGH", "ADD_TO_LOCAL_GROUP"),
        },
        "System": {
            7045: ("HIGH", "SVC_INSTALL"),
            7036: ("LOW",  "SVC_STATE"),
        },
        "Microsoft-Windows-PowerShell/Operational": {
            4104: ("LOW",  "PS_SCRIPT_BLOCK"),   # promoted by classifier below
            4103: ("LOW",  "PS_MODULE"),
        },
        "Microsoft-Windows-Windows Defender/Operational": {
            1116: ("HIGH", "DEFENDER_DETECTED"),
            1117: ("HIGH", "DEFENDER_ACTION"),
            5007: ("MED",  "DEFENDER_CONFIG_CHANGE"),
        },
    }

    # PowerShell ScriptBlock substrings that indicate offensive tradecraft.
    # Match is case-insensitive; bumps severity to HIGH and rewrites event_id
    # so analysts can immediately see WHY a 4104 was flagged.
    # NOTE: each pattern is intentionally specific. Bare strings like "bypass"
    # were tried in early v1.3 dev and produced massive false-positive volume
    # because PowerShell module-definition scriptblocks (auto-emitted when ANY
    # cmdlet from NetSecurity / NetTCPIP / etc. is loaded) contain enum names
    # with "Bypass" in them.
    PS_OFFENSIVE_PATTERNS = [
        ("FromBase64String",                    "PS_BASE64_DECODE"),
        ("[Convert]::FromBase64String",         "PS_BASE64_DECODE"),
        ("[Reflection.Assembly]::Load",         "PS_REFLECTION_LOAD"),
        ("DownloadString",                      "PS_DOWNLOAD_STRING"),
        ("DownloadFile",                        "PS_DOWNLOAD_FILE"),
        ("Net.WebClient",                       "PS_WEBCLIENT"),
        ("Invoke-WebRequest",                   "PS_INVOKE_WEBREQ"),
        ("Invoke-Mimikatz",                     "PS_MIMIKATZ"),
        ("Mimikatz",                            "PS_MIMIKATZ"),
        ("Invoke-DllInjection",                 "PS_DLL_INJECTION"),
        ("Invoke-Shellcode",                    "PS_SHELLCODE"),
        ("Invoke-ReflectivePEInjection",        "PS_PE_INJECTION"),
        ("VirtualAllocEx",                      "PS_INJECTION_API"),
        ("CreateRemoteThread",                  "PS_INJECTION_API"),
        ("WriteProcessMemory",                  "PS_INJECTION_API"),
        ("Add-MpPreference -Exclusion",         "PS_DEFENDER_TAMPER"),
        ("Set-MpPreference -Disable",           "PS_DEFENDER_TAMPER"),
        ("Set-MpPreference -ExclusionPath",     "PS_DEFENDER_TAMPER"),
        ("amsiInitFailed",                      "PS_AMSI_BYPASS"),
        ("AmsiUtils",                           "PS_AMSI_BYPASS"),
        ("Net.Sockets.TcpClient",               "PS_RAW_SOCKET"),
        ("Net.Sockets.UdpClient",               "PS_RAW_SOCKET"),
        # Be specific about bypass — only the well-known abuse forms.
        ("-ExecutionPolicy Bypass",             "PS_EXECPOLICY_BYPASS"),
        ("-ep bypass",                          "PS_EXECPOLICY_BYPASS"),
        ("Set-ExecutionPolicy Bypass",          "PS_EXECPOLICY_BYPASS"),
        ("New-Object IO.MemoryStream",          "PS_MEMORY_LOAD"),
    ]

    # Strings that mark an EID 4103/4104 event as netmon's own internal
    # PowerShell call or as PowerShell-runtime auto-compiled boilerplate (the
    # CIM module's alias-init, the cmdletization parameter-validators, etc.).
    # All such events are dropped entirely. The classifier below applies this
    # filter to BOTH 4103 (PS_MODULE) and 4104 (PS_SCRIPT_BLOCK).
    PS_NETMON_SELF_PATTERNS = [
        # --- Cmdlets netmon invokes directly ---
        "Get-AuthenticodeSignature",
        "Get-ScheduledTask",
        "Get-ScheduledTaskInfo",
        "Get-NetFirewallProfile",
        "Get-NetFirewallRule",
        "Get-WinEvent",
        "Get-CimInstance",
        "Get-CimClass",
        "Get-CimSession",
        "[Console]::In.ReadLine",
        # Where-Object filter literals used in netmon's PS commands.
        "$_.StartMode -eq 'Auto'",
        "$_.State -ne 'Disabled'",
        "$_.State -ne 'Running'",
        # --- PowerShell engine / module init boilerplate ---
        # Every `powershell -Command ...` invocation triggers the engine to
        # emit a $global:? scriptblock (readiness check) plus N Set-Alias
        # scriptblocks when the CIM module loads (gcls=Get-CimClass,
        # ncso=New-CimSessionOption, etc.). These are pure scaffolding.
        "$global:?",
        "Set-Alias -Name gcim",
        "Set-Alias -Name gcls",
        "Set-Alias -Name ncso",
        "Set-Alias -Name gcms",
        "Set-Alias -Name rcms",
        "Set-Alias -Name ncms",
        "Set-Alias -Name rcie",
        "Set-Alias -Name gcai",
        "Set-Alias -Name icim",
        "Set-Alias -Name rcim",
        "Set-Alias -Name ncim",
        "Set-Alias -Name scim",
        "Set-StrictMode",
        # Cmdletization-backed module boilerplate (NetSecurity, NetTCPIP,
        # ScheduledTasks, Storage…). Parameter validators with no operator-
        # controlled content.
        "PowerShell.Cmdletization.GeneratedTypes",
        "PSCmdlet.ParameterSetName",
        "__cmdletization_",                # catches BindCommonParameters,
                                            # methodParameter, queryBuilder,
                                            # objectModelWrapper, defaultValue,
                                            # any future __cmdletization_*
        "ParameterSetName='ByQuery'",
        "ParameterSetName='ByName'",
        # CIM infrastructure type-name strings emitted when ScheduledTask /
        # Win32_Service / NetSecurity cmdlets compile their type bindings.
        "Microsoft.Management.Infrastructure.CimInstance#",
        # ValidateSet validator scriptblocks emitted for ScheduledTask params.
        "@('Object') -contains",
        "@('Name') -contains",
        # netmon's own Get-ScheduledTask action-expression scriptblocks (the
        # PowerShell `@{N='Command';E={...}}` calc-property bodies get
        # compiled as standalone scriptblocks and logged).
        "$_.Execute + ' ' + $_.Arguments",
        "$_.Actions | ForEach-Object",
        # PS_DEBUG / engine wrappers
        "$ErrorActionPreference",
    ]

    # PowerShell profile paths — files that run on every PS launch.
    # When a 4104 event's "Path:" field points at one of these, it's the
    # OS compiling the user's profile on session start. The profile content
    # is the same data the --persistence scanner enumerates. Tagging the
    # 4104 as PS_PROFILE_LOAD lets the analyst see at-a-glance "this is the
    # profile compiling, not arbitrary PowerShell activity".
    PS_PROFILE_PATH_FRAGMENTS = (
        # Windows PowerShell 5.1
        r"\WindowsPowerShell\profile.ps1",
        r"\WindowsPowerShell\Microsoft.PowerShell_profile.ps1",
        # PowerShell 7+
        r"\PowerShell\profile.ps1",
        r"\PowerShell\Microsoft.PowerShell_profile.ps1",
        # All-users variants
        r"\System32\WindowsPowerShell\v1.0\profile.ps1",
        r"\System32\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1",
    )

    # Well-known machine / service SIDs that ALWAYS get the full SYSTEM
    # privilege set. 4672 firing for these is routine OS behavior (Service
    # Control Manager starting a service); flagging it MED on every service
    # start drowned out real signal. SIDs from MS-DTYP appendix:
    SYSTEM_SIDS = frozenset({
        "S-1-5-18",   # NT AUTHORITY\SYSTEM (LocalSystem)
        "S-1-5-19",   # NT AUTHORITY\LOCAL SERVICE
        "S-1-5-20",   # NT AUTHORITY\NETWORK SERVICE
    })

    @classmethod
    def classify_security_event(cls, eid, msg):
        """Smarter classification for the Security log's high-volume events
        4624 (logon-success) and 4672 (special-privileges-assigned).

        Both fire as a pair every time Service Control Manager starts a
        service running under SYSTEM/LocalService/NetworkService — that's
        ~10-50 times per minute on a typical desktop and is pure noise.
        A real privilege-escalation signal is 4672 firing for a NON-system
        SID, or 4624 with Logon Type != 5 on an admin account.

        Returns (severity, kind_suffix) or None to fall back to the table
        default.
        """
        if not msg:
            return None
        # Match the FIRST Security ID line — that's the Subject (who's
        # logging on / receiving privileges), not the New Logon block.
        m = re.search(r"Security ID:\s*(S-\d-\d+(?:-\d+)*)", msg)
        subject_sid = m.group(1) if m else ""
        # Logon Type is only meaningful for 4624; 4672 doesn't carry it.
        lt_match = re.search(r"Logon Type:\s*(\d+)", msg)
        logon_type = int(lt_match.group(1)) if lt_match else None

        # --- 4672: privilege assignment ---
        if eid == 4672:
            if subject_sid in cls.SYSTEM_SIDS:
                # Service-account logon. Routine; downgrade to LOW so it's
                # available for context but not alarming.
                return ("LOW", "SPECIAL_PRIV_SYSTEM")
            return ("MED", "SPECIAL_PRIV")

        # --- 4624: logon success ---
        if eid == 4624:
            if logon_type == 5:
                # Service Control Manager starting a service — routine.
                return ("LOW", "LOGON_SUCCESS_SERVICE")
            if logon_type == 4:
                # Batch (scheduled task) — usually routine.
                return ("LOW", "LOGON_SUCCESS_BATCH")
            if logon_type == 7:
                # Workstation unlock (lock screen → password) — routine.
                return ("LOW", "LOGON_SUCCESS_UNLOCK")
            if logon_type == 10:
                # Remote Interactive (RDP) — MED on a desktop.
                return ("MED", "LOGON_SUCCESS_RDP")
            if logon_type == 3:
                # Network (SMB, IIS auth, etc.).
                if subject_sid in cls.SYSTEM_SIDS:
                    return ("LOW", "LOGON_SUCCESS_NET_SYSTEM")
                return ("MED", "LOGON_SUCCESS_NET")
            if logon_type == 2:
                # Interactive console login.
                return ("LOW", "LOGON_SUCCESS_INTERACTIVE")
            return None

        return None

    @classmethod
    def _classify_ps_scriptblock(cls, msg):
        """Return (severity, kind_suffix). Severity 'SELF' marks events
        generated by netmon's own PowerShell invocations — they're kept
        in the entry list but tagged so the HTML report can hide them
        behind a 'Show events generated by netmon.py' toggle (analyst
        gets visibility on demand without the noise by default).

        Earlier v1.3 dev returned (None, None) for these and the caller
        dropped them entirely; that broke audit completeness — operators
        had no way to see what netmon itself contributed to the logs.
        """
        if not msg:
            return ("LOW", "PS_SCRIPT_BLOCK")
        # netmon-self events: kept but tagged, hidden by default in HTML.
        for needle in cls.PS_NETMON_SELF_PATTERNS:
            if needle in msg:
                return ("SELF", "PS_NETMON_SELF")
        # Promote to HIGH on offensive tradecraft (regardless of source —
        # malicious code in a profile DOES still get flagged HIGH).
        for needle, kind in cls.PS_OFFENSIVE_PATTERNS:
            if needle.lower() in msg.lower():
                return ("HIGH", kind)
        # Profile compile: same content every PS launch, low signal value.
        # Tagged so analysts know what they're looking at.
        for frag in cls.PS_PROFILE_PATH_FRAGMENTS:
            if frag in msg:
                return ("LOW", "PS_PROFILE_LOAD")
        # Everything else stays LOW — informational only.
        return ("LOW", "PS_SCRIPT_BLOCK")

    def _read_windows(self):
        """Read the four Windows log sources in PARALLEL so one slow log
        (typically Security on a busy desktop) doesn't starve the others
        of the shared time budget. Per-source access failures (typically
        Security log requiring admin) are recorded in self.sources_skipped
        so the operator can see why a source contributed zero entries."""
        from concurrent.futures import ThreadPoolExecutor, as_completed

        items = list(self.WIN_EVENT_IDS.items())
        per_call_timeout = max(5, min(15, int(self.MAX_TIME_SECONDS)))
        results = []
        with ThreadPoolExecutor(max_workers=len(items)) as ex:
            futures = {ex.submit(self._collect_windows_log, log_name, ids,
                                 per_call_timeout): log_name
                       for log_name, ids in items}
            for fut in as_completed(futures, timeout=self.MAX_TIME_SECONDS + 5):
                try:
                    results.append(fut.result(timeout=1))
                except (OSError, subprocess.SubprocessError, ValueError,
                        json.JSONDecodeError, RuntimeError, TimeoutError) as e:
                    log.debug("windows log read future failed: %s", e)
        # Merge results from all sources into self.entries.
        for log_name, entries, skip_reason in results:
            for ts_unix, sev, kind, user, src_ip, msg in entries:
                self._add(log_name.replace("Microsoft-Windows-", ""),
                          ts_unix, sev, kind, user, src_ip, msg)
            if entries:
                self.sources_read.append((log_name, log_name))
            if skip_reason:
                self.sources_skipped.append((log_name, skip_reason))

    def _collect_windows_log(self, log_name, ids, timeout):
        """PowerShell-side read for a single log. Returns a tuple of
        (log_name, [entries], skip_reason). skip_reason is a short string
        when the log was unreadable, else None. No instance state mutated
        here — safe to call concurrently."""
        start = datetime.fromtimestamp(self.cutoff).strftime("%Y-%m-%dT%H:%M:%S")
        ids_csv = ",".join(str(i) for i in ids)
        per_source_cap = min(self.MAX_ENTRIES_PER_SOURCE, 2000)
        # Use a verbose error stream — we WANT the UnauthorizedAccessException
        # text on stderr so we can surface "needs admin" to the operator.
        ps = (
            f"$ErrorActionPreference='Continue';"
            f"Get-WinEvent -FilterHashtable @{{LogName='{log_name}';"
            f"StartTime=[datetime]'{start}';Id=@({ids_csv})}} -MaxEvents {per_source_cap} | "
            f"Select-Object @{{N='ts';E={{$_.TimeCreated.ToUniversalTime().ToString('o')}}}},"
            f"Id, LevelDisplayName, "
            f"@{{N='User';E={{if($_.UserId){{$_.UserId.Value}}else{{''}}}}}}, "
            f"@{{N='Message';E={{if($_.Message){{$_.Message.Substring(0,[Math]::Min($_.Message.Length,4000))}}else{{''}}}}}} | "
            f"ConvertTo-Json -Compress -Depth 3"
        )
        out = []
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                capture_output=True, text=True, timeout=timeout, check=False,
            )
        except (OSError, subprocess.SubprocessError) as e:
            log.debug("windows log read for %s failed: %s", log_name, e)
            return (log_name, out, f"subprocess error: {e}")
        stderr = (r.stderr or "")
        # Classify common failure modes so the operator sees actionable info.
        skip_reason = None
        if "UnauthorizedAccessException" in stderr or "Access is denied" in stderr:
            skip_reason = "access denied (run elevated for full coverage)"
        elif "No events were found" in stderr:
            skip_reason = "no matching events in window"
        elif "There is not an event log" in stderr or "Could not retrieve" in stderr:
            skip_reason = "log not present on this host"
        if not (r.stdout or "").strip():
            return (log_name, out, skip_reason)
        try:
            data = json.loads(r.stdout)
        except (ValueError, json.JSONDecodeError):
            return (log_name, out, skip_reason or "unparseable JSON output")
        if isinstance(data, dict):
            data = [data]
        for ev in data:
            try:
                ts = ev.get("ts", "")
                if not ts:
                    continue
                ts_unix = datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
            except (ValueError, TypeError):
                continue
            eid = ev.get("Id", 0)
            sev, kind = ids.get(eid, ("LOW", str(eid)))
            msg = ev.get("Message", "") or ""
            user = ev.get("User", "") or ""
            src_ip = ""
            m = re.search(r"Source Network Address:\s*(\S+)", msg)
            if m:
                src_ip = m.group(1)
            # Apply the noise / promotion classifier to BOTH 4103 (PS_MODULE)
            # and 4104 (PS_SCRIPT_BLOCK). 4103 events carry the "Host
            # Application" line (which contains netmon's `powershell …
            # -Command Get-CimInstance …` invocation), so the same self-noise
            # filter catches them. Without this, every netmon call to
            # PersistenceScanner / Get-WinEvent / etc. produced ~14 LOW
            # log entries on Windows hosts.
            #
            # v1.3 UX (this turn): netmon-self events are KEPT (not dropped)
            # with severity 'SELF'. The HTML hides them by default and
            # surfaces a 'Show events generated by netmon.py (N hidden)'
            # toggle so analysts can audit netmon's own runtime footprint
            # on demand. Severity 'SELF' is filtered out of HIGH/MED/LOW
            # counts.
            if eid in (4103, 4104):
                ps_sev, ps_kind = self._classify_ps_scriptblock(msg)
                if eid == 4104:
                    sev, kind = ps_sev, ps_kind
                # For 4103 the classifier promotes severity if real malicious
                # patterns appear in the host-application line; SELF still
                # propagates so the toggle works for 4103 too.
                elif ps_sev == "HIGH":
                    sev = "HIGH"
                    kind = ps_kind
                elif ps_sev == "SELF":
                    sev = "SELF"
                    kind = ps_kind
            # v1.3: SID + Logon-Type aware Security-event classifier so
            # SCM service starts (4624 Type 5 + 4672 for SYSTEM SID) stop
            # generating MED-noise on every service launch.
            if eid in (4624, 4672):
                sec = self.classify_security_event(eid, msg)
                if sec is not None:
                    sev, kind = sec
            out.append((ts_unix, sev, f"EID_{eid}_{kind}", user, src_ip, msg))
        return (log_name, out, None if out else skip_reason)

    # --- macOS ---
    def _read_macos(self):
        # macOS uses `log show` for the unified log. It's heavy; just collect
        # the auth/sudo events for the window.
        if not shutil.which("log"):
            return
        try:
            r = subprocess.run(
                ["log", "show", "--last", f"{self.minutes}m",
                 "--predicate", "process == 'sudo' OR process == 'sshd' OR eventMessage CONTAINS 'authentication'",
                 "--style", "compact", "--info"],
                capture_output=True, text=True, timeout=30, check=False,
            )
            for line in (r.stdout or "").splitlines()[: self.MAX_ENTRIES_PER_SOURCE]:
                # macOS compact: "2025-12-31 14:23:45.123456+0000  I  sudo[123]:  message"
                m = re.match(r"(\S+\s\S+)\s+\S+\s+(\S+):\s+(.*)", line)
                if not m:
                    continue
                try:
                    # v1.4 (F9): keep the timezone. macOS `log show` emits e.g.
                    # "2025-12-31 14:23:45.123456-0800"; the old split(".")[0]
                    # dropped both fraction AND offset -> naive local time.
                    raw = m.group(1).strip()
                    mt = re.match(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:\.\d+)?\s*([+-]\d{4})?", raw)
                    if not mt:
                        continue
                    if mt.group(2):
                        ts_unix = datetime.strptime(mt.group(1) + mt.group(2),
                                                    "%Y-%m-%d %H:%M:%S%z").timestamp()
                    else:
                        ts_unix = datetime.strptime(mt.group(1), "%Y-%m-%d %H:%M:%S") \
                            .replace(tzinfo=timezone.utc).timestamp()
                except (ValueError, TypeError):
                    continue
                prog = m.group(2)
                msg = m.group(3)
                self._add("macos_log", ts_unix, "LOW", prog, "", "", msg)
            self.sources_read.append(("macos_log", "log show"))
        except (OSError, subprocess.SubprocessError):
            return


def correlate_log_findings(entries):
    """Apply cross-event correlation rules. Returns a list of derived
    finding dicts (same shape as LogReader entries) representing higher-
    level signals like brute-force-then-success."""
    derived = []
    # Bucket by (src_ip, user) for SSH brute-force-then-success.
    ssh_fails = defaultdict(list)
    ssh_oks = []
    for e in entries:
        if e["event_id"] == "SSH_FAILED" and e["src_ip"]:
            ssh_fails[(e["src_ip"], e["user"])].append(e["timestamp_unix"])
        elif e["event_id"] == "SSH_ACCEPTED" and e["src_ip"]:
            ssh_oks.append((e["src_ip"], e["user"], e["timestamp_unix"]))
    for src_ip, user, ok_ts in ssh_oks:
        fails = ssh_fails.get((src_ip, user), [])
        nearby = [t for t in fails if 0 < ok_ts - t < 300]   # 5-min window
        if len(nearby) >= 10:
            derived.append({
                "timestamp_unix": ok_ts,
                "timestamp": datetime.fromtimestamp(ok_ts).strftime("%Y-%m-%d %H:%M:%S"),
                "source": "correlation",
                "severity": "HIGH",
                "event_id": "BRUTE_FORCE_THEN_SUCCESS",
                "user": user, "src_ip": src_ip,
                "message": f"sshd: {len(nearby)} failed attempts then SUCCESS for {user}@{src_ip}",
            })
    return derived


# === v1.3: SCTP / Unix-socket / non-TCP transport enumeration (F-1.x) =======

def enumerate_sctp():
    """Read /proc/net/sctp/{eps,assocs} for SCTP endpoints + associations.

    Returns list of (transport='sctp', local, remote, status, kind).
    Linux-only; empty list elsewhere.
    """
    out = []
    if not sys.platform.startswith("linux"):
        return out
    # /proc/net/sctp/eps: ENDPT SOCK STY SST HBKT LPORT uid inode LADDRS
    try:
        with open("/proc/net/sctp/eps") as f:
            header = f.readline()
            if "LPORT" not in header:
                return out
            for line in f:
                parts = line.split()
                if len(parts) < 9:
                    continue
                try:
                    lport = int(parts[5])
                except (ValueError, IndexError):
                    continue
                laddrs = " ".join(parts[8:])
                # Take just the first address for display
                first = laddrs.split()[0] if laddrs.split() else "0.0.0.0"
                local = f"{first}:{lport}"
                out.append({
                    "transport": "sctp", "local": local, "remote": "",
                    "status": "LISTEN", "kind": "endpoint",
                })
    except OSError:
        pass
    # /proc/net/sctp/assocs: many fields; format is well-known but order can differ
    try:
        with open("/proc/net/sctp/assocs") as f:
            header = f.readline()
            if "LPORT" not in header:
                return out
            cols = header.split()
            try:
                idx_lport = cols.index("LPORT")
                idx_rport = cols.index("RPORT")
                idx_laddr = cols.index("LADDRS")
                idx_raddr = cols.index("RADDRS") if "RADDRS" in cols else None
            except ValueError:
                return out
            for line in f:
                parts = line.split()
                if len(parts) <= idx_lport:
                    continue
                try:
                    lport = int(parts[idx_lport])
                    rport = int(parts[idx_rport])
                except (ValueError, IndexError):
                    continue
                laddr = parts[idx_laddr] if idx_laddr < len(parts) else "0.0.0.0"
                raddr = parts[idx_raddr] if (idx_raddr is not None and idx_raddr < len(parts)) else "0.0.0.0"
                out.append({
                    "transport": "sctp",
                    "local":  f"{laddr}:{lport}",
                    "remote": f"{raddr}:{rport}",
                    "status": "ESTABLISHED", "kind": "assoc",
                })
    except OSError:
        pass
    return out


def enumerate_unix_sockets():
    """List AF_UNIX sockets via psutil. Returns list of dicts with the same
    shape as TCP/UDP rows; transport='unix'. Per-socket peer info varies by
    platform and is often unavailable for stream sockets."""
    out = []
    # AF_UNIX only exists on POSIX. psutil rejects kind="unix" on Windows.
    if sys.platform == "win32":
        return out
    try:
        conns = psutil.net_connections(kind="unix")
    except (psutil.AccessDenied, AttributeError, ValueError):
        return out
    for c in conns:
        path = getattr(c.laddr, "path", "") or ""
        if not path:
            continue
        out.append({
            "transport": "unix",
            "local": path,
            "remote": "",
            "status": c.status or "NONE",
            "pid": c.pid,
            "kind": "stream",
        })
    return out


# === v1.3: DoH endpoint detection (F-1.5) ===================================

# Public DoH endpoints we recognize. Used to flag connections that talk DNS
# over HTTPS, which is suspicious unless the calling process is a browser.
DOH_HOSTS = frozenset({
    "1.1.1.1", "1.0.0.1",
    "8.8.8.8", "8.8.4.4",
    "9.9.9.9", "149.112.112.112",
    "dns.google", "dns.google.com",
    "cloudflare-dns.com", "mozilla.cloudflare-dns.com",
    "doh.opendns.com", "doh.cleanbrowsing.org",
    "dns.quad9.net", "doh.familyshield.opendns.com",
})

BROWSER_PROCESSES = frozenset({
    "firefox", "firefox.exe", "firefox-bin",
    "chrome", "chrome.exe", "google-chrome", "google-chrome-stable",
    "msedge", "msedge.exe", "microsoft-edge",
    "safari", "brave", "brave.exe", "opera", "opera.exe",
    "vivaldi", "vivaldi.exe",
})


def looks_like_doh(remote_ip, remote_port, hostname):
    """Return True if a connection looks like DNS-over-HTTPS."""
    if remote_port != 443:
        return False
    # v1.4 (R6): require a DoH *hostname* signal (SNI / resolved name), not a bare
    # IP match — many resolver IPs (1.1.1.1, 8.8.8.8) serve ordinary HTTPS too, so
    # IP-only matching flagged benign `curl https://1.1.1.1` / health checks.
    if hostname:
        host_lower = hostname.lower()
        if any(host_lower == h or host_lower.endswith("." + h) for h in DOH_HOSTS):
            return True
    return False


def is_browser_process(app_name):
    if not app_name:
        return False
    return _normalize_app_name(app_name) in BROWSER_PROCESSES


# === v1.3: JA3 TLS fingerprinting (F-1.6) ===================================

# JA3 string = SSLVersion,Cipher,Extension,EllipticCurve,EllipticCurvePointFormat
# Reference: https://github.com/salesforce/ja3
# MD5 of that string is the JA3 hash. Small bundled list of known C2 JA3
# hashes — operators can swap in a richer feed via --ja3-feed.
KNOWN_BAD_JA3 = {
    # Cobalt Strike default profile (Java HTTPSURLConnection) — multiple known
    "72a589da586844d7f0818ce684948eea": "Cobalt Strike Java client",
    "a0e9f5d64349fb13191bc781f81f42e1": "Cobalt Strike (legacy)",
    "06c2c1c3c5d17cf26b8e58b67c1a8b8a": "Sliver beacon (default)",
    "e7d705a3286e19ea42f587b344ee6865": "Metasploit Meterpreter (Windows)",
    "51c64c77e60f3980eea90869b68c58a8": "Empire 3.x default",
}


def compute_ja3(client_hello_body):
    """Compute the JA3 hash given the TLS Client Hello body (without the
    record / handshake headers — starts at the ClientHello version field).

    Returns (ja3_string, ja3_hash) or (None, None) on parse failure.
    """
    try:
        buf = client_hello_body
        if len(buf) < 38:
            return None, None
        # ClientHello layout:
        # 2  version
        # 32 random
        # 1  session_id_length
        # session_id_length bytes session_id
        # 2  cipher_suites_length
        # cipher_suites_length bytes cipher_suites
        # 1  compression_methods_length
        # n  compression_methods
        # 2  extensions_length
        # extensions
        version = struct.unpack(">H", buf[0:2])[0]
        idx = 2 + 32
        sid_len = buf[idx]
        idx += 1 + sid_len
        if idx + 2 > len(buf):
            return None, None
        cs_len = struct.unpack(">H", buf[idx:idx+2])[0]
        idx += 2
        if idx + cs_len > len(buf):
            return None, None
        cipher_bytes = buf[idx:idx+cs_len]
        ciphers = [struct.unpack(">H", cipher_bytes[i:i+2])[0]
                   for i in range(0, cs_len, 2)]
        idx += cs_len
        if idx >= len(buf):
            return None, None
        cm_len = buf[idx]
        idx += 1 + cm_len
        if idx + 2 > len(buf):
            return None, None
        ext_total = struct.unpack(">H", buf[idx:idx+2])[0]
        idx += 2
        ext_end = idx + ext_total
        if ext_end > len(buf):
            return None, None
        extensions = []
        curves = []
        ec_formats = []
        # GREASE values to filter out per the JA3 spec
        GREASE = {0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
                  0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA}
        while idx + 4 <= ext_end:
            etype = struct.unpack(">H", buf[idx:idx+2])[0]
            elen = struct.unpack(">H", buf[idx+2:idx+4])[0]
            idx += 4
            if idx + elen > ext_end:   # extension body overruns the block — stop
                break
            ebody = buf[idx:idx+elen]
            idx += elen
            if etype in GREASE:
                continue
            extensions.append(etype)
            if etype == 0x000a and len(ebody) >= 2:   # supported_groups (curves)
                clen = struct.unpack(">H", ebody[0:2])[0]
                curves_bytes = ebody[2:2+clen]
                for i in range(0, len(curves_bytes), 2):
                    if i + 2 <= len(curves_bytes):
                        cv = struct.unpack(">H", curves_bytes[i:i+2])[0]
                        if cv not in GREASE:
                            curves.append(cv)
            elif etype == 0x000b and len(ebody) >= 1:  # ec_point_formats
                fmt_len = ebody[0]
                for b in ebody[1:1+fmt_len]:
                    ec_formats.append(b)
        ciphers_str = "-".join(str(c) for c in ciphers if c not in GREASE)
        ext_str = "-".join(str(e) for e in extensions)
        curves_str = "-".join(str(c) for c in curves)
        ec_fmt_str = "-".join(str(f) for f in ec_formats)
        ja3 = f"{version},{ciphers_str},{ext_str},{curves_str},{ec_fmt_str}"
        # Bandit B324 false positive — MD5 here is the JA3 spec, NOT crypto.
        ja3_hash = hashlib.md5(ja3.encode("ascii")).hexdigest()  # nosec B324 - JA3 spec
        return ja3, ja3_hash
    except (struct.error, IndexError, ValueError):
        return None, None


# === v1.3: ICMP-tunnel heuristic (F-1.3) ====================================
# Threshold: ≥50 echo packets to one peer AND avg payload > 1000 bytes.
ICMP_TUNNEL_MIN_PACKETS = 50
ICMP_TUNNEL_MIN_AVG_PAYLOAD = 1000


# === v1.3: Diff mode (F-6.3) ================================================

def load_run_json(path):
    """Load a previous run's JSON output (--json). Returns the parsed dict."""
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def compute_diff(old, new):
    """Compute the diff between two run dicts. Returns a dict with keys:
       new_flows / gone_flows / risk_transitions, each a list."""
    def _key(r):
        # v1.4 (B3): key on stable flow identity. pid and the ephemeral local
        # port change every run, so keying on them reported nearly every
        # persistent flow as both "gone" and "new" and missed real risk changes.
        rip = SecurityMonitor._remote_ip(r.get("remote") or "")
        rport = SecurityMonitor._remote_port(r.get("remote") or "")
        return (r.get("app"), rip, rport, r.get("status"))
    old_by_key = {_key(r): r for r in old.get("connections", [])}
    new_by_key = {_key(r): r for r in new.get("connections", [])}
    new_flows = [new_by_key[k] for k in new_by_key.keys() - old_by_key.keys()]
    gone_flows = [old_by_key[k] for k in old_by_key.keys() - new_by_key.keys()]
    transitions = []
    for k in new_by_key.keys() & old_by_key.keys():
        old_r = old_by_key[k]
        new_r = new_by_key[k]
        if old_r.get("risk") != new_r.get("risk"):
            transitions.append({"key": list(k),
                                "from": old_r.get("risk"),
                                "to":   new_r.get("risk"),
                                "row":  new_r})
    return {
        "new_flows": new_flows,
        "gone_flows": gone_flows,
        "risk_transitions": transitions,
    }


# === v1.3: Webhook alerting (F-9.1) =========================================

def send_webhook_alerts(webhook_url, conn_history, log_findings=None,
                       persistence=None, webshell=None, console=None):
    """POST a JSON payload of HIGH findings to a webhook. Caller passes URL.
    Errors are logged but never raised — alerting failure must not break
    the report run.

    INTERNAL / UNDOCUMENTED: the --alert-webhook CLI flag that drives this
    is hidden from --help on purpose (argparse.SUPPRESS). Reasoning:
        - it ships findings off-host to a third-party URL,
        - a stale $NETMON_WEBHOOK env var would leak data to the wrong sink,
        - operators who actually want this kept it discoverable via source.
    If you're reading this and want to enable: set $NETMON_WEBHOOK or pass
    --alert-webhook URL explicitly. Slack / Teams / Discord incoming
    webhooks all accept the payload shape below (rendering will be raw JSON;
    map through a relay if you want formatting). No custom headers / HMAC
    signing in v1.3 — treat the URL as a shared secret accordingly.
    """
    if not webhook_url:
        return
    high_rows = [c for c in conn_history.values()
                 if c.get("risk") == "HIGH"]
    high_logs = [e for e in (log_findings or [])
                 if e.get("severity") == "HIGH"]
    high_persist = [p for p in (persistence or [])
                    if p.get("recent")]
    if not (high_rows or high_logs or high_persist or webshell):
        return
    payload = {
        "tool":    f"netmon.py/{VERSION}",
        "host":    socket.gethostname(),
        "ts":      datetime.now().isoformat(),
        "high_conn_count": len(high_rows),
        "high_log_count":  len(high_logs),
        "recent_persistence": len(high_persist),
        "webshell_findings": len(webshell or []),
        "summary": _summarize_for_webhook(high_rows, high_logs, webshell or []),
    }
    try:
        requests.post(webhook_url, json=payload, timeout=HTTP_TIMEOUT)
        if console:
            console.print(f"[green]Webhook alert sent:[/green] {webhook_url}")
    except requests.RequestException as e:
        log.warning("webhook alert failed: %s", e)
        if console:
            console.print(f"[yellow]Webhook alert failed:[/yellow] {e}")


def _summarize_for_webhook(rows, logs, webshell):
    """Build a small human-readable summary for the webhook body."""
    lines = []
    for c in rows[:20]:
        lines.append(f"  HIGH conn: {c.get('app')} {c.get('local')} → "
                     f"{c.get('remote')} [{', '.join(c.get('flags') or [])}]")
    for e in logs[:20]:
        lines.append(f"  HIGH log:  {e.get('source')} {e.get('event_id')} — {e.get('message','')[:120]}")
    for w in webshell[:20]:
        lines.append(f"  WEBSHELL:  {w.get('path')} [{', '.join(w.get('flags') or [])}]")
    return "\n".join(lines)


def classify_local_ip(ip):
    """Categorize a non-public IP. Returns a human-readable label or None.

    Used to render meaningful Geo/Org values for loopback/LAN/wildcard
    addresses instead of empty 'N/A' fields. None means 'public — go
    through GeoIP'.
    """
    if not ip:
        return "no remote"
    if ip in ("0.0.0.0", "::"):  # nosec B104 - classification, not bind
        return "wildcard (any-interface listen)"
    if ip.startswith("127.") or ip == "::1":
        return "loopback (this host)"
    if ip.startswith("169.254.") or ip.lower().startswith("fe80:"):
        return "link-local"
    # IPv4 RFC1918 private ranges
    octets = ip.split(".")
    if len(octets) == 4:
        try:
            o0, o1 = int(octets[0]), int(octets[1])
            if o0 == 10:
                return "private LAN (10.0.0.0/8)"
            if o0 == 172 and 16 <= o1 <= 31:
                return "private LAN (172.16.0.0/12)"
            if o0 == 192 and o1 == 168:
                return "private LAN (192.168.0.0/16)"
            if o0 == 100 and 64 <= o1 <= 127:
                return "carrier-grade NAT (100.64.0.0/10)"
        except ValueError:
            pass
    # IPv6 ULA fc00::/7
    if ip.lower().startswith(("fc", "fd")):
        return "private LAN (IPv6 ULA)"
    # IPv6 multicast
    if ip.lower().startswith("ff"):
        return "IPv6 multicast"
    return None


class ThreatIntel:
    def __init__(self, offline=False, scan_tor=False, threat_intel=False, console=None):
        self.offline = offline
        self.scan_tor = scan_tor
        self.threat_intel = threat_intel
        self.console = console
        self.tor_exits = set()
        self.c2_ips = set()         # curated, high-confidence -> CRITICAL
        self.c2_ips_broad = set()   # broad history -> HIGH
        self._whois_cache = {}
        self._cache_dir = _safe_cache_dir()
        # Tor exit-list fetch is OPT-IN (--scan-tor / --deep-triage). v1.1 made
        # it default-on and many networks SNI-filter torproject.org, producing a
        # noisy warning on every run — and on a possibly-compromised host you do
        # NOT want the triage tool itself reaching out to torproject.org.
        if not offline and scan_tor:
            self._load_tor_exits()
        # Botnet-C2 IP feed (abuse.ch Feodo). Opt-in (--threat-intel /
        # --deep-triage) so QUICK triage makes no external intel calls.
        if not offline and threat_intel:
            self._load_c2_feed()

    def _load_tor_exits(self):
        cache_file = self._cache_dir / "tor_exits.txt"
        # Try cache first.
        try:
            if cache_file.exists():
                age = time.time() - cache_file.stat().st_mtime
                if age < TOR_CACHE_TTL and cache_file.stat().st_size <= MAX_TOR_LIST_BYTES:
                    self.tor_exits = {
                        ln for ln in cache_file.read_text().splitlines()
                        if _is_valid_ip(ln)
                    }
                    return
        except OSError as e:
            log.debug("tor cache read failed: %s", e)
        # Fetch from network with size cap and IP validation.
        try:
            ips = set()
            with requests.get(TOR_EXIT_LIST_URL, timeout=TOR_FETCH_TIMEOUT, stream=True) as r:
                if r.status_code != 200:
                    log.warning("tor list HTTP %d", r.status_code)
                    return
                buf = bytearray()
                for chunk in r.iter_content(chunk_size=65536):
                    buf.extend(chunk)
                    if len(buf) > MAX_TOR_LIST_BYTES:
                        log.warning("tor list exceeded %d bytes; aborting", MAX_TOR_LIST_BYTES)
                        return
                for raw_line in buf.decode("ascii", errors="replace").splitlines():
                    line = raw_line.strip()
                    if line and not line.startswith("#") and _is_valid_ip(line):
                        ips.add(line)
            self.tor_exits = ips
            try:
                cache_file.write_text("\n".join(sorted(ips)))
            except OSError as e:
                log.debug("tor cache write failed: %s", e)
        except requests.RequestException as e:
            # Most common cause in restrictive jurisdictions is SNI-based
            # TLS filtering by the local ISP — DNS resolves and TCP connects
            # but the TLS handshake stalls (ConnectTimeout/ReadTimeout). Give
            # the operator enough context to act on the warning instead of
            # filing it under "weird transient error".
            hint = ""
            err_text = str(e).lower()
            if "timed out" in err_text or "timeout" in err_text:
                hint = (" — your ISP is likely TLS-SNI-filtering "
                        "torproject.org. Tor exit detection will be unavailable "
                        "this run. Workarounds: pass --offline to suppress, "
                        "pre-seed the cache from another network, or use a VPN.")
            elif "ssl" in err_text or "certificate" in err_text:
                hint = (" — TLS error reaching torproject.org; possible MITM "
                        "or cert issue.")
            log.warning("tor list fetch failed: %s%s", e, hint)

    def is_tor_exit(self, ip):
        return ip in self.tor_exits

    def _fetch_ip_set(self, url, cache_name):
        """Fetch a newline-delimited IP blocklist with 24h cache, 8 MB cap and
        per-line inet validation. Returns a set of IPv4 strings (never raises) —
        a poisoned upstream can neither DoS nor inject."""
        cache_file = self._cache_dir / cache_name
        try:
            if cache_file.exists():
                age = time.time() - cache_file.stat().st_mtime
                if age < C2_FEED_CACHE_TTL and cache_file.stat().st_size <= MAX_TOR_LIST_BYTES:
                    return {ln for ln in cache_file.read_text().splitlines() if _is_valid_ip(ln)}
        except OSError as e:
            log.debug("c2 cache read failed (%s): %s", cache_name, e)
        ips = set()
        try:
            with requests.get(url, timeout=TOR_FETCH_TIMEOUT, stream=True) as r:
                if r.status_code != 200:
                    log.warning("c2 feed HTTP %d (%s)", r.status_code, url)
                    return ips
                buf = bytearray()
                for chunk in r.iter_content(chunk_size=65536):
                    buf.extend(chunk)
                    if len(buf) > MAX_TOR_LIST_BYTES:
                        log.warning("c2 feed exceeded %d bytes; aborting", MAX_TOR_LIST_BYTES)
                        return ips
                for raw_line in buf.decode("ascii", errors="replace").splitlines():
                    line = raw_line.strip()
                    if line and not line.startswith("#") and _is_valid_ip(line):
                        ips.add(line)
            try:
                cache_file.write_text("\n".join(sorted(ips)))
            except OSError as e:
                log.debug("c2 cache write failed (%s): %s", cache_name, e)
        except requests.RequestException as e:
            log.warning("c2 feed fetch failed (%s): %s", url, e)
        return ips

    def _load_c2_feed(self):
        """Load the abuse.ch Feodo Tracker C2 IP blocklists (free, no auth, open
        data, single trusted host) in two confidence tiers:
          - ipblocklist.txt             currently-active, high-confidence -> CRITICAL
          - ipblocklist_aggressive.txt  broad history (thousands)         -> HIGH
        The curated list is often tiny (single digits); the aggressive list is
        what gives real coverage."""
        self.c2_ips = self._fetch_ip_set(C2_FEED_URL, "c2_feed.txt")
        self.c2_ips_broad = self._fetch_ip_set(C2_FEED_AGGRESSIVE_URL, "c2_feed_aggressive.txt")
        if self.console:
            self.console.print(
                f"[dim]Threat-intel: {len(self.c2_ips)} high-confidence + "
                f"{len(self.c2_ips_broad)} historical C2 IPs (abuse.ch Feodo Tracker).[/dim]")

    def is_known_c2(self, ip):
        return ip in self.c2_ips or ip in self.c2_ips_broad

    def c2_confidence(self, ip):
        """'high' = curated / currently-active (CRITICAL); 'broad' = historical
        (HIGH); None = not listed."""
        if ip in self.c2_ips:
            return "high"
        if ip in self.c2_ips_broad:
            return "broad"
        return None

    def whois(self, ip):
        if not HAS_IPWHOIS or self.offline or not ip:
            return None
        if ip in self._whois_cache:
            return self._whois_cache[ip]
        try:
            data = IPWhois(ip).lookup_rdap(depth=0)
            result = {
                "asn": data.get("asn"),
                "asn_description": data.get("asn_description"),
                "asn_country": data.get("asn_country_code"),
                "network_name": (data.get("network") or {}).get("name"),
                "cidr": (data.get("network") or {}).get("cidr"),
            }
            self._whois_cache[ip] = result
            return result
        except Exception as e:  # ipwhois raises a wide range of exception types
            log.debug("whois lookup failed for %s: %s", ip, e)
            self._whois_cache[ip] = None
            return None


# === VirusTotal (optional, requires free user-supplied API key) ===

class VirusTotalClient:
    BASE = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key, console=None):
        self.api_key = api_key
        self.console = console
        self.cache = {}

    @staticmethod
    def _is_valid_sha256(s):
        return isinstance(s, str) and len(s) == 64 and all(c in "0123456789abcdef" for c in s.lower())

    def lookup_hash(self, sha256):
        if not self.api_key or not self._is_valid_sha256(sha256):
            return None
        if sha256 in self.cache:
            return self.cache[sha256]
        try:
            r = requests.get(
                f"{self.BASE}/files/{urllib.parse.quote(sha256, safe='')}",
                headers={"x-apikey": self.api_key},
                timeout=HTTP_TIMEOUT,
            )
            if r.status_code == 404:
                self.cache[sha256] = {"found": False}
                return self.cache[sha256]
            if r.status_code == 200:
                attrs = r.json().get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {}) or {}
                self.cache[sha256] = {
                    "found": True,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "type_description": attrs.get("type_description"),
                    "meaningful_name": attrs.get("meaningful_name"),
                    "reputation": attrs.get("reputation", 0),
                }
                return self.cache[sha256]
            if r.status_code == 429:
                log.warning("virustotal: rate limited (HTTP 429)")
            elif r.status_code in (401, 403):
                log.error("virustotal: auth failed (HTTP %d) — check API key", r.status_code)
            else:
                log.debug("virustotal: HTTP %d for hash lookup", r.status_code)
        except (requests.RequestException, ValueError) as e:
            log.debug("virustotal lookup failed: %s", e)
        # v1.4 (F7): do NOT cache transient failures (429 / auth / network) — a
        # routine free-tier rate-limit would otherwise become a permanent
        # per-hash blind spot for the rest of the run. Only 200/404 are cached.
        return None


# === Main monitor ===

class SecurityMonitor:
    def __init__(self, args, console):
        self.args = args
        self.console = console
        self.conn_history = {}
        # First-seen timestamp per unique (pid, local_addr, remote_addr).
        # A "beacon" = many distinct local-port attempts to the same remote at regular intervals.
        self.first_seen = {}
        # Map (pid, local, remote) -> wall-clock start time for the session age column.
        self.session_start = {}
        self.ip_cache = {}
        self.file_hash_cache = {}
        # Per-process metadata cache keyed by pid -> (create_time, meta). The
        # monitor polls every second; without this cache each pass re-ran ~6
        # psutil calls + a SHA-256 for every connection. create_time validation
        # also defeats PID reuse (a recycled PID forces a fresh resolve).
        self._proc_meta_cache = {}
        self.headers = {"User-Agent": f"netmon.py/{VERSION}"}
        # Code-signing/trust checker. On Windows: Authenticode. On Linux:
        # owning-package via dpkg/rpm/pacman/apk. On macOS: codesign.
        no_signing = getattr(args, "no_signing", False)
        if sys.platform == "win32":
            self.signing = SignatureChecker(enabled=not no_signing)
        elif sys.platform.startswith("linux"):
            self.signing = LinuxPackageChecker(enabled=not no_signing)
        elif sys.platform == "darwin":
            self.signing = MacOSSignatureChecker(enabled=not no_signing)
        else:
            self.signing = SignatureChecker(enabled=False)
        self.threat = ThreatIntel(
            offline=args.offline,
            scan_tor=getattr(args, "scan_tor", False),
            threat_intel=getattr(args, "threat_intel", False),
            console=console,
        )
        self.vt = VirusTotalClient(args.vt_api_key, console=console) if args.vt_api_key else None
        # CrowdSec — only meaningful on Linux hosts that run CrowdSec.
        if (sys.platform.startswith("linux")
                and not getattr(args, "no_crowdsec", False)
                and not args.offline):
            self.crowdsec = CrowdSecClient(
                token=getattr(args, "crowdsec_token", None),
                console=console,
            )
        else:
            self.crowdsec = None
        # Firewall state snapshot. Cheap one-shot probe at startup; subsequent
        # rows reuse the cached verdict.
        self.firewall = FirewallState() if not getattr(args, "no_firewall", False) else None
        self.flow = None
        self.capture = None
        self.dns_findings = []
        self.saved_pcap_path = None
        # v1.3 finding collections — populated during monitor()
        self.log_findings = []         # F-3
        self.log_sources_skipped = []  # F-3 — list of (source, reason) tuples
        self.persistence_findings = []  # F-4
        self.webshell_findings = []     # F-2.3
        self.diff_result = None         # F-6.3

    # --- file hashing ---
    def get_file_hash(self, path):
        """Compute SHA256 of a file. TOCTOU-resistant: open first, then fstat
        the open fd to confirm it's a regular file."""
        if not path or path in ("N/A", "Access Denied"):
            return "N/A"
        if path in self.file_hash_cache:
            return self.file_hash_cache[path]
        try:
            # Open then stat the fd — defeats symlink-swap races between
            # check and open. We tolerate symlinks because psutil.Process.exe()
            # may resolve to one on POSIX, but we refuse non-regular files.
            with open(path, "rb") as f:
                st = os.fstat(f.fileno())
                if not stat_mod.S_ISREG(st.st_mode):
                    self.file_hash_cache[path] = "N/A"
                    return "N/A"
                if st.st_size > 2 * 1024 * 1024 * 1024:  # 2 GB sanity cap
                    self.file_hash_cache[path] = "TOO_LARGE"
                    return "TOO_LARGE"
                sha256_hash = hashlib.sha256()
                for byte_block in iter(lambda: f.read(65536), b""):
                    sha256_hash.update(byte_block)
                digest = sha256_hash.hexdigest()
                self.file_hash_cache[path] = digest
                return digest
        except (PermissionError, OSError) as e:
            log.debug("hash failed for %s: %s", path, e)
            self.file_hash_cache[path] = "ACCESS_DENIED"
            return "ACCESS_DENIED"

    # --- IP enrichment ---
    @staticmethod
    def _is_local_ip(ip):
        # Bandit B104 false positive: we DETECT 0.0.0.0 as a local/wildcard
        # address; we never bind a socket to it.
        if not ip:
            return True
        return (ip.startswith("127.") or ip == "::1"
                or ip.startswith("0.0.0.0") or ip == "0.0.0.0"  # nosec B104 - pattern check, not bind
                or ip.startswith("169.254.")
                or ip.startswith("fe80:") or ip == "::")

    def get_ip_details(self, ip):
        """Looks up enrichment from cache. Local/private IPs get a descriptive
        label (loopback / private LAN / link-local) instead of N/A so analysts
        can see at a glance why GeoIP wasn't attempted. Public IPs return
        placeholder until batch_enrich_ips() runs."""
        local_label = classify_local_ip(ip)
        if local_label:
            return {"country": "—", "country_code": "", "org": local_label,
                    "hostname": "N/A", "asn": None, "is_tor": False, "is_private": True}
        if ip in self.ip_cache:
            return self.ip_cache[ip]
        return {"country": "Unknown", "country_code": "", "org": "Unknown",
                "hostname": "N/A", "asn": None, "is_tor": False, "is_private": False}

    def batch_enrich_ips(self):
        """Resolve all unique remote IPs: HTTPS GeoIP via ipwho.is + threaded rDNS.

        SECURITY: previously used http://ip-api.com (cleartext); switched to
        https://ipwho.is which is HTTPS, free, and requires no API key. The
        per-call latency is higher than ip-api's /batch endpoint, but a
        ThreadPoolExecutor compensates and the entire enrichment phase still
        completes in a few seconds for typical workloads.
        """
        from concurrent.futures import ThreadPoolExecutor

        unique_ips = set()
        for conn in self.conn_history.values():
            ip = conn.get("remote_ip")
            if ip and not self._is_local_ip(ip) and ip not in self.ip_cache:
                unique_ips.add(ip)
        if not unique_ips:
            return

        # Pre-populate every IP so subsequent thread mutations only update
        # existing keys (avoids race on key creation).
        for ip in unique_ips:
            self.ip_cache[ip] = {
                "country": "Unknown", "country_code": "", "org": "Unknown",
                "hostname": "N/A", "asn": None,
                "is_tor": self.threat.is_tor_exit(ip), "is_private": False,
            }

        def _rdns(ip):
            try:
                return ip, socket.gethostbyaddr(ip)[0]
            except (OSError, socket.herror, socket.gaierror):
                return ip, None

        def _geoip(ip):
            """Single-IP HTTPS GeoIP lookup via ipwho.is."""
            try:
                r = requests.get(
                    f"https://ipwho.is/{urllib.parse.quote(ip, safe='')}",
                    timeout=HTTP_TIMEOUT,
                    headers=self.headers,
                )
                if r.status_code != 200:
                    return ip, None
                d = r.json()
                if not d.get("success"):
                    return ip, None
                conn = d.get("connection") or {}
                return ip, {
                    "country": d.get("country") or "Unknown",
                    "country_code": d.get("country_code") or "",
                    "org": conn.get("isp") or conn.get("org") or "Unknown",
                    "asn": (f"AS{conn['asn']} {conn.get('org') or ''}".strip()
                            if conn.get("asn") else None),
                }
            except (requests.RequestException, ValueError) as e:
                log.debug("geoip lookup failed for %s: %s", ip, e)
                return ip, None

        with ThreadPoolExecutor(max_workers=16) as ex:
            for ip, name in ex.map(_rdns, list(unique_ips)):
                if name:
                    self.ip_cache[ip]["hostname"] = name

        if self.args.offline:
            return

        with ThreadPoolExecutor(max_workers=12) as ex:
            for ip, info in ex.map(_geoip, list(unique_ips)):
                if info:
                    self.ip_cache[ip].update(info)

        # Fallback: WHOIS RDAP for IPs whose GeoIP failed.
        if HAS_IPWHOIS:
            unresolved = [ip for ip in unique_ips
                          if self.ip_cache[ip]["org"] in ("Unknown", "", None)]
            for ip in unresolved[:25]:  # cap; RDAP is slow
                who = self.threat.whois(ip)
                if who and who.get("asn_description"):
                    self.ip_cache[ip]["org"] = who["asn_description"]
                    self.ip_cache[ip]["asn"] = who.get("asn")

    # --- risk model ---
    def analyze_risk(self, conn):
        score = 0
        flags = []
        # v1.4 (Stage 2): confirmed-bad evidence → CRITICAL regardless of score.
        # Heuristic signals only sum toward HIGH; this separates "confirmed" from
        # "suspicious" so a wall of unsigned dev tools never outranks real malware.
        confirmed = False
        path_lower = (conn["path"] or "").lower().replace("/", "\\")
        app_lower = (conn["app"] or "").lower()

        # 1. Hard suspicious paths (Temp, Public, Recycle Bin, /tmp)
        if any(frag in path_lower for frag in (s.lower() for s in HIGH_RISK_PATH_FRAGMENTS)):
            score += 3
            flags.append("HIGH_RISK_PATH")

        # 2. System binary in wrong location (e.g. svchost.exe outside System32).
        # v1.4 (F2): anchor the expected directory to the START of the path (after
        # the drive letter) instead of substring-anywhere, so an attacker folder
        # like C:\Users\Public\Windows\System32\svchost.exe no longer passes.
        expected = SYSTEM_BINARY_LOCATIONS.get(app_lower)
        if expected and path_lower and path_lower not in ("n/a", "access denied"):
            anchored = path_lower[2:] if (len(path_lower) > 2 and path_lower[1] == ":") else path_lower
            if not any(anchored.startswith(loc) for loc in expected):
                score += 5
                confirmed = True  # masquerading as a system binary is confirmed-bad
                flags.append("IMPOSTOR_SYSTEM_BIN")

        # 3. Suspicious port
        port = self._remote_port(conn["remote"])
        if port in SUSPICIOUS_PORTS:
            score += 3
            flags.append(f"SUSPICIOUS_PORT_{port}")

        # 4. Tor exit node
        ip = self._remote_ip(conn["remote"])
        if ip and self.threat.is_tor_exit(ip):
            score += 3
            flags.append("TOR_EXIT")

        # 4a. Known botnet-C2 IP (abuse.ch Feodo feed; armed by --threat-intel /
        # --deep-triage). A confirmed-bad destination is HIGH on its own.
        # v1.4: abuse.ch Feodo C2 feed, tiered by confidence. The curated
        # high-confidence list (currently-active C2) is CONFIRMED -> CRITICAL;
        # the broad historical list is HIGH (the IP was C2 but may be stale).
        c2_conf = self.threat.c2_confidence(ip) if ip else None
        if c2_conf == "high":
            score += 5
            confirmed = True
            flags.append("C2_FEED_MATCH")
        elif c2_conf == "broad":
            score += 5
            flags.append("C2_FEED_HISTORICAL")

        # 4b. CrowdSec verdict on the remote IP (T2-1)
        cs_verdict = conn.get("crowdsec")
        if cs_verdict == "ban":
            score += 3
            flags.append("CROWDSEC_BANNED")
        elif cs_verdict in ("captcha", "throttle"):
            score += 1
            flags.append(f"CROWDSEC_{cs_verdict.upper()}")

        # 5. Soft path + unsigned binary = MED bump
        sig = conn.get("signature") or {}
        is_signed_trusted = sig.get("trusted", False)
        is_signed = sig.get("signed", False)
        is_tampered = sig.get("tampered", False)

        # 5b. PACKAGE_TAMPERED (T1-1) — Linux package-manager integrity check
        # failed for this binary. Modified system binaries are a major IoC,
        # so this is HIGH-risk on its own.
        if is_tampered:
            score += 5
            confirmed = True  # a modified packaged binary is confirmed-bad
            flags.append("PACKAGE_TAMPERED")

        soft_path_hit = any(frag in path_lower for frag in (s.lower() for s in SOFT_SUSPICIOUS_PATH_FRAGMENTS))
        if soft_path_hit:
            if is_signed_trusted:
                pass  # trusted publisher in AppData/Roaming → don't penalize
            elif is_signed:
                score += 1
                flags.append("USER_PATH_UNTRUSTED_SIGNER")
            else:
                score += 2
                flags.append("UNSIGNED_USER_PATH")

        # === Direction-aware C2 detection (T1-2) ===
        # Pre-computed by the monitor — 'INBOUND' / 'OUTBOUND' / 'LOOPBACK' /
        # 'LISTEN' / 'AMBIGUOUS'. INBOUND means we're the server side of the
        # socket, so UNSIGNED_OUTBOUND_C2 must NOT fire (an inbound SSH from
        # a random WAN IP is exactly what sshd is supposed to accept).
        direction = conn.get("direction") or classify_direction(
            conn.get("local"), conn.get("remote"), conn.get("status")
        ) or "AMBIGUOUS"
        status = (conn.get("status") or "").upper()

        # 6. Unsigned binary with network activity. Skip if this is a known
        # server-role binary on its expected port handling an inbound
        # connection — that's the daemon doing its job.
        is_known_server = (server_expected_port(conn.get("app"), self._local_port(conn["local"]))
                           or server_expected_port(conn.get("app"), port))
        suppress_unsigned = (
            is_known_server
            and direction in ("INBOUND", "LISTEN")
            and not is_tampered
        )

        # v1.4 (R1): unsigned alone is WEAK. On Linux every locally-built / pip /
        # npm / cargo binary is "unsigned"; on Windows so is every portable / venv
        # / dev tool. So unsigned (+1) and unsigned-outbound (+1) sum only to MED,
        # and HIGH now REQUIRES a corroborating signal (bad path/port, Tor, C2
        # feed, CrowdSec, beacon, JA3, VT, cmdline) rather than unsigned alone.
        if (conn["path"] and conn["path"] not in ("N/A", "Access Denied")
                and ip and not is_signed and not suppress_unsigned):
            score += 1
            flags.append("UNSIGNED_BINARY")

        # 6b. UNSIGNED_OUTBOUND_C2: fires for OUTBOUND or AMBIGUOUS direction.
        # An inbound SSH session from a public IP (direction=INBOUND) is NOT
        # C2 — but AMBIGUOUS (both sides in the user-port range) defaults to
        # the v1.2 behavior so client traffic with a low local ephemeral port
        # (e.g. Win 7-style 1024+ range) still gets flagged.
        if (conn["path"] and conn["path"] not in ("N/A", "Access Denied")
                and ip and not is_signed
                and status == "ESTABLISHED"
                and classify_local_ip(ip) is None
                and direction in ("OUTBOUND", "AMBIGUOUS")
                and not suppress_unsigned):
            score += 1
            flags.append("UNSIGNED_OUTBOUND_C2")

        # 6c. INBOUND_SESSION informational flag (no risk bump). Surfaces the
        # inbound flow in the UI so operators can spot unexpected listeners.
        if direction == "INBOUND" and status == "ESTABLISHED":
            flags.append("INBOUND_SESSION")
            # 6d. INBOUND_FROM_TOR — real signal: an exposed service taking
            # connections from Tor exits is almost always abusive scanning.
            if ip and self.threat.is_tor_exit(ip):
                score += 3
                flags.append("INBOUND_FROM_TOR")

        # 6e. REVERSE_SHELL_LIKELY (T2-4): a server-role process (sshd,
        # apache2, …) making an OUTBOUND connection to a public IP. Server
        # daemons accept inbound, they don't dial out — this is the textbook
        # reverse-shell fingerprint regardless of whether the binary is
        # signed / packaged.
        # v1.4 (R2): require a NON-web destination port. Legit web servers dial
        # out on 80/443 constantly (proxy_pass upstreams, ACME/OCSP, webhooks); a
        # server daemon connecting OUT to an odd port is the real signal.
        if (is_server_binary(conn.get("app"))
                and direction == "OUTBOUND"
                and status == "ESTABLISHED"
                and ip and classify_local_ip(ip) is None
                and port not in (80, 443, 8080, 8443)):
            score += 5
            flags.append("REVERSE_SHELL_LIKELY")

        # 6f. IMPOSTOR_LISTEN_PORT: a known server binary bound to a port that
        # is NOT in its expected port set. e.g. sshd listening on :8888.
        if direction == "LISTEN" and is_server_binary(conn.get("app")):
            lport = self._local_port(conn["local"])
            if lport and not server_expected_port(conn.get("app"), lport):
                score += 2
                flags.append("IMPOSTOR_LISTEN_PORT")

        # === v1.3 — additional detection content ===

        # F-5.1: Suspicious command-line patterns.
        cmdline = conn.get("cmdline") or ""
        if cmdline:
            sev, cmd_flags = analyze_cmdline(cmdline)
            if cmd_flags:
                for f in cmd_flags:
                    if f not in flags:
                        flags.append(f)
                if sev == "HIGH":
                    score += 5
                elif sev == "MED":
                    score += 2
                # v1.4: an actual reverse-shell / dropper one-liner is confirmed-bad.
                if any(k in cf for cf in cmd_flags
                       for k in ("REV_SHELL", "DOWNLOAD_PIPE_SHELL", "BASH_C_CURL")):
                    confirmed = True

        # F-2.1: Web-shell spawn — web-server process has a blocklisted child.
        # Implemented as: this row IS the blocklisted child AND its parent is
        # a web server. (Detecting both halves of the relationship.)
        if (is_blocklisted_child(conn.get("app"))
                and is_web_server_process(conn.get("parent_app"))):
            score += 5
            confirmed = True  # web server spawning a shell is confirmed-bad
            flags.append("WEB_SHELL_SPAWN")

        # F-2.5: Web-runtime user making outbound to public — extremely
        # suspicious because legitimate web servers don't dial out.
        if (is_web_user(conn.get("user"))
                and direction == "OUTBOUND"
                and ip and classify_local_ip(ip) is None
                and status == "ESTABLISHED"):
            score += 4
            flags.append("WEBUSER_OUTBOUND")

        # F-1.5: DoH from a non-browser process — likely covert C2.
        if (status == "ESTABLISHED"
                and looks_like_doh(ip, conn.get("remote_port"), conn.get("hostname"))
                and not is_browser_process(conn.get("app"))):
            score += 3
            flags.append("DOH_FROM_NON_BROWSER")

        # F-1.1: SCTP to a public IP — almost never legitimate.
        if (conn.get("transport") == "sctp"
                and ip and classify_local_ip(ip) is None):
            score += 2
            flags.append("SCTP_UNUSUAL")

        # F-1.2: Unix socket with non-root process attached to docker.sock —
        # well-known container-escape pre-cursor.
        if (conn.get("transport") == "unix"
                and "docker.sock" in (conn.get("local") or "")
                and conn.get("user") not in ("root", "N/A", "Access Denied", "")):
            score += 4
            flags.append("UNIX_SOCKET_DOCKER")

        # F-1.6: Known-bad JA3 fingerprint.
        ja3 = conn.get("ja3")
        if ja3 and ja3 in KNOWN_BAD_JA3:
            score += 5
            confirmed = True  # known-C2 TLS fingerprint is confirmed-bad
            flags.append(f"JA3_C2_{KNOWN_BAD_JA3[ja3][:24].replace(' ', '_')}")

        # F-1.3: ICMP-tunnel — peer flagged by FlowAnalyzer's per-peer
        # echo-packet / payload thresholds. Conn has the matching remote_ip.
        if ip and conn.get("icmp_tunnel"):
            score += 3
            flags.append("ICMP_TUNNEL_LIKELY")

        # 7. VT malicious hits
        vt = conn.get("vt")
        if vt and vt.get("found"):
            mal = vt.get("malicious", 0)
            if mal >= 5:
                score += 5
                confirmed = True  # multi-vendor VT malicious is confirmed-bad
                flags.append(f"VT_MALICIOUS_{mal}")
            elif mal >= 1:
                score += 2
                flags.append(f"VT_MALICIOUS_{mal}")
            elif vt.get("suspicious", 0) >= 1:
                score += 1
                flags.append("VT_SUSPICIOUS")

        # 8. Beaconing (filled in later, after history accumulated)

        # v1.4 tiers: CONFIRMED-bad → CRITICAL; otherwise additive heuristic score.
        if confirmed:
            return "CRITICAL", flags
        if score >= 5:
            return "HIGH", flags
        if score >= 2:
            return "MED", flags
        return "LOW", flags

    @staticmethod
    def _remote_ip(remote):
        if not remote:
            return None
        # IPv6: [::1]:443  or  ::1:443
        if remote.startswith("["):
            return remote.split("]")[0][1:]
        parts = remote.rsplit(":", 1)
        if len(parts) != 2:
            return None
        ip = parts[0]
        return ip or None

    @staticmethod
    def _remote_port(remote):
        if not remote:
            return None
        try:
            return int(remote.rsplit(":", 1)[-1])
        except (ValueError, IndexError):
            return None

    @staticmethod
    def _local_port(local):
        if not local:
            return None
        try:
            if local.startswith("["):
                return int(local.split("]:", 1)[1])
            return int(local.rsplit(":", 1)[-1])
        except (ValueError, IndexError):
            return None

    # --- beacon detection ---
    def detect_beacons(self):
        """Detect periodic outbound calls — same (pid, remote) opens multiple
        distinct local sockets at regular intervals."""
        # Group first-seen timestamps by (pid, remote_addr); ignore local-only flows.
        attempts = defaultdict(list)
        for (pid, _local, remote), ts in self.first_seen.items():
            if not remote or not pid:
                continue
            ip = self._remote_ip(remote)
            if not ip or self._is_local_ip(ip):
                continue
            attempts[(pid, remote)].append(ts)

        beacons = {}
        for (pid, remote), ts_list in attempts.items():
            if len(ts_list) < 4:
                continue
            ts_list.sort()
            intervals = [ts_list[i + 1] - ts_list[i] for i in range(len(ts_list) - 1)]
            mean = sum(intervals) / len(intervals)
            if mean < 1.0:
                continue
            variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
            stdev = variance ** 0.5
            if mean > 0 and stdev / mean < 0.20:
                beacons[(pid, remote)] = {
                    "mean_interval_s": round(mean, 2),
                    "attempts": len(ts_list),
                }
        return beacons

    # --- main loop ---
    def _netmon_self_pids(self):
        """Return the set of PIDs that belong to *this* netmon run: our own
        PID plus any descendant processes spawned by us (pktmon / tcpdump /
        PowerShell sig-verify children / etc.). Connections owned by these
        PIDs are tagged is_netmon_self=True so the HTML report hides them by
        default (an analyst's first view shouldn't be polluted by the
        monitor's own footprint). Recomputed each enumeration so newly-
        spawned children are caught."""
        pids = {os.getpid()}
        try:
            me = psutil.Process(os.getpid())
            for child in me.children(recursive=True):
                pids.add(child.pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
            pass
        return pids

    def _resolve_proc_meta(self, pid, default_app):
        """Resolve per-process metadata (name/exe/user/hash/cmdline/ppid/parent),
        cached by (pid, create_time) so the per-second monitor loop doesn't
        re-run ~6 psutil calls + a SHA-256 for every connection on every pass.
        create_time validation also defeats PID reuse."""
        meta_default = {
            "app": default_app, "path": "N/A", "user": "N/A", "hash": "N/A",
            "cmdline": "", "ppid": None, "parent_app": "",
        }
        if not pid:
            return meta_default
        proc = None
        ctime = None
        try:
            proc = psutil.Process(pid)
            ctime = proc.create_time()
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
            pass
        if ctime is not None:
            cached = self._proc_meta_cache.get(pid)
            if cached is not None and cached[0] == ctime:
                return cached[1]
        meta = dict(meta_default)
        try:
            if proc is None:
                proc = psutil.Process(pid)
            meta["app"] = proc.name()
            meta["path"] = proc.exe()
            meta["user"] = proc.username()
            meta["hash"] = self.get_file_hash(meta["path"])
            try:
                meta["cmdline"] = " ".join(proc.cmdline())[:4096]
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                meta["cmdline"] = ""
            try:
                ppid = proc.ppid()
                meta["ppid"] = ppid
                if ppid:
                    meta["parent_app"] = psutil.Process(ppid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                meta["ppid"] = None
                meta["parent_app"] = ""
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            meta["app"] = "System/Protected"
            meta["path"] = "Access Denied"
        if ctime is not None:
            if len(self._proc_meta_cache) > 200_000:
                self._proc_meta_cache.clear()
            self._proc_meta_cache[pid] = (ctime, meta)
        return meta

    def _prewarm_hashes(self):
        """Hash the executables of processes that currently hold sockets, in
        parallel, so the per-second monitor loop never blocks on a cold SHA-256.
        Only the connected pids are hashed (the same set the loop needs).
        Best-effort — any failure falls back to the inline get_file_hash path."""
        try:
            pids = {c.pid for c in psutil.net_connections(kind="inet") if c.pid}
        except (psutil.Error, OSError):
            return
        paths = set()
        for pid in pids:
            try:
                exe = psutil.Process(pid).exe()
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                continue
            if exe and exe not in self.file_hash_cache:
                paths.add(exe)
        if not paths:
            return
        self.console.print(f"[dim]Pre-hashing {len(paths)} binaries...[/dim]")
        try:
            from concurrent.futures import ThreadPoolExecutor
            workers = min(8, (os.cpu_count() or 2) * 2)
            with ThreadPoolExecutor(max_workers=workers) as ex:
                list(ex.map(self.get_file_hash, paths))
        except (OSError, RuntimeError) as e:
            log.debug("hash prewarm failed: %s", e)

    def get_connections(self):
        connections = []
        self_pids = self._netmon_self_pids()
        for conn in psutil.net_connections(kind="inet"):
            try:
                local_addr = self._fmt_addr(conn.laddr)
                remote_addr = self._fmt_addr(conn.raddr)
                pid = conn.pid
                # v1.3: pid=0 means the kernel holds an orphaned 4-tuple after
                # the original owner exited — almost always TIME_WAIT or
                # CLOSE_WAIT residue. Label it explicitly so analysts (and
                # any AV / IR / auditor reviewing the report) don't read
                # "Unknown" as "unidentified suspicious process".
                status_upper = (conn.status or "").upper()
                if pid in (0, None) and status_upper in (
                        "TIME_WAIT", "CLOSE_WAIT", "FIN_WAIT1", "FIN_WAIT2",
                        "LAST_ACK", "CLOSING"):
                    default_app = "(closed/pid-0)"
                else:
                    default_app = "Unknown"
                # Cached by (pid, create_time) — see _resolve_proc_meta. Avoids
                # re-running ~6 psutil calls + a SHA-256 per connection every pass.
                meta = self._resolve_proc_meta(pid, default_app)
                app_name = meta["app"]
                exe_path = meta["path"]
                username = meta["user"]
                file_hash = meta["hash"]
                cmdline = meta["cmdline"]
                ppid = meta["ppid"]
                parent_app = meta["parent_app"]

                ip = self._remote_ip(remote_addr)
                ip_info = self.get_ip_details(ip) if ip else {
                    "country": "N/A", "country_code": "", "org": "N/A", "hostname": "N/A",
                    "asn": None, "is_tor": False, "is_private": False,
                }
                # Pre-classify direction (T1-2) and resolve systemd unit (T2-2).
                direction = classify_direction(local_addr, remote_addr, conn.status)
                systemd_unit = systemd_unit_for_pid(pid) if pid else None
                # v1.3: tag transport for the unified table (TCP vs UDP).
                transport = "tcp" if conn.type == socket.SOCK_STREAM else "udp"
                conn_data = {
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "pid": pid,
                    "app": app_name,
                    "user": username,
                    "path": exe_path,
                    "hash": file_hash,
                    "local": local_addr,
                    "remote": remote_addr,
                    "remote_ip": ip,
                    "remote_port": self._remote_port(remote_addr),
                    "status": conn.status,
                    "direction": direction,
                    "transport": transport,           # v1.3 — tcp/udp/sctp/unix
                    "cmdline": cmdline,                # v1.3 F-5.1
                    "ppid": ppid,                      # v1.3 F-6.2
                    "parent_app": parent_app,          # v1.3 F-6.2
                    "ja3": None,                       # v1.3 F-1.6 — populated after pcap parse
                    "systemd_unit": systemd_unit,
                    "session_age_s": None,           # filled in monitor()
                    "crowdsec": None,                # filled in monitor()
                    "firewall": None,                # filled in monitor()
                    "country": ip_info["country"],
                    "country_code": ip_info["country_code"],
                    "org": ip_info["org"],
                    "asn": ip_info.get("asn"),
                    "hostname": ip_info["hostname"],
                    "is_tor": ip_info["is_tor"],
                    "signature": None,
                    "vt": None,
                    "risk": "LOW",
                    "flags": [],
                    # v1.3 UX: tag rows owned by this netmon process (or its
                    # children — pktmon/tcpdump/PowerShell sig-verifier) so
                    # the HTML report can hide them by default. Without this
                    # filter the analyst's first view is polluted by the
                    # monitor's own footprint (Python's HTTPS to ipwho.is,
                    # transient PowerShell sockets, etc.).
                    "is_netmon_self": (pid in self_pids
                                       or (ppid is not None and ppid in self_pids)),
                }
                connections.append(conn_data)
            except (psutil.Error, OSError, ValueError) as e:
                # psutil can raise transient errors when a process disappears
                # mid-iteration; skip the row and keep going.
                log.debug("connection row skipped: %s", e)
                continue
        return connections

    @staticmethod
    def _fmt_addr(addr):
        if not addr:
            return ""
        ip, port = addr.ip, addr.port
        if ":" in ip:
            return f"[{ip}]:{port}"
        return f"{ip}:{port}"

    # v1.3 (F-1.1, F-1.2): pull in SCTP + Unix domain sockets as additional
    # rows in the connection table. These transports are invisible to
    # psutil.net_connections(kind="inet") and to the existing pcap parser.
    def get_alt_transports(self):
        rows = []
        for s in enumerate_sctp():
            rows.append(self._make_alt_row(s, transport="sctp"))
        for s in enumerate_unix_sockets():
            rows.append(self._make_alt_row(s, transport="unix"))
        return rows

    def _make_alt_row(self, sock, transport):
        pid = sock.get("pid")
        app_name, exe_path, username = "Unknown", "N/A", "N/A"
        cmdline = ""
        ppid = None
        parent_app = ""
        if pid:
            try:
                proc = psutil.Process(pid)
                app_name = proc.name()
                exe_path = proc.exe()
                username = proc.username()
                try:
                    cmdline = " ".join(proc.cmdline())[:4096]
                except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                    pass
                try:
                    ppid = proc.ppid()
                    if ppid:
                        parent_app = psutil.Process(ppid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                    pass
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                app_name = "System/Protected"
                exe_path = "Access Denied"
        # For SCTP the remote field is populated for assocs; UDS has none.
        remote = sock.get("remote") or ""
        local = sock.get("local") or ""
        return {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "pid": pid, "app": app_name, "user": username,
            "path": exe_path, "hash": "N/A",
            "local": local, "remote": remote,
            "remote_ip": self._remote_ip(remote) if remote else None,
            "remote_port": self._remote_port(remote) if remote else None,
            "status": sock.get("status") or "NONE",
            "direction": "LISTEN" if not remote else (
                "LOOPBACK" if (self._remote_ip(remote) or "").startswith("127.") else "AMBIGUOUS"
            ),
            "transport": transport,
            "cmdline": cmdline, "ppid": ppid, "parent_app": parent_app,
            "ja3": None,
            "systemd_unit": systemd_unit_for_pid(pid) if pid else None,
            "session_age_s": None, "crowdsec": None, "firewall": None,
            "country": "—", "country_code": "",
            "org": f"{transport.upper()} socket",
            "asn": None, "hostname": "N/A", "is_tor": False,
            "signature": None, "vt": None,
            "risk": "LOW", "flags": [],
        }

    def monitor(self):
        start = datetime.now()
        self.console.print(f"[bold green]netmon.py v{VERSION}[/bold green] starting (duration: {self.args.time}s)")

        if self.args.capture:
            self.capture = PacketCapture(self.args.time, self.console)
            if not self.capture.available():
                self.console.print("[yellow]Packet capture requested but no pktmon/tcpdump found.[/yellow]")
                self.capture = None
            elif self.capture.start():
                self.console.print(f"[green]Capture started ({self.capture.tool}).[/green]")
            else:
                self.console.print("[yellow]Capture failed to start (need elevation?). Continuing without capture.[/yellow]")
                self.capture = None

        # Warm the file-hash cache in parallel so the per-second loop never
        # blocks on a cold SHA-256 (keeps the live monitor responsive).
        self._prewarm_hashes()

        try:
            # Interactive live monitor — progress bar + live socket activity so
            # the operator stays oriented during the (deliberately longer) triage
            # window. Auto-disabled on non-TTY (piped / CI) runs; the loop and all
            # bookkeeping are identical either way.
            total_s = max(1, int(self.args.time))
            last_seen = "-"
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold cyan]Live monitor[/bold cyan]"),
                BarColumn(),
                TextColumn("[dim]{task.fields[status]}[/dim]"),
                TimeRemainingColumn(),
                console=self.console,
                transient=False,
                disable=not self.console.is_terminal,
            ) as progress:
                task = progress.add_task("monitor", total=total_s, status="starting...")
                while (datetime.now() - start).total_seconds() < self.args.time:
                    now = time.time()
                    for conn in self.get_connections():
                        # v1.4 (B1): key on (pid, transport, local, remote) so UDP
                        # / multi-transport / multiple sockets to the same peer no
                        # longer collapse (last-writer-wins) and vanish from the
                        # report. Matches the alt-transport key format below.
                        key = (conn["pid"], conn.get("transport"), conn["local"], conn["remote"])
                        # v1.4 (B2): once full, skip only NEW keys; keep refreshing
                        # existing rows instead of going blind mid-snapshot.
                        if key not in self.conn_history and len(self.conn_history) >= MAX_CONN_HISTORY:
                            log.warning("conn_history cap reached (%d); dropping new entries",
                                        MAX_CONN_HISTORY)
                            continue
                        # Live activity line: surface the newest outbound socket.
                        if key not in self.conn_history and conn.get("remote"):
                            _ip = self._remote_ip(conn["remote"])
                            if _ip:
                                last_seen = f"{(conn.get('app') or '?')[:18]} -> {_ip}"
                        self.conn_history[key] = conn
                        if len(self.first_seen) < MAX_FIRST_SEEN:
                            fs_key = (conn["pid"], conn["local"], conn["remote"])
                            self.first_seen.setdefault(fs_key, now)
                            # Track session-start wall time for the session-age column
                            self.session_start.setdefault(fs_key, now)
                    progress.update(
                        task,
                        completed=min((datetime.now() - start).total_seconds(), total_s),
                        status=f"{len(self.conn_history)} sockets - last: {last_seen}",
                    )
                    time.sleep(1)
                progress.update(task, completed=total_s, status="done")
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Monitoring interrupted by user.[/yellow]")
            raise

        # Stop capture and analyze pcap
        self.saved_pcap_path = None
        if self.capture:
            pcap_path = self.capture.stop()
            if pcap_path and os.path.exists(pcap_path):
                self.console.print(f"[green]Analyzing capture:[/green] {pcap_path}")
                self.flow = FlowAnalyzer()
                try:
                    self.flow.feed_pcap(pcap_path)
                    self.console.print(f"[green]Capture summary:[/green] {self.flow.summary()}")
                except (struct.error, ValueError, OSError) as e:
                    log.warning("pcap parse error: %s", e)
                    self.console.print(f"[yellow]pcap parse error: {e}[/yellow]")
                # Persist the pcap to the user's location if requested.
                # v1.3 (T2-5): --capture saves by default; --capture-fly skips.
                if getattr(self.args, "capture_save", False) and getattr(self.args, "capture_path", None):
                    try:
                        dest = Path(self.args.capture_path).resolve()
                        shutil.copy2(pcap_path, dest)
                        size = dest.stat().st_size
                        self.saved_pcap_path = str(dest)
                        self.console.print(
                            f"[bold green]Saved capture:[/bold green] {dest} "
                            f"({size / 1024 / 1024:.1f} MB)"
                        )
                        if size > CAPTURE_WARN_THRESHOLD:
                            self.console.print(
                                f"[yellow]note:[/yellow] saved file exceeds "
                                f"{CAPTURE_WARN_THRESHOLD / 1024 / 1024:.0f} MB."
                            )
                    except OSError as e:
                        log.error("failed to save capture: %s", e)
                        self.console.print(f"[bold red]save-capture failed:[/bold red] {e}")

        # Batch IP enrichment (ip-api /batch + threaded rDNS)
        self.console.print("[dim]Enriching remote IPs...[/dim]")
        self.batch_enrich_ips()
        for conn in self.conn_history.values():
            ip = conn.get("remote_ip")
            if ip:
                info = self.get_ip_details(ip)
                conn["country"] = info["country"]
                conn["country_code"] = info["country_code"]
                conn["org"] = info["org"]
                conn["asn"] = info.get("asn")
                conn["hostname"] = info["hostname"]
                conn["is_tor"] = info["is_tor"]

        # Annotate hostnames from flow capture (DNS / SNI) — overrides rDNS when available
        if self.flow:
            for conn in self.conn_history.values():
                if conn["remote_ip"]:
                    names = self.flow.hostname_for_ip(conn["remote_ip"])
                    if names and (conn["hostname"] in ("N/A", "", None)):
                        conn["hostname"] = ", ".join(sorted(names))

        # DNS heuristics (DGA-like, suspicious TLD, invalid chars, NXDOMAIN burst)
        self.dns_findings = []
        if self.flow and self.flow.dns_queries:
            analyzer = DNSAnalyzer(
                self.flow.dns_queries,
                rcode_counts=getattr(self.flow, "dns_rcode_counts", None),
            )
            self.dns_findings = analyzer.suspicious_summary()
            # Map suspicious-DNS findings onto any connection whose hostname matches.
            suspicious_by_name = {r["qname"].rstrip(".").lower(): r["flags"]
                                  for r in self.dns_findings}
            for conn in self.conn_history.values():
                host = (conn.get("hostname") or "").lower()
                for sname, sflags in suspicious_by_name.items():
                    if sname and (sname == host or sname in host or host.endswith(sname)):
                        # Use list (ordered) but de-dupe.
                        for f in sflags:
                            if f not in conn["flags"]:
                                conn["flags"].append(f)

        # Batch signature / package verification and VT lookups
        self.console.print("[dim]Verifying code signatures / packages...[/dim]")
        all_paths = [c["path"] for c in self.conn_history.values()]
        self.signing.batch_check(all_paths)
        for conn in self.conn_history.values():
            conn["signature"] = self.signing.get(conn["path"])
            if self.vt:
                conn["vt"] = self.vt.lookup_hash(conn["hash"])

        # CrowdSec lookups for every unique public remote IP (T2-1)
        if self.crowdsec and self.crowdsec.enabled:
            self.console.print("[dim]Querying local CrowdSec...[/dim]")
            for conn in self.conn_history.values():
                ip = conn.get("remote_ip")
                if ip:
                    conn["crowdsec"] = self.crowdsec.lookup(ip)

        # Firewall per-port verdict (T2-3)
        if self.firewall and self.firewall.backend:
            for conn in self.conn_history.values():
                # v1.4 (R7): only a local *listen* port has a meaningful firewall
                # verdict. For OUTBOUND rows the local port is ephemeral, so the
                # old code annotated a misleading "blocked"/"allowed" for a random
                # port. Annotate listeners / inbound only.
                if conn.get("direction") in ("LISTEN", "INBOUND"):
                    lport = self._local_port(conn["local"])
                    if lport is not None:
                        conn["firewall"] = self.firewall.verdict_for_port(lport)

        # Session age (T3-1): wall-clock seconds since the (pid, local, remote)
        # tuple was first observed in this run. Best-effort — for ESTABLISHED
        # sockets older than the run, this just reflects "since we noticed it".
        run_now = time.time()
        for conn in self.conn_history.values():
            fs_key = (conn["pid"], conn["local"], conn["remote"])
            start = self.session_start.get(fs_key)
            if start is not None:
                conn["session_age_s"] = round(max(0.0, run_now - start), 1)

        # v1.3: pull in SCTP + Unix-domain socket rows (F-1.1, F-1.2). These
        # are point-in-time snapshots, not continuously monitored — sufficient
        # for "is there an active SCTP association / suspicious UDS attach?".
        for row in self.get_alt_transports():
            key = (row["pid"], row["transport"], row["local"], row["remote"])
            self.conn_history[key] = row

        # v1.3 F-1.6: thread JA3 fingerprint per connection if we captured TLS.
        if self.flow and getattr(self.flow, "ja3_by_peer", None):
            for conn in self.conn_history.values():
                ip = conn.get("remote_ip")
                if ip and ip in self.flow.ja3_by_peer:
                    conn["ja3"] = next(iter(self.flow.ja3_by_peer[ip]))

        # v1.3 F-1.3: mark connections whose remote_ip showed up in the
        # ICMP-tunnel findings from FlowAnalyzer.
        if self.flow:
            self.flow._compute_icmp_findings()
            tunnel_peers = {f["peer"] for f in self.flow.icmp_findings}
            for conn in self.conn_history.values():
                if conn.get("remote_ip") in tunnel_peers:
                    conn["icmp_tunnel"] = True

        # v1.3 F-2.3: webroot content scan (opt-in via --scan-webroots).
        if getattr(self.args, "scan_webroots", False):
            self.console.print("[dim]Scanning webroots for shell signatures...[/dim]")
            roots = getattr(self.args, "webroots", None) or DEFAULT_WEBROOTS
            scanner = WebShellScanner(roots=roots)
            self.webshell_findings = scanner.scan()
            if self.webshell_findings:
                self.console.print(
                    f"[bold red]WebShell scan: {len(self.webshell_findings)} suspicious files![/bold red]"
                )

        # v1.3 F-4: persistence enumeration (opt-in via --persistence).
        # --hash-tasks implies --persistence so a "hash only" run still works.
        if getattr(self.args, "persistence", False) or getattr(self.args, "hash_tasks", False):
            self.console.print("[dim]Enumerating persistence mechanisms...[/dim]")
            self.persistence_findings = PersistenceScanner().scan()
            if getattr(self.args, "hash_tasks", False):
                self.console.print("[dim]Hashing persistence binaries...[/dim]")
                self._hash_persistence_binaries()

        # v1.3 F-3: host event log review (opt-in via --logs N).
        logs_minutes = getattr(self.args, "logs", None)
        if logs_minutes:
            self.console.print(f"[dim]Reading host event logs (last {logs_minutes} minutes)...[/dim]")
            reader = LogReader(logs_minutes)
            self.log_findings = reader.read_all()
            self.log_findings.extend(correlate_log_findings(self.log_findings))
            # Re-sort with derived correlation entries
            self.log_findings.sort(key=lambda e: e.get("timestamp_unix", 0), reverse=True)
            self.console.print(
                f"[dim]Collected {len(self.log_findings)} log entries from "
                f"{len(reader.sources_read)} sources.[/dim]"
            )
            # v1.3: surface skipped sources so the operator knows WHY a log
            # contributed zero entries. Most common reason on Windows is
            # "access denied" because the Security log requires admin and
            # the user is running non-elevated.
            self.log_sources_skipped = list(getattr(reader, "sources_skipped", []))
            if self.log_sources_skipped:
                self.console.print("[yellow]Some log sources were skipped:[/yellow]")
                for src, reason in self.log_sources_skipped:
                    self.console.print(f"  [yellow]·[/yellow] {src}: {reason}")
                if any("access denied" in r for _, r in self.log_sources_skipped):
                    self.console.print(
                        "  [dim]Re-run as Administrator for full Security-log "
                        "coverage (logon events, process creation, etc).[/dim]"
                    )

        # Final risk analysis (after all enrichment is in place)
        for conn in self.conn_history.values():
            risk, flags = self.analyze_risk(conn)
            # Preserve any DNS_* flags already set during the DNS heuristics
            # pass — they would otherwise be overwritten.
            preserved = [f for f in conn["flags"] if f.startswith("DNS_")]
            conn["risk"] = risk
            conn["flags"] = list(flags) + [p for p in preserved if p not in flags]

        # Beacon detection (raises risk one level if periodic)
        beacons = self.detect_beacons()
        # v1.4 (B1): conn_history is now keyed by the 4-tuple, but beacons are
        # keyed (pid, remote). Match every history row with that pid+remote so the
        # BEACON flag + risk bump land on all of the peer's sockets.
        for (b_pid, b_remote), info in beacons.items():
            for conn in self.conn_history.values():
                if conn.get("pid") == b_pid and conn.get("remote") == b_remote:
                    conn["flags"].append(f"BEACON_{info['mean_interval_s']}s")
                    if conn["risk"] == "LOW":
                        conn["risk"] = "MED"
                    elif conn["risk"] == "MED":
                        conn["risk"] = "HIGH"

        # Promote risk for connections that DNS heuristics already flagged.
        for conn in self.conn_history.values():
            dns_flags = [f for f in conn["flags"] if f.startswith("DNS_")]
            if dns_flags and conn["risk"] == "LOW":
                conn["risk"] = "MED"

        return self.conn_history

    # v1.3: --hash-tasks — SHA-256 every persistence-entry binary and (if a
    # VT key is set) look it up in VirusTotal. Result lives on the entry as
    # binary_path / binary_hash / vt so the HTML/JSON renderers can show it.
    def _hash_persistence_binaries(self):
        for entry in self.persistence_findings:
            cmd = entry.get("command") or ""
            path = entry.get("path") or ""
            # 1. Try to extract a binary path from the command itself.
            bin_path = PersistenceScanner.extract_binary_path(cmd)
            # 2. Fallbacks for entries where `command` is empty or doesn't
            # contain a path (e.g. some launchd plists, ssh_key entries):
            #   - cron jobs already keep the first non-comment line as cmd
            #   - launchd: the .plist itself is the persistence artifact
            #   - ssh_key: skip (it's a key, not a binary)
            if not bin_path and entry.get("kind") == "launchd":
                bin_path = path
            if not bin_path:
                continue
            if not os.path.isfile(bin_path):
                # Path didn't resolve — note it so the analyst sees the
                # cmd referenced a nonexistent file (which can itself be
                # suspicious — leftover startup entry from removed malware).
                entry["binary_path"] = bin_path
                entry["binary_hash"] = "NOT_FOUND"
                continue
            entry["binary_path"] = bin_path
            entry["binary_hash"] = self.get_file_hash(bin_path)
            if self.vt and entry["binary_hash"] not in (
                    "N/A", "ACCESS_DENIED", "TOO_LARGE", "NOT_FOUND"):
                entry["vt"] = self.vt.lookup_hash(entry["binary_hash"])


# === Reporters ===

CSV_FIELDS = [
    "timestamp", "pid", "ppid", "app", "parent_app", "user", "path", "hash",
    "local", "remote", "status",
    # v1.3 additions
    "transport",
    "direction", "systemd_unit", "session_age_s", "crowdsec", "firewall",
    "cmdline", "ja3",
    "country", "country_code", "org", "asn", "hostname",
    "is_tor", "signature_status", "signature_publisher", "signature_trusted",
    "vt_malicious", "vt_suspicious",
    "risk", "flags",
]


def export_text(conn_history, path, console, args=None, flow=None,
                dns_findings=None, saved_pcap_path=None):
    """Plain-text report — fixed-width columns, ASCII only, cat/grep-friendly.

    Designed to render identically on `cat report.txt` (Linux) and Notepad
    (Windows). No ANSI colors, no Unicode line-drawing — only ASCII so
    grep/awk/sort/less work without surprises.
    """
    if not conn_history:
        return

    risk_order = {"CRITICAL": 0, "HIGH": 1, "MED": 2, "LOW": 3}
    rows = sorted(conn_history.values(),
                  key=lambda x: (risk_order.get(x["risk"], 9), x["app"]))

    def _sig(c):
        s = c.get("signature") or {}
        if s.get("trusted"):
            return f"trusted ({s.get('publisher') or '?'})"
        if s.get("signed"):
            return f"signed ({s.get('publisher') or '?'})"
        if s.get("status") in ("n/a", "skipped", "missing"):
            return "-"
        return "UNSIGNED"

    def _geo(c):
        if c.get("is_tor"):
            return "TOR EXIT"
        if c.get("country") in ("—", "N/A", "", None):
            return c.get("org") or "-"
        return f"{c.get('country_code') or '-'} | {c.get('org') or '-'}"

    # Fixed-width columns. Widths chosen to fit a typical terminal but
    # err on the wide side — long fields get truncated with '...' suffix.
    cols = [
        ("RISK",   4,  lambda c: c["risk"]),
        ("PROC",   28, lambda c: c["app"] or ""),
        ("PID",    6,  lambda c: str(c["pid"] or "")),
        ("SIGNED", 32, lambda c: _sig(c)),
        ("LOCAL",  22, lambda c: c["local"] or "-"),
        ("REMOTE", 36, lambda c: c["remote"] or describe_listener_exposure(c.get("local"))),
        ("GEO/ORG", 28, lambda c: _geo(c)),
        ("HOST",   28, lambda c: c.get("hostname") or "-"),
        ("FLAGS",  40, lambda c: ", ".join(c.get("flags") or []) or "-"),
    ]

    def _truncate(s, w):
        s = str(s)
        if len(s) <= w:
            return s.ljust(w)
        return (s[:w - 3] + "...").ljust(w)

    lines = []
    lines.append("netmon.py Report")
    lines.append("=" * 72)
    lines.append(f"Generated:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    if args is not None:
        lines.append(f"Duration:    {args.time}s")
    lines.append(f"Host OS:     {sys.platform}")
    lines.append(f"Connections: {len(conn_history)} unique")
    lines.append("")

    risk_count = Counter(c["risk"] for c in rows)
    lines.append("Risk distribution:")
    lines.append(f"  CRIT  {risk_count.get('CRITICAL', 0):>5}")
    lines.append(f"  HIGH  {risk_count.get('HIGH', 0):>5}")
    lines.append(f"  MED   {risk_count.get('MED', 0):>5}")
    lines.append(f"  LOW   {risk_count.get('LOW', 0):>5}")
    lines.append("")

    # External-peer summary (helps you skim what's reaching the internet)
    ext = [c for c in rows if c.get("remote_ip") and not classify_local_ip(c["remote_ip"])]
    lines.append(f"External peers: {len({c['remote_ip'] for c in ext})}")
    lines.append("")

    # Connections table
    header = " ".join(_truncate(name, w) for name, w, _ in cols).rstrip()
    lines.append(header)
    lines.append("-" * len(header))
    for c in rows:
        line = " ".join(_truncate(fn(c), w) for _, w, fn in cols).rstrip()
        lines.append(line)
    lines.append("")

    # Capture summary
    if flow:
        s = flow.summary()
        lines.append("Packet capture")
        lines.append("-" * 14)
        lines.append(f"  DNS queries:        {s['dns_query_count']}")
        lines.append(f"  Unique DNS names:   {s['unique_dns_names']}")
        lines.append(f"  TLS SNI hosts:      {s['unique_sni_names']}")
        lines.append(f"  Tracked peers:      {s['tracked_peer_count']}")
        lines.append(f"  Parse errors:       {s['parse_errors']}")
        lines.append("")
        if flow.dns_queries:
            lines.append("Top DNS queries:")
            top = Counter(q[0] for q in flow.dns_queries).most_common(15)
            for name, count in top:
                lines.append(f"  {count:>4}  {name}")
            lines.append("")

    # DNS heuristic findings
    if dns_findings:
        lines.append(f"Suspicious DNS findings ({len(dns_findings)}):")
        lines.append("-" * 40)
        for r in dns_findings[:30]:
            flagstr = " ".join(r["flags"])
            lines.append(f"  [{r['count']:>4}x]  {r['qname']}")
            lines.append(f"          flags: {flagstr}")
        lines.append("")

    if saved_pcap_path:
        lines.append(f"Saved pcap: {saved_pcap_path}")
        lines.append("  (open in Wireshark for full packet inspection)")
        lines.append("")

    lines.append(f"-- netmon.py v{VERSION} --")

    try:
        Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")
        console.print(f"[bold green]Text report:[/bold green] {path}")
    except OSError as e:
        log.error("text export failed: %s", e)
        console.print(f"[bold red]Text export failed:[/bold red] {e}")


# JSON / NDJSON output (v1.3 F-6.4 — schema-stable for SIEM ingestion).
# Note: fields kept flat where possible so the schema is greppable from a
# command line; nested fields use snake_case dict keys.
def _conn_to_jsonable(c):
    sig = c.get("signature") or {}
    vt = c.get("vt") or {}
    return {
        "timestamp": c.get("timestamp"),
        "pid": c.get("pid"),
        "ppid": c.get("ppid"),
        "app": c.get("app"),
        "parent_app": c.get("parent_app"),
        "user": c.get("user"),
        "cmdline": c.get("cmdline"),
        "path": c.get("path"),
        "hash": c.get("hash"),
        "transport": c.get("transport"),
        "local": c.get("local"),
        "remote": c.get("remote"),
        "remote_ip": c.get("remote_ip"),
        "remote_port": c.get("remote_port"),
        "status": c.get("status"),
        "direction": c.get("direction"),
        "session_age_s": c.get("session_age_s"),
        "systemd_unit": c.get("systemd_unit"),
        "crowdsec": c.get("crowdsec"),
        "firewall": c.get("firewall"),
        "ja3": c.get("ja3"),
        "country": c.get("country"),
        "country_code": c.get("country_code"),
        "org": c.get("org"),
        "asn": c.get("asn"),
        "hostname": c.get("hostname"),
        "is_tor": bool(c.get("is_tor")),
        "signature": {
            "signed": sig.get("signed", False),
            "publisher": sig.get("publisher"),
            "status": sig.get("status"),
            "trusted": sig.get("trusted", False),
            "tampered": sig.get("tampered", False),
        },
        "vt": {
            "found": vt.get("found", False),
            "malicious": vt.get("malicious", 0),
            "suspicious": vt.get("suspicious", 0),
        } if vt else None,
        "risk": c.get("risk"),
        "flags": list(c.get("flags") or []),
    }


def export_json(conn_history, monitor, path, console):
    """Single-document JSON: connection rows + log findings + persistence +
    webshell findings + flow summary. Stable schema; new keys are appended."""
    doc = {
        "tool": f"netmon.py/{VERSION}",
        "host": socket.gethostname(),
        "generated": datetime.now().isoformat(),
        "connections": [_conn_to_jsonable(c) for c in conn_history.values()],
        "log_findings": getattr(monitor, "log_findings", []) or [],
        "log_sources_skipped": getattr(monitor, "log_sources_skipped", []) or [],
        "persistence":  getattr(monitor, "persistence_findings", []) or [],
        "webshell":     getattr(monitor, "webshell_findings", []) or [],
        "dns_findings": getattr(monitor, "dns_findings", []) or [],
        "flow_summary": monitor.flow.summary() if monitor.flow else None,
    }
    try:
        Path(path).write_text(json.dumps(doc, default=str, indent=2),
                              encoding="utf-8")
        console.print(f"[bold green]JSON exported:[/bold green] {path}")
    except OSError as e:
        log.error("JSON export failed: %s", e)
        console.print(f"[bold red]JSON export failed:[/bold red] {e}")


def export_ndjson(conn_history, path, console):
    """Newline-delimited JSON — one connection per line, suitable for tail-F
    ingestion by Loki/Splunk/ELK."""
    try:
        with open(path, "w", encoding="utf-8") as f:
            for c in conn_history.values():
                f.write(json.dumps(_conn_to_jsonable(c), default=str))
                f.write("\n")
        console.print(f"[bold green]NDJSON exported:[/bold green] {path}")
    except OSError as e:
        log.error("NDJSON export failed: %s", e)
        console.print(f"[bold red]NDJSON export failed:[/bold red] {e}")


def _csv_safe(v):
    """Prevent CSV formula injection: a cell beginning with = + - @ tab or CR is
    executed as a formula by Excel / LibreOffice. Prefix a single quote."""
    s = "" if v is None else str(v)
    return ("'" + s) if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def export_csv(conn_history, path, console):
    if not conn_history:
        return
    try:
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_FIELDS, extrasaction="ignore")
            writer.writeheader()
            for c in conn_history.values():
                row = {k: c.get(k, "") for k in CSV_FIELDS}
                sig = c.get("signature") or {}
                vt = c.get("vt") or {}
                row["signature_status"] = sig.get("status", "")
                row["signature_publisher"] = sig.get("publisher", "") or ""
                row["signature_trusted"] = sig.get("trusted", False)
                row["vt_malicious"] = vt.get("malicious", "") if vt else ""
                row["vt_suspicious"] = vt.get("suspicious", "") if vt else ""
                row["flags"] = ", ".join(c.get("flags") or [])
                # v1.3 — direction/systemd_unit/crowdsec/firewall already
                # populated via base dict copy; coerce None -> "" so CSV is clean.
                for k in ("direction", "systemd_unit", "crowdsec", "firewall",
                          "session_age_s", "transport", "cmdline", "ja3",
                          "ppid", "parent_app"):
                    if row.get(k) is None:
                        row[k] = ""
                # v1.4 (S2): neutralize CSV formula injection on every cell.
                row = {k: _csv_safe(v) for k, v in row.items()}
                writer.writerow(row)
        console.print(f"[bold green]CSV exported:[/bold green] {path}")
    except (OSError, csv.Error) as e:
        log.error("CSV export failed: %s", e)
        console.print(f"[bold red]CSV export failed:[/bold red] {e}")


def display_terminal(conn_history, console, flow=None):
    table = Table(
        show_header=True, header_style="bold magenta", box=box.SIMPLE,
        title=f"netmon.py — {len(conn_history)} unique connections",
    )
    table.add_column("Risk", width=5, no_wrap=True)
    table.add_column("Process", style="cyan", no_wrap=True)
    table.add_column("PID", style="dim", no_wrap=True)
    table.add_column("Signed", no_wrap=True)
    table.add_column("Local", style="bright_blue", overflow="ellipsis", max_width=24)
    table.add_column("Remote", style="yellow", overflow="ellipsis", max_width=38)
    table.add_column("Geo / Org", style="green", overflow="ellipsis", max_width=30)
    table.add_column("Flags", style="red", overflow="ellipsis", max_width=36)

    risk_order = {"CRITICAL": 0, "HIGH": 1, "MED": 2, "LOW": 3}
    for c in sorted(conn_history.values(), key=lambda x: (risk_order.get(x["risk"], 9), x["app"])):
        risk_color = {"CRITICAL": "magenta", "HIGH": "red", "MED": "yellow", "LOW": "green"}.get(c["risk"], "magenta")
        sig = c.get("signature") or {}
        if sig.get("trusted"):
            sig_str = "[green]trusted[/green]"
        elif sig.get("signed"):
            sig_str = "[yellow]signed[/yellow]"
        elif sig.get("status") in ("n/a", "skipped", "missing"):
            sig_str = "[dim]-[/dim]"
        else:
            sig_str = "[red]unsigned[/red]"
        # Escape rDNS hostnames and process names — they're attacker-influenced
        # and rich would otherwise interpret embedded markup like "[red]EVIL[/red]".
        local = rich_escape(c["local"]) if c["local"] else "-"
        if c["remote"]:
            remote = rich_escape(c["remote"])
        else:
            # Listener — describe exposure level (loopback vs any-interface)
            remote = f"[dim]{rich_escape(describe_listener_exposure(c.get('local')))}[/dim]"
        if c.get("hostname") and c["hostname"] != "N/A":
            remote = f"{remote}\n[dim]{rich_escape(c['hostname'])}[/dim]"
        # Geo column. For local/private/loopback IPs the org field already
        # carries the descriptive label (loopback / private LAN / etc.), so
        # render that directly without the country code prefix.
        if c.get("is_tor"):
            geo = "[red]TOR EXIT[/red]"
        elif c['country'] in ('—', 'N/A', '', None):
            geo = f"[dim]{rich_escape(c['org'] or '-')}[/dim]"
        else:
            geo = f"{rich_escape(c['country_code'] or '-')} | {rich_escape(c['org'] or '-')}"
        flags = ", ".join(c.get("flags") or []) or "-"
        table.add_row(
            f"[{risk_color}]{c['risk']}[/{risk_color}]",
            rich_escape(c["app"] or ""),
            str(c["pid"] or ""),
            sig_str,
            local,
            remote,
            geo,
            rich_escape(flags),
        )
    console.print(table)
    if flow:
        s = flow.summary()
        console.print(
            f"[dim]Capture: {s['dns_query_count']} DNS queries "
            f"({s['unique_dns_names']} unique), {s['unique_sni_names']} unique SNI hosts, "
            f"{s['tracked_peer_count']} peers tracked.[/dim]"
        )


# === HTML report ===

HTML_TEMPLATE = string.Template("""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>netmon.py Report</title>
<style>
  :root {
    --bg: #0e1117; --panel: #161b22; --border: #30363d; --text: #c9d1d9;
    --muted: #8b949e; --accent: #58a6ff;
    --red: #f85149; --orange: #d29922; --green: #3fb950; --gray: #484f58;
  }
  * { box-sizing: border-box; }
  body { background: var(--bg); color: var(--text); font: 13px/1.4 ui-monospace, "SF Mono", Consolas, monospace; margin: 0; padding: 24px; }
  h1 { margin: 0 0 4px; font-size: 20px; }
  .sub { color: var(--muted); margin-bottom: 20px; }
  .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin-bottom: 20px; }
  .stat { background: var(--panel); border: 1px solid var(--border); border-radius: 6px; padding: 12px; transition: border-color .15s; }
  .stat .label { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .04em; }
  .stat .val { font-size: 20px; font-weight: 600; margin-top: 4px; }
  .stat[data-filter] { cursor: pointer; user-select: none; }
  .stat[data-filter]:hover { border-color: var(--accent); }
  .stat[data-filter].active { border-color: var(--accent); background: rgba(88, 166, 255, 0.08); }
  .stat[data-filter] .label::after { content: " ↻"; color: var(--accent); opacity: .5; font-size: 10px; }
  .controls { margin-bottom: 12px; display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }
  input[type=search] { background: var(--panel); border: 1px solid var(--border); color: var(--text); padding: 6px 10px; border-radius: 4px; font: inherit; min-width: 240px; }
  .filter-btn { background: var(--panel); border: 1px solid var(--border); color: var(--text); padding: 4px 10px; border-radius: 4px; cursor: pointer; font: inherit; }
  .filter-btn.active { background: var(--accent); color: #fff; border-color: var(--accent); }
  .control-group-label { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .04em; margin-right: 4px; }
  .status-btn { font-size: 11px; padding: 3px 8px; }
  /* v1.3: persistent "Showing X of Y" pill. Always visible next to the
     risk-filter buttons so the operator can never be confused about
     whether a filter is hiding rows. Goes amber when filtered. */
  .row-count {
    margin-left: auto;
    background: var(--panel); border: 1px solid var(--border);
    color: var(--muted); padding: 4px 10px; border-radius: 4px;
    font-size: 12px; font-variant-numeric: tabular-nums;
  }
  .row-count.filtered {
    color: var(--orange); border-color: var(--orange);
    background: rgba(255, 165, 0, 0.08);
  }
  /* # column — narrow, right-aligned, dimmed */
  #conntable th.col-num, #conntable td.row-num {
    width: 36px; text-align: right; color: var(--muted);
    font-variant-numeric: tabular-nums; user-select: none;
  }
  /* Pkts column — compact mono-style for the count · bytes display */
  #conntable th[data-sort="pkts"], #conntable td.pkts {
    text-align: right; font-variant-numeric: tabular-nums; white-space: nowrap;
  }
  /* Process selection: the process name cell is a button-styled clickable
     element so the affordance is unambiguous. Whole-row click also works
     as a fallback for clicks anywhere outside the VT hash link. */
  #conntable tbody tr { cursor: pointer; }
  #conntable tbody tr:hover { outline: 1px solid rgba(88, 166, 255, 0.3); }
  .proc-link {
    color: var(--accent); cursor: pointer; user-select: none;
    text-decoration: underline dotted; text-underline-offset: 3px;
    text-decoration-color: rgba(88, 166, 255, 0.4);
  }
  .proc-link:hover {
    color: #fff; text-decoration: underline solid;
    text-decoration-color: var(--accent);
  }
  tr.selected-process {
    background: rgba(88, 166, 255, 0.15) !important;
    box-shadow: inset 4px 0 0 var(--accent), inset -4px 0 0 var(--accent);
  }
  tr.selected-process td { color: var(--text) !important; }
  /* Brief flash animation on row click so the user always gets visual
     feedback even if the selection state didn't change. */
  @keyframes row-flash {
    0%   { background: rgba(88, 166, 255, 0.40); }
    100% { background: transparent; }
  }
  tr.click-flash { animation: row-flash 0.4s ease-out; }
  #process-selection-indicator {
    display: none; padding: 8px 12px; margin-bottom: 12px;
    background: rgba(88, 166, 255, 0.10); border: 1px solid var(--accent);
    border-radius: 6px; color: var(--text); font-size: 12px;
    /* v1.3 T3-6: sticky so the operator never loses track of which process
       is selected even after scrolling deep into the packet log. */
    position: sticky; top: 0; z-index: 20;
    backdrop-filter: blur(6px);
    background-color: rgba(22, 27, 34, 0.92);
  }
  #process-selection-indicator.visible { display: block; }
  #process-selection-indicator .name { color: var(--accent); font-weight: 600; }
  #process-selection-indicator button {
    margin-left: 12px; background: var(--panel); border: 1px solid var(--border);
    color: var(--text); padding: 2px 10px; border-radius: 4px; cursor: pointer;
    font: inherit; font-size: 11px;
  }
  label.toggle { display: inline-flex; align-items: center; gap: 6px; cursor: pointer; user-select: none; color: var(--muted); }
  label.toggle:hover { color: var(--text); }
  label.toggle input { accent-color: var(--accent); }
  table { width: 100%; border-collapse: collapse; background: var(--panel); border: 1px solid var(--border); border-radius: 6px; overflow: hidden; }
  th, td { padding: 8px 10px; text-align: left; border-bottom: 1px solid var(--border); vertical-align: top; }
  th { background: #1c2128; cursor: pointer; user-select: none; position: sticky; top: 0; font-weight: 600; font-size: 12px; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); }
  th:hover { color: var(--text); }
  tr:last-child td { border-bottom: none; }
  tr.HIGH { background: rgba(248, 81, 73, 0.08); }
  tr.MED { background: rgba(210, 153, 34, 0.06); }
  /* Hide Microsoft + System rows by default; checkbox below toggles them. */
  body:not(.show-noisy) tr.noisy { display: none; }
  /* v1.3 UX: hide rows owned by netmon (and its child processes) by
     default so the analyst doesn't see the monitor's own footprint.
     The "Show netmon-generated events" checkbox reveals them. */
  body:not(.show-netmon) tr.cat-netmon-self { display: none; }
  /* Same pattern for log-table events generated by netmon. The toggle
     "Show events generated by netmon.py" in the log section drives this. */
  body:not(.show-netmon-logs) tr.self-event { display: none; }
  /* SELF severity pill — neutral gray, not red/orange/green. */
  .risk.noisy-self { background: var(--muted); color: var(--bg); }
  .risk { display: inline-block; padding: 2px 8px; border-radius: 4px; font-weight: 600; font-size: 11px; }
  .risk.CRITICAL { background: #d6409f; color: #fff; }
  .risk.HIGH { background: var(--red); color: #fff; }
  .risk.MED { background: var(--orange); color: #fff; }
  .risk.LOW { background: var(--green); color: #fff; }
  .sig.trusted { color: var(--green); }
  .sig.signed { color: var(--orange); }
  .sig.unsigned { color: var(--red); }
  .sig.unknown { color: var(--gray); }
  .hash { color: var(--accent); text-decoration: none; word-break: break-all; }
  .hash:hover { text-decoration: underline; }
  .flags { color: var(--red); font-size: 11px; }
  .muted { color: var(--muted); font-size: 11px; }
  .vt-mal { color: var(--red); font-weight: 600; }
  .vt-clean { color: var(--green); }
  .footer { margin-top: 24px; color: var(--muted); font-size: 11px; text-align: center; }
  details { margin-top: 16px; }
  details summary { cursor: pointer; padding: 8px 0; color: var(--muted); }
  details summary:hover { color: var(--text); }
  .kv { display: grid; grid-template-columns: 200px 1fr; gap: 4px 12px; padding: 8px 0; font-size: 12px; }
  .kv .k { color: var(--muted); }
  td.path { font-size: 11px; color: var(--muted); word-break: break-all; max-width: 320px; }
  td.local { font-size: 11px; color: var(--accent); white-space: nowrap; }
  #load-packets-btn:not(:disabled) { background: var(--accent); color: #fff; border-color: var(--accent); }
  #packet-detail { margin-top: 12px; }
  .packet { background: #0d1117; border: 1px solid var(--border); border-radius: 4px; padding: 8px; margin-bottom: 6px; font-size: 11px; }
  .packet-head { color: var(--muted); margin-bottom: 4px; }
  .packet-head .proto { display: inline-block; padding: 1px 6px; border-radius: 3px; background: var(--panel); color: var(--accent); margin-right: 8px; font-weight: 600; }
  .packet-head .direction { color: var(--orange); margin: 0 6px; }
  .packet-hex { font-family: ui-monospace, "SF Mono", Consolas, monospace; white-space: pre; line-height: 1.4; overflow-x: auto; }
  .packet-hex .hex-byte { color: var(--text); }
  .packet-hex .ascii { color: var(--green); }
  /* Listener-exposure highlighting — make exposed listeners shine */
  /* Remote cell is the 6th td: Risk, Process, PID, Trust, Local, Remote, ... */
  tr.cat-exposed-any   td:nth-child(6) {
    border-left: 4px solid var(--red);
    color: var(--red);
    font-weight: 600;
    background: rgba(248, 81, 73, 0.10);
    box-shadow: inset 0 0 8px rgba(248, 81, 73, 0.18);
  }
  tr.cat-exposed-lan   td:nth-child(6) {
    border-left: 4px solid var(--orange);
    color: var(--orange);
    font-weight: 600;
    background: rgba(210, 153, 34, 0.08);
    box-shadow: inset 0 0 8px rgba(210, 153, 34, 0.14);
  }
  /* v1.3 — Direction column visual cues */
  td.dir { font-weight: 600; font-size: 11px; white-space: nowrap; }
  td.dir.dir-out    { color: var(--orange); }
  td.dir.dir-in     { color: var(--accent); }
  td.dir.dir-loop   { color: var(--muted); }
  td.dir.dir-listen { color: var(--green); }
  td.age { font-size: 11px; color: var(--muted); white-space: nowrap; }
  .dns-flag { display: inline-block; background: rgba(248, 81, 73, 0.15); color: var(--red); padding: 1px 6px; border-radius: 3px; font-size: 10px; margin-right: 4px; }
  .pcap-link { display: inline-block; background: var(--accent); color: #fff; padding: 6px 12px; border-radius: 4px; text-decoration: none; font-weight: 600; }
  .pcap-link:hover { opacity: 0.9; }
  .log-table { font-size: 11px; }
  .log-table td { padding: 4px 8px; word-break: break-all; }

  /* === v1.3 UX overhaul ====================================================
     The HTML grew big: connection table + capture summary + DNS findings +
     packet log + host event logs + persistence + web-shell findings. Without
     a quick-nav the analyst has to scroll past 100+ rows to reach the
     persistence section. The sticky TOC fixes that.
  */
  .toc {
    position: sticky; top: 0; z-index: 30;
    background: rgba(13, 17, 23, 0.94);
    backdrop-filter: blur(6px); -webkit-backdrop-filter: blur(6px);
    border-bottom: 1px solid var(--border);
    padding: 8px 12px;
    display: flex; gap: 6px; flex-wrap: wrap; align-items: center;
    margin: 0 -20px 16px; /* extend to edges */
    font-size: 12px;
  }
  .toc-label {
    color: var(--muted); text-transform: uppercase; letter-spacing: .06em;
    font-size: 10px; margin-right: 4px;
  }
  .toc a {
    color: var(--text); text-decoration: none;
    background: var(--panel); border: 1px solid var(--border);
    padding: 4px 10px; border-radius: 4px;
    display: inline-flex; align-items: center; gap: 6px;
    transition: border-color .15s, background .15s;
  }
  .toc a:hover { border-color: var(--accent); }
  .toc a.has-hi { border-color: var(--red); }
  .toc a .badge {
    background: var(--bg); color: var(--muted);
    padding: 1px 6px; border-radius: 9px; font-size: 10px;
    font-variant-numeric: tabular-nums;
  }
  .toc a.has-hi .badge { background: var(--red); color: #fff; }
  .toc a .badge.warn { background: var(--orange); color: #fff; }

  /* Back-to-top floating button */
  #back-to-top {
    position: fixed; bottom: 20px; right: 20px; z-index: 50;
    background: var(--accent); color: #fff; border: none;
    width: 40px; height: 40px; border-radius: 50%;
    cursor: pointer; font-size: 18px; font-weight: 700;
    box-shadow: 0 2px 8px rgba(0,0,0,.4);
    display: none; align-items: center; justify-content: center;
  }
  #back-to-top.visible { display: flex; }
  #back-to-top:hover { opacity: .9; }

  /* Section headers — bigger summary text, more visual weight */
  details > summary {
    cursor: pointer; padding: 10px 14px; user-select: none;
    background: var(--panel); border: 1px solid var(--border);
    border-radius: 6px; font-weight: 600; font-size: 14px;
    margin-top: 16px;
  }
  details[open] > summary {
    background: var(--bg);
    border-color: var(--accent); border-bottom-left-radius: 0;
    border-bottom-right-radius: 0;
  }
  details > summary:hover { border-color: var(--accent); }
  details > summary .count-badge {
    display: inline-block; margin-left: 8px;
    background: var(--bg); border: 1px solid var(--border);
    padding: 1px 8px; border-radius: 9px; font-size: 11px;
    font-weight: 500; color: var(--muted);
    font-variant-numeric: tabular-nums;
  }
  details > summary .count-badge.has-hi { background: var(--red); color: #fff; border-color: var(--red); }
  details > summary .count-badge.warn   { background: var(--orange); color: #fff; border-color: var(--orange); }
  details > summary .count-badge.ok     { background: var(--green); color: #fff; border-color: var(--green); }
  /* Empty-state callout — used when a section has nothing to report. */
  .empty-state {
    padding: 12px 16px; color: var(--muted);
    background: var(--panel); border: 1px dashed var(--border);
    border-radius: 4px; margin: 8px 0;
    font-size: 12px;
  }
  .empty-state strong { color: var(--green); }
  /* Anchor offset so sticky-header doesn't cover the section heading */
  section[id], details[id] { scroll-margin-top: 60px; }
</style>
</head>
<body class="$body_class">
<h1>netmon.py Report</h1>
<div class="sub">Generated $generated &middot; Duration ${duration}s &middot; Captured $conn_count unique connections &middot; Host: $host_os</div>

$toc_html

<button id="back-to-top" title="Back to top" aria-label="Back to top">^</button>

<div class="stats">
  <div class="stat" data-filter="CRITICAL" title="Click to filter to CRITICAL-risk rows"><div class="label">Critical</div><div class="val" style="color: #d6409f">$crit</div></div>
  <div class="stat" data-filter="HIGH" title="Click to filter to HIGH-risk rows"><div class="label">High risk</div><div class="val" style="color: var(--red)">$high</div></div>
  <div class="stat" data-filter="MED" title="Click to filter to MED-risk rows"><div class="label">Medium risk</div><div class="val" style="color: var(--orange)">$med</div></div>
  <div class="stat" data-filter="LOW" title="Click to filter to LOW-risk rows"><div class="label">Low risk</div><div class="val" style="color: var(--green)">$low</div></div>
  <div class="stat" data-filter="dedupe-process" title="Click to show one representative row per unique process name"><div class="label">Unique processes</div><div class="val">$procs</div></div>
  <div class="stat" data-filter="collapse-app-pid" title="Click to collapse multi-flow processes into one row per (app, pid). Useful on busy hosts."><div class="label">Collapse by PID</div><div class="val">▦</div></div>
  <div class="stat" data-filter="cat-external" title="Click to filter to external peers"><div class="label">External peers</div><div class="val">$peers</div></div>
  <div class="stat" data-filter="cat-unsigned" title="Click to filter to unsigned binaries"><div class="label">Unsigned binaries</div><div class="val" style="color: var(--orange)">$unsigned</div></div>
  <div class="stat" data-filter="cat-exposed-any" title="Click to filter to listeners on ANY interface (0.0.0.0 / [::])"><div class="label">Exposed: any iface</div><div class="val" style="color: var(--red)">$exposed_any</div></div>
  <div class="stat" data-filter="cat-exposed-lan" title="Click to filter to listeners on LAN/link-local interfaces"><div class="label">Exposed: LAN</div><div class="val" style="color: var(--orange)">$exposed_lan</div></div>
  <div class="stat" data-filter="cat-tor" title="Click to filter to Tor-exit destinations"><div class="label">Tor exits</div><div class="val">$tor</div></div>
  <div class="stat" data-filter="cat-vt-malicious" title="Click to filter to VT malicious hits"><div class="label">VT malicious</div><div class="val" style="color: var(--red)">$vt_mal</div></div>
</div>

<div class="controls">
  <input type="search" id="filter" placeholder="Search process, IP, hostname, flag, hash...">
  <span class="control-group-label">Risk:</span>
  <button class="filter-btn" data-risk="all">All</button>
  <button class="filter-btn" data-risk="CRITICAL">Critical</button>
  <button class="filter-btn" data-risk="HIGH">High</button>
  <button class="filter-btn" data-risk="MED">Medium</button>
  <button class="filter-btn" data-risk="LOW">Low</button>
  $noise_toggle
  $netmon_self_toggle
  <span id="row-count-pill" class="row-count" title="Visible rows vs total. Always shows the current filter effect so you never forget a filter is active.">Showing 0 of 0</span>
</div>
<div class="controls">
  <span class="control-group-label">Status:</span>
  <button class="filter-btn status-btn" data-status="all">All</button>
  <button class="filter-btn status-btn active" data-status="status-established">Established</button>
  <button class="filter-btn status-btn" data-status="status-listen">Listening</button>
  <button class="filter-btn status-btn" data-status="status-time-wait">Time-Wait</button>
  <button class="filter-btn status-btn" data-status="status-close-wait">Close-Wait</button>
  <button class="filter-btn status-btn" data-status="status-syn-sent">Syn-Sent</button>
  <button class="filter-btn status-btn" data-status="status-syn-recv">Syn-Recv</button>
  <button class="filter-btn status-btn" data-status="status-fin-wait">Fin-Wait</button>
  <button class="filter-btn status-btn" data-status="status-other">Other</button>
  <span class="muted">Click a process row to drill into its pcap traffic. SHA-256 links open VirusTotal.</span>
</div>

<div id="process-selection-indicator">
  Drill-down active: <span class="name" id="selected-process-name">—</span>
  <span id="selection-counts" class="muted"></span>
  <button id="clear-selection">Clear</button>
</div>

<section id="section-connections" class="anchor-wrap">
<table id="conntable">
<thead>
<tr>
  <th data-sort="num" class="col-num" title="Row number among currently-visible rows. Updates when filters change.">#</th>
  <th data-sort="risk">Risk</th>
  <th data-sort="app">Process</th>
  <th data-sort="pid">PID</th>
  <th data-sort="sig">Trust</th>
  <th data-sort="local">Local</th>
  <th data-sort="remote">Remote</th>
  <th data-sort="dir">Dir</th>
  <th data-sort="geo">Geo / Org</th>
  <th data-sort="age">Age</th>
  $pkts_th
  <th data-sort="svc">Service</th>
  <th data-sort="path">Path / Hash</th>
  <th data-sort="vt">VT</th>
  <th data-sort="flags">Flags</th>
</tr>
</thead>
<tbody>
$rows
</tbody>
</table>
</section>

$webshell_section
$log_section
$persistence_section
$dns_section
$capture_section
$packet_log_section
$coverage_section

<details>
<summary>Methodology &amp; signals</summary>
<div class="kv">
<span class="k">HIGH_RISK_PATH</span><span>Executable runs from Temp/Recycle Bin/etc.</span>
<span class="k">IMPOSTOR_SYSTEM_BIN</span><span>Process named like a Windows system binary, but in wrong location.</span>
<span class="k">SUSPICIOUS_PORT_*</span><span>Connection on a port commonly used for C2 / miners / backdoors.</span>
<span class="k">TOR_EXIT</span><span>Remote IP appears on the Tor public exit-node list.</span>
<span class="k">UNSIGNED_BINARY</span><span>Executable lacks a valid Authenticode signature (Windows).</span>
<span class="k">UNSIGNED_USER_PATH</span><span>Unsigned binary running from %AppData%/Downloads/etc.</span>
<span class="k">USER_PATH_UNTRUSTED_SIGNER</span><span>Signed binary in user paths, but not from a known publisher.</span>
<span class="k">BEACON_*</span><span>Periodic outbound connection (low jitter) &mdash; possible C2 beacon.</span>
<span class="k">VT_MALICIOUS_*</span><span>VirusTotal vendors flagged the SHA256 as malicious.</span>
<span class="k">DNS_DGA_LIKE</span><span>Resolved domain has a high-entropy random-looking label (DGA pattern).</span>
<span class="k">DNS_SUSPICIOUS_TLD_*</span><span>Resolved domain uses an abuse-prone TLD (.tk, .xyz, .top, etc).</span>
<span class="k">DNS_INVALID_CHARS</span><span>DNS query contained characters not legal in a hostname (homoglyph / typed garbage).</span>
<span class="k">DNS_HIGH_RETRY_*</span><span>Same name queried many times (typical of NXDOMAIN beacon).</span>
<span class="k">INBOUND_SESSION</span><span>v1.3 — informational; we are the server side of this TCP socket.</span>
<span class="k">INBOUND_FROM_TOR</span><span>v1.3 — inbound connection sourced from a Tor exit. Suspicious for exposed services.</span>
<span class="k">REVERSE_SHELL_LIKELY</span><span>v1.3 — server-role daemon (sshd, apache2…) making an outbound call to a public IP.</span>
<span class="k">IMPOSTOR_LISTEN_PORT</span><span>v1.3 — known server binary bound to an unexpected port (e.g. sshd on :8888).</span>
<span class="k">PACKAGE_TAMPERED</span><span>v1.3 — Linux package-manager integrity check (dpkg -V / rpm -V) reports the binary differs from its package.</span>
<span class="k">CROWDSEC_BANNED</span><span>v1.3 — local CrowdSec instance has an active ban decision on the remote IP.</span>
<span class="k">WEB_SHELL_SPAWN</span><span>v1.3 — web server (apache/nginx/IIS) spawned a shell, interpreter, or net tool — textbook web-shell signature.</span>
<span class="k">WEBUSER_OUTBOUND</span><span>v1.3 — web-runtime user (www-data, IUSR…) making outbound to a public IP. Web servers don't dial out.</span>
<span class="k">DOH_FROM_NON_BROWSER</span><span>v1.3 — DNS-over-HTTPS endpoint hit by a non-browser process. Covert C2 indicator.</span>
<span class="k">SCTP_UNUSUAL</span><span>v1.3 — SCTP association to a public IP. Outside telco contexts, almost never legitimate.</span>
<span class="k">UNIX_SOCKET_DOCKER</span><span>v1.3 — non-root process attached to /var/run/docker.sock. Container-escape precursor.</span>
<span class="k">JA3_C2_*</span><span>v1.3 — TLS Client Hello fingerprint (JA3) matched a known C2 framework profile.</span>
<span class="k">ICMP_TUNNEL_LIKELY</span><span>v1.3 — peer received high-volume ICMP echo traffic with large payloads (≥50 pkts, avg ≥1000B).</span>
<span class="k">SUSPICIOUS_CMDLINE_*</span><span>v1.3 — process cmdline matched a known dropper/loader/reverse-shell pattern.</span>
<span class="k">WEBSHELL_SIGNATURE_*</span><span>v1.3 — file under a webroot matched a web-shell content signature.</span>
</div>
</details>

<div class="footer"><a href="https://github.com/Ozear/netmon.py" target="_blank" rel="noopener noreferrer" style="color: var(--accent); text-decoration: none;">netmon.py</a> v$version &middot; by Ozear AL_Zadjali</div>

<script>
(function() {
  const body = document.body;
  const tbody = document.querySelector('#conntable tbody');
  const rows = Array.from(tbody.rows);
  const filter = document.getElementById('filter');
  const riskButtons = document.querySelectorAll('.filter-btn:not(.status-btn)');
  const statusButtons = document.querySelectorAll('.filter-btn.status-btn');
  const noiseToggle = document.getElementById('show-noisy');
  const netmonToggle = document.getElementById('show-netmon');
  const statTiles = document.querySelectorAll('.stat[data-filter]');
  const pcapTables = document.querySelectorAll('.log-table tbody');
  const rowCountPill = document.getElementById('row-count-pill');

  // Filter state:
  //   activeRisk    — risk dimension: 'all' / 'HIGH' / 'MED' / 'LOW'
  //   activeStatus  — connection-state dimension: 'all' / 'status-established' / …
  //                   Default is 'status-established' (most useful triage view —
  //                   passive Listen/TIME_WAIT noise hidden).
  //   activeCategories — set of cat-* filters (unsigned, tor, exposed, …).
  //   selectedProcess  — process name selected via row click; drills the pcap
  //                      detail tables down to that process's local ports.
  let activeRisk = 'all';
  let activeStatus = 'status-established';
  const activeCategories = new Set();
  let selectedProcess = null;
  let selectedProcessPorts = new Set();

  function isRiskFilter(key) {
    return key === 'CRITICAL' || key === 'HIGH' || key === 'MED' || key === 'LOW';
  }

  // When user clicks risk / category, reset status to 'all'. Otherwise
  // clicking "HIGH" while status=Established could hide a HIGH-risk LISTEN
  // (e.g. unsigned binary on :4444). Make sure intentional searches always
  // see all matching rows regardless of the default Established-only view.
  function resetStatusToAll() { activeStatus = 'all'; }

  function applyFilters() {
    const q = filter.value.toLowerCase();
    const dedupeProcess = activeCategories.has('dedupe-process');
    // Auto-reveal noisy rows whenever any explicit filter is active so the
    // visible count matches the stat tile.
    const explicit = (activeRisk !== 'all') || activeCategories.size > 0
                     || q !== '' || activeStatus !== 'all';
    body.classList.toggle('show-noisy', explicit || (noiseToggle && noiseToggle.checked));

    const seenProc = new Set();
    const seenAppPid = new Set();
    const collapseAppPid = activeCategories.has('collapse-app-pid');
    // Cells indices changed in v1.3: a # column was prepended, so Process is
    // now cells[2] (was cells[1]) and PID is cells[3] (was cells[2]). All
    // cell lookups in this file use the new positions.
    rows.forEach(r => {
      const matchesText = !q || r.textContent.toLowerCase().includes(q);
      const matchesRisk = activeRisk === 'all' || r.classList.contains(activeRisk);
      const matchesStatus = activeStatus === 'all' || r.classList.contains(activeStatus);
      let matchesCats = true;
      activeCategories.forEach(cat => {
        if (cat === 'dedupe-process' || cat === 'collapse-app-pid') return;
        if (!r.classList.contains(cat)) matchesCats = false;
      });
      let visible = matchesText && matchesRisk && matchesStatus && matchesCats;
      if (visible && dedupeProcess) {
        const proc = (r.cells[2].textContent || '').trim();
        if (seenProc.has(proc)) visible = false;
        else seenProc.add(proc);
      }
      if (visible && collapseAppPid) {
        const proc = (r.cells[2].textContent || '').trim();
        const pid  = (r.cells[3].textContent || '').trim();
        const key = proc + ':' + pid;
        if (seenAppPid.has(key)) visible = false;
        else seenAppPid.add(key);
      }
      r.style.display = visible ? '' : 'none';
    });

    riskButtons.forEach(b => b.classList.toggle('active', b.dataset.risk === activeRisk));
    statusButtons.forEach(b => b.classList.toggle('active', b.dataset.status === activeStatus));
    statTiles.forEach(t => {
      const f = t.dataset.filter;
      t.classList.toggle('active',
        (isRiskFilter(f) && f === activeRisk) ||
        (!isRiskFilter(f) && activeCategories.has(f))
      );
    });

    // v1.3 UX: renumber the visible rows in display order, AND update the
    // "Showing X of Y" pill — runs on every filter change so the operator
    // can ALWAYS see whether a filter is hiding rows. Without this, an
    // accidentally-active filter (e.g. status=Established hiding LISTENs)
    // can read as "no findings" when there are actually rows being hidden.
    let visibleCount = 0;
    rows.forEach(r => {
      const numCell = r.cells[0];
      // v1.4: count ACTUAL rendered visibility. Rows hidden by a CSS class
      // (noisy / netmon-self) have empty inline style, so the old
      // r.style.display check mis-counted them as visible — "Showing X of Y"
      // and the row numbers were wrong by default. getComputedStyle sees class
      // rules too, so the count is now correct.
      if (window.getComputedStyle(r).display === 'none') {
        if (numCell) numCell.textContent = '';
      } else {
        visibleCount += 1;
        if (numCell) numCell.textContent = String(visibleCount);
      }
    });
    if (rowCountPill) {
      rowCountPill.textContent = 'Showing ' + visibleCount + ' of ' + rows.length;
      // Visual hint: amber when a filter is hiding rows, dim when showing all.
      rowCountPill.classList.toggle('filtered', visibleCount < rows.length);
    }

    applyPcapFilter();
  }

  function applyPcapFilter() {
    // Per-process drill-down: when a row is selected, filter pcap detail
    // tables (DNS, TLS, TCP flows) to show only rows whose source/destination
    // address contains one of the selected process's local ports.
    pcapTables.forEach(tb => {
      Array.from(tb.rows).forEach(r => {
        if (!selectedProcess) { r.style.display = ''; return; }
        const txt = r.textContent;
        let match = false;
        for (const p of selectedProcessPorts) {
          if (txt.indexOf(':' + p) !== -1) { match = true; break; }
        }
        r.style.display = match ? '' : 'none';
      });
    });
  }

  filter.addEventListener('input', applyFilters);

  riskButtons.forEach(b => b.addEventListener('click', () => {
    activeRisk = b.dataset.risk;
    if (activeRisk === 'all') activeCategories.clear();
    resetStatusToAll();
    applyFilters();
  }));

  statusButtons.forEach(b => b.addEventListener('click', () => {
    activeStatus = b.dataset.status;
    applyFilters();
  }));

  statTiles.forEach(tile => tile.addEventListener('click', () => {
    const key = tile.dataset.filter;
    if (isRiskFilter(key)) {
      activeRisk = (activeRisk === key) ? 'all' : key;
    } else {
      if (activeCategories.has(key)) activeCategories.delete(key);
      else activeCategories.add(key);
    }
    resetStatusToAll();
    applyFilters();
  }));

  // Per-process drill-down. Click any row to select that process's local
  // ports; click again to deselect. The selection indicator at the top of
  // the table shows what's selected + how much pcap data exists for it.
  const selectionIndicator = document.getElementById('process-selection-indicator');
  const selectionName = document.getElementById('selected-process-name');
  const selectionCounts = document.getElementById('selection-counts');
  const clearSelectionBtn = document.getElementById('clear-selection');

  function deselectProcess() {
    selectedProcess = null;
    selectedProcessPorts = new Set();
    rows.forEach(rr => rr.classList.remove('selected-process'));
    if (selectionIndicator) selectionIndicator.classList.remove('visible');
    applyFilters();
  }

  function selectProcess(proc) {
    selectedProcess = proc;
    selectedProcessPorts = new Set();
    rows.forEach(rr => {
      const proc2 = (rr.cells[2].textContent || '').trim();
      if (proc2 === proc) {
        // v1.3 bug fix: pull the local port from the row-level data attribute
        // instead of parsing cells[5].textContent. The textContent path broke
        // once v1.3 started appending "fw: allowed" annotations into the same
        // cell — lastIndexOf(':') would lock onto the colon in "fw:" and
        // produce an empty selectedProcessPorts, leaving 0 matches when the
        // user clicked "Load packets".
        const port = rr.dataset.localPort;
        if (port) selectedProcessPorts.add(port);
        // Fallback: if data-local-port is missing (older row, manual edit),
        // try to parse an IP:port pattern from the start of cells[5].
        if (!port) {
          const localTxt = (rr.cells[5].textContent || '').trim();
          const m = localTxt.match(/^[0-9.]+:([0-9]+)|^\\[[0-9a-fA-F:]+\\]:([0-9]+)/);
          const p2 = m ? (m[1] || m[2]) : null;
          if (p2) selectedProcessPorts.add(p2);
        }
      }
      rr.classList.toggle('selected-process', proc2 === proc);
    });

    // Count data available for this process across all pcap tables.
    let dnsMatches = 0, tlsMatches = 0, httpMatches = 0, tcpMatches = 0;
    pcapTables.forEach((tb, idx) => {
      Array.from(tb.rows).forEach(r => {
        const txt = r.textContent;
        for (const p of selectedProcessPorts) {
          if (txt.indexOf(':' + p) !== -1) {
            // Heuristic: the first three .log-table tbodys are DNS, TLS, HTTP
            // in render order, then TCP flows. We just give a total count.
            if (idx === 0) dnsMatches++;
            else if (idx === 1) tlsMatches++;
            else if (idx === 2) httpMatches++;
            else tcpMatches++;
            break;
          }
        }
      });
    });
    const pktMatches = (typeof previewsForSelectedProcess === 'function')
                       ? previewsForSelectedProcess().length : 0;
    const totalDetail = dnsMatches + tlsMatches + httpMatches + tcpMatches + pktMatches;

    if (selectionIndicator) {
      selectionName.textContent = proc;
      selectionCounts.textContent =
        ' · ' + dnsMatches + ' DNS, ' + tlsMatches + ' TLS, '
        + httpMatches + ' HTTP, ' + tcpMatches + ' TCP flows, '
        + pktMatches + ' captured packets';
      selectionIndicator.classList.add('visible');
    }

    applyFilters();
    // Auto-scroll to packet log ONLY when there's data to show. If pcap
    // detail is empty for this process, the user stays in the connection
    // table where the selection highlight is now visible.
    if (totalDetail > 0) {
      const target = document.querySelector('.log-table');
      if (target) {
        let p = target.parentElement;
        while (p && p.tagName !== 'BODY') {
          if (p.tagName === 'DETAILS') p.open = true;
          p = p.parentElement;
        }
        target.scrollIntoView({behavior: 'smooth', block: 'start'});
      }
    }
  }

  function handleRowClick(r, evt) {
    // Let SHA-256 VT links work — we explicitly skip those.
    if (evt && evt.target && evt.target.tagName === 'A') return;
    const proc = (r.cells[2].textContent || '').trim();
    if (!proc) return;
    // Flash the row briefly so the user always sees that the click registered,
    // even if (de)selection state is the same.
    r.classList.remove('click-flash');
    void r.offsetWidth;  // force reflow so the animation restarts
    r.classList.add('click-flash');
    if (selectedProcess === proc) deselectProcess();
    else selectProcess(proc);
  }

  rows.forEach(r => {
    // Whole-row click as fallback
    r.addEventListener('click', evt => handleRowClick(r, evt));
    // Specific clickable element on the process-name cell so the
    // affordance is unambiguous (the underline + accent color screams
    // "I am clickable").
    const procCell = r.cells[2];
    if (procCell) {
      const link = procCell.querySelector('.proc-link');
      if (link) {
        link.addEventListener('click', evt => {
          evt.stopPropagation();   // don't double-fire via row handler
          handleRowClick(r, evt);
        });
      }
    }
  });

  if (clearSelectionBtn) {
    clearSelectionBtn.addEventListener('click', deselectProcess);
  }

  if (noiseToggle) {
    noiseToggle.addEventListener('change', () => {
      body.classList.toggle('show-noisy', noiseToggle.checked);
    });
  }

  // v1.3: netmon-self toggle. Same affordance as the Microsoft toggle —
  // unchecked = hidden (the default), checked = visible. The body class
  // drives the CSS rule on tr.cat-netmon-self.
  if (netmonToggle) {
    netmonToggle.addEventListener('change', () => {
      body.classList.toggle('show-netmon', netmonToggle.checked);
      applyFilters();   // re-renumber + update X-of-Y counter
    });
  }

  // v1.3: same toggle for log events. Lives inside the Logs section and
  // controls .self-event rows in the log tables.
  const netmonLogToggle = document.getElementById('show-netmon-logs');
  if (netmonLogToggle) {
    netmonLogToggle.addEventListener('change', () => {
      body.classList.toggle('show-netmon-logs', netmonLogToggle.checked);
    });
  }

  document.querySelectorAll('th[data-sort]').forEach((th) => {
    let asc = true;
    // v1.3: use th.cellIndex (the REAL column position) instead of the index
    // inside the querySelectorAll result. The two stopped matching once the
    // # / Pkts columns were added — querySelectorAll skips non-data-sort
    // columns, so idx=0 was Risk but cells[0] was now the # column.
    const colIdx = th.cellIndex;
    th.addEventListener('click', () => {
      const sorted = rows.slice().sort((a, b) => {
        const av = a.cells[colIdx].getAttribute('data-sort') || a.cells[colIdx].textContent;
        const bv = b.cells[colIdx].getAttribute('data-sort') || b.cells[colIdx].textContent;
        const an = parseFloat(av), bn = parseFloat(bv);
        if (!isNaN(an) && !isNaN(bn)) return asc ? an - bn : bn - an;
        return asc ? av.localeCompare(bv) : bv.localeCompare(av);
      });
      asc = !asc;
      sorted.forEach(r => tbody.appendChild(r));
      // After sort, the visible-order changed → renumber rows.
      applyFilters();
    });
  });

  // === "Load Packets" — read embedded packet previews and render inline ===
  const loadBtn = document.getElementById('load-packets-btn');
  const loadCount = document.getElementById('load-packets-count');
  const packetDetail = document.getElementById('packet-detail');
  const previewBlob = document.getElementById('packet-previews');
  let allPreviews = [];
  if (previewBlob && previewBlob.textContent.trim()) {
    try { allPreviews = JSON.parse(previewBlob.textContent); } catch (e) { allPreviews = []; }
  }

  function previewsForSelectedProcess() {
    if (!selectedProcess || selectedProcessPorts.size === 0) return [];
    const ports = new Set();
    selectedProcessPorts.forEach(p => ports.add(':' + p));
    return allPreviews.filter(p => {
      for (const port of ports) {
        if (p.src.endsWith(port) || p.dst.endsWith(port)) return true;
      }
      return false;
    });
  }

  function refreshLoadButton() {
    if (!loadBtn) return;
    // Clear any previously-rendered packet detail when the selection changes.
    // Otherwise stale packets from a previous selection persist below the button.
    if (packetDetail) packetDetail.innerHTML = '';
    const matching = previewsForSelectedProcess();
    if (!selectedProcess) {
      loadBtn.disabled = true;
      loadBtn.textContent = 'Load packets';
      if (loadCount) loadCount.textContent = '';
    } else if (matching.length === 0) {
      loadBtn.disabled = true;
      loadBtn.textContent = 'Load packets';
      if (loadCount) loadCount.textContent =
        ' — no captured payload packets for ' + selectedProcess
        + ' (pure ACKs and metadata-only packets are not stored)';
    } else {
      loadBtn.disabled = false;
      loadBtn.textContent = 'Load ' + matching.length + ' packets for ' + selectedProcess;
      if (loadCount) loadCount.textContent = '';
    }
  }

  function fmtTs(ts) {
    if (!ts) return '-';
    const d = new Date(ts * 1000);
    const hh = String(d.getHours()).padStart(2, '0');
    const mm = String(d.getMinutes()).padStart(2, '0');
    const ss = String(d.getSeconds()).padStart(2, '0');
    const ms = String(d.getMilliseconds()).padStart(3, '0');
    return hh + ':' + mm + ':' + ss + '.' + ms;
  }

  function renderHexAscii(hex, ascii) {
    // Format like xxd: 16 bytes per line, with the ASCII gutter.
    const out = [];
    for (let i = 0; i < hex.length; i += 32) {
      const hexChunk = hex.slice(i, i + 32);
      const asciiStart = i / 2;
      const asciiChunk = ascii.slice(asciiStart, asciiStart + 16);
      // Group hex into pairs for readability
      const grouped = [];
      for (let j = 0; j < hexChunk.length; j += 2) {
        grouped.push(hexChunk.slice(j, j + 2));
      }
      const offset = ('0000' + asciiStart.toString(16)).slice(-4);
      out.push(offset + '  ' + grouped.join(' ').padEnd(48) + '  ' + asciiChunk);
    }
    return out.join('\\n');
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ({
      '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
    }[c]));
  }

  function renderPackets() {
    if (!packetDetail) return;
    const matching = previewsForSelectedProcess();
    if (matching.length === 0) {
      packetDetail.innerHTML = '';
      return;
    }
    const parts = [];
    parts.push('<p class="muted">Showing ' + matching.length + ' packet'
               + (matching.length === 1 ? '' : 's') + ' for '
               + escapeHtml(selectedProcess) + ' (first '
               + (allPreviews.length && allPreviews[0].hex ? (allPreviews[0].hex.length / 2) : 0)
               + ' bytes of each payload; pure ACKs not stored).</p>');
    for (const p of matching) {
      const local = selectedProcessPorts;
      // Figure out direction by which side matches a local port.
      let direction = '→';
      for (const port of local) {
        if (p.src.endsWith(':' + port)) direction = '→ OUT';
        else if (p.dst.endsWith(':' + port)) direction = '← IN';
      }
      parts.push(
        '<div class="packet">' +
          '<div class="packet-head">' +
            '<span class="proto">' + escapeHtml(p.proto) + '</span>' +
            fmtTs(p.ts) +
            '<span class="direction">' + escapeHtml(direction) + '</span>' +
            escapeHtml(p.src) + '  →  ' + escapeHtml(p.dst) +
            '  ' + p.size + ' bytes' +
          '</div>' +
          '<pre class="packet-hex">' + escapeHtml(renderHexAscii(p.hex, p.ascii)) + '</pre>' +
        '</div>'
      );
    }
    packetDetail.innerHTML = parts.join('');
  }

  if (loadBtn) {
    loadBtn.addEventListener('click', renderPackets);
    refreshLoadButton();
  }

  // Hook into the existing process-click flow: refresh the button label
  // whenever the selection changes. The selection logic above already
  // updates selectedProcess + selectedProcessPorts before calling
  // applyFilters(), and applyFilters() calls applyPcapFilter() — we tack
  // refreshLoadButton on the end of that chain.
  const origApplyPcap = applyPcapFilter;
  applyPcapFilter = function() { origApplyPcap(); refreshLoadButton(); };

  // v1.3 UX: floating back-to-top button. Shows after scrolling >400px.
  const backToTop = document.getElementById('back-to-top');
  if (backToTop) {
    window.addEventListener('scroll', () => {
      backToTop.classList.toggle('visible', window.scrollY > 400);
    });
    backToTop.addEventListener('click', () => {
      window.scrollTo({top: 0, behavior: 'smooth'});
    });
  }

  // Apply initial filter — Status defaults to Established for the most useful
  // triage view; "All" or any other status button opens it up.
  applyFilters();
})();
</script>
</body>
</html>
""")


def _is_noisy_microsoft_or_system(conn):
    """Return True for trusted-Microsoft binaries, unprivileged System
    placeholders, and PID-0/(closed) orphaned TIME_WAIT residue. These
    rows are hidden by default in the HTML report on Windows runs to
    reduce visual noise; a checkbox toggles them."""
    app = (conn.get("app") or "").lower()
    sig = conn.get("signature") or {}
    publisher = (sig.get("publisher") or "").lower()
    if app in ("system", "system/protected", "unknown", "(closed/pid-0)"):
        return True
    if sig.get("trusted") and "microsoft" in publisher:
        return True
    return False


def _sev_class(sev):
    """Map severity strings to existing risk-class CSS so colors stay consistent."""
    s = (sev or "").upper()
    if s in ("HIGH", "MED", "LOW"):
        return s
    return "LOW"


def _render_log_section(findings, skipped=None):
    """Render the host event-log review section (F-3). Default-collapsed
    unless a HIGH finding exists. Surfaces skipped log sources (typically
    Security log when not elevated) so the operator knows what's missing."""
    if not findings and not skipped:
        # v1.3 UX: always render an empty-state callout instead of omitting
        # the section entirely. Lets the analyst confirm "yes the section is
        # there, it just has nothing in it" — much less ambiguous than the
        # section silently disappearing.
        return ('<section id="section-logs">'
                '<div class="empty-state">'
                '<strong>Host event logs:</strong> no entries collected '
                '(pass <code>--logs N</code> to read the last N minutes of '
                'host event logs).'
                '</div></section>')
    has_high = any(e.get("severity") == "HIGH" for e in findings or [])
    open_attr = " open" if has_high else ""
    # SELF events (netmon's own runtime footprint) are excluded from
    # severity counts on the section badge — they have their own toggle.
    non_self = [e for e in (findings or [])
                if e.get("severity") != "SELF"]
    high_count = sum(1 for e in non_self if e.get("severity") == "HIGH")
    med_count = sum(1 for e in non_self if e.get("severity") == "MED")
    self_count = sum(1 for e in (findings or [])
                     if e.get("severity") == "SELF")
    badge_class = "has-hi" if high_count else ("warn" if med_count else "ok")
    badge_label = (
        f"{high_count} HIGH" if high_count else
        f"{med_count} MED" if med_count else f"{len(non_self)} entries"
    )
    # Skipped-sources notice — rendered at the top of the section
    skipped_html = ""
    if skipped:
        rows = "".join(
            f'<tr><td>{html_mod.escape(src)}</td>'
            f'<td>{html_mod.escape(reason)}</td></tr>'
            for src, reason in skipped
        )
        skipped_html = (
            f'<p class="muted">Skipped log sources — these contributed zero '
            f'entries. Most commonly because the process needs Administrator '
            f'to read the Security log:</p>'
            f'<table class="log-table"><thead><tr><th>Source</th>'
            f'<th>Reason</th></tr></thead><tbody>{rows}</tbody></table>'
        )
    if not findings:
        return f"""
<section id="section-logs">
<details open id="logs-details">
<summary>Host event log review<span class="count-badge warn">no events in window</span></summary>
{skipped_html}
</details>
</section>
"""
    by_source = defaultdict(list)
    for e in findings:
        by_source[e.get("source", "?")].append(e)
    src_html = [skipped_html] if skipped_html else []
    # v1.3 UX: 'Show events generated by netmon.py (N hidden)' toggle.
    # Renders only when at least one SELF event exists; otherwise omitted.
    if self_count:
        src_html.append(
            f'<label class="toggle" title="Events generated by netmon\'s own '
            f'PowerShell invocations (Get-AuthenticodeSignature, '
            f'Get-ScheduledTask, Get-WinEvent, etc.) and the runtime '
            f'scaffolding they trigger. Hidden by default so the report '
            f'shows host activity, not the monitor\'s footprint.">'
            f'<input type="checkbox" id="show-netmon-logs"> '
            f'Show events generated by netmon.py ({self_count} hidden)</label>'
        )
    for source, entries in sorted(by_source.items(), key=lambda kv: -len(kv[1])):
        rows = []
        for e in entries[:500]:
            sev_raw = e.get("severity") or "LOW"
            sev_class = "noisy-self" if sev_raw == "SELF" else _sev_class(sev_raw)
            row_classes = "self-event" if sev_raw == "SELF" else ""
            display_sev = "SELF" if sev_raw == "SELF" else _sev_class(sev_raw)
            ip = e.get("src_ip") or ""
            user = e.get("user") or ""
            msg = e.get("message") or ""
            rows.append(
                f'<tr class="{row_classes}">'
                f'<td>{html_mod.escape(e.get("timestamp", ""))}</td>'
                f'<td><span class="risk {sev_class}">{html_mod.escape(display_sev)}</span></td>'
                f'<td>{html_mod.escape(e.get("event_id", ""))}</td>'
                f'<td>{html_mod.escape(user)}</td>'
                f'<td>{html_mod.escape(ip)}</td>'
                f'<td class="path">{html_mod.escape(msg)}</td></tr>'
            )
        # Count only non-SELF entries for the source-section badge.
        non_self_count = sum(1 for e in entries if e.get("severity") != "SELF")
        self_in_src = len(entries) - non_self_count
        sub = (f"{non_self_count}"
               + (f" + {self_in_src} netmon-self" if self_in_src else ""))
        src_html.append(
            f"<h3 style='margin-top:14px'>{html_mod.escape(source)} "
            f"({sub})</h3>"
            f"<table class='log-table'><thead><tr>"
            f"<th>Time</th><th>Sev</th><th>Event</th><th>User</th><th>Source IP</th><th>Message</th>"
            f"</tr></thead><tbody>{''.join(rows)}</tbody></table>"
        )
    return f"""
<section id="section-logs">
<details{open_attr} id="logs-details">
<summary>Host event log review<span class="count-badge {badge_class}">{badge_label}</span></summary>
<p class="muted">Tail-N-minutes parse of host audit/auth/web logs. PII (passwords, tokens, JWTs, certs, emails) is scrubbed before rendering.</p>
{''.join(src_html)}
</details>
</section>
"""


def _render_persistence_section(findings):
    """Render persistence-enumeration findings (F-4). When `--hash-tasks` is
    enabled, each row also carries SHA-256 of the binary the entry calls,
    rendered as a click-to-VirusTotal link, and (if --vt-api-key was passed)
    VT verdict counts."""
    if not findings:
        return ('<section id="section-persistence">'
                '<div class="empty-state">'
                '<strong>Persistence mechanisms:</strong> not enumerated '
                '(pass <code>--persistence</code> to scan cron, systemd, '
                'scheduled tasks, registry Run keys, launchd, SSH keys).'
                '</div></section>')
    recent_count = sum(1 for f in findings if f.get("recent"))
    has_hashes = any(f.get("binary_hash") for f in findings)
    rows = []
    for f in findings[:500]:
        sev_class = "HIGH" if f.get("recent") else "LOW"
        # VT-malicious row gets HIGH regardless of mtime.
        vt = f.get("vt") or {}
        if vt.get("found") and vt.get("malicious", 0) > 0:
            sev_class = "HIGH"
        kind = f.get("kind", "?")
        name = f.get("name", "")
        path = f.get("path", "")
        cmd = f.get("command", "")
        mtime = f.get("mtime")
        mtime_str = (datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M")
                     if mtime else "—")
        # v1.3 --hash-tasks columns
        hash_cell = ""
        vt_cell = ""
        if has_hashes:
            bh = f.get("binary_hash") or ""
            bp = f.get("binary_path") or ""
            if VirusTotalClient._is_valid_sha256(bh):
                href = f"https://www.virustotal.com/gui/file/{urllib.parse.quote(bh, safe='')}"
                hash_cell = (
                    f'<a class="hash" target="_blank" rel="noopener noreferrer" '
                    f'href="{html_mod.escape(href, quote=True)}" '
                    f'title="{html_mod.escape(bp)}">{html_mod.escape(bh[:16])}…</a>'
                )
            elif bh in ("NOT_FOUND", "ACCESS_DENIED", "TOO_LARGE", "N/A"):
                hash_cell = f'<span class="muted">{html_mod.escape(bh)}</span>'
            elif bh:
                hash_cell = f'<span class="muted">{html_mod.escape(bh[:16])}…</span>'
            else:
                hash_cell = '<span class="muted">—</span>'
            if vt.get("found"):
                mal = vt.get("malicious", 0)
                sus = vt.get("suspicious", 0)
                if mal > 0:
                    vt_cell = f'<span class="vt-mal">{mal} mal</span> / {sus} sus'
                elif sus > 0:
                    vt_cell = f'<span class="vt-mal">{sus} sus</span>'
                else:
                    vt_cell = '<span class="vt-clean">clean</span>'
            else:
                vt_cell = '<span class="muted">—</span>'
        extra_cols = (f'<td>{hash_cell}</td><td>{vt_cell}</td>'
                      if has_hashes else "")
        rows.append(
            f'<tr><td><span class="risk {sev_class}">{html_mod.escape(kind.upper())}</span></td>'
            f'<td>{html_mod.escape(name)}</td>'
            f'<td class="path">{html_mod.escape(path)}</td>'
            f'<td class="path">{html_mod.escape(cmd)}</td>'
            f'<td>{mtime_str}{" ⚡" if f.get("recent") else ""}</td>'
            f'{extra_cols}</tr>'
        )
    extra_headers = ("<th>Binary SHA-256</th><th>VT</th>"
                     if has_hashes else "")
    hash_blurb = (" Hashes are clickable VirusTotal links — no API key needed for "
                  "the redirect; pass --vt-api-key for inline verdict counts."
                  if has_hashes else "")
    badge_cls = "has-hi" if recent_count else ("ok" if findings else "warn")
    badge_text = (f"{recent_count} recent" if recent_count
                  else f"{len(findings)} entries")
    return f"""
<section id="section-persistence">
<details{' open' if recent_count else ''} id="persistence-details">
<summary>Persistence mechanisms<span class="count-badge {badge_cls}">{badge_text}</span></summary>
<p class="muted">Cron, systemd, scheduled tasks, registry Run keys, launchd, SSH authorized_keys.
The ⚡ marker indicates files modified within the last {PersistenceScanner.RECENT_DAYS} days — these are the IoCs worth investigating first.{hash_blurb}</p>
<table class='log-table'>
<thead><tr><th>Kind</th><th>Name</th><th>Path</th><th>Command</th><th>Modified</th>{extra_headers}</tr></thead>
<tbody>{''.join(rows)}</tbody></table>
</details>
</section>
"""


def _render_webshell_section(findings):
    """Render web-shell content-scan findings (F-2.3)."""
    if not findings:
        return ('<section id="section-webshell">'
                '<div class="empty-state">'
                '<strong>Web shells:</strong> clean (no webroot scan performed, '
                'or 0 matches). Pass <code>--scan-webroots</code> to walk '
                'webroots looking for shell signatures.'
                '</div></section>')
    rows = []
    for f in findings:
        mtime = f.get("mtime")
        mtime_str = (datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M")
                     if mtime else "—")
        flags = ", ".join(f.get("flags") or [])
        rows.append(
            f'<tr><td class="path">{html_mod.escape(f.get("path", ""))}</td>'
            f'<td>{f.get("size", 0):,}</td>'
            f'<td>{mtime_str}</td>'
            f'<td class="flags">{html_mod.escape(flags)}</td></tr>'
        )
    return f"""
<section id="section-webshell">
<details open id="webshell-details">
<summary>⚠ Web-shell content findings<span class="count-badge has-hi">{len(findings)} hits</span></summary>
<p class="muted">Files matching known web-shell signatures (Weevely, China Chopper, eval/base64 patterns).
This is a content-only signal — investigate each file before deletion (may be a planted backdoor; may be operator-installed admin shell; may be a false positive).</p>
<table class='log-table'>
<thead><tr><th>Path</th><th>Size</th><th>Modified</th><th>Signatures matched</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
</details>
</section>
"""


def _fmt_bytes_compact(n):
    """Compact bytes formatter for the HTML Pkts column: '850 B', '4.2 KB',
    '1.1 MB'. Returns '—' for 0 / None."""
    if not n:
        return "—"
    n = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            if unit == "B":
                return f"{int(n)} {unit}"
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


def _render_coverage_section(args):
    """v1.4: a 'Coverage & limitations' panel so a clean run is never mistaken
    for a clean host. States which detections were armed vs dormant and what is
    out of scope (pair with EDR/AV/FIM)."""
    def _row(label, on, detail=""):
        mark = ("<span style='color:var(--green)'>&#10003; armed</span>" if on
                else "<span class='muted'>&mdash; not armed</span>")
        d = f"<span class='muted'>{html_mod.escape(detail)}</span>" if detail else ""
        return f"<tr><td>{html_mod.escape(label)}</td><td>{mark}</td><td>{d}</td></tr>"
    offline = bool(getattr(args, "offline", False))
    has_vt = bool(getattr(args, "vt_api_key", None))
    rows = [
        _row("Process/socket mapping + risk scoring", True),
        _row("Code-signing / package trust", not getattr(args, "no_signing", False)),
        _row("Packet capture (DNS/TLS-SNI/JA3/HTTP)", bool(getattr(args, "capture", None))),
        _row("GeoIP enrichment (ipwho.is)", not offline),
        _row("Threat-intel C2 feed (abuse.ch)", bool(getattr(args, "threat_intel", False)) and not offline),
        _row("Tor-exit detection", bool(getattr(args, "scan_tor", False)) and not offline),
        _row("VirusTotal hash lookups", has_vt and not offline,
             "" if has_vt else "no $VT_API_KEY (hash links still work)"),
        _row("Persistence enumeration", bool(getattr(args, "persistence", False) or getattr(args, "hash_tasks", False))),
        _row("Host event-log review", bool(getattr(args, "logs", None)),
             f"last {args.logs} min" if getattr(args, "logs", None) else ""),
        _row("Web-shell webroot scan", bool(getattr(args, "scan_webroots", False))),
    ]
    win = (f"Observation window: {getattr(args, 'time', '?')}s "
           "(beacon detection needs ~4+ intervals; use -t 240 for slow beacons).")
    return f"""
<section id="section-coverage">
<details>
<summary>Coverage &amp; limitations<span class="count-badge">scope</span></summary>
<p class="muted">{html_mod.escape(win)}</p>
<table><thead><tr><th>Capability</th><th>Status</th><th></th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
<div class="empty-state" style="margin-top:12px">
<strong>Not covered (by design):</strong> memory / process-injection forensics, kernel rootkits,
on-access AV signature scanning, file-integrity monitoring, initial-access / email security, disk
forensics. netmon is a network + host-triage lens &mdash; <strong>pair it with EDR/Sysmon, AV, and a
FIM</strong>. A clean netmon run does not by itself mean a clean host.
</div>
</details>
</section>
"""


def render_html(conn_history, args, flow, output_path, console,
                dns_findings=None, saved_pcap_path=None,
                log_findings=None, persistence_findings=None,
                webshell_findings=None, log_sources_skipped=None):
    rows_html = []
    risk_order = {"CRITICAL": 0, "HIGH": 1, "MED": 2, "LOW": 3}
    sorted_conns = sorted(conn_history.values(), key=lambda x: (risk_order.get(x["risk"], 9), x["app"]))

    # v1.3 UX: build a per-local-port packet-statistics index from the saved
    # pcap so each connection row can show "N pkts / B bytes" up-front. Lets
    # the operator see at a glance which rows have actual captured traffic
    # without having to click "Load packets" first. The packet_previews list
    # only contains TCP packets WITH payload (pure ACKs are excluded), so the
    # bytes here represent real application data — not link-layer overhead.
    port_pkt_stats = {}
    if flow is not None:
        for p in getattr(flow, "packet_previews", []):
            for endpoint in (p.get("src", ""), p.get("dst", "")):
                colon = endpoint.rfind(":")
                if colon < 0:
                    continue
                try:
                    port = int(endpoint[colon + 1:])
                except ValueError:
                    continue
                count, total = port_pkt_stats.get(port, (0, 0))
                port_pkt_stats[port] = (count + 1, total + int(p.get("size", 0) or 0))
    has_packet_data = bool(port_pkt_stats)
    crit = sum(1 for c in sorted_conns if c["risk"] == "CRITICAL")
    high = sum(1 for c in sorted_conns if c["risk"] == "HIGH")
    med = sum(1 for c in sorted_conns if c["risk"] == "MED")
    low = sum(1 for c in sorted_conns if c["risk"] == "LOW")
    procs = len({c["app"] for c in sorted_conns})
    # Count unique PUBLIC peers — same definition that drives the cat-external
    # row class, so the tile count and the filter show the same set of rows
    # when collapsed to one-per-peer.
    peers = len({c["remote_ip"] for c in sorted_conns
                 if c.get("remote_ip") and not classify_local_ip(c["remote_ip"])})
    # An "unsigned binary" requires THREE conditions: a real executable path,
    # a signature check that actually ran, and a result of not-signed. The
    # System kernel (PID 4) has no path and so doesn't qualify, even though
    # its sig.signed is False.
    def _is_unsigned_binary(c):
        path = c.get("path") or ""
        if not path or path in ("N/A", "Access Denied"):
            return False
        sig = c.get("signature") or {}
        if sig.get("status") in (None, "", "skipped", "n/a", "missing"):
            return False
        return not sig.get("signed")
    unsigned = sum(1 for c in sorted_conns if _is_unsigned_binary(c))
    tor = sum(1 for c in sorted_conns if c.get("is_tor"))
    vt_mal = sum(1 for c in sorted_conns if (c.get("vt") or {}).get("malicious", 0) > 0)
    # Count listeners by exposure for the new "Exposed listeners" stat tile.
    exposed_any = sum(1 for c in sorted_conns
                      if not c["remote"] and listener_exposure_level(c.get("local")) == "any")
    exposed_lan = sum(1 for c in sorted_conns
                      if not c["remote"] and listener_exposure_level(c.get("local")) == "lan")
    is_windows = sys.platform == "win32"
    noisy_count = sum(1 for c in sorted_conns if _is_noisy_microsoft_or_system(c))

    for c in sorted_conns:
        sig = c.get("signature") or {}
        if sig.get("trusted"):
            sig_class, sig_text = "trusted", f"trusted ({sig.get('publisher') or '?'})"
        elif sig.get("signed"):
            sig_class, sig_text = "signed", f"signed ({sig.get('publisher') or '?'})"
        elif sig.get("status") in ("n/a", "skipped", "missing"):
            sig_class, sig_text = "unknown", "—"
        else:
            sig_class, sig_text = "unsigned", "UNSIGNED"

        h = c["hash"]
        # Defensive: only emit a VT link for syntactically valid SHA256s.
        # If the hash field is ever populated from a less-trusted source in
        # the future, this prevents XSS / open-redirect via crafted strings.
        if VirusTotalClient._is_valid_sha256(h):
            h_safe = html_mod.escape(h)
            href = f"https://www.virustotal.com/gui/file/{urllib.parse.quote(h, safe='')}"
            hash_html = (f'<a class="hash" target="_blank" rel="noopener noreferrer" '
                         f'href="{html_mod.escape(href, quote=True)}">{h_safe[:16]}…</a>')
        else:
            hash_html = f'<span class="muted">{html_mod.escape(h or "N/A")}</span>'

        vt = c.get("vt") or {}
        if vt.get("found"):
            mal = vt.get("malicious", 0)
            sus = vt.get("suspicious", 0)
            if mal > 0:
                vt_html = f'<span class="vt-mal">{mal} mal</span> / {sus} sus'
            elif sus > 0:
                vt_html = f'<span class="vt-mal">{sus} sus</span>'
            else:
                vt_html = '<span class="vt-clean">clean</span>'
        elif args.vt_api_key:
            vt_html = '<span class="muted">unknown</span>'
        else:
            vt_html = '<span class="muted">—</span>'

        local_html = html_mod.escape(c.get("local") or "—")
        if c["remote"]:
            remote = c["remote"]
            host = c.get("hostname")
            if host and host not in ("N/A", ""):
                remote_html = f"{html_mod.escape(remote)}<br><span class='muted'>{html_mod.escape(host)}</span>"
            else:
                remote_html = html_mod.escape(remote)
            if c.get("is_tor"):
                remote_html += " <span class='vt-mal'>[TOR]</span>"
        else:
            # Listening socket — describe which interface it's exposed on so
            # the operator immediately sees 'any IPv4' vs 'loopback only'.
            exposure = describe_listener_exposure(c.get("local"))
            remote_html = f"<span class='muted'>{html_mod.escape(exposure)}</span>"

        country = c.get("country") or ""
        country_code = c.get("country_code") or ""
        # For loopback / private LAN / wildcard listens, the org field carries
        # the descriptive label (no point trying to GeoIP a loopback). Render
        # that directly so the operator sees "loopback" / "private LAN"
        # instead of "—" with no context.
        if country in ("—", "N/A", "", None):
            geo = (f"<span class='muted'>{html_mod.escape(c.get('org') or '—')}</span>"
                   "<br><span class='muted'>(no GeoIP for non-public IP)</span>")
        else:
            geo = (f"{html_mod.escape(country_code or '-')} &middot; {html_mod.escape(c.get('org') or '-')}"
                   f"<br><span class='muted'>{html_mod.escape(c.get('asn') or '')}</span>")

        path_html = (f"<div>{html_mod.escape(c['path'])}</div>"
                     f"<div>{hash_html}</div>")

        flags = ", ".join(c.get("flags") or []) or "—"
        # Tag the row with every category it belongs to so stat-tile filters
        # in the HTML can show/hide by simple CSS class match.
        row_class_set = [c["risk"]]
        if _is_noisy_microsoft_or_system(c):
            row_class_set.append("noisy")
        # v1.3: rows owned by netmon (this script + its child processes) are
        # tagged cat-netmon-self and hidden by default. The "Show netmon-
        # generated events" toggle in the HTML reveals them.
        if c.get("is_netmon_self"):
            row_class_set.append("cat-netmon-self")
        if _is_unsigned_binary(c):
            row_class_set.append("cat-unsigned")
        if c.get("is_tor"):
            row_class_set.append("cat-tor")
        if (c.get("vt") or {}).get("malicious", 0) > 0:
            row_class_set.append("cat-vt-malicious")
        if c.get("remote_ip") and not classify_local_ip(c["remote_ip"]):
            row_class_set.append("cat-external")
        if c.get("flags"):
            row_class_set.append("cat-flagged")
        # Listener exposure highlighting — only for rows with no remote.
        if not c["remote"]:
            level = listener_exposure_level(c.get("local"))
            if level == "any":
                row_class_set.append("cat-exposed-any")
            elif level == "lan":
                row_class_set.append("cat-exposed-lan")
            # loopback listeners aren't highlighted (safe)

        # Status filter: tag every row with a status-* class so the new status
        # button row can filter by connection state (ESTABLISHED, LISTEN, etc.).
        # Normalize to lowercase ASCII and group rarely-seen states under 'other'.
        _STATUS_GROUPS = {
            "ESTABLISHED": "status-established",
            "LISTEN": "status-listen",
            "TIME_WAIT": "status-time-wait",
            "CLOSE_WAIT": "status-close-wait",
            "SYN_SENT": "status-syn-sent",
            "SYN_RECV": "status-syn-recv",
            "FIN_WAIT1": "status-fin-wait",
            "FIN_WAIT2": "status-fin-wait",
            "LAST_ACK": "status-fin-wait",
            "CLOSING": "status-fin-wait",
            "NONE": "status-listen",   # UDP listeners report NONE; group with LISTEN
        }
        status_raw = (c.get("status") or "NONE").upper()
        row_class_set.append(_STATUS_GROUPS.get(status_raw, "status-other"))
        row_classes = " ".join(row_class_set)

        # v1.3 — Direction (T1-2), Age (T3-1), Service (T2-2) columns
        direction = c.get("direction") or ""
        dir_glyph = {
            "OUTBOUND": "↑ OUT",
            "INBOUND":  "↓ IN",
            "LOOPBACK": "↔ LOOP",
            "LISTEN":   "○ LSTN",
            "AMBIGUOUS": "?",
        }.get(direction, html_mod.escape(direction))
        dir_class = {
            "OUTBOUND": "dir-out", "INBOUND": "dir-in",
            "LOOPBACK": "dir-loop", "LISTEN": "dir-listen",
        }.get(direction, "")

        age = c.get("session_age_s")
        if age is None:
            age_html = '<span class="muted">—</span>'
        else:
            age_html = _fmt_age(age)

        service = c.get("systemd_unit") or ""
        if service:
            service_html = f'<span class="muted">{html_mod.escape(service)}</span>'
        else:
            service_html = '<span class="muted">—</span>'

        # T2-1: CrowdSec verdict pill, embedded next to the remote.
        cs_verdict = c.get("crowdsec")
        if cs_verdict == "ban":
            remote_html += ' <span class="vt-mal">[CS:BAN]</span>'
        elif cs_verdict in ("captcha", "throttle"):
            remote_html += f' <span class="sig signed">[CS:{cs_verdict.upper()}]</span>'
        elif cs_verdict == "clean":
            remote_html += ' <span class="sig trusted">[CS:OK]</span>'

        # T2-3: Firewall verdict pill on the local cell (listener allow/deny).
        fw_verdict = c.get("firewall")
        if fw_verdict == "blocked":
            local_html += '<br><span class="sig trusted">fw: blocked</span>'
        elif fw_verdict == "lan-only":
            local_html += '<br><span class="sig signed">fw: LAN only</span>'
        elif fw_verdict == "allowed":
            local_html += '<br><span class="muted">fw: allowed</span>'

        # v1.3 bug fix — emit the local port as a row-level data attribute so
        # the Load-Packets JS can read it directly. Previously the JS parsed
        # cells[4].textContent.lastIndexOf(':'), which broke once we started
        # appending "fw: allowed/blocked/LAN only" annotations into the same
        # cell (the parser would lock onto the colon in "fw:" and produce an
        # empty port set, so per-process packet filtering returned 0 matches).
        row_attrs = []
        lport = SecurityMonitor._local_port(c.get("local") or "")
        if lport is not None:
            row_attrs.append(f'data-local-port="{lport}"')

        # v1.3 UX: per-row packet stats (count + bytes) AND a tooltip on the
        # process cell so the operator sees BEFORE clicking which rows have
        # actual captured traffic. Computed from the per-port stats built
        # above; rows with zero captured payload show "—" so analysts don't
        # waste time on Load-Packets clicks that return nothing.
        pkt_count, pkt_bytes = (0, 0)
        if lport is not None and lport in port_pkt_stats:
            pkt_count, pkt_bytes = port_pkt_stats[lport]
        row_attrs.append(f'data-pkt-count="{pkt_count}"')
        row_attrs.append(f'data-pkt-bytes="{pkt_bytes}"')
        if has_packet_data:
            if pkt_count:
                pkts_html = (f'<span title="{pkt_count} packets, '
                             f'{pkt_bytes} bytes total">'
                             f'{pkt_count} · {_fmt_bytes_compact(pkt_bytes)}'
                             f'</span>')
                proc_title = (f'{pkt_count} captured packets · '
                              f'{_fmt_bytes_compact(pkt_bytes)} payload')
            else:
                pkts_html = '<span class="muted" title="No payload packets captured for this socket. Pure ACKs are not stored.">—</span>'
                proc_title = "No captured payload packets for this socket"
            pkts_cell = f'<td class="pkts" data-sort="{pkt_count}">{pkts_html}</td>'
        else:
            pkts_cell = ""
            proc_title = ""

        proc_html = html_mod.escape(c["app"] or "")
        if proc_title:
            proc_span = f'<span class="proc-link" title="{html_mod.escape(proc_title)}">{proc_html}</span>'
        else:
            proc_span = f'<span class="proc-link">{proc_html}</span>'

        row_attr_str = (" " + " ".join(row_attrs)) if row_attrs else ""
        rows_html.append(
            f'<tr class="{row_classes}"{row_attr_str}>'
            f'<td class="row-num"></td>'                                # NEW: filled by JS
            f'<td><span class="risk {c["risk"]}">{c["risk"]}</span></td>'
            f'<td>{proc_span}</td>'
            f'<td>{c["pid"] or ""}</td>'
            f'<td class="sig {sig_class}">{html_mod.escape(sig_text)}</td>'
            f'<td class="local">{local_html}</td>'
            f'<td>{remote_html}</td>'
            f'<td class="dir {dir_class}">{dir_glyph}</td>'
            f'<td>{geo}</td>'
            f'<td class="age">{age_html}</td>'
            f'{pkts_cell}'                                              # NEW: conditional
            f'<td>{service_html}</td>'
            f'<td class="path">{path_html}</td>'
            f'<td>{vt_html}</td>'
            f'<td class="flags">{html_mod.escape(flags)}</td>'
            f'</tr>'
        )

    # === Noise-toggle checkbox (Windows-only) ===
    if is_windows and noisy_count:
        noise_toggle = (
            f'<label class="toggle"><input type="checkbox" id="show-noisy"> '
            f'Show Microsoft &amp; system processes ({noisy_count} hidden)</label>'
        )
    else:
        noise_toggle = ""

    # === v1.3: netmon-self toggle ===
    # Count connections owned by netmon itself. These are tagged
    # cat-netmon-self in the row classes and hidden by default via CSS.
    netmon_self_count = sum(
        1 for c in sorted_conns if c.get("is_netmon_self"))
    if netmon_self_count:
        netmon_self_toggle = (
            f'<label class="toggle" title="Connections owned by this netmon '
            f'run or its child processes (pktmon / PowerShell sig-verifier / '
            f'etc.). Hidden by default so the report shows external activity, '
            f'not the monitor\'s own footprint."><input type="checkbox" '
            f'id="show-netmon"> Show netmon-generated events '
            f'({netmon_self_count} hidden)</label>'
        )
    else:
        netmon_self_toggle = ""

    # === Packet capture summary ===
    capture_section = ""
    if flow:
        s = flow.summary()
        top_dns = Counter(q[0] for q in flow.dns_queries).most_common(20)
        top_sni = sorted({sni for v in flow.sni_by_peer.values() for sni in v})[:50]
        dns_rows = "".join(
            f"<tr><td>{html_mod.escape(name)}</td><td>{count}</td></tr>"
            for name, count in top_dns
        ) or "<tr><td colspan='2' class='muted'>(no DNS queries captured)</td></tr>"
        sni_html = ", ".join(html_mod.escape(s) for s in top_sni) or "<span class='muted'>(none)</span>"
        # Total bytes badge — quickly tells the analyst how much traffic
        # was captured (helps spot "5 MB exfil" patterns).
        cap_badge = (f"{s['unique_dns_names']} DNS + "
                     f"{s['unique_sni_names']} TLS hosts")
        capture_section = f"""
<section id="section-capture">
<details open id="capture-details">
<summary>Packet capture summary<span class="count-badge ok">{cap_badge}</span></summary>
<div class="kv">
  <span class="k">DNS queries</span><span>{s['dns_query_count']}</span>
  <span class="k">Unique DNS names</span><span>{s['unique_dns_names']}</span>
  <span class="k">TLS SNI hosts</span><span>{s['unique_sni_names']}</span>
  <span class="k">Tracked peers</span><span>{s['tracked_peer_count']}</span>
  <span class="k">Parse errors</span><span>{s['parse_errors']}</span>
</div>
<h3 style="margin-top:16px">Top DNS queries</h3>
<table><thead><tr><th>Name</th><th>Count</th></tr></thead><tbody>{dns_rows}</tbody></table>
<h3 style="margin-top:16px">TLS SNI hosts</h3>
<div>{sni_html}</div>
</details>
</section>
"""

    # === DNS heuristic findings ===
    dns_section = ""
    if dns_findings:
        def _flag_pills(flags):
            return "".join(
                f'<span class="dns-flag">{html_mod.escape(fl)}</span>' for fl in flags
            )
        dns_rows_html = "".join(
            f'<tr><td>{html_mod.escape(r["qname"])}</td>'
            f'<td>{r["count"]}</td>'
            f'<td>{_flag_pills(r["flags"])}</td>'
            f'</tr>'
            for r in dns_findings[:50]
        )
        # Severity badge: NXDOMAIN-burst flags are HIGH (probable beacon),
        # plain HIGH_RETRY is informational.
        has_nx = any("NXDOMAIN" in fl for r in dns_findings
                     for fl in (r.get("flags") or []))
        dns_badge_cls = "has-hi" if has_nx else "warn"
        dns_section = f"""
<section id="section-dns">
<details open id="dns-details">
<summary>Suspicious DNS findings<span class="count-badge {dns_badge_cls}">{len(dns_findings)} flagged</span></summary>
<table>
  <thead><tr><th>Domain</th><th>Queries</th><th>Flags</th></tr></thead>
  <tbody>{dns_rows_html}</tbody>
</table>
</details>
</section>
"""

    # === Browsable packet log (only when --save-capture was used) ===
    packet_log_section = ""
    if saved_pcap_path and flow:
        pcap_link = (f'<p><a class="pcap-link" href="{html_mod.escape(saved_pcap_path)}" '
                     f'download>Download saved pcap</a> '
                     f'<span class="muted">— open in Wireshark for full packet inspection</span></p>')

        # DNS query log
        dns_log_rows = "".join(
            f'<tr><td>{html_mod.escape(datetime.fromtimestamp(q["ts"]).strftime("%H:%M:%S.%f")[:-3] if q["ts"] else "-")}</td>'
            f'<td>{html_mod.escape(q["qname"])}</td>'
            f'<td>{q["qtype"]}</td>'
            f'<td>{html_mod.escape(q["src"])}</td>'
            f'<td>{html_mod.escape(q["dst"])}</td>'
            f'</tr>'
            for q in flow.dns_query_log[:500]
        ) or "<tr><td colspan='5' class='muted'>(no DNS queries logged)</td></tr>"

        # TLS handshake log
        tls_log_rows = "".join(
            f'<tr><td>{html_mod.escape(datetime.fromtimestamp(h["ts"]).strftime("%H:%M:%S.%f")[:-3] if h["ts"] else "-")}</td>'
            f'<td>{html_mod.escape(h["sni"])}</td>'
            f'<td>{html_mod.escape(h["src"])}</td>'
            f'<td>{html_mod.escape(h["dst"])}</td>'
            f'</tr>'
            for h in flow.tls_handshakes[:500]
        ) or "<tr><td colspan='4' class='muted'>(no TLS handshakes logged)</td></tr>"

        # TCP flow log (top 100 by bytes)
        sorted_flows = sorted(flow.tcp_flow_log.items(), key=lambda kv: -kv[1]["bytes"])[:100]
        tcp_log_rows = "".join(
            f'<tr><td>{html_mod.escape(src_ip)}:{sport}</td>'
            f'<td>{html_mod.escape(dst_ip)}:{dport}</td>'
            f'<td>{f["bytes"]:,}</td>'
            f'<td>{f["pkts"]:,}</td>'
            f'<td>{(f["last_ts"] - f["first_ts"]):.2f}s</td>'
            f'</tr>'
            for (src_ip, sport, dst_ip, dport, _), f in sorted_flows
        ) or "<tr><td colspan='5' class='muted'>(no TCP flows logged)</td></tr>"

        # HTTP request/response log (plaintext only — port 80)
        http_log_rows = "".join(
            f'<tr><td>{html_mod.escape(datetime.fromtimestamp(m["ts"]).strftime("%H:%M:%S.%f")[:-3] if m["ts"] else "-")}</td>'
            f'<td>{html_mod.escape(m["kind"])}</td>'
            f'<td>{html_mod.escape(m["method"] or m["status"])}</td>'
            f'<td>{html_mod.escape(m["host"])}</td>'
            f'<td>{html_mod.escape(m["path"])}</td>'
            f'<td>{html_mod.escape(m["src"])}</td>'
            f'<td>{html_mod.escape(m["dst"])}</td>'
            f'</tr>'
            for m in flow.http_messages[:500]
        ) or "<tr><td colspan='7' class='muted'>(no plaintext HTTP — modern traffic is HTTPS so this is normal)</td></tr>"

        # Serialize packet previews as JSON for the on-demand "Load packets"
        # button. Using json.dumps protects against accidental HTML/script
        # injection — every string is properly escaped and quoted. We embed
        # inside <script type="application/json"> so the browser never
        # executes it as code, just treats it as a data island.
        previews_payload = [
            {
                "ts": p["ts"],
                "src": p["src"],
                "dst": p["dst"],
                "size": p["size"],
                "hex": p["hex"],
                "ascii": p["ascii"],
                "proto": p["proto"],
            }
            for p in flow.packet_previews
        ]
        # </script> in the JSON would terminate the data island; replace the
        # literal "</" sequence with the equivalent escaped form so it's
        # impossible to break out of the script tag.
        packet_previews_json = json.dumps(previews_payload).replace("</", "<\\/")

        packet_log_section = f"""
<details>
<summary>Saved packet capture &mdash; browsable detail (HTTPS payloads encrypted; metadata only)</summary>
{pcap_link}
<p class="muted" style="margin-top:8px">Tip: click any row in the connection table above to drill these tables down to that process's local ports. Click the same row again to clear.</p>
<h3 style="margin-top:16px">DNS queries (full log, up to 500 rows)</h3>
<table class="log-table">
  <thead><tr><th>Time</th><th>Name</th><th>Type</th><th>Source</th><th>Destination</th></tr></thead>
  <tbody>{dns_log_rows}</tbody>
</table>
<h3 style="margin-top:16px">TLS handshakes (Client Hello SNI, up to 500 rows)</h3>
<table class="log-table">
  <thead><tr><th>Time</th><th>SNI hostname</th><th>Source</th><th>Destination</th></tr></thead>
  <tbody>{tls_log_rows}</tbody>
</table>
<h3 style="margin-top:16px">HTTP request / response (plaintext port-80 only, up to 500 rows)</h3>
<table class="log-table">
  <thead><tr><th>Time</th><th>Type</th><th>Method / Status</th><th>Host</th><th>Path</th><th>Source</th><th>Destination</th></tr></thead>
  <tbody>{http_log_rows}</tbody>
</table>
<h3 style="margin-top:16px">TCP flows (top 100 by bytes)</h3>
<table class="log-table">
  <thead><tr><th>Source</th><th>Destination</th><th>Bytes</th><th>Packets</th><th>Duration</th></tr></thead>
  <tbody>{tcp_log_rows}</tbody>
</table>
<h3 style="margin-top:16px">Packet contents</h3>
<div id="packet-load-area">
  <p class="muted">Select a process row above to enable per-packet inspection.</p>
  <button id="load-packets-btn" class="filter-btn" disabled>Load packets</button>
  <span id="load-packets-count" class="muted"></span>
  <div id="packet-detail"></div>
</div>
<script type="application/json" id="packet-previews">{packet_previews_json}</script>
</details>
"""

    host_os = "Windows" if is_windows else ("Linux" if sys.platform.startswith("linux") else sys.platform)

    # === v1.3 — Host event log review (F-3) ===
    log_section = _render_log_section(log_findings, log_sources_skipped)
    # === v1.3 — Persistence enumeration (F-4) ===
    persistence_section = _render_persistence_section(persistence_findings)
    # === v1.3 — Web-shell scan findings (F-2.3) ===
    webshell_section = _render_webshell_section(webshell_findings)

    # === v1.3 UX: sticky table-of-contents nav ===
    # The HTML report has 5-7 major sections plus the connection table.
    # Without a quick-nav the analyst has to scroll past 100+ rows to reach
    # the persistence or log sections. The TOC pins to the top and badges
    # each section with its finding count (red if HIGH-severity exists).
    log_hi = sum(1 for e in (log_findings or [])
                 if e.get("severity") == "HIGH")
    log_total = len(log_findings or [])
    pers_recent = sum(1 for p in (persistence_findings or []) if p.get("recent"))
    pers_total = len(persistence_findings or [])
    ws_total = len(webshell_findings or [])
    dns_total = len(dns_findings or [])
    capture_present = flow is not None and getattr(flow, "packet_previews", [])

    def _toc_link(href, label, count, hi):
        cls = "has-hi" if hi else ""
        badge_cls = "warn" if (count and not hi) else ""
        if count:
            badge = f'<span class="badge {badge_cls}">{count}</span>'
        else:
            badge = '<span class="badge">0</span>'
        return f'<a href="{href}" class="{cls}">{label}{badge}</a>'

    high_count_total = sum(1 for c in conn_history.values() if c["risk"] in ("HIGH", "CRITICAL"))
    toc_links = [
        _toc_link("#section-connections", "Connections ",
                  len(conn_history), high_count_total > 0),
    ]
    if capture_present or dns_total:
        toc_links.append(_toc_link("#section-capture", "Capture ",
                                   1 if capture_present else 0, False))
    if dns_total:
        toc_links.append(_toc_link("#section-dns", "DNS findings ",
                                   dns_total, False))
    toc_links.append(_toc_link("#section-logs", "Event logs ",
                               log_total, log_hi > 0))
    toc_links.append(_toc_link("#section-persistence", "Persistence ",
                               pers_total, pers_recent > 0))
    toc_links.append(_toc_link("#section-webshell", "Web shells ",
                               ws_total, ws_total > 0))
    toc_html = (
        '<nav class="toc" id="section-nav">'
        '<span class="toc-label">Jump to:</span>'
        + "".join(toc_links)
        + '</nav>'
    )

    # v1.3 UX: the Pkts column header only shows when capture data is present;
    # the corresponding <td> cells are empty when has_packet_data is False
    # (see the row-builder loop above), but the template still needs SOME
    # substitution value for $pkts_th — empty string when absent.
    pkts_th = ('<th data-sort="pkts" title="Captured packets and total payload '
               'bytes for this connection during the capture window. — means '
               'no payload packets were stored for this socket.">Pkts</th>'
               if has_packet_data else "")

    html_out = HTML_TEMPLATE.substitute(
        generated=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        duration=args.time,
        conn_count=len(conn_history),
        crit=crit, high=high, med=med, low=low,
        procs=procs, peers=peers, unsigned=unsigned, tor=tor, vt_mal=vt_mal,
        exposed_any=exposed_any, exposed_lan=exposed_lan,
        rows="\n".join(rows_html),
        pkts_th=pkts_th,
        capture_section=capture_section,
        dns_section=dns_section,
        packet_log_section=packet_log_section,
        coverage_section=_render_coverage_section(args),
        log_section=log_section,
        persistence_section=persistence_section,
        webshell_section=webshell_section,
        noise_toggle=noise_toggle,
        netmon_self_toggle=netmon_self_toggle,
        toc_html=toc_html,
        body_class="",
        host_os=html_mod.escape(host_os),
        version=VERSION,
    )
    try:
        Path(output_path).write_text(html_out, encoding="utf-8")
        console.print(f"[bold green]HTML report:[/bold green] {output_path}")
    except OSError as e:
        log.error("HTML write failed: %s", e)
        console.print(f"[bold red]HTML write failed:[/bold red] {e}")


# === main ===

# Exit codes (sysexits-inspired):
EXIT_OK = 0
EXIT_USAGE = 64       # CLI usage error
EXIT_NOPERM = 77      # capture/signing requested without privileges
EXIT_INTERRUPT = 130  # SIGINT (Ctrl+C)
EXIT_FAIL = 1


def is_admin():
    """Return True iff we have root (POSIX) or local Administrator (Windows)."""
    if hasattr(os, "getuid"):
        return os.getuid() == 0
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except (AttributeError, OSError):
        return False


def _install_signal_handlers():
    """Install handlers so Ctrl+C / SIGTERM produce a clean exit code."""
    def _handler(_signum, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGINT, _handler)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _handler)


def _build_arg_parser():
    parser = argparse.ArgumentParser(
        prog="netmon",
        description=f"netmon.py v{VERSION} — Cybersecurity Network Monitor (IOC focused)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        epilog="Source: https://github.com/Ozear/netmon.py",
    )
    parser.add_argument("--version", action="version", version=f"netmon {VERSION}")
    parser.add_argument("-t", "--time", type=int, default=15,
                        help="Monitoring duration in seconds (1-86400)")
    # Output formats — HTML and TXT are ON by default (visual + cat-friendly);
    # CSV is opt-in. All write timestamped files into ./reports/ unless an
    # explicit path is supplied.
    parser.add_argument("--html", default="__AUTO__", nargs="?", const="__AUTO__",
                        help="Self-contained HTML report. ON by default — writes "
                             "./reports/netmon-<YYYYMMDD-HHMMSS>.html. Pass a path to override "
                             "or pass --no-html to disable.")
    parser.add_argument("--no-html", action="store_true",
                        help="Disable the HTML report (HTML is on by default).")
    parser.add_argument("--text", default="__AUTO__", nargs="?", const="__AUTO__",
                        help="Plain-text report (cat / grep / less friendly). ON by default — "
                             "writes ./reports/netmon-<YYYYMMDD-HHMMSS>.txt. Pass --no-text to disable.")
    parser.add_argument("--no-text", action="store_true",
                        help="Disable the plain-text report (text is on by default).")
    parser.add_argument("-o", "--output", "--csv", default=None, nargs="?", const="__AUTO__",
                        help="CSV machine-readable export. OFF by default. Pass --csv (no value) to "
                             "auto-generate ./reports/netmon-<YYYYMMDD-HHMMSS>.csv, or pass a path.",
                        dest="output")
    # v1.3 capture CLI rework (T2-5):
    #   --capture [PATH]   capture AND save (the common case is the default)
    #   --capture-fly      capture, parse, discard the pcap (ephemeral)
    #   --save-capture     v1.2 alias for --capture, kept for backward compat
    parser.add_argument("--capture", default=None, nargs="?", const="__AUTO__",
                        metavar="PATH",
                        help="Capture packets (pktmon on Windows, tcpdump on Linux/macOS) "
                             "AND save the .pcap. Default destination: "
                             "./reports/netmon-<YYYYMMDD-HHMMSS>.pcap. Pass an explicit path "
                             "to override. Requires admin/root. WARNING: captures can be tens-"
                             "hundreds of MB; you'll be prompted unless --yes is given. New in "
                             "v1.3: was previously ephemeral by default — now saves by default.")
    parser.add_argument("--capture-fly", action="store_true",
                        help="Capture, parse, and DISCARD the pcap at the end. Use when you "
                             "only need the HTML's DNS/TLS/HTTP/TCP-flow metadata views and "
                             "don't want a pcap on disk (read-only / CI). Skips the disk-usage "
                             "prompt. Mutually exclusive with --capture.")
    parser.add_argument("--save-capture", default=None, nargs="?", const="__AUTO__",
                        metavar="PATH",
                        help="DEPRECATED v1.2 alias for --capture; prints a deprecation note. "
                             "Will be removed in v2.0.")
    parser.add_argument("--yes", action="store_true",
                        help="Auto-confirm prompts (e.g. for --capture disk-usage warning). "
                             "Use for non-interactive / scripted runs.")
    parser.add_argument("--vt-api-key", default=os.environ.get("VT_API_KEY"),
                        help="VirusTotal API key. Prefer $VT_API_KEY env var — passing on CLI exposes "
                             "the key in process listings (ps, Task Manager) and shell history.")
    parser.add_argument("--offline", action="store_true",
                        help="Skip GeoIP / threat-intel network calls")
    parser.add_argument("--scan-tor", action="store_true",
                        help="Fetch and use the Tor exit-list to flag connections to Tor exits. "
                             "Default OFF — many networks SNI-filter torproject.org and this "
                             "produces a noisy warning otherwise. Enable when you actually want "
                             "Tor-exit detection.")
    parser.add_argument("--no-signing", action="store_true",
                        help="Skip Authenticode / package signature verification")
    parser.add_argument("--crowdsec-token", default=os.environ.get("CROWDSEC_LAPI_KEY"),
                        help="CrowdSec Local API token. If omitted, netmon auto-detects from "
                             "/etc/crowdsec/local_api_credentials.yaml when running as root. "
                             "Prefer $CROWDSEC_LAPI_KEY env var over CLI flag.")
    parser.add_argument("--no-crowdsec", action="store_true",
                        help="Skip CrowdSec lookups even if a local LAPI is running.")
    parser.add_argument("--no-firewall", action="store_true",
                        help="Skip the firewall-state snapshot (ufw / nft / iptables / "
                             "Windows Firewall profile).")
    parser.add_argument("--quick-triage", "--tr", "--full-triage",
                        action="store_true", dest="quick_triage",
                        help="QUICK one-shot triage — safe for a possibly-compromised or "
                             "privacy-sensitive host. Enables: -t 60 --capture --yes "
                             "--persistence --hash-tasks --scan-webroots --logs 3 "
                             "--threat-intel, plus a live progress display. Uses exactly "
                             "ONE trusted intel host (the abuse.ch Feodo C2 feed) and "
                             "GeoIP; makes NO Tor-exit fetch and NO VirusTotal API calls "
                             "(SHA-256s still render as click-through VirusTotal links — "
                             "no account needed). Add --offline for zero external calls. "
                             "('--full-triage' is a kept-for-compat alias.) Any explicit "
                             "flag you also pass wins.")
    parser.add_argument("--deep-triage", "--dtr",
                        action="store_true", dest="deep_triage",
                        help="DEEP triage = everything --quick-triage does PLUS a longer "
                             "window (-t 120) and all external intelligence: Tor-exit "
                             "detection (--scan-tor), the abuse.ch Feodo botnet-C2 IP feed "
                             "(--threat-intel), and VirusTotal lookups when $VT_API_KEY is "
                             "set. Use on a TRUSTED analysis host where outbound lookups "
                             "are acceptable. Any explicit flag you also pass wins.")
    parser.add_argument("--threat-intel", action="store_true", dest="threat_intel",
                        help="Fetch and use a free, open, no-auth botnet-C2 IP blocklist "
                             "(abuse.ch Feodo Tracker — a single trusted host) to flag "
                             "connections to known C2 (C2_FEED_MATCH, HIGH). OFF by "
                             "default; auto-enabled by --deep-triage. Honors --offline.")
    # === v1.3 host-context features ===
    parser.add_argument("--logs", type=int, default=None, metavar="MINUTES",
                        help="Review host event logs for the last N minutes (1-1440). "
                             "Linux: /var/log/auth, syslog, apache/nginx, mysql, audit, "
                             "fail2ban, crowdsec. Windows: Security / System / PowerShell "
                             "Operational / Defender event logs. Findings render in a new "
                             "HTML section with brute-force / privesc / web-shell rules. "
                             "PII (passwords, tokens, JWTs, certs, emails) is scrubbed.")
    parser.add_argument("--persistence", action="store_true",
                        help="Enumerate host persistence mechanisms (cron, systemd unit "
                             "files, registry Run keys, Windows scheduled tasks + services, "
                             "macOS launchd, SSH authorized_keys). Recently-modified "
                             "entries are flagged as IoCs.")
    parser.add_argument("--hash-tasks", action="store_true",
                        help="For every persistence entry (cron job, systemd unit, "
                             "scheduled task, registry Run key, service, launchd plist), "
                             "extract the binary path from the command, compute its SHA-256, "
                             "and (when --vt-api-key is set) look up VirusTotal verdicts. "
                             "Implies --persistence. Adds binary_hash + VT columns to the "
                             "HTML / JSON output. The HTML hash becomes a clickable link to "
                             "https://www.virustotal.com/gui/file/<sha256> so analysts can "
                             "triage in one click even without an API key.")
    parser.add_argument("--scan-webroots", action="store_true",
                        help="Scan common webroot directories for web-shell content "
                             "signatures (Weevely, China Chopper, eval/base64 patterns "
                             "for PHP/ASP/JSP). Bounded; ~1s on typical hosts.")
    parser.add_argument("--webroots", default=None,
                        help="Comma-separated list of webroot directories to scan (overrides "
                             "the bundled DEFAULT_WEBROOTS list when --scan-webroots is set).")
    parser.add_argument("--json", default=None, nargs="?", const="__AUTO__",
                        metavar="PATH",
                        help="Write machine-readable JSON output. Pass --json with no value "
                             "to auto-generate ./reports/netmon-<TS>.json. Includes every "
                             "connection field plus log findings, persistence, webshell "
                             "results. Suitable for SIEM ingestion.")
    parser.add_argument("--ndjson", default=None, nargs="?", const="__AUTO__",
                        metavar="PATH",
                        help="Write newline-delimited JSON (one object per connection per "
                             "line). Suitable for streaming into Splunk / ELK / Loki.")
    parser.add_argument("--diff", default=None, nargs=2,
                        metavar=("OLD.json", "NEW.json"),
                        help="Compare two previous --json runs. Reports new flows, gone "
                             "flows, and risk-class transitions. Writes a dedicated diff "
                             "HTML report. When --diff is given, no live monitoring runs.")
    # --alert-webhook is intentionally undocumented (help=SUPPRESS). It POSTs
    # a JSON summary of HIGH findings to the URL — useful for SIEM ingest
    # or operator alerting, but kept off the --help surface to avoid
    # encouraging casual users to ship findings off-host. Anyone reviewing
    # the source can still use it via $NETMON_WEBHOOK or the CLI flag.
    parser.add_argument("--alert-webhook", default=os.environ.get("NETMON_WEBHOOK"),
                        metavar="URL", help=argparse.SUPPRESS)
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="Increase logging verbosity (-v info, -vv debug)")
    return parser


def _apply_triage_defaults(args, console):
    """Apply --quick-triage / --deep-triage implied defaults onto args.

    Only fills fields that are STILL at their argparse default — so explicit
    flags the operator also passed (e.g. -t 240, --logs 10) win over the preset.
    Returns the (possibly mutated) args.

    QUICK (default; safe for a possibly-compromised host) — a complete LOCAL
    sweep that makes no chatty/identifying outbound calls:
        -t 60, --capture, --yes, --persistence, --hash-tasks, --scan-webroots,
        --logs 3.  No Tor fetch, no external threat-intel, no VirusTotal API.

    DEEP — everything QUICK does, a longer window, plus opt-in external
    intelligence on a trusted host:
        -t 120, --scan-tor, --threat-intel (+ VirusTotal if $VT_API_KEY set).
    """
    quick = getattr(args, "quick_triage", False)
    deep = getattr(args, "deep_triage", False)
    if not quick and not deep:
        return args
    mode = "deep" if deep else "quick"
    activated = []
    # Longer default window than a bare run (the old preset's 30 s was too short
    # for beacon detection, which needs >= 4 timed attempts). Deep waits longer.
    default_time = 120 if deep else 60
    if args.time == 15:  # 15 == argparse default == "still default"
        args.time = default_time
        activated.append(f"-t {default_time}")
    # Local capture (+ auto-confirm), persistence, hash-tasks, webroots, logs.
    if args.capture is None and not getattr(args, "capture_fly", False) \
            and getattr(args, "save_capture", None) is None:
        args.capture = "__AUTO__"
        activated.append("--capture --yes")
    args.yes = True
    if not args.persistence:
        args.persistence = True
        activated.append("--persistence")
    if not args.hash_tasks:
        args.hash_tasks = True
        activated.append("--hash-tasks")
    if not args.scan_webroots:
        args.scan_webroots = True
        activated.append("--scan-webroots")
    if args.logs is None:
        args.logs = 3
        activated.append("--logs 3")
    # Threat-intel C2 feed (abuse.ch Feodo) — a SINGLE trusted host, so it is
    # acceptable even in QUICK mode (the common case). Honors --offline.
    if not getattr(args, "threat_intel", False):
        args.threat_intel = True
        activated.append("--threat-intel")
    # DEEP-only: Tor-exit detection (torproject.org is widely SNI-filtered and
    # sensitive to reach from a monitored host) plus VirusTotal lookups. QUICK
    # stays Tor-free and makes no VirusTotal API calls.
    if deep and not getattr(args, "scan_tor", False):
        args.scan_tor = True
        activated.append("--scan-tor")
    console.print(f"[bold cyan]--{mode}-triage active.[/bold cyan] "
                  "Activated: " + ", ".join(activated))
    # Tell the operator what IS and is NOT armed, so a clean run is never
    # mistaken for "nothing to find" (the most dangerous failure for a triage
    # tool). See also the report's coverage notes.
    geo = "GeoIP via ipwho.is" + (" (disabled: --offline)" if args.offline else "")
    if deep:
        vt_state = "ON ($VT_API_KEY set)" if args.vt_api_key else "no API key (link-level only)"
        console.print(f"[dim]External intel ARMED: abuse.ch C2 feed, Tor exits, "
                      f"VirusTotal {vt_state}. {geo}.[/dim]")
    else:
        console.print(f"[dim]Armed: abuse.ch C2 feed (one trusted host), {geo}. "
                      "NOT armed: Tor fetch, VirusTotal API calls (SHA-256s still link "
                      "to VirusTotal). Run --deep-triage on a trusted host for Tor + VT.[/dim]")
    return args


def _resolve_default_paths(args, console):
    """Auto-create the project's reports/ dir and resolve default paths.

    Best-practice layout: every artifact from a single run shares the same
    timestamp basename (e.g. netmon-20260502-154533.{csv,html,pcap}) so the
    HTML report links to its OWN pcap, never a stale one from a prior run.

    Tries `./reports/` first; falls back to the system tempdir if the project
    directory is not writable. Sets mode 0700 on the directory on POSIX so
    other local users can't read your captures.

    v1.3 (T2-5): merges the legacy --save-capture into --capture. --capture
    now both captures AND saves by default; --capture-fly is the new ephemeral
    mode. Internally we normalize to:
      args.capture_path = path or None (None = no capture)
      args.capture_save = True if the pcap should be persisted
    """
    # Apply --no-html / --no-text negators before resolving paths.
    if getattr(args, "no_html", False):
        args.html = None
    if getattr(args, "no_text", False):
        args.text = None

    # Normalize the new --capture / --capture-fly / legacy --save-capture
    # triplet into a single internal pair (capture_path, capture_save).
    capture_arg = getattr(args, "capture", None)
    capture_fly = getattr(args, "capture_fly", False)
    save_capture = getattr(args, "save_capture", None)

    if capture_fly and (capture_arg is not None or save_capture is not None):
        console.print("[yellow]warning:[/yellow] --capture-fly was passed alongside "
                      "--capture/--save-capture; --capture-fly wins (no pcap will be saved).")
    if save_capture is not None and capture_arg is None and not capture_fly:
        console.print("[dim]note: --save-capture is a deprecated alias for --capture "
                      "(unchanged behavior). It will be removed in v2.0.[/dim]")
        capture_arg = save_capture

    needs_default_dir = (
        args.output == "__AUTO__"
        or args.html == "__AUTO__"
        or getattr(args, "text", None) == "__AUTO__"
        or capture_arg == "__AUTO__"
        or getattr(args, "json", None) == "__AUTO__"
        or getattr(args, "ndjson", None) == "__AUTO__"
    )
    output_dir = None
    if needs_default_dir:
        candidates = [
            Path.cwd() / "reports",
            Path(tempfile.gettempdir()) / "netmon-reports",
        ]
        for candidate in candidates:
            try:
                candidate.mkdir(exist_ok=True)
                if hasattr(os, "chmod"):
                    try:
                        os.chmod(candidate, 0o700)
                    except OSError:
                        pass
                # Confirm we can actually write here.
                probe = candidate / ".netmon_write_probe"
                probe.touch()
                probe.unlink()
                output_dir = candidate
                break
            except OSError as e:
                log.debug("output dir candidate %s rejected: %s", candidate, e)
                continue
        if output_dir is None:
            console.print("[yellow]warning:[/yellow] could not create writable reports/ "
                          "directory; falling back to current working directory.")
            output_dir = Path.cwd()
        elif output_dir != candidates[0]:
            console.print(f"[yellow]note:[/yellow] project directory not writable; "
                          f"using {output_dir} for outputs.")

    # Single timestamp shared across all artifacts of this run.
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    if args.output == "__AUTO__":
        args.output = str(output_dir / f"netmon-{ts}.csv")
    if args.html == "__AUTO__":
        args.html = str(output_dir / f"netmon-{ts}.html")
    if getattr(args, "text", None) == "__AUTO__":
        args.text = str(output_dir / f"netmon-{ts}.txt")
    if getattr(args, "json", None) == "__AUTO__":
        args.json = str(output_dir / f"netmon-{ts}.json")
    if getattr(args, "ndjson", None) == "__AUTO__":
        args.ndjson = str(output_dir / f"netmon-{ts}.ndjson")
    # Normalize --webroots into a list for the scanner
    raw_webroots = getattr(args, "webroots", None)
    if raw_webroots:
        args.webroots = [p.strip() for p in raw_webroots.split(",") if p.strip()]

    # Resolve the capture path and the save flag in one pass. After this:
    #   args.capture_path → resolved pcap path (or None if no capture)
    #   args.capture_save → True if pcap should be persisted
    if capture_fly:
        args.capture_path = None  # we still capture, but to a temp dir only
        args.capture_save = False
        # Keep the public flag set so SecurityMonitor knows capture is on
        args.capture = "__FLY__"
    elif capture_arg == "__AUTO__":
        args.capture_path = str(output_dir / f"netmon-{ts}.pcap")
        args.capture_save = True
        args.capture = args.capture_path
    elif capture_arg:
        args.capture_path = capture_arg
        args.capture_save = True
        args.capture = capture_arg
    else:
        args.capture_path = None
        args.capture_save = False
        args.capture = None
    # Back-compat: keep save_capture populated when a save IS happening, so
    # any external code reading args.save_capture sees the same value as v1.2.
    if args.capture_save:
        args.save_capture = args.capture_path
    else:
        args.save_capture = None
    return args


def _confirm_save_capture(path, console, auto_yes):
    """Show disk-usage warning for --save-capture and require explicit yes."""
    console.print(
        "\n[bold yellow]WARNING — packet capture saving enabled[/bold yellow]\n"
        f"  Destination: [cyan]{path}[/cyan]\n"
        "  Captures can grow large (tens to hundreds of MB depending on duration\n"
        "  and traffic volume). The saved file will contain raw packet data —\n"
        "  treat it as sensitive and store it accordingly.\n"
    )
    if auto_yes:
        console.print("  [dim]--yes given; proceeding.[/dim]\n")
        return True
    try:
        answer = input("  Continue and save the capture? Type 'yes' to confirm: ").strip().lower()
    except EOFError:
        return False
    if answer != "yes":
        console.print("  [yellow]Aborted by user. Capture will not be saved.[/yellow]\n")
        return False
    return True


def _validate_args(args, console):
    if args.time < 1 or args.time > 86400:
        console.print("[bold red]error:[/bold red] --time must be between 1 and 86400 seconds")
        return EXIT_USAGE
    for path_attr in ("output", "html", "capture_path"):
        p = getattr(args, path_attr, None)
        if p:
            try:
                parent = Path(p).resolve().parent
                if not parent.exists():
                    console.print(f"[bold red]error:[/bold red] --{path_attr.replace('_', '-')} "
                                  f"parent directory does not exist: {parent}")
                    return EXIT_USAGE
            except (OSError, ValueError) as e:
                console.print(f"[bold red]error:[/bold red] invalid --{path_attr.replace('_', '-')} "
                              f"path: {e}")
                return EXIT_USAGE
    # --capture saves by default now (T2-5); confirm before persisting.
    # --capture-fly is exempt because nothing is written to disk.
    if getattr(args, "capture_save", False) and args.capture_path:
        if not _confirm_save_capture(args.capture_path, console, args.yes):
            return EXIT_USAGE
    if args.vt_api_key and len(args.vt_api_key) < 32:
        console.print("[yellow]warning:[/yellow] --vt-api-key looks too short to be a real "
                      "VirusTotal key; lookups will likely fail.")
    return EXIT_OK


def main(argv=None):
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    # Set up logging — INFO by default, DEBUG with -vv.
    # Verbosity applies ONLY to our 'netmon' logger; third-party libraries
    # (urllib3, requests, ipwhois) stay at WARNING so -vv doesn't drown the
    # console in connection-pool chatter.
    level = logging.WARNING
    if args.verbose == 1:
        level = logging.INFO
    elif args.verbose >= 2:
        level = logging.DEBUG
    logging.basicConfig(
        level=logging.WARNING,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    log.setLevel(level)

    console = Console()

    # v1.3 F-6.3: --diff old.json new.json — short-circuit; no live monitoring.
    if getattr(args, "diff", None):
        return _run_diff_mode(args, console)

    # Convenience presets: --quick-triage / --tr (safe, local-only) and
    # --deep-triage / --dtr (adds Tor + abuse.ch C2 feed + VT). Applied BEFORE
    # _resolve_default_paths so the auto-path machinery resolves capture/log/etc.
    # paths properly.
    args = _apply_triage_defaults(args, console)

    # Resolve auto paths (--output / --html / --save-capture / --json) into
    # timestamped filenames inside ./reports/ so reruns don't overwrite each
    # other and the HTML report links to its own pcap.
    args = _resolve_default_paths(args, console)

    rc = _validate_args(args, console)
    if rc != EXIT_OK:
        return rc

    # Warn about insecure ways of passing the VT key (process listing leak).
    if args.vt_api_key and "--vt-api-key" in (sys.argv[1:] or []):
        console.print("[yellow]warning:[/yellow] passing --vt-api-key on the command line "
                      "exposes the key via process listings; prefer the $VT_API_KEY env var.")

    if not is_admin():
        console.print("[yellow]WARNING: not running as Administrator/root.[/yellow] "
                      "System processes will show as 'Access Denied'; packet capture "
                      "and signature checks may be limited.")
        if args.capture:
            console.print("[yellow]--capture requested but you are not elevated. "
                          "pktmon/tcpdump will likely fail to start.[/yellow]")
        time.sleep(1)

    _install_signal_handlers()

    monitor = SecurityMonitor(args, console)
    try:
        history = monitor.monitor()
    except KeyboardInterrupt:
        console.print("[yellow]Aborted by user.[/yellow]")
        return EXIT_INTERRUPT

    display_terminal(history, console, monitor.flow)
    if args.html:
        render_html(
            history, args, monitor.flow, args.html, console,
            dns_findings=getattr(monitor, "dns_findings", None),
            saved_pcap_path=getattr(monitor, "saved_pcap_path", None),
            log_findings=getattr(monitor, "log_findings", None),
            persistence_findings=getattr(monitor, "persistence_findings", None),
            webshell_findings=getattr(monitor, "webshell_findings", None),
            log_sources_skipped=getattr(monitor, "log_sources_skipped", None),
        )
    if getattr(args, "text", None):
        export_text(
            history, args.text, console,
            args=args, flow=monitor.flow,
            dns_findings=getattr(monitor, "dns_findings", None),
            saved_pcap_path=getattr(monitor, "saved_pcap_path", None),
        )
    if args.output:
        export_csv(history, args.output, console)
    if getattr(args, "json", None):
        export_json(history, monitor, args.json, console)
    if getattr(args, "ndjson", None):
        export_ndjson(history, args.ndjson, console)

    # v1.3 F-9.1: webhook alert (HIGH findings only). Failure never blocks.
    if getattr(args, "alert_webhook", None):
        send_webhook_alerts(
            args.alert_webhook,
            history,
            log_findings=getattr(monitor, "log_findings", None),
            persistence=getattr(monitor, "persistence_findings", None),
            webshell=getattr(monitor, "webshell_findings", None),
            console=console,
        )

    # Final summary — show every artifact location so the operator can find
    # the run's outputs without reading scrollback.
    written = []
    if args.html:
        written.append(("HTML", args.html))
    if getattr(args, "text", None):
        written.append(("TEXT", args.text))
    if args.output:
        written.append(("CSV", args.output))
    if getattr(args, "json", None):
        written.append(("JSON", args.json))
    if getattr(args, "ndjson", None):
        written.append(("NDJSON", args.ndjson))
    if monitor.saved_pcap_path:
        written.append(("PCAP", monitor.saved_pcap_path))
    if written:
        console.print("\n[bold]Artifacts written:[/bold]")
        for label, path in written:
            console.print(f"  [cyan]{label:>6}[/cyan]  {path}")

    return EXIT_OK


def _run_diff_mode(args, console):
    """Diff two prior --json runs and write an HTML diff report.
    Returns EXIT_OK on success or EXIT_USAGE on file errors."""
    old_path, new_path = args.diff
    try:
        old = load_run_json(old_path)
        new = load_run_json(new_path)
    except (OSError, json.JSONDecodeError) as e:
        console.print(f"[bold red]diff: failed to load input(s):[/bold red] {e}")
        return EXIT_USAGE
    result = compute_diff(old, new)
    out_path = args.html if args.html and args.html != "__AUTO__" else None
    if not out_path:
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        out_path = str(Path.cwd() / "reports" / f"netmon-diff-{ts}.html")
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    render_diff_html(result, old, new, out_path, console)
    console.print(f"[bold green]Diff report:[/bold green] {out_path}")
    console.print(f"  new flows: {len(result['new_flows'])}")
    console.print(f"  gone flows: {len(result['gone_flows'])}")
    console.print(f"  risk transitions: {len(result['risk_transitions'])}")
    return EXIT_OK


def render_diff_html(result, old, new, out_path, console):
    """Minimal self-contained diff HTML — reuses the main theme's CSS variables."""
    def _risk_span(v):
        # v1.4 (S1): risk/from/to come from an UNVALIDATED --diff JSON file.
        # Whitelist the CSS class and escape the text, or a planted report file
        # yields stored XSS when the analyst opens the diff HTML.
        v = v if v in ("CRITICAL", "HIGH", "MED", "LOW", "INFO") else "LOW"
        return f"<span class='risk {v}'>{html_mod.escape(v)}</span>"

    def _rows(items, kind):
        out = []
        for r in items[:500]:
            if kind == "transition":
                row = r["row"]
                out.append(
                    f"<tr><td>{html_mod.escape(row.get('app') or '')}</td>"
                    f"<td>{row.get('pid') or ''}</td>"
                    f"<td>{html_mod.escape(row.get('local') or '')}</td>"
                    f"<td>{html_mod.escape(row.get('remote') or '')}</td>"
                    f"<td>{_risk_span(r['from'])} → {_risk_span(r['to'])}</td>"
                    f"<td>{html_mod.escape(', '.join(row.get('flags') or []))}</td></tr>"
                )
            else:
                out.append(
                    f"<tr><td>{html_mod.escape(r.get('app') or '')}</td>"
                    f"<td>{r.get('pid') or ''}</td>"
                    f"<td>{html_mod.escape(r.get('local') or '')}</td>"
                    f"<td>{html_mod.escape(r.get('remote') or '')}</td>"
                    f"<td>{_risk_span(r.get('risk','LOW'))}</td>"
                    f"<td>{html_mod.escape(', '.join(r.get('flags') or []))}</td></tr>"
                )
        return "".join(out)

    new_rows = _rows(result["new_flows"], "new")
    gone_rows = _rows(result["gone_flows"], "gone")
    tx_rows = _rows(result["risk_transitions"], "transition")
    html_out = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>netmon.py diff</title>
<style>
:root {{ --bg:#0e1117; --panel:#161b22; --border:#30363d; --text:#c9d1d9;
        --muted:#8b949e; --accent:#58a6ff; --red:#f85149; --orange:#d29922; --green:#3fb950; }}
body {{ background:var(--bg); color:var(--text); font:13px/1.4 ui-monospace,Consolas,monospace;
       padding:24px; margin:0; }}
h1 {{ margin:0 0 4px; font-size:20px; }}
.sub {{ color:var(--muted); margin-bottom:20px; }}
.stats {{ display:flex; gap:16px; margin-bottom:24px; }}
.stat {{ background:var(--panel); border:1px solid var(--border); border-radius:6px;
        padding:12px 16px; min-width:140px; }}
.stat .label {{ color:var(--muted); font-size:11px; text-transform:uppercase; }}
.stat .val   {{ font-size:24px; font-weight:600; margin-top:4px; }}
details {{ margin-top:16px; }}
table {{ width:100%; border-collapse:collapse; background:var(--panel);
         border:1px solid var(--border); border-radius:6px; overflow:hidden; }}
th, td {{ padding:8px 10px; text-align:left; border-bottom:1px solid var(--border); }}
th {{ background:#1c2128; color:var(--muted); font-size:12px; }}
.risk {{ padding:2px 8px; border-radius:4px; font-weight:600; font-size:11px; color:#fff; }}
.risk.CRITICAL {{ background:#d6409f; }}
.risk.HIGH {{ background:var(--red); }}
.risk.MED  {{ background:var(--orange); }}
.risk.LOW  {{ background:var(--green); }}
</style></head>
<body>
<h1>netmon.py — diff report</h1>
<div class="sub">old: {html_mod.escape(old.get('generated',''))} · new: {html_mod.escape(new.get('generated',''))}</div>

<div class="stats">
  <div class="stat"><div class="label">New flows</div><div class="val" style="color:var(--red)">{len(result['new_flows'])}</div></div>
  <div class="stat"><div class="label">Gone flows</div><div class="val" style="color:var(--green)">{len(result['gone_flows'])}</div></div>
  <div class="stat"><div class="label">Risk transitions</div><div class="val" style="color:var(--orange)">{len(result['risk_transitions'])}</div></div>
</div>

<details open><summary>New flows ({len(result['new_flows'])})</summary>
<table><thead><tr><th>Process</th><th>PID</th><th>Local</th><th>Remote</th><th>Risk</th><th>Flags</th></tr></thead>
<tbody>{new_rows}</tbody></table></details>

<details><summary>Gone flows ({len(result['gone_flows'])})</summary>
<table><thead><tr><th>Process</th><th>PID</th><th>Local</th><th>Remote</th><th>Risk</th><th>Flags</th></tr></thead>
<tbody>{gone_rows}</tbody></table></details>

<details open><summary>Risk transitions ({len(result['risk_transitions'])})</summary>
<table><thead><tr><th>Process</th><th>PID</th><th>Local</th><th>Remote</th><th>Risk</th><th>Flags</th></tr></thead>
<tbody>{tx_rows}</tbody></table></details>

</body></html>
"""
    Path(out_path).write_text(html_out, encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
