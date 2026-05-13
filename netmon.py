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
from datetime import datetime
from pathlib import Path
from typing import ClassVar

import psutil
import requests
from rich import box
from rich.console import Console
from rich.markup import escape as rich_escape
from rich.table import Table

try:
    from ipwhois import IPWhois
    HAS_IPWHOIS = True
except ImportError:
    HAS_IPWHOIS = False


VERSION = "1.2.0"

log = logging.getLogger("netmon")

# === Hard limits — defend against malicious / oversized input ===

MAX_PCAP_BYTES = 256 * 1024 * 1024       # never process > 256 MB of pcap
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
    3333:  "Common cryptominer pool",
    5555:  "ADB / Android Debug Bridge",
    6667:  "IRC (legacy C2)",
    6668:  "IRC (legacy C2)",
    9001:  "Tor relay (ORPort)",
    9050:  "Tor SOCKS",
    9999:  "Common reverse-shell port",
    8333:  "Bitcoin core",
}

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
                # body[0:4] is byte-order magic; we assume little-endian.
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
        self.sni_by_peer = defaultdict(set)    # remote_ip -> {sni, sni}
        self.bytes_per_peer = Counter()        # remote_ip -> total bytes
        self.packets_per_peer = Counter()
        self.errors = 0

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

    def _handle_ipv6(self, ts, ip):
        if len(ip) < 40:
            return
        proto = ip[6]
        src_ip = socket.inet_ntop(socket.AF_INET6, ip[8:24])
        dst_ip = socket.inet_ntop(socket.AF_INET6, ip[24:40])
        payload = ip[40:]
        self._handle_l4(ts, src_ip, dst_ip, proto, payload)

    def _handle_l4(self, ts, src_ip, dst_ip, proto, payload):
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
        return {
            "dns_query_count": len(self.dns_queries),
            "unique_dns_names": len({q[0] for q in self.dns_queries}),
            "sni_peer_count": len(self.sni_by_peer),
            "unique_sni_names": len({s for v in self.sni_by_peer.values() for s in v}),
            "tracked_peer_count": len(self.bytes_per_peer),
            "parse_errors": self.errors,
        }


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

    def __init__(self, queries):
        # queries: list of (qname, qtype, ts) from FlowAnalyzer
        self.queries = list(queries) if queries else []
        self.query_counts = Counter(q[0] for q in self.queries if q and q[0])
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
        # Signal 1: classic high-entropy random-character DGA.
        if cls._shannon_entropy(lower) >= DNS_DGA_ENTROPY_THRESHOLD:
            return True
        # Signal 2: long label with very few vowels — typical of keyboard-mash
        # ("dkjlfhlkdjfghlkdfjh") OR of consonant-DGA families. Real domain
        # words almost always exceed 15% vowels.
        vowel_count = sum(1 for c in lower if c in "aeiou")
        if len(lower) >= 12 and vowel_count / len(lower) < 0.15:
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

        # 4. High retry count (typical of beacon DGA on NXDOMAIN)
        cnt = self.query_counts[qname]
        if cnt >= DNS_HIGH_RETRY_THRESHOLD:
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
                subprocess.run(["pktmon", "filter", "remove"], capture_output=True, timeout=10, check=False)
                for port in (53, 80, 443):
                    subprocess.run(
                        ["pktmon", "filter", "add", "-t", "TCP", "UDP", "-p", str(port)],
                        capture_output=True, timeout=10, check=False,
                    )
                subprocess.run(
                    ["pktmon", "start", "--capture", "--file", self._etl_path,
                     "--pkt-size", "512", "--file-size", "256"],
                    capture_output=True, text=True, timeout=15, check=False,
                )
                return True
            except (OSError, subprocess.SubprocessError) as e:
                log.warning("pktmon start failed: %s", e)
                self.console.print(f"[yellow]Capture start failed:[/yellow] {e}")
                return False
        if self.tool == "tcpdump":
            self.capture_path = os.path.join(tmp, "capture.pcap")
            cmd = [
                "tcpdump", "-i", "any", "-w", self.capture_path,
                "-G", str(self.duration), "-W", "1", "-s", "512", "-q", "-nn",
                "(port 80 or port 443 or port 53)",
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
                trusted = signed and any(
                    tp.lower() in (publisher or "").lower() for tp in TRUSTED_PUBLISHERS
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


# === Threat intel: Tor exits, ipwhois enrichment ===

def _safe_cache_dir():
    """Return a per-user cache dir with mode 0700 (best effort).

    On a multi-user host, /tmp is world-writable; another local user could
    pre-create our cache dir and seed it with poisoned files. We use a
    user-specific subdirectory under the tempdir and chmod to 0700 on POSIX.
    """
    base = Path(tempfile.gettempdir()) / f"netmon_cache_{os.getuid() if hasattr(os, 'getuid') else os.getlogin()}"
    base.mkdir(exist_ok=True)
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
    def __init__(self, offline=False, scan_tor=False, console=None):
        self.offline = offline
        self.scan_tor = scan_tor
        self.console = console
        self.tor_exits = set()
        self._whois_cache = {}
        self._cache_dir = _safe_cache_dir()
        # Tor exit-list fetch is now OPT-IN (--scan-tor). v1.1 made it default-on
        # and many networks SNI-filter torproject.org, producing a noisy warning
        # on every run. Users who want Tor-exit detection can pass --scan-tor.
        if not offline and scan_tor:
            self._load_tor_exits()

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
        self.cache[sha256] = None
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
        self.ip_cache = {}
        self.file_hash_cache = {}
        self.headers = {"User-Agent": f"netmon.py/{VERSION}"}
        self.signing = SignatureChecker(enabled=not args.no_signing)
        self.threat = ThreatIntel(
            offline=args.offline,
            scan_tor=getattr(args, "scan_tor", False),
            console=console,
        )
        self.vt = VirusTotalClient(args.vt_api_key, console=console) if args.vt_api_key else None
        self.flow = None
        self.capture = None
        self.dns_findings = []
        self.saved_pcap_path = None

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
        path_lower = (conn["path"] or "").lower().replace("/", "\\")
        app_lower = (conn["app"] or "").lower()

        # 1. Hard suspicious paths (Temp, Public, Recycle Bin, /tmp)
        if any(frag in path_lower for frag in (s.lower() for s in HIGH_RISK_PATH_FRAGMENTS)):
            score += 3
            flags.append("HIGH_RISK_PATH")

        # 2. System binary in wrong location (e.g. svchost.exe outside System32)
        expected = SYSTEM_BINARY_LOCATIONS.get(app_lower)
        if expected and path_lower and path_lower not in ("n/a", "access denied") \
                and not any(loc in path_lower for loc in expected):
            score += 5  # always HIGH — impostors are critical
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

        # 5. Soft path + unsigned binary = MED bump
        sig = conn.get("signature") or {}
        is_signed_trusted = sig.get("trusted", False)
        is_signed = sig.get("signed", False)

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

        # 6. Unsigned binary with network activity. Score bumped from +1 to +2
        # because an unsigned executable making outbound network calls is a
        # primary C2 indicator. v1.1 under-weighted this and missed real C2.
        if conn["path"] and conn["path"] not in ("N/A", "Access Denied") and ip and not is_signed:
            score += 2
            flags.append("UNSIGNED_BINARY")

        # 6b. UNSIGNED_OUTBOUND_C2: unsigned binary + ESTABLISHED connection +
        # public destination IP. This is the textbook C2 fingerprint and
        # should reach HIGH on its own. Combined with UNSIGNED_BINARY (+2)
        # the score lands at HIGH (≥5) without requiring suspicious-path /
        # suspicious-port / Tor-exit signals to also fire.
        status = (conn.get("status") or "").upper()
        if (conn["path"] and conn["path"] not in ("N/A", "Access Denied")
                and ip and not is_signed
                and status == "ESTABLISHED"
                and classify_local_ip(ip) is None):
            score += 3
            flags.append("UNSIGNED_OUTBOUND_C2")

        # 7. VT malicious hits
        vt = conn.get("vt")
        if vt and vt.get("found"):
            mal = vt.get("malicious", 0)
            if mal >= 5:
                score += 5
                flags.append(f"VT_MALICIOUS_{mal}")
            elif mal >= 1:
                score += 2
                flags.append(f"VT_MALICIOUS_{mal}")
            elif vt.get("suspicious", 0) >= 1:
                score += 1
                flags.append("VT_SUSPICIOUS")

        # 8. Beaconing (filled in later, after history accumulated)

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
    def get_connections(self):
        connections = []
        for conn in psutil.net_connections(kind="inet"):
            try:
                local_addr = self._fmt_addr(conn.laddr)
                remote_addr = self._fmt_addr(conn.raddr)
                pid = conn.pid
                app_name, exe_path, username, file_hash = "Unknown", "N/A", "N/A", "N/A"
                if pid:
                    try:
                        proc = psutil.Process(pid)
                        app_name = proc.name()
                        exe_path = proc.exe()
                        username = proc.username()
                        file_hash = self.get_file_hash(exe_path)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        app_name = "System/Protected"
                        exe_path = "Access Denied"

                ip = self._remote_ip(remote_addr)
                ip_info = self.get_ip_details(ip) if ip else {
                    "country": "N/A", "country_code": "", "org": "N/A", "hostname": "N/A",
                    "asn": None, "is_tor": False, "is_private": False,
                }
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

        try:
            while (datetime.now() - start).total_seconds() < self.args.time:
                now = time.time()
                for conn in self.get_connections():
                    # Bound per-run state to prevent unbounded growth on long runs
                    # or noisy hosts. New entries past the cap are silently dropped.
                    if len(self.conn_history) >= MAX_CONN_HISTORY:
                        log.warning("conn_history cap reached (%d); dropping new entries",
                                    MAX_CONN_HISTORY)
                        break
                    key = (conn["pid"], conn["remote"]) if conn["remote"] else (conn["pid"], conn["local"], "L")
                    self.conn_history[key] = conn
                    if len(self.first_seen) < MAX_FIRST_SEEN:
                        fs_key = (conn["pid"], conn["local"], conn["remote"])
                        self.first_seen.setdefault(fs_key, now)
                time.sleep(1)
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
                # Persist the pcap to the user's location if --save-capture was given.
                if self.args.save_capture:
                    try:
                        dest = Path(self.args.save_capture).resolve()
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
            analyzer = DNSAnalyzer(self.flow.dns_queries)
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

        # Batch signature verification (one PowerShell call) and VT lookups
        self.console.print("[dim]Verifying code signatures...[/dim]")
        all_paths = [c["path"] for c in self.conn_history.values()]
        self.signing.batch_check(all_paths)
        for conn in self.conn_history.values():
            conn["signature"] = self.signing.get(conn["path"])
            if self.vt:
                conn["vt"] = self.vt.lookup_hash(conn["hash"])

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
        for key, info in beacons.items():
            if key in self.conn_history:
                conn = self.conn_history[key]
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


# === Reporters ===

CSV_FIELDS = [
    "timestamp", "pid", "app", "user", "path", "hash",
    "local", "remote", "status",
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

    risk_order = {"HIGH": 0, "MED": 1, "LOW": 2}
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

    risk_order = {"HIGH": 0, "MED": 1, "LOW": 2}
    for c in sorted(conn_history.values(), key=lambda x: (risk_order.get(x["risk"], 9), x["app"])):
        risk_color = {"HIGH": "red", "MED": "yellow", "LOW": "green"}[c["risk"]]
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
  .risk { display: inline-block; padding: 2px 8px; border-radius: 4px; font-weight: 600; font-size: 11px; }
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
  /* Remote cell is the 6th td: Risk, Process, PID, Signed, Local, Remote, ... */
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
  .dns-flag { display: inline-block; background: rgba(248, 81, 73, 0.15); color: var(--red); padding: 1px 6px; border-radius: 3px; font-size: 10px; margin-right: 4px; }
  .pcap-link { display: inline-block; background: var(--accent); color: #fff; padding: 6px 12px; border-radius: 4px; text-decoration: none; font-weight: 600; }
  .pcap-link:hover { opacity: 0.9; }
  .log-table { font-size: 11px; }
  .log-table td { padding: 4px 8px; word-break: break-all; }
</style>
</head>
<body class="$body_class">
<h1>netmon.py Report</h1>
<div class="sub">Generated $generated &middot; Duration ${duration}s &middot; Captured $conn_count unique connections &middot; Host: $host_os</div>

<div class="stats">
  <div class="stat" data-filter="HIGH" title="Click to filter to HIGH-risk rows"><div class="label">High risk</div><div class="val" style="color: var(--red)">$high</div></div>
  <div class="stat" data-filter="MED" title="Click to filter to MED-risk rows"><div class="label">Medium risk</div><div class="val" style="color: var(--orange)">$med</div></div>
  <div class="stat" data-filter="LOW" title="Click to filter to LOW-risk rows"><div class="label">Low risk</div><div class="val" style="color: var(--green)">$low</div></div>
  <div class="stat" data-filter="dedupe-process" title="Click to show one representative row per unique process name"><div class="label">Unique processes</div><div class="val">$procs</div></div>
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
  <button class="filter-btn" data-risk="HIGH">High</button>
  <button class="filter-btn" data-risk="MED">Medium</button>
  <button class="filter-btn" data-risk="LOW">Low</button>
  $noise_toggle
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

<table id="conntable">
<thead>
<tr>
  <th data-sort="risk">Risk</th>
  <th data-sort="app">Process</th>
  <th data-sort="pid">PID</th>
  <th data-sort="sig">Signed</th>
  <th data-sort="local">Local</th>
  <th data-sort="remote">Remote</th>
  <th data-sort="geo">Geo / Org</th>
  <th data-sort="path">Path / Hash</th>
  <th data-sort="vt">VT</th>
  <th data-sort="flags">Flags</th>
</tr>
</thead>
<tbody>
$rows
</tbody>
</table>

$dns_section
$capture_section
$packet_log_section

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
  const statTiles = document.querySelectorAll('.stat[data-filter]');
  const pcapTables = document.querySelectorAll('.log-table tbody');

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
    return key === 'HIGH' || key === 'MED' || key === 'LOW';
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
    rows.forEach(r => {
      const matchesText = !q || r.textContent.toLowerCase().includes(q);
      const matchesRisk = activeRisk === 'all' || r.classList.contains(activeRisk);
      const matchesStatus = activeStatus === 'all' || r.classList.contains(activeStatus);
      let matchesCats = true;
      activeCategories.forEach(cat => {
        if (cat === 'dedupe-process') return;
        if (!r.classList.contains(cat)) matchesCats = false;
      });
      let visible = matchesText && matchesRisk && matchesStatus && matchesCats;
      if (visible && dedupeProcess) {
        const proc = (r.cells[1].textContent || '').trim();
        if (seenProc.has(proc)) visible = false;
        else seenProc.add(proc);
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
      const proc2 = (rr.cells[1].textContent || '').trim();
      if (proc2 === proc) {
        const local = (rr.cells[4].textContent || '').trim();
        const colon = local.lastIndexOf(':');
        if (colon >= 0) {
          const port = local.slice(colon + 1).replace(/[^0-9]/g, '');
          if (port) selectedProcessPorts.add(port);
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
    const proc = (r.cells[1].textContent || '').trim();
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
    const procCell = r.cells[1];
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

  document.querySelectorAll('th[data-sort]').forEach((th, idx) => {
    let asc = true;
    th.addEventListener('click', () => {
      const sorted = rows.slice().sort((a, b) => {
        const av = a.cells[idx].getAttribute('data-sort') || a.cells[idx].textContent;
        const bv = b.cells[idx].getAttribute('data-sort') || b.cells[idx].textContent;
        const an = parseFloat(av), bn = parseFloat(bv);
        if (!isNaN(an) && !isNaN(bn)) return asc ? an - bn : bn - an;
        return asc ? av.localeCompare(bv) : bv.localeCompare(av);
      });
      asc = !asc;
      sorted.forEach(r => tbody.appendChild(r));
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

  // Apply initial filter — Status defaults to Established for the most useful
  // triage view; "All" or any other status button opens it up.
  applyFilters();
})();
</script>
</body>
</html>
""")


def _is_noisy_microsoft_or_system(conn):
    """Return True for trusted-Microsoft binaries and unprivileged System
    placeholders. These rows are hidden by default in the HTML report on
    Windows runs to reduce visual noise; a checkbox toggles them."""
    app = (conn.get("app") or "").lower()
    sig = conn.get("signature") or {}
    publisher = (sig.get("publisher") or "").lower()
    if app in ("system", "system/protected", "unknown"):
        return True
    if sig.get("trusted") and "microsoft" in publisher:
        return True
    return False


def render_html(conn_history, args, flow, output_path, console,
                dns_findings=None, saved_pcap_path=None):
    rows_html = []
    risk_order = {"HIGH": 0, "MED": 1, "LOW": 2}
    sorted_conns = sorted(conn_history.values(), key=lambda x: (risk_order.get(x["risk"], 9), x["app"]))
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

        rows_html.append(
            f'<tr class="{row_classes}">'
            f'<td><span class="risk {c["risk"]}">{c["risk"]}</span></td>'
            f'<td><span class="proc-link">{html_mod.escape(c["app"] or "")}</span></td>'
            f'<td>{c["pid"] or ""}</td>'
            f'<td class="sig {sig_class}">{html_mod.escape(sig_text)}</td>'
            f'<td class="local">{local_html}</td>'
            f'<td>{remote_html}</td>'
            f'<td>{geo}</td>'
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
        capture_section = f"""
<details open>
<summary>Packet capture summary ({s['unique_dns_names']} DNS names, {s['unique_sni_names']} TLS hosts)</summary>
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
        dns_section = f"""
<details open>
<summary>Suspicious DNS findings ({len(dns_findings)} flagged names)</summary>
<table>
  <thead><tr><th>Domain</th><th>Queries</th><th>Flags</th></tr></thead>
  <tbody>{dns_rows_html}</tbody>
</table>
</details>
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

    html_out = HTML_TEMPLATE.substitute(
        generated=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        duration=args.time,
        conn_count=len(conn_history),
        high=high, med=med, low=low,
        procs=procs, peers=peers, unsigned=unsigned, tor=tor, vt_mal=vt_mal,
        exposed_any=exposed_any, exposed_lan=exposed_lan,
        rows="\n".join(rows_html),
        capture_section=capture_section,
        dns_section=dns_section,
        packet_log_section=packet_log_section,
        noise_toggle=noise_toggle,
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
    parser.add_argument("--capture", action="store_true",
                        help="Also capture packets via pktmon (Windows) / tcpdump (Linux). Requires admin/root.")
    parser.add_argument("--save-capture", default=None, nargs="?", const="__AUTO__",
                        metavar="PATH",
                        help="Save the raw pcap AND embed a browsable packet log "
                             "(DNS queries, TLS handshakes, TCP flows) in the HTML report. "
                             "Implies --capture. PATH is optional — bare --save-capture "
                             "auto-generates 'netmon-capture-<YYYYMMDD-HHMMSS>.pcap' in the "
                             "current directory. WARNING: pcaps can be large (tens-hundreds "
                             "of MB); you'll be prompted to confirm unless --yes is given.")
    parser.add_argument("--yes", action="store_true",
                        help="Auto-confirm prompts (e.g. for --save-capture disk-usage warning). "
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
                        help="Skip Authenticode signature verification")
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="Increase logging verbosity (-v info, -vv debug)")
    return parser


def _resolve_default_paths(args, console):
    """Auto-create the project's reports/ dir and resolve default paths.

    Best-practice layout: every artifact from a single run shares the same
    timestamp basename (e.g. netmon-20260502-154533.{csv,html,pcap}) so the
    HTML report links to its OWN pcap, never a stale one from a prior run.

    Tries `./reports/` first; falls back to the system tempdir if the project
    directory is not writable. Sets mode 0700 on the directory on POSIX so
    other local users can't read your captures.
    """
    # Apply --no-html / --no-text negators before resolving paths.
    if getattr(args, "no_html", False):
        args.html = None
    if getattr(args, "no_text", False):
        args.text = None
    needs_default_dir = (
        args.output == "__AUTO__"
        or args.html == "__AUTO__"
        or getattr(args, "text", None) == "__AUTO__"
        or args.save_capture == "__AUTO__"
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
    if args.save_capture == "__AUTO__":
        args.save_capture = str(output_dir / f"netmon-{ts}.pcap")
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
    for path_attr in ("output", "html", "save_capture"):
        p = getattr(args, path_attr, None)
        if p:
            try:
                parent = Path(p).resolve().parent
                if not parent.exists():
                    console.print(f"[bold red]error:[/bold red] --{path_attr.replace('_', '-')} "
                                  f"parent directory does not exist: {parent}")
                    return EXIT_USAGE
            except OSError as e:
                console.print(f"[bold red]error:[/bold red] invalid --{path_attr.replace('_', '-')} "
                              f"path: {e}")
                return EXIT_USAGE
    # --save-capture implies --capture, but only after confirmation.
    if args.save_capture:
        if not _confirm_save_capture(args.save_capture, console, args.yes):
            return EXIT_USAGE
        args.capture = True
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

    # Resolve auto paths (--output / --html / --save-capture) into timestamped
    # filenames inside ./reports/ so reruns don't overwrite each other and
    # the HTML report links to its own pcap.
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

    # Final summary — show every artifact location so the operator can find
    # the run's outputs without reading scrollback.
    written = []
    if args.html:
        written.append(("HTML", args.html))
    if getattr(args, "text", None):
        written.append(("TEXT", args.text))
    if args.output:
        written.append(("CSV", args.output))
    if monitor.saved_pcap_path:
        written.append(("PCAP", monitor.saved_pcap_path))
    if written:
        console.print("\n[bold]Artifacts written:[/bold]")
        for label, path in written:
            console.print(f"  [cyan]{label:>5}[/cyan]  {path}")

    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
