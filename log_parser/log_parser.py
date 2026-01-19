#!/usr/bin/env python3
"""
SOC & DFIR Toolkit - Log Parser
- Supports: Linux auth.log, Apache access.log (common/combined)
- Output: JSONL (default) or CSV
- Features: auto log-type detection, basic normalization, quick stats

Usage:
  python3 log_parser.py /path/to/auth.log
  python3 log_parser.py /path/to/access.log --out parsed.jsonl
  python3 log_parser.py /path/to/access.log --format csv --out parsed.csv
  python3 log_parser.py /path/to/auth.log --stats
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

# ---------------------------
# Regex patterns
# ---------------------------

# auth.log example:
# Jan 19 11:22:33 host sshd[1234]: Failed password for invalid user admin from 1.2.3.4 port 5555 ssh2
AUTH_SSHD_RE = re.compile(
    r'^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+(?P<proc>sshd)\[(?P<pid>\d+)\]:\s+'
    r'(?P<msg>.+)$'
)

AUTH_USER_IP_RE = re.compile(
    r'(?:(?:invalid user)\s+)?(?P<user>[A-Za-z0-9._-]+).*?\sfrom\s(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})'
)

AUTH_ACCEPTED_RE = re.compile(r'Accepted\s+\w+\s+for\s+(?P<user>\S+)\s+from\s+(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})')
AUTH_FAILED_RE = re.compile(r'Failed\s+\w+\s+for\s+(?:(?:invalid user)\s+)?(?P<user>\S+)\s+from\s+(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})')
AUTH_INVALID_USER_RE = re.compile(r'invalid user\s+(?P<user>\S+)\s+from\s+(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})')

# Apache access log common/combined:
# 127.0.0.1 - frank [10/Oct/2000:13:55:36 +0000] "GET /apache_pb.gif HTTP/1.0" 200 2326 "ref" "ua"
APACHE_RE = re.compile(
    r'^(?P<src_ip>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+(?P<proto>[^"]+))?"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)")?'
    r'\s*$'
)

# Log-type detection heuristics
DETECT_AUTH_HINT = re.compile(r'\bsshd\[\d+\]:')
DETECT_APACHE_HINT = re.compile(r'^\S+\s+\S+\s+\S+\s+\[[0-9]{2}/[A-Za-z]{3}/[0-9]{4}:')

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
    "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
    "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
}


@dataclass
class ParsedEvent:
    timestamp: str               # ISO8601 (best-effort)
    event_type: str              # e.g., auth_failed, auth_accepted, apache_request, unknown
    src_ip: Optional[str] = None
    user: Optional[str] = None
    host: Optional[str] = None
    process: Optional[str] = None
    pid: Optional[int] = None
    method: Optional[str] = None
    path: Optional[str] = None
    status: Optional[int] = None
    raw: Optional[str] = None
    tags: Optional[List[str]] = None


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="SOC & DFIR Toolkit - Log Parser")
    p.add_argument("logfile", help="Path to log file (auth.log or apache access.log)")
    p.add_argument("--format", choices=["jsonl", "csv"], default="jsonl", help="Output format")
    p.add_argument("--out", default="", help="Output file path (default: <input>.parsed.jsonl/csv)")
    p.add_argument("--year", type=int, default=0, help="Year override for logs without year (e.g., auth.log)")
    p.add_argument("--stats", action="store_true", help="Print quick stats summary to stderr")
    p.add_argument("--max-lines", type=int, default=0, help="Limit number of lines processed (0 = no limit)")
    return p.parse_args()


def guess_log_type(sample_lines: List[str]) -> str:
    """Return 'auth', 'apache', or 'unknown'."""
    auth_hits = sum(1 for l in sample_lines if DETECT_AUTH_HINT.search(l))
    apache_hits = sum(1 for l in sample_lines if DETECT_APACHE_HINT.search(l))
    if auth_hits > apache_hits and auth_hits > 0:
        return "auth"
    if apache_hits > auth_hits and apache_hits > 0:
        return "apache"
    # Tie-break with deeper checks
    if any(AUTH_SSHD_RE.match(l) for l in sample_lines):
        return "auth"
    if any(APACHE_RE.match(l) for l in sample_lines):
        return "apache"
    return "unknown"


def iso_from_auth(mon: str, day: str, hhmmss: str, year: int) -> str:
    m = MONTHS.get(mon, 1)
    d = int(day)
    if year <= 0:
        # Best-effort: use current year
        year = datetime.utcnow().year
    dt = datetime(year, m, d, int(hhmmss[0:2]), int(hhmmss[3:5]), int(hhmmss[6:8]))
    return dt.isoformat() + "Z"


def iso_from_apache(ts: str) -> str:
    # Example: 10/Oct/2000:13:55:36 +0000
    try:
        dt = datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z")
        return dt.astimezone().isoformat()
    except Exception:
        return ""


def parse_auth_line(line: str, year: int) -> Optional[ParsedEvent]:
    m = AUTH_SSHD_RE.match(line)
    if not m:
        return None

    mon, day, hhmmss = m.group("mon"), m.group("day"), m.group("time")
    host = m.group("host")
    proc = m.group("proc")
    pid = int(m.group("pid"))
    msg = m.group("msg")

    ts_iso = iso_from_auth(mon, day, hhmmss, year)

    # Determine event type & extract user/ip
    event_type = "auth_event"
    tags: List[str] = []

    src_ip = None
    user = None

    m_acc = AUTH_ACCEPTED_RE.search(msg)
    m_fail = AUTH_FAILED_RE.search(msg)
    m_inv = AUTH_INVALID_USER_RE.search(msg)

    if m_acc:
        event_type = "auth_accepted"
        user = m_acc.group("user")
        src_ip = m_acc.group("src_ip")
        tags.append("ssh")
        tags.append("login_success")
    elif m_fail:
        event_type = "auth_failed"
        user = m_fail.group("user")
        src_ip = m_fail.group("src_ip")
        tags.append("ssh")
        tags.append("login_failed")
    elif m_inv:
        event_type = "auth_invalid_user"
        user = m_inv.group("user")
        src_ip = m_inv.group("src_ip")
        tags.append("ssh")
        tags.append("invalid_user")
    else:
        # Fallback extraction
        uip = AUTH_USER_IP_RE.search(msg)
        if uip:
            user = uip.group("user")
            src_ip = uip.group("src_ip")

    return ParsedEvent(
        timestamp=ts_iso,
        event_type=event_type,
        src_ip=src_ip,
        user=user,
        host=host,
        process=proc,
        pid=pid,
        raw=line.rstrip("\n"),
        tags=tags or None
    )


def parse_apache_line(line: str) -> Optional[ParsedEvent]:
    m = APACHE_RE.match(line)
    if not m:
        return None

    src_ip = m.group("src_ip")
    user = m.group("user")
    if user == "-":
        user = None

    ts = m.group("ts")
    ts_iso = iso_from_apache(ts) or ""

    status = int(m.group("status"))
    method = m.group("method")
    path = m.group("path")

    tags = ["http"]
    if status >= 400:
        tags.append("http_error")
    if status == 401 or status == 403:
        tags.append("auth_related")

    return ParsedEvent(
        timestamp=ts_iso if ts_iso else ts,
        event_type="apache_request",
        src_ip=src_ip,
        user=user,
        method=method,
        path=path,
        status=status,
        raw=line.rstrip("\n"),
        tags=tags
    )


def iter_lines(path: str, max_lines: int = 0) -> Iterator[str]:
    with open(path, "r", errors="replace") as f:
        for i, line in enumerate(f, start=1):
            if max_lines and i > max_lines:
                break
            yield line


def write_jsonl(out_path: str, events: Iterable[ParsedEvent]) -> int:
    count = 0
    with open(out_path, "w", encoding="utf-8") as w:
        for ev in events:
            w.write(json.dumps(asdict(ev), ensure_ascii=False) + "\n")
            count += 1
    return count


def write_csv(out_path: str, events: Iterable[ParsedEvent]) -> int:
    count = 0
    fieldnames = [
        "timestamp", "event_type", "src_ip", "user", "host", "process", "pid",
        "method", "path", "status", "tags", "raw"
    ]
    with open(out_path, "w", newline="", encoding="utf-8") as w:
        writer = csv.DictWriter(w, fieldnames=fieldnames)
        writer.writeheader()
        for ev in events:
            d = asdict(ev)
            # flatten tags
            if isinstance(d.get("tags"), list):
                d["tags"] = ",".join(d["tags"])
            writer.writerow({k: d.get(k) for k in fieldnames})
            count += 1
    return count


def main() -> int:
    args = parse_args()
    in_path = args.logfile

    if not os.path.exists(in_path):
        print(f"[!] File not found: {in_path}", file=sys.stderr)
        return 2

    # Read small sample for detection
    sample = []
    for i, line in enumerate(iter_lines(in_path, max_lines=200), start=1):
        if line.strip():
            sample.append(line.rstrip("\n"))
        if len(sample) >= 50:
            break

    log_type = guess_log_type(sample)

    if not args.out:
        base = os.path.splitext(in_path)[0]
        args.out = f"{base}.parsed.{args.format}"

    stats: Dict[str, int] = {}
    parsed_events: List[ParsedEvent] = []

    for line in iter_lines(in_path, max_lines=args.max_lines):
        line = line.rstrip("\n")
        if not line.strip():
            continue

        ev: Optional[ParsedEvent] = None
        if log_type == "auth":
            ev = parse_auth_line(line, args.year)
        elif log_type == "apache":
            ev = parse_apache_line(line)

        if ev is None:
            # Try both as fallback
            ev = parse_auth_line(line, args.year) or parse_apache_line(line)

        if ev is None:
            ev = ParsedEvent(
                timestamp="",
                event_type="unknown",
                raw=line,
                tags=["unparsed"]
            )

        parsed_events.append(ev)
        stats[ev.event_type] = stats.get(ev.event_type, 0) + 1

    # Write output
    if args.format == "jsonl":
        n = write_jsonl(args.out, parsed_events)
    else:
        n = write_csv(args.out, parsed_events)

    print(f"[+] Parsed {n} lines -> {args.out}", file=sys.stderr)

    if args.stats:
        print("\n=== Quick Stats ===", file=sys.stderr)
        for k in sorted(stats.keys()):
            print(f"{k}: {stats[k]}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

