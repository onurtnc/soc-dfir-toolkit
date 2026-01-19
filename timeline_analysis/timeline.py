#!/usr/bin/env python3
"""
SOC & DFIR Toolkit - Timeline Analyzer
Builds a single investigation timeline from multiple sources.

Supported inputs (auto-detected best-effort):
- JSONL events (from log_parser.py output)
- JSON IOC file (from ioc_extractor.py output) (optional for marking)
- Raw Linux auth.log (sshd lines)
- Raw Apache access.log (common/combined)

Outputs:
- JSONL (default) or CSV

Usage:
  python3 timeline.py --inputs auth.log access.log
  python3 timeline.py --inputs auth.log --year 2026 --out timeline.jsonl
  python3 timeline.py --inputs auth.parsed.jsonl access.parsed.jsonl --format csv --out timeline.csv
  python3 timeline.py --inputs auth.parsed.jsonl --ioc-file suspicious.iocs.json --out timeline_marked.jsonl
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

# ---------------------------
# Regex (same spirit as log_parser)
# ---------------------------

AUTH_SSHD_RE = re.compile(
    r'^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+(?P<proc>sshd)\[(?P<pid>\d+)\]:\s+'
    r'(?P<msg>.+)$'
)

AUTH_ACCEPTED_RE = re.compile(r'Accepted\s+\w+\s+for\s+(?P<user>\S+)\s+from\s+(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})')
AUTH_FAILED_RE = re.compile(r'Failed\s+\w+\s+for\s+(?:(?:invalid user)\s+)?(?P<user>\S+)\s+from\s+(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})')
AUTH_INVALID_USER_RE = re.compile(r'invalid user\s+(?P<user>\S+)\s+from\s+(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})')

APACHE_RE = re.compile(
    r'^(?P<src_ip>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+(?P<proto>[^"]+))?"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)")?'
    r'\s*$'
)

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
    "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
    "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
}

IPV4_RE = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b')
DOMAIN_RE = re.compile(r'\b(?:[a-zA-Z0-9-]{1,63}\.)+(?:[a-zA-Z]{2,24})\b')
URL_RE = re.compile(r'\bhttps?://[^\s<>"\'\]]+', re.IGNORECASE)
HASH_RE = re.compile(r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b')


@dataclass
class TimelineEvent:
    ts: str                    # normalized ISO8601 if possible
    ts_epoch: float            # epoch seconds for sorting
    source: str                # filename
    event_type: str            # auth_failed / apache_request / parsed_event / unknown
    summary: str               # human-readable summary
    src_ip: Optional[str] = None
    user: Optional[str] = None
    method: Optional[str] = None
    path: Optional[str] = None
    status: Optional[int] = None
    ioc_matches: Optional[List[str]] = None
    raw: Optional[str] = None


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="SOC & DFIR Toolkit - Timeline Analyzer")
    p.add_argument("--inputs", nargs="+", required=True, help="Input files (raw logs or JSONL parsed events)")
    p.add_argument("--format", choices=["jsonl", "csv"], default="jsonl", help="Output format")
    p.add_argument("--out", default="timeline.jsonl", help="Output file path")
    p.add_argument("--year", type=int, default=0, help="Year override for logs without year (auth.log)")
    p.add_argument("--ioc-file", default="", help="IOC JSON file from ioc_extractor.py to mark matches")
    p.add_argument("--max-lines", type=int, default=0, help="Max lines per input (0=no limit)")
    return p.parse_args()


def read_lines(path: str, max_lines: int = 0) -> Iterator[str]:
    with open(path, "r", errors="replace") as f:
        for i, line in enumerate(f, start=1):
            if max_lines and i > max_lines:
                break
            yield line.rstrip("\n")


def try_parse_iso(ts: str) -> Optional[datetime]:
    # Handles "2026-01-19T12:34:56Z" or "2026-01-19T12:34:56+00:00"
    try:
        if ts.endswith("Z"):
            return datetime.fromisoformat(ts[:-1]).replace(tzinfo=timezone.utc)
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def auth_ts_to_dt(mon: str, day: str, hhmmss: str, year: int) -> datetime:
    if year <= 0:
        year = datetime.utcnow().year
    m = MONTHS.get(mon, 1)
    d = int(day)
    dt = datetime(year, m, d, int(hhmmss[0:2]), int(hhmmss[3:5]), int(hhmmss[6:8]), tzinfo=timezone.utc)
    return dt


def apache_ts_to_dt(ts: str) -> Optional[datetime]:
    # Example: 10/Oct/2000:13:55:36 +0000
    try:
        dt = datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z")
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def load_iocs(ioc_path: str) -> List[str]:
    if not ioc_path:
        return []
    with open(ioc_path, "r", encoding="utf-8") as f:
        obj = json.load(f)

    values: List[str] = []
    for k, v in obj.items():
        if isinstance(v, list):
            for item in v:
                if isinstance(item, str) and item.strip():
                    values.append(item.strip())
    # Dedup, keep longer first for better match clarity
    values = sorted(set(values), key=lambda s: (-len(s), s.lower()))
    return values


def find_ioc_matches(text: str, iocs: List[str]) -> List[str]:
    if not text or not iocs:
        return []
    hits = []
    lower_text = text.lower()
    for ioc in iocs:
        # case-insensitive contains
        if ioc.lower() in lower_text:
            hits.append(ioc)
    return hits


def parse_jsonl_event(line: str) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(line)
    except Exception:
        return None


def build_summary(ev: Dict[str, Any]) -> str:
    et = ev.get("event_type") or "event"
    src_ip = ev.get("src_ip")
    user = ev.get("user")
    method = ev.get("method")
    path = ev.get("path")
    status = ev.get("status")

    if et.startswith("auth_"):
        if src_ip and user:
            return f"{et}: user={user} from {src_ip}"
        if src_ip:
            return f"{et}: from {src_ip}"
        return f"{et}"
    if et == "apache_request":
        s = f"http: {method or '-'} {path or '-'}"
        if status is not None:
            s += f" status={status}"
        if src_ip:
            s += f" src_ip={src_ip}"
        return s
    return f"{et}"


def yield_events_from_file(path: str, year: int, max_lines: int, iocs: List[str]) -> Iterator[TimelineEvent]:
    filename = os.path.basename(path)

    # Heuristic: if extension is .jsonl, try JSONL first
    is_jsonl = path.lower().endswith(".jsonl")

    for line in read_lines(path, max_lines=max_lines):
        if not line.strip():
            continue

        # JSONL parsed events
        if is_jsonl:
            obj = parse_jsonl_event(line)
            if not isinstance(obj, dict):
                continue

            ts_raw = str(obj.get("timestamp") or "")
            dt = try_parse_iso(ts_raw)
            if dt is None:
                # allow raw timestamp, push to end with 0
                dt = datetime.fromtimestamp(0, tz=timezone.utc)

            summary = build_summary(obj)
            raw_text = obj.get("raw") or line

            match_text = f"{summary} {raw_text}"
            matches = find_ioc_matches(match_text, iocs)

            yield TimelineEvent(
                ts=dt.isoformat(),
                ts_epoch=dt.timestamp(),
                source=filename,
                event_type=str(obj.get("event_type") or "parsed_event"),
                summary=summary,
                src_ip=obj.get("src_ip"),
                user=obj.get("user"),
                method=obj.get("method"),
                path=obj.get("path"),
                status=obj.get("status"),
                ioc_matches=matches or None,
                raw=str(raw_text)
            )
            continue

        # Raw auth.log
        m_auth = AUTH_SSHD_RE.match(line)
        if m_auth:
            dt = auth_ts_to_dt(m_auth.group("mon"), m_auth.group("day"), m_auth.group("time"), year)
            msg = m_auth.group("msg")
            host = m_auth.group("host")

            event_type = "auth_event"
            src_ip = None
            user = None

            m_acc = AUTH_ACCEPTED_RE.search(msg)
            m_fail = AUTH_FAILED_RE.search(msg)
            m_inv = AUTH_INVALID_USER_RE.search(msg)

            if m_acc:
                event_type = "auth_accepted"
                user = m_acc.group("user")
                src_ip = m_acc.group("src_ip")
            elif m_fail:
                event_type = "auth_failed"
                user = m_fail.group("user")
                src_ip = m_fail.group("src_ip")
            elif m_inv:
                event_type = "auth_invalid_user"
                user = m_inv.group("user")
                src_ip = m_inv.group("src_ip")

            summary = f"{event_type}: host={host}"
            if user:
                summary += f" user={user}"
            if src_ip:
                summary += f" src_ip={src_ip}"

            matches = find_ioc_matches(summary + " " + line, iocs)

            yield TimelineEvent(
                ts=dt.isoformat(),
                ts_epoch=dt.timestamp(),
                source=filename,
                event_type=event_type,
                summary=summary,
                src_ip=src_ip,
                user=user,
                ioc_matches=matches or None,
                raw=line
            )
            continue

        # Raw apache access.log
        m_ap = APACHE_RE.match(line)
        if m_ap:
            dt = apache_ts_to_dt(m_ap.group("ts"))
            if dt is None:
                dt = datetime.fromtimestamp(0, tz=timezone.utc)

            src_ip = m_ap.group("src_ip")
            method = m_ap.group("method")
            path_ = m_ap.group("path")
            status = int(m_ap.group("status"))
            user = m_ap.group("user")
            if user == "-":
                user = None

            summary = f"http: {method} {path_} status={status} src_ip={src_ip}"
            matches = find_ioc_matches(summary + " " + line, iocs)

            yield TimelineEvent(
                ts=dt.isoformat(),
                ts_epoch=dt.timestamp(),
                source=filename,
                event_type="apache_request",
                summary=summary,
                src_ip=src_ip,
                user=user,
                method=method,
                path=path_,
                status=status,
                ioc_matches=matches or None,
                raw=line
            )
            continue

        # Unknown line: try to extract any timestamp-like ISO (rare)
        dt = None
        iso_guess = re.search(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?', line)
        if iso_guess:
            dt = try_parse_iso(iso_guess.group(0))
        if dt is None:
            dt = datetime.fromtimestamp(0, tz=timezone.utc)

        # quick ioc scan on unknown raw line
        matches = find_ioc_matches(line, iocs)

        yield TimelineEvent(
            ts=dt.isoformat(),
            ts_epoch=dt.timestamp(),
            source=filename,
            event_type="unknown",
            summary="unparsed_line",
            ioc_matches=matches or None,
            raw=line
        )


def write_jsonl(out_path: str, events: Iterable[TimelineEvent]) -> int:
    n = 0
    with open(out_path, "w", encoding="utf-8") as w:
        for ev in events:
            w.write(json.dumps(asdict(ev), ensure_ascii=False) + "\n")
            n += 1
    return n


def write_csv(out_path: str, events: Iterable[TimelineEvent]) -> int:
    n = 0
    fields = ["ts", "source", "event_type", "summary", "src_ip", "user", "method", "path", "status", "ioc_matches", "raw"]
    with open(out_path, "w", newline="", encoding="utf-8") as w:
        writer = csv.DictWriter(w, fieldnames=fields)
        writer.writeheader()
        for ev in events:
            d = asdict(ev)
            if isinstance(d.get("ioc_matches"), list):
                d["ioc_matches"] = ",".join(d["ioc_matches"])
            writer.writerow({k: d.get(k) for k in fields})
            n += 1
    return n


def main() -> int:
    args = parse_args()

    # Validate inputs
    for p in args.inputs:
        if not os.path.exists(p):
            print(f"[!] Input not found: {p}", file=sys.stderr)
            return 2

    iocs = load_iocs(args.ioc_file) if args.ioc_file else []

    all_events: List[TimelineEvent] = []
    for p in args.inputs:
        for ev in yield_events_from_file(p, args.year, args.max_lines, iocs):
            all_events.append(ev)

    # Sort by epoch; unknown ones (epoch=0) will appear first; move them last:
    all_events.sort(key=lambda e: (e.ts_epoch, e.source))
    # push epoch=0 to end
    known = [e for e in all_events if e.ts_epoch != 0]
    unknown = [e for e in all_events if e.ts_epoch == 0]
    all_events = known + unknown

    if args.format == "jsonl":
        n = write_jsonl(args.out, all_events)
    else:
        n = write_csv(args.out, all_events)

    print(f"[+] Timeline generated: {args.out} ({n} events)", file=sys.stderr)
    if args.ioc_file:
        marked = sum(1 for e in all_events if e.ioc_matches)
        print(f"[+] IOC-marked events: {marked}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
