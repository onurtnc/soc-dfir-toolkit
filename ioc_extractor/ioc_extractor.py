#!/usr/bin/env python3
"""
SOC & DFIR Toolkit - IOC Extractor
Extracts IOCs from text/log files:
- IPv4
- Domains
- URLs
- Hashes (MD5/SHA1/SHA256)

Outputs:
- json (default), csv, or txt

Usage:
  python3 ioc_extractor.py /path/to/file.log
  python3 ioc_extractor.py file.txt --format csv --out iocs.csv
  python3 ioc_extractor.py file.txt --format txt --out iocs.txt
  python3 ioc_extractor.py file.txt --stats
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
from dataclasses import dataclass, asdict
from typing import Dict, List, Set, Tuple


# ---------------------------
# Regex patterns (best-effort)
# ---------------------------

IPV4_RE = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b'
)

# URL: keep it permissive but not too greedy
URL_RE = re.compile(
    r'\bhttps?://[^\s<>"\'\]]+',
    re.IGNORECASE
)

# Domain: avoid emails by requiring a dot + TLD length >=2
# (Not perfect, but solid for DFIR triage)
DOMAIN_RE = re.compile(
    r'\b(?!(?:\d{1,3}\.){3}\d{1,3}\b)(?:[a-zA-Z0-9-]{1,63}\.)+(?:[a-zA-Z]{2,24})\b'
)

# Hashes
MD5_RE = re.compile(r'\b[a-fA-F0-9]{32}\b')
SHA1_RE = re.compile(r'\b[a-fA-F0-9]{40}\b')
SHA256_RE = re.compile(r'\b[a-fA-F0-9]{64}\b')


# Common false-positive domains
COMMON_FP = {
    "localhost",
}


@dataclass
class IOCs:
    ipv4: List[str]
    domains: List[str]
    urls: List[str]
    md5: List[str]
    sha1: List[str]
    sha256: List[str]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="SOC & DFIR Toolkit - IOC Extractor")
    p.add_argument("input", help="Path to input file (log/text/json/etc.)")
    p.add_argument("--format", choices=["json", "csv", "txt"], default="json", help="Output format")
    p.add_argument("--out", default="", help="Output file path (default: <input>.iocs.json/csv/txt)")
    p.add_argument("--stats", action="store_true", help="Print quick stats to stderr")
    p.add_argument("--max-bytes", type=int, default=0, help="Max bytes to read (0 = no limit)")
    return p.parse_args()


def read_file(path: str, max_bytes: int = 0) -> str:
    with open(path, "rb") as f:
        data = f.read(max_bytes) if max_bytes and max_bytes > 0 else f.read()
    return data.decode("utf-8", errors="replace")


def normalize_domain(d: str) -> str:
    d = d.strip().strip(".").lower()
    return d


def normalize_url(u: str) -> str:
    # Strip trailing punctuation common in logs
    u = u.strip().rstrip(").,;\"'")
    return u


def extract_iocs(text: str) -> Tuple[IOCs, Dict[str, int]]:
    ipv4: Set[str] = set(IPV4_RE.findall(text))
    urls: Set[str] = {normalize_url(u) for u in URL_RE.findall(text)}

    # Domains from text
    raw_domains = set(DOMAIN_RE.findall(text))
    domains: Set[str] = set()

    for d in raw_domains:
        nd = normalize_domain(d)
        if nd in COMMON_FP:
            continue
        # avoid picking domains that are part of URLs twice (we still keep it, but domain list can include)
        domains.add(nd)

    # Hashes
    md5 = {h.lower() for h in MD5_RE.findall(text)}
    sha1 = {h.lower() for h in SHA1_RE.findall(text)}
    sha256 = {h.lower() for h in SHA256_RE.findall(text)}

    # Remove overlaps: SHA256 includes MD5 lengths? (no) but SHA1/MD5 could match within longer sequences
    # Our regex is strict with word boundaries, so overlaps are minimal. Still, keep as-is.

    iocs = IOCs(
        ipv4=sorted(ipv4),
        domains=sorted(domains),
        urls=sorted(urls),
        md5=sorted(md5),
        sha1=sorted(sha1),
        sha256=sorted(sha256),
    )

    stats = {
        "ipv4": len(iocs.ipv4),
        "domains": len(iocs.domains),
        "urls": len(iocs.urls),
        "md5": len(iocs.md5),
        "sha1": len(iocs.sha1),
        "sha256": len(iocs.sha256),
        "total": len(iocs.ipv4) + len(iocs.domains) + len(iocs.urls) + len(iocs.md5) + len(iocs.sha1) + len(iocs.sha256),
    }

    return iocs, stats


def default_out_path(in_path: str, fmt: str) -> str:
    base = os.path.splitext(in_path)[0]
    ext = {"json": "json", "csv": "csv", "txt": "txt"}[fmt]
    return f"{base}.iocs.{ext}"


def write_json(out_path: str, iocs: IOCs) -> None:
    with open(out_path, "w", encoding="utf-8") as w:
        json.dump(asdict(iocs), w, ensure_ascii=False, indent=2)


def write_txt(out_path: str, iocs: IOCs) -> None:
    with open(out_path, "w", encoding="utf-8") as w:
        w.write("# IOC Extractor Output\n\n")

        def section(title: str, items: List[str]):
            w.write(f"## {title} ({len(items)})\n")
            for it in items:
                w.write(it + "\n")
            w.write("\n")

        section("IPv4", iocs.ipv4)
        section("Domains", iocs.domains)
        section("URLs", iocs.urls)
        section("MD5", iocs.md5)
        section("SHA1", iocs.sha1)
        section("SHA256", iocs.sha256)


def write_csv(out_path: str, iocs: IOCs) -> None:
    rows = []
    for v in iocs.ipv4:
        rows.append(("ipv4", v))
    for v in iocs.domains:
        rows.append(("domain", v))
    for v in iocs.urls:
        rows.append(("url", v))
    for v in iocs.md5:
        rows.append(("md5", v))
    for v in iocs.sha1:
        rows.append(("sha1", v))
    for v in iocs.sha256:
        rows.append(("sha256", v))

    with open(out_path, "w", newline="", encoding="utf-8") as w:
        writer = csv.writer(w)
        writer.writerow(["type", "value"])
        writer.writerows(rows)


def main() -> int:
    args = parse_args()

    if not os.path.exists(args.input):
        print(f"[!] File not found: {args.input}", file=sys.stderr)
        return 2

    text = read_file(args.input, args.max_bytes)

    iocs, stats = extract_iocs(text)

    out_path = args.out or default_out_path(args.input, args.format)

    if args.format == "json":
        write_json(out_path, iocs)
    elif args.format == "csv":
        write_csv(out_path, iocs)
    else:
        write_txt(out_path, iocs)

    print(f"[+] Extracted IOCs -> {out_path}", file=sys.stderr)

    if args.stats:
        print("\n=== Quick Stats ===", file=sys.stderr)
        for k in ["ipv4", "domains", "urls", "md5", "sha1", "sha256", "total"]:
            print(f"{k}: {stats[k]}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
