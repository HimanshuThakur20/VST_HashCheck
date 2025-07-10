#!/usr/bin/env python3
"""
vt_hash_lookup.py — VirusTotal hash scanner with progress, cache, and malicious summary

Version 1.8 — 2025-07-09
"""

from __future__ import annotations
import argparse
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

import requests

try:
    from tqdm import tqdm
except ImportError:
    tqdm = None

try:
    from tabulate import tabulate
except ImportError:
    tabulate = None

API_URL = "https://www.virustotal.com/api/v3/files/{}"
DEFAULT_CACHE = Path.home() / ".vt_cache.json"
DEFAULT_MIN_INTERVAL = 15
DEFAULT_BATCH = 10


def load_cache(path: Path) -> Dict[str, Any]:
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def save_cache(path: Path, data: Dict[str, Any]) -> None:
    try:
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception as e:
        print(f"[!] Could not write cache: {e}", file=sys.stderr)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="VirusTotal hash lookup with progress bar, batch output, and final malicious summary",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("hashes", nargs="*", help="Hash(es) directly on the command line")
    p.add_argument("--file", "-f", metavar="PATH", help="File containing hashes (one per line)")
    p.add_argument("--api-key", help="VirusTotal API key (or set VT_API_KEY env var)")
    p.add_argument("--cache", "-c", type=Path, default=DEFAULT_CACHE, help="Path to JSON cache file")
    p.add_argument("--output", "-o", choices=["table", "json"], default="table", help="Output format")
    p.add_argument("--min-interval", type=int, default=DEFAULT_MIN_INTERVAL, metavar="SEC",
                   help="Seconds to wait between API calls")
    p.add_argument("--batch", type=int, default=DEFAULT_BATCH, metavar="N",
                   help="Print results every N hashes (0 = disable)")
    p.add_argument("--no-progress", action="store_true", help="Disable progress bar")
    p.add_argument("--verbose", "-v", action="store_true", help="Extra debug info")
    p.add_argument("--insecure", action="store_true", help="Disable SSL certificate verification (insecure)")
    return p.parse_args()


def vt_request(hash_: str, api_key: str, verify_ssl: bool = True) -> Dict[str, Any] | None:
    headers = {"x-apikey": api_key}
    while True:
        resp = requests.get(API_URL.format(hash_), headers=headers, verify=verify_ssl)
        if resp.status_code == 200:
            return resp.json()
        if resp.status_code == 404:
            return {"data": None, "error": "Not found"}
        if resp.status_code == 429:
            retry = int(resp.headers.get("Retry-After", 15))
            print(f"[Rate-limit] Sleeping {retry}s…", file=sys.stderr, flush=True)
            time.sleep(retry)
            continue
        resp.raise_for_status()


def analyze_stats(data: Dict[str, Any] | None) -> Tuple[int, int, int, int]:
    if not (isinstance(data, dict) and data.get("data")):
        return 0, 0, 0, 0
    stats = data["data"]["attributes"].get("last_analysis_stats", {})
    return (
        stats.get("malicious", 0),
        stats.get("suspicious", 0),
        stats.get("harmless", 0),
        stats.get("undetected", 0),
    )


def format_epoch(ts: int | None) -> str:
    return datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M UTC") if ts else "—"


def print_table(rows: List[Dict[str, Any]]) -> None:
    headers = ["Hash", "Malicious", "Suspicious", "Harmless", "Undetected", "First Seen", "Last Scan"]
    body = []
    for r in rows:
        data = r.get("response") if isinstance(r, dict) else None
        if not isinstance(data, dict):
            body.append([r["hash"], "—", "—", "—", "—", "—", "—"])
            continue
        attrs = (data.get("data") or {}).get("attributes", {})
        m, s, h, u = analyze_stats(data)
        body.append([
            r["hash"], m, s, h, u,
            format_epoch(attrs.get("first_submission_date")),
            format_epoch(attrs.get("last_analysis_date")),
        ])
    if tabulate:
        print(tabulate(body, headers=headers, tablefmt="github"))
    else:
        print("\t".join(headers))
        for row in body:
            print("\t".join(map(str, row)))


def main() -> None:
    args = parse_args()

    if args.insecure:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if not args.hashes and not args.file:
        print("[!] Provide hashes or use --file", file=sys.stderr)
        sys.exit(1)

    api_key = args.api_key or os.getenv("VT_API_KEY")
    if not api_key:
        print("[!] Missing API key (use --api-key or set VT_API_KEY)", file=sys.stderr)
        sys.exit(1)

    # Load hashes
    hashes: List[str] = []
    if args.file:
        try:
            hashes.extend([h.strip() for h in Path(args.file).read_text().splitlines() if h.strip()])
        except OSError as e:
            print(f"[!] Cannot read {args.file}: {e}", file=sys.stderr)
            sys.exit(1)
    hashes.extend(args.hashes)
    hashes = [h.lower() for h in hashes]

    if not hashes:
        print("[!] No valid hashes found", file=sys.stderr)
        sys.exit(1)

    if args.verbose:
        print(f"[*] Loaded {len(hashes)} hashes", file=sys.stderr)

    cache = load_cache(args.cache)
    results: List[Dict[str, Any]] = []
    batch: List[Dict[str, Any]] = []
    last_query_time = 0.0

    use_tqdm = bool(tqdm and not args.no_progress and sys.stderr.isatty())
    iterator = tqdm(hashes, desc="VirusTotal", unit="hash") if use_tqdm else hashes

    def flush(force: bool = False):
        nonlocal batch
        if args.batch and (force or len(batch) >= args.batch):
            if args.output == "table":
                if use_tqdm:
                    tqdm.write(f"\nBatch results ({len(batch)} hashes):")
                print_table(batch)
            else:
                print(json.dumps({r['hash']: r['response'] for r in batch}, indent=2))
            batch = []

    for h in iterator:
        if h in cache:
            resp = cache[h]
        else:
            wait = args.min_interval - (time.time() - last_query_time)
            if wait > 0:
                time.sleep(wait)
            try:
                resp = vt_request(h, api_key, verify_ssl=not args.insecure)
            except requests.RequestException as e:
                print(f"[!] Error querying {h}: {e}", file=sys.stderr)
                resp = None
            cache[h] = resp
            last_query_time = time.time()

        results.append({"hash": h, "response": resp})
        batch.append({"hash": h, "response": resp})

        if not use_tqdm and not args.no_progress:
            print(f"Queried {h}", file=sys.stderr)

        flush()

    flush(force=True)
    save_cache(args.cache, cache)

    if args.output == "json" and not args.batch:
        print(json.dumps({r["hash"]: r["response"] for r in results}, indent=2))
    elif args.output == "table" and args.batch == 0:
        print("\nFull results:")
        print_table(results)

    # ───── Final Summary ─────
    malicious: List[Tuple[str, str]] = []
    suspicious: List[str] = []

    for r in results:
        hash_ = r["hash"]
        data = r.get("response")
        if not isinstance(data, dict):
            continue
        stats = (data.get("data") or {}).get("attributes", {}).get("last_analysis_stats", {})
        total = sum(stats.values())
        if stats.get("malicious", 0) > 0:
            score = f"{stats.get('malicious', 0)}/{total}"
            malicious.append((hash_, score))
        elif stats.get("suspicious", 0) > 0:
            suspicious.append(hash_)

    print("\n========== SUMMARY ==========")
    print(f"Total hashes checked: {len(results)}")
    print(f"Malicious: {len(malicious)}")
    print(f"Suspicious: {len(suspicious)}")

    if malicious:
        print("\n[!] Malicious hashes (malicious/total):")
        for h, score in malicious:
            print(f"  - {h}  ({score})")

    if suspicious:
        print("\n[!] Suspicious hashes:")
        for h in suspicious:
            print(f"  - {h}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("[!] Interrupted", file=sys.stderr)
        sys.exit(130)
