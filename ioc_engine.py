"""
Threat Intelligence Aggregator (Non-AI)
Core Engine - ioc_engine.py

Pipeline:
  Step 1: Load Feeds
  Step 2: Parse Indicators
  Step 3: Normalize Data
  Step 4: Correlation Engine
  Step 5: Blocklist Generation
  Step 6: Final Reporting
"""

import re
import json
import hashlib
import os
import urllib.request
import urllib.error
from datetime import datetime
from collections import defaultdict
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Optional


# ─────────────────────────────────────────────
#  DATA MODELS
# ─────────────────────────────────────────────

@dataclass
class IOC:
    value: str
    ioc_type: str          # ip, url, domain, hash_md5, hash_sha256, email
    source_feed: str
    seen_count: int = 1
    risk_score: int = 0    # 0-100
    tags: List[str] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""

    def __post_init__(self):
        now = datetime.utcnow().isoformat()
        if not self.first_seen:
            self.first_seen = now
        self.last_seen = now


@dataclass
class FeedResult:
    feed_name: str
    feed_url: str
    status: str            # success | error | simulated
    raw_lines: int = 0
    ioc_count: int = 0
    error_msg: str = ""


# ─────────────────────────────────────────────
#  STEP 1 — LOAD FEEDS
# ─────────────────────────────────────────────

SAMPLE_FEEDS = {
    "AlienVault_OTX_Malware_IPs": [
        "# AlienVault OTX - Malware IPs",
        "# Generated: 2026-05-25",
        "192.168.100.55",
        "10.0.0.99",
        "185.220.101.47",
        "45.142.212.100",
        "91.108.4.0/22",
        "198.51.100.23",
        "203.0.113.5",
        "http://malicious-payload.xyz/shell.php",
        "evil-domain.ru",
        "d41d8cd98f00b204e9800998ecf8427e",   # MD5
        "attacker@phishme.net",
    ],
    "Abuse_ch_URLhaus": [
        "# URLhaus Feed",
        "http://badsite.tk/wp-admin/update.php",
        "https://phish-login.com/secure/bank",
        "http://185.220.101.47/payload.exe",
        "185.220.101.47",
        "45.142.212.100",
        "trojan-c2.cn",
        "aabbccddeeff00112233445566778899",     # MD5
        "a3f5b2c1d4e6f708192a3b4c5d6e7f8091a2b3c4d5e6f7081920a1b2c3d4e5f6",  # SHA256
        "hacker@spam.org",
    ],
    "Emerging_Threats_CNC": [
        "# Emerging Threats C&C IPs",
        "91.108.4.1",
        "203.0.113.5",
        "185.220.101.47",
        "198.51.100.99",
        "c2-server.io",
        "botnet-master.pw",
        "evil-domain.ru",
        "a3f5b2c1d4e6f708192a3b4c5d6e7f8091a2b3c4d5e6f7081920a1b2c3d4e5f6",
        "http://c2-server.io/beacon",
        "victim@target.com",
    ],
    "PhishTank_URLs": [
        "# PhishTank Phishing URLs",
        "https://secure-bank-login.evil.com/auth",
        "http://paypa1-verify.tk/login",
        "https://phish-login.com/secure/bank",
        "phish-login.com",
        "paypa1-verify.tk",
        "scammer@phish.net",
        "45.142.212.100",
    ],
}


def load_feeds_from_urls(feed_urls: Dict[str, str]) -> tuple:
    """Try to load feeds from real URLs; fall back to samples if blocked."""
    results: List[FeedResult] = []
    raw_data: Dict[str, List[str]] = {}

    for name, url in feed_urls.items():
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "IOC-Aggregator/1.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                content = resp.read().decode("utf-8", errors="ignore")
                lines = [l.strip() for l in content.splitlines() if l.strip()]
                raw_data[name] = lines
                results.append(FeedResult(name, url, "success", len(lines)))
        except Exception as e:
            # Fall back to sample data
            lines = SAMPLE_FEEDS.get(name, [])
            raw_data[name] = lines
            results.append(FeedResult(name, url, "simulated", len(lines),
                                      error_msg=f"Using sample data ({e})"))

    return raw_data, results


def load_from_files(file_paths: List[str]) -> tuple:
    """Load IOC feeds from local text files."""
    raw_data: Dict[str, List[str]] = {}
    results: List[FeedResult] = []
    for path in file_paths:
        name = os.path.basename(path)
        try:
            with open(path) as f:
                lines = [l.strip() for l in f if l.strip()]
            raw_data[name] = lines
            results.append(FeedResult(name, path, "success", len(lines)))
        except Exception as e:
            results.append(FeedResult(name, path, "error", error_msg=str(e)))
    return raw_data, results


def load_sample_feeds() -> tuple:
    """Use built-in sample feeds for demo."""
    raw_data = {k: v for k, v in SAMPLE_FEEDS.items()}
    results = [FeedResult(k, "built-in", "simulated", len(v)) for k, v in SAMPLE_FEEDS.items()]
    return raw_data, results


# ─────────────────────────────────────────────
#  STEP 2 — PARSE INDICATORS
# ─────────────────────────────────────────────

PATTERNS = {
    "ip": re.compile(
        r"(?<!\d)(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:/\d{1,2})?(?!\d)"
    ),
    "url": re.compile(r"https?://[^\s,\"'<>]+"),
    "domain": re.compile(
        r"(?<!\@)(?<!\.)(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
        r"+(?:com|net|org|io|ru|cn|tk|pw|xyz|info|biz|gov|edu|uk|de|fr|in|co)"
        r"(?!\w)"
    ),
    "hash_md5": re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{32}(?![a-fA-F0-9])"),
    "hash_sha256": re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{64}(?![a-fA-F0-9])"),
    "email": re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
}

PRIORITY_ORDER = ["hash_sha256", "hash_md5", "email", "url", "ip", "domain"]


def parse_line(line: str, feed_name: str) -> List[IOC]:
    """Extract all IOCs from a single line of feed data."""
    if line.startswith("#") or not line:
        return []

    found: List[IOC] = []
    matched_spans = []

    for ioc_type in PRIORITY_ORDER:
        pattern = PATTERNS[ioc_type]
        for m in pattern.finditer(line):
            # Avoid overlapping matches
            overlap = any(s <= m.start() < e or s < m.end() <= e
                          for s, e in matched_spans)
            if not overlap:
                matched_spans.append((m.start(), m.end()))
                found.append(IOC(
                    value=m.group().strip("/"),
                    ioc_type=ioc_type,
                    source_feed=feed_name,
                ))
    return found


def parse_all_feeds(raw_data: Dict[str, List[str]]) -> List[IOC]:
    """Parse every feed and return flat list of IOCs."""
    all_iocs: List[IOC] = []
    for feed_name, lines in raw_data.items():
        for line in lines:
            all_iocs.extend(parse_line(line, feed_name))
    return all_iocs


# ─────────────────────────────────────────────
#  STEP 3 — NORMALIZE DATA
# ─────────────────────────────────────────────

PRIVATE_IP_RANGES = [
    re.compile(r"^10\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),
    re.compile(r"^127\."),
]

WHITELIST = {
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
    "google.com", "microsoft.com", "github.com",
}


def is_private_ip(ip: str) -> bool:
    return any(p.match(ip) for p in PRIVATE_IP_RANGES)


def normalize_ioc(ioc: IOC) -> Optional[IOC]:
    """Clean, validate and standardize a single IOC."""
    val = ioc.value.lower().strip().rstrip(".")

    # Hashes → uppercase
    if "hash" in ioc.ioc_type:
        val = ioc.value.upper().strip()

    # Drop private IPs
    if ioc.ioc_type == "ip" and is_private_ip(val):
        return None

    # Drop whitelisted values
    if val in WHITELIST:
        return None

    # Strip trailing slashes from URLs
    if ioc.ioc_type == "url":
        val = val.rstrip("/")

    ioc.value = val
    return ioc


def normalize_all(iocs: List[IOC]) -> List[IOC]:
    normalized = []
    for ioc in iocs:
        n = normalize_ioc(ioc)
        if n:
            normalized.append(n)
    return normalized


# ─────────────────────────────────────────────
#  STEP 4 — CORRELATION ENGINE
# ─────────────────────────────────────────────

RISK_BASE = {
    "ip": 40,
    "url": 50,
    "domain": 35,
    "hash_md5": 60,
    "hash_sha256": 65,
    "email": 25,
}

RISK_MULTIPLIER_PER_FEED = 15   # +15 per additional feed seeing same IOC
RISK_CAP = 100


def calculate_risk(ioc_type: str, seen_count: int) -> int:
    base = RISK_BASE.get(ioc_type, 30)
    bonus = (seen_count - 1) * RISK_MULTIPLIER_PER_FEED
    return min(base + bonus, RISK_CAP)


def correlate(iocs: List[IOC]) -> List[IOC]:
    """
    Merge duplicate IOCs across feeds.
    IOCs seen in multiple feeds get higher risk scores.
    """
    merged: Dict[str, IOC] = {}

    for ioc in iocs:
        key = f"{ioc.ioc_type}::{ioc.value}"
        if key in merged:
            existing = merged[key]
            existing.seen_count += 1
            if ioc.source_feed not in existing.source_feed:
                existing.source_feed += f", {ioc.source_feed}"
            existing.last_seen = datetime.utcnow().isoformat()
        else:
            merged[key] = ioc

    # Assign risk scores
    for ioc in merged.values():
        ioc.risk_score = calculate_risk(ioc.ioc_type, ioc.seen_count)
        # Tag high-priority repeated IOCs
        if ioc.seen_count >= 3:
            ioc.tags.append("HIGH_CONFIDENCE")
        elif ioc.seen_count == 2:
            ioc.tags.append("CORRELATED")
        if ioc.risk_score >= 80:
            ioc.tags.append("CRITICAL")
        elif ioc.risk_score >= 60:
            ioc.tags.append("HIGH")
        elif ioc.risk_score >= 40:
            ioc.tags.append("MEDIUM")
        else:
            ioc.tags.append("LOW")

    return sorted(merged.values(), key=lambda x: x.risk_score, reverse=True)


# ─────────────────────────────────────────────
#  STEP 5 — BLOCKLIST GENERATION
# ─────────────────────────────────────────────

def generate_blocklists(iocs: List[IOC], output_dir: str = "output") -> Dict[str, str]:
    """Write category-based blocklist files."""
    os.makedirs(output_dir, exist_ok=True)

    categories = defaultdict(list)
    for ioc in iocs:
        categories[ioc.ioc_type].append(ioc)

    paths = {}
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    for cat, items in categories.items():
        filename = os.path.join(output_dir, f"blocklist_{cat}_{ts}.txt")
        with open(filename, "w") as f:
            f.write(f"# IOC Blocklist - {cat.upper()}\n")
            f.write(f"# Generated: {datetime.utcnow().isoformat()}\n")
            f.write(f"# Total entries: {len(items)}\n\n")
            for ioc in sorted(items, key=lambda x: x.risk_score, reverse=True):
                f.write(f"{ioc.value}  # risk={ioc.risk_score} feeds={ioc.seen_count} tags={','.join(ioc.tags)}\n")
        paths[cat] = filename

    return paths


# ─────────────────────────────────────────────
#  STEP 6 — FINAL REPORTING
# ─────────────────────────────────────────────

def generate_report(iocs: List[IOC], feed_results: List[FeedResult],
                    blocklist_paths: Dict[str, str],
                    report_dir: str = "reports") -> dict:
    """Build JSON + text summary report."""
    os.makedirs(report_dir, exist_ok=True)

    by_type = defaultdict(list)
    for ioc in iocs:
        by_type[ioc.ioc_type].append(ioc)

    critical = [i for i in iocs if i.risk_score >= 80]
    high = [i for i in iocs if 60 <= i.risk_score < 80]
    medium = [i for i in iocs if 40 <= i.risk_score < 60]
    low = [i for i in iocs if i.risk_score < 40]

    report = {
        "generated_at": datetime.utcnow().isoformat(),
        "summary": {
            "total_feeds": len(feed_results),
            "total_iocs": len(iocs),
            "unique_types": list(by_type.keys()),
            "critical_iocs": len(critical),
            "high_iocs": len(high),
            "medium_iocs": len(medium),
            "low_iocs": len(low),
        },
        "feeds": [asdict(r) for r in feed_results],
        "by_type": {k: len(v) for k, v in by_type.items()},
        "blocklists_generated": blocklist_paths,
        "top_iocs": [asdict(i) for i in iocs[:20]],
        "all_iocs": [asdict(i) for i in iocs],
    }

    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    json_path = os.path.join(report_dir, f"ti_report_{ts}.json")
    txt_path = os.path.join(report_dir, f"ti_report_{ts}.txt")

    with open(json_path, "w") as f:
        json.dump(report, f, indent=2)

    with open(txt_path, "w") as f:
        f.write("=" * 60 + "\n")
        f.write("  THREAT INTELLIGENCE REPORT\n")
        f.write(f"  Generated: {report['generated_at']}\n")
        f.write("=" * 60 + "\n\n")
        s = report["summary"]
        f.write(f"  Feeds Processed : {s['total_feeds']}\n")
        f.write(f"  Total IOCs       : {s['total_iocs']}\n")
        f.write(f"  CRITICAL         : {s['critical_iocs']}\n")
        f.write(f"  HIGH             : {s['high_iocs']}\n")
        f.write(f"  MEDIUM           : {s['medium_iocs']}\n")
        f.write(f"  LOW              : {s['low_iocs']}\n\n")
        f.write("IOC BREAKDOWN BY TYPE:\n")
        for t, c in report["by_type"].items():
            f.write(f"  {t:20s}: {c}\n")
        f.write("\nTOP 10 HIGHEST-RISK IOCs:\n")
        for i, ioc in enumerate(iocs[:10], 1):
            f.write(f"  {i:2}. [{ioc.risk_score:3d}] {ioc.ioc_type:15s} {ioc.value}\n")
            f.write(f"       Sources: {ioc.source_feed}\n")
            f.write(f"       Tags: {', '.join(ioc.tags)}\n\n")

    return {"json": json_path, "txt": txt_path, "data": report}


# ─────────────────────────────────────────────
#  FULL PIPELINE RUNNER
# ─────────────────────────────────────────────

def run_pipeline(feed_urls: Optional[Dict[str, str]] = None,
                 feed_files: Optional[List[str]] = None,
                 output_dir: str = "output",
                 report_dir: str = "reports") -> dict:
    """
    Execute all 6 pipeline steps and return the full report.
    """
    print("\n" + "=" * 55)
    print("  THREAT INTELLIGENCE AGGREGATOR (NON-AI)")
    print("=" * 55)

    # STEP 1
    print("\n[STEP 1] Loading feeds...")
    if feed_urls:
        raw_data, feed_results = load_feeds_from_urls(feed_urls)
    elif feed_files:
        raw_data, feed_results = load_from_files(feed_files)
    else:
        raw_data, feed_results = load_sample_feeds()

    for r in feed_results:
        status = "✓" if r.status == "success" else "~"
        print(f"  {status} {r.feed_name} ({r.status}) - {r.raw_lines} lines")

    # STEP 2
    print("\n[STEP 2] Parsing indicators...")
    raw_iocs = parse_all_feeds(raw_data)
    print(f"  Extracted {len(raw_iocs)} raw IOCs")

    # STEP 3
    print("\n[STEP 3] Normalizing data...")
    clean_iocs = normalize_all(raw_iocs)
    dropped = len(raw_iocs) - len(clean_iocs)
    print(f"  {len(clean_iocs)} clean IOCs ({dropped} dropped as private/whitelisted)")

    # STEP 4
    print("\n[STEP 4] Running correlation engine...")
    correlated = correlate(clean_iocs)
    multi_feed = [i for i in correlated if i.seen_count > 1]
    print(f"  {len(correlated)} unique IOCs")
    print(f"  {len(multi_feed)} appear in multiple feeds (high confidence)")

    # STEP 5
    print("\n[STEP 5] Generating blocklists...")
    blocklist_paths = generate_blocklists(correlated, output_dir)
    for cat, path in blocklist_paths.items():
        print(f"  → {path}")

    # STEP 6
    print("\n[STEP 6] Generating final report...")
    result = generate_report(correlated, feed_results, blocklist_paths, report_dir)
    print(f"  → {result['json']}")
    print(f"  → {result['txt']}")

    s = result["data"]["summary"]
    print("\n" + "=" * 55)
    print(f"  DONE — {s['total_iocs']} IOCs | "
          f"CRITICAL:{s['critical_iocs']} HIGH:{s['high_iocs']} "
          f"MEDIUM:{s['medium_iocs']} LOW:{s['low_iocs']}")
    print("=" * 55 + "\n")

    return result
