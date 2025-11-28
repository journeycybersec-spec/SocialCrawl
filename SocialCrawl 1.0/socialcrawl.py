"""
socialcrawl.py

username OSINT scanner (SocialCrawl).

Features:
- Async httpx-based scans across many sites
- Supports external sites.json for big platform lists
- Colorized, human-readable console report
- Optional JSON output for machine use
- Optional alias discovery (Light Mode) via --aliases
- Alias confidence scoring (HIGH/MEDIUM/LOW)
- Multi-platform alias strength
- Weighted exposure score v2.0 (with aliases)
- Optional HTML report with light/dark theme toggle
- Professional OPSEC pack:
    - Randomized User-Agent
    - Proxy / Tor support
    - Stealth mode (reduced concurrency, jitter)
    - Browser-like headers
    - OPSEC summary

Usage examples:
    python socialcrawl.py --username techwolf --sites-json sites.json
    python socialcrawl.py --username techwolf --sites-json sites.json --aliases
    python socialcrawl.py --username techwolf --sites-json sites.json --aliases --html-report
    python socialcrawl.py --username techwolf --sites-json sites.json --stealth --tor
"""

from __future__ import annotations

import asyncio
import html
import json
import logging
import random
import time
import itertools
import threading
import shutil
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple, Callable

import httpx

from alias_engine import generate_aliases  # Light Mode alias generator


# ---------------------------------------------------------------------------
# GREEN CRT TERMINAL PROGRESS BAR + SPINNER
# ---------------------------------------------------------------------------
def start_progress_spinner(total: int):
    import itertools, threading, time, shutil

    spinner_cycle = itertools.cycle(["⠁", "⠃", "⠇", "⠧", "⠷", "⠿", "⠟", "⠯", "⠷"])
    progress = {"done": 0, "running": True}

    GREEN = "\033[92m"
    RESET = "\033[0m"

    def worker():
        while progress["running"]:
            done = progress["done"]
            pct = int((done / total) * 100) if total > 0 else 0

            cols = shutil.get_terminal_size(fallback=(80, 20)).columns
            bar_width = max(10, min(40, cols - 30))

            filled = int(bar_width * (pct / 100))
            bar = f"{GREEN}{'█' * filled}{RESET}{'░' * (bar_width - filled)}"

            frame = next(spinner_cycle)
            print(f"\r{GREEN}Scanning{RESET} [{bar}] {pct:3d}% {GREEN}{frame}{RESET}", end="", flush=True)
            time.sleep(0.1)

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()

    def increment():
        progress["done"] += 1

    def stop():
        progress["running"] = False
        done = progress["done"]
        pct = int((done / total) * 100) if total > 0 else 0

        cols = shutil.get_terminal_size(fallback=(80, 20)).columns
        bar_width = max(10, min(40, cols - 30))
        filled = int(bar_width * (pct / 100))
        bar = f"{GREEN}{'█' * filled}{RESET}{'░' * (bar_width - filled)}"

        print(f"\r{GREEN}Scanning{RESET} [{bar}] {pct:3d}% {GREEN}✓{RESET}")
        print()

    return increment, stop




# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class SiteConfig:
    """Configuration for a single site check."""

    name: str
    url: str  # e.g. "https://github.com/{username}"
    error_type: str = "status_code"  # "status_code" or "message"
    valid_status: List[int] = field(default_factory=lambda: [200])
    claimed_indicators: List[str] = field(default_factory=list)
    missing_indicators: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    enabled: bool = True
    timeout: float = 15.0

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SiteConfig":
        return cls(
            name=data["name"],
            url=data["url"],
            error_type=data.get("error_type", "status_code"),
            valid_status=data.get("valid_status", [200]),
            claimed_indicators=data.get("claimed_indicators", []),
            missing_indicators=data.get("missing_indicators", []),
            headers=data.get("headers", {}),
            enabled=data.get("enabled", True),
            timeout=float(data.get("timeout", 15.0)),
        )


@dataclass
class UsernameResult:
    """Result of checking a single site for a username."""

    username: str
    site: str
    profile_url: str
    exists: bool
    http_status: Optional[int]
    response_time: Optional[float]
    error: Optional[str] = None
    inconclusive: bool = False
    opsec_flags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Default sites (fallback if no sites.json is provided)
# ---------------------------------------------------------------------------

DEFAULT_SITES: List[Dict[str, Any]] = [
    {
        "name": "GitHub",
        "url": "https://github.com/{username}",
        "error_type": "status_code",
        "valid_status": [200],
    },
    {
        "name": "Reddit",
        "url": "https://www.reddit.com/user/{username}",
        "error_type": "message",
        "valid_status": [200],
        "claimed_indicators": ["u/{username}", "overview for"],
        "missing_indicators": ["page not found", "unable to find"],
    },
    {
        "name": "Twitter (X)",
        "url": "https://x.com/{username}",
        "error_type": "status_code",
        "valid_status": [200],
    },
    {
        "name": "Instagram",
        "url": "https://www.instagram.com/{username}/",
        "error_type": "status_code",
        "valid_status": [200],
    },
    {
        "name": "GitLab",
        "url": "https://gitlab.com/{username}",
        "error_type": "status_code",
        "valid_status": [200],
    },
    {
        "name": "Dev.to",
        "url": "https://dev.to/{username}",
        "error_type": "status_code",
        "valid_status": [200],
    },
    {
        "name": "HackerNews",
        "url": "https://news.ycombinator.com/user?id={username}",
        "error_type": "message",
        "valid_status": [200],
        "claimed_indicators": ["user:", "created:"],
        "missing_indicators": ["No such user"],
    },
]


def load_sites_from_json(path: Path) -> List[SiteConfig]:
    """
    Load site configuration from a JSON file.
    """
    with path.open("r", encoding="utf-8") as f:
        raw = json.load(f)
    return [SiteConfig.from_dict(item) for item in raw if item.get("enabled", True)]


def get_default_sites() -> List[SiteConfig]:
    """Return the built-in default site list as SiteConfig objects."""
    return [SiteConfig.from_dict(item) for item in DEFAULT_SITES]


# ---------------------------------------------------------------------------
# OPSEC helpers
# ---------------------------------------------------------------------------

USER_AGENTS = [
    # Desktop
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",

    # Mobile
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/118.0.0.0 Mobile Safari/537.36",
]


def build_browser_headers(base_headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """
    Build realistic browser-like headers, merging any site-specific headers.
    """
    headers = {
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,*/*;q=0.8"
        ),
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }
    if base_headers:
        headers.update(base_headers)
    return headers


def detect_opsec_flags(body: str, status: Optional[int]) -> List[str]:
    """Detect basic OPSEC-related flags such as captcha/WAF pages."""
    flags: List[str] = []
    lower = (body or "").lower()

    if "captcha" in lower or "are you a human" in lower:
        flags.append("captcha_or_bot_challenge")

    if "cloudflare" in lower and "attention required" in lower:
        flags.append("cloudflare_waf")

    if status in (403, 429):
        flags.append("blocked_or_rate_limited")

    return flags


# ---------------------------------------------------------------------------
# Spinner + progress bar helper
# ---------------------------------------------------------------------------




# ---------------------------------------------------------------------------
# Core async implementation
# ---------------------------------------------------------------------------

async def _check_single_site(
    client: httpx.AsyncClient,
    username: str,
    site: SiteConfig,
    semaphore: asyncio.Semaphore,
    jitter_range: Optional[Tuple[float, float]] = None,
) -> UsernameResult:
    profile_url = site.url.format(username=username)
    http_status: Optional[int] = None
    response_time: Optional[float] = None
    resp: Optional[httpx.Response] = None

    async with semaphore:
        if jitter_range is not None:
            await asyncio.sleep(random.uniform(*jitter_range))

        start = time.perf_counter()
        try:
            resp = await client.get(
                profile_url,
                timeout=site.timeout,
                headers=site.headers or None,
            )
            http_status = resp.status_code
            response_time = time.perf_counter() - start
        except Exception as exc:
            logging.getLogger(__name__).debug(
                "Error checking %s on %s: %s", username, site.name, exc
            )
            return UsernameResult(
                username=username,
                site=site.name,
                profile_url=profile_url,
                exists=False,
                http_status=http_status,
                response_time=response_time,
                error=str(exc),
                inconclusive=True,
                opsec_flags=["request_error"],
            )

    exists = False
    inconclusive = False
    error: Optional[str] = None
    opsec_flags: List[str] = []

    try:
        body_text = resp.text if resp is not None else ""  # type: ignore[union-attr]
        opsec_flags.extend(detect_opsec_flags(body_text, http_status))

        if site.error_type == "status_code":
            if http_status in site.valid_status:
                exists = True
            else:
                exists = False

        elif site.error_type == "message":
            text = (body_text or "").lower()
            lowered_claimed = [
                c.lower().format(username=username) for c in site.claimed_indicators
            ]
            lowered_missing = [
                m.lower().format(username=username) for m in site.missing_indicators
            ]

            if any(m in text for m in lowered_missing):
                exists = False
            elif any(c in text for c in lowered_claimed):
                exists = True
            else:
                exists = False
                inconclusive = True
                error = "Content-based detection inconclusive"
        else:
            exists = False
            inconclusive = True
            error = f"Unknown error_type '{site.error_type}'"

    except Exception as exc:
        exists = False
        inconclusive = True
        error = f"Post-processing error: {exc}"
        opsec_flags.append("post_processing_error")

    return UsernameResult(
        username=username,
        site=site.name,
        profile_url=profile_url,
        exists=exists,
        http_status=http_status,
        response_time=response_time,
        error=error,
        inconclusive=inconclusive,
        opsec_flags=opsec_flags,
    )


async def enumerate_username(
    username: str,
    sites: Optional[Iterable[SiteConfig]] = None,
    max_concurrency: int = 10,
    global_timeout: float = 60.0,
    user_agent: Optional[str] = None,
    proxies: Optional[Dict[str, str]] = None,
    use_browser_headers: bool = False,
    jitter_range: Optional[Tuple[float, float]] = None,
    progress_callback: Optional[Callable[[], None]] = None,
) -> List[UsernameResult]:
    """
    Run a username enumeration against a list of sites.

    OPSEC-aware arguments:
      user_agent: if None, default; if set, overrides UA.
      proxies: optional httpx-style proxies dict (we collapse to a single URL for httpx>=0.27).
      use_browser_headers: if True, use realistic browser headers.
      jitter_range: if set, apply (min,max) random delay per request.
      progress_callback: if provided, called once per completed site.
    """
    if sites is None:
        sites = get_default_sites()

    sites_list = [s for s in sites if s.enabled]
    semaphore = asyncio.Semaphore(max_concurrency)

    # Default headers (will be merged with per-site later)
    base_headers: Dict[str, str] = {}
    if use_browser_headers:
        base_headers = build_browser_headers()
    if user_agent:
        base_headers["User-Agent"] = user_agent

    # httpx 0.27+ uses `proxy` (single URL) instead of `proxies`
    proxy: Optional[str] = None
    if proxies:
        try:
            proxy = next(iter(proxies.values()))
        except StopIteration:
            proxy = None

    async with httpx.AsyncClient(
        headers=base_headers,
        follow_redirects=True,
        proxy=proxy,
    ) as client:

        async def run_site(site: SiteConfig) -> UsernameResult:
            res = await _check_single_site(
                client,
                username,
                site,
                semaphore,
                jitter_range=jitter_range,
            )
            if progress_callback is not None:
                progress_callback()
            return res

        tasks = [run_site(site) for site in sites_list]

        try:
            results: List[UsernameResult] = await asyncio.wait_for(
                asyncio.gather(*tasks), timeout=global_timeout
            )
        except asyncio.TimeoutError:
            logging.getLogger(__name__).warning(
                "Global timeout reached while scanning username '%s'", username
            )
            return []

    return results


# ---------------------------------------------------------------------------
# Helper: exposure summary (basic)
# ---------------------------------------------------------------------------

def summarize_results(results: Iterable[UsernameResult]) -> Dict[str, Any]:
    results = list(results)
    total_sites = len(results)
    hits = [r for r in results if r.exists]
    errors = [r for r in results if r.error]
    inconclusive = [r for r in results if r.inconclusive]

    hit_count = len(hits)
    error_count = len(errors)
    inconclusive_count = len(inconclusive)

    exposure_score = 0
    if total_sites > 0:
        exposure_score = min(100, int((hit_count / total_sites) * 100))

    return {
        "total_sites": total_sites,
        "hit_count": hit_count,
        "error_count": error_count,
        "inconclusive_count": inconclusive_count,
        "exposure_score": exposure_score,
        "hits": [r.to_dict() for r in hits],
    }


# ---------------------------------------------------------------------------
# Advanced helpers: alias confidence & weighted exposure v2.0
# ---------------------------------------------------------------------------

def levenshtein(a: str, b: str) -> int:
    """Simple Levenshtein distance implementation."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    len_a, len_b = len(a), len(b)
    dp = [[0] * (len_b + 1) for _ in range(len_a + 1)]

    for i in range(len_a + 1):
        dp[i][0] = i
    for j in range(len_b + 1):
        dp[0][j] = j

    for i in range(1, len_a + 1):
        for j in range(1, len_b + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            dp[i][j] = min(
                dp[i - 1][j] + 1,      # deletion
                dp[i][j - 1] + 1,      # insertion
                dp[i - 1][j - 1] + cost,  # substitution
            )
    return dp[len_a][len_b]


def compute_alias_confidence(
    base_username: str,
    alias: str,
    platform_count: int,
) -> (float, str):
    """
    Compute an alias confidence score [0.0, 1.0] and label.
    Factors:
      - similarity to base username (Levenshtein-based)
      - common OSINT alias patterns (prefix/suffix)
      - number of platforms where alias has hits
    """
    base = base_username.lower()
    al = alias.lower()

    dist = levenshtein(base, al)
    max_len = max(len(base), len(al)) or 1
    similarity = 1.0 - (dist / max_len)

    score = similarity

    # Common prefixes/suffixes
    prefix_bonus_tags = ("its", "iam", "the")
    suffix_bonus_tags = ("1", "01", "123", "_1", "_01")

    if al.startswith(prefix_bonus_tags) or al.endswith(suffix_bonus_tags):
        score += 0.1

    # Multi-platform strength
    if platform_count >= 3:
        score += 0.15
    elif platform_count == 2:
        score += 0.08

    score = max(0.0, min(1.0, score))

    if score >= 0.8:
        label = "HIGH"
    elif score >= 0.5:
        label = "MEDIUM"
    else:
        label = "LOW"

    return score, label


def classify_site(site_name: str) -> str:
    """Rough classification of site type based on its name."""
    n = site_name.lower()

    if any(k in n for k in [
        "twitter", "x)", "instagram", "tiktok", "facebook",
        "reddit", "snapchat", "pinterest", "vk", "weibo",
        "telegram", "whatsapp"
    ]):
        return "social"
    if any(k in n for k in [
        "github", "gitlab", "bitbucket", "dev.to", "stack",
        "kaggle", "docker", "pypi", "codepen", "replit", "hashnode"
    ]):
        return "dev"
    if any(k in n for k in ["porn", "xvideo", "onlyfans", "xhamster", "adult"]):
        return "adult"
    if any(k in n for k in ["coin", "crypto", "binance", "kraken", "blockchain"]):
        return "crypto"
    return "other"


def compute_weighted_exposure_v2(
    base_results: Iterable[UsernameResult],
    alias_results: Iterable[UsernameResult],
    total_site_count: int,
) -> int:
    """
    Compute a weighted exposure score [0-100].
    - Base username hits counted at full weight.
    - Alias hits counted at 0.7x weight.
    - Max capacity approximated as total_sites * max_weight.
    """
    weights = {
        "social": 3,
        "dev": 2,
        "adult": 4,
        "crypto": 5,
        "other": 1,
    }
    max_weight = max(weights.values()) if weights else 5
    if total_site_count <= 0:
        return 0

    raw = 0.0

    # Base hits
    for r in base_results:
        if r.exists:
            cat = classify_site(r.site)
            raw += weights.get(cat, 1)

    # Alias hits (slightly discounted)
    for r in alias_results:
        if r.exists:
            cat = classify_site(r.site)
            raw += 0.7 * weights.get(cat, 1)

    capacity = total_site_count * max_weight
    if capacity <= 0:
        return 0

    score = int(min(100, (raw / capacity) * 100))
    return score


# ---------------------------------------------------------------------------
# HTML report generator
# ---------------------------------------------------------------------------

def generate_html_report(
    username: str,
    results: List[UsernameResult],
    summary_basic: Dict[str, Any],
    alias_summary: Dict[str, Any],
    weighted_score_v2: int,
    output_path: Path,
) -> None:
    """Generate an HTML report with light/dark theme toggle."""
    primary_hits = [r for r in results if r.exists]

    matched_aliases: Dict[str, Dict[str, Any]] = alias_summary.get("matched", {})
    unmatched_aliases: List[str] = alias_summary.get("unmatched", [])

    def esc(s: Any) -> str:
        return html.escape(str(s)) if s is not None else ""

    html_content = f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
  <meta charset="utf-8">
  <title>SocialCrawl Report - {esc(username)}</title>
  <style>
    :root {{
      --bg-light: #f9fafb;
      --bg-card-light: #ffffff;
      --text-light: #111827;
      --muted-light: #6b7280;
      --accent-light: #0f766e;

      --bg-dark: #020617;
      --bg-card-dark: #020617;
      --text-dark: #e5e7eb;
      --muted-dark: #9ca3af;
      --accent-dark: #22d3ee;

      --radius: 10px;
      --shadow: 0 10px 30px rgba(0,0,0,0.35);
    }}

    :root[data-theme='light'] {{
      --bg: var(--bg-light);
      --bg-card: var(--bg-card-light);
      --text: var(--text-light);
      --muted: var(--muted-light);
      --accent: var(--accent-light);
    }}

    :root[data-theme='dark'] {{
      --bg: var(--bg-dark);
      --bg-card: var(--bg-card-dark);
      --text: var(--text-dark);
      --muted: var(--muted-dark);
      --accent: var(--accent-dark);
    }}

    body {{
      margin: 0;
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: radial-gradient(circle at top, #0f172a 0, var(--bg) 45%);
      color: var(--text);
      padding: 2rem;
    }}

    .container {{
      max-width: 1000px;
      margin: 0 auto;
    }}

    .header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 1.5rem;
    }}

    .title {{
      font-size: 1.8rem;
      font-weight: 700;
    }}

    .subtitle {{
      color: var(--muted);
      font-size: 0.95rem;
    }}

    .theme-toggle button {{
      border-radius: 999px;
      border: 1px solid var(--muted);
      padding: 0.3rem 0.75rem;
      background: transparent;
      color: var(--text);
      font-size: 0.85rem;
      cursor: pointer;
      margin-left: 0.25rem;
    }}

    .theme-toggle button.active {{
      background: var(--accent);
      color: #020617;
      border-color: var(--accent);
    }}

    .card {{
      background: radial-gradient(circle at top left, #0f172a 0, var(--bg-card) 45%);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      padding: 1.25rem 1.5rem;
      margin-bottom: 1rem;
      border: 1px solid rgba(148, 163, 184, 0.3);
    }}

    .card h2 {{
      margin-top: 0;
      font-size: 1.2rem;
      margin-bottom: 0.75rem;
    }}

    .metrics {{
      display: flex;
      flex-wrap: wrap;
      gap: 0.75rem;
    }}

    .metric {{
      min-width: 140px;
      padding: 0.4rem 0.75rem;
      border-radius: 999px;
      background: rgba(15, 23, 42, 0.5);
      font-size: 0.85rem;
    }}

    .metric span.label {{
      color: var(--muted);
      margin-right: 0.3rem;
    }}

    a {{
      color: var(--accent);
      text-decoration: none;
    }}
    a:hover {{
      text-decoration: underline;
    }}

    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.88rem;
    }}

    th, td {{
      padding: 0.4rem 0.5rem;
      border-bottom: 1px solid rgba(148, 163, 184, 0.3);
      text-align: left;
    }}

    th {{
      font-weight: 600;
      color: var(--muted);
      background: rgba(15, 23, 42, 0.6);
    }}

    .tag {{
      display: inline-block;
      padding: 0.15rem 0.5rem;
      border-radius: 999px;
      font-size: 0.75rem;
      margin-right: 0.25rem;
    }}

    .tag-primary {{
      background: rgba(34, 211, 238, 0.12);
      color: var(--accent);
      border: 1px solid rgba(34, 211, 238, 0.65);
    }}

    .tag-good {{
      background: rgba(34, 197, 94, 0.15);
      color: #4ade80;
      border: 1px solid rgba(34,197,94,0.6);
    }}

    .tag-warn {{
      background: rgba(250, 204, 21, 0.12);
      color: #facc15;
      border: 1px solid rgba(250,204,21,0.5);
    }}

    .tag-bad {{
      background: rgba(248, 113, 113, 0.15);
      color: #fca5a5;
      border: 1px solid rgba(248,113,113,0.5);
    }}

    .alias-block {{
      margin-bottom: 0.75rem;
      padding-bottom: 0.5rem;
      border-bottom: 1px dashed rgba(148, 163, 184, 0.35);
    }}

    .alias-name {{
      font-weight: 600;
      font-size: 0.98rem;
    }}

    .muted {{
      color: var(--muted);
      font-size: 0.85rem;
    }}
  </style>
</head>
<body>
  <div class="container">
    <header class="header">
      <div>
        <div class="title">SocialCrawl OSINT Report</div>
        <div class="subtitle">Username &amp; alias exposure assessment</div>
      </div>
      <div class="theme-toggle">
        <span class="muted">Theme:</span>
        <button id="btn-light" onclick="setTheme('light')">Light</button>
        <button id="btn-dark" onclick="setTheme('dark')" class="active">Dark</button>
      </div>
    </header>

    <section class="card">
      <h2>Summary</h2>
      <div class="metrics">
        <div class="metric">
          <span class="label">Username</span>
          <span>{esc(username)}</span>
        </div>
        <div class="metric">
          <span class="label">Sites Checked</span>
          <span>{summary_basic.get('total_sites', 0)}</span>
        </div>
        <div class="metric">
          <span class="label">Profiles Found</span>
          <span>{summary_basic.get('hit_count', 0)}</span>
        </div>
        <div class="metric">
          <span class="label">Errors</span>
          <span>{summary_basic.get('error_count', 0)}</span>
        </div>
        <div class="metric">
          <span class="label">Inconclusive</span>
          <span>{summary_basic.get('inconclusive_count', 0)}</span>
        </div>
        <div class="metric">
          <span class="label">Exposure v1</span>
          <span>{summary_basic.get('exposure_score', 0)} / 100</span>
        </div>
        <div class="metric">
          <span class="label">Exposure v2</span>
          <span>{weighted_score_v2} / 100</span>
        </div>
      </div>
    </section>

    <section class="card">
      <h2>Primary Username Matches</h2>
      {"<p class='muted'>No direct matches found for this username.</p>" if not primary_hits else ""}
"""

    if primary_hits:
        html_content += """
      <table>
        <thead>
          <tr>
            <th>Site</th>
            <th>Status</th>
            <th>Profile URL</th>
          </tr>
        </thead>
        <tbody>
"""
        for r in primary_hits:
            html_content += f"""
          <tr>
            <td>{esc(r.site)}</td>
            <td><span class="tag tag-good">FOUND</span></td>
            <td><a href="{esc(r.profile_url)}" target="_blank">{esc(r.profile_url)}</a></td>
          </tr>
"""
        html_content += """
        </tbody>
      </table>
"""

    html_content += """
    </section>

    <section class="card">
      <h2>Alias Discovery</h2>
"""

    matched_aliases = alias_summary.get("matched", {})
    unmatched_aliases = alias_summary.get("unmatched", [])

    if matched_aliases:
        html_content += """
      <h3>Aliases With Matches</h3>
"""
        for alias, data in matched_aliases.items():
            conf = data.get("confidence_score", 0.0)
            label = data.get("confidence_label", "UNKNOWN")
            platforms = data.get("platform_count", 0)
            hits = data.get("hits", [])

            if label == "HIGH":
                tag_class = "tag-good"
            elif label == "MEDIUM":
                tag_class = "tag-warn"
            else:
                tag_class = "tag-primary"

            html_content += f"""
      <div class="alias-block">
        <div class="alias-name">{esc(alias)}
          <span class="tag {tag_class}">Confidence: {esc(label)}</span>
          <span class="tag tag-primary">{platforms} platform(s)</span>
        </div>
"""
            if hits:
                html_content += "<div class='muted'>Matches:</div>\n<ul>\n"
                for h in hits:
                    html_content += f"""
          <li>
            <span>{esc(h.site)}</span> —
            <a href="{esc(h.profile_url)}" target="_blank">{esc(h.profile_url)}</a>
          </li>
"""
                html_content += "</ul>\n"

            html_content += "</div>\n"
    else:
        html_content += "<p class='muted'>No aliases with matches were discovered.</p>\n"

    html_content += """
      <h3>Aliases With No Matches</h3>
"""
    if unmatched_aliases:
        html_content += "<p class='muted'>" + ", ".join(esc(a) for a in unmatched_aliases) + "</p>\n"
    else:
        html_content += "<p class='muted'>None.</p>\n"

    html_content += """
    </section>
  </div>

  <script>
    function applyTheme(theme) {
      document.documentElement.setAttribute('data-theme', theme);
      localStorage.setItem('sc-theme', theme);
      var btnLight = document.getElementById('btn-light');
      var btnDark = document.getElementById('btn-dark');
      if (theme === 'light') {
        btnLight.classList.add('active');
        btnDark.classList.remove('active');
      } else {
        btnDark.classList.add('active');
        btnLight.classList.remove('active');
      }
    }

    function setTheme(theme) {
      applyTheme(theme);
    }

    (function() {
      var saved = localStorage.getItem('sc-theme') || 'dark';
      applyTheme(saved);
    })();
  </script>
</body>
</html>
"""

    output_path.write_text(html_content, encoding="utf-8")


# ---------------------------------------------------------------------------
# CLI helpers
# ---------------------------------------------------------------------------

def _configure_logging(verbose: bool = False) -> None:
    """
    Silent logging unless --verbose is used.
    """
    if verbose:
        level = logging.DEBUG
    else:
        level = logging.CRITICAL  # fully silent

    # Main logging config
    logging.basicConfig(
        level=level,
        format="[%(asctime)s] [%(levelname)s] %(name)s: %(message)s",
    )

    # Silence noisy libraries
    logging.getLogger("httpx").setLevel(logging.CRITICAL)
    logging.getLogger("httpcore").setLevel(logging.CRITICAL)
    logging.getLogger("asyncio").setLevel(logging.CRITICAL)


def _parse_args() -> Any:
    import argparse

    parser = argparse.ArgumentParser(
        description="username enumeration (SocialCrawl)."
    )
    parser.add_argument(
        "--username",
        "-u",
        required=True,
        help="Username to search for across sites.",
    )
    parser.add_argument(
        "--sites-json",
        "-s",
        type=str,
        help="Optional path to JSON file defining sites. Overrides defaults.",
    )
    parser.add_argument(
        "--max-concurrency",
        "-c",
        type=int,
        default=10,
        help="Maximum concurrent HTTP requests (default: 10).",
    )
    parser.add_argument(
        "--global-timeout",
        "-t",
        type=float,
        default=60.0,
        help="Global timeout for the entire scan in seconds (default: 60).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output JSON instead of human-readable text.",
    )
    parser.add_argument(
        "--aliases",
        action="store_true",
        help="Scan for common alias variations (Light Mode).",
    )
    parser.add_argument(
        "--html-report",
        action="store_true",
        help="Generate an HTML report in ./reports/<username>_report.html.",
    )
    parser.add_argument(
        "--stealth",
        action="store_true",
        help="Enable stealth mode (lower concurrency, jitter, browser headers, random UA).",
    )
    parser.add_argument(
        "--proxy",
        type=str,
        help="Optional proxy URL (e.g. socks5://127.0.0.1:9050).",
    )
    parser.add_argument(
        "--tor",
        action="store_true",
        help="Shortcut for Tor proxy at socks5://127.0.0.1:9050.",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging.",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# CLI main
# ---------------------------------------------------------------------------

def _cli_main() -> None:
    args = _parse_args()
    _configure_logging(verbose=args.verbose)

    logger = logging.getLogger("socialcrawl")

    username = args.username.strip()
    if not username:
        raise SystemExit("Username cannot be empty.")

    # LEGAL / OPSEC banner for stealth use
    if args.stealth or args.tor or args.proxy:
        print("\033[93m[LEGAL / OPSEC NOTICE]\033[0m")
        print(
            "This tool is for lawful OSINT use only. "
            "Ensure you have proper authorization before scanning targets.\n"
        )

    # Load sites
    if args.sites_json:
        sites_path = Path(args.sites_json)
        if not sites_path.is_file():
            raise SystemExit(f"Sites JSON file not found: {sites_path}")
        logger.info("Loading sites from %s", sites_path)
        sites = load_sites_from_json(sites_path)
    else:
        logger.info("Using built-in default sites list.")
        sites = get_default_sites()

    if not sites:
        raise SystemExit("No sites loaded. Check your sites.json.")

    # OPSEC config
    opsec_user_agent = random.choice(USER_AGENTS)
    use_browser_headers = args.stealth
    jitter_range = (0.3, 1.5) if args.stealth else None

    max_concurrency = args.max_concurrency
    if args.stealth and max_concurrency > 4:
        max_concurrency = 4  # stealth: reduce concurrency

    # Proxy / Tor settings
    proxies: Optional[Dict[str, str]] = None
    if args.tor:
        proxies = {"all://": "socks5://127.0.0.1:9050"}
    elif args.proxy:
        proxies = {"all://": args.proxy}

    logger.info(
        "Checking username '%s' across %d sites (stealth=%s, proxy=%s, tor=%s)...",
        username,
        len(sites),
        args.stealth,
        bool(args.proxy),
        args.tor,
    )

    total_sites = len(sites)

    # Start spinner + progress bar for the main username scan (not in JSON mode)
    progress_increment: Optional[Callable[[], None]] = None
    progress_stop: Optional[Callable[[], None]] = None
    if not args.json and total_sites > 0:
        progress_increment, progress_stop = start_progress_spinner(total_sites)

    # Run main scan
    results = asyncio.run(
        enumerate_username(
            username=username,
            sites=sites,
            max_concurrency=max_concurrency,
            global_timeout=args.global_timeout,
            user_agent=opsec_user_agent,
            proxies=proxies,
            use_browser_headers=use_browser_headers,
            jitter_range=jitter_range,
            progress_callback=progress_increment,
        )
    )

    if progress_stop is not None:
        progress_stop()

    # JSON mode (no alias/HTML logic for now)
    if args.json:
        payload = {
            "username": username,
            "results": [r.to_dict() for r in results],
            "summary": summarize_results(results),
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return

    # -----------------------------------------------------------------------
    # Clean text output (no edges, cyan title bar)
    # -----------------------------------------------------------------------

    RESET = "\033[0m"
    BOLD = "\033[1m"
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    WHITE = "\033[96m"

    summary = summarize_results(results)
    bar = "=" * 60

    # Title bar
    title = " USERNAME EXPOSURE REPORT "
    print("\n" + CYAN + bar + RESET)
    padding = (60 - len(title)) // 2
    print(CYAN + "=" * padding + title + "=" * (60 - len(title) - padding) + RESET)
    print(CYAN + bar + RESET + "\n")

    # Header info
    print(f"{WHITE}Username:{RESET}        {username}")
    print(f"{WHITE}Sites Checked:{RESET}   {summary['total_sites']}")
    print(f"{WHITE}Profiles Found:{RESET}  {GREEN}{summary['hit_count']}{RESET}")
    print(f"{WHITE}Errors:{RESET}          {YELLOW}{summary['error_count']}{RESET}")
    print(f"{WHITE}Inconclusive:{RESET}    {YELLOW}{summary['inconclusive_count']}{RESET}")
    print(f"{WHITE}Exposure Score v1:{RESET}  {summary['exposure_score']} / 100\n")

    # Group results
    found = [r for r in results if r.exists]
    not_found = [r for r in results if not r.exists and not r.error]
    errors = [r for r in results if r.error]

    # FOUND section
    print(GREEN + BOLD + "FOUND ON" + RESET)
    if found:
        for r in found:
            print(f"  {GREEN}✓{RESET} {WHITE}{r.site:<15}{RESET} {r.profile_url}")
    else:
        print("  None")
    print()

    # NOT FOUND section
    print(RED + BOLD + "NOT FOUND" + RESET)
    if not_found:
        for r in not_found:
            print(f"  {RED}✗{RESET} {WHITE}{r.site}{RESET}")
    else:
        print("  None")
    print()

    # ERRORS section
    print(YELLOW + BOLD + "ERRORS" + RESET)
    if errors:
        for r in errors:
            err_txt = (r.error or "Unknown")[:60]
            print(f"  {YELLOW}!{RESET} {WHITE}{r.site:<15}{RESET} ({err_txt})")
    else:
        print("  None")
    print()

    # OPSEC SUMMARY
    opsec_issues = [r for r in results if r.opsec_flags]
    if opsec_issues:
        print(CYAN + bar + RESET)
        opsec_title = " OPSEC SUMMARY "
        padding = (60 - len(opsec_title)) // 2
        print(
            CYAN
            + "=" * padding
            + opsec_title
            + "=" * (60 - len(opsec_title) - padding)
            + RESET
        )
        print(CYAN + bar + RESET + "\n")

        for r in opsec_issues:
            flags_str = ", ".join(r.opsec_flags)
            print(
                f"{YELLOW}!{RESET} {WHITE}{r.site:<15}{RESET} "
                f"flags: {YELLOW}{flags_str}{RESET}"
            )
        print()

    # Prepare alias summary container
    alias_summary: Dict[str, Any] = {"matched": {}, "unmatched": []}
    alias_hits_flat: List[UsernameResult] = []

    # -----------------------------------------------------------------------
    # Alias Discovery (Light Mode) with final summary
    # -----------------------------------------------------------------------
    if args.aliases:
        print(CYAN + bar + RESET)
        alias_title = " ALIAS DISCOVERY (Light Mode) "
        padding = (60 - len(alias_title)) // 2
        print(
            CYAN
            + "=" * padding
            + alias_title
            + "=" * (60 - len(alias_title) - padding)
            + RESET
        )
        print(CYAN + bar + RESET + "\n")

        alias_list = generate_aliases(username)
        if not alias_list:
            print(f"{YELLOW}No alias patterns generated for this username.{RESET}")
        else:
            print(f"{WHITE}Aliases Generated:{RESET} {len(alias_list)}")
            print(f"{WHITE}Scanning aliases asynchronously...{RESET}\n")

            alias_scan_results: Dict[str, List[UsernameResult]] = {}
            for alias in alias_list:
                alias_scan = asyncio.run(
                    enumerate_username(
                        username=alias,
                        sites=sites,
                        max_concurrency=max_concurrency,
                        global_timeout=args.global_timeout,
                        user_agent=opsec_user_agent,
                        proxies=proxies,
                        use_browser_headers=use_browser_headers,
                        jitter_range=jitter_range,
                        progress_callback=None,  # no spinner per alias
                    )
                )
                alias_scan_results[alias] = alias_scan

            matched_aliases: Dict[str, Dict[str, Any]] = {}
            unmatched_aliases: List[str] = []

            for alias, scans in alias_scan_results.items():
                hits = [r for r in scans if r.exists]
                if hits:
                    platform_count = len(hits)
                    score, label = compute_alias_confidence(
                        base_username=username,
                        alias=alias,
                        platform_count=platform_count,
                    )
                    matched_aliases[alias] = {
                        "confidence_score": score,
                        "confidence_label": label,
                        "platform_count": platform_count,
                        "hits": hits,
                    }
                    alias_hits_flat.extend(hits)
                else:
                    unmatched_aliases.append(alias)

            alias_summary["matched"] = matched_aliases
            alias_summary["unmatched"] = unmatched_aliases

            print(CYAN + "=" * 60 + RESET)
            fs_title = " FINAL ALIAS SUMMARY "
            padding = (60 - len(fs_title)) // 2
            print(
                CYAN
                + "=" * padding
                + fs_title
                + "=" * (60 - len(fs_title) - padding)
                + RESET
            )
            print(CYAN + "=" * 60 + RESET + "\n")

            print(f"{WHITE}Primary Username Checked:{RESET}")
            print(f"    {username}\n")

            print(f"{GREEN}{BOLD}Aliases With Matches:{RESET}")
            if matched_aliases:
                for alias, data in matched_aliases.items():
                    conf_label = data["confidence_label"]
                    platform_count = data["platform_count"]
                    hits = data["hits"]

                    print(
                        f"    {GREEN}{alias}{RESET} "
                        f"({conf_label} confidence, {platform_count} platform(s))"
                    )
                    for r in hits:
                        print(
                            f"        {GREEN}✓{RESET} "
                            f"{WHITE}{r.site:<15}{RESET} {r.profile_url}"
                        )
                    print()
            else:
                print("    None\n")

            print(f"{YELLOW}{BOLD}Aliases With No Matches:{RESET}")
            if unmatched_aliases:
                for alias in unmatched_aliases:
                    print(f"    {YELLOW}{alias}{RESET}")
            else:
                print("    None")
            print()

    # -----------------------------------------------------------------------
    # Weighted Exposure v2.0 and HTML report (optional)
    # -----------------------------------------------------------------------
    weighted_v2 = compute_weighted_exposure_v2(
        base_results=results,
        alias_results=alias_hits_flat,
        total_site_count=len(sites),
    )

    print(f"{WHITE}Exposure Score v2.0 (weighted + aliases):{RESET} {weighted_v2} / 100\n")

    if args.html_report:
        reports_dir = Path("reports")
        reports_dir.mkdir(parents=True, exist_ok=True)
        output_path = reports_dir / f"{username}_report.html"
        generate_html_report(
            username=username,
            results=results,
            summary_basic=summary,
            alias_summary=alias_summary,
            weighted_score_v2=weighted_v2,
            output_path=output_path,
        )
        print(f"{WHITE}HTML report written to:{RESET} {output_path}\n")


if __name__ == "__main__":
    _cli_main()
