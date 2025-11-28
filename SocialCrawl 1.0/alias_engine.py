"""
alias_engine.py

Light Mode alias generator for SocialCrawl.

Generates a small set (up to ~20) of realistic username variations
to help discover likely aliases across platforms, without creating
huge noisy lists.

Example:
    from alias_engine import generate_aliases
    aliases = generate_aliases("techwolf")
"""

from __future__ import annotations
from typing import List, Set


def generate_aliases(username: str) -> List[str]:
    """
    Generate realistic username variations (Light Mode).

    Strategy:
    - Simple prefixes/suffixes
    - Separator variants
    - Limited leetspeak substitutions
    - De-duplicated, capped at ~20 entries
    """
    base = username.strip()
    if not base:
        return []

    base_lower = base.lower()
    aliases: Set[str] = set()

    # 1. Common suffixes
    suffixes = ["1", "01", "123", "_1", "_01"]
    for s in suffixes:
        aliases.add(f"{base_lower}{s}")

    # 2. Common prefixes
    prefixes = ["its", "iam", "the"]
    for p in prefixes:
        aliases.add(f"{p}{base_lower}")
        aliases.add(f"{p}_{base_lower}")

    # 3. Separator in the middle (if long enough)
    if len(base_lower) >= 5:
        mid = len(base_lower) // 2
        left, right = base_lower[:mid], base_lower[mid:]
        for sep in ["_", ".", "-"]:
            aliases.add(f"{left}{sep}{right}")

    # 4. Limited leetspeak substitutions (single replacement each)
    leet_map = {
        "a": "4",
        "e": "3",
        "i": "1",
        "o": "0",
        "s": "5",
    }
    for orig, sub in leet_map.items():
        if orig in base_lower:
            aliases.add(base_lower.replace(orig, sub, 1))

    # 5. Remove original if present
    if base_lower in aliases:
        aliases.discard(base_lower)

    # Light Mode cap
    out = list(aliases)
    out.sort()
    return out[:20]