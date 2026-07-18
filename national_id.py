"""Data-driven national-ID detection: one registry row per country, validated by python-stdnum."""
from __future__ import annotations

import os
import re
from typing import Any, Iterator, NamedTuple, Optional

try:
    from stdnum import get_cc_module
except ImportError:
    get_cc_module = None

# region -> (stdnum module, candidate pattern, human label). Patterns are permissive
# over-matchers; stdnum is the validation authority. Extend by adding a row.
REGISTRY: dict[str, tuple[str, str, str]] = {
    "NO": ("fodselsnummer", r"\d{6}[ -]?\d{5}",            "fødselsnummer"),
    "SE": ("personnummer",  r"(?:\d{8}|\d{6})[-+]?\d{4}",  "personnummer"),
    "DK": ("cpr",           r"\d{6}-?\d{4}",               "CPR"),
    "FI": ("hetu",          r"\d{6}[-+ABCDEFYXWVU]\d{3}[0-9A-Za-z]", "HETU"),
    "NL": ("bsn",           r"\d{4}\.?\d{2}\.?\d{2,3}",    "BSN"),
    "US": ("ssn",           r"\d{3}-?\d{2}-?\d{4}",        "SSN"),
    "DE": ("idnr",          r"\d{2} ?\d{3} ?\d{3} ?\d{3}", "IdNr"),
}

_MODULE_CACHE: dict[str, Any] = {}


def available() -> bool:
    return get_cc_module is not None


def _module(region: str):
    row = REGISTRY.get(region)
    if row is None or get_cc_module is None:
        return None
    if region not in _MODULE_CACHE:
        _MODULE_CACHE[region] = get_cc_module(region.lower(), row[0])
    return _MODULE_CACHE[region]


def validate(value: str, region: str) -> bool:
    mod = _module(region)
    return bool(mod and mod.is_valid(value))


def classify(value: str, regions: list[str]) -> Optional[tuple[str, str]]:
    for region in regions:
        if validate(value, region):
            return region, REGISTRY[region][2]
    return None


def _locale_region() -> str:
    for var in ("LC_ALL", "LC_CTYPE", "LANG"):
        match = re.match(r"[a-z]+_([A-Z]{2})", os.environ.get(var, "") or "")
        if match:
            return match.group(1)
    return ""


def resolve_id_regions(spec: str, phone_region: str) -> tuple[list[str], list[str]]:
    """Turn a --id-regions spec (auto|all|none|CSV) into (regions, unknown_codes)."""
    spec = (spec or "auto").strip()
    low = spec.lower()
    if low == "none":
        return [], []
    if low == "all":
        return list(REGISTRY), []
    if low == "auto":
        region = _locale_region() or (phone_region or "").upper()
        return ([region] if region in REGISTRY else []), []
    wanted = list(dict.fromkeys(c.strip().upper() for c in spec.split(",") if c.strip()))
    known = [c for c in wanted if c in REGISTRY]
    unknown = [c for c in wanted if c not in REGISTRY]
    return known, unknown


class Hit(NamedTuple):
    value: str
    country: str
    type: str
    start: int


def _compiled(regions: list[str]):
    for region in regions:
        row = REGISTRY.get(region)
        if row:
            yield region, row[2], re.compile(r"(?<![A-Za-z0-9])(?:" + row[1] + r")(?![A-Za-z0-9])")


def scan_text(text: str, regions: list[str]) -> Iterator[Hit]:
    for region, label, pattern in _compiled(regions):
        for match in pattern.finditer(text):
            value = match.group(0)
            if validate(value, region):
                yield Hit(value, region, label, match.start())


def gitleaks_rules(regions: list[str]) -> list[tuple[str, str]]:
    """(rule_id, RE2 regex) per region; group 2 is the candidate (use secretGroup = 2)."""
    rules = []
    for region in regions:
        row = REGISTRY.get(region)
        if row:
            regex = r"(^|[^A-Za-z0-9])(" + row[1] + r")([^A-Za-z0-9]|$)"
            rules.append((f"national-id-{region}", regex))
    return rules
