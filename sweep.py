#!/usr/bin/env python3
"""
sweep.py — find leaked personal information across all your GitHub repos.

For each repo (cloned/updated under work/):
  1. gitleaks over the FULL git history: secrets (API keys, tokens, passwords),
     your own watchlist terms from personal.txt, and national ID numbers for the
     selected regions (validated afterwards in Python via python-stdnum)
  2. Presidio (NER) over prose files in the current tree: names, locations,
     emails, phone numbers, credit cards, IBANs, public IP addresses
  3. Fast regex scan over all text files: email, phone, card, nat.ID, IP
  4. Commit identities (author/committer) and file paths in history that match
     your watchlist terms

Report: reports/report-<timestamp>.md + .json (both gitignored).

Sensitive values (credit cards, national IDs, secrets) are masked in the report
by default — pass --raw to write full values. Only scans repos you can access
via `gh`; nothing leaves your machine except GitHub API calls and clones.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import ipaddress
import json
import logging
import os
import re
import shutil
import subprocess
import sys
from bisect import bisect_right
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

import national_id
from leak_sweep_reporting import (
    finding_count,
    redact,
    redact_extras,
    redact_results,
    render_md,
)

try:
    import phonenumbers  # pulled in by presidio-analyzer; also used directly
except ImportError:
    phonenumbers = None

MODULE_ROOT = Path(__file__).resolve().parent
__version__ = "1.0.0"


def _data_root() -> Path:
    if (MODULE_ROOT / "personal.example.txt").is_file():
        return MODULE_ROOT
    return (Path.home() / ".leak-sweep").resolve()


ROOT = _data_root()
WORK = ROOT / "work"
REPORTS = ROOT / "reports"
PERSONAL_FILE = ROOT / "personal.txt"


def _github_repo_from_url(value: str) -> str:
    match = re.search(r"github\.com[:/](.+?)(?:\.git)?$", value.strip())
    return match.group(1) if match else ""


def _self_repo() -> str:
    """The tool's own GitHub repo (owner/name from origin) — never scan it."""
    p = subprocess.run(["git", "-C", str(MODULE_ROOT), "remote", "get-url", "origin"],
                       capture_output=True, text=True)
    return _github_repo_from_url(p.stdout)

PROSE_EXT = {".md", ".txt", ".rst", ".html", ".htm", ".csv", ".json", ".ipynb",
             ".yaml", ".yml", ".tex", ".org", ".adoc"}
SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".venv", "venv",
             "__pycache__", ".next", ".terraform", "target", ".tox"}
MAX_FILE_BYTES = 512 * 1024
MAX_NER_FILES = 400
MAX_NER_CHARS = 200_000
HUGE_REPO_KB = 2_000_000      # ~2 GB: repo is skipped with a notice
MAX_ACTIONS_ZIP_BYTES = 100 * 1024 * 1024
MAX_ACTION_LOG_BYTES = 20 * 1024 * 1024
MAX_ACTIONS_UNPACKED_BYTES = 200 * 1024 * 1024

NER_ENTITIES = ["EMAIL_ADDRESS", "PHONE_NUMBER", "PERSON", "LOCATION",
                "CREDIT_CARD", "IBAN_CODE", "IP_ADDRESS"]

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
BORING_EMAIL_RE = re.compile(
    r"(@example\.(com|org|net)$|@users\.noreply\.github\.com$|^git@github\.com$"
    r"|^noreply@|^no-reply@|@(localhost|test|invalid)\.)", re.I)
# email-looking strings that are really filenames (logo@2x.png etc.)
FILE_EXT_TLDS = {"png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "css", "js",
                 "mjs", "cjs", "ts", "tsx", "jsx", "map", "html", "json", "lock",
                 "yml", "yaml", "py", "sh", "xml", "gz", "zip", "min", "scss"}
CC_RE = re.compile(r"(?<!\d)(?:4\d{15}|5[1-5]\d{14}|3[47]\d{13})(?!\d)")
IP_RE = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")
PERSON_OK_RE = re.compile(r"[A-Za-zÆØÅæøåÉéÜü' .\-]{4,60}")

# Committed binary types worth checking for embedded metadata (needs exiftool).
BINARY_META_EXT = {".jpg", ".jpeg", ".png", ".tif", ".tiff", ".heic", ".heif",
                   ".webp", ".gif", ".pdf", ".docx", ".xlsx", ".pptx", ".doc",
                   ".xls", ".ppt", ".mp4", ".mov", ".m4a", ".mp3"}
GPS_FIELDS = ("GPSLatitude", "GPSLongitude", "GPSPosition")


def run(cmd, cwd=None, check=True, timeout=300):
    p = subprocess.run([str(c) for c in cmd], cwd=cwd, text=True, capture_output=True,
                       timeout=timeout)
    if check and p.returncode != 0:
        raise RuntimeError(
            f"command failed ({p.returncode}): {' '.join(str(c) for c in cmd)}\n"
            f"{(p.stderr or p.stdout or '')[:2000]}")
    return p


def _windows_user_sid() -> str:
    p = subprocess.run(
        ["whoami.exe", "/user", "/fo", "csv", "/nh"],
        capture_output=True,
        text=True,
    )
    match = re.search(r"S-\d(?:-\d+)+", p.stdout) if p.returncode == 0 else None
    return match.group(0) if match else ""


def restrict_private_path(path: Path, directory: bool = False) -> None:
    """Restrict sensitive paths to the current user on POSIX and Windows."""
    if os.name != "nt":
        path.chmod(0o700 if directory else 0o600)
        return
    sid = _windows_user_sid()
    if not sid:
        raise RuntimeError("could not determine the current Windows user SID")
    inheritance = "(OI)(CI)" if directory else ""
    p = subprocess.run(
        [
            "icacls.exe",
            str(path),
            "/inheritance:r",
            "/grant:r",
            f"*{sid}:{inheritance}F",
            "/q",
        ],
        capture_output=True,
        text=True,
    )
    if p.returncode != 0:
        raise RuntimeError(f"could not restrict Windows permissions for {path}: {p.stderr[:300]}")


def ensure_private_dir(path: Path) -> None:
    """Create a private directory and reject symlinked storage locations."""
    if path.is_symlink():
        raise RuntimeError(f"refusing symlinked private directory: {path}")
    path.mkdir(mode=0o700, exist_ok=True)
    restrict_private_path(path, directory=True)


def ensure_private_dirs() -> None:
    """Create ROOT before work/ and reports/, since ensure_private_dir does not create parents."""
    if ROOT != MODULE_ROOT:
        ensure_private_dir(ROOT)
    ensure_private_dir(WORK)
    ensure_private_dir(REPORTS)


def write_private_text(path: Path, text: str) -> None:
    """Write sensitive text with owner-only permissions."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fd = -1
            fh.write(text)
    finally:
        if fd >= 0:
            os.close(fd)
    restrict_private_path(path)


def install_hint(tool: str) -> str:
    if os.name == "nt":
        return {
            "gh": "winget install --id GitHub.cli -e; gh auth login",
            "git": "winget install --id Git.Git -e",
            "gitleaks": "winget install --id Gitleaks.Gitleaks -e",
            "exiftool": "install ExifTool and add exiftool.exe to PATH",
        }[tool]
    if sys.platform == "darwin":
        return {
            "gh": "brew install gh && gh auth login",
            "git": "xcode-select --install",
            "gitleaks": "brew install gitleaks",
            "exiftool": "brew install exiftool",
        }[tool]
    return {
        "gh": "install GitHub CLI for your distribution, then run gh auth login",
        "git": "install Git with your distribution's package manager",
        "gitleaks": "install Gitleaks from its official release",
        "exiftool": "install ExifTool with your distribution's package manager",
    }[tool]


def luhn_ok(s: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(s)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def email_ok(v: str) -> bool:
    if BORING_EMAIL_RE.search(v):
        return False
    return v.rsplit(".", 1)[-1].lower() not in FILE_EXT_TLDS


def known_region(region: str) -> bool:
    """True if `region` is an ISO code phonenumbers can use (True when it is absent)."""
    if phonenumbers is None:
        return True
    return region.upper() in phonenumbers.SUPPORTED_REGIONS


def make_line_lookup(text: str):
    nl = [m.start() for m in re.finditer("\n", text)]
    return lambda pos: bisect_right(nl, pos) + 1


def load_watchlist() -> list[str]:
    if not PERSONAL_FILE.exists():
        return []
    terms = []
    for line in PERSONAL_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            terms.append(line)
    return terms


def gitleaks_config_text(terms: list[str], regions=()) -> str:
    lines = ["# Generated by sweep.py — do not edit by hand",
             "[extend]", "useDefault = true", ""]
    for rule_id, regex in national_id.gitleaks_rules(list(regions)):
        lines += [
            "[[rules]]",
            f'id = "{rule_id}"',
            'description = "Possible national ID (validated by sweep.py)"',
            f"regex = {json.dumps(regex, ensure_ascii=False)}",
            "secretGroup = 2",
            "",
        ]
    for i, t in enumerate(terms):
        pattern = "(?i)" + re.escape(t)
        lines += [
            "[[rules]]",
            f'id = "watchlist-{i}"',
            f'description = "Match on personal watchlist term #{i}"',
            f"regex = {json.dumps(pattern, ensure_ascii=False)}",
            "",
        ]
    return "\n".join(lines)


_GITLEAKS_MODERN: bool | None = None


def gitleaks_scan(repo_dir: Path, cfg: Path, name: str) -> list[dict]:
    global _GITLEAKS_MODERN
    if _GITLEAKS_MODERN is None:
        _GITLEAKS_MODERN = subprocess.run(
            ["gitleaks", "git", "--help"], capture_output=True).returncode == 0
    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "__", name)
    out = WORK / f"{safe_name}.gitleaks.json"
    out.unlink(missing_ok=True)
    flags = ["-c", cfg, "--report-format", "json", "--report-path", out,
             "--exit-code", "0", "--log-level", "error"]
    if _GITLEAKS_MODERN:
        cmd = ["gitleaks", "git", *flags, repo_dir]
    else:
        cmd = ["gitleaks", "detect", "-s", repo_dir, *flags]
    try:
        previous_umask = os.umask(0o077)
        try:
            run(cmd)
        finally:
            os.umask(previous_umask)
        if not out.exists():
            raise RuntimeError("gitleaks did not create its JSON report")
        try:
            findings = json.loads(out.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            raise RuntimeError("gitleaks returned an invalid JSON report") from e
        if not isinstance(findings, list):
            raise RuntimeError("gitleaks returned an unexpected JSON report")
        return findings
    finally:
        out.unlink(missing_ok=True)


def split_gitleaks(findings: list[dict], terms: list[str], regions=()):
    secrets, watch, national_ids = [], [], []
    regions = list(regions)
    for f in findings:
        rid = f.get("RuleID", "")
        if rid.startswith("national-id"):
            hit = national_id.classify(f.get("Secret", ""), regions)
            if hit:
                f["country"], f["type"] = hit
                national_ids.append(f)
        elif rid.startswith("watchlist-"):
            try:
                f["term"] = terms[int(rid.split("-", 1)[1])]
            except (ValueError, IndexError):
                f["term"] = rid
            watch.append(f)
        else:
            secrets.append(f)
    return secrets, watch, national_ids


def list_repos(args) -> tuple[list[dict], bool]:
    cmd = ["gh", "repo", "list"] + ([args.owner] if args.owner else []) + [
        "--limit", "1000", "--json",
        "name,nameWithOwner,isPrivate,isFork,isArchived,diskUsage,defaultBranchRef,hasWikiEnabled"]
    repos = json.loads(run(cmd).stdout)
    truncated = len(repos) >= 1000
    if truncated:
        print("⚠ Repo listing hit the 1000 cap — some repos may not be scanned.")
    self_repo = _self_repo()
    wanted = {r.lower() for r in args.repo} if args.repo else None
    out, skipped_forks = [], 0
    for r in repos:
        if r.get("nameWithOwner", "").lower() == self_repo.lower():
            continue
        if wanted is not None and r["name"].lower() not in wanted:
            continue
        if r["isFork"] and not args.include_forks and wanted is None:
            skipped_forks += 1
            continue
        out.append(r)
    if skipped_forks:
        print(f"  (skipping {skipped_forks} forks — use --include-forks to include them)")
    return out, truncated


def repo_storage_name(repo: dict) -> str:
    identity = repo.get("nameWithOwner") or repo["name"]
    readable = re.sub(r"[^A-Za-z0-9._-]+", "__", identity)[:120]
    digest = hashlib.sha256(identity.lower().encode("utf-8")).hexdigest()[:12]
    return f"{readable}-{digest}"


def clone_or_update(repo: dict) -> Path:
    d = WORK / repo_storage_name(repo)
    if d.exists():
        remote = subprocess.run(
            ["git", "-C", str(d), "remote", "get-url", "origin"],
            capture_output=True, text=True,
        )
        actual = _github_repo_from_url(remote.stdout).lower()
        expected = repo["nameWithOwner"].lower()
        if remote.returncode != 0 or actual != expected:
            raise RuntimeError(
                f"work clone origin mismatch for {repo['nameWithOwner']}; run --clean"
            )
        dirty = subprocess.run(
            ["git", "-C", str(d), "status", "--porcelain"],
            capture_output=True, text=True,
        )
        if dirty.returncode != 0 or dirty.stdout:
            raise RuntimeError(
                f"work clone has local changes for {repo['nameWithOwner']}; run --clean"
            )
        ok = subprocess.run(
            ["git", "-C", str(d), "fetch", "--all", "--prune", "--quiet"],
            capture_output=True,
        ).returncode == 0
        if not ok:
            shutil.rmtree(d)
    if not d.exists():
        run(["gh", "repo", "clone", repo["nameWithOwner"], d, "--", "--quiet"])
    dirty = subprocess.run(
        ["git", "-C", str(d), "status", "--porcelain"], capture_output=True, text=True
    )
    if dirty.returncode != 0 or dirty.stdout:
        raise RuntimeError(f"work clone has local changes for {repo['nameWithOwner']}; run --clean")
    if not has_commits(d):
        return d
    default_branch = (repo.get("defaultBranchRef") or {}).get("name")
    target = f"origin/{default_branch}" if default_branch else "origin/HEAD"
    checkout = subprocess.run(
        ["git", "-C", str(d), "checkout", "--detach", "--quiet", target],
        capture_output=True, text=True,
    )
    if checkout.returncode != 0:
        raise RuntimeError(
            f"could not select the default branch for {repo['nameWithOwner']}; run --clean"
        )
    return d


def has_commits(d: Path) -> bool:
    p = subprocess.run(["git", "-C", str(d), "rev-list", "-n1", "--all"],
                       capture_output=True, text=True)
    return p.returncode == 0 and bool(p.stdout.strip())


def commit_identities(d: Path, terms: list[str]) -> list[dict]:
    p = run(["git", "-C", d, "log", "--all", "--format=%an <%ae>%n%cn <%ce>"])
    idents = Counter(line for line in p.stdout.splitlines() if line.strip())
    hits = []
    for t in terms:
        tl = t.lower()
        for ident, cnt in idents.items():
            if tl in ident.lower():
                hits.append({"term": t, "identity": ident, "commits": cnt})
    return hits


def history_path_hits(d: Path, terms: list[str]) -> list[dict]:
    p = run(["git", "-C", d, "log", "--all", "--name-only", "--format="])
    paths = {line for line in p.stdout.splitlines() if line.strip()}
    return [{"term": t, "path": x}
            for t in terms for x in sorted(paths) if t.lower() in x.lower()]


def iter_text_files(d: Path, stats: dict):
    def walk_error(_error):
        stats["file_errors"] += 1

    for root, dirs, files in os.walk(d, onerror=walk_error):
        dirs[:] = [x for x in dirs if x not in SKIP_DIRS]
        for fn in files:
            path = Path(root) / fn
            try:
                if path.is_symlink() or not path.is_file():
                    continue
                if path.stat().st_size > MAX_FILE_BYTES:
                    stats["skipped_big"] += 1
                    continue
                with path.open("rb") as fh:
                    if b"\0" in fh.read(8192):
                        stats["skipped_binary"] += 1
                        continue
            except OSError:
                stats["file_errors"] += 1
                continue
            yield path


def fast_scan(text: str, rel: str, add, region: str = "NO", regions=()):
    line = make_line_lookup(text)
    for m in EMAIL_RE.finditer(text):
        if email_ok(m.group(0)):
            add("EMAIL_ADDRESS", m.group(0), rel, line(m.start()))
    for hit in national_id.scan_text(text, list(regions)):
        add("NATIONAL_ID", hit.value, rel, line(hit.start),
            country=hit.country, type=hit.type)
    for m in CC_RE.finditer(text):
        v = m.group(0)
        if luhn_ok(v) and len(set(v)) > 1:
            add("CREDIT_CARD", v, rel, line(m.start()))
    for m in IP_RE.finditer(text):
        try:
            if ipaddress.ip_address(m.group(0)).is_global:
                add("IP_ADDRESS", m.group(0), rel, line(m.start()))
        except ValueError:
            pass
    if phonenumbers:
        try:
            for m in phonenumbers.PhoneNumberMatcher(text, region):
                raw = m.raw_string
                if raw.startswith("+") or any(c in raw for c in " -()"):
                    add("PHONE_NUMBER", raw, rel, line(m.start))
        except Exception:
            pass  # skip unparseable input


def build_presidio(region: str = "NO"):
    try:
        logging.getLogger("presidio-analyzer").setLevel(logging.ERROR)
        from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
        from presidio_analyzer.nlp_engine import NlpEngineProvider
        from presidio_analyzer.predefined_recognizers import PhoneRecognizer
        conf = {"nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}]}
        nlp = NlpEngineProvider(nlp_configuration=conf).create_engine()
        registry = RecognizerRegistry()
        registry.load_predefined_recognizers()
        try:
            registry.remove_recognizer("PhoneRecognizer")
        except Exception:
            pass
        regions = tuple(dict.fromkeys([region, "US", "GB"]))
        registry.add_recognizer(PhoneRecognizer(supported_regions=regions))
        return AnalyzerEngine(nlp_engine=nlp, registry=registry,
                              supported_languages=["en"])
    except Exception as e:
        print(f"  ⚠ Presidio unavailable ({type(e).__name__}: {e})")
        print("    Fix: rerun ./setup.sh to install the locked dependencies and model")
        return None


def presidio_scan(analyzer, text: str, rel: str, add):
    line = make_line_lookup(text)
    for r in analyzer.analyze(text=text, language="en", entities=NER_ENTITIES,
                              score_threshold=0.4):
        val = text[r.start:r.end].strip()
        et = r.entity_type
        if et == "EMAIL_ADDRESS" and not email_ok(val):
            continue
        if et == "IP_ADDRESS":
            try:
                if not ipaddress.ip_address(val).is_global:
                    continue
            except ValueError:
                continue
        if et == "PERSON" and (" " not in val or not PERSON_OK_RE.fullmatch(val)):
            continue
        if et == "LOCATION" and (len(val) < 4 or not PERSON_OK_RE.fullmatch(val)):
            continue
        add(et, val, rel, line(r.start), round(r.score, 2))


def empty_result(repo: dict) -> dict:
    return {
        "repo": repo["name"], "nameWithOwner": repo.get("nameWithOwner", ""),
        "public": not repo.get("isPrivate", True),
        "fork": repo.get("isFork", False), "archived": repo.get("isArchived", False),
        "error": None, "secrets": [], "watchlist_history": [], "national_id_history": [],
        "pii": [], "identities": [], "path_hits": [], "exif": [],
        "releases": [], "actions": [], "deep_errors": [],
        "stats": {"files_scanned": 0, "ner_files": 0, "ner_skipped": 0,
                  "ner_truncated": 0,
                  "ner_errors": 0, "file_errors": 0,
                  "skipped_big": 0, "skipped_binary": 0},
    }


def scan_repo(repo: dict, cfg: Path, terms: list[str], analyzer, region: str = "NO",
              regions=(), exif: bool = False) -> dict:
    res = empty_result(repo)
    if repo.get("diskUsage", 0) > HUGE_REPO_KB:
        res["error"] = f"skipped: repo is {repo['diskUsage'] // 1024} MB (> {HUGE_REPO_KB // 1024} MB)"
        return res
    return scan_tree(clone_or_update(repo), res, cfg, terms, analyzer, region, regions, exif=exif)


def scan_tree(d: Path, res: dict, cfg, terms: list[str], analyzer, region: str = "NO",
              regions=(), use_gitleaks: bool = True, exif: bool = False) -> dict:
    """Scan an already-present clone `d` into `res`."""
    stats = res["stats"]
    if exif:
        try:
            res["exif"] = binary_metadata_hits(d, terms)
        except Exception as e:
            res["deep_errors"].append(f"exif: {type(e).__name__}: {e}")
    if has_commits(d):
        if use_gitleaks:
            secrets, watch, id_hist = split_gitleaks(
                gitleaks_scan(d, cfg, res["repo"]), terms, list(regions))
            res["secrets"], res["watchlist_history"], res["national_id_history"] = (
                secrets, watch, id_hist)
        if terms:
            res["identities"] = commit_identities(d, terms)
            res["path_hits"] = history_path_hits(d, terms)

    pii, seen = [], set()

    def add(entity, value, rel, line, score=None, **extra):
        key = (entity, value.lower(), rel, line)
        if key not in seen:
            seen.add(key)
            item = {"entity": entity, "value": value, "file": rel, "line": line}
            if score is not None:
                item["score"] = score
            item.update(extra)
            pii.append(item)

    for path in iter_text_files(d, stats):
        rel = str(path.relative_to(d))
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            stats["file_errors"] += 1
            continue
        stats["files_scanned"] += 1
        fast_scan(text, rel, add, region, regions)
        if analyzer and path.suffix.lower() in PROSE_EXT:
            if stats["ner_files"] >= MAX_NER_FILES:
                stats["ner_skipped"] += 1
                continue
            stats["ner_files"] += 1
            if len(text) > MAX_NER_CHARS:
                stats["ner_truncated"] += 1
                text = text[:MAX_NER_CHARS]
            try:
                presidio_scan(analyzer, text, rel, add)
            except Exception:
                stats["ner_errors"] += 1
    res["pii"] = pii
    return res


def scan_error_count(res: dict) -> int:
    return (len(res.get("deep_errors", []))
            + res.get("stats", {}).get("ner_errors", 0)
            + res.get("stats", {}).get("file_errors", 0))


def oneline(res: dict) -> str:
    if res["error"]:
        return f"⚠ {res['error']}"
    check_errors = scan_error_count(res)
    incomplete = f", {check_errors} check error(s)" if check_errors else ""
    if finding_count(res) == 0:
        return f"{'⚠ incomplete' if incomplete else '✓ clean'}{incomplete}"
    extra_counts = [
        ("exif", len(res.get("exif", []))),
        ("releases", len(res.get("releases", []))),
        ("actions", len(res.get("actions", []))),
    ]
    extras = "".join(f", {count} {label}" for label, count in extra_counts if count)
    return (f"❗ {len(res['secrets'])} secrets, {len(res['watchlist_history'])} watchlist, "
            f"{len(res['national_id_history'])} nat.ID, {len(res['pii'])} PII, "
            f"{len(res['identities'])} identities, {len(res['path_hits'])} paths"
            + extras + incomplete)


def list_collaborator_repos() -> list[dict]:
    """Repos you collaborate on but don't own (gh repo list misses these)."""
    p = run(["gh", "api", "--paginate",
             "/user/repos?affiliation=collaborator&per_page=100",
             "--jq", ".[] | {name, nameWithOwner: .full_name, isPrivate: .private, "
                     "isFork: .fork, isArchived: .archived, diskUsage: .size, "
                     "defaultBranchRef: {name: .default_branch}, "
                     "hasWikiEnabled: .has_wiki}"])
    out = []
    for line in p.stdout.splitlines():
        if line.strip():
            try:
                r = json.loads(line)
                r["collaborator"] = True
                out.append(r)
            except json.JSONDecodeError as e:
                raise RuntimeError("GitHub returned invalid collaborator-repository JSON") from e
    return out


def check_profile() -> dict:
    """Personal data your public GitHub profile exposes."""
    u = json.loads(run(["gh", "api", "user"]).stdout)
    social = json.loads(run(["gh", "api", "/user/social_accounts"]).stdout or "[]")
    exposed = {k: u[k] for k in ("name", "email", "bio", "location", "company", "blog",
                                 "twitter_username") if u.get(k)}
    if u.get("hireable"):
        exposed["hireable"] = True
    return {"login": u.get("login"), "exposed": exposed,
            "social": [s.get("url") for s in social if isinstance(s, dict) and s.get("url")],
            "public_repos": u.get("public_repos"), "followers": u.get("followers")}


def check_forks(repos: list[dict]) -> list[dict]:
    """Public repos of yours that have forks — any leak there lives on in the fork."""
    out = []
    for r in repos:
        if r.get("isFork") or r.get("isPrivate") or r.get("collaborator"):
            continue
        p = run(["gh", "api", "--paginate",
                 f"/repos/{r['nameWithOwner']}/forks?per_page=100",
                 "--jq", ".[].full_name"])
        forks = [x for x in p.stdout.splitlines() if x.strip()]
        if forks:
            out.append({"repo": r["name"], "forks": forks})
    return out


def scan_gists(terms: list[str], region: str, regions) -> list[dict]:
    """Scan your gists (public + secret) for watchlist terms and PII."""
    p = run(["gh", "api", "--paginate", "/gists",
             "--jq", ".[] | {id, public, desc: .description}"])
    findings = []
    for line in p.stdout.splitlines():
        if not line.strip():
            continue
        try:
            g = json.loads(line)
        except json.JSONDecodeError as e:
            raise RuntimeError("GitHub returned invalid gist JSON") from e
        content = run(
            ["gh", "api", f"/gists/{g['id']}", "--jq", ".files[].content"]
        ).stdout
        hits = []
        fast_scan(content, f"gist:{g['id']}",
                  lambda e, v, rel, ln, s=None, **x: hits.append({"entity": e, "value": v, **x}),
                  region, regions)
        low = content.lower()
        for t in terms:
            if t.lower() in low:
                hits.append({"entity": "watchlist", "value": t})
        if hits:
            findings.append({"id": g["id"], "public": g.get("public"),
                             "desc": g.get("desc"), "hits": hits})
    return findings


def _parse_search_lines(text: str):
    """Parse '"TOTAL " + count' followed by item lines → (total, items)."""
    total, items = 0, []
    for line in text.splitlines():
        if line.startswith("TOTAL "):
            try:
                total = int(line[6:])
            except ValueError:
                pass
        elif line.strip():
            items.append(line)
    return total, items


def _gh_search(endpoint: str, q: str, item_jq: str, cap: int = 60):
    """One search call → (total_count, up to `cap` items); total is -1 on error."""
    p = subprocess.run(
        ["gh", "api", "-X", "GET", endpoint, "-f", f"q={q}", "-f", "per_page=100",
         "--jq", f'"TOTAL " + (.total_count | tostring), (.items[]? | {item_jq})'],
        capture_output=True, text=True)
    if p.returncode != 0:
        return -1, []
    if not any(line.startswith("TOTAL ") for line in p.stdout.splitlines()):
        return -1, []
    total, items = _parse_search_lines(p.stdout)
    return total, items[:cap]


def search_github(terms: list[str], user: str) -> list[dict]:
    """Best-effort GitHub-wide search across code, commits and issues/PRs. GitHub
    only indexes default branches of non-archived public repos, so archived/private/
    forked sources are missed — this complements, not replaces, the clone scan."""
    out = []
    for t in terms:
        ct, code = _gh_search("/search/code", f'"{t}"',
                              '.repository.full_name + " :: " + .path')
        q = f"author-email:{t}" if "@" in t else f'"{t}"'
        mt, com = _gh_search("/search/commits", q,
                             '.repository.full_name + " :: " + .sha[0:7]')
        it, iss = _gh_search("/search/issues", f'"{t}"', ".html_url")
        out.append({"term": t, "code": code, "code_total": max(0, ct),
                    "commits": com, "commits_total": max(0, mt),
                    "issues": iss, "issues_total": max(0, it),
                    "error": ct < 0 or mt < 0 or it < 0})
    return out


def _exif_meta_hits(meta: dict, rel: str, terms: list[str]) -> list[dict]:
    """GPS and watchlist hits from one exiftool metadata dict."""
    hits = []
    if any(meta.get(g) is not None for g in GPS_FIELDS):
        hits.append({"file": rel, "field": "GPS",
                     "value": f"{meta.get('GPSLatitude')},{meta.get('GPSLongitude')}"})
    blob = " ".join(str(v) for v in meta.values()).lower()
    for t in terms:
        if t.lower() in blob:
            hits.append({"file": rel, "field": "watchlist", "value": t})
    return hits


def binary_metadata_hits(d: Path, terms: list[str]) -> list[dict]:
    """GPS coordinates and watchlist terms embedded in committed binaries (exiftool)."""
    if not shutil.which("exiftool"):
        return []
    files = []
    for root, dirs, fs in os.walk(d):
        dirs[:] = [x for x in dirs if x not in SKIP_DIRS]
        for fn in fs:
            if Path(fn).suffix.lower() in BINARY_META_EXT:
                files.append(str(Path(root) / fn))
    hits = []
    for i in range(0, len(files), 100):
        p = run(["exiftool", "-j", "-n", *files[i:i + 100]])
        try:
            metas = json.loads(p.stdout)
        except json.JSONDecodeError as e:
            raise RuntimeError("exiftool returned invalid JSON") from e
        if not isinstance(metas, list):
            raise RuntimeError("exiftool returned unexpected JSON")
        for meta in metas:
            try:
                rel = str(Path(meta.get("SourceFile", "")).relative_to(d))
            except ValueError:
                rel = meta.get("SourceFile", "?")
            hits.extend(_exif_meta_hits(meta, rel, terms))
    return hits


def scan_wiki(repo, cfg, terms, analyzer, region, regions, exif):
    """Clone and scan a repo's wiki (a separate .wiki.git repo), if it has one."""
    if repo.get("hasWikiEnabled") is False:
        return None
    d = WORK / f"{repo_storage_name(repo)}.wiki"
    shutil.rmtree(d, ignore_errors=True)
    url = f"https://github.com/{repo['nameWithOwner']}.wiki.git"
    if subprocess.run(["git", "clone", "--quiet", url, str(d)],
                      capture_output=True).returncode != 0:
        raise RuntimeError("could not clone the enabled wiki")
    res = empty_result({"name": f"{repo['name']} (wiki)", "nameWithOwner": repo["nameWithOwner"],
                        "isPrivate": repo.get("isPrivate", True), "isFork": False,
                        "isArchived": repo.get("isArchived", False)})
    return scan_tree(d, res, cfg, terms, analyzer, region, regions, exif=exif)


def scan_releases(repo, terms, region, regions) -> list[dict]:
    """Scan release names and notes (body) for watchlist terms and PII."""
    p = run(["gh", "api", "--paginate",
             f"/repos/{repo['nameWithOwner']}/releases?per_page=100",
             "--jq", ".[] | {tag: .tag_name, name, body}"])
    hits = []
    for line in p.stdout.splitlines():
        if not line.strip():
            continue
        try:
            rel = json.loads(line)
        except json.JSONDecodeError as e:
            raise RuntimeError("GitHub returned invalid release JSON") from e
        text = f"{rel.get('name') or ''}\n{rel.get('body') or ''}"
        loc = f"release:{rel.get('tag', '?')}"
        fast_scan(text, loc,
                  lambda e, v, r, ln, s=None, **x: hits.append(
                      {"entity": e, "value": v, "where": loc, **x}),
                  region, regions)
        low = text.lower()
        for t in terms:
            if t.lower() in low:
                hits.append({"entity": "watchlist", "value": t, "where": loc})
    return hits


def scan_actions(repo, terms, max_runs: int = 5) -> list[dict]:
    """Grep recent GitHub Actions run logs for watchlist terms (bounded, heavy)."""
    if not terms:
        return []
    import io as _io
    import zipfile
    p = run(["gh", "api", f"/repos/{repo['nameWithOwner']}/actions/runs?per_page={max_runs}",
             "--jq", ".workflow_runs[].id"])
    hits = []
    for rid in [x for x in p.stdout.splitlines() if x.strip()][:max_runs]:
        logs = subprocess.run(
            ["gh", "api", f"/repos/{repo['nameWithOwner']}/actions/runs/{rid}/logs"],
            capture_output=True)
        if logs.returncode != 0:
            raise RuntimeError(f"could not fetch Actions logs for run {rid}")
        blob = logs.stdout
        if not blob:
            continue
        if len(blob) > MAX_ACTIONS_ZIP_BYTES:
            raise RuntimeError(f"Actions logs for run {rid} exceed the 100 MB safety limit")
        try:
            zf = zipfile.ZipFile(_io.BytesIO(blob))
        except zipfile.BadZipFile as e:
            raise RuntimeError(f"Actions logs for run {rid} are not a valid ZIP archive") from e
        with zf:
            infos = zf.infolist()
            if sum(info.file_size for info in infos) > MAX_ACTIONS_UNPACKED_BYTES:
                raise RuntimeError(
                    f"Actions logs for run {rid} exceed the 200 MB unpacked safety limit"
                )
            for info in infos:
                if info.file_size > MAX_ACTION_LOG_BYTES:
                    raise RuntimeError(
                        f"Actions log {info.filename} in run {rid} exceeds the 20 MB safety limit"
                    )
                try:
                    low = zf.read(info).decode("utf-8", "replace").lower()
                except (OSError, RuntimeError, zipfile.BadZipFile) as e:
                    raise RuntimeError(
                        f"could not read Actions log {info.filename} in run {rid}"
                    ) from e
                for t in terms:
                    if t.lower() in low:
                        hits.append({"run": rid, "file": info.filename, "term": t})
    return hits


def integration_test():
    """End-to-end scan of a throwaway local git repo (no network/gitleaks/presidio)."""
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        (d / "app.py").write_text(
            "email = 'ola@company.no'\n"
            "fnr = '15108695088'\n"           # stdnum-valid Norwegian ID (synthetic)
            "card = '4111111111111111'\n"
            "ip = '8.8.8.8'\n", encoding="utf-8")
        for gc in (["init", "-q"], ["config", "user.email", "ola@company.no"],
                   ["config", "user.name", "Ola Nordmann"], ["add", "-A"],
                   ["commit", "-q", "--no-gpg-sign", "-m", "init"]):
            run(["git", "-C", d, *gc])

        res = empty_result({"name": "fixture", "isPrivate": True})
        scan_tree(d, res, None, ["Ola Nordmann"], None, use_gitleaks=False, regions=["NO"])
        got = {(p["entity"], p["value"]) for p in res["pii"]}
        assert ("NATIONAL_ID", "15108695088") in got, "national-ID not reaching fast_scan"
        assert ("EMAIL_ADDRESS", "ola@company.no") in got
        assert ("CREDIT_CARD", "4111111111111111") in got
        assert ("IP_ADDRESS", "8.8.8.8") in got
        assert any(h["identity"].startswith("Ola Nordmann") for h in res["identities"])

        res2 = empty_result({"name": "fixture", "isPrivate": True})
        scan_tree(d, res2, None, [], None, use_gitleaks=False, regions=[])
        assert not any(p["entity"] == "NATIONAL_ID" for p in res2["pii"]), \
            "empty regions should suppress national-ID detection"
    print("Integration test OK ✓")


def selftest():
    # validators
    assert luhn_ok("4111111111111111")
    assert not luhn_ok("4111111111111112")
    assert email_ok("jane.doe@gmail.com")
    assert not email_ok("logo@2x.png")
    assert not email_ok("user@example.com")
    assert not email_ok("bot@users.noreply.github.com")

    # gitleaks config generation
    cfg = gitleaks_config_text(["ola@x.no", "Ola Nordmann"], ["NO"])
    assert "useDefault = true" in cfg
    assert 'id = "watchlist-1"' in cfg
    assert 'id = "national-id-NO"' in cfg

    look = make_line_lookup("a\nbb\nccc\n")
    assert look(0) == 1 and look(2) == 2 and look(5) == 3

    # redaction of sensitive values
    assert redact("CREDIT_CARD", "4111111111111111") == "••••••••••••1111"
    assert redact("NATIONAL_ID", "15108695088") == "•" * 11
    assert redact("EMAIL_ADDRESS", "me@x.com") == "me@x.com"          # kept visible
    assert redact("CREDIT_CARD", "4111111111111111", raw=True) == "4111111111111111"

    # split_gitleaks routing (national ID validated, watchlist labelled, rest = secret)
    fx = [{"RuleID": "national-id-NO", "Secret": "15108695088", "File": "a"},
          {"RuleID": "national-id-NO", "Secret": "12345678901", "File": "b"},  # invalid → dropped
          {"RuleID": "watchlist-0", "Secret": "x", "File": "a"},
          {"RuleID": "generic-api-key", "Secret": "AKIA", "File": "b"}]
    secrets, watch, ids = split_gitleaks(fx, ["me@x.com"], ["NO"])
    assert len(ids) == 1 and len(watch) == 1 and len(secrets) == 1
    assert ids[0]["country"] == "NO"

    # render_md masks by default, reveals with raw, keeps emails visible
    res = empty_result({"name": "R", "isPrivate": False})
    res["pii"] = [{"entity": "CREDIT_CARD", "value": "4111111111111111", "file": "f", "line": 1},
                  {"entity": "EMAIL_ADDRESS", "value": "me@x.com", "file": "f", "line": 2},
                  {"entity": "NATIONAL_ID", "value": "15108695088", "country": "NO", "file": "f", "line": 1}]
    meta = {"when": "now", "user": "u", "terms": 0, "presidio": False}
    md = render_md([res], meta)
    assert "4111111111111111" not in md and "1111" in md and "me@x.com" in md
    assert "15108695088" not in md and "NO" in md
    assert "4111111111111111" in render_md([res], meta, raw=True)
    assert redact_results([res], raw=False)[0]["pii"][0]["value"] != "4111111111111111"

    # deep-check helpers
    assert _parse_search_lines("TOTAL 3\nfoo\nbar\n") == (3, ["foo", "bar"])
    assert _parse_search_lines("") == (0, [])
    ex_hits = _exif_meta_hits({"GPSLatitude": 59.9, "GPSLongitude": 10.7, "Make": "leak@x.com"},
                              "photo.jpg", ["leak@x.com"])
    assert any(h["field"] == "GPS" for h in ex_hits)
    assert any(h["field"] == "watchlist" for h in ex_hits)
    assert _exif_meta_hits({"Make": "Canon"}, "p.jpg", ["me@x.com"]) == []
    rr = empty_result({"name": "R", "isPrivate": True})
    rr["releases"] = [{"entity": "CREDIT_CARD", "value": "4111111111111111", "where": "release:v1"}]
    assert "•" in redact_results([rr], raw=False)[0]["releases"][0]["value"]

    if shutil.which("git"):
        integration_test()
    else:
        print("(skipping integration test — git not found)")
    print("Self-test OK ✓")


def personal_txt_tracked() -> bool:
    """True if personal.txt is tracked by git in this tool's own repo."""
    return subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "--error-unmatch", "personal.txt"],
        capture_output=True).returncode == 0


def write_reports(results, meta, raw, extras: dict | None = None) -> Path:
    ensure_private_dir(REPORTS)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    md_path = REPORTS / f"report-{ts}.md"
    write_private_text(md_path, render_md(results, meta, raw=raw, extras=extras))
    payload = {"meta": meta, "results": redact_results(results, raw),
               "extras": redact_extras(extras or {}, raw)}
    write_private_text(
        REPORTS / f"report-{ts}.json",
        json.dumps(payload, indent=2, ensure_ascii=False, default=str),
    )
    return md_path


def main():
    for _stream in (sys.stdout, sys.stderr):
        if isinstance(_stream, io.TextIOWrapper):
            try:
                _stream.reconfigure(encoding="utf-8")
            except ValueError:
                pass
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", action="append",
                    help="scan only this repo (repeatable)")
    ap.add_argument("--owner", help="scan another user/org (default: yourself)")
    ap.add_argument("--include-forks", action="store_true",
                    help="include forks (default: skipped)")
    ap.add_argument("--no-presidio", action="store_true",
                    help="skip the NER scan (faster)")
    ap.add_argument("--id-regions", default="auto",
                    help="national-ID regions: auto (locale→--region), all, none, "
                         "or a comma list of ISO codes (e.g. SE,DK)")
    ap.add_argument("--no-fnr", action="store_true",
                    help="deprecated alias for --id-regions none")
    ap.add_argument("--region", default="NO",
                    help="default phone-number region (ISO code) for parsing (default: NO)")
    ap.add_argument("--raw", action="store_true",
                    help="write full unmasked values (cards/national IDs/secrets) to the report")
    ap.add_argument("--fail-on", choices=["never", "public", "any"], default="never",
                    help="exit non-zero on findings: never (default), public, or any (for cron/CI)")
    ap.add_argument("--clean", action="store_true",
                    help="delete the work/ clones and exit")
    ap.add_argument("--collaborator", action="store_true",
                    help="also scan repos you collaborate on (not just own)")
    ap.add_argument("--gists", action="store_true", help="scan your gists")
    ap.add_argument("--profile", action="store_true",
                    help="report what your public profile exposes")
    ap.add_argument("--forks", action="store_true",
                    help="check for forks of your public repos")
    ap.add_argument("--exif", action="store_true",
                    help="check committed binaries for GPS/metadata (needs exiftool)")
    ap.add_argument("--search", action="store_true",
                    help="GitHub-wide search (code/commits/issues) for your watchlist terms")
    ap.add_argument("--wiki", action="store_true", help="scan your repos' wikis")
    ap.add_argument("--releases", action="store_true", help="scan release notes")
    ap.add_argument("--actions", action="store_true",
                    help="grep recent Actions run logs for watchlist terms (slow)")
    ap.add_argument("--deep", action="store_true",
                    help="enable all the extra checks above")
    ap.add_argument("--version", action="version", version=f"leak-sweep {__version__}")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.deep:
        args.collaborator = args.gists = args.profile = True
        args.forks = args.exif = args.search = True
        args.wiki = args.releases = args.actions = True

    if args.selftest:
        selftest()
        return
    if args.clean:
        n = sum(1 for _ in WORK.iterdir()) if WORK.exists() else 0
        shutil.rmtree(WORK, ignore_errors=True)
        print(f"Removed work/ ({n} entries).")
        return

    for private_dir in (WORK, REPORTS):
        if private_dir.exists():
            ensure_private_dir(private_dir)
    if PERSONAL_FILE.exists():
        restrict_private_path(PERSONAL_FILE)

    for tool in ("gh", "git", "gitleaks"):
        if not shutil.which(tool):
            sys.exit(f"Missing `{tool}` — install with: {install_hint(tool)}")
    if subprocess.run(["gh", "auth", "status"], capture_output=True).returncode != 0:
        sys.exit("gh is not logged in — run: gh auth login")
    if personal_txt_tracked():
        sys.exit("SECURITY STOP: personal.txt is tracked by git in this repo. It holds your "
                 "private identifiers and must never be committed. Fix: git rm --cached "
                 "personal.txt  (and confirm it is listed in .gitignore).")

    ensure_private_dirs()

    terms = load_watchlist()
    if not terms:
        if ROOT == MODULE_ROOT:
            hint = "Copy personal.example.txt to personal.txt."
        else:
            hint = f"Create {PERSONAL_FILE} with one identifier per line."
        print("⚠ personal.txt is missing/empty — watchlist, identity and path checks will "
              f"find nothing. {hint}")
    short = [t for t in terms if len(t) < 4]
    if short:
        print(f"⚠ {len(short)} watchlist term(s) shorter than 4 characters may match too broadly.")
    if not known_region(args.region):
        print(f"⚠ --region {args.region!r} is not a recognized ISO country code; national-format "
              "phone numbers may be missed (international +numbers are still detected).")
    id_spec = args.id_regions
    if args.no_fnr:
        if id_spec != "auto":
            print("⚠ --no-fnr ignored because --id-regions was given.")
        else:
            print("⚠ --no-fnr is deprecated; use --id-regions none.")
            id_spec = "none"
    regions, unknown_regions = national_id.resolve_id_regions(id_spec, args.region.upper())
    if unknown_regions:
        print(f"⚠ unknown --id-regions code(s): {', '.join(unknown_regions)} (ignored).")
    if regions and not national_id.available():
        print("⚠ python-stdnum unavailable — national-ID checks skipped. Fix: rerun ./setup.sh")
        regions = []
    if regions:
        labels = ", ".join(f"{r} ({national_id.REGISTRY[r][2]})" for r in regions)
        print(f"· national-ID checks: {labels}")
    else:
        print("· national-ID checks: off")
    cfg = WORK / "gitleaks.toml"
    write_private_text(cfg, gitleaks_config_text(terms, regions))

    presidio_requested = not args.no_presidio
    analyzer = None if args.no_presidio else build_presidio(args.region.upper())
    user = run(["gh", "api", "user", "--jq", ".login"]).stdout.strip()
    repos, repo_listing_truncated = list_repos(args)
    external_errors = []
    if repo_listing_truncated:
        external_errors.append("repo listing reached the 1000-repository limit")
    if args.collaborator and not args.owner:
        try:
            collab = list_collaborator_repos()
            repos += collab
            if collab:
                print(f"  (+{len(collab)} collaborator repos)")
        except Exception as e:
            external_errors.append(f"collaborator repos: {type(e).__name__}: {e}")
    if not repos:
        sys.exit("Found no repos to scan.")
    if args.exif and not shutil.which("exiftool"):
        print("⚠ --exif requested but exiftool not found — binary metadata NOT checked "
              f"(install: {install_hint('exiftool')}).")
    if args.wiki or args.releases or args.actions or args.search:
        print("· deep checks on — this can take several minutes and many API calls.")

    print(f"Scanning {len(repos)} repos for {user} "
          f"(watchlist: {len(terms)} terms, presidio: {'on' if analyzer else 'off'}) …")
    results: list[dict[str, Any]] = []
    wiki_results: list[dict[str, Any]] = []
    interrupted = False
    try:
        for i, r in enumerate(repos, 1):
            print(f"[{i}/{len(repos)}] {r['name']} …", flush=True)
            try:
                res = scan_repo(r, cfg, terms, analyzer, args.region.upper(), regions, args.exif)
            except Exception as e:
                res = empty_result(r)
                res["error"] = f"{type(e).__name__}: {e}"
            if not res["error"]:
                if args.releases:
                    try:
                        res["releases"] = scan_releases(
                            r, terms, args.region.upper(), regions
                        )
                    except Exception as e:
                        res["deep_errors"].append(f"releases: {type(e).__name__}: {e}")
                if args.actions:
                    try:
                        res["actions"] = scan_actions(r, terms)
                    except Exception as e:
                        res["deep_errors"].append(f"Actions: {type(e).__name__}: {e}")
            results.append(res)
            print(f"    {oneline(res)}", flush=True)
            if args.wiki and not res["error"]:
                try:
                    w = scan_wiki(r, cfg, terms, analyzer, args.region.upper(), regions, args.exif)
                except Exception as e:
                    res["deep_errors"].append(f"wiki: {type(e).__name__}: {e}")
                    w = None
                if w:
                    print(f"    wiki: {oneline(w)}", flush=True)
                    if finding_count(w) > 0 or w["error"] or scan_error_count(w):
                        wiki_results.append(w)
    except KeyboardInterrupt:
        interrupted = True
        print(f"\n⚠ Interrupted — writing a partial report for the {len(results)} repos "
              "scanned so far …")
    results.extend(wiki_results)

    extras: dict[str, Any] = {"errors": external_errors}
    if not interrupted:
        try:
            if args.profile:
                try:
                    extras["profile"] = check_profile()
                except Exception as e:
                    extras["profile"] = {"exposed": {}, "error": str(e)}
                    extras["errors"].append(f"profile: {type(e).__name__}: {e}")
            if args.search and terms:
                print("Searching GitHub-wide for your terms …", flush=True)
                extras["search"] = search_github(terms, user)
            if args.gists:
                try:
                    extras["gists"] = scan_gists(terms, args.region.upper(), regions)
                except Exception as e:
                    extras["errors"].append(f"gists: {type(e).__name__}: {e}")
            if args.forks:
                print("Checking for forks of your public repos …", flush=True)
                try:
                    extras["forks"] = check_forks(repos)
                except Exception as e:
                    extras["errors"].append(f"forks: {type(e).__name__}: {e}")
        except KeyboardInterrupt:
            interrupted = True
            print("\n⚠ Interrupted during external checks — writing the repository results …")

    dirty = sum(1 for r in results if finding_count(r) > 0)
    pub_dirty = sum(1 for r in results if finding_count(r) > 0 and r["public"])
    errors = (sum(1 for r in results if r["error"])
              + sum(len(r.get("deep_errors", [])) for r in results)
              + len(extras["errors"])
              + sum(bool(s.get("error")) for s in extras.get("search", []))
              + sum(r["stats"]["ner_errors"] + r["stats"].get("file_errors", 0)
                    for r in results))
    incomplete = bool(interrupted or errors or (presidio_requested and analyzer is None)
                      or (args.exif and not shutil.which("exiftool"))
                      or (id_spec != "none" and not national_id.available()))
    meta = {"when": datetime.now().strftime("%Y-%m-%d %H:%M"), "user": user,
            "terms": len(terms), "presidio": analyzer is not None,
            "incomplete": incomplete}
    md_path = write_reports(results, meta, args.raw, extras)

    print(f"\n{'Interrupted' if interrupted else 'Done'}: {len(results)} repos, "
          f"findings in {dirty} ({pub_dirty} PUBLIC), {errors} errors.")
    if presidio_requested and analyzer is None:
        print("⚠ NER was REQUESTED but Presidio was DISABLED — names/locations were NOT "
              "scanned. See the fix hint above.")
    own_prefix = f"{user}/".lower()
    own_url = f"github.com/{user}/".lower()
    ext_terms = sum(
        bool([x for x in s["code"] + s["commits"]
              if not x.lower().startswith(own_prefix)]
             + [x for x in s.get("issues", []) if own_url not in x.lower()])
        for s in extras.get("search", [])
    )
    external_any_findings = (ext_terms + len(extras.get("gists", []))
                             + bool(extras.get("profile", {}).get("exposed")))
    external_public_findings = (
        sum(bool(g.get("public")) for g in extras.get("gists", []))
        + bool(extras.get("profile", {}).get("exposed"))
    )
    ext_notes = []
    if ext_terms:
        ext_notes.append(f"{ext_terms} watchlist term(s) found in OTHERS' repos")
    if extras.get("forks"):
        ext_notes.append(f"{len(extras['forks'])} of your repos have forks")
    if extras.get("gists"):
        ext_notes.append(f"{len(extras['gists'])} gist(s) with hits")
    if extras.get("profile", {}).get("exposed"):
        ext_notes.append("your profile exposes personal data")
    if any(s.get("error") for s in extras.get("search", [])):
        ext_notes.append("some GitHub searches were throttled")
    if ext_notes:
        print("External surface: " + "; ".join(ext_notes) + " — see the report.")
    print(f"Report: {md_path}")

    if interrupted:
        sys.exit(130)
    if incomplete:
        sys.exit(2)
    if args.fail_on == "any" and (dirty or external_any_findings):
        sys.exit(1)
    if args.fail_on == "public" and (pub_dirty or external_public_findings):
        sys.exit(1)


if __name__ == "__main__":
    main()
