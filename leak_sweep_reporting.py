from __future__ import annotations

import copy
import re

SENSITIVE_ENTITIES = {"CREDIT_CARD", "NATIONAL_ID", "GPS"}


def mask(v: str) -> str:
    """Fully mask a secret while retaining its length."""
    v = str(v)
    return "•" * len(v)


def redact(entity: str, value: str, raw: bool = False) -> str:
    """Mask high-stakes values (cards, national IDs) in reports unless raw."""
    if raw or entity not in SENSITIVE_ENTITIES:
        return value
    if entity == "CREDIT_CARD" and len(re.sub(r"\D", "", value)) >= 4:
        return "•" * (len(value) - 4) + value[-4:]
    return "•" * len(value)


def finding_count(res: dict) -> int:
    return (len(res["secrets"]) + len(res["watchlist_history"]) + len(res.get("national_id_history", []))
            + len(res["pii"]) + len(res["identities"]) + len(res["path_hits"])
            + len(res.get("exif", [])) + len(res.get("releases", []))
            + len(res.get("actions", [])))


def redact_results(results: list[dict], raw: bool) -> list[dict]:
    """Copy of results with card/nat.ID/secret values masked (for the JSON report)."""
    if raw:
        return results
    out = copy.deepcopy(results)
    for r in out:
        for f in r["secrets"]:
            secret = str(f.get("Secret", ""))
            f.pop("Match", None)
            f.pop("Line", None)
            if secret:
                replacement = mask(secret)
                for key, value in f.items():
                    if isinstance(value, str):
                        f[key] = value.replace(secret, replacement)
                f["Secret"] = replacement
        for f in r.get("national_id_history", []):
            secret = str(f.get("Secret", ""))
            f.pop("Match", None)
            f.pop("Line", None)
            if secret:
                replacement = "•" * len(secret)
                for key, value in f.items():
                    if isinstance(value, str):
                        f[key] = value.replace(secret, replacement)
                f["Secret"] = replacement
        for p in r["pii"]:
            p["value"] = redact(p["entity"], p["value"], False)
        for h in r.get("exif", []):
            h["value"] = redact(h["field"], h["value"], False)
        for h in r.get("releases", []):
            h["value"] = redact(h["entity"], h["value"], False)
    return out


def redact_extras(extras: dict, raw: bool) -> dict:
    """Mask sensitive values found outside repository scan results."""
    if raw:
        return extras
    out = copy.deepcopy(extras)
    for gist in out.get("gists", []):
        for hit in gist.get("hits", []):
            hit["value"] = redact(hit["entity"], hit["value"], False)
    return out


def collapse(findings: list[dict], key_fields):
    groups = {}
    for f in findings:
        key = tuple(f.get(k) for k in key_fields)
        g = groups.setdefault(key, {"f": f, "count": 0, "commits": set()})
        g["count"] += 1
        if f.get("Commit"):
            g["commits"].add(f["Commit"][:7])
    return list(groups.values())


def md_code(value) -> str:
    """Render untrusted single-line text as a non-breakable Markdown code span."""
    text = str(value).replace("\r", " ").replace("\n", " ")
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * (longest + 1)
    return f"{fence} {text} {fence}"


def md_table(value) -> str:
    return str(value).replace("\r", " ").replace("\n", " ").replace("|", "\\|")


def render_md(results: list[dict], meta: dict, raw: bool = False, extras: dict | None = None) -> str:
    L = [f"# Leak report — {meta['when']}", ""]
    L.append(f"Scanned **{len(results)}** repos for {md_code(meta['user'])} · "
             f"{meta['terms']} watchlist terms · Presidio: "
             f"{'on' if meta['presidio'] else 'OFF'}"
             f"{' · values UNMASKED (--raw)' if raw else ''}")
    L.append("")
    if meta.get("incomplete"):
        L.append("> ⚠ This scan is incomplete; review the errors below before relying on it.")
        L.append("")
    L.append("> ⚠ Contains your personal identifiers in cleartext by design — "
             "keep this report private; do not share or commit it.")
    L.append("")
    dirty = [
        r for r in results
        if finding_count(r) > 0
        or r["error"]
        or r.get("deep_errors")
        or r.get("stats", {}).get("file_errors")
        or r.get("stats", {}).get("ner_errors")
    ]
    clean = [r for r in results if r not in dirty]
    dirty.sort(key=lambda r: (not r["public"], -finding_count(r)))

    L.append("| Repo | Visibility | Secrets | Watchlist | Nat.ID | PII | Identities | Paths | Other |")
    L.append("|---|---|---|---|---|---|---|---|---|")
    for r in dirty:
        vis = "**PUBLIC**" if r["public"] else "private"
        if r["archived"]:
            vis += " (archived)"
        if r["error"]:
            L.append(f"| {md_table(r['repo'])} | {vis} | "
                     f"⚠ {md_table(md_code(r['error']))} |||||||")
        else:
            other = (len(r.get("exif", [])) + len(r.get("releases", []))
                     + len(r.get("actions", [])))
            L.append(f"| {r['repo']} | {vis} | {len(r['secrets'])} | "
                     f"{len(r['watchlist_history'])} | {len(r.get('national_id_history', []))} | "
                     f"{len(r['pii'])} | {len(r['identities'])} | {len(r['path_hits'])} | "
                     f"{other} |")
    L.append("")
    L.append(f"**{len(clean)}** repos with no findings: " +
             (", ".join(r["repo"] for r in clean) if clean else "—"))
    L.append("")

    for r in dirty:
        if r["error"] and finding_count(r) == 0:
            continue
        vis = "PUBLIC" if r["public"] else "private"
        L.append(f"## {r['repo']} ({vis}{', archived' if r['archived'] else ''})")
        L.append("")
        if r["secrets"]:
            L.append("### Secrets in git history (gitleaks)")
            for g in collapse(r["secrets"], ("RuleID", "Secret", "File"))[:50]:
                f = g["f"]
                c = sorted(g["commits"])[:1]
                shown = f.get("Secret", "") if raw else mask(f.get("Secret", ""))
                location = f"{f.get('File')}:{f.get('StartLine')}"
                L.append(f"- {md_code(f.get('RuleID'))} in "
                         f"{md_code(location)} "
                         f"({g['count']}× in history, e.g. commit "
                         f"{md_code(c[0] if c else '?')} "
                         f"{str(f.get('Date', ''))[:10]}): {md_code(shown)}")
            if len(r["secrets"]) > 50:
                L.append(f"- … see the JSON report for all ({len(r['secrets'])} total)")
            L.append("")
        if r["watchlist_history"]:
            L.append("### Personal watchlist terms in git history")
            for g in collapse(r["watchlist_history"], ("term", "File")):
                f = g["f"]
                location = f"{f.get('File')}:{f.get('StartLine')}"
                L.append(f"- {md_code(f.get('term'))} in "
                         f"{md_code(location)} "
                         f"({g['count']}×, e.g. commit "
                         f"{md_code(sorted(g['commits'])[0] if g['commits'] else '?')})")
            L.append("")
        if r.get("national_id_history"):
            L.append("### Possible national IDs in git history (validated)")
            for g in collapse(r["national_id_history"], ("Secret", "File")):
                f = g["f"]
                shown = f.get("Secret", "") if raw else "•" * len(str(f.get("Secret", "")))
                where = " · ".join(x for x in (f.get("country"), f.get("type")) if x)
                location = f"{f.get('File')}:{f.get('StartLine')}"
                L.append(f"- {md_code(shown)} ({md_code(where)}) in "
                         f"{md_code(location)} ({g['count']}×)")
            L.append("")
        if r["pii"]:
            L.append("### PII in current files")
            by_ent: dict[str, dict[str, dict]] = {}
            for p in r["pii"]:
                entry = by_ent.setdefault(p["entity"], {}).setdefault(
                    p["value"], {"locs": [], "where": ""})
                entry["locs"].append(f"{p['file']}:{p['line']}")
                if not entry["where"]:
                    entry["where"] = " · ".join(
                        x for x in (p.get("country"), p.get("type")) if x)
            for ent in sorted(by_ent):
                vals = by_ent[ent]
                L.append(f"- **{ent}** ({len(vals)} unique values):")
                for v, entry in list(vals.items())[:15]:
                    locs = entry["locs"]
                    shown = ", ".join(md_code(x) for x in locs[:4])
                    more = f" (+{len(locs) - 4} more)" if len(locs) > 4 else ""
                    tag = f" ({md_code(entry['where'])})" if entry["where"] else ""
                    L.append(f"  - {md_code(redact(ent, v, raw))}{tag} — {shown}{more}")
                if len(vals) > 15:
                    L.append(f"  - … {len(vals) - 15} more values in the JSON report")
            L.append("")
        if r["identities"]:
            L.append("### Commit identities matching watchlist")
            for h in r["identities"]:
                L.append(f"- {md_code(h['term'])} → {md_code(h['identity'])} "
                         f"({h['commits']} commits)")
            L.append("")
        if r["path_hits"]:
            L.append("### File paths in history matching watchlist")
            for h in r["path_hits"][:30]:
                L.append(f"- {md_code(h['term'])} → {md_code(h['path'])}")
            if len(r["path_hits"]) > 30:
                L.append(f"- … {len(r['path_hits']) - 30} more in the JSON report")
            L.append("")
        if r.get("exif"):
            L.append("### Metadata in committed binaries (exiftool)")
            for h in r["exif"]:
                L.append(f"- **{h['field']}** in {md_code(h['file'])}: "
                         f"{md_code(redact(h['field'], h['value'], raw))}")
            L.append("")
        if r.get("releases"):
            L.append("### Release notes")
            for h in r["releases"]:
                L.append(f"- **{h['entity']}** in {md_code(h['where'])}: "
                         f"{md_code(redact(h['entity'], h['value'], raw))}")
            L.append("")
        if r.get("actions"):
            L.append("### GitHub Actions logs (watchlist)")
            for h in r["actions"]:
                L.append(f"- {md_code(h['term'])} in run {md_code(h['run'])} → "
                         f"{md_code(h['file'])}")
            L.append("")
        if r.get("deep_errors"):
            L.append("### Incomplete optional checks")
            for error in r["deep_errors"]:
                L.append(f"- ⚠ {md_code(error)}")
            L.append("")
        st = r["stats"]
        L.append(f"<sub>{st['files_scanned']} files scanned, {st['ner_files']} with NER"
                 f"{', ' + str(st.get('ner_skipped', 0)) + ' NER-skipped' if st.get('ner_skipped') else ''}"
                 f"{', ' + str(st['ner_truncated']) + ' NER-truncated' if st['ner_truncated'] else ''}"
                 f"{', ' + str(st['ner_errors']) + ' NER errors' if st['ner_errors'] else ''}, "
                 f"{str(st.get('file_errors', 0)) + ' file errors, ' if st.get('file_errors') else ''}"
                 f"{st['skipped_big']} too big, {st['skipped_binary']} binary skipped</sub>")
        L.append("")

    ex = extras or {}
    if ex.get("profile"):
        pr = ex["profile"]
        L.append("## Your GitHub profile (public)")
        L.append("")
        if pr.get("error"):
            L.append(f"- ⚠ Profile check failed: {md_code(pr['error'])}")
        elif pr["exposed"]:
            for k, v in pr["exposed"].items():
                flag = " — ⚠ real email public" if k == "email" else ""
                L.append(f"- **{k}**: {md_code(v)}{flag}")
        else:
            L.append("- Nothing exposed (name/email/bio/location/company/blog all empty).")
        if pr.get("social"):
            L.append(f"- **linked accounts**: "
                     f"{', '.join(md_code(x) for x in pr['social'])}")
        L.append(f"<sub>{pr.get('public_repos')} public repos · {pr.get('followers')} followers</sub>")
        L.append("")
    if ex.get("search"):
        L.append("## GitHub-wide search (best-effort — misses archived/non-indexed repos)")
        L.append("")
        found = False
        throttled = [s["term"] for s in ex["search"] if s.get("error")]
        for s in ex["search"]:
            own = f"{meta['user']}/".lower()
            own_url = f"github.com/{meta['user']}/".lower()
            code = [x for x in s["code"] if not x.lower().startswith(own)]
            com = [x for x in s["commits"] if not x.lower().startswith(own)]
            iss = [x for x in s.get("issues", []) if own_url not in x.lower()]
            if code or com or iss:
                found = True
                L.append(f"- {md_code(s['term'])} in others' repos (totals: "
                         f"{s.get('code_total', 0)} code, {s.get('commits_total', 0)} commits, "
                         f"{s.get('issues_total', 0)} issues/PRs):")
                for x in code[:10]:
                    L.append(f"  - code: {md_code(x)}")
                for x in com[:10]:
                    L.append(f"  - commit: {md_code(x)}")
                for x in iss[:10]:
                    L.append(f"  - issue/PR: {md_code(x)}")
        if not found:
            L.append("- No external hits found (mind the indexing caveat above).")
        if throttled:
            L.append(f"- ⚠ search was throttled/failed for: "
                     f"{', '.join(md_code(x) for x in throttled)} — "
                     "rerun later; results may be incomplete.")
        L.append("")
    if ex.get("gists"):
        L.append("## Gists")
        L.append("")
        for g in ex["gists"]:
            ents = ", ".join(sorted({h["entity"] for h in g["hits"]}))
            L.append(f"- gist {md_code(g['id'])} "
                     f"({'public' if g['public'] else 'secret'}): {ents}")
        L.append("")
    if ex.get("forks"):
        L.append("## Forks of your public repos (leaks persist in forks)")
        L.append("")
        for f in ex["forks"]:
            shown = ", ".join(md_code(x) for x in f["forks"][:8])
            shown += " …" if len(f["forks"]) > 8 else ""
            L.append(f"- {md_code(f['repo'])} → {len(f['forks'])} fork(s): {shown}")
        L.append("")
    if ex.get("errors"):
        L.append("## Incomplete external checks")
        L.append("")
        for error in ex["errors"]:
            L.append(f"- ⚠ {md_code(error)}")
        L.append("")
    return "\n".join(L)
