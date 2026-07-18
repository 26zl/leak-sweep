#!/usr/bin/env python3
"""
gitcheck.py — verify your local Git / GitHub setup is correct and consistent
across git, the gh CLI and GitHub Desktop.

It checks identity/privacy, authentication and signing, safe Git defaults,
platform-specific settings, and the health of the current repository.

Read-only. Run it anywhere; run it inside a repo for remote/branch/history checks.
Exit code: 0 if no failures, 1 otherwise.
"""
from __future__ import annotations

import io
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

OK, WARN, FAIL, INFO = "ok", "warn", "fail", "info"
SYM = {OK: "✓", WARN: "⚠", FAIL: "✗", INFO: "·"}
results: list[str] = []


def run(*cmd, timeout=15):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()
    except subprocess.TimeoutExpired:
        return 1, "", "timeout"
    except FileNotFoundError:
        return 1, "", "not found"


def sanitize_url(value: str) -> str:
    """Remove credentials and query data before displaying a remote URL."""
    try:
        parsed = urlsplit(value)
        if parsed.scheme and parsed.hostname:
            host = parsed.hostname
            if ":" in host:
                host = f"[{host}]"
            if parsed.port:
                host += f":{parsed.port}"
            if parsed.username is not None or parsed.password is not None:
                host = f"***@{host}"
            query = "[REDACTED]" if parsed.query else ""
            return urlunsplit((parsed.scheme, host, parsed.path, query, ""))
    except ValueError:
        pass
    sanitized = re.sub(r"(?i)([a-z][a-z0-9+.-]*://)[^/@\s]+@", r"\1***@", value)
    sanitized = re.sub(r"(?i)^(?!git@)[^@\s]+@([^:\s]+):", r"***@\1:", sanitized)
    if "://" in sanitized and "?" in sanitized:
        sanitized = sanitized.split("?", 1)[0] + "?[REDACTED]"
    if "://" in sanitized and "#" in sanitized:
        sanitized = sanitized.split("#", 1)[0]
    return sanitized


def sanitize_remote_error(value: str, remote: str) -> str:
    sanitized = value.replace(remote, sanitize_url(remote)) if remote else value
    return re.sub(r"(?i)([a-z][a-z0-9+.-]*://)[^/@\s]+@", r"\1***@", sanitized)


def gitconf(key, *scope):
    rc, out, _ = run("git", "config", *scope, "--get", key)
    return out if rc == 0 else ""


def gitconf_all(key, *scope):
    rc, out, _ = run("git", "config", *scope, "--get-all", key)
    return [line.strip() for line in out.splitlines() if line.strip()] if rc == 0 else []


def git_bool(value: str) -> bool | None:
    normalized = value.strip().lower()
    if normalized in {"true", "yes", "on", "1"}:
        return True
    if normalized in {"false", "no", "off", "0"}:
        return False
    return None


def github_slug(remote: str) -> str:
    match = re.search(r"(?i)github\.com[:/]([^/\s]+/[^/?#\s]+)", remote)
    return match.group(1).removesuffix(".git") if match else ""


def install_hint(tool: str) -> str:
    if sys.platform == "win32":
        return {
            "git": "winget install --id Git.Git -e",
            "gh": "winget install --id GitHub.cli -e",
            "ssh": "install Git for Windows or the Windows OpenSSH Client",
        }[tool]
    if sys.platform == "darwin":
        return {
            "git": "xcode-select --install",
            "gh": "brew install gh",
            "ssh": "install the macOS command-line tools",
        }[tool]
    return f"install {tool} with your distribution's package manager"


def github_desktop_installed() -> bool:
    if sys.platform == "win32":
        roots = [os.environ.get("LOCALAPPDATA"), os.environ.get("PROGRAMFILES")]
        for root in (Path(value) for value in roots if value):
            if (root / "GitHubDesktop").exists() or (root / "GitHub Desktop").exists():
                return True
        return False
    if sys.platform == "darwin":
        return (Path("/Applications/GitHub Desktop.app").exists()
                or (Path.home() / "Library/Application Support/GitHub Desktop").exists())
    return False


def report(status, label, detail="", hint=""):
    results.append(status)
    print(f"  {SYM[status]} {label}" + (f": {detail}" if detail else ""))
    if hint and status in (WARN, FAIL):
        print(f"      → {hint}")


def section(title):
    print(f"\n{title}")


def check_git_behavior():
    section("Git behavior / safety")

    rc, _, err = run("git", "config", "--global", "--list", "--show-origin")
    report(OK if rc == 0 else FAIL, "global config parses",
           "ok" if rc == 0 else (err[:160] or "invalid configuration"),
           "inspect ~/.gitconfig and included configuration files")

    use_config_only = gitconf("user.useConfigOnly", "--global")
    if git_bool(use_config_only) is True:
        report(OK, "user.useConfigOnly", "true (Git will not guess an identity)")
    elif use_config_only and git_bool(use_config_only) is None:
        report(FAIL, "user.useConfigOnly", f"invalid boolean: {use_config_only!r}",
               "git config --global user.useConfigOnly true")
    else:
        report(WARN, "user.useConfigOnly", use_config_only or "unset",
               "git config --global user.useConfigOnly true")

    default_branch = gitconf("init.defaultBranch", "--global")
    if default_branch:
        report(OK if default_branch == "main" else INFO, "init.defaultBranch", default_branch)
    else:
        report(WARN, "init.defaultBranch", "unset",
               "git config --global init.defaultBranch main")

    pull_rebase = gitconf("pull.rebase", "--global").lower()
    pull_ff = gitconf("pull.ff", "--global").lower()
    valid_rebase = (git_bool(pull_rebase) is not None
                    or pull_rebase in {"merges", "interactive", "preserve"})
    valid_ff = git_bool(pull_ff) is not None or pull_ff == "only"
    if pull_rebase and not valid_rebase:
        report(FAIL, "pull.rebase", f"invalid value: {pull_rebase!r}")
    elif pull_ff and not valid_ff:
        report(FAIL, "pull.ff", f"invalid value: {pull_ff!r}")
    elif pull_rebase or pull_ff:
        detail = ", ".join(filter(None, (
            f"rebase={pull_rebase}" if pull_rebase else "",
            f"ff={pull_ff}" if pull_ff else "",
        )))
        report(OK, "pull policy", detail)
    else:
        report(WARN, "pull policy", "neither pull.rebase nor pull.ff is explicit",
               "choose one, for example: git config --global pull.ff only")

    push_default = gitconf("push.default", "--global").lower()
    valid_push = {"nothing", "current", "upstream", "simple", "matching"}
    if not push_default:
        report(OK, "push.default", "unset (Git's safe default is simple)")
    elif push_default not in valid_push:
        report(FAIL, "push.default", f"invalid value: {push_default!r}")
    elif push_default == "matching":
        report(WARN, "push.default", "matching can push several branches unexpectedly",
               "git config --global push.default simple")
    else:
        report(OK, "push.default", push_default)

    prune = gitconf("fetch.prune", "--global")
    parsed_prune = git_bool(prune) if prune else None
    if parsed_prune is True:
        report(OK, "fetch.prune", "true")
    elif prune and parsed_prune is None:
        report(FAIL, "fetch.prune", f"invalid boolean: {prune!r}")
    else:
        report(INFO, "fetch.prune", prune or "unset (stale remote branches are retained)")

    autocrlf = gitconf("core.autocrlf", "--global").lower()
    if not autocrlf:
        report(INFO, "core.autocrlf", "unset (repository .gitattributes applies)")
    elif git_bool(autocrlf) is not None or autocrlf == "input":
        report(OK, "core.autocrlf", autocrlf)
    else:
        report(FAIL, "core.autocrlf", f"invalid value: {autocrlf!r}")

    if sys.platform == "win32":
        longpaths = gitconf("core.longpaths")
        if git_bool(longpaths) is True:
            report(OK, "core.longpaths", "true")
        else:
            report(WARN, "core.longpaths", longpaths or "unset",
                   "git config --global core.longpaths true")

        protect_ntfs = gitconf("core.protectNTFS")
        if git_bool(protect_ntfs) is False:
            report(WARN, "core.protectNTFS", "false weakens Windows path protection",
                   "git config --global --unset core.protectNTFS")
        elif protect_ntfs and git_bool(protect_ntfs) is None:
            report(FAIL, "core.protectNTFS", f"invalid boolean: {protect_ntfs!r}")
        else:
            report(OK, "core.protectNTFS", protect_ntfs or "default protection enabled")

    safe_dirs = gitconf_all("safe.directory", "--global")
    if "*" in safe_dirs:
        report(WARN, "safe.directory", "wildcard trusts every repository owner",
               "git config --global --unset-all safe.directory '*'")
    elif safe_dirs:
        report(INFO, "safe.directory", f"{len(safe_dirs)} explicit exception(s)")
    else:
        report(OK, "safe.directory", "no global exceptions")

    file_protocol = gitconf("protocol.file.allow", "--global").lower()
    if file_protocol == "always":
        report(WARN, "protocol.file.allow", "always (local-path submodules are unrestricted)",
               "git config --global --unset protocol.file.allow")
    elif file_protocol in {"never", "user"}:
        report(OK, "protocol.file.allow", file_protocol)
    elif file_protocol:
        report(FAIL, "protocol.file.allow", f"invalid value: {file_protocol!r}")
    else:
        report(OK, "protocol.file.allow", "default restrictions")

    hooks_path = gitconf("core.hooksPath", "--global")
    if hooks_path:
        expanded = Path(os.path.expandvars(os.path.expanduser(hooks_path)))
        if expanded.is_absolute() and not expanded.exists():
            report(WARN, "core.hooksPath", f"missing path: {hooks_path}")
        else:
            report(INFO, "core.hooksPath", hooks_path)


def main():
    results.clear()
    for s in (sys.stdout, sys.stderr):
        if isinstance(s, io.TextIOWrapper):
            try:
                s.reconfigure(encoding="utf-8")
            except ValueError:
                pass

    print("git / GitHub setup check")

    section("Tools")
    have = {}
    for tool in ("git", "gh", "ssh"):
        have[tool] = bool(shutil.which(tool))
        if have[tool]:
            _, ver, _ = run(tool, "--version")
            report(OK, tool, ver.splitlines()[0] if ver else "installed")
        else:
            report(FAIL if tool == "git" else WARN, tool, "not found",
                   install_hint(tool))

    if not have["git"]:
        n_fail, n_warn = results.count(FAIL), results.count(WARN)
        print("\n" + "-" * 48)
        print(f"Summary: {results.count(OK)} ok · {n_warn} warnings · {n_fail} failures")
        sys.exit(1)

    section("Git identity (also used by GitHub Desktop)")
    name = gitconf("user.name", "--global")
    email = gitconf("user.email", "--global")
    report(OK if name else FAIL, "user.name", name or "unset",
           'git config --global user.name "Your Name"')
    if not email:
        report(FAIL, "user.email", "unset",
               'git config --global user.email "ID+user@users.noreply.github.com"')
    elif email.endswith("@users.noreply.github.com"):
        report(OK, "user.email", f"{email}  (GitHub noreply — private)")
    else:
        report(WARN, "user.email", f"{email}  (real address — every commit you push leaks it)",
               "switch to your GitHub noreply and enable 'Keep my email addresses "
               "private' at github.com/settings/emails")

    check_git_behavior()

    section("Commit signing")
    sign_value = gitconf("commit.gpgsign", "--global")
    sign = git_bool(sign_value)
    key = gitconf("user.signingkey", "--global")
    fmt = gitconf("gpg.format", "--global") or "openpgp"
    if sign_value and sign is None:
        report(FAIL, "commit.gpgsign", f"invalid boolean: {sign_value!r}")
    elif fmt not in {"openpgp", "x509", "ssh"}:
        report(FAIL, "gpg.format", f"unsupported value: {fmt!r}")
    elif not sign:
        report(INFO, "commit signing", "off")
    elif key:
        report(OK, "commit signing", f"on ({fmt}, key configured)")
    else:
        report(FAIL, "commit signing", f"on ({fmt}) but no user.signingkey — commits will fail",
               "set user.signingkey, or: git config --global commit.gpgsign false")

    gh_protocol = ""
    if have["gh"]:
        _, gh_protocol, _ = run("gh", "config", "get", "git_protocol")
        gh_protocol = gh_protocol.strip().lower()

    section("Credentials / auth")
    _, helper, _ = run("git", "config", "--get-urlmatch", "credential.helper", "https://github.com")
    helper = helper.strip().splitlines()[0] if helper.strip() else ""
    if not helper and gh_protocol == "ssh":
        report(INFO, "credential helper", "none for github.com (gh uses SSH)")
    elif not helper:
        report(WARN, "credential helper", "none resolved for github.com",
               "run: gh auth setup-git   (lets git push/pull via your gh login)")
    elif "gh" in helper:
        report(OK, "GitHub credential helper", "gh (handles push/pull auth over https)")
    else:
        helper_name = "custom shell command" if helper.startswith("!") else helper.split()[0]
        report(OK, "credential helper", helper_name)

    login = ""
    if have["gh"]:
        section("gh (GitHub CLI)")
        rc, out, err = run("gh", "auth", "status")
        text = f"{out}\n{err}"
        if rc == 0:
            acct = re.search(r"account (\S+)", text)
            proto = re.search(r"protocol:\s*(\S+)", text)
            login = acct.group(1) if acct else ""
            report(OK, "gh auth", f"logged in as {login or '?'}"
                   + (f", git protocol {proto.group(1)}" if proto else ""))
            scopes = re.search(r"[Tt]oken scopes:\s*(.+)", text)
            if scopes:
                report(INFO, "token scopes", scopes.group(1).strip())
        else:
            report(FAIL, "gh auth", "not logged in", "run: gh auth login")

    if have["ssh"] and gh_protocol == "ssh":
        section("SSH")
        _, out, err = run("ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=6",
                          "-o", "StrictHostKeyChecking=yes", "git@github.com", timeout=12)
        blob = f"{out}\n{err}"
        if "successfully authenticated" in blob:
            m = re.search(r"Hi (\S+?)!", blob)
            report(OK, "ssh auth", f"works as {m.group(1) if m else 'ok'}")
        elif "host key verification failed" in blob.lower():
            report(FAIL, "ssh host key", "github.com is not trusted in known_hosts",
                   "verify GitHub's published SSH fingerprint, then run: ssh -T git@github.com")
        else:
            report(FAIL, "ssh auth", "cannot authenticate to git@github.com",
                   "gh auth login (choose SSH), or add a key at github.com/settings/keys")

    section("Cross-tool identity")
    if login:
        _, uid, _ = run("gh", "api", "user", "--jq", ".id")
        expected = f"{uid}+{login}@users.noreply.github.com" if uid else ""
        report(INFO, "gh account", login)
        if email.endswith("@users.noreply.github.com"):
            if login.lower() in email.lower():
                report(OK, "git email ↔ gh account", "match")
            else:
                report(WARN, "git email ↔ gh account",
                       f"git commits as {email} but gh is {login}",
                       f"align them: git config --global user.email {expected}" if expected else "")
        elif email and expected:
            report(WARN, "git email is not your gh noreply",
                   f"recommended: {expected}",
                   f"git config --global user.email {expected}")
    else:
        report(INFO, "cross-tool identity", "gh not logged in — cannot compare")

    section("Current repository")
    rc, _, _ = run("git", "rev-parse", "--is-inside-work-tree")
    if rc != 0:
        report(INFO, "not inside a git repo", "run inside a repo for remote/branch/history checks")
    else:
        rc, _, err = run("git", "config", "--local", "--list", "--show-origin")
        report(OK if rc == 0 else FAIL, "repository config parses",
               "ok" if rc == 0 else (err[:160] or "invalid configuration"))

        rc, branch, _ = run("git", "symbolic-ref", "--quiet", "--short", "HEAD")
        detached = rc != 0
        if detached:
            _, short_head, _ = run("git", "rev-parse", "--short", "HEAD")
            report(WARN, "current branch", f"detached HEAD at {short_head or '?'}")
        else:
            report(OK, "current branch", branch)

        _, status, _ = run("git", "--no-optional-locks", "status", "--porcelain=v1",
                           "--untracked-files=normal")
        changed = len(status.splitlines()) if status else 0
        report(OK if changed == 0 else INFO, "worktree",
               "clean" if changed == 0 else f"{changed} changed/untracked path(s)")

        rc, _, err = run("git", "fsck", "--connectivity-only", "--no-dangling", timeout=30)
        if rc == 0:
            report(OK, "object database", "connectivity check passed")
        elif err == "timeout":
            report(WARN, "object database", "connectivity check timed out")
        else:
            report(FAIL, "object database", "connectivity check failed",
                   "run git fsck --full and inspect the reported corruption")

        rc, origin, _ = run("git", "remote", "get-url", "origin")
        if rc != 0:
            report(WARN, "origin remote", "none", "git remote add origin <url>")
        else:
            if origin.startswith(("git@", "ssh://")):
                kind = "ssh"
            elif origin.startswith(("http://", "https://")):
                kind = "https"
            else:
                kind = "local/other"
            report(INFO, "origin", f"{sanitize_url(origin)}  ({kind})")

            rc, push_url, _ = run("git", "remote", "get-url", "--push", "origin")
            if rc == 0 and push_url != origin:
                report(INFO, "origin push URL", sanitize_url(push_url))

            refspecs = gitconf_all("remote.origin.fetch")
            broad_fetch = any("refs/heads/*:refs/remotes/origin/*" in spec
                              for spec in refspecs)
            report(OK if broad_fetch else WARN, "origin fetch refspec",
                   "all branches" if broad_fetch else (", ".join(refspecs) or "unset"),
                   "git config remote.origin.fetch '+refs/heads/*:refs/remotes/origin/*'")

            if gh_protocol in {"ssh", "https"} and kind in {"ssh", "https"}:
                if gh_protocol == kind:
                    report(OK, "origin protocol ↔ gh", kind)
                else:
                    report(WARN, "origin protocol ↔ gh",
                           f"origin uses {kind}, gh prefers {gh_protocol}",
                           "gh config set git_protocol " + kind)

            slug = github_slug(origin)
            if login and slug:
                rc, selected, _ = run("gh", "repo", "view", "--json", "nameWithOwner",
                                      "--jq", ".nameWithOwner")
                if rc == 0:
                    if selected.lower() == slug.lower():
                        report(OK, "gh repository context", selected)
                    else:
                        report(WARN, "gh repository context",
                               f"origin is {slug}, gh resolved {selected}")

            rc, _, err = run("git", "ls-remote", "origin", "HEAD", timeout=25)
            report(OK if rc == 0 else FAIL, "remote reachable / auth",
                   "ok" if rc == 0 else (sanitize_remote_error(err, origin)[:120] or "failed"),
                   "check the URL and your credentials (gh auth login)")

            _, remote_head, _ = run("git", "symbolic-ref", "--quiet", "--short",
                                    "refs/remotes/origin/HEAD")
            if remote_head:
                report(INFO, "origin default branch", remote_head.removeprefix("origin/"))

        if not detached:
            rc, up, _ = run("git", "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}")
            if rc == 0:
                report(OK, "upstream tracking", up)
                rc, counts, _ = run("git", "rev-list", "--left-right", "--count",
                                    "@{u}...HEAD")
                parts = counts.split()
                if rc == 0 and len(parts) == 2:
                    behind, ahead = parts
                    report(OK if ahead == behind == "0" else INFO, "upstream divergence",
                           f"ahead {ahead}, behind {behind}")
            else:
                report(WARN, "upstream tracking", "current branch tracks nothing",
                       f"git push -u origin {branch}")

        effective_name = gitconf("user.name")
        effective_email = gitconf("user.email")
        report(OK if effective_name else FAIL, "effective commit name",
               effective_name or "unset", 'git config user.name "Your Name"')
        if not effective_email:
            report(FAIL, "effective commit email", "unset",
                   'git config user.email "ID+user@users.noreply.github.com"')
        elif effective_email.endswith("@users.noreply.github.com"):
            detail = effective_email
            if effective_email != email:
                detail += " (repository override)"
            report(OK, "effective commit email", detail)
        else:
            detail = effective_email
            if effective_email != email:
                detail += " (repository override)"
            report(WARN, "effective commit email", f"{detail} — real address",
                   'git config user.email "ID+user@users.noreply.github.com"')

        rc, _, _ = run("git", "rev-parse", "--verify", "HEAD")
        if rc == 0:
            _, emails, _ = run("git", "log", "--all", "--format=%ae")
            addrs = {e for e in emails.splitlines() if e.strip()}
            real = sorted(e for e in addrs if not e.endswith("@users.noreply.github.com"))
            if real:
                report(WARN, "commit emails in history",
                       f"{len(real)} non-noreply: {', '.join(real[:3])}"
                       + (" …" if len(real) > 3 else ""),
                       "these are baked into history and pushed; rewrite with git-filter-repo "
                       "if this repo is/goes public")
            elif addrs:
                report(OK, "commit emails in history", "all GitHub noreply")

    section("GitHub Desktop")
    desktop = github_desktop_installed()
    if desktop:
        report(OK, "GitHub Desktop", "installed")
        report(INFO, "identity", "commits with your global git user.name/email (checked above), "
               "so the same noreply protection applies")
    else:
        report(INFO, "GitHub Desktop", "not detected")

    n_fail, n_warn = results.count(FAIL), results.count(WARN)
    print("\n" + "-" * 48)
    print(f"Summary: {results.count(OK)} ok · {n_warn} warnings · {n_fail} failures")
    if n_fail or n_warn:
        print("Fix the ✗ / ⚠ lines above.")
    sys.exit(1 if n_fail else 0)


if __name__ == "__main__":
    main()
