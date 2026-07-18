# leak-sweep

**Scan all your GitHub repos for leaked personal information — so you don't get
doxxed by your own git history.** The main Python scanner drives
[gitleaks](https://github.com/gitleaks/gitleaks),
[Presidio](https://github.com/data-privacy-stack/presidio) and
[python-stdnum](https://github.com/arthurdejong/python-stdnum) (LGPL) over every
repo you can reach with `gh`, and tells you exactly where your private data shows up.

It looks for:

- **Secrets** (API keys, tokens, passwords) across the *entire git history* — gitleaks
- **Your own identifiers** (name, email, phone, address — from `personal.txt`) across the whole history
- **National ID numbers** for the selected regions (checksum-validated via python-stdnum), in history and files
- **General PII** in current files (names, locations, emails, phones, cards, IBAN, public IPs) — Presidio
- **Commit identities** (author/committer) and **file paths** matching your identifiers
- **Beyond your own repos** (with `--deep`): repos you collaborate on, your public profile, gists, forks of your repos, EXIF/GPS in committed images, and a GitHub-wide search for your identifiers in *other people's* repos

Nothing leaves your machine except requests and clones sent to GitHub. The
optional `--search` check submits each watchlist term to GitHub's Search API.
Sensitive values (cards, national IDs, secrets and GPS coordinates) are
**masked in the report by default**.

## Why

Public repos leak more than code: a real email in an old commit, a phone number
in a test fixture, an API key in history, a config file you forgot to `.gitignore`.
This finds those before someone else does.

## Setup

### macOS

```sh
brew install python gh gitleaks  # then `gh auth login` if you aren't logged in
./setup.sh                   # creates .venv, installs deps + the spaCy model, seeds personal.txt
```

### Linux

Install Python 3.9–3.14, Git and GitHub CLI with your distribution's package
manager, install Gitleaks from its official release, then run:

```sh
./setup.sh
gh auth login
```

### Windows (PowerShell)

```powershell
winget install --id Python.Python.3.13 -e
winget install --id Git.Git -e
winget install --id GitHub.cli -e
winget install --id Gitleaks.Gitleaks -e
```

Open a new PowerShell window after the installs so `PATH` is refreshed, then:

```powershell
.\setup.ps1
gh auth login
.\.venv\Scripts\python.exe .\sweep.py --selftest
```

<details><summary>Manual setup (if you'd rather not run the script)</summary>

```sh
python3 -m venv .venv
.venv/bin/pip install --require-hashes -r requirements.lock
cp personal.example.txt personal.txt   # then fill in your own identifiers
chmod 600 personal.txt
```
</details>

Edit `personal.txt` with the identifiers you care about (emails, phone numbers
in a few formats, addresses, old usernames). It is **gitignored** and the tool
refuses to run if it ever becomes git-tracked. Its terms stay local unless you
explicitly enable `--search` or `--deep`.

> Runs natively on Python 3.9–3.14 on macOS, Linux and Windows. `setup.ps1`
> creates the Windows virtual environment and restricts `personal.txt` to the
> current Windows account.

When run from this checkout, private data stays under the checkout. An installed
`leak-sweep` command uses the private `~/.leak-sweep` directory.

## Usage

```sh
.venv/bin/python sweep.py                  # all your repos (forks skipped)
.venv/bin/python sweep.py --repo NAME      # a single repo (repeatable)
.venv/bin/python sweep.py --owner ORG      # a user/org you have access to
.venv/bin/python sweep.py --include-forks  # include forks
.venv/bin/python sweep.py --no-presidio    # skip the NER pass (faster)
.venv/bin/python sweep.py --id-regions SE,DK   # national-ID regions (default: auto)
.venv/bin/python sweep.py --id-regions all      # every supported country (noisier)
.venv/bin/python sweep.py --id-regions none     # disable national-ID detection
.venv/bin/python sweep.py --region GB      # phone-number region for parsing (default: NO)
.venv/bin/python sweep.py --raw            # write full unmasked values to the report
.venv/bin/python sweep.py --fail-on public # exit 1 on public findings (default: never; for cron/CI)
.venv/bin/python sweep.py --clean          # delete the work/ clones
.venv/bin/python sweep.py --version        # print version
.venv/bin/python sweep.py --selftest       # run the built-in checks
```

In Windows PowerShell, use `.\.venv\Scripts\python.exe .\sweep.py` in place
of `.venv/bin/python sweep.py`.

### Beyond your own repos

By default the tool scans repos you **own**. These flags widen the net to the
rest of your GitHub doxxing surface:

```sh
.venv/bin/python sweep.py --collaborator   # also repos you collaborate on (not just own)
.venv/bin/python sweep.py --profile        # what your public profile exposes (name/location/bio/email)
.venv/bin/python sweep.py --gists          # your gists (public + secret)
.venv/bin/python sweep.py --forks          # forks of your public repos (leaks live on there)
.venv/bin/python sweep.py --exif           # GPS/author metadata in committed images/PDFs (needs exiftool)
.venv/bin/python sweep.py --search         # GitHub-wide search (code/commits/issues) in OTHERS' repos
.venv/bin/python sweep.py --wiki           # your repos' wikis (separate .wiki.git repos)
.venv/bin/python sweep.py --releases       # release names + notes
.venv/bin/python sweep.py --actions        # recent Actions run logs (watchlist terms; slow)
.venv/bin/python sweep.py --deep           # all of the above at once
```

`--search` is **best-effort** and sends every term in `personal.txt` to GitHub's
Search API. GitHub only indexes default branches of non-archived public repos,
so it can miss things — it complements, not replaces, the clone scan of your
own repos.

The report lands in `reports/report-<timestamp>.md` (plus a `.json`).
`reports/`, `work/` (the clones) and `personal.txt` are gitignored — no findings
or private data are ever committed, and source-checkout runs skip that
checkout's origin. These paths use owner-only POSIX permissions on macOS/Linux
and a current-user-only ACL on Windows. **The report still contains your
watchlist identifiers in cleartext — keep it private.**

### Exit codes (for cron/CI)

By default the tool exits `0` after a complete report-only scan. For automation,
pass `--fail-on public` (or `any`): `1` = matching findings, `2` = an incomplete
scan, and `130` = interrupted (a partial report is still written).

Weekly sweep via cron (adjust the path to wherever you cloned it):

```
0 9 * * 1 cd /path/to/leak-sweep && .venv/bin/python sweep.py --fail-on public
```

## Check your git setup

`gitcheck.py` performs a read-only check of your local Git / GitHub setup across
**git, the gh CLI and GitHub Desktop**:

```sh
python3 gitcheck.py
# or, after installing the wheel: leak-sweep-gitcheck
```

It checks commit identity and GitHub noreply use, auth and credential helpers,
commit signing, default branch and pull/push policy, pruning and line-ending
behavior, risky `safe.directory`/file-protocol settings, hooks, and
Windows-specific long-path/NTFS protection. Inside a repo it also checks local
config parsing, branch/worktree state, object-database connectivity, origin and
fetch refspec, remote protocol/reachability, upstream/ahead/behind status, and
commit emails already present in history. It exits non-zero if a check fails;
warnings identify recommended or privacy-sensitive improvements.

## Development checks

```sh
.venv/bin/pip install --require-hashes -r requirements-dev.lock
.venv/bin/python -m py_compile sweep.py gitcheck.py leak_sweep_reporting.py national_id.py
.venv/bin/python sweep.py --selftest
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/ruff check .
.venv/bin/pyright --pythonpath .venv/bin/python
.venv/bin/pip-audit --require-hashes -r requirements.lock
.venv/bin/pip-licenses
.venv/bin/python -m build --no-isolation
bash -n setup.sh
```

`pyproject.toml` is the dependency source of truth. Regenerate the checked-in
hash-locked files with [uv](https://docs.astral.sh/uv/) after changing it:

```sh
uv pip compile pyproject.toml --python-version 3.9 --universal --generate-hashes -o requirements.lock
uv pip compile pyproject.toml --extra dev --python-version 3.9 --universal --generate-hashes -o requirements-dev.lock
```

## Releases

Update `sweep.__version__`, merge a green CI run, then create and push a matching
signed or annotated `vX.Y.Z` tag. The release workflow verifies the tag/version
pair, rebuilds and tests the wheel, generates release notes from Git history,
and publishes it to GitHub Releases. It does not publish to PyPI.

## Known limitations

- Phone numbers without `+`/separators in code files are not reported (too much
  noise from dates) — put your number in `personal.txt` and it's caught everywhere
- NER runs on at most 400 prose files per repo; files > 512 KB are skipped (counted in the report)
- Binary files (PDFs, images) aren't scanned — but their paths are checked against your watchlist
- Presidio uses the English model (`en_core_web_sm`); Norwegian names are caught
  most reliably via `personal.txt`. For better NER, install `en_core_web_lg` into
  the venv and swap the model name in `sweep.py`.
- National-ID detection is checksum-based (python-stdnum); some countries' IDs
  have weak validation, so verify before acting.

## License

MIT — see [LICENSE](LICENSE). Use at your own risk, and only scan repos you own
or are authorised to access.
