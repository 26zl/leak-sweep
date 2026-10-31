# Contributing

Bug reports and feature requests go in
[GitHub issues](https://github.com/26zl/leak-sweep/issues). Vulnerabilities go
through GitHub Security Advisories instead, as described in
[SECURITY.md](SECURITY.md). Never put real secrets, credentials, national IDs
or other personal data in an issue, pull request, screenshot or test fixture;
keep test data synthetic.

## Development setup

You need Python 3.10–3.14, Git, the GitHub CLI (`gh`) and
[gitleaks](https://github.com/gitleaks/gitleaks); the README lists per-platform
installs. [uv](https://docs.astral.sh/uv/) is only needed to regenerate the
lock files.

```sh
./setup.sh                                                        # .venv, runtime deps, personal.txt
.venv/bin/pip install --require-hashes -r requirements-dev.lock   # ruff, pyright, pip-audit, pip-licenses, build
```

On Windows run `.\setup.ps1` and use `.\.venv\Scripts\python.exe`,
`.\.venv\Scripts\ruff.exe` and so on in the commands below.

## Checks

CI (`.github/workflows/ci.yml`) runs these; run them before opening a pull
request:

```sh
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

Tests are standard `unittest` modules in `tests/`; add a `test_*.py` file or
extend an existing one. Code targets Python 3.10 syntax with 100-character
lines; `ruff` and `pyright` are configured in `pyproject.toml`.

`pip-audit` lists `en-core-web-sm` as skipped because the spaCy model is
installed from a GitHub release wheel rather than from PyPI. That is expected;
the check only fails on known vulnerabilities in the PyPI packages.

## Dependencies

`pyproject.toml` is the source of truth. `requirements.lock` and
`requirements-dev.lock` are hash-locked with uv for Python 3.10–3.14 on all
platforms, and CI's `locks` job fails when they no longer match
`pyproject.toml`. After changing a dependency, regenerate both:

```sh
uv pip compile pyproject.toml --python-version 3.10 --universal --generate-hashes -o requirements.lock
uv pip compile pyproject.toml --extra dev --python-version 3.10 --universal --generate-hashes -o requirements-dev.lock
```

To move a single package, for example after a security advisory, add
`--upgrade-package NAME` to both commands. Dependabot only bumps the pins in
`pyproject.toml`; push a commit with the regenerated lock files to its branch
before merging.

## Pull requests

- Branch from `main` and keep each pull request to one change.
- Write commit messages in the imperative mood and explain the why in the
  body when it is not obvious from the diff.
- Never commit `personal.txt`, `reports/` or `work/`; they are gitignored on
  purpose and the tool refuses to run if `personal.txt` is tracked.
- CI must pass on the pull request: self-test and unit tests on Python
  3.10–3.14 (Linux) and 3.11 (Windows), the locked installs, the `quality`
  job and the lock-file check.

## Releases

Maintainers release by bumping `sweep.__version__`, merging a green `main` and
pushing a matching `vX.Y.Z` tag. `.github/workflows/release.yml` verifies the
tag against the version, re-runs the checks, builds the wheel and publishes it
to GitHub Releases. Nothing is published to PyPI.
