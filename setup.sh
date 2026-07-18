#!/usr/bin/env bash
# One-step setup: venv + dependencies + spaCy model + personal.txt.
set -euo pipefail
cd "$(dirname "$0")"

for tool in gh git gitleaks python3; do
  command -v "$tool" >/dev/null || { echo "Missing '$tool' — install it first (see README)."; exit 1; }
done
if ! python3 -c 'import sys; raise SystemExit(not ((3, 9) <= sys.version_info[:2] < (3, 15)))'; then
  echo "Python 3.9–3.14 is required."
  exit 1
fi

python3 -m venv .venv
.venv/bin/pip install --require-hashes -r requirements.lock

if [ ! -f personal.txt ]; then
  cp personal.example.txt personal.txt
  echo "Created personal.txt from the example — edit it with your own identifiers."
fi
chmod 600 personal.txt

echo
echo "Done. Next:"
echo "  1. edit personal.txt"
echo "  2. gh auth login   (if not already)"
echo "  3. .venv/bin/python sweep.py"
