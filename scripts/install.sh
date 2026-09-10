#!/usr/bin/env sh
# Install the CLI without requiring root. Full web scanning is run in OCI.
set -eu

if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3.10 or newer is required." >&2
  exit 1
fi

python3 -m pip install --user --upgrade pipx
python3 -m pipx ensurepath
python3 -m pipx install --force .
echo "Installed. Open a new shell, then run: uncp_offsec doctor"
