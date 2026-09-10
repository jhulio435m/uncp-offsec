# Requires Python 3.10+ in PATH. The full scanner runs through Docker Desktop/WSL2.
$ErrorActionPreference = 'Stop'
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    throw 'Python 3.10 or newer is required. Install it, reopen PowerShell, and retry.'
}
python -m pip install --user --upgrade pipx
python -m pipx ensurepath
python -m pipx install --force .
Write-Host 'Installed. Open a new PowerShell session, then run: uncp_offsec doctor'
