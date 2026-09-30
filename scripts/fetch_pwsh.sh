#!/usr/bin/env bash
# Fetch a user local PowerShell 7 plus Pester and PSScriptAnalyzer into tools/
# (ignored by git) so the collector checks can run off Windows:
#
#   scripts/fetch_pwsh.sh
#   pytest tests/test_collectors_pwsh.py
#
# Nothing is installed system wide. The tarball is the official PowerShell
# release, pinned by version and SHA-256 from the release's hashes.sha256:
# https://github.com/PowerShell/PowerShell/releases/tag/v7.4.6
# The collectors themselves target Windows PowerShell 5.1; PowerShell 7 is
# only the host for the portable tests and for PSScriptAnalyzer, whose
# compatibility rules check the scripts against 5.1.
set -euo pipefail

VERSION=7.4.6
PESTER_VERSION=5.6.1
ANALYZER_VERSION=1.23.0
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="$ROOT/tools/pwsh"
MODULES="$ROOT/tools/psmodules"

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64)  ASSET="powershell-$VERSION-osx-arm64.tar.gz";   SHA=a482d668787ef98c37f0a5a7696107dffdb3dc340c5be3d1c153ec9d239072a8 ;;
  Darwin-x86_64) ASSET="powershell-$VERSION-osx-x64.tar.gz";     SHA=7a18daed105b7cfc80bf8cc00762fe7990105dd23f951cc32ceb744651650e3d ;;
  Linux-x86_64)  ASSET="powershell-$VERSION-linux-x64.tar.gz";   SHA=6f6015203c47806c5cc444c19d8ed019695e610fbd948154264bf9ca8e157561 ;;
  Linux-aarch64) ASSET="powershell-$VERSION-linux-arm64.tar.gz"; SHA=c0159b03e85f44ae1e7697818a011558da6c813d0aae848bf5ac13bf435d8624 ;;
  *) echo "no pinned PowerShell build for $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac

if [ ! -x "$DEST/pwsh" ]; then
  mkdir -p "$DEST"
  TARBALL="$DEST/$ASSET"
  curl -fsSL -o "$TARBALL" "https://github.com/PowerShell/PowerShell/releases/download/v$VERSION/$ASSET"
  if command -v sha256sum >/dev/null 2>&1; then ACTUAL="$(sha256sum "$TARBALL" | cut -d' ' -f1)"; else ACTUAL="$(shasum -a 256 "$TARBALL" | cut -d' ' -f1)"; fi
  if [ "$ACTUAL" != "$SHA" ]; then
    echo "checksum mismatch for $ASSET: expected $SHA, got $ACTUAL" >&2
    rm -f "$TARBALL"
    exit 1
  fi
  tar -xzf "$TARBALL" -C "$DEST"
  rm -f "$TARBALL"
  chmod +x "$DEST/pwsh"
fi

mkdir -p "$MODULES"
"$DEST/pwsh" -NoProfile -NonInteractive -Command "
  \$ErrorActionPreference = 'Stop'
  \$ProgressPreference = 'SilentlyContinue'
  if (-not (Test-Path -LiteralPath '$MODULES/Pester/$PESTER_VERSION')) { Save-Module -Name Pester -RequiredVersion $PESTER_VERSION -Path '$MODULES' -Repository PSGallery }
  if (-not (Test-Path -LiteralPath '$MODULES/PSScriptAnalyzer/$ANALYZER_VERSION')) { Save-Module -Name PSScriptAnalyzer -RequiredVersion $ANALYZER_VERSION -Path '$MODULES' -Repository PSGallery }
"
echo "PowerShell $("$DEST/pwsh" -NoProfile -Command '$PSVersionTable.PSVersion.ToString()') in $DEST, modules in $MODULES"
