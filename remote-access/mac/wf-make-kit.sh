#!/bin/sh
# wf-make-kit.sh: build the folder you carry to the PC, as one zip with one SHA-256 to check.
#
#   sh remote-access/mac/wf-make-kit.sh --mac-address <MAC_LAN_ADDRESS> [--account <name>] [--public-key <file.pub>] [--out <file.zip>]
#
# The kit holds the setup script, the dispatcher, any collectors in collectors/windows, the
# checklist, the Mac's PUBLIC key, and RUN-AT-PC.txt with the exact command to run. It never
# holds a private key: a file that is not a bare ssh-ed25519 public key is refused.
set -eu
# shellcheck source-path=SCRIPTDIR
. "$(dirname "$0")/wf-common.sh"

mac_address=""
account="wfcollector"
public_key="$WF_KEY_FILE.pub"
out_zip="$HOME/Desktop/wf-frontdoor-kit.zip"
while [ $# -gt 0 ]; do
    case "$1" in
        --mac-address) mac_address="${2:-}"; shift 2 ;;
        --account) account="${2:-}"; shift 2 ;;
        --public-key) public_key="${2:-}"; shift 2 ;;
        --out) out_zip="${2:-}"; shift 2 ;;
        -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
        *) wf_die "unknown option: $1" ;;
    esac
done
[ -n "$mac_address" ] || wf_die "give this Mac's address on the home network: --mac-address <MAC_LAN_ADDRESS> (System Settings > Network, or: ipconfig getifaddr en0)"
wf_is_ipv4 "$mac_address" || wf_die "--mac-address must be an IPv4 address (four numbers separated by dots), not a hardware address"
# The same rule Install-FrontDoor.ps1 applies to -AccountName, and wf-mac-setup.sh to --account.
printf '%s\n' "$account" | grep -Eq '^[a-z][a-z0-9]{2,19}$' || wf_die "--account must be lower case letters and digits, 3 to 20 characters, the same value given to wf-mac-setup.sh"
[ -f "$public_key" ] || wf_die "public key file not found: $public_key (run wf-mac-setup.sh first)"
if grep -q "PRIVATE KEY" "$public_key"; then
    wf_die "$public_key is a PRIVATE key. It must never leave this Mac. Use the file ending in .pub"
fi
[ "$(grep -c . "$public_key")" = "1" ] || wf_die "$public_key must hold exactly one line"
[ "$(awk 'NF { print $1; exit }' "$public_key")" = "ssh-ed25519" ] || wf_die "$public_key is not a bare ssh-ed25519 public key"
ssh-keygen -l -E sha256 -f "$public_key" >/dev/null 2>&1 || wf_die "$public_key is not a valid public key"
command -v zip >/dev/null 2>&1 || wf_die "the zip command is not available"

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
kit="$stage/wf-frontdoor-kit"
mkdir -p "$kit/remote-access/windows" "$kit/collectors/windows"
for f in Install-FrontDoor.ps1 WfSetupLib.ps1 WfCommon.ps1 dispatch.ps1; do
    cp "$repo_root/remote-access/windows/$f" "$kit/remote-access/windows/$f"
done
cp "$repo_root/remote-access/CHECKLIST.md" "$kit/CHECKLIST.md"
collectors=0
for f in "$repo_root"/collectors/windows/*.ps1; do
    [ -f "$f" ] || continue
    cp "$f" "$kit/collectors/windows/"
    collectors=$((collectors + 1))
done
# Only the key type and the key itself travel; the comment (usually user@host) stays here.
awk 'NF { print $1, $2, "win-forensics-mac"; exit }' "$public_key" >"$kit/mac-public-key.pub"

# The two values the double click launcher (Start-FrontDoorSetup.ps1) passes to the setup script.
# It reads them from the verified zip, never from the command line or from a person.
{
    printf '# win-forensics front door kit parameters, written by wf-make-kit.sh. Start-FrontDoorSetup.ps1 reads them.\n'
    printf 'mac_address=%s\n' "$mac_address"
    printf 'account=%s\n' "$account"
} >"$kit/kit-parameters.txt"

command_line="powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\\remote-access\\windows\\Install-FrontDoor.ps1 -MacIpAddress $mac_address -MacPublicKeyFile .\\mac-public-key.pub -AccountName $account"
{
    printf 'win-forensics front door kit\r\n\r\n'
    printf 'Follow CHECKLIST.md (step 5 onward). The short form:\r\n\r\n'
    printf '1. Right click the Start button and choose "Terminal (Admin)".\r\n'
    # shellcheck disable=SC2016
    printf '2. Go to this folder, for example:  cd $HOME\\Desktop\\wf-frontdoor-kit\r\n'
    printf '3. Run this one line:\r\n\r\n'
    printf '%s\r\n\r\n' "$command_line"
    printf 'The last lines say RESULT: PASS, RESULT: INCOMPLETE, or RESULT: FAIL. Only PASS means\r\n'
    printf 'it worked; INCOMPLETE means a check could not run and is not a pass. It is safe to run again.\r\n'
} >"$kit/RUN-AT-PC.txt"

mkdir -p "$(dirname "$out_zip")"
rm -f "$out_zip"
(cd "$stage" && zip -q -r -X "$stage/kit.zip" wf-frontdoor-kit)
mv "$stage/kit.zip" "$out_zip"

digest="$(wf_sha256 "$out_zip" | tr 'a-f' 'A-F')"
grouped="$(printf '%s' "$digest" | sed 's/.\{8\}/& /g; s/ $//')"
printf 'Kit written: %s (%s collector script(s) inside; account %s)\n\n' "$out_zip" "$collectors" "$account"
printf 'Kit code (what the double click launcher at the PC asks for):\n\n    %s\n\n' "$(wf_kit_code "$digest")"
printf 'SHA-256 of the zip. Keep this on screen, or photograph it, to compare at the PC:\n\n    %s\n\n' "$grouped"
printf 'At the PC, before unpacking, this must print the same eight groups:\n\n'
printf "    ((Get-FileHash .\\\\wf-frontdoor-kit.zip -Algorithm SHA256).Hash -split '(.{8})' -ne '') -join ' '\n\n"
printf 'Then unpack it (Expand-Archive .\\wf-frontdoor-kit.zip -DestinationPath .) and run, as Administrator, inside the wf-frontdoor-kit folder:\n\n    %s\n' "$command_line"
