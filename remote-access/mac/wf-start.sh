#!/bin/sh
# wf-start.sh: the whole Mac side of the win-forensics front door setup, in one command.
#
#   sh remote-access/mac/wf-start.sh --pc-address <PC_LAN_ADDRESS> [--mac-address <MAC_LAN_ADDRESS>] [--kit <folder>] [--account <name>]
#
# It runs the existing scripts in order and explains what to do at the PC afterwards:
#   1. wf-mac-setup.sh   the dedicated Ed25519 key (created with a passphrase, or reused when it
#                        already exists), the ssh-agent, and the "Host gaming-pc" block in ~/.ssh/config
#   2. wf-make-kit.sh    the zip that goes to the PC, with only the PUBLIC key in it
#   3. this script       the kit folder (default: ~/Desktop/wf-frontdoor) holding that zip, the
#                        double click launcher SETUP-PC.cmd with its Start-FrontDoorSetup.ps1, and
#                        READ-ME-FIRST.txt; then the kit code to carry to the PC
# The Mac's own address is detected from the default network interface (macOS: route and
# ipconfig, see "man route" and "man ipconfig") and can be given with --mac-address instead.
# Nothing here reads, prints, or moves a private key or a passphrase.
set -eu
# shellcheck source-path=SCRIPTDIR
. "$(dirname "$0")/wf-common.sh"

pc_address=""
mac_address=""
account="wfcollector"
kit_folder="$HOME/Desktop/wf-frontdoor"
while [ $# -gt 0 ]; do
    case "$1" in
        --pc-address) pc_address="${2:-}"; shift 2 ;;
        --mac-address) mac_address="${2:-}"; shift 2 ;;
        --account) account="${2:-}"; shift 2 ;;
        --kit) kit_folder="${2:-}"; shift 2 ;;
        --host-alias) WF_HOST_ALIAS="${2:-}"; shift 2 ;;
        -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
        *) wf_die "unknown option: $1" ;;
    esac
done
[ -n "$pc_address" ] || wf_die "give the PC's address on the home network: --pc-address <PC_LAN_ADDRESS> (on the PC: Settings > Network & internet > your connection > IPv4 address)"
wf_is_ipv4 "$pc_address" || wf_die "--pc-address must be an IPv4 address (four numbers separated by dots)"
[ -n "$kit_folder" ] || wf_die "--kit needs a folder path"
script_dir="$(cd "$(dirname "$0")" && pwd)"
windows_dir="$script_dir/../windows"

# The Mac's address, detected unless given. The PC will accept SSH from this address only.
if [ -z "$mac_address" ]; then
    if [ "$(uname -s)" = "Darwin" ]; then
        iface="$(route -n get default 2>/dev/null | awk '/interface:/ {print $2}')"
        [ -n "$iface" ] && mac_address="$(ipconfig getifaddr "$iface" 2>/dev/null || true)"
    fi
    [ -n "$mac_address" ] || wf_die "could not detect this Mac's address on the home network. Give it with --mac-address <MAC_LAN_ADDRESS> (System Settings > Network > your connection > Details)"
    printf 'This Mac'"'"'s address: %s (detected; give --mac-address to use another)\n' "$mac_address"
fi
wf_is_ipv4 "$mac_address" || wf_die "--mac-address must be an IPv4 address (four numbers separated by dots), not a hardware address"
[ "$mac_address" != "$pc_address" ] || wf_die "the Mac's address and the PC's address are the same ($pc_address); one of them is wrong"

printf '\n==== 1 of 3: key and ssh configuration on this Mac ====\n'
sh "$script_dir/wf-mac-setup.sh" --pc-address "$pc_address" --account "$account" --host-alias "$WF_HOST_ALIAS"

printf '\n==== 2 of 3: the kit for the PC ====\n'
mkdir -p "$kit_folder"
# Leftovers of an earlier trip to the PC would mislead wf-finish.sh: a new kit starts a new trip.
for stale in pc-host-key.pub wf-frontdoor-report.txt; do
    if [ -f "$kit_folder/$stale" ]; then
        rm -f "$kit_folder/$stale"
        printf 'Removed %s from an earlier setup.\n' "$kit_folder/$stale"
    fi
done
zip_path="$kit_folder/wf-frontdoor-kit.zip"
kit_log="$(mktemp)"
trap 'rm -f "$kit_log"' EXIT
if ! sh "$script_dir/wf-make-kit.sh" --mac-address "$mac_address" --account "$account" --out "$zip_path" >"$kit_log" 2>&1; then
    cat "$kit_log" >&2
    wf_die "the kit could not be built (see above)"
fi
head -n 1 "$kit_log"
for f in SETUP-PC.cmd Start-FrontDoorSetup.ps1; do
    [ -f "$windows_dir/$f" ] || wf_die "$windows_dir/$f is missing from this checkout"
    cp "$windows_dir/$f" "$kit_folder/$f"
done
digest="$(wf_sha256 "$zip_path")"
code="$(wf_kit_code "$digest")"
{
    printf 'win-forensics front door: the kit for the PC\r\n\r\n'
    printf 'This folder holds no secret. It goes to the PC as a whole (USB stick is simplest).\r\n\r\n'
    printf '1. Close any game on the PC.\r\n'
    printf '2. Double click SETUP-PC.cmd in this folder. If Windows warns about an unknown\r\n'
    printf '   publisher, choose to run it; then choose Yes at the "make changes" prompt.\r\n'
    printf '3. Type the kit code that the Mac printed when it asked for it (8 groups of 4).\r\n'
    printf '4. Wait for the last line: DONE: RESULT: PASS is the only good one.\r\n'
    printf '5. Take this folder (the stick) back to the Mac and run:\r\n'
    printf '       sh remote-access/mac/wf-finish.sh\r\n\r\n'
    printf 'For people who prefer typing commands, RUN-AT-PC.txt inside the zip has the long way.\r\n'
} >"$kit_folder/READ-ME-FIRST.txt"

printf '\n==== 3 of 3: what to do next ====\n\n'
printf 'The kit folder is ready:  %s\n' "$kit_folder"
printf '    SETUP-PC.cmd, Start-FrontDoorSetup.ps1, wf-frontdoor-kit.zip, READ-ME-FIRST.txt (no secret in any of them)\n\n'
printf 'Write down or photograph this KIT CODE. The PC asks you to type it:\n\n'
printf '    %s\n\n' "$code"
printf '(That is the start of the zip'"'"'s SHA-256, %s. Typing all 64 characters at the PC works too.)\n\n' "$digest"
printf 'Then:\n'
printf '  1. Copy the whole wf-frontdoor folder to a USB stick (or any way you move files to the PC).\n'
printf '  2. At the PC, with no game running: open the folder and double click SETUP-PC.cmd.\n'
printf '     Windows asks whether the program may make changes: choose Yes.\n'
printf '  3. In the window that opens, type the kit code above when asked.\n'
printf '     If it says the code does not match, stop: copy the folder from this Mac again.\n'
printf '  4. Wait. The last line must read DONE: RESULT: PASS (about 10 minutes, mostly waiting).\n'
printf '     INCOMPLETE or FAIL: read the line above it and the checklist row it names, then double click again.\n'
printf '  5. Bring the stick back here and run:  sh remote-access/mac/wf-finish.sh\n'
printf '     (it reads the PC'"'"'s host key from the stick; if the kit did not travel on a stick, it shows the\n'
printf '     fingerprint and asks you to compare it with the PC screen).\n\n'
printf 'Router reminder: reserve both addresses (%s for the PC, %s for this Mac) in the router, see CHECKLIST.md action 2.\n' "$pc_address" "$mac_address"
