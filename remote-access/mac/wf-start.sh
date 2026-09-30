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
#                        READ-ME-FIRST.txt; then the two values to carry to the PC
# The two values: the kit code (for the double click launcher, which only runs from a USB stick)
# and the full SHA-256 (for the manual check with Windows' own Get-FileHash, which is the only
# check for a kit that went any other way). Neither is written into the kit: they travel from
# this screen, not with the files they check.
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
        -h|--help) sed -n '2,19p' "$0"; exit 0 ;;
        *) wf_die "unknown option: $1" ;;
    esac
done
[ -n "$pc_address" ] || wf_die "give the PC's address on the home network: --pc-address <PC_LAN_ADDRESS> (on the PC: Settings > Network & internet > your connection > IPv4 address)"
wf_is_ipv4 "$pc_address" || wf_die "--pc-address must be an IPv4 address (four numbers from 0 to 255 separated by dots)"
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
wf_is_ipv4 "$mac_address" || wf_die "--mac-address must be an IPv4 address (four numbers from 0 to 255 separated by dots), not a hardware address"
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
full="$(wf_full_digest "$digest")"
run_line="powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\\remote-access\\windows\\Install-FrontDoor.ps1 -MacIpAddress $mac_address -MacPublicKeyFile .\\mac-public-key.pub -AccountName $account"
# The read me names no code and no digest: they come from the Mac screen, never with the kit.
{
    printf 'win-forensics front door: the kit for the PC\r\n\r\n'
    printf 'This folder holds no secret. Close any game on the PC before you start. Two ways in:\r\n\r\n'
    printf 'A. THE KIT CAME ON A USB STICK that stayed in your hands (the one double click):\r\n'
    printf '   1. Double click SETUP-PC.cmd in this folder, on the stick. If Windows warns about an unknown\r\n'
    printf '      publisher, choose to run it; then choose Yes at the "make changes" prompt.\r\n'
    printf '   2. Type the KIT CODE the Mac printed when it asks (8 groups of 4).\r\n'
    printf '   3. Wait for the last line: DONE: RESULT: PASS is the only good one.\r\n'
    printf '   4. Take the stick back to the Mac and run:  sh remote-access/mac/wf-finish.sh\r\n'
    printf '   The launcher refuses to run from anywhere but a removable drive, because it travels with\r\n'
    printf '   the kit and cannot prove it was not changed on the way.\r\n\r\n'
    printf 'B. THE KIT CAME ANY OTHER WAY (cloud folder, network share, download, a copy on this PC):\r\n'
    printf '   Do not double click anything. Windows itself checks the zip first:\r\n'
    printf '   1. Right click Start, "Terminal (Admin)", Yes at the prompt. If the prompt does not start\r\n'
    printf '      with PS, type powershell and press Enter.\r\n'
    # shellcheck disable=SC2016
    printf '   2. cd into this folder (for example: cd $HOME\\Desktop\\wf-frontdoor), then type, with the\r\n'
    printf '      64 characters of the FULL SHA-256 from the Mac screen in place of the dots (no spaces):\r\n'
    printf "         (Get-FileHash .\\\\wf-frontdoor-kit.zip -Algorithm SHA256).Hash -eq '................................................................'\\r\\n"
    printf '      It must print True. If it prints False, stop: copy the kit again. Nothing has run yet.\r\n'
    printf '   3. Expand-Archive .\\wf-frontdoor-kit.zip -DestinationPath . -Force\r\n'
    printf '   4. cd .\\wf-frontdoor-kit\r\n'
    printf '   5. Get-NetConnectionProfile   (your home connection must say Private; CHECKLIST.md, Appendix A, L5)\r\n'
    printf '   6. %s\r\n' "$run_line"
    printf '   7. The summary ends with RESULT: PASS, INCOMPLETE, or FAIL; only PASS is done. Write down the\r\n'
    printf '      SHA256: line it prints, and on the Mac run:  sh remote-access/mac/wf-finish.sh --fingerprint SHA256:...\r\n\r\n'
    printf 'CHECKLIST.md (inside the zip) has both ways in full, with what to do if something fails.\r\n'
} >"$kit_folder/READ-ME-FIRST.txt"

printf '\n==== 3 of 3: what to do next ====\n\n'
printf 'The kit folder is ready:  %s\n' "$kit_folder"
printf '    SETUP-PC.cmd, Start-FrontDoorSetup.ps1, wf-frontdoor-kit.zip, READ-ME-FIRST.txt (no secret in any of them)\n\n'
printf 'Write down or photograph BOTH of these. Neither is in the kit; they travel with you, not with the files.\n\n'
printf '    KIT CODE (the double click launcher asks for it; USB stick only):\n\n'
printf '        %s\n\n' "$code"
printf '    FULL SHA-256 of the zip (for the manual check with Windows'"'"' own Get-FileHash, any other way in):\n\n'
printf '        %s\n\n' "$full"
printf 'Then, WAY A: the kit goes on a USB stick that stays in your hands.\n'
printf '  1. Copy the whole wf-frontdoor folder to the stick (or give --kit /Volumes/<stick>/wf-frontdoor to write it there).\n'
printf '  2. At the PC, with no game running: open the folder on the stick and double click SETUP-PC.cmd.\n'
printf '     Windows asks whether the program may make changes: choose Yes.\n'
printf '  3. In the window that opens, type the kit code above when asked.\n'
printf '     If it says the code does not match, stop: copy the folder from this Mac again.\n'
printf '  4. Wait. The last line must read DONE: RESULT: PASS (about 10 minutes, mostly waiting).\n'
printf '     INCOMPLETE or FAIL: read the line above it and the checklist row it names, then double click again.\n'
printf '  5. Bring the stick back here and run:  sh remote-access/mac/wf-finish.sh\n\n'
printf 'WAY B: the kit goes any other way (cloud folder, network share, download, a copy on the PC).\n'
printf '  The launcher will refuse to run there, on purpose: it travels with the kit and cannot prove itself.\n'
printf '  Do not double click. At the PC, in "Terminal (Admin)" (right click Start), in the folder holding the zip:\n\n'
printf "      (Get-FileHash .\\\\wf-frontdoor-kit.zip -Algorithm SHA256).Hash -eq '%s'\\n\\n" "$(printf '%s' "$digest" | tr 'a-f' 'A-F')"
printf '  That is Windows'"'"' own hash of the zip compared with the 64 characters you type from this screen; nothing from\n'
printf '  the kit has run yet. It must print True. Then:\n\n'
printf '      Expand-Archive .\\wf-frontdoor-kit.zip -DestinationPath . -Force\n'
printf '      cd .\\wf-frontdoor-kit\n'
printf '      Get-NetConnectionProfile      (your home connection must say Private; see CHECKLIST.md, Appendix A, L5)\n'
printf '      %s\n\n' "$run_line"
printf '  Only RESULT: PASS is done. Write down the SHA256: line it prints and, back here, run:\n'
printf '      sh remote-access/mac/wf-finish.sh --fingerprint SHA256:<that line>\n\n'
printf 'Router reminder: reserve both addresses (%s for the PC, %s for this Mac) in the router, see CHECKLIST.md, the router step.\n' "$pc_address" "$mac_address"
