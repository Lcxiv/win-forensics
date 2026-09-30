#!/bin/sh
# wf-finish.sh: the last Mac command of the win-forensics front door setup. Pins the PC's host
# key and runs every acceptance check, ending with a PASS, FAIL, or INCOMPLETE list.
#
#   sh remote-access/mac/wf-finish.sh [--kit <folder>] [--fingerprint SHA256:<from the PC screen>] [--after-reboot] [--replace]
#
# Where the expected host key comes from, in this order:
#   --fingerprint   the line the PC launcher printed, typed or pasted (use this when the kit did
#                   not travel on removable media: a cloud folder or a network share can be changed
#                   by whoever controls it)
#   --kit <folder>  pc-host-key.pub, which the PC launcher wrote next to the zip on the same stick
#   (neither)       pc-host-key.pub is looked for in ~/Desktop/wf-frontdoor and in every
#                   /Volumes/*/wf-frontdoor (where macOS mounts other disks: Apple, File System
#                   Programming Guide, "File System Basics"); exactly one must exist
#   (none found)    wf-pin-host-key.sh shows the fingerprint it received over the network and
#                   asks you to compare it with the PC screen and type yes
# The key offered over the network is fetched by wf-pin-host-key.sh and pinned only when its
# fingerprint equals the expected one; on any difference nothing is pinned and this ends in FAIL.
# Exit codes: 0 PASS, 1 FAIL, 2 INCOMPLETE (a check could not run; not a pass).
set -u
# shellcheck source-path=SCRIPTDIR
. "$(dirname "$0")/wf-common.sh"

kit_folder=""
fingerprint=""
after_reboot=0
replace=0
while [ $# -gt 0 ]; do
    case "$1" in
        --kit) kit_folder="${2:-}"; shift 2 ;;
        --fingerprint) fingerprint="${2:-}"; shift 2 ;;
        --after-reboot) after_reboot=1; shift ;;
        --replace) replace=1; shift ;;
        --host-alias) WF_HOST_ALIAS="${2:-}"; shift 2 ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        *) wf_die "unknown option: $1" ;;
    esac
done
script_dir="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
summary="$work/summary"
: >"$summary"
result="PASS"

note() { # note <STATUS> <text>: one line of the final list
    printf '%s  %s\n' "$1" "$2" >>"$summary"
    case "$1" in
        FAIL) result="FAIL" ;;
        INCOMPLETE) [ "$result" = "FAIL" ] || result="INCOMPLETE" ;;
    esac
}
finish() {
    printf '\n==================== win-forensics front door: finish ====================\n'
    cat "$summary"
    printf '\nRESULT: %s\n' "$result"
    case "$result" in
        PASS) printf 'The front door works from this Mac. A9 (the check from another device) is still yours to do by hand; see CHECKLIST.md.\n'; exit 0 ;;
        INCOMPLETE) printf 'A check could not run, so this is not a pass. Fix what the line above names and run wf-finish.sh again.\n'; exit 2 ;;
        *) printf 'Read the FAIL line above and the checklist section "If an action fails".\n'; exit 1 ;;
    esac
}

# ---- 1. the expected host key ---------------------------------------------------------------
printf '==== 1 of 2: pin the PC'"'"'s host key ====\n'
source=""
if [ -n "$fingerprint" ]; then
    printf '%s\n' "$fingerprint" | grep -Eq '^SHA256:[A-Za-z0-9+/]{43}$' || { note FAIL "host key: --fingerprint must be SHA256: followed by 43 characters, exactly as the PC printed it"; finish; }
    source="the fingerprint you typed from the PC screen"
else
    key_file=""
    if [ -n "$kit_folder" ]; then
        key_file="$kit_folder/pc-host-key.pub"
        [ -f "$key_file" ] || { note INCOMPLETE "host key: $key_file does not exist. The PC launcher writes it next to the zip after a PASS; or give --fingerprint from the PC screen"; finish; }
    else
        found=""
        count=0
        for candidate in "$HOME/Desktop/wf-frontdoor/pc-host-key.pub" /Volumes/*/wf-frontdoor/pc-host-key.pub; do
            [ -f "$candidate" ] || continue
            found="$candidate"
            count=$((count + 1))
        done
        if [ "$count" -gt 1 ]; then
            note FAIL "host key: more than one pc-host-key.pub was found; say which kit folder with --kit <folder>"
            finish
        fi
        key_file="$found"
    fi
    if [ -n "$key_file" ]; then
        [ "$(grep -c . "$key_file")" = "1" ] || { note FAIL "host key: $key_file must hold exactly one line"; finish; }
        awk 'NF { print $1, $2; exit }' "$key_file" >"$work/hostkey"
        [ "$(awk '{print $1}' "$work/hostkey")" = "ssh-ed25519" ] || { note FAIL "host key: $key_file is not an ssh-ed25519 public key line"; finish; }
        fingerprint="$(ssh-keygen -l -E sha256 -f "$work/hostkey" 2>/dev/null | awk '{print $2}')"
        printf '%s\n' "$fingerprint" | grep -Eq '^SHA256:[A-Za-z0-9+/]{43}$' || { note FAIL "host key: $key_file could not be read as a public key"; finish; }
        source="pc-host-key.pub in $(dirname "$key_file") (written by the PC launcher)"
        case "$key_file" in
            /Volumes/*) ;;
            *) printf 'Note: %s did not come from a mounted disk under /Volumes. If the kit travelled through a cloud folder or a network share, prefer --fingerprint from the PC screen.\n' "$key_file" ;;
        esac
    fi
fi

if [ -n "$fingerprint" ]; then
    printf 'Expected host key fingerprint, from %s:\n    %s\n' "$source" "$fingerprint"
    set -- --fingerprint "$fingerprint"
else
    printf 'No pc-host-key.pub was found and no --fingerprint was given: comparing by eye with the PC screen.\n'
    [ -t 0 ] || { note INCOMPLETE "host key: nothing to compare against (no pc-host-key.pub, no --fingerprint, no terminal to ask on). Run again with --fingerprint SHA256:... from the PC screen"; finish; }
    set --
fi
[ "$replace" -eq 1 ] && set -- "$@" --replace
pin_rc=0
sh "$script_dir/wf-pin-host-key.sh" --host-alias "$WF_HOST_ALIAS" "$@" 2>"$work/pin.err" || pin_rc=$?
cat "$work/pin.err" >&2
if [ "$pin_rc" -eq 0 ]; then
    note PASS "host key: the key the PC offers matches $source; pinned with StrictHostKeyChecking yes"
elif grep -q 'no SSH answer' "$work/pin.err"; then
    note INCOMPLETE "host key: no SSH answer from the PC, so nothing could be compared and nothing was pinned. Is the PC on and awake, did the setup end with PASS, and is this Mac on the home network?"
    finish
else
    note FAIL "host key: NOT pinned. $(tr '\n' ' ' <"$work/pin.err" | sed 's/^error: //')"
    finish
fi

# ---- 2. the acceptance checks ----------------------------------------------------------------
printf '\n==== 2 of 2: acceptance checks ====\n'
set --
[ "$after_reboot" -eq 1 ] && set -- --after-reboot
acceptance_rc=0
sh "$script_dir/wf-acceptance.sh" --host-alias "$WF_HOST_ALIAS" "$@" | tee "$work/acceptance" || acceptance_rc=$?
# tee hides the script's exit code in a POSIX pipeline; the RESULT line carries it.
if grep -q '^RESULT: PASS' "$work/acceptance"; then
    note PASS "acceptance: every check passed (A1 to A8$([ "$after_reboot" -eq 1 ] && printf ' and A10'))"
elif grep -q '^RESULT: FAIL' "$work/acceptance"; then
    note FAIL "acceptance: $(grep -c '^FAIL' "$work/acceptance") check(s) failed; the FAIL lines above say which"
else
    note INCOMPLETE "acceptance: the checks did not finish (exit code $acceptance_rc); nothing can be concluded"
fi
grep '^WARN' "$work/acceptance" | while IFS= read -r line; do note WARN "acceptance: ${line#WARN }"; done
report="$(sed -n 's/^Report saved to \([^ ]*\).*/\1/p' "$work/acceptance" | tail -n 1)"
[ -n "$report" ] && note INFO "acceptance report: $report (facts about your PC; keep it out of any repository)"
[ "$after_reboot" -eq 1 ] || note TODO "restart test: restart the PC, do not sign in, and within 30 minutes run: sh remote-access/mac/wf-finish.sh --after-reboot"
note TODO "A9 by hand: from another device at home, port 22 of the PC must NOT answer (CHECKLIST.md)"
finish
