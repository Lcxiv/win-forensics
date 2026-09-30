#!/bin/sh
# wf-finish.sh: the last Mac command of the win-forensics front door setup. Pins the PC's host
# key and runs every acceptance check, ending with a PASS, FAIL, or INCOMPLETE list.
#
#   sh remote-access/mac/wf-finish.sh [--kit <folder>] [--fingerprint SHA256:<from the PC screen>] [--by-eye] [--after-reboot] [--replace]
#
# Where the expected host key comes from, in this order:
#   --fingerprint   the line the PC printed, typed or pasted. Required when the kit did not travel
#                   on a removable drive: a file in a cloud folder, on a network share, or on the
#                   Desktop can be changed by whoever controls that place
#   --kit <folder>  pc-host-key.pub in that folder, which the PC launcher wrote next to the zip;
#                   used automatically only when the folder, with links and .. resolved
#                   (pwd -P), is on a disk mounted under /Volumes that diskutil info reports as
#                   an external, removable or ejectable disk; a network share, the boot disk,
#                   and anything else end INCOMPLETE and ask for --fingerprint
#   (neither)       pc-host-key.pub is looked for in every /Volumes/*/wf-frontdoor; exactly one
#                   must exist, and the same rule applies to it. None: plug the stick in and run
#                   again, or give --fingerprint
#   --by-eye        only when there is no file and no line to type: wf-pin-host-key.sh shows the
#                   fingerprint it received over the network and asks you to compare it with the
#                   PC screen and type yes
# The key offered over the network is fetched by wf-pin-host-key.sh and pinned only when its
# fingerprint equals the expected one; on any difference nothing is pinned, this ends in FAIL,
# and no acceptance check is sent.
# Exit codes: 0 PASS, 1 FAIL, 2 INCOMPLETE (a check could not run; not a pass).
set -u
# shellcheck source-path=SCRIPTDIR
. "$(dirname "$0")/wf-common.sh"

kit_folder=""
fingerprint=""
by_eye=0
after_reboot=0
replace=0
# Where mounted disks appear. Overridable for the tests, which cannot mount a disk.
volumes_dir="${WF_VOLUMES_DIR:-/Volumes}"
while [ $# -gt 0 ]; do
    case "$1" in
        --kit) kit_folder="${2:-}"; shift 2 ;;
        --fingerprint) fingerprint="${2:-}"; shift 2 ;;
        --by-eye) by_eye=1; shift ;;
        --after-reboot) after_reboot=1; shift ;;
        --replace) replace=1; shift ;;
        --host-alias) WF_HOST_ALIAS="${2:-}"; shift 2 ;;
        -h|--help) sed -n '2,25p' "$0"; exit 0 ;;
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
        INCOMPLETE) printf 'A check could not run, so this is not a pass. Do what the line above says and run wf-finish.sh again.\n'; exit 2 ;;
        *) printf 'Read the FAIL line above and the checklist section "If an action fails".\n'; exit 1 ;;
    esac
}
# untrusted_reason <folder>: nothing when the folder is on a removable disk, otherwise why not.
# The folder is resolved first (pwd -P: POSIX, every link and .. resolved), so a link or a
# "/Volumes/.." path is judged by where it really is; /Volumes/Macintosh HD is a link to /.
# The disk it is on is the mount point directly under /Volumes (where macOS mounts other disks:
# Apple, File System Programming Guide, "File System Basics"), and diskutil info on that mount
# point must report it mounted there, not over a network protocol, as External, and as
# Removable media or Ejectable (diskutil(8)). A network share has no disk, so diskutil info does
# not report one.
# https://pubs.opengroup.org/onlinepubs/9699919799/utilities/pwd.html
# https://developer.apple.com/library/archive/documentation/Darwin/Reference/ManPages/man8/diskutil.8.html
untrusted_reason() {
    canonical="$(cd "$1" 2>/dev/null && pwd -P)" || { printf 'the folder cannot be opened'; return; }
    volumes_real="$(cd "$volumes_dir" 2>/dev/null && pwd -P)" || volumes_real="$volumes_dir"
    case "$canonical" in
        "$volumes_real"/?*) ;;
        *) printf 'it is really %s, which is not on a disk mounted under %s' "$canonical" "$volumes_dir"; return ;;
    esac
    rest="${canonical#"$volumes_real"/}"
    mount_point="$volumes_real/${rest%%/*}"
    diskutil info "$mount_point" >"$work/diskutil" 2>&1 || :
    disk_field() { sed -n "s/^ *$1: *//p" "$work/diskutil" | head -n 1; }
    [ "$(disk_field 'Mount Point')" = "$mount_point" ] || { printf 'macOS reports no disk mounted at %s (a network share is not a disk)' "$mount_point"; return; }
    case "$(disk_field 'Protocol')" in
        SMB*|AFP*|NFS*|WebDAV*) printf '%s is a network share' "$mount_point"; return ;;
    esac
    [ "$(disk_field 'Device Location')" = "External" ] || { printf '%s is not an external disk (the boot disk and internal disks are not trusted)' "$mount_point"; return; }
    [ "$(disk_field 'Removable Media')" = "Removable" ] || [ "$(disk_field 'Ejectable')" = "Yes" ] || { printf '%s is neither removable nor ejectable' "$mount_point"; return; }
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
        [ -f "$key_file" ] || { note INCOMPLETE "host key: $key_file does not exist. The PC launcher writes it next to the zip after a PASS. Plug in the stick the kit came back on and run again, or give --fingerprint SHA256:... from the PC screen"; finish; }
    else
        found=""
        count=0
        for candidate in "$volumes_dir"/*/wf-frontdoor/pc-host-key.pub; do
            [ -f "$candidate" ] || continue
            found="$candidate"
            count=$((count + 1))
        done
        if [ "$count" -gt 1 ]; then
            note FAIL "host key: more than one pc-host-key.pub was found under $volumes_dir; say which kit folder with --kit <folder>"
            finish
        fi
        if [ "$count" -eq 0 ] && [ "$by_eye" -eq 0 ]; then
            note INCOMPLETE "host key: no pc-host-key.pub on any disk under $volumes_dir. Plug in the USB stick the kit came back on and run again; if the kit did not travel on a stick, run again with --fingerprint SHA256:... typed from the PC screen; with neither, --by-eye shows the fingerprint received over the network for you to compare with the PC screen yourself"
            finish
        fi
        key_file="$found"
    fi
    if [ -n "$key_file" ]; then
        why="$(untrusted_reason "$(dirname "$key_file")")"
        [ -z "$why" ] && [ -L "$key_file" ] && why="the file is a link"
        if [ -n "$why" ]; then
            note INCOMPLETE "host key: $key_file is not on a removable disk ($why), so it is not trusted: a file in a cloud folder, on a network share, or on this Mac can be changed by whoever controls that place. Run again with --fingerprint SHA256:... typed from the PC screen (it is also in the wf-frontdoor-report.txt the PC wrote), or plug the stick in and give its folder"
            finish
        fi
        [ "$(grep -c . "$key_file")" = "1" ] || { note FAIL "host key: $key_file must hold exactly one line"; finish; }
        awk 'NF { print $1, $2; exit }' "$key_file" >"$work/hostkey"
        [ "$(awk '{print $1}' "$work/hostkey")" = "ssh-ed25519" ] || { note FAIL "host key: $key_file is not an ssh-ed25519 public key line"; finish; }
        fingerprint="$(ssh-keygen -l -E sha256 -f "$work/hostkey" 2>/dev/null | awk '{print $2}')"
        printf '%s\n' "$fingerprint" | grep -Eq '^SHA256:[A-Za-z0-9+/]{43}$' || { note FAIL "host key: $key_file could not be read as a public key"; finish; }
        source="pc-host-key.pub on the removable disk at $(dirname "$key_file") (written by the PC launcher)"
    fi
fi

if [ -n "$fingerprint" ]; then
    printf 'Expected host key fingerprint, from %s:\n    %s\n' "$source" "$fingerprint"
    set -- --fingerprint "$fingerprint"
else
    source="your own comparison with the PC screen (--by-eye)"
    printf 'Expected host key fingerprint, from %s: the one received over the network is shown next; compare it with the PC screen.\n' "$source"
    [ -t 0 ] || { note INCOMPLETE "host key: --by-eye needs a terminal to ask on. Run again from Terminal, or with --fingerprint SHA256:... from the PC screen"; finish; }
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
# The output is captured first and shown after, so that the script's own exit code is known.
acceptance_rc=0
sh "$script_dir/wf-acceptance.sh" --host-alias "$WF_HOST_ALIAS" "$@" >"$work/acceptance" 2>&1 || acceptance_rc=$?
cat "$work/acceptance"
if [ "$acceptance_rc" -eq 0 ] && grep -q '^RESULT: PASS' "$work/acceptance"; then
    note PASS "acceptance: every check passed (A1 to A8$([ "$after_reboot" -eq 1 ] && printf ' and A10'))"
elif grep -q '^RESULT: FAIL' "$work/acceptance"; then
    note FAIL "acceptance: $(grep -c '^FAIL' "$work/acceptance") check(s) failed; the FAIL lines above say which"
else
    note INCOMPLETE "acceptance: the checks did not finish (wf-acceptance.sh exit code $acceptance_rc, no RESULT line); nothing can be concluded. The last lines above say what stopped it"
fi
grep '^WARN' "$work/acceptance" | while IFS= read -r line; do note WARN "acceptance: ${line#WARN }"; done
report="$(sed -n 's/^Report saved to \([^ ]*\).*/\1/p' "$work/acceptance" | tail -n 1)"
[ -n "$report" ] && note INFO "acceptance report: $report (facts about your PC; keep it out of any repository)"
[ "$after_reboot" -eq 1 ] || note TODO "restart test: restart the PC, do not sign in, and within 30 minutes run: sh remote-access/mac/wf-finish.sh --after-reboot"
note TODO "A9 by hand: from another device at home, port 22 of the PC must NOT answer (CHECKLIST.md)"
finish
