#!/bin/sh
# wf-pin-host-key.sh: pin the PC's SSH host key on the Mac, after comparing its fingerprint with
# the one Install-FrontDoor.ps1 printed at the PC's own console.
#
#   sh remote-access/mac/wf-pin-host-key.sh --fingerprint SHA256:<the line from the PC>
#   sh remote-access/mac/wf-pin-host-key.sh            (shows the fingerprint and asks you to compare)
#   add --replace only when the PC's key really changed (Windows reinstalled) and you compared again
#
# The key is fetched with ssh-keyscan, which proves nothing by itself: anything answering on that
# address would be accepted. The comparison with the fingerprint read at the PC is what makes it
# trustworthy. A fingerprint of a public key is not a secret.
# ssh-keyscan(1): https://man.openbsd.org/ssh-keyscan   ssh-keygen -l: https://man.openbsd.org/ssh-keygen
set -eu
# shellcheck source-path=SCRIPTDIR
. "$(dirname "$0")/wf-common.sh"

expected=""
replace=0
while [ $# -gt 0 ]; do
    case "$1" in
        --fingerprint) expected="${2:-}"; shift 2 ;;
        --host-alias) WF_HOST_ALIAS="${2:-}"; shift 2 ;;
        --replace) replace=1; shift ;;
        -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
        *) wf_die "unknown option: $1" ;;
    esac
done
if [ -n "$expected" ]; then
    printf '%s\n' "$expected" | grep -Eq '^SHA256:[A-Za-z0-9+/]{43}$' || wf_die "--fingerprint must look like SHA256: followed by 43 characters, exactly as the PC printed it"
fi

resolved="$(wf_ssh -G "$WF_HOST_ALIAS")" || wf_die "ssh could not read its configuration for '$WF_HOST_ALIAS'"
host="$(printf '%s\n' "$resolved" | awk '$1 == "hostname" { print $2; exit }')"
port="$(printf '%s\n' "$resolved" | awk '$1 == "port" { print $2; exit }')"
[ -n "$host" ] && [ "$host" != "$WF_HOST_ALIAS" ] || wf_die "no 'Host $WF_HOST_ALIAS' block found in the ssh config; run wf-mac-setup.sh first"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
ssh-keyscan -T 10 -t ed25519 -p "${port:-22}" "$host" 2>/dev/null | awk '$2 == "ssh-ed25519" { print $2, $3; exit }' >"$work/key" || true
if [ ! -s "$work/key" ]; then
    wf_die "no SSH answer from $host port ${port:-22}. Check: the PC is on and awake, the setup script ended with PASS, the address is right, and this Mac has the address the setup script was given"
fi
actual="$(ssh-keygen -l -E sha256 -f "$work/key" | awk '{print $2}')"
printf 'Host key offered by %s:\n\n    %s\n\n' "$host" "$actual"

if [ -n "$expected" ]; then
    if [ "$actual" != "$expected" ]; then
        printf 'The PC printed:\n\n    %s\n\n' "$expected" >&2
        wf_die "the fingerprints DIFFER. Nothing was pinned. Either the line was mistyped, or the machine answering at $host is not your PC. Read the line at the PC again"
    fi
    printf 'It matches the fingerprint you gave.\n'
else
    [ -t 0 ] || wf_die "no --fingerprint given and no terminal to ask on"
    printf 'Compare it, character by character, with the "host key fingerprint" line on the PC screen.\n'
    printf 'Type yes only if they are identical: '
    read -r answer
    [ "$answer" = "yes" ] || wf_die "not confirmed. Nothing was pinned"
fi

mkdir -p "$(dirname "$WF_KNOWN_HOSTS")"
touch "$WF_KNOWN_HOSTS"
chmod 600 "$WF_KNOWN_HOSTS"
new_line="$WF_HOST_ALIAS $(cat "$work/key")"
old_line="$(awk -v alias="$WF_HOST_ALIAS" '$1 == alias { print; exit }' "$WF_KNOWN_HOSTS")"
if [ "$old_line" = "$new_line" ]; then
    printf 'Already pinned in %s. Nothing to change.\n' "$WF_KNOWN_HOSTS"
    exit 0
fi
if [ -n "$old_line" ] && [ "$replace" -ne 1 ]; then
    wf_die "a DIFFERENT host key is already pinned for '$WF_HOST_ALIAS'. A host key changes only when Windows or OpenSSH was reinstalled. If that happened, compare the fingerprint at the PC again and rerun with --replace"
fi
awk -v alias="$WF_HOST_ALIAS" '$1 != alias { print }' "$WF_KNOWN_HOSTS" >"$work/known_hosts"
printf '%s\n' "$new_line" >>"$work/known_hosts"
cat "$work/known_hosts" >"$WF_KNOWN_HOSTS"
printf 'Pinned in %s.\nNext: sh remote-access/mac/wf-acceptance.sh\n' "$WF_KNOWN_HOSTS"
