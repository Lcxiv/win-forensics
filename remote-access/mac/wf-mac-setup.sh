#!/bin/sh
# wf-mac-setup.sh: prepare the Mac for the win-forensics front door.
#
#   sh remote-access/mac/wf-mac-setup.sh --pc-address <PC_LAN_ADDRESS>
#
# It creates a dedicated Ed25519 key used for nothing else (ssh-keygen asks you for a passphrase;
# this script never sees it), adds the key to the macOS ssh-agent, and puts a "Host gaming-pc"
# block at the top of ~/.ssh/config that pins the host key and refuses everything but key
# authentication. Safe to run again: it replaces only its own block.
#
# ssh_config(5): https://man.openbsd.org/ssh_config   ssh-keygen(1): https://man.openbsd.org/ssh-keygen
# --apple-use-keychain and UseKeychain are Apple additions; see "man ssh-add" and "man ssh_config"
# on macOS.
set -eu
# shellcheck source-path=SCRIPTDIR
. "$(dirname "$0")/wf-common.sh"

pc_address=""
account="wfcollector"
while [ $# -gt 0 ]; do
    case "$1" in
        --pc-address) pc_address="${2:-}"; shift 2 ;;
        --host-alias) WF_HOST_ALIAS="${2:-}"; shift 2 ;;
        --account) account="${2:-}"; shift 2 ;;
        -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
        *) wf_die "unknown option: $1" ;;
    esac
done
[ -n "$pc_address" ] || wf_die "give the PC's address on the home network: --pc-address <PC_LAN_ADDRESS>"
wf_is_ipv4 "$pc_address" || wf_die "--pc-address must be an IPv4 address such as the one the PC shows under Settings > Network & internet"
printf '%s\n' "$WF_HOST_ALIAS" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._-]*$' || wf_die "--host-alias may only hold letters, digits, dot, underscore, and hyphen"
printf '%s\n' "$account" | grep -Eq '^[a-z][a-z0-9]{2,19}$' || wf_die "--account must be lower case letters and digits, 3 to 20 characters"

config_file="${WF_SSH_CONFIG:-$HOME/.ssh/config}"
mkdir -p "$(dirname "$WF_KEY_FILE")" "$(dirname "$config_file")"
chmod 700 "$(dirname "$WF_KEY_FILE")"

# 1. The key. ssh-keygen prompts for the passphrase on the terminal.
if [ -f "$WF_KEY_FILE" ]; then
    printf 'Key already exists: %s\n' "$WF_KEY_FILE"
else
    printf 'Creating a new key. Choose a passphrase when asked; do not leave it empty.\n'
    ssh-keygen -t ed25519 -a 64 -C "win-forensics-frontdoor" -f "$WF_KEY_FILE"
fi
[ -f "$WF_KEY_FILE.pub" ] || wf_die "the public key $WF_KEY_FILE.pub is missing"
# "ssh-keygen -y -P ''" only succeeds when the private key has no passphrase at all.
if ssh-keygen -y -P "" -f "$WF_KEY_FILE" >/dev/null 2>&1; then
    wf_die "the key $WF_KEY_FILE has no passphrase. Set one with: ssh-keygen -p -f $WF_KEY_FILE   then run this script again"
fi

# 2. The agent, so the passphrase is asked once and kept in the macOS keychain.
if [ "${WF_SKIP_AGENT:-0}" = "1" ]; then
    printf 'Skipping ssh-add (WF_SKIP_AGENT=1).\n'
elif [ "$(uname -s)" = "Darwin" ]; then
    ssh-add --apple-use-keychain "$WF_KEY_FILE"
else
    ssh-add "$WF_KEY_FILE"
fi

# 3. The ssh config block, first in the file: ssh uses the first value it finds for each option,
#    so a "Host *" block further down cannot weaken these.
block_file="$(mktemp)"
rest_file="$(mktemp)"
trap 'rm -f "$block_file" "$rest_file"' EXIT
cat >"$block_file" <<BLOCK
# BEGIN win-forensics front door ($WF_HOST_ALIAS). Managed by wf-mac-setup.sh; edits here are overwritten.
Host $WF_HOST_ALIAS
    HostName $pc_address
    User $account
    HostKeyAlias $WF_HOST_ALIAS
    IdentityFile $WF_KEY_FILE
    IdentitiesOnly yes
    PreferredAuthentications publickey
    PasswordAuthentication no
    StrictHostKeyChecking yes
    UserKnownHostsFile $WF_KNOWN_HOSTS
    GlobalKnownHostsFile /dev/null
    UpdateHostKeys no
    HostKeyAlgorithms ssh-ed25519
    ForwardAgent no
    ForwardX11 no
    ClearAllForwardings yes
    RequestTTY no
    ServerAliveInterval 15
    ServerAliveCountMax 4
    ConnectTimeout 10
    IgnoreUnknown UseKeychain
    UseKeychain yes
    AddKeysToAgent yes
# END win-forensics front door ($WF_HOST_ALIAS)
BLOCK
if [ -f "$config_file" ]; then
    [ -f "$config_file.wf-backup" ] || cp -p "$config_file" "$config_file.wf-backup"
    awk -v alias="$WF_HOST_ALIAS" '
        $0 == "# BEGIN win-forensics front door (" alias "). Managed by wf-mac-setup.sh; edits here are overwritten." { skip = 1; next }
        $0 == "# END win-forensics front door (" alias ")" { skip = 0; next }
        !skip { print }
    ' "$config_file" >"$rest_file"
else
    : >"$rest_file"
fi
{
    cat "$block_file"
    # Exactly one blank line between the block and whatever was there before.
    awk 'NF { seen = 1 } seen { print }' "$rest_file" | { printf '\n'; cat; }
} >"$config_file.wf-new"
mv "$config_file.wf-new" "$config_file"
chmod 600 "$config_file"

printf '\nDone.\n'
printf '  ssh config:  Host %s -> %s as %s  (%s)\n' "$WF_HOST_ALIAS" "$pc_address" "$account" "$config_file"
printf '  public key:  %s.pub\n' "$WF_KEY_FILE"
printf '  fingerprint: %s\n' "$(ssh-keygen -l -E sha256 -f "$WF_KEY_FILE.pub" | awk '{print $2}')"
if [ "$(uname -s)" = "Darwin" ]; then
    iface="$(route -n get default 2>/dev/null | awk '/interface:/ {print $2}')"
    if [ -n "$iface" ]; then
        mac_ip="$(ipconfig getifaddr "$iface" 2>/dev/null || true)"
        [ -n "$mac_ip" ] && printf '  this Mac:    %s on %s (the address to give wf-make-kit.sh)\n' "$mac_ip" "$iface"
    fi
fi
printf 'Next: sh remote-access/mac/wf-make-kit.sh --mac-address <MAC_LAN_ADDRESS>\n'
