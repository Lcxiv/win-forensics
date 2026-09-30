# wf-common.sh: shared by the Mac side scripts of the win-forensics front door. Sourced, not run.
# POSIX sh. Nothing here reads, prints, or moves a private key or a passphrase.
# shellcheck shell=sh

# The host alias in ~/.ssh/config, the dedicated key, and the dedicated known_hosts file.
WF_HOST_ALIAS="${WF_HOST_ALIAS:-gaming-pc}"
WF_KEY_FILE="${WF_KEY_FILE:-$HOME/.ssh/id_ed25519_winforensics}"
WF_KNOWN_HOSTS="${WF_KNOWN_HOSTS:-$HOME/.ssh/known_hosts_winforensics}"
# Patterns the dispatcher also enforces (remote-access/windows/WfCommon.ps1).
# shellcheck disable=SC2034
WF_BUNDLE_DIR_RE='^[0-9]{8}T[0-9]{6}Z_[a-z][a-z0-9-]{1,40}_[0-9a-f]{8}$'

wf_die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

# ssh with the user's normal configuration. WF_SSH_CONFIG points it at another config file; the
# tests use that, because ssh ignores $HOME when it looks for ~/.ssh/config.
wf_ssh() {
    if [ -n "${WF_SSH_CONFIG:-}" ]; then
        ssh -F "$WF_SSH_CONFIG" "$@"
    else
        ssh "$@"
    fi
}

# Run one dispatcher verb. stdin is closed (-n) and no terminal is requested (-T): the forced
# command never reads input. BatchMode makes ssh fail instead of prompting.
wf_verb() {
    wf_ssh -n -T -o BatchMode=yes -o ConnectTimeout=10 "$WF_HOST_ALIAS" "$@"
}

wf_sha256() {
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    elif command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        wf_die "neither shasum nor sha256sum is available"
    fi
}

# wf_kit_code <hex digest>: the kit code the person carries from the Mac screen to the PC. The
# left-most 32 hex characters (128 bits) of the kit zip's SHA-256, lower case, in 8 groups of 4.
# Start-FrontDoorSetup.ps1 (Get-WfKitCode) derives the same code at the PC; the two must agree.
# Why 128 bits: a digest truncated to its left-most bits keeps a preimage and second preimage
# resistance equal to its length (NIST SP 800-107 Rev. 1, section 5.1), and 128 bits is the
# smallest strength NIST rates "Acceptable" beyond 2030 (NIST SP 800-57 Part 1 Rev. 5, Table 4).
wf_kit_code() {
    printf '%s' "$1" | tr 'A-F' 'a-f' | cut -c 1-32 | sed 's/.\{4\}/& /g; s/ $//'
}

wf_base64_decode() {
    # macOS and GNU base64 both accept --decode; BusyBox only knows -d.
    if printf 'QQ==' | base64 --decode >/dev/null 2>&1; then
        base64 --decode
    else
        base64 -d
    fi
}

# wf_json_string <key> <file>: the string value of a top level key in one line of compact JSON.
# Good for the flat, quote free values the dispatcher emits; not a JSON parser.
wf_json_string() {
    sed -n 's/.*"'"$1"'":"\([^"]*\)".*/\1/p' "$2" | head -n 1
}

# Four numbers separated by dots, each 0 to 255. The same shape and range rule the launcher
# (Test-WfIPv4Text) and the setup script (Get-WfIPv4Info) apply at the PC.
wf_is_ipv4() {
    printf '%s\n' "$1" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$' || return 1
    printf '%s\n' "$1" | awk -F. '{ for (i = 1; i <= 4; i++) if ($i + 0 > 255) exit 1 }'
}

# wf_full_digest <hex digest>: the full SHA-256 as the Mac prints it for the manual check at
# the PC, upper case in 8 groups of 8, the way Get-FileHash prints its Hash (upper case).
wf_full_digest() {
    printf '%s' "$1" | tr 'a-f' 'A-F' | sed 's/.\{8\}/& /g; s/ $//'
}
