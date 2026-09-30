#!/bin/sh
# wf-acceptance.sh: the Mac side acceptance checks for the win-forensics front door (plan G2-M2).
#
#   sh remote-access/mac/wf-acceptance.sh [--after-reboot] [--report <file>]
#
# Read only: every check is either a local look at the ssh configuration or one allowlisted verb
# sent to the PC. Each line starts with PASS, FAIL, WARN, INFO, or TODO. Exit code 0 means no
# FAIL. The checklist (remote-access/CHECKLIST.md, step 8) says what each check proves.
#
#   A1  the host key is pinned and strict checking is on for the host alias
#   A2  "ping" returns the dispatcher's health JSON
#   A3  commands outside the allowlist are refused, not run (whoami and friends), and a forced
#       terminal request (-tt) gets neither a terminal nor a shell
#   A4  password authentication is refused by the server
#   A5  a host key mismatch, or a missing pin, stops the connection before anything is sent
#   A6  "collect-<name>" answers "unknown collector" until collectors are installed
#   A7  "security-log-access": what the account can see of the Security log (a measurement)
#   A8  "list-bundles" works; with --fetch-newest, fetch the newest bundle and verify its SHA-256
#   A9  TODO by hand: a connection from any other address is refused
#   A10 with --after-reboot: the PC restarted recently and nobody is signed in at its screen
set -u
# shellcheck source-path=SCRIPTDIR
. "$(dirname "$0")/wf-common.sh"

after_reboot=0
fetch_newest=0
report="$HOME/wf-frontdoor-acceptance-$(date -u +%Y%m%dT%H%M%SZ).txt"
while [ $# -gt 0 ]; do
    case "$1" in
        --after-reboot) after_reboot=1; shift ;;
        --fetch-newest) fetch_newest=1; shift ;;
        --report) report="${2:-}"; shift 2 ;;
        --host-alias) WF_HOST_ALIAS="${2:-}"; shift 2 ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        *) wf_die "unknown option: $1" ;;
    esac
done

script_dir="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
fails=0
: >"$report" || wf_die "cannot write the report file $report"

say() {
    printf '%s\n' "$*"
    printf '%s\n' "$*" >>"$report"
}
pass() { say "PASS $*"; }
warn() { say "WARN $*"; }
info() { say "INFO $*"; }
fail() {
    say "FAIL $*"
    fails=$((fails + 1))
}

# run <verb...>: run a dispatcher verb; stdout in $work/out, stderr in $work/err, exit code in $rc.
run() {
    rc=0
    wf_verb "$@" >"$work/out" 2>"$work/err" || rc=$?
}

say "win-forensics front door acceptance, $(date -u +%Y-%m-%dT%H:%M:%SZ), host alias '$WF_HOST_ALIAS'"

# ---- A1: pinning and strict checking -----------------------------------------------------------
resolved="$(wf_ssh -G "$WF_HOST_ALIAS" 2>/dev/null)" || resolved=""
opt() { printf '%s\n' "$resolved" | awk -v k="$1" '$1 == k { $1 = ""; sub(/^ /, ""); print; exit }'; }
strict="$(opt stricthostkeychecking)"
known="$(opt userknownhostsfile)"
hostname_value="$(opt hostname)"
if [ -z "$resolved" ] || [ "$hostname_value" = "$WF_HOST_ALIAS" ] || [ -z "$hostname_value" ]; then
    hostname_value=""
    fail "A1 no 'Host $WF_HOST_ALIAS' block in the ssh config; run wf-mac-setup.sh"
else
    case "$strict" in
        yes|true) pass "A1 StrictHostKeyChecking is on for $WF_HOST_ALIAS ($hostname_value)" ;;
        *) fail "A1 StrictHostKeyChecking is '$strict' for $WF_HOST_ALIAS; it must be yes" ;;
    esac
    case "$known" in
        *"$WF_KNOWN_HOSTS"*) pass "A1 the dedicated known_hosts file is used ($WF_KNOWN_HOSTS)" ;;
        *) fail "A1 UserKnownHostsFile is '$known', not $WF_KNOWN_HOSTS" ;;
    esac
    if awk -v alias="$WF_HOST_ALIAS" '$1 == alias && $2 == "ssh-ed25519" { found = 1 } END { exit !found }' "$WF_KNOWN_HOSTS" 2>/dev/null; then
        pass "A1 an Ed25519 host key is pinned for $WF_HOST_ALIAS"
    else
        fail "A1 no pinned host key for $WF_HOST_ALIAS in $WF_KNOWN_HOSTS; run wf-pin-host-key.sh"
    fi
    [ "$(opt passwordauthentication)" = "no" ] || warn "A1 the Mac side ssh config does not set PasswordAuthentication no"
    [ "$(opt forwardagent)" = "no" ] || fail "A1 ForwardAgent is not 'no' for $WF_HOST_ALIAS"
fi

# ---- A2: ping ------------------------------------------------------------------------------------
run ping
cp "$work/out" "$work/ping"
if [ "$rc" -eq 0 ] && grep -q '"ok":true' "$work/ping" && grep -q '"verb":"ping"' "$work/ping"; then
    pass "A2 ping returned the health JSON"
    say "     $(head -n 1 "$work/ping")"
    account="$(wf_json_string account "$work/ping")"
    remote_sha="$(wf_json_string dispatcher_sha256 "$work/ping")"
    local_sha="$(wf_sha256 "$script_dir/../windows/dispatch.ps1" 2>/dev/null || true)"
    if [ -n "$remote_sha" ] && [ "$remote_sha" = "$local_sha" ]; then
        pass "A2 the dispatcher on the PC is byte for byte the one in this checkout"
    else
        warn "A2 the dispatcher on the PC ($remote_sha) differs from this checkout ($local_sha); make a new kit and run the setup script again when convenient"
    fi
    if grep -q '"host_id":"[0-9a-f]\{16\}"' "$work/ping"; then
        pass "A2 the host name is reported only as a hash"
    else
        fail "A2 the health JSON has no hashed host_id"
    fi
else
    account=""
    fail "A2 ping failed (exit code $rc): $(tr '\n' ' ' <"$work/err")$(head -c 300 "$work/out")"
    say "     255 means ssh itself could not connect or log in; see the checklist, 'If a Mac side check fails'"
fi

# ---- A3: refusals --------------------------------------------------------------------------------
refused() { # refused <label> <args...>
    label="$1"
    shift
    run "$@"
    classify_refusal "$label"
}
# classify_refusal <label>: a refusal is the dispatcher's JSON with no leaked account name. The
# exit code is transport evidence only: 64 is the dispatcher's code, anything else (zero included)
# means the code did not survive the trip and is a warning, not a failure.
classify_refusal() {
    label="$1"
    # whoami on Windows prints <computer>\<account>; that must not be in the answer.
    leaked=0
    if [ -n "$account" ] && grep -qF "\\$account" "$work/out"; then
        leaked=1
    fi
    if grep -q '"error":"refused"' "$work/out" && [ "$leaked" -eq 0 ]; then
        if [ "$rc" -eq 64 ]; then
            pass "A3 refused, exit code 64: $label"
        else
            warn "A3 refused, but the exit code was $rc instead of 64: $label"
        fi
    else
        fail "A3 NOT refused (exit code $rc): $label -> $(head -c 200 "$work/out" | tr '\n' ' ')"
    fi
}
refused "whoami" whoami
refused "ping; whoami" "ping; whoami"
refused "ping & whoami" "ping & whoami"
refused "powershell -Command whoami" powershell -Command whoami
refused "cmd /c whoami" cmd /c whoami
refused "collect-../../windows/system32/whoami" "collect-../../windows/system32/whoami"
refused "fetch-C:\\Windows\\win.ini" 'fetch-C:\Windows\win.ini'
# No command at all is a request for an interactive shell.
rc=0
wf_ssh -n -T -o BatchMode=yes -o ConnectTimeout=10 "$WF_HOST_ALIAS" >"$work/out" 2>"$work/err" || rc=$?
classify_refusal "a request for an interactive shell (no command)"
# A forced terminal request. Win32-OpenSSH enforces ForceCommand only on sessions without a
# terminal and relies on PermitTTY no to refuse one; the client reports a refused terminal as
# "PTY allocation request failed on channel 0". There must be no terminal, no prompt, no shell.
rc=0
wf_ssh -tt -o BatchMode=yes -o ConnectTimeout=10 "$WF_HOST_ALIAS" >"$work/out" 2>"$work/err" </dev/null || rc=$?
tr -d '\r' <"$work/out" >"$work/out.txt"
if grep -Eq '^(PS )?[A-Za-z]:\\[^>]*>' "$work/out.txt" || { [ -n "$account" ] && grep -qF "\\$account" "$work/out.txt"; }; then
    fail "A3 a forced terminal request (-tt) reached a shell: $(head -c 200 "$work/out.txt" | tr '\n' ' ')"
elif ! grep -q 'PTY allocation request failed' "$work/err"; then
    fail "A3 a forced terminal request (-tt) was granted a terminal (PermitTTY no is not in effect); exit code $rc"
else
    cp "$work/out.txt" "$work/out"
    classify_refusal "a forced terminal request (-tt): no terminal was granted"
fi
# scp and sftp are blocked by the forced command as well.
rc=0
wf_ssh -n -T -o BatchMode=yes -o ConnectTimeout=10 -s "$WF_HOST_ALIAS" sftp >"$work/out" 2>"$work/err" || rc=$?
if grep -q 'SSH_FXP\|^sftp>' "$work/out"; then
    fail "A3 the sftp subsystem answered (exit code $rc)"
else
    classify_refusal "the sftp subsystem"
fi

# ---- A4: password authentication ---------------------------------------------------------------
rc=0
wf_ssh -n -T -o BatchMode=yes -o ConnectTimeout=10 -o PubkeyAuthentication=no -o PasswordAuthentication=yes \
    -o PreferredAuthentications=password,keyboard-interactive "$WF_HOST_ALIAS" ping >"$work/out" 2>"$work/err" || rc=$?
methods="$(sed -n 's/.*Permission denied (\([^)]*\)).*/\1/p' "$work/err" | head -n 1)"
if [ "$rc" -eq 0 ] || grep -q '"ok":true' "$work/out"; then
    fail "A4 a connection WITHOUT the key succeeded"
elif [ -z "$methods" ]; then
    fail "A4 could not tell which methods the server offers: $(tr '\n' ' ' <"$work/err")"
else
    case ",$methods," in
        *,password,*|*,keyboard-interactive,*) fail "A4 the server still offers password logon (methods: $methods)" ;;
        *) pass "A4 password authentication is refused; the server offers only: $methods" ;;
    esac
fi

# ---- A5: host key mismatch and missing pin -----------------------------------------------------
if ssh-keygen -q -t ed25519 -N "" -C wf-acceptance-decoy -f "$work/decoy" >/dev/null 2>&1; then
    printf '%s %s\n' "$WF_HOST_ALIAS" "$(awk '{print $1, $2}' "$work/decoy.pub")" >"$work/wrong_known_hosts"
    rc=0
    wf_ssh -n -T -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$work/wrong_known_hosts" \
        "$WF_HOST_ALIAS" ping >"$work/out" 2>"$work/err" || rc=$?
    if [ "$rc" -eq 255 ] && ! grep -q '"ok":true' "$work/out" && grep -Eq 'HOST IDENTIFICATION HAS CHANGED|Host key verification failed' "$work/err"; then
        pass "A5 a different host key stops the connection (exit code 255, nothing was sent)"
    else
        fail "A5 a different host key did NOT stop the connection (exit code $rc)"
    fi
    : >"$work/empty_known_hosts"
    rc=0
    wf_ssh -n -T -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$work/empty_known_hosts" \
        "$WF_HOST_ALIAS" ping >"$work/out" 2>"$work/err" || rc=$?
    if [ "$rc" -eq 255 ] && ! grep -q '"ok":true' "$work/out"; then
        pass "A5 an unpinned host is not trusted on first contact"
    else
        fail "A5 an unpinned host was trusted (exit code $rc)"
    fi
else
    fail "A5 could not create the decoy key for the mismatch test"
fi

# ---- A6: unknown collector ---------------------------------------------------------------------
run collect-no-such-collector
if [ "$rc" -eq 65 ] && grep -q '"error":"unknown collector"' "$work/out"; then
    pass "A6 collect-no-such-collector answered 'unknown collector' (exit code 65)"
elif grep -q '"error":"unknown collector"' "$work/out"; then
    warn "A6 'unknown collector' came back, but with exit code $rc instead of 65"
else
    fail "A6 unexpected answer to collect-no-such-collector (exit code $rc): $(head -c 200 "$work/out" | tr '\n' ' ')"
fi
collectors="$(sed -n 's/.*"collectors":\[\([^]]*\)\].*/\1/p' "$work/ping" | head -n 1)"
if [ -n "$collectors" ]; then
    info "A6 collectors installed on the PC: $collectors"
else
    info "A6 no collectors are installed yet, so every collect-<name> answers 'unknown collector'. They arrive with a later kit"
fi

# ---- A7: Security log measurement -------------------------------------------------------------
run security-log-access
if [ "$rc" -eq 0 ] && grep -q '"verb":"security-log-access"' "$work/out"; then
    pass "A7 security-log-access returned a measurement (recorded below)"
    say "     channelAccess: $(wf_json_string channel_access "$work/out")"
    say "     the account can read the channel configuration: $(sed -n 's/.*"config_readable":\([a-z]*\).*/\1/p' "$work/out")"
    say "     the account can read the Security log itself:    $(sed -n 's/.*"log_readable":\([a-z]*\).*/\1/p' "$work/out")"
    say "     read entry for Event Log Readers (S-1-5-32-573):  $(sed -n 's/.*"event_log_readers_read_entry":\([a-z]*\).*/\1/p' "$work/out")"
    say "     raw: $(head -n 1 "$work/out")"
else
    fail "A7 security-log-access failed (exit code $rc): $(head -c 200 "$work/out" | tr '\n' ' ')"
fi

# ---- A8: outbox and transfer ------------------------------------------------------------------
run list-bundles
if [ "$rc" -eq 0 ] && grep -q '"verb":"list-bundles"' "$work/out"; then
    newest="$(grep -o '"bundle_dir":"[^"]*"' "$work/out" | tail -n 1 | sed 's/.*:"\(.*\)"/\1/')"
    if [ -z "$newest" ]; then
        pass "A8 list-bundles works; the outbox is empty (expected before collectors are installed)"
    elif [ "$fetch_newest" -eq 1 ]; then
        if sh "$script_dir/wf-fetch.sh" --host-alias "$WF_HOST_ALIAS" --out "$work/fetched" "$newest" >"$work/fetch.out" 2>&1; then
            pass "A8 fetched $newest and its SHA-256 matches what the PC reported"
        else
            fail "A8 fetching $newest failed: $(tr '\n' ' ' <"$work/fetch.out")"
        fi
    else
        pass "A8 list-bundles works; newest bundle: $newest (add --fetch-newest to fetch and verify it)"
    fi
else
    fail "A8 list-bundles failed (exit code $rc)"
fi

# ---- A9: other addresses ------------------------------------------------------------------------
say "TODO A9 not testable from this Mac: a connection from any OTHER address must be refused."
say "     From another device on the home network (not this Mac), try the PC's port 22, for example:"
say "         nc -vz -w 5 ${hostname_value:-<PC_LAN_ADDRESS>} 22"
say "     It must time out. If it connects, stop and rerun the setup script at the PC."
say "     The setup script's step S3 already verified the firewall rule at the PC itself."

# ---- A10: after a reboot with nobody signed in ------------------------------------------------
boot="$(wf_json_string boot_time_utc "$work/ping")"
console="$(sed -n 's/.*"console_user":\([a-z]*\).*/\1/p' "$work/ping" | head -n 1)"
if [ "$after_reboot" -eq 1 ]; then
    boot_epoch=""
    if [ -n "$boot" ]; then
        boot_epoch="$(date -j -u -f '%Y-%m-%dT%H:%M:%SZ' "$boot" +%s 2>/dev/null || date -u -d "$boot" +%s 2>/dev/null || true)"
    fi
    if [ -z "$boot_epoch" ]; then
        warn "A10 the PC did not report its boot time, so the restart cannot be confirmed from here"
    else
        age=$(( $(date -u +%s) - boot_epoch ))
        if [ "$age" -ge 0 ] && [ "$age" -le 1800 ]; then
            pass "A10 the PC restarted $((age / 60)) minute(s) ago and the checks above ran after that restart"
        else
            fail "A10 the PC last started $((age / 60)) minute(s) ago; restart it, do not sign in, and run this again within 30 minutes"
        fi
    fi
    case "$console" in
        false) pass "A10 nobody is signed in at the PC's screen" ;;
        true) fail "A10 somebody is signed in at the PC's screen; restart, do not sign in, and run this again" ;;
        *) warn "A10 the PC did not report whether somebody is signed in" ;;
    esac
else
    info "A10 not run. After restarting the PC and NOT signing in, run: sh remote-access/mac/wf-acceptance.sh --after-reboot"
fi

say ""
if [ "$fails" -eq 0 ]; then
    say "RESULT: PASS (no check failed; A9 is still yours to do by hand)"
else
    say "RESULT: FAIL ($fails check(s) failed)"
fi
say "Report saved to $report (facts about your PC: keep it out of any repository)"
[ "$fails" -eq 0 ]
