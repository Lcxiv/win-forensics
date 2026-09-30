"""The SSH front door under remote-access/: Mac side scripts, documents, and the PowerShell suite.

Nothing here talks to a real PC. The Mac side scripts run against a stand-in `ssh` placed first on
PATH. When a PowerShell 7 is available (on PATH, in $WF_PWSH, or under tools/pwsh) the stand-in
runs the real dispatcher, and the Pester suite and PSScriptAnalyzer run too; otherwise those tests
are skipped and say so. What can only be proven on Windows is listed in remote-access/README.md.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import textwrap
import zipfile
from pathlib import Path

import pytest

from test_docs import DASHES, FINDING_TOKENS

REPO_ROOT = Path(__file__).resolve().parent.parent
REMOTE = REPO_ROOT / "remote-access"
MAC = REMOTE / "mac"
WINDOWS = REMOTE / "windows"
MAC_SCRIPTS = ["wf-mac-setup.sh", "wf-make-kit.sh", "wf-pin-host-key.sh", "wf-acceptance.sh", "wf-fetch.sh", "wf-start.sh", "wf-finish.sh"]
# What travels inside the kit zip ...
WINDOWS_SCRIPTS = ["Install-FrontDoor.ps1", "WfSetupLib.ps1", "WfCommon.ps1", "dispatch.ps1"]
# ... and what sits next to it in the kit folder: the double click launcher.
LAUNCHER_FILES = ["SETUP-PC.cmd", "Start-FrontDoorSetup.ps1"]
BUNDLE_DIR = "20260930T171044Z_sample-ok_0123abcd"


# ---------------------------------------------------------------------------------------------
# PowerShell discovery
# ---------------------------------------------------------------------------------------------

def find_pwsh() -> str | None:
    candidates = [os.environ.get("WF_PWSH"), shutil.which("pwsh"), str(REPO_ROOT / "tools" / "pwsh" / "pwsh")]
    for candidate in candidates:
        if candidate and Path(candidate).is_file() and os.access(candidate, os.X_OK):
            return candidate
    return None


def module_path() -> str | None:
    candidate = os.environ.get("WF_PSMODULES") or str(REPO_ROOT / "tools" / "psmodules")
    return candidate if Path(candidate).is_dir() else None


PWSH = find_pwsh()
needs_pwsh = pytest.mark.skipif(PWSH is None, reason="no PowerShell 7 found (PATH, $WF_PWSH, tools/pwsh); see remote-access/README.md, Tests")


# ---------------------------------------------------------------------------------------------
# A stand-in for ssh
# ---------------------------------------------------------------------------------------------

FAKE_SSH = r'''
import base64, hashlib, io, json, os, subprocess, sys, time, zipfile

args = sys.argv[1:]
opts, flags, positional = {}, set(), []
i = 0
while i < len(args):
    a = args[i]
    if a == "-o":
        key, _, value = args[i + 1].partition("=")
        opts.setdefault(key.lower(), value)  # like ssh: the first value wins
        i += 2
    elif a in ("-F", "-i", "-p"):
        i += 2
    elif a in ("-n", "-T", "-G", "-s", "-tt", "-t"):
        flags.add(a)
        i += 1
    else:
        positional = args[i:]
        break
host = positional[0]
command = " ".join(positional[1:])
mode = os.environ.get("FAKE_SSH_MODE", "healthy")
known_hosts = os.environ["WF_KNOWN_HOSTS"]
host_key = os.environ["FAKE_HOST_KEY"]
with open(os.environ["FAKE_SSH_LOG"], "a") as log:
    log.write(json.dumps({"flags": sorted(flags), "opts": opts, "host": host, "command": command}) + "\n")

if "-G" in flags:
    hostname = host if mode == "noconfig" else "192.0.2.20"
    strict = "false" if mode == "lax-client" else "true"
    print(f"hostname {hostname}\nport 22\nstricthostkeychecking {strict}\nuserknownhostsfile {known_hosts}\n"
          "passwordauthentication no\nforwardagent no")
    sys.exit(0)

def die(message, code=255):
    sys.stderr.write(message + "\n")
    sys.exit(code)

if mode == "unreachable":
    die(f"ssh: connect to host 192.0.2.20 port 22: Operation timed out")

# Host key check, as StrictHostKeyChecking yes does it.
with open(opts.get("userknownhostsfile", known_hosts)) as handle:
    pinned = [line.split() for line in handle if line.strip()]
pinned_key = next((parts[2] for parts in pinned if parts[0] == host), None)
if mode != "trusting":
    if pinned_key is None:
        die(f"No ED25519 host key is known for {host} and you have requested strict checking.\nHost key verification failed.")
    if pinned_key != host_key:
        die("@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\nHost key verification failed.")

if opts.get("pubkeyauthentication") == "no":
    methods = "publickey,password,keyboard-interactive" if mode == "password-enabled" else "publickey"
    die(f"wfcollector@192.0.2.20: Permission denied ({methods}).")

def out(obj, code=0):
    sys.stdout.write(json.dumps(obj, separators=(",", ":")) + "\n")
    sys.exit(code)

if mode == "shell":  # a PC where the forced command is missing: it just runs things
    if "-tt" in flags:
        sys.stdout.write("Microsoft Windows [Version 10.0.26100]\r\nC:\\Users\\wfcollector>")
    else:
        sys.stdout.write("gamingpc\\wfcollector\n")
    sys.exit(0)

# PermitTTY no: the server refuses the terminal, the client says so, the forced command runs.
if "-tt" in flags and mode != "pty-granted":
    sys.stderr.write("PTY allocation request failed on channel 0\n")

dispatcher = os.environ.get("FAKE_SSH_DISPATCHER")
if dispatcher and command != "security-log-access":
    env = dict(os.environ)
    env.pop("SSH_ORIGINAL_COMMAND", None)
    if command:
        env["SSH_ORIGINAL_COMMAND"] = command
    done = subprocess.run([os.environ["FAKE_SSH_PWSH"], "-NoProfile", "-NonInteractive", "-File", dispatcher], env=env, stdin=subprocess.DEVNULL)
    sys.exit(done.returncode)

refusal_code = {"exit-codes-lost": 1, "exit-zero": 0}.get(mode, 64)
if command == "ping":
    boot = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - int(os.environ.get("FAKE_BOOT_AGE", "300"))))
    out({"ok": True, "verb": "ping", "protocol": 1, "host_id": "0123abcd0123abcd", "account": "wfcollector",
         "dispatcher_sha256": os.environ.get("FAKE_DISPATCHER_SHA", ""), "collectors": [],
         "boot_time_utc": boot, "console_user": mode == "signed-in"})
if command == "collect-no-such-collector":
    out({"ok": False, "verb": "collect", "error": "unknown collector", "collector": "no-such-collector", "available": []}, 65)
if command == "security-log-access":
    out({"ok": True, "verb": "security-log-access", "account": "wfcollector", "config_exit_code": 0, "config_readable": True,
         "channel_access": "O:BAG:SYD:(A;;0xf0005;;;SY)(A;;0x5;;;BA)(A;;0x1;;;S-1-5-32-573)",
         "event_log_readers_read_entry": True, "log_info_exit_code": 0, "log_readable": True})
bundle_dir = os.environ.get("FAKE_BUNDLE_DIR", "")
if command == "list-bundles":
    bundles = [{"bundle_dir": bundle_dir, "files": 2, "bytes": 30}] if bundle_dir else []
    out({"ok": True, "verb": "list-bundles", "bundles": bundles})
if bundle_dir and command == "fetch-" + bundle_dir:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(bundle_dir + "/manifest.json", '{"manifest_version":"1.0.0"}')
        archive.writestr(bundle_dir + "/raw/eventlog/system.json", "[]" * 5000)
        if mode == "zip-slip":
            archive.writestr("../escaped.txt", "out of the bundle directory")
        if mode == "symlink":
            info = zipfile.ZipInfo(bundle_dir + "/raw/link")
            info.external_attr = (0o120777 << 16)
            archive.writestr(info, "../../../../etc/passwd")
    data = buffer.getvalue()
    digest = hashlib.sha256(data).hexdigest()
    body = base64.encodebytes(data).decode().splitlines()
    if mode == "corrupt-body":
        body[1] = body[1][:10] + ("A" if body[1][10] != "A" else "B") + body[1][11:]
    if mode == "wrong-sha":
        digest = "0" * 64
    size = len(data) + (1 if mode == "wrong-size" else 0)
    lines = [f"WF-BUNDLE-BEGIN v1 dir={bundle_dir} bytes={size} sha256={digest}"] + body
    if mode != "truncated":
        lines.append(f"WF-BUNDLE-END v1 dir={bundle_dir}")
    newline = "\r\n" if mode == "crlf" else "\n"
    sys.stdout.write(newline.join(lines) + newline)
    sys.exit(0)
if command.startswith("fetch-") and len(command) > 40:
    out({"ok": False, "verb": "fetch", "error": "unknown bundle"}, 66)
sys.stderr.write("wf-dispatch: refused: not an allowed verb\n")
out({"ok": False, "error": "refused", "reason": "not an allowed verb"}, refusal_code)
'''

FAKE_KEYSCAN = r'''
import os, sys
if os.environ.get("FAKE_SSH_MODE") == "unreachable":
    sys.exit(1)
print("192.0.2.20 ssh-ed25519 " + os.environ["FAKE_HOST_KEY"])
'''


def make_public_key(seed: int) -> tuple[str, str]:
    """A syntactically valid Ed25519 public key blob (base64) and its SHA256 fingerprint."""
    blob = (11).to_bytes(4, "big") + b"ssh-ed25519" + (32).to_bytes(4, "big") + bytes([seed]) * 32
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    return base64.b64encode(blob).decode(), fingerprint


def write_executable(path: Path, body: str) -> None:
    path.write_text(f"#!{sys.executable}\n" + textwrap.dedent(body))
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


@pytest.fixture()
def mac(tmp_path: Path) -> dict:
    """A throwaway Mac: HOME, a bin directory with the stand-ins first on PATH, a pinned host key."""
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    write_executable(bin_dir / "ssh", FAKE_SSH)
    write_executable(bin_dir / "ssh-keyscan", FAKE_KEYSCAN)
    host_key, fingerprint = make_public_key(7)
    known_hosts = home / ".ssh" / "known_hosts_winforensics"
    known_hosts.write_text(f"gaming-pc ssh-ed25519 {host_key}\n")
    env = {
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "HOME": str(home),
        "WF_KNOWN_HOSTS": str(known_hosts),
        "WF_KEY_FILE": str(home / ".ssh" / "id_ed25519_winforensics"),
        "FAKE_HOST_KEY": host_key,
        "FAKE_SSH_LOG": str(tmp_path / "ssh.log"),
        "FAKE_DISPATCHER_SHA": hashlib.sha256((WINDOWS / "dispatch.ps1").read_bytes()).hexdigest(),
        "TMPDIR": str(tmp_path),
    }
    return {"env": env, "home": home, "tmp": tmp_path, "fingerprint": fingerprint, "host_key": host_key, "known_hosts": known_hosts}


def run_script(mac: dict, script: str, *args: str, mode: str = "healthy", extra_env: dict | None = None, stdin: str | None = None):
    env = dict(mac["env"], FAKE_SSH_MODE=mode, **(extra_env or {}))
    return subprocess.run(["sh", str(MAC / script), *args], env=env, capture_output=True, text=True,
                          input=stdin, stdin=None if stdin is not None else subprocess.DEVNULL, timeout=120)


def ssh_calls(mac: dict) -> list[dict]:
    log = Path(mac["env"]["FAKE_SSH_LOG"])
    return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []


# ---------------------------------------------------------------------------------------------
# Files and documents
# ---------------------------------------------------------------------------------------------

def remote_text_files() -> list[Path]:
    return sorted(p for p in REMOTE.rglob("*") if p.is_file() and p.suffix in {".md", ".ps1", ".psd1", ".sh", ".cmd"})


def test_expected_files_exist():
    for name in MAC_SCRIPTS + ["wf-common.sh"]:
        assert (MAC / name).is_file(), name
    for name in WINDOWS_SCRIPTS + LAUNCHER_FILES:
        assert (WINDOWS / name).is_file(), name
    assert (REMOTE / "README.md").is_file()
    assert (REMOTE / "CHECKLIST.md").is_file()


def test_no_em_or_en_dashes_and_no_win_opt_findings():
    offenders = []
    for path in remote_text_files() + [Path(__file__)]:
        text = path.read_text(encoding="utf-8")
        for number, line in enumerate(text.splitlines(), start=1):
            if DASHES.search(line):
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{number} dash")
        if path != Path(__file__):
            offenders += [f"{path.relative_to(REPO_ROOT)}: {token}" for token in FINDING_TOKENS if token in text]
    assert not offenders, offenders


def test_scripts_are_ascii_with_unix_line_endings():
    # Windows PowerShell 5.1 reads a script without a byte order mark as ANSI, so anything beyond
    # ASCII would be misread on the PC. The one .cmd file is the exception for line endings:
    # cmd.exe batch files are written with CRLF.
    for path in remote_text_files():
        if path.suffix == ".md":
            continue
        data = path.read_bytes()
        assert all(byte < 128 for byte in data), path.name
        if path.suffix == ".cmd":
            assert b"\n" in data and data.count(b"\r\n") == data.count(b"\n"), path.name
        else:
            assert b"\r" not in data, path.name


def test_scripts_hold_no_address_key_or_secret():
    private_range = re.compile(r"\b(10\.\d{1,3}|192\.168|172\.(1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b")
    for name in WINDOWS_SCRIPTS + LAUNCHER_FILES:
        text = (WINDOWS / name).read_text()
        assert not private_range.search(text), name
    for name in MAC_SCRIPTS + ["wf-common.sh"]:
        text = (MAC / name).read_text()
        assert not private_range.search(text), name
        assert "PRIVATE KEY-----" not in text, name
    for path in remote_text_files():
        text = path.read_text()
        assert "BEGIN OPENSSH PRIVATE KEY-----\nb3Blbn" not in text, path.name
        assert not re.search(r"(?i)passphrase\s*[:=]\s*\S", text), path.name


def test_checklist_uses_placeholders_and_covers_every_step():
    text = (REMOTE / "CHECKLIST.md").read_text()
    for placeholder in ["<MAC_LAN_ADDRESS>", "<PC_LAN_ADDRESS>"]:
        assert placeholder in text, placeholder
    for needle in [
        "ssh-keygen", "passphrase", "Get-FileHash", "DHCP", "Private", "Install-FrontDoor.ps1",
        "wf-pin-host-key.sh", "wf-acceptance.sh", "StrictHostKeyChecking", "If a step fails",
        "How to turn it all off", "Disable-LocalUser", "Remove-WindowsCapability", "Remove-NetFirewallRule",
        "unknown collector", "--after-reboot", "wf-start.sh", "wf-finish.sh", "SETUP-PC.cmd", "kit code",
        "If an action fails", "minutes", "removable", "USB stick", "Get-FileHash", "--fingerprint", "full SHA-256",
    ]:
        assert needle in text, needle
    # Three actions, the router as the manual step between them, and the long procedure as an appendix
    # with its own L ids, distinct from the acceptance A ids.
    assert "Action 1" in text and "Action 2" in text and "Action 3" in text
    assert "Router" in text
    assert "Appendix" in text
    for step in ["L1", "L2", "L3", "L4", "L5", "L6", "L7", "L8"]:
        assert re.search(rf"^\| {step} \|", text, re.M), step
    # The acceptance IDs are explained in the acceptance table of action 3, not anywhere else.
    acceptance_section = re.search(r"\| Check \| What it proves \|(.*?)\n\n", text, re.S).group(1)
    for check in sorted(set(re.findall(r"\b(A\d+)\b", (MAC / "wf-acceptance.sh").read_text()))):
        assert re.search(rf"^\| {check} \|", acceptance_section, re.M), f"check {check} is not explained in the acceptance table"
    # Every way the launcher can stop has a row under "If an action fails".
    launcher = (WINDOWS / "Start-FrontDoorSetup.ps1").read_text()
    for stop in ["permission prompt was declined", "kit code did not match", "not Private", "not running as Administrator",
                 "is missing", "not on a removable one", "could not look up a route", "no staging folder could be made",
                 "could not be unpacked", "exit code could not be read"]:
        assert stop in launcher, stop
    for row in ["declined", "code does not match", "not Private", "not running as Administrator", "missing",
                "not on a removable", "could not look up a route", "staging folder", "could not be unpacked",
                "exit code could not be read", "more than one pc-host-key.pub", "is not on a disk mounted under",
                "no pc-host-key.pub on any disk", "report"]:
        assert re.search(rf"^\| .*{row}", text, re.M), f"no failure row about: {row}"
    # Every step id the setup script reports has a failure row: InstallFrontDoor.Tests.ps1 checks
    # that against the step records of a run, in the Pester suite below.


def test_checklist_never_asks_for_a_secret():
    text = (REMOTE / "CHECKLIST.md").read_text().lower()
    for phrase in ["paste your passphrase", "paste the private key", "send the private key", "type your passphrase into"]:
        assert phrase not in text
    assert "never" in text and "private key" in text


def test_readme_points_at_remote_access():
    assert "remote-access/" in (REPO_ROOT / "README.md").read_text()


def test_documents_cite_their_sources():
    readme = (REMOTE / "README.md").read_text()
    for url in [
        "https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse",
        "https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-server-configuration",
        "https://github.com/PowerShell/openssh-portable/blob/",
        "https://github.com/PowerShell/Win32-OpenSSH/wiki/sshd_config",
        "https://man.openbsd.org/sshd",
    ]:
        assert url in readme, url
    assert "Not verified off Windows" in readme
    assert "Where this departs from the plan" in readme


@pytest.mark.parametrize("name", MAC_SCRIPTS + ["wf-common.sh"])
def test_shell_scripts_parse(name):
    assert subprocess.run(["sh", "-n", str(MAC / name)], capture_output=True).returncode == 0


def test_setup_pc_cmd_starts_the_launcher_from_its_own_folder_with_a_process_scoped_policy():
    text = (WINDOWS / "SETUP-PC.cmd").read_text()
    command = [line for line in text.splitlines() if "powershell.exe" in line and not line.startswith("rem")]
    assert len(command) == 1
    line = command[0]
    assert line.startswith('"%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"'), line
    assert '-File "%~dp0Start-FrontDoorSetup.ps1"' in line
    assert '-KitFolder "%~dp0."' in line, "a trailing backslash before the closing quote would escape it"
    assert "-ExecutionPolicy Bypass" in line and "-NoProfile" in line
    assert "-Elevated" not in line, "elevation is the launcher's decision, after the UAC prompt"
    assert text.rstrip().endswith("pause")
    assert "removable drive" in text and "Get-FileHash" in text


def full_digest(hex_digest: str) -> str:
    upper = hex_digest.upper()
    return " ".join(upper[i:i + 8] for i in range(0, 64, 8))


@pytest.mark.parametrize("bad", ["999.999.999.999", "256.0.0.1", "192.0.2.300", "1.2.3", "a.b.c.d", "10.0.0.1.2"])
def test_wf_is_ipv4_rejects_out_of_range_and_malformed_addresses(bad):
    done = subprocess.run(["sh", "-c", f'. "{MAC / "wf-common.sh"}"; wf_is_ipv4 "{bad}"'], capture_output=True, text=True)
    assert done.returncode != 0, bad
    for good in ["0.0.0.0", "255.255.255.255", "192.0.2.10"]:
        assert subprocess.run(["sh", "-c", f'. "{MAC / "wf-common.sh"}"; wf_is_ipv4 "{good}"'], capture_output=True).returncode == 0, good


def kit_code(hex_digest: str) -> str:
    prefix = hex_digest.lower()[:32]
    return " ".join(prefix[i:i + 4] for i in range(0, 32, 4))


def test_kit_code_is_derived_the_same_way_on_the_mac_and_at_the_pc():
    digest = hashlib.sha256(b"any kit").hexdigest()
    expected = kit_code(digest)
    assert len(expected) == 39 and expected.count(" ") == 7
    done = subprocess.run(["sh", "-c", f'. "{MAC / "wf-common.sh"}"; wf_kit_code {digest.upper()}'], capture_output=True, text=True)
    assert done.returncode == 0 and done.stdout.strip() == expected
    if PWSH:
        script = f'. "{WINDOWS / "Start-FrontDoorSetup.ps1"}" -KitFolder x; Get-WfKitCode -HexHash "{digest.upper()}"'
        done = subprocess.run([PWSH, "-NoProfile", "-Command", script], capture_output=True, text=True, timeout=120)
        assert done.returncode == 0, done.stderr
        assert done.stdout.strip() == expected


@pytest.mark.skipif(shutil.which("shellcheck") is None, reason="shellcheck is not installed")
def test_shell_scripts_pass_shellcheck():
    done = subprocess.run(["shellcheck", "-x", *MAC_SCRIPTS, "wf-common.sh"], cwd=MAC, capture_output=True, text=True)
    assert done.returncode == 0, done.stdout


# ---------------------------------------------------------------------------------------------
# wf-acceptance.sh
# ---------------------------------------------------------------------------------------------

def acceptance(mac: dict, *args: str, mode: str = "healthy", extra_env: dict | None = None):
    report = mac["tmp"] / "report.txt"
    done = run_script(mac, "wf-acceptance.sh", "--report", str(report), *args, mode=mode, extra_env=extra_env)
    return done, report.read_text() if report.exists() else ""


def lines_with(output: str, prefix: str) -> list[str]:
    return [line for line in output.splitlines() if line.startswith(prefix)]


def test_acceptance_passes_against_a_correct_front_door(mac):
    done, report = acceptance(mac)
    assert done.returncode == 0, done.stdout + done.stderr
    assert "RESULT: PASS" in done.stdout
    assert not lines_with(done.stdout, "FAIL")
    assert not lines_with(done.stdout, "WARN")
    for check in ["A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8"]:
        assert lines_with(done.stdout, f"PASS {check}"), check
    assert lines_with(done.stdout, "TODO A9")
    assert "unknown collector" in done.stdout
    assert "channelAccess: O:BAG:SYD:" in report
    assert report.strip().splitlines()[-1].startswith("Report saved to")


def test_acceptance_sends_only_allowlisted_or_refusable_requests_and_one_deliberate_terminal_request(mac):
    acceptance(mac)
    calls = [c for c in ssh_calls(mac) if "-G" not in c["flags"]]
    assert calls
    terminal = [c for c in calls if "-tt" in c["flags"]]
    assert len(terminal) == 1 and terminal[0]["command"] == ""
    for call in calls:
        if call in terminal:
            continue
        assert "-n" in call["flags"] and "-T" in call["flags"], call
        assert call["opts"].get("batchmode") == "yes", call
    sent = {c["command"] for c in calls}
    assert {"ping", "whoami", "ping; whoami", "collect-no-such-collector", "security-log-access", "list-bundles", ""} <= sent


def test_acceptance_passes_the_terminal_request_only_when_no_terminal_and_no_shell_came_back(mac):
    done, _ = acceptance(mac)
    assert any("forced terminal request" in line for line in lines_with(done.stdout, "PASS A3"))

    done, _ = acceptance(mac, mode="pty-granted")
    assert done.returncode != 0
    assert any("granted a terminal" in line for line in lines_with(done.stdout, "FAIL A3"))

    done, _ = acceptance(mac, mode="shell")
    assert any("reached a shell" in line for line in lines_with(done.stdout, "FAIL A3"))


def test_acceptance_fails_when_whoami_is_executed(mac):
    done, _ = acceptance(mac, mode="shell")
    assert done.returncode != 0
    assert "RESULT: FAIL" in done.stdout
    assert any("NOT refused" in line for line in lines_with(done.stdout, "FAIL A3"))


def test_acceptance_fails_when_the_server_offers_passwords(mac):
    done, _ = acceptance(mac, mode="password-enabled")
    assert done.returncode != 0
    assert lines_with(done.stdout, "FAIL A4")


def test_acceptance_fails_when_a_wrong_host_key_is_accepted(mac):
    done, _ = acceptance(mac, mode="trusting")
    assert done.returncode != 0
    assert len(lines_with(done.stdout, "FAIL A5")) == 2


def test_acceptance_fails_without_a_pinned_key_or_with_lax_checking(mac):
    mac["known_hosts"].write_text("")
    done, _ = acceptance(mac)
    assert done.returncode != 0
    assert any("no pinned host key" in line for line in lines_with(done.stdout, "FAIL A1"))
    assert lines_with(done.stdout, "FAIL A2")

    mac["known_hosts"].write_text(f"gaming-pc ssh-ed25519 {mac['host_key']}\n")
    done, _ = acceptance(mac, mode="lax-client")
    assert done.returncode != 0
    assert any("StrictHostKeyChecking" in line for line in lines_with(done.stdout, "FAIL A1"))


def test_acceptance_a9_guidance_names_a_placeholder_when_no_host_is_known(mac):
    done, _ = acceptance(mac, mode="noconfig")
    assert done.returncode != 0
    assert lines_with(done.stdout, "FAIL A1")
    assert "nc -vz -w 5 <PC_LAN_ADDRESS> 22" in done.stdout
    assert "nc -vz -w 5  22" not in done.stdout


def test_acceptance_reports_an_unreachable_pc_as_failure_with_guidance(mac):
    done, _ = acceptance(mac, mode="unreachable")
    assert done.returncode != 0
    assert lines_with(done.stdout, "FAIL A2")
    assert "255 means ssh itself could not connect" in done.stdout


@pytest.mark.parametrize("mode", ["exit-codes-lost", "exit-zero"])
def test_acceptance_warns_when_exit_codes_do_not_arrive(mac, mode):
    # A refusal is the dispatcher's JSON with nothing leaked; a wrong exit code, zero included,
    # is a transport warning, never a pass and never a failure.
    done, _ = acceptance(mac, mode=mode)
    assert done.returncode == 0
    assert any("instead of 64" in line for line in lines_with(done.stdout, "WARN A3"))
    assert not lines_with(done.stdout, "FAIL")
    assert not lines_with(done.stdout, "PASS A3 refused, exit code 64")


def test_acceptance_warns_when_the_installed_dispatcher_differs(mac):
    done, _ = acceptance(mac, extra_env={"FAKE_DISPATCHER_SHA": "f" * 64})
    assert done.returncode == 0
    assert any("differs from this checkout" in line for line in lines_with(done.stdout, "WARN A2"))


def test_acceptance_after_reboot(mac):
    done, _ = acceptance(mac, "--after-reboot")
    assert done.returncode == 0
    assert len(lines_with(done.stdout, "PASS A10")) == 2

    done, _ = acceptance(mac, "--after-reboot", extra_env={"FAKE_BOOT_AGE": "90000"})
    assert done.returncode != 0
    assert any("restart it" in line for line in lines_with(done.stdout, "FAIL A10"))

    done, _ = acceptance(mac, "--after-reboot", mode="signed-in")
    assert done.returncode != 0
    assert any("signed in" in line for line in lines_with(done.stdout, "FAIL A10"))


def test_acceptance_fetches_and_verifies_the_newest_bundle_on_request(mac):
    done, _ = acceptance(mac, "--fetch-newest", extra_env={"FAKE_BUNDLE_DIR": BUNDLE_DIR})
    assert done.returncode == 0, done.stdout
    assert any(BUNDLE_DIR in line and "SHA-256 matches" in line for line in lines_with(done.stdout, "PASS A8"))

    done, _ = acceptance(mac, "--fetch-newest", mode="wrong-sha", extra_env={"FAKE_BUNDLE_DIR": BUNDLE_DIR})
    assert done.returncode != 0
    assert lines_with(done.stdout, "FAIL A8")


# ---------------------------------------------------------------------------------------------
# wf-fetch.sh
# ---------------------------------------------------------------------------------------------

def fetch(mac: dict, *args: str, mode: str = "healthy"):
    out_dir = mac["tmp"] / "bundles"
    done = run_script(mac, "wf-fetch.sh", BUNDLE_DIR, "--out", str(out_dir), *args, mode=mode, extra_env={"FAKE_BUNDLE_DIR": BUNDLE_DIR})
    return done, out_dir


@pytest.mark.parametrize("mode", ["healthy", "crlf"])
def test_fetch_keeps_a_bundle_whose_size_and_sha256_match(mac, mode):
    done, out_dir = fetch(mac, mode=mode)
    assert done.returncode == 0, done.stderr
    zip_path = out_dir / f"{BUNDLE_DIR}.zip"
    digest = hashlib.sha256(zip_path.read_bytes()).hexdigest()
    assert digest in done.stdout
    with zipfile.ZipFile(zip_path) as archive:
        assert sorted(archive.namelist()) == [f"{BUNDLE_DIR}/manifest.json", f"{BUNDLE_DIR}/raw/eventlog/system.json"]
    assert [c["command"] for c in ssh_calls(mac)] == [f"fetch-{BUNDLE_DIR}"]


@pytest.mark.parametrize("mode", ["corrupt-body", "wrong-sha", "wrong-size", "truncated"])
def test_fetch_refuses_and_keeps_nothing_when_the_stream_is_damaged(mac, mode):
    done, out_dir = fetch(mac, mode=mode)
    assert done.returncode == 3, done.stdout + done.stderr
    assert "INTEGRITY FAILURE" in done.stderr
    assert not out_dir.exists() or not list(out_dir.iterdir())


def test_fetch_extracts_only_inside_the_bundle_directory(mac):
    done, out_dir = fetch(mac, "--extract")
    assert done.returncode == 0, done.stderr
    assert (out_dir / BUNDLE_DIR / "manifest.json").is_file()
    assert (out_dir / BUNDLE_DIR / "raw" / "eventlog" / "system.json").is_file()


def test_fetch_refuses_a_zip_with_a_symbolic_link_entry(mac):
    done, out_dir = fetch(mac, "--extract", mode="symlink")
    assert done.returncode == 3, done.stdout + done.stderr
    assert "symbolic link" in done.stderr
    assert not out_dir.exists() or not list(out_dir.iterdir())
    # Without --extract the archive is kept as a file; nothing in it is ever followed.
    done, out_dir = fetch(mac, mode="symlink")
    assert done.returncode == 0


def test_fetch_extract_needs_unzip_and_says_so_before_fetching(mac):
    done = run_script(mac, "wf-fetch.sh", BUNDLE_DIR, "--out", str(mac["tmp"] / "bundles"), "--extract",
                      extra_env={"WF_UNZIP": "/nonexistent/unzip", "FAKE_BUNDLE_DIR": BUNDLE_DIR})
    assert done.returncode == 1
    assert "unzip" in done.stderr
    assert ssh_calls(mac) == []


def test_fetch_refuses_a_zip_that_would_write_outside_the_bundle_directory(mac):
    done, out_dir = fetch(mac, "--extract", mode="zip-slip")
    assert done.returncode == 3, done.stdout + done.stderr
    assert "outside the bundle directory" in done.stderr
    assert not (mac["tmp"] / "escaped.txt").exists()
    assert not out_dir.exists() or not list(out_dir.iterdir())


@pytest.mark.parametrize("bad", ["../../etc/passwd", "ping", "20260930T171044Z_sample-ok_0123ABCD", "x; rm -rf ~"])
def test_fetch_never_sends_something_that_is_not_a_bundle_directory_name(mac, bad):
    done = run_script(mac, "wf-fetch.sh", bad, "--out", str(mac["tmp"] / "bundles"))
    assert done.returncode == 1
    assert "not a bundle directory name" in done.stderr
    assert ssh_calls(mac) == []


def test_fetch_reports_an_unknown_bundle(mac):
    done = run_script(mac, "wf-fetch.sh", "20200101T000000Z_sample-ok_00000000", "--out", str(mac["tmp"] / "bundles"))
    assert done.returncode == 1
    assert "exit code 66" in done.stderr


# ---------------------------------------------------------------------------------------------
# wf-finish.sh: pin from the kit folder (or a typed fingerprint), then the acceptance checks
# ---------------------------------------------------------------------------------------------

def finish(mac: dict, *args: str, mode: str = "healthy", extra_env: dict | None = None):
    env = {"WF_VOLUMES_DIR": str(mac["tmp"] / "volumes"), **(extra_env or {})}
    return run_script(mac, "wf-finish.sh", *args, mode=mode, extra_env=env)


def kit_folder_with_host_key(mac: dict, key_blob: str, where: Path | None = None) -> Path:
    """A kit folder; by default on a stand-in mounted disk under the volumes directory."""
    folder = where or (mac["tmp"] / "volumes" / "STICK" / "wf-frontdoor")
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "pc-host-key.pub").write_text(f"ssh-ed25519 {key_blob} win-forensics-pc\n")
    return folder


def summary_lines(output: str, prefix: str) -> list[str]:
    return [line for line in output.splitlines() if line.startswith(prefix)]


@pytest.mark.skipif(shutil.which("ssh-keygen") is None, reason="ssh-keygen is not installed")
class TestFinish:
    def test_pins_from_the_stick_and_runs_every_check(self, mac):
        mac["known_hosts"].unlink()
        kit_folder_with_host_key(mac, mac["host_key"])
        done = finish(mac)
        assert done.returncode == 0, done.stdout + done.stderr
        assert "RESULT: PASS" in done.stdout.splitlines()[-2]
        assert any("matches pc-host-key.pub on the removable disk at" in line for line in summary_lines(done.stdout, "PASS  host key"))
        assert summary_lines(done.stdout, "PASS  acceptance: every check passed")
        assert summary_lines(done.stdout, "TODO  A9")
        assert summary_lines(done.stdout, "TODO  restart test")
        assert mac["known_hosts"].read_text() == f"gaming-pc ssh-ed25519 {mac['host_key']}\n"
        assert {"ping", "whoami", "list-bundles"} <= {c["command"] for c in ssh_calls(mac)}

    def test_pins_from_an_explicit_kit_folder_on_the_stick(self, mac):
        mac["known_hosts"].unlink()
        folder = kit_folder_with_host_key(mac, mac["host_key"])
        done = finish(mac, "--kit", str(folder))
        assert done.returncode == 0, done.stdout + done.stderr
        assert mac["known_hosts"].exists()

    def test_refuses_a_host_key_file_that_does_not_match_what_the_pc_offers(self, mac):
        mac["known_hosts"].unlink()
        other_key, _ = make_public_key(8)
        kit_folder_with_host_key(mac, other_key)
        done = finish(mac)
        assert done.returncode == 1
        assert "RESULT: FAIL" in done.stdout
        assert summary_lines(done.stdout, "FAIL  host key: NOT pinned")
        assert not mac["known_hosts"].exists()
        assert not [c for c in ssh_calls(mac) if "-G" not in c["flags"]], "no acceptance check may run without a pin"

    def test_does_not_trust_a_host_key_file_off_removable_media(self, mac):
        # Desktop, cloud folder, network share: the file could have been replaced.
        mac["known_hosts"].unlink()
        desktop = kit_folder_with_host_key(mac, mac["host_key"], mac["home"] / "Desktop" / "wf-frontdoor")
        done = finish(mac, "--kit", str(desktop))
        assert done.returncode == 2, done.stdout + done.stderr
        assert "RESULT: INCOMPLETE" in done.stdout
        assert any("is not on a disk mounted under" in line and "--fingerprint" in line for line in summary_lines(done.stdout, "INCOMPLETE  host key"))
        assert not mac["known_hosts"].exists()
        assert ssh_calls(mac) == [] or all("-G" in c["flags"] for c in ssh_calls(mac))
        # Without --kit the Desktop copy is not even looked at.
        done = finish(mac)
        assert done.returncode == 2 and "no pc-host-key.pub on any disk" in done.stdout
        assert not mac["known_hosts"].exists()

    def test_tells_the_captain_to_plug_in_the_stick_before_offering_by_eye(self, mac):
        mac["known_hosts"].unlink()
        done = finish(mac)  # no stick, no fingerprint, no terminal
        assert done.returncode == 2
        line = summary_lines(done.stdout, "INCOMPLETE  host key")[0]
        assert line.index("Plug in the USB stick") < line.index("--fingerprint") < line.index("--by-eye")
        assert not mac["known_hosts"].exists()
        assert not [c for c in ssh_calls(mac) if "-G" not in c["flags"]]

    def test_by_eye_names_its_source_and_needs_a_terminal(self, mac):
        mac["known_hosts"].unlink()
        done = finish(mac, "--by-eye")
        assert done.returncode == 2
        assert "your own comparison with the PC screen" in done.stdout
        assert "needs a terminal" in done.stdout
        assert not mac["known_hosts"].exists()

    def test_accepts_a_typed_fingerprint_and_rejects_a_malformed_one(self, mac):
        mac["known_hosts"].unlink()
        done = finish(mac, "--fingerprint", mac["fingerprint"])
        assert done.returncode == 0, done.stdout + done.stderr
        assert "the fingerprint you typed from the PC screen" in done.stdout
        assert mac["known_hosts"].exists()
        mac["known_hosts"].unlink()
        done = finish(mac, "--fingerprint", "SHA256:short")
        assert done.returncode == 1 and "RESULT: FAIL" in done.stdout
        assert not mac["known_hosts"].exists()

    def test_refuses_to_guess_between_two_sticks(self, mac):
        mac["known_hosts"].unlink()
        kit_folder_with_host_key(mac, mac["host_key"])
        kit_folder_with_host_key(mac, mac["host_key"], mac["tmp"] / "volumes" / "OTHER" / "wf-frontdoor")
        done = finish(mac)
        assert done.returncode == 1
        assert "more than one pc-host-key.pub" in done.stdout
        assert not mac["known_hosts"].exists()

    def test_is_incomplete_when_the_pc_does_not_answer_or_the_file_is_missing(self, mac):
        mac["known_hosts"].unlink()
        done = finish(mac, "--kit", str(mac["tmp"] / "volumes" / "STICK" / "wf-frontdoor"))
        assert done.returncode == 2 and "does not exist" in done.stdout and "Plug in the stick" in done.stdout
        kit_folder_with_host_key(mac, mac["host_key"])
        done = finish(mac, mode="unreachable")
        assert done.returncode == 2
        assert summary_lines(done.stdout, "INCOMPLETE  host key: no SSH answer")
        assert not mac["known_hosts"].exists()

    def test_fails_when_the_acceptance_checks_fail_and_keeps_their_lines(self, mac):
        kit_folder_with_host_key(mac, mac["host_key"])
        done = finish(mac, mode="shell")
        assert done.returncode == 1
        assert "RESULT: FAIL" in done.stdout
        assert summary_lines(done.stdout, "PASS  host key")
        assert summary_lines(done.stdout, "FAIL  acceptance:")
        assert lines_with(done.stdout, "FAIL A3")

    def test_is_incomplete_with_the_real_exit_code_when_the_acceptance_run_does_not_finish(self, mac):
        # wf-acceptance.sh dies before any check when it cannot write its report into $HOME.
        kit_folder_with_host_key(mac, mac["host_key"])
        mac["home"].chmod(0o500)
        try:
            done = finish(mac)
        finally:
            mac["home"].chmod(0o700)
        assert done.returncode == 2, done.stdout + done.stderr
        line = summary_lines(done.stdout, "INCOMPLETE  acceptance")[0]
        assert "exit code 1" in line and "exit code 0" not in line
        assert "RESULT: INCOMPLETE" in done.stdout

    def test_after_reboot_runs_a10_and_drops_the_restart_reminder(self, mac):
        kit_folder_with_host_key(mac, mac["host_key"])
        done = finish(mac, "--after-reboot")
        assert done.returncode == 0, done.stdout
        assert lines_with(done.stdout, "PASS A10")
        assert not summary_lines(done.stdout, "TODO  restart test")
        assert any("A1 to A8 and A10" in line for line in summary_lines(done.stdout, "PASS  acceptance"))

    def test_carries_acceptance_warnings_into_the_final_list(self, mac):
        kit_folder_with_host_key(mac, mac["host_key"])
        done = finish(mac, extra_env={"FAKE_DISPATCHER_SHA": "f" * 64})
        assert done.returncode == 0
        assert any("differs from this checkout" in line for line in summary_lines(done.stdout, "WARN  acceptance:"))


# ---------------------------------------------------------------------------------------------
# wf-pin-host-key.sh
# ---------------------------------------------------------------------------------------------

@pytest.mark.skipif(shutil.which("ssh-keygen") is None, reason="ssh-keygen is not installed")
class TestPinHostKey:
    def test_pins_when_the_fingerprint_matches(self, mac):
        mac["known_hosts"].unlink()
        done = run_script(mac, "wf-pin-host-key.sh", "--fingerprint", mac["fingerprint"])
        assert done.returncode == 0, done.stderr
        assert mac["known_hosts"].read_text() == f"gaming-pc ssh-ed25519 {mac['host_key']}\n"
        assert stat.S_IMODE(mac["known_hosts"].stat().st_mode) == 0o600

    def test_refuses_when_the_fingerprint_differs(self, mac):
        mac["known_hosts"].unlink()
        _, other = make_public_key(8)
        done = run_script(mac, "wf-pin-host-key.sh", "--fingerprint", other)
        assert done.returncode == 1
        assert "DIFFER" in done.stderr
        assert not mac["known_hosts"].exists()

    def test_is_idempotent(self, mac):
        done = run_script(mac, "wf-pin-host-key.sh", "--fingerprint", mac["fingerprint"])
        assert done.returncode == 0
        assert "Already pinned" in done.stdout

    def test_a_changed_host_key_is_a_hard_failure_unless_replaced_on_purpose(self, mac):
        old_key, _ = make_public_key(9)
        mac["known_hosts"].write_text(f"other-pc ssh-ed25519 {old_key}\ngaming-pc ssh-ed25519 {old_key}\n")
        done = run_script(mac, "wf-pin-host-key.sh", "--fingerprint", mac["fingerprint"])
        assert done.returncode == 1
        assert "DIFFERENT host key is already pinned" in done.stderr
        assert mac["host_key"] not in mac["known_hosts"].read_text()

        done = run_script(mac, "wf-pin-host-key.sh", "--fingerprint", mac["fingerprint"], "--replace")
        assert done.returncode == 0, done.stderr
        assert mac["known_hosts"].read_text() == f"other-pc ssh-ed25519 {old_key}\ngaming-pc ssh-ed25519 {mac['host_key']}\n"

    def test_refuses_without_a_fingerprint_when_there_is_no_terminal(self, mac):
        mac["known_hosts"].unlink()
        done = run_script(mac, "wf-pin-host-key.sh")
        assert done.returncode == 1
        assert not mac["known_hosts"].exists()

    def test_rejects_a_malformed_fingerprint_and_an_unreachable_pc(self, mac):
        assert run_script(mac, "wf-pin-host-key.sh", "--fingerprint", "SHA256:short").returncode == 1
        done = run_script(mac, "wf-pin-host-key.sh", "--fingerprint", mac["fingerprint"], mode="unreachable")
        assert done.returncode == 1
        assert "no SSH answer" in done.stderr

    def test_needs_the_host_block(self, mac):
        done = run_script(mac, "wf-pin-host-key.sh", "--fingerprint", mac["fingerprint"], mode="noconfig")
        assert done.returncode == 1
        assert "wf-mac-setup.sh" in done.stderr


# ---------------------------------------------------------------------------------------------
# wf-mac-setup.sh and wf-make-kit.sh (real ssh-keygen and real ssh -G, throwaway keys)
# ---------------------------------------------------------------------------------------------

REAL_SSH = shutil.which("ssh")
needs_openssh = pytest.mark.skipif(REAL_SSH is None or shutil.which("ssh-keygen") is None, reason="OpenSSH client tools are not installed")


def make_key(path: Path, passphrase: str) -> None:
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", passphrase, "-C", "someone@some-mac", "-f", str(path)], check=True)


@pytest.fixture()
def real_mac(tmp_path: Path) -> dict:
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    env = {
        "PATH": os.environ["PATH"],
        "HOME": str(home),
        "WF_SSH_CONFIG": str(home / ".ssh" / "config"),
        "WF_KEY_FILE": str(home / ".ssh" / "id_ed25519_winforensics"),
        "WF_KNOWN_HOSTS": str(home / ".ssh" / "known_hosts_winforensics"),
        "WF_SKIP_AGENT": "1",
        "TMPDIR": str(tmp_path),
    }
    return {"env": env, "home": home, "tmp": tmp_path}


def run_real(real_mac: dict, script: str, *args: str):
    return subprocess.run(["sh", str(MAC / script), *args], env=real_mac["env"], capture_output=True, text=True,
                          stdin=subprocess.DEVNULL, timeout=120)


@needs_openssh
def test_mac_setup_writes_a_host_block_that_ssh_resolves_as_intended(real_mac):
    make_key(Path(real_mac["env"]["WF_KEY_FILE"]), "a throwaway test passphrase")
    config = Path(real_mac["env"]["WF_SSH_CONFIG"])
    config.write_text("Host *\n    StrictHostKeyChecking no\n    ForwardAgent yes\n")
    done = run_real(real_mac, "wf-mac-setup.sh", "--pc-address", "192.0.2.20")
    assert done.returncode == 0, done.stdout + done.stderr

    resolved = subprocess.run([REAL_SSH, "-G", "-F", str(config), "gaming-pc"], capture_output=True, text=True, check=True).stdout
    options = dict(line.split(" ", 1) for line in resolved.splitlines() if " " in line)
    assert options["hostname"] == "192.0.2.20"
    assert options["user"] == "wfcollector"
    # The block is first in the file, so the looser "Host *" below it cannot win.
    assert options["stricthostkeychecking"] in ("yes", "true")
    assert options["forwardagent"] == "no"
    assert options["passwordauthentication"] == "no"
    assert options["identitiesonly"] == "yes"
    assert options["hostkeyalias"] == "gaming-pc"
    assert options["userknownhostsfile"] == real_mac["env"]["WF_KNOWN_HOSTS"]
    assert options["identityfile"] == real_mac["env"]["WF_KEY_FILE"]
    assert stat.S_IMODE(config.stat().st_mode) == 0o600
    assert (config.parent / "config.wf-backup").read_text().startswith("Host *")

    first = config.read_text()
    again = run_real(real_mac, "wf-mac-setup.sh", "--pc-address", "192.0.2.20")
    assert again.returncode == 0
    assert config.read_text() == first
    assert first.count("BEGIN win-forensics front door") == 1
    assert first.rstrip().endswith("ForwardAgent yes")


@needs_openssh
def test_mac_setup_refuses_a_key_without_a_passphrase(real_mac):
    make_key(Path(real_mac["env"]["WF_KEY_FILE"]), "")
    done = run_real(real_mac, "wf-mac-setup.sh", "--pc-address", "192.0.2.20")
    assert done.returncode == 1
    assert "has no passphrase" in done.stderr
    assert not Path(real_mac["env"]["WF_SSH_CONFIG"]).exists()


@needs_openssh
def test_mac_setup_validates_its_arguments(real_mac):
    assert run_real(real_mac, "wf-mac-setup.sh").returncode == 1
    assert run_real(real_mac, "wf-mac-setup.sh", "--pc-address", "gaming-pc.local").returncode == 1
    assert run_real(real_mac, "wf-mac-setup.sh", "--pc-address", "192.0.2.20", "--account", "Admin User").returncode == 1


@needs_openssh
@pytest.mark.skipif(shutil.which("zip") is None, reason="zip is not installed")
def test_make_kit_builds_one_zip_with_the_public_key_only(real_mac):
    key = Path(real_mac["env"]["WF_KEY_FILE"])
    make_key(key, "a throwaway test passphrase")
    out_zip = real_mac["tmp"] / "kit.zip"
    done = run_real(real_mac, "wf-make-kit.sh", "--mac-address", "192.0.2.10", "--out", str(out_zip))
    assert done.returncode == 0, done.stderr

    digest = hashlib.sha256(out_zip.read_bytes()).hexdigest().upper()
    grouped = " ".join(digest[i:i + 8] for i in range(0, 64, 8))
    assert grouped in done.stdout
    with zipfile.ZipFile(out_zip) as archive:
        names = set(archive.namelist())
        for name in WINDOWS_SCRIPTS:
            assert f"wf-frontdoor-kit/remote-access/windows/{name}" in names
            assert archive.read(f"wf-frontdoor-kit/remote-access/windows/{name}") == (WINDOWS / name).read_bytes()
        assert "wf-frontdoor-kit/CHECKLIST.md" in names
        public = archive.read("wf-frontdoor-kit/mac-public-key.pub").decode()
        run_at_pc = archive.read("wf-frontdoor-kit/RUN-AT-PC.txt").decode()
        everything = b"".join(archive.read(name) for name in names if not name.endswith("/"))
        collectors = sorted(name for name in names if name.startswith("wf-frontdoor-kit/collectors/windows/") and name.endswith(".ps1"))
    source_collectors = sorted(p.name for p in (REPO_ROOT / "collectors" / "windows").glob("*.ps1"))
    assert [Path(name).name for name in collectors] == source_collectors
    assert public.split()[:1] == ["ssh-ed25519"]
    assert public.split()[1] == key.with_suffix(".pub").read_text().split()[1]
    assert "someone@some-mac" not in public
    assert b"BEGIN OPENSSH PRIVATE KEY" not in everything
    assert "-MacIpAddress 192.0.2.10 -MacPublicKeyFile .\\mac-public-key.pub -AccountName wfcollector" in run_at_pc
    assert "powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\\remote-access\\windows\\Install-FrontDoor.ps1" in run_at_pc
    assert "step 5" not in run_at_pc and "L3" in run_at_pc and "Get-FileHash" in run_at_pc
    assert "Kit code" in done.stdout and "Full SHA-256" in done.stdout and "-eq '" in done.stdout


@needs_openssh
@pytest.mark.skipif(shutil.which("zip") is None, reason="zip is not installed")
def test_alternate_account_travels_from_the_mac_setup_into_the_kit(real_mac):
    key = Path(real_mac["env"]["WF_KEY_FILE"])
    make_key(key, "a throwaway test passphrase")
    config = Path(real_mac["env"]["WF_SSH_CONFIG"])
    assert run_real(real_mac, "wf-mac-setup.sh", "--pc-address", "192.0.2.20", "--account", "wfcollector2").returncode == 0
    resolved = subprocess.run([REAL_SSH, "-G", "-F", str(config), "gaming-pc"], capture_output=True, text=True, check=True).stdout
    assert "user wfcollector2\n" in resolved
    out_zip = real_mac["tmp"] / "kit.zip"
    done = run_real(real_mac, "wf-make-kit.sh", "--mac-address", "192.0.2.10", "--account", "wfcollector2", "--out", str(out_zip))
    assert done.returncode == 0, done.stderr
    with zipfile.ZipFile(out_zip) as archive:
        run_at_pc = archive.read("wf-frontdoor-kit/RUN-AT-PC.txt").decode()
    assert "-AccountName wfcollector2" in run_at_pc
    assert "account wfcollector2" in done.stdout
    assert run_real(real_mac, "wf-make-kit.sh", "--mac-address", "192.0.2.10", "--account", "Bad Name", "--out", str(out_zip)).returncode == 1


@needs_openssh
def test_make_kit_refuses_a_private_key_and_a_bad_address(real_mac):
    key = Path(real_mac["env"]["WF_KEY_FILE"])
    make_key(key, "a throwaway test passphrase")
    out_zip = real_mac["tmp"] / "kit.zip"
    done = run_real(real_mac, "wf-make-kit.sh", "--mac-address", "192.0.2.10", "--public-key", str(key), "--out", str(out_zip))
    assert done.returncode == 1
    assert "PRIVATE key" in done.stderr
    assert not out_zip.exists()
    assert run_real(real_mac, "wf-make-kit.sh", "--mac-address", "a4:83:e7:12:34:56", "--out", str(out_zip)).returncode == 1
    assert run_real(real_mac, "wf-make-kit.sh", "--mac-address", "999.999.999.999", "--out", str(out_zip)).returncode == 1
    assert run_real(real_mac, "wf-make-kit.sh", "--out", str(out_zip)).returncode == 1
    assert not out_zip.exists()


@needs_openssh
@pytest.mark.skipif(shutil.which("zip") is None, reason="zip is not installed")
def test_start_does_the_whole_mac_side_and_prints_the_kit_code(real_mac):
    key = Path(real_mac["env"]["WF_KEY_FILE"])
    make_key(key, "a throwaway test passphrase")
    kit = real_mac["tmp"] / "stick" / "wf-frontdoor"
    kit.mkdir(parents=True)
    (kit / "pc-host-key.pub").write_text("stale line from an earlier trip\n")
    done = run_real(real_mac, "wf-start.sh", "--pc-address", "192.0.2.20", "--mac-address", "192.0.2.10", "--kit", str(kit))
    assert done.returncode == 0, done.stdout + done.stderr

    # The ssh side was done by wf-mac-setup.sh.
    config = Path(real_mac["env"]["WF_SSH_CONFIG"]).read_text()
    assert "Host gaming-pc" in config and "HostName 192.0.2.20" in config
    # The kit folder holds the launcher pair, the zip, and the read me, and nothing stale.
    assert sorted(p.name for p in kit.iterdir()) == ["READ-ME-FIRST.txt", "SETUP-PC.cmd", "Start-FrontDoorSetup.ps1", "wf-frontdoor-kit.zip"]
    for name in LAUNCHER_FILES:
        assert (kit / name).read_bytes() == (WINDOWS / name).read_bytes()
    with zipfile.ZipFile(kit / "wf-frontdoor-kit.zip") as archive:
        parameters = archive.read("wf-frontdoor-kit/kit-parameters.txt").decode()
        everything = b"".join(archive.read(name) for name in archive.namelist() if not name.endswith("/"))
    assert "mac_address=192.0.2.10\n" in parameters and "account=wfcollector\n" in parameters
    private = key.read_bytes()
    assert b"BEGIN OPENSSH PRIVATE KEY" in private
    assert b"BEGIN OPENSSH PRIVATE KEY" not in everything
    for path in kit.iterdir():
        assert b"BEGIN OPENSSH PRIVATE KEY" not in path.read_bytes(), path.name
    # The code and the full digest printed are the ones Windows will compute from the zip, and
    # neither is written into anything that travels with the kit: a value shipped next to the
    # file it checks would prove nothing.
    digest = hashlib.sha256((kit / "wf-frontdoor-kit.zip").read_bytes()).hexdigest()
    assert kit_code(digest) in done.stdout
    assert full_digest(digest) in done.stdout
    assert f"-eq '{digest.upper()}'" in done.stdout, "the exact Get-FileHash comparison to type at the PC"
    code_forms = {kit_code(digest), kit_code(digest).replace(" ", ""), digest, digest.upper(), full_digest(digest)}
    for path in kit.iterdir():
        text = path.read_text(errors="replace")
        for form in code_forms:
            assert form not in text, f"{path.name} carries {form}"
    with zipfile.ZipFile(kit / "wf-frontdoor-kit.zip") as archive:
        for name in archive.namelist():
            if name.endswith("/"):
                continue
            member = archive.read(name).decode(errors="replace")
            for form in code_forms:
                assert form not in member, f"{name} carries {form}"
    assert "SETUP-PC.cmd" in done.stdout and "wf-finish.sh" in done.stdout
    assert "WAY A" in done.stdout and "WAY B" in done.stdout and "Get-FileHash" in done.stdout
    assert "Removed" in done.stdout and "pc-host-key.pub" in done.stdout
    readme = (kit / "READ-ME-FIRST.txt").read_bytes()
    assert b"SETUP-PC.cmd" in readme and b"wf-finish.sh" in readme and b"\r\n" in readme
    assert b"Get-FileHash" in readme and b"removable drive" in readme

    # Running it again reuses the key and rebuilds the kit.
    again = run_real(real_mac, "wf-start.sh", "--pc-address", "192.0.2.20", "--mac-address", "192.0.2.10", "--kit", str(kit))
    assert again.returncode == 0, again.stdout + again.stderr
    assert "Key already exists" in again.stdout


@needs_openssh
def test_start_validates_its_addresses_before_touching_anything(real_mac):
    make_key(Path(real_mac["env"]["WF_KEY_FILE"]), "a throwaway test passphrase")
    kit = real_mac["tmp"] / "wf-frontdoor"
    assert run_real(real_mac, "wf-start.sh", "--kit", str(kit)).returncode == 1
    assert run_real(real_mac, "wf-start.sh", "--pc-address", "gaming-pc.local", "--kit", str(kit)).returncode == 1
    done = run_real(real_mac, "wf-start.sh", "--pc-address", "192.0.2.20", "--mac-address", "192.0.2.20", "--kit", str(kit))
    assert done.returncode == 1 and "the same" in done.stderr
    assert run_real(real_mac, "wf-start.sh", "--pc-address", "192.0.2.20", "--mac-address", "a4:83:e7:12:34:56", "--kit", str(kit)).returncode == 1
    assert run_real(real_mac, "wf-start.sh", "--pc-address", "999.999.999.999", "--mac-address", "192.0.2.10", "--kit", str(kit)).returncode == 1
    assert run_real(real_mac, "wf-start.sh", "--pc-address", "192.0.2.20", "--mac-address", "192.0.2.256", "--kit", str(kit)).returncode == 1
    assert not Path(real_mac["env"]["WF_SSH_CONFIG"]).exists()
    assert not kit.exists()


# ---------------------------------------------------------------------------------------------
# PowerShell: the Pester suite, the analyzer, and the Mac scripts against the real dispatcher
# ---------------------------------------------------------------------------------------------

@needs_pwsh
def test_pester_suite_and_script_analyzer():
    command = [PWSH, "-NoLogo", "-NoProfile", "-File", str(REMOTE / "tests" / "Invoke-Tests.ps1")]
    if module_path():
        command += ["-ModulePath", module_path()]
    done = subprocess.run(command, capture_output=True, text=True, timeout=900)
    output = done.stdout + done.stderr
    if "Import-Module" in output and ("Pester" in output or "PSScriptAnalyzer" in output) and "PESTER passed" not in output:
        pytest.skip("Pester 5.5 or later and PSScriptAnalyzer are not installed for this PowerShell; see remote-access/README.md, Tests")
    assert done.returncode == 0, output[-4000:]
    assert "ANALYZER findings: 0" in output
    assert re.search(r"PESTER passed: [1-9]\d* failed: 0", output)


@pytest.fixture()
def real_dispatcher(mac) -> dict:
    """The installed layout in a temporary directory, with the stand-in ssh running dispatch.ps1."""
    root = mac["tmp"] / "pc" / "win-forensics"
    remote = root / "remote"
    (remote / "collectors").mkdir(parents=True)
    (root / "outbox").mkdir()
    for name in ["dispatch.ps1", "WfCommon.ps1"]:
        shutil.copy(WINDOWS / name, remote / name)
    (remote / "collectors" / "sample-ok.ps1").write_text(textwrap.dedent('''\
        param([Parameter(Mandatory = $true)][string]$OutputDirectory)
        [void](New-Item -ItemType Directory -Path (Join-Path $OutputDirectory 'raw'))
        [System.IO.File]::WriteAllText((Join-Path $OutputDirectory 'manifest.json'), '{"manifest_version":"1.0.0"}')
        [System.IO.File]::WriteAllBytes((Join-Path (Join-Path $OutputDirectory 'raw') 'blob.bin'), [byte[]](0..255) * 700)
        [Console]::Out.WriteLine('{"collector":"sample-ok","status":"ok","bundle":"x","artifacts":2}')
        '''))
    mac["env"].update({"FAKE_SSH_DISPATCHER": str(remote / "dispatch.ps1"), "FAKE_SSH_PWSH": PWSH})
    mac["outbox"] = root / "outbox"
    return mac


@needs_pwsh
def test_acceptance_against_the_real_dispatcher(real_dispatcher):
    done, _ = acceptance(real_dispatcher)
    assert done.returncode == 0, done.stdout + done.stderr
    assert not lines_with(done.stdout, "FAIL")
    assert any("byte for byte" in line for line in lines_with(done.stdout, "PASS A2"))
    assert len(lines_with(done.stdout, "PASS A3")) == 10
    assert any("forced terminal request" in line for line in lines_with(done.stdout, "PASS A3"))
    assert lines_with(done.stdout, "PASS A6")
    assert "collectors installed on the PC: \"sample-ok\"" in done.stdout
    assert not list(real_dispatcher["outbox"].iterdir()), "the acceptance checks must not create bundles"


@needs_pwsh
def test_collect_then_fetch_end_to_end_through_the_real_dispatcher(real_dispatcher):
    env = dict(real_dispatcher["env"], FAKE_SSH_MODE="healthy")
    collect = subprocess.run(["ssh", "-n", "-T", "gaming-pc", "collect-sample-ok"], env=env, capture_output=True, text=True, timeout=120)
    assert collect.returncode == 0, collect.stderr
    summary = json.loads(collect.stdout.strip().splitlines()[-1])
    assert summary["ok"] is True and summary["summary"]["status"] == "ok" and summary["files"] == 2
    bundle_dir = summary["bundle_dir"]

    out_dir = real_dispatcher["tmp"] / "bundles"
    done = run_script(real_dispatcher, "wf-fetch.sh", bundle_dir, "--out", str(out_dir), "--extract")
    assert done.returncode == 0, done.stdout + done.stderr
    source = real_dispatcher["outbox"] / bundle_dir
    for relative in ["manifest.json", "raw/blob.bin"]:
        assert (out_dir / bundle_dir / relative).read_bytes() == (source / relative).read_bytes()
    # The checksum the Mac verified is the one the dispatcher computed over the same bytes.
    header_sha = re.search(r"SHA-256 ([0-9a-f]{64})", done.stdout).group(1)
    assert hashlib.sha256((out_dir / f"{bundle_dir}.zip").read_bytes()).hexdigest() == header_sha

    done, _ = acceptance(real_dispatcher, "--fetch-newest")
    assert done.returncode == 0, done.stdout
    assert any(bundle_dir in line for line in lines_with(done.stdout, "PASS A8"))
