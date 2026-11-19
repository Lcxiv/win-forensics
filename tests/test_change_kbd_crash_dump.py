"""The change area and the kbd-crash-dump change script: isolation, posture, and the PowerShell suite.

Change scripts are the only code here that writes to a Windows machine, so these checks keep them
apart from everything the dispatcher, the scenario runner and the collectors can run, and pin what
the one script may touch. The Pester suite and the off Windows process run need ``pwsh`` and skip
without it (``scripts/fetch_pwsh.sh``, or ``WF_PWSH`` and ``WF_PSMODULES``).
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import REPO_ROOT

CHANGES = REPO_ROOT / "changes"
CHANGE_DIR = CHANGES / "windows"
SCRIPT = CHANGE_DIR / "kbd-crash-dump.ps1"
TESTS_DIR = CHANGE_DIR / "tests"
DOC = REPO_ROOT / "docs" / "kbd-crash-dump.md"
LEARN_KBD = "https://learn.microsoft.com/windows-hardware/drivers/debugger/forcing-a-system-crash-from-the-keyboard"

# A reference to the change area from code or prose: the directory in either separator, or a
# change script by name. Plain words such as "changes the machine" do not match.
CHANGE_REFERENCE = re.compile(r"changes[/\\]|kbd-crash-dump", re.IGNORECASE)
# The scenario runner lives in collectors/windows (the leading underscore keeps it out of the
# dispatcher's verbs); it is named here so the rule still holds if it moves.
RUNNER_NAMES = ("_run-scenario.ps1", "_scenarios.ps1")

# Commands no change script may use: prompts, restarts, services, scheduled tasks, downloads,
# installs, policy changes, text run as code, and interop beyond the .NET registry classes.
FORBIDDEN = [
    "Read-Host", "Get-Credential", "PromptForChoice", "ShouldContinue", "Restart-Computer", "Stop-Computer",
    "shutdown", "New-Service", "Set-Service", "Start-Service", "Stop-Service", "Restart-Service", "sc.exe",
    "Register-ScheduledTask", "schtasks", "Invoke-WebRequest", "Invoke-RestMethod", "Net.WebClient",
    "Start-BitsTransfer", "Install-", "Uninstall-", "Set-ExecutionPolicy", "Invoke-Expression", "Invoke-Command",
    "EncodedCommand", "Add-Type", "DllImport", "Start-Process", "ProcessStartInfo", "Set-ItemProperty",
    "New-ItemProperty", "Remove-ItemProperty", "Remove-Item", "DeleteSubKeyTree", "hyperkbd", "ConvertTo-Json",
    "Write-Host", "$global:",
]


def code_of(path: Path) -> str:
    """The script without comment lines."""
    return "\n".join(line for line in path.read_text(encoding="ascii").splitlines() if not line.lstrip().startswith("#"))


def scanned_files() -> list[Path]:
    roots = [REPO_ROOT / "collectors", REPO_ROOT / "remote-access"]
    files = [p for root in roots for p in root.rglob("*") if p.is_file() and "__pycache__" not in p.parts]
    files += [p for p in REPO_ROOT.rglob("*") if p.name in RUNNER_NAMES and p.is_file()]
    return sorted(set(files))


def test_collectors_runner_and_front_door_never_reference_the_change_area():
    offenders = []
    for path in scanned_files():
        text = path.read_bytes().decode("utf-8", errors="replace")
        for number, line in enumerate(text.splitlines(), start=1):
            if CHANGE_REFERENCE.search(line):
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{number}")
    assert not offenders, offenders


def test_the_change_area_holds_only_change_scripts_and_their_tests():
    assert sorted(p.name for p in CHANGE_DIR.iterdir() if p.is_file()) == ["README.md", "kbd-crash-dump.ps1"]
    assert sorted(p.name for p in CHANGES.iterdir()) == ["windows"]
    # The front door installs collectors/windows/*.ps1; nothing under it may be a change script.
    assert not [p for p in (REPO_ROOT / "collectors").rglob("*.ps1") if "changes" in p.parts]


@pytest.mark.parametrize("path", sorted(CHANGE_DIR.rglob("*.ps1")) + sorted(CHANGE_DIR.rglob("*.psd1")), ids=lambda p: p.name)
def test_change_scripts_are_plain_ascii(path):
    data = path.read_bytes()
    assert not data.startswith(b"\xef\xbb\xbf")
    offenders = [i for i, b in enumerate(data) if b > 126 or (b < 32 and b not in (9, 10))]
    assert not offenders, f"{path.name}: byte offsets {offenders[:5]}"


def test_the_script_holds_no_forbidden_command():
    code = code_of(SCRIPT).lower()
    assert [token for token in FORBIDDEN if token.lower() in code] == []


def test_the_only_process_is_reg_export_from_the_system_directory():
    code = code_of(SCRIPT)
    calls = [line.strip() for line in code.splitlines() if re.search(r"(^|[=;(])\s*&\s*\$", line.strip())]
    assert calls == ["$null = & $reg 'export' $Key $File '/y' 2>$null"]
    assert "$reg = Join-Path -Path ([Environment]::GetFolderPath('System')) -ChildPath 'reg.exe'" in code
    assert "cmd.exe" not in code.lower() and "powershell.exe" not in code.lower()


def test_the_script_names_only_the_documented_keys_and_values():
    code = code_of(SCRIPT)
    assert "function Get-KcdKeyboardServices { return @('kbdhid', 'i8042prt') }" in code
    assert "function Get-KcdServicesPath { return 'SYSTEM\\CurrentControlSet\\Services' }" in code
    assert "function Get-KcdCrashControlPath { return 'SYSTEM\\CurrentControlSet\\Control\\CrashControl' }" in code
    assert set(re.findall(r"-Role 'change' -Path \$(\w+) -Name '(\w+)'", code)) == {
        ("parameters", "CrashOnCtrlScroll"), ("crashdump", "Dump1Keys"), ("crashdump", "Dump2Key")}
    assert "$parameters = (Get-KcdServicesPath) + '\\' + $service + '\\Parameters'" in code
    assert "$crashdump = (Get-KcdServicesPath) + '\\' + $service + '\\crashdump'" in code
    # Microsoft's example second key, 0x3d, and its six documented first keys.
    assert "function Get-KcdAlternateDump2Key { return 61 }" in code
    assert sorted(int(bit, 16) for bit in re.findall(r"@\{ Bit = (0x[0-9a-f]{2});", code)) == [0x01, 0x02, 0x04, 0x10, 0x20, 0x40]
    # Every write goes through the two write adapters, and only the verbs call them.
    for adapter in ("Set-KcdRegistryDword", "Remove-KcdRegistryValue", "Remove-KcdRegistryKey"):
        callers = [line for line in code.splitlines() if adapter in line and not line.lstrip().startswith("function ")]
        assert callers, adapter
    bodies = re.split(r"^function ", code, flags=re.MULTILINE)
    writers = {body.split(" ", 1)[0] for body in bodies if re.search(r"^\s+(Set-KcdRegistryDword|Remove-KcdRegistryValue|Remove-KcdRegistryKey) -Path", body, re.MULTILINE)}
    assert writers == {"Invoke-KcdApply", "Invoke-KcdUndo"}


def test_the_real_adapters_sit_in_one_guarded_block():
    code = code_of(SCRIPT)
    guard = "if (-not (Get-Command -Name 'Get-KcdRegistryKey' -CommandType Function -ErrorAction SilentlyContinue)) {"
    assert code.count(guard) == 1
    before, after = code.split(guard)
    for name in ("Microsoft.Win32", "Get-CimInstance", "WindowsIdentity", "GetFolderPath", "[Console]"):
        assert name not in before, name
    synthetic = (TESTS_DIR / "KbdCrashDump.Synthetic.ps1").read_text(encoding="ascii")
    adapters = re.findall(r"^    function ([A-Za-z-]+) \{", after, re.MULTILINE)
    replaced = set(re.findall(r"^function ([A-Za-z-]+) \{", synthetic, re.MULTILINE))
    # Every adapter the portable code calls is replaced by the synthetic backend.
    internal = {"Open-KcdBaseKey", "Open-KcdParentForWrite"}
    assert set(adapters) - internal <= replaced, set(adapters) - internal - replaced


def test_the_operator_page_covers_the_brief():
    text = DOC.read_text(encoding="utf-8")
    for needle in ("Hold down the right CTRL key, and press SCROLL LOCK twice", "MANUALLY_INITIATED_CRASH", "Dump1Keys",
                   "Dump2Key", "-AlternateKeys", "## What you should see", "## After the reboot", "## What it cannot do",
                   "high interrupt request level", "Whether a GPU hang freeze responds is unverified",
                   "crashes the PC on purpose", "## Follow-up: a deliberate test crash", "take effect", LEARN_KBD,
                   "BugcheckCode` 226"):
        assert needle in text, needle
    readme = (CHANGE_DIR / "README.md").read_text(encoding="utf-8")
    assert "## Facts to verify on the PC" in readme
    assert re.findall(r"^\| (K\d+) \|", readme, re.MULTILINE) == [f"K{i}" for i in range(1, 12)]


# ---------------------------------------------------------------------------
# PowerShell
# ---------------------------------------------------------------------------

def find_pwsh() -> str | None:
    candidates = [os.environ.get("WF_PWSH"), str(REPO_ROOT / "tools" / "pwsh" / "pwsh"), shutil.which("pwsh")]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return candidate
    return None


PWSH = find_pwsh()
MODULES = os.environ.get("WF_PSMODULES") or str(REPO_ROOT / "tools" / "psmodules")
needs_pwsh = pytest.mark.skipif(PWSH is None, reason="no pwsh; run scripts/fetch_pwsh.sh or set WF_PWSH")


def run(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    env = dict(os.environ, NO_COLOR="1")
    return subprocess.run([PWSH, "-NoProfile", "-NonInteractive", *args], cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                          capture_output=True, text=True, timeout=900)


@needs_pwsh
def test_script_analyzer_and_pester_suite_pass():
    args = ["-File", str(TESTS_DIR / "Invoke-Checks.ps1")]
    if Path(MODULES).is_dir():
        args += ["-ModulePath", MODULES]
    result = run(args)
    if result.returncode == 3:
        pytest.skip("Pester 5 or PSScriptAnalyzer is not installed; run scripts/fetch_pwsh.sh")
    assert result.returncode == 0, result.stdout[-6000:] + result.stderr[-3000:]
    assert "PSScriptAnalyzer: 0 findings" in result.stderr
    assert "Failed: 0" in result.stdout


@needs_pwsh
@pytest.mark.skipif(sys.platform == "win32", reason="on Windows the real adapters would read the machine")
@pytest.mark.parametrize("verb", ["-Plan", "-Apply", "-Undo", "-Readback"])
def test_real_adapters_fail_closed_off_windows(verb, tmp_path):
    """The unmodified script as a process where no Windows API exists: every read fails, and it must refuse."""
    root = tmp_path / "evidence root"
    result = run(["-File", str(SCRIPT), verb, "-EvidenceRoot", str(root)])
    assert result.returncode == 1, result.stdout + result.stderr
    assert result.stderr == ""
    if verb in ("-Plan", "-Apply"):
        assert "FAIL" in result.stdout and "REFUSED" in result.stdout
    if verb == "-Undo":
        assert "REFUSED: no apply folder" in result.stdout
    if verb == "-Readback":
        assert "RESULT: FAIL" in result.stdout
    assert not root.exists(), "nothing may be saved when the preconditions fail"
    assert list(tmp_path.iterdir()) == []
