"""Static checks on the collector scripts that need no PowerShell: the seam, read only posture, citations."""
from __future__ import annotations

import re

import pytest

from conftest import REPO_ROOT

COLLECTOR_DIR = REPO_ROOT / "collectors" / "windows"
COLLECTOR_NAME = re.compile(r"^[a-z][a-z0-9-]{1,40}$")
HELPER = "_common.ps1"
SHIPPED = sorted(COLLECTOR_DIR.glob("*.ps1"))
COLLECTORS = [p for p in SHIPPED if p.name != HELPER]
EXPECTED_COLLECTORS = ["application-errors", "bugcheck-history", "config-snapshot", "driver-inventory", "reliability-records", "rf-survey", "tdr-events", "whea-errors"]

# Commands that change the machine, reach the network, prompt, handle credentials, or run text
# as code. A read only collector has no use for any of them.
FORBIDDEN = [
    "Clear-EventLog", "Remove-EventLog", "Limit-EventLog", "New-EventLog", "Write-EventLog", "clear-log", "wevtutil cl",
    " sl ", "set-log", "Set-ItemProperty", "New-ItemProperty", "Remove-ItemProperty", "Set-Service", "Start-Service",
    "Stop-Service", "Restart-Service", "Stop-Process", "Start-Process", "Restart-Computer", "Stop-Computer",
    "Register-ScheduledTask", "schtasks", "Invoke-WebRequest", "Invoke-RestMethod", "Net.WebClient", "Start-BitsTransfer",
    "Invoke-Expression", "Invoke-Command", "EncodedCommand", "Add-Type", "DllImport", "Read-Host", "Get-Credential",
    "ConvertTo-SecureString", "Set-ExecutionPolicy", "Enable-", "Disable-", "Install-", "Uninstall-", "Set-Content",
    "Out-File", "Add-Content", "Remove-CimInstance", "Set-CimInstance", "Invoke-CimMethod", "Invoke-WmiMethod",
]


# The two native boundaries the helper may declare, each a literal Add-Type block in one named function. The static guard
# below pins the exact imports (library and entry point), the search path attribute, the access masks and the flags, and
# fails on anything added, widened or interpolated. Everything else in the helper stays under the ban.
NATIVE_BLOCKS = {
    "New-WfDeviceKeyNative": {
        ("setupapi.dll", "SetupDiCreateDeviceInfoList"), ("setupapi.dll", "SetupDiOpenDeviceInfoW"), ("setupapi.dll", "SetupDiOpenDevRegKey"),
        ("setupapi.dll", "SetupDiDestroyDeviceInfoList"), ("advapi32.dll", "RegOpenKeyExW"), ("advapi32.dll", "RegEnumValueW"),
        ("advapi32.dll", "RegQueryValueExW"), ("advapi32.dll", "RegCloseKey"),
    },
    "Get-WfLogicalProcessorInformation": {("kernel32.dll", "GetLogicalProcessorInformationEx")},
}
# Native names that must never appear anywhere in the helper, inside or outside the two blocks: setters, creators, device
# state changes, process and timer calls, dynamic loading.
NATIVE_FORBIDDEN = ["RegSetValue", "RegCreateKey", "RegDeleteKey", "RegDeleteValue", "RegSaveKey", "RegRestoreKey", "RegLoadKey",
                    "SetupDiCallClassInstaller", "SetupDiSetClassInstallParams", "SetupDiRemoveDevice", "SetupDiCreateDeviceInfo(", "SetupDiChangeState",
                    "SetupDiInstallDevice", "CM_Set_", "CM_Disable", "CM_Enable", "CM_Uninstall", "OpenProcess", "CreateProcess", "TerminateProcess",
                    "NtSetTimerResolution", "timeBeginPeriod", "SetThreadAffinityMask", "SetProcessAffinityMask", "KEY_WRITE", "KEY_ALL_ACCESS",
                    "KEY_SET_VALUE", "0xF003F", "0x20006", "DIOD_CANCEL_REMOVE", "Reflection.Emit", "GetProcAddress", "LoadLibrary", "DynamicMethod"]
DLL_IMPORT = re.compile(r'\[DllImport\("([a-z0-9]+\.dll)"[^\]]*\)\]\s*public static extern [A-Za-z\.]+ ([A-Za-z0-9_]+)\(')


def function_bodies(code: str) -> dict[str, str]:
    """Each top level helper function's text, from its header to the next header."""
    bodies: dict[str, str] = {}
    headers = [(m.start(), m.group(1)) for m in re.finditer(r"^function ([A-Za-z\-]+) \{", code, re.MULTILINE)]
    for (start, name), (end, _) in zip(headers, headers[1:] + [(len(code), "")]):
        bodies[name] = code[start:end]
    return bodies


def native_boundary_errors(code: str) -> list[str]:
    """Why the helper's native boundary is not the audited one; empty when it is."""
    errors: list[str] = []
    bodies = function_bodies(code)
    for token in NATIVE_FORBIDDEN:
        if token in code:
            errors.append(f"forbidden native name {token}")
    for name, body in bodies.items():
        if name in NATIVE_BLOCKS:
            continue
        for token in ("Add-Type", "DllImport", "extern "):
            if token in body:
                errors.append(f"{token.strip()} outside the audited blocks, in {name}")
    for name, expected in NATIVE_BLOCKS.items():
        body = bodies.get(name)
        if body is None:
            errors.append(f"{name} is missing")
            continue
        if body.count("Add-Type") != 1:
            errors.append(f"{name} must call Add-Type exactly once")
        if "-MemberDefinition $declaration" not in body or "-Path" in body or "-TypeDefinition" in body or "-OutputAssembly" in body or "-CompilerOptions" in body or "-ReferencedAssemblies" in body:
            errors.append(f"{name} must compile only the literal $declaration member definition")
        literal = re.search(r"\$declaration = (@'|')", body)
        if not literal:
            errors.append(f"{name} must assign $declaration from a single quoted literal")
        else:
            start = literal.end()
            end = body.find("'@" if literal.group(1) == "@'" else "'", start)
            text = body[start:end]
            if "$" in text or "`" in text:
                errors.append(f"{name}: the declaration literal must not interpolate")
            imports = {(dll, entry) for dll, entry in DLL_IMPORT.findall(text)}
            if imports != expected:
                errors.append(f"{name}: imports {sorted(imports)} differ from the audited {sorted(expected)}")
            if text.count("[DllImport(") != len(expected) or text.count("extern ") != len(expected):
                errors.append(f"{name}: the declaration holds a declaration that is not one of the audited imports")
            if text.count("[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]") != len(expected):
                errors.append(f"{name}: every import must bind to the system directory")
    device = bodies.get("Get-WfDeviceInterruptPolicy", "")
    constants = bodies.get("Get-WfDeviceKeyConstants", "")
    if "KEY_READ                 = [uint32]0x20019" not in constants or "DICS_FLAG_GLOBAL         = [uint32]1" not in constants or "DIREG_DEV                = [uint32]1" not in constants:
        errors.append("the device key constants are not DICS_FLAG_GLOBAL 1, DIREG_DEV 1, KEY_READ 0x20019")
    if "$api.SetupDiOpenDevRegKey($set, [ref]$data, $c['DICS_FLAG_GLOBAL'], [uint32]0, $c['DIREG_DEV'], $c['KEY_READ'])" not in device:
        errors.append("SetupDiOpenDevRegKey is not called with global scope, profile 0, DIREG_DEV and KEY_READ")
    if "$api.SetupDiOpenDeviceInfoW($set, $InstanceId, [IntPtr]::Zero, [uint32]0, [ref]$data)" not in device:
        errors.append("SetupDiOpenDeviceInfoW is not called with OpenFlags 0")
    if re.search(r"RegOpenKeyExW\([^)]*\$c\['KEY_READ'\]", device) is None or re.search(r"RegOpenKeyExW\((?![^)]*\$c\['KEY_READ'\])", device):
        errors.append("every RegOpenKeyExW must ask for KEY_READ")
    subkeys = bodies.get("Get-WfInterruptManagementSubkeys", "")
    if "return @('Interrupt Management\\Affinity Policy', 'Interrupt Management\\MessageSignaledInterruptProperties')" not in subkeys:
        errors.append("the relative subkeys are not the two documented ones")
    if "'Interrupt Management'" not in device or "HKLM" in device or "CurrentControlSet" in device or "Enum" in device.replace("enumerat", ""):
        errors.append("the device sequencing names a physical registry path")
    return errors


def test_the_collector_set_is_the_documented_one():
    assert [p.stem for p in COLLECTORS] == EXPECTED_COLLECTORS


def test_names_follow_the_seam_and_the_helper_cannot_be_dispatched():
    for path in COLLECTORS:
        assert COLLECTOR_NAME.match(path.stem), path.name
    assert (COLLECTOR_DIR / HELPER).is_file()
    assert not COLLECTOR_NAME.match(HELPER.removesuffix(".ps1")), "the dispatcher must never map a verb to the helper"
    assert [p.name for p in COLLECTOR_DIR.iterdir() if p.is_file() and p.suffix != ".ps1"] == ["README.md"], \
        "the setup script installs *.ps1 from this directory; everything a collector needs at run time is a .ps1 file here"


@pytest.mark.parametrize("path", sorted(COLLECTOR_DIR.rglob("*.ps1")), ids=lambda p: p.name)
def test_scripts_are_plain_ascii(path):
    # Windows PowerShell 5.1 reads a script without a byte order mark in the ANSI code page, so a
    # non ASCII character would be read differently on the PC than here.
    data = path.read_bytes()
    assert not data.startswith(b"\xef\xbb\xbf")
    offenders = [i for i, b in enumerate(data) if b > 126 or (b < 32 and b not in (9, 10))]
    assert not offenders, f"{path.name}: byte offsets {offenders[:5]}"


@pytest.mark.parametrize("path", SHIPPED, ids=lambda p: p.name)
def test_shipped_scripts_are_read_only(path):
    text = path.read_text(encoding="ascii")
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    scanned = code
    if path.name == HELPER:
        # The two audited native blocks are the only place Add-Type and DllImport may appear; the boundary test pins them.
        for name in NATIVE_BLOCKS:
            body = function_bodies(code)[name]
            scanned = scanned.replace(body, "")
    for token in FORBIDDEN:
        assert token.lower() not in scanned.lower(), f"{path.name} uses {token.strip()}"
    # The only deletions are of the collector's own exports inside the output directory: a failed or
    # over-cap .evtx, and a primary export that must not be left behind ($Path is the primary passed to
    # Remove-WfPrimaryUnlessKept; the others are the primaries of the event, WMI, netsh, file, device,
    # registry and directory sources).
    removals = [line.strip() for line in code.splitlines() if "Remove-Item" in line]
    own = ("-LiteralPath $evtxPath", "-LiteralPath $recordsPath", "-LiteralPath $eventsPath", "-LiteralPath $outputPath",
           "-LiteralPath $primaryPath", "-LiteralPath $devicesPath", "-LiteralPath $keysPath", "-LiteralPath $listingPath",
           "-LiteralPath $topologyPath", "-LiteralPath $Path -Force")
    assert all(any(marker in r for marker in own) for r in removals), removals
    # The only process started is wevtutil, with the export verb and nothing else; the netsh and powercfg
    # listings the collectors run are checked on what the runs record (test_collector_bundles and the Pester suite).
    if path.name == HELPER:
        assert code.count("System.Diagnostics.ProcessStartInfo") == 1
        assert "'epl \"{0}\" \"{1}\" /sq:true /ow:true'" in code
    else:
        assert "ProcessStartInfo" not in code


def test_helper_writes_json_without_convertto_json():
    # ConvertTo-Json has a default depth of 2, and in Windows PowerShell it writes a psobject
    # wrapped array as an object with value and Count members (PowerShell/PowerShell issues 3153
    # and 5579). Neither can be tested off Windows, so the helper has its own writer and must
    # not fall back to the cmdlet.
    text = (COLLECTOR_DIR / HELPER).read_text(encoding="ascii")
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    assert "ConvertTo-Json" not in code and "ConvertFrom-Json" not in code
    assert "$script:" not in code and "$global:" not in code


def test_readme_covers_every_collector_and_the_elevated_list():
    readme = (COLLECTOR_DIR / "README.md").read_text(encoding="utf-8")
    for path in COLLECTORS:
        assert f"`{path.stem}`" in readme, path.stem
    for heading in ("## Interface", "## Collectors", "## Needs elevation", "## Facts to verify on the PC", "## Testing"):
        assert heading in readme, heading
    for term in ("Minidump", "MEMORY.DMP", "Security", "Get-StorageReliabilityCounter", "chkdsk", "sfc", "wlanreport"):
        assert term in readme, term


def test_rf_survey_sources_are_documented_with_their_privacy_rule():
    """Every rf-survey source id appears in the README, as does the pseudonym rule and the method document."""
    readme = (COLLECTOR_DIR / "README.md").read_text(encoding="utf-8")
    script = (COLLECTOR_DIR / "rf-survey.ps1").read_text(encoding="ascii")
    ids = re.findall(r"Id\s*=\s*'([a-z_]+)'", script)
    assert len(ids) == 10 and len(set(ids)) == 10
    for source_id in ids:
        assert f"`{source_id}`" in readme, source_id
    for term in ("ssid-", "mac-", "docs/rf-survey.md", "location", "Get-PnpDeviceProperty", "MSFT_NetAdapter"):
        assert term in readme, term


def test_config_snapshot_sources_are_documented_and_read_only():
    """Every config-snapshot source id appears in the README; the registry is only ever opened for reading and the powercfg verbs are listings."""
    readme = (COLLECTOR_DIR / "README.md").read_text(encoding="utf-8")
    script = (COLLECTOR_DIR / "config-snapshot.ps1").read_text(encoding="ascii")
    ids = re.findall(r"Id\s*=\s*'([a-z_]+)'", script)
    assert len(ids) == 19 and len(set(ids)) == 19
    for source_id in ids:
        assert f"`{source_id}`" in readme, source_id
    for verb in re.findall(r"Arguments\s*=\s*'(/[a-z]+)'", script):
        assert verb in ("/list", "/getactivescheme", "/aliases", "/query", "/qh"), verb
    helper = (COLLECTOR_DIR / HELPER).read_text(encoding="ascii")
    code = "\n".join(line for line in helper.splitlines() if not line.lstrip().startswith("#"))
    for token in ("SetValue(", "CreateSubKey", "DeleteSubKey", "DeleteValue", "New-Item -Path HK", "New-Item -LiteralPath HK", "Registry::"):
        assert token not in code, token
    for term in ("Interrupt Management", "MessageSignaledInterruptProperties", "GraphicsDrivers", "Win32_Processor", "Win32_CacheMemory",
                 "Win32_Process", "SetupDiOpenDevRegKey", "GetLogicalProcessorInformationEx", "powercfg /energy", "user-", "mail-"):
        assert term in readme, term



def helper_code() -> str:
    text = (COLLECTOR_DIR / HELPER).read_text(encoding="ascii")
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def test_native_boundary_is_exactly_the_audited_one():
    assert native_boundary_errors(helper_code()) == []
    for path in COLLECTORS:
        code = "\n".join(line for line in path.read_text(encoding="ascii").splitlines() if not line.lstrip().startswith("#"))
        assert "Add-Type" not in code and "DllImport" not in code, path.name


@pytest.mark.parametrize("mutation", [
    "extra_import", "write_access", "setter_import", "interpolated_source", "add_type_elsewhere", "cancel_remove_flag", "physical_path", "write_mask_literal",
])
def test_native_boundary_guard_rejects_each_widening(mutation):
    """Each mutation of the helper widens or moves the native surface; the guard must refuse every one."""
    code = helper_code()
    if mutation == "extra_import":
        code = code.replace('[DllImport("advapi32.dll")] public static extern int RegCloseKey(IntPtr hKey);',
                            '[DllImport("advapi32.dll")] public static extern int RegCloseKey(IntPtr hKey);\n[DefaultDllImportSearchPaths(DllImportSearchPath.System32)] [DllImport("advapi32.dll")] public static extern int RegFlushKey(IntPtr hKey);')
    elif mutation == "write_access":
        code = code.replace("KEY_READ                 = [uint32]0x20019", "KEY_READ                 = [uint32]0x2001F")
    elif mutation == "setter_import":
        code = code.replace('public static extern int RegCloseKey(IntPtr hKey);', 'public static extern int RegCloseKey(IntPtr hKey);\n[DefaultDllImportSearchPaths(DllImportSearchPath.System32)] [DllImport("advapi32.dll")] public static extern int RegSetValueExW(IntPtr hKey);')
    elif mutation == "interpolated_source":
        code = code.replace("$declaration = @'", "$declaration = @\"").replace("'@\n            Add-Type -MemberDefinition $declaration -Name 'WfDeviceKey'", "\"@\n            Add-Type -MemberDefinition $declaration -Name 'WfDeviceKey'")
    elif mutation == "add_type_elsewhere":
        code = code.replace("function Get-WfToolPath {", "function Get-WfToolPath {\n    Add-Type -MemberDefinition $declaration -Name 'X' -Namespace 'Y'")
    elif mutation == "cancel_remove_flag":
        code = code.replace("$api.SetupDiOpenDeviceInfoW($set, $InstanceId, [IntPtr]::Zero, [uint32]0, [ref]$data)", "$api.SetupDiOpenDeviceInfoW($set, $InstanceId, [IntPtr]::Zero, [uint32]4, [ref]$data)")
    elif mutation == "physical_path":
        code = code.replace("$api.RegOpenKeyExW($hardwareKey, 'Interrupt Management',", "$api.RegOpenKeyExW($hardwareKey, 'HKLM\\SYSTEM\\CurrentControlSet\\Enum',")
    elif mutation == "write_mask_literal":
        code = code.replace("$c['DIREG_DEV'], $c['KEY_READ'])", "$c['DIREG_DEV'], [uint32]0xF003F)")
    assert code != helper_code(), "the mutation did not apply"
    assert native_boundary_errors(code), mutation
