# Change tooling for the gaming PC

This directory holds the only code in the repository that changes the PC. Each script makes one change, is run by hand at the PC on the captain's own Yes for that change, and can put back exactly what it changed. Everything else in the repository (the collectors, the scenario runner, the SSH front door) is read only and never refers to this directory; `tests/test_changes_area.py` enforces that.

## Rules for every change script

- **Separate area.** Change scripts live here, outside `collectors/`, one self contained script per change, with a library beside it when it needs one. No collector, no part of the scenario runner and nothing in `remote-access/` may call, list or name anything here, and nothing the dispatcher, the runner or a collector does may start a change script. Collectors keep their own read only rules and forbidden command list.
- **Verbs.** `-Plan` is the default and reads only: it prints the current state, exactly what would change and every precondition, and refuses with the reason when one fails. `-Apply` saves the before-state, checks, writes and reads back. `-Undo` restores the saved before-state. `-Readback` reads only and prints PASS or FAIL per value. Only `-Apply` and `-Undo` change anything; each must be named, one verb per run, and no script ever prompts.
- **Save before change, refuse without it.** `-Apply` writes every affected value to a timestamped evidence folder first (a values CSV, `reg export` files and a SHA-256 list written last) and refuses if any part of that fails. `-Undo` restores exactly what was saved and nothing else. Every Apply and Undo ends with a readback that prints PASS or FAIL per value.
- **Stop on the unexpected.** The precheck refuses when a live value is not the one the plan expects, and prints what is there instead.
- **Nothing else.** No installs, downloads, network calls, scheduled tasks, services, restarts, game handles, injection or overlays, and nothing runs while the game or its launcher runs. Nothing gives itself lasting elevation: a script that needs administrator rights says so and the operator starts an elevated Windows PowerShell by hand.
- **Privacy.** Output uses fixed labels (`ethernet-1`) and `<profile>`; it never prints a user name, profile path, command line, device instance path, or hardware or network address. Evidence folders stay on the PC.
- **Windows PowerShell 5.1, plain ASCII,** and no `ConvertTo-Json`. Every Windows fact is cited to Microsoft Learn or the tool's own documentation next to the code, and anything not yet seen on the PC is on the list at the end of this page.

The scripts are tested only against a synthetic backend: `tests/` replaces every adapter that touches Windows, and the Pester suite runs every Apply, Undo and Readback path, including the failure paths (export fails, precheck fails, write fails, readback mismatch, undo after a partial apply). Nothing is ever tested on a real registry or adapter.

```
pwsh -NoProfile -File changes/windows/tests/Invoke-Checks.ps1 -ModulePath tools/psmodules
pytest tests/test_changes_area.py tests/test_change_network_tuning.py tests/test_changes_pwsh.py
```

## `network-tuning.ps1`: the wired adapter's network settings

What it changes: advanced properties of the one wired Realtek adapter on the Realtek NetAdapterCx driver (`rt25cx21x64`) installed on 19 November, and only those the research gave an include verdict. Today that is one setting, `idle-restriction`: `*IdleRestriction` from 0 ("No restriction", the value the install set) back to 1 ("Only idle when user isn't present", the value before the install). It never touches the TCP/IP stack, QoS, DNS, IPv6, the MTU, interrupt affinity or MSI (step 4a), device power management or USB (step 4b), or ExitLag (step 7). Why each other setting is left alone, with sources, is in [docs/changes/network-tuning-research.md](../../docs/changes/network-tuning-research.md); the operator page with the sequence and what to record is [docs/changes/network-tuning.md](../../docs/changes/network-tuning.md).

```
network-tuning.ps1 [-Plan] | -Apply | -Undo [-EvidenceFolder <yyyyMMddTHHmmssZ>] | -Readback
                   [-Only <name>[,<name>...]] [-EvidenceRoot <dir>]
```

`-Only` takes setting names (one comma separated string or several) and goes with Plan, Apply and Readback; an unknown name is refused with the list of known ones. Undo takes no `-Only`: one Apply run is one evidence folder, and Undo puts back everything that folder saved. The evidence root defaults to `%ProgramData%\win-forensics\changes\network-tuning`. Exit codes: 0 done (Plan: ready to apply; Readback: every value PASS), 1 a write or a readback failed, 2 refused, nothing to do, or stopped on an unexpected error, with nothing changed. Plan and Readback run unelevated; Apply and Undo refuse unless the console is elevated.

### What Plan checks

| Check | Passes when |
| --- | --- |
| `game` | neither `Overwatch` nor `Battle.net` is running |
| `adapter` | exactly one physical adapter with the 802.3 medium (`NdisPhysicalMediumType` 14) is Up (`Get-NetAdapter -Physical`) |
| `realtek` | its description names Realtek and its driver file is `rt25cx21x64.sys` (a rollback to another driver is refused, since `*IdleRestriction` is a NetAdapterCx keyword) |
| `name` | its name has no wildcard characters, so the NetAdapter cmdlets take it literally |
| `driver-key` | its driver key name (`DEVPKEY_Device_Driver`) has the network class shape `{4d36e972-e325-11ce-bfc1-08002be10318}\nnnn`, so Apply can export it |
| per setting `exposed` | the driver lists the keyword exactly once (`Get-NetAdapterAdvancedProperty -AllProperties`) |
| per setting `displayed` | it has a display name (a hidden property is refused) |
| per setting `type` | its registry type is REG_SZ (1), as for every displayed property |
| per setting `value` | the live value is one decimal number |
| per setting `valid` | the driver's valid values include both the live and the proposed value |

When every selected setting already holds its proposed value, Plan says NOTHING TO DO and Apply refuses. Plan also lists every other displayed property of the adapter (never one whose keyword or name mentions an address) and the "allow the computer to turn off this device" state, read only, so the before-and-after record has them.

### Saving, the write, Undo and Readback

- **The evidence folder** `<root>\<yyyyMMddTHHmmssZ>` holds `before-values.csv` (setting, keyword, display name, the live value and its display text, the proposed value, the valid values, a SHA-256 of the device instance path, never the path, the driver file and version), `adapter-driver-key.reg` (`reg export` of `HKLM\SYSTEM\CurrentControlSet\Control\Class\<driver key>`, where the driver keeps its advanced properties) and `SHA256SUMS`, written last. Apply refuses if the folder exists, the export exits non zero or writes nothing, or the CSV does not read back. A folder without `SHA256SUMS` is incomplete and Undo never uses it. The `.reg` export can hold the adapter's addresses, so the folder stays on the PC.
- **The write** is `Set-NetAdapterAdvancedProperty -Name <adapter> -RegistryKeyword <keyword> -RegistryValue <value> -NoRestart`, one setting at a time, in the table's order, after a precheck that every live value still equals the saved one. A failed write stops the run; the readback that follows names what changed, and the output says to run `-Undo -EvidenceFolder <stamp>`.
- **Undo** uses the newest complete folder, or the one named with `-EvidenceFolder`. It checks every file against `SHA256SUMS` and the device hash against the adapter, then for each saved row: a live value equal to the saved one is left alone (so Undo after a partial Apply writes only what Apply wrote), a live value equal to the proposed one is written back, and anything else refuses the whole Undo. It ends with a readback against the saved values.
- **Readback** reads the newest complete folder and prints PASS when the live value is the applied one (without a folder, the proposed one). After an Undo it therefore reads FAIL, as expected; the Undo output itself shows PASS against the saved values. When the last boot is older than the Apply, it adds that the PC has not restarted since.

### Sources

- **The keyword.** `*IdleRestriction`: 0 (default) "No restriction", 1 "Only idle when user isn't present"; [standardized INF keywords for power management](https://learn.microsoft.com/windows-hardware/drivers/network/standardized-inf-keywords-for-power-management). The resume latency guideline and the framework's D0 while the interface is in use: [configuring NetAdapterCx power management](https://learn.microsoft.com/windows-hardware/drivers/netcx/configuring-power-management), [porting NDIS miniports to NetAdapterCx](https://learn.microsoft.com/windows-hardware/drivers/netcx/porting-ndis-miniport-drivers-to-netadaptercx#querying-and-setting-power-management-capabilities).
- **Reading.** [Get-NetAdapter](https://learn.microsoft.com/powershell/module/netadapter/get-netadapter) and [MSFT_NetAdapter](https://learn.microsoft.com/windows/win32/fwp/wmi/netadaptercimprov/msft-netadapter) (Status, ConnectorPresent, NdisPhysicalMedium, DriverFileName), [Get-NetAdapterAdvancedProperty](https://learn.microsoft.com/powershell/module/netadapter/get-netadapteradvancedproperty) and [MSFT_NetAdapterAdvancedPropertySettingData](https://learn.microsoft.com/windows/win32/fwp/wmi/netadaptercimprov/msft-netadapteradvancedpropertysettingdata) (RegistryDataType, ValidRegistryValues), [MSFT_NetAdapterPowerManagementSettingData](https://learn.microsoft.com/windows/win32/fwp/wmi/netadaptercimprov/msft-netadapterpowermanagementsettingdata) (AllowComputerToTurnOffDevice, read only), [Get-PnpDeviceProperty](https://learn.microsoft.com/powershell/module/pnpdevice/get-pnpdeviceproperty) with [DEVPKEY_Device_Driver](https://learn.microsoft.com/windows-hardware/drivers/install/devpkey-device-driver), the network class GUID from [system defined device setup classes](https://learn.microsoft.com/windows-hardware/drivers/install/system-defined-device-setup-classes-available-to-vendors), [Win32_OperatingSystem](https://learn.microsoft.com/windows/win32/cimwin32prov/win32-operatingsystem) for the last boot.
- **Writing and restarting.** [Set-NetAdapterAdvancedProperty](https://learn.microsoft.com/powershell/module/netadapter/set-netadapteradvancedproperty) with `-NoRestart`; "Many advanced properties require restarting the network adapter before the new settings take effect" ([New-NetAdapterAdvancedProperty](https://learn.microsoft.com/powershell/module/netadapter/new-netadapteradvancedproperty), [Restart-NetAdapter](https://learn.microsoft.com/powershell/module/netadapter/restart-netadapter)). The script restarts nothing; the operator disables and enables the adapter in Device Manager or restarts the PC.
- **Saving.** `reg export <key> <file> /y` returns 0 on success and 1 on failure: [reg export](https://learn.microsoft.com/windows-server/administration/windows-commands/reg-export).

## Facts to verify on the PC

Kept here rather than in the collectors' list, because nothing under `collectors/` may name this area. Each item is unverified until the PC session reports it, with its date and "reported, not reproduced" status. The `4n` prefix marks the network items, next to steps 4a and 4b.

4n.1. `Get-NetAdapter -Physical` on the PC lists the wired adapter with `Status` `Up`, `NdisPhysicalMedium` 14, `ConnectorPresent` true and `DriverFileName` `rt25cx21x64.sys`, and lists the Wi-Fi adapter (if present) with another medium.
4n.2. `Get-NetAdapterAdvancedProperty -Name <adapter> -AllProperties` runs unelevated and returns `*IdleRestriction` once, displayed as "idle power down restriction", with `RegistryDataType` 1, `RegistryValue` `0` and `ValidRegistryValues` `0` and `1`.
4n.3. `Get-PnpDeviceProperty -KeyName DEVPKEY_Device_Driver` returns the driver key name as `{4d36e972-e325-11ce-bfc1-08002be10318}\nnnn`, and `HKLM\SYSTEM\CurrentControlSet\Control\Class\<that name>` holds the advanced property values.
4n.4. `reg export` of that key exits 0 from an elevated console and writes UTF-16 text with the header `Windows Registry Editor Version 5.00`.
4n.5. `Set-NetAdapterAdvancedProperty -NoRestart` returns without dropping the link, and an immediate `Get-NetAdapterAdvancedProperty` (the Readback) shows the new `RegistryValue` before any restart.
4n.6. After Device Manager Disable device and Enable device (or a PC restart) the value is still 1, and the driver honours it; the registry readback alone cannot show what the driver does with it.
4n.7. `AllowComputerToTurnOffDevice` reads unelevated through `Get-NetAdapterPowerManagement`; and whether `PnPCapabilities` 24 in the driver key governs that box for this NetAdapterCx driver (the 19 November transcription shows 24 with the box Enabled, which suggests it does not).
4n.8. Process names as `Get-Process` reports them: `Overwatch` and `Battle.net`.
