# WfSetupLib.ps1: the decisions and text rendering behind Install-FrontDoor.ps1.
#
# Everything here is a pure function: it takes values and returns values, touches no registry,
# service, firewall, account, or file. That is what lets remote-access/tests exercise it under
# PowerShell 7 on a Mac. Install-FrontDoor.ps1 does the reading and writing around these.
#
# Win32-OpenSSH source links are pinned to commit e581929 of PowerShell/openssh-portable (branch
# latestw_all, read 2026-09-30). The OpenSSH build inside Windows can be older than that source,
# which is why the installer ends with a loopback self test instead of trusting this reading.

function Get-WfLayout {
    # The installed layout. Built with literal backslashes (not Join-Path) so the strings are the
    # same when the tests render them off Windows.
    param([Parameter(Mandatory = $true)][string]$ProgramData)
    $base = $ProgramData.TrimEnd('\')
    $root = $base + '\win-forensics'
    $remote = $root + '\remote'
    return @{
        Root           = $root
        Remote         = $remote
        Dispatcher     = $remote + '\dispatch.ps1'
        Common         = $remote + '\WfCommon.ps1'
        Collectors     = $remote + '\collectors'
        AuthorizedKeys = $remote + '\authorized_keys'
        State          = $remote + '\install-state.json'
        Outbox         = $root + '\outbox'
        Staging        = $root + '\outbox\.staging'
        SshDir         = $base + '\ssh'
        SshdConfig     = $base + '\ssh\sshd_config'
        SshdLog        = $base + '\ssh\logs\sshd.log'
    }
}

function Get-WfAuthorizedKeysFileToken {
    # The AuthorizedKeysFile value for the Match block. __PROGRAMDATA__ is the token the default
    # Windows sshd_config itself uses for administrators_authorized_keys; sshd expands it and
    # treats the path as absolute:
    # https://github.com/PowerShell/openssh-portable/blob/e581929d3d0cf44e033e47bf3b75a2544918b87e/contrib/win32/openssh/sshd_config#L85-L86
    # https://github.com/PowerShell/openssh-portable/blob/e581929d3d0cf44e033e47bf3b75a2544918b87e/contrib/win32/win32compat/misc.c#L976-L978
    #
    # Why not the documented C:\Users\<account>\.ssh\authorized_keys: a relative AuthorizedKeysFile
    # is resolved against the account's profile directory, and for an account that has never
    # logged on there is no profile. sshd then falls back to the Windows directory, so it would
    # look for C:\Windows\.ssh\authorized_keys and key authentication would fail:
    # https://github.com/PowerShell/openssh-portable/blob/e581929d3d0cf44e033e47bf3b75a2544918b87e/contrib/win32/win32compat/pwd.c#L266-L276
    # An absolute path under ProgramData does not depend on a profile, and it also keeps the key
    # line out of a directory the account owns.
    '__PROGRAMDATA__/win-forensics/remote/authorized_keys'
}

function Test-WfAccountName {
    # Lower case letters and digits only. Microsoft Learn: account names in sshd_config "must be
    # specified in lower case"; New-LocalUser allows at most 20 characters.
    # https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-server-configuration
    # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/new-localuser?view=powershell-5.1
    param([AllowNull()][AllowEmptyString()][string]$Name)
    if ([string]::IsNullOrEmpty($Name)) { return $false }
    return ($Name -cmatch '\A[a-z][a-z0-9]{2,19}\z')
}

function Get-WfIPv4Info {
    # Validate the Mac's LAN address. Returns Valid, Reason (when not valid), and Warning (valid
    # but unusual, for example not a private range).
    param([AllowNull()][AllowEmptyString()][string]$Text)
    $result = @{ Valid = $false; Reason = ''; Warning = ''; Address = '' }
    if ([string]::IsNullOrEmpty($Text)) {
        $result.Reason = 'no address given'
        return $result
    }
    if ($Text -match '\A[0-9A-Fa-f]{2}([:-][0-9A-Fa-f]{2}){5}\z') {
        $result.Reason = 'that is a hardware (MAC) address; this needs the Mac computer''s IP address, four numbers separated by dots'
        return $result
    }
    if ($Text -notmatch '\A([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\z') {
        $result.Reason = 'not an IPv4 address (expected four numbers separated by dots)'
        return $result
    }
    $octets = @([int]$Matches[1], [int]$Matches[2], [int]$Matches[3], [int]$Matches[4])
    $parts = $Text.Split('.')
    foreach ($part in $parts) {
        if ($part.Length -gt 1 -and $part.StartsWith('0')) {
            $result.Reason = 'numbers in the address must not have leading zeros'
            return $result
        }
    }
    foreach ($octet in $octets) {
        if ($octet -gt 255) {
            $result.Reason = 'each number in the address must be between 0 and 255'
            return $result
        }
    }
    if ($octets[0] -eq 127) {
        $result.Reason = 'that is a loopback address; this needs the address the Mac has on the home network'
        return $result
    }
    if ($octets[0] -eq 0 -or $octets[0] -ge 224) {
        $result.Reason = 'that is not the address of one computer (reserved or multicast range)'
        return $result
    }
    $result.Valid = $true
    $result.Address = $Text
    $private = ($octets[0] -eq 10) -or ($octets[0] -eq 172 -and $octets[1] -ge 16 -and $octets[1] -le 31) -or ($octets[0] -eq 192 -and $octets[1] -eq 168)
    if ($octets[3] -eq 0 -or $octets[3] -eq 255) {
        $result.Warning = 'that address ends in 0 or 255, which on most home networks is not a computer; check it is the Mac''s address'
    } elseif ($octets[0] -eq 169 -and $octets[1] -eq 254) {
        $result.Warning = 'that is a self assigned (169.254.x.x) address, which changes; check the Mac is really connected to the router'
    } elseif (-not $private) {
        $result.Warning = 'that is not a private home network address (10.x, 172.16 to 172.31, 192.168.x); check it is the Mac''s address on the home network'
    }
    return $result
}

function Read-WfPublicKey {
    # Parse the contents of the Mac's .pub file. Throws with a plain message when the file is not
    # exactly one bare Ed25519 public key line. Only the key type and the key itself are kept;
    # the comment (usually user@host of the Mac) is dropped.
    param([AllowNull()][AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { throw 'the public key file is empty' }
    if ($Text -match 'PRIVATE KEY') {
        throw 'this is a PRIVATE key file. Never copy a private key to the PC. Delete this copy, and use the file whose name ends in .pub instead'
    }
    $lines = @($Text -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_.Length -gt 0 -and -not $_.StartsWith('#') })
    if ($lines.Count -ne 1) {
        throw "the public key file must hold exactly one key line; this one holds $($lines.Count)"
    }
    $tokens = @($lines[0] -split '\s+')
    if ($tokens.Count -lt 2) { throw 'the public key line is incomplete (expected: ssh-ed25519 AAAA... comment)' }
    if ($tokens[0] -cne 'ssh-ed25519') {
        throw "the key type is '$($tokens[0])'; this front door accepts a plain ssh-ed25519 public key with no options in front of it"
    }
    if ($tokens[1] -cnotmatch '\A[A-Za-z0-9+/]+={0,2}\z') { throw 'the key is not valid base64; the file may have been cut or wrapped' }
    try {
        $blob = [System.Convert]::FromBase64String($tokens[1])
    } catch {
        throw 'the key is not valid base64; the file may have been cut or wrapped'
    }
    # An Ed25519 public key blob is: uint32 11, "ssh-ed25519", uint32 32, 32 key bytes. RFC 8709.
    $prefix = [byte[]](0, 0, 0, 11) + [System.Text.Encoding]::ASCII.GetBytes('ssh-ed25519') + [byte[]](0, 0, 0, 32)
    if ($blob.Length -ne 51) { throw 'the key is not an Ed25519 public key (wrong length); the file may have been cut' }
    for ($i = 0; $i -lt $prefix.Length; $i++) {
        if ($blob[$i] -ne $prefix[$i]) { throw 'the key is not an Ed25519 public key (wrong header)' }
    }
    return @{
        KeyType     = 'ssh-ed25519'
        KeyBase64   = $tokens[1]
        Fingerprint = Get-WfKeyFingerprint -KeyBase64 $tokens[1]
    }
}

function Get-WfKeyFingerprint {
    # The SHA256 fingerprint ssh-keygen -l prints: base64 of the SHA-256 of the key blob, without
    # padding. A fingerprint of a public key is not a secret.
    param([Parameter(Mandatory = $true)][string]$KeyBase64)
    $blob = [System.Convert]::FromBase64String($KeyBase64)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash($blob)
    } finally {
        $sha.Dispose()
    }
    return 'SHA256:' + [System.Convert]::ToBase64String($hash).TrimEnd('=')
}

function Get-WfForcedCommand {
    # The one command line sshd may run for the account. It is handed to the default shell as
    #   "<cmd.exe>" /c "<this string>"
    # https://github.com/PowerShell/openssh-portable/blob/e581929d3d0cf44e033e47bf3b75a2544918b87e/contrib/win32/win32compat/w32-doexec.c#L385-L404
    # so it must not contain a double quote, and neither path may contain a space (Win32-OpenSSH
    # has a documented problem with spaces in executable paths, which is also why this uses
    # Windows PowerShell 5.1 in System32 and not PowerShell 7 under "Program Files"):
    # https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/ssh-remoting-in-powershell
    # -ExecutionPolicy RemoteSigned applies to this one process only and does not change the
    # machine's policy. The default policy on Windows client is Restricted, which would refuse
    # the script. RemoteSigned is the narrowest value that runs it: it "doesn't require digital
    # signatures on scripts that are written on the local computer and not downloaded from the
    # internet", and it runs downloaded ones "if the scripts are unblocked, such as by using the
    # Unblock-File cmdlet", which the setup script does for every file it installs.
    # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-5.1
    # With -File, the script's "exit N" becomes the process exit code:
    # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe?view=powershell-5.1
    param(
        [Parameter(Mandatory = $true)][string]$PowerShellExe,
        [Parameter(Mandatory = $true)][string]$DispatcherPath
    )
    foreach ($path in @($PowerShellExe, $DispatcherPath)) {
        if ($path -match '[\s"]') { throw "the forced command path '$path' contains a space or a quote, which this design does not allow" }
    }
    return "$PowerShellExe -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File $DispatcherPath"
}

function Format-WfAuthorizedKeysLine {
    # One authorized_keys line: options, key type, key, comment.
    #   command="..."  the key can only ever run the dispatcher
    #   restrict       no port, agent, or X11 forwarding, no pty, no user rc
    #   from="..."     the key is only accepted from the Mac's address
    # https://man.openbsd.org/sshd#AUTHORIZED_KEYS_FILE_FORMAT
    param(
        [Parameter(Mandatory = $true)][string]$ForcedCommand,
        [Parameter(Mandatory = $true)][string]$FromAddress,
        [Parameter(Mandatory = $true)][string]$KeyBase64,
        [string]$KeyType = 'ssh-ed25519',
        [string]$Comment = 'win-forensics-mac'
    )
    if ($ForcedCommand.Contains('"')) { throw 'the forced command must not contain a double quote' }
    if ($FromAddress -notmatch '\A[0-9.]+\z') { throw 'the from address must be a plain IPv4 address' }
    if ($KeyType -cne 'ssh-ed25519') { throw 'only ssh-ed25519 keys are installed' }
    if ($KeyBase64 -cnotmatch '\A[A-Za-z0-9+/]+={0,2}\z') { throw 'the key is not valid base64' }
    if ($Comment -cnotmatch '\A[A-Za-z0-9._@-]{1,64}\z') { throw 'the key comment may only hold letters, digits, dot, underscore, at sign, and hyphen' }
    return ('command="{0}",restrict,from="{1}" {2} {3} {4}' -f $ForcedCommand, $FromAddress, $KeyType, $KeyBase64, $Comment)
}

function Format-WfSshdGlobalBlock {
    # Global sshd_config directives. Only keywords Win32-OpenSSH supports are used; the list of
    # unsupported ones is on
    # https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-server-configuration
    #   PasswordAuthentication no   keys only
    #   AllowUsers <account>        nobody else may connect over SSH (lower case, as Learn requires)
    #   SyslogFacility LOCAL0       log to %programdata%\ssh\logs\sshd.log instead of ETW
    #   LogLevel VERBOSE            also record the key fingerprint and the forced command of each
    #                               session; sshd_config(5) advises against the DEBUG levels
    param([Parameter(Mandatory = $true)][string]$AccountName)
    return @(
        '# BEGIN win-forensics front door (global). Managed by Install-FrontDoor.ps1; edits here are overwritten.'
        '# sshd uses the first value it reads for each keyword, so this block sits at the top of the file.'
        'PasswordAuthentication no'
        'PubkeyAuthentication yes'
        "AllowUsers $AccountName"
        'SyslogFacility LOCAL0'
        'LogLevel VERBOSE'
        '# END win-forensics front door (global)'
    )
}

function Format-WfSshdMatchBlock {
    # The Match User block: the second, independent place that pins the account to the dispatcher.
    # PermitTTY no matters on Windows: the Win32-OpenSSH wiki says ForceCommand is "Enforced only
    # on non-PTY sessions. To block PTY access, use PermitTTY="no"".
    # https://github.com/PowerShell/Win32-OpenSSH/wiki/sshd_config#forcecommand
    param(
        [Parameter(Mandatory = $true)][string]$AccountName,
        [Parameter(Mandatory = $true)][string]$ForcedCommand,
        [Parameter(Mandatory = $true)][string]$AuthorizedKeysFileToken
    )
    return @(
        '# BEGIN win-forensics front door (match). Managed by Install-FrontDoor.ps1; edits here are overwritten.'
        "Match User $AccountName"
        "    AuthorizedKeysFile $AuthorizedKeysFileToken"
        "    ForceCommand $ForcedCommand"
        '    PasswordAuthentication no'
        '    PubkeyAuthentication yes'
        '    AuthenticationMethods publickey'
        '    PermitTTY no'
        '    AllowTcpForwarding no'
        '    AllowAgentForwarding no'
        '# END win-forensics front door (match)'
    )
}

function Merge-WfSshdConfig {
    # Return the sshd_config text with the two managed blocks in place: the global block first,
    # the Match block directly before the first existing Match line (so it is the first Match
    # block sshd evaluates) or at the end when there is none. Any earlier managed blocks are
    # removed first, so applying this to its own output changes nothing.
    # sshd_config(5): "for each keyword, the first obtained value will be used", and a Match
    # block runs "until either another Match line or the end of the file".
    # https://man.openbsd.org/sshd_config
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Existing,
        [Parameter(Mandatory = $true)][string[]]$GlobalBlock,
        [Parameter(Mandatory = $true)][string[]]$MatchBlock
    )
    $newline = "`r`n"
    if ($Existing.Length -gt 0 -and $Existing -notmatch "`r`n") { $newline = "`n" }

    $kept = New-Object System.Collections.Generic.List[string]
    $inBlock = $false
    foreach ($line in @($Existing -split "`r?`n")) {
        if ($line -match '^\s*# BEGIN win-forensics front door') {
            if ($inBlock) { throw 'sshd_config has a win-forensics BEGIN marker inside a managed block; fix the file by hand' }
            $inBlock = $true
            continue
        }
        if ($line -match '^\s*# END win-forensics front door') {
            if (-not $inBlock) { throw 'sshd_config has a win-forensics END marker without a BEGIN; fix the file by hand' }
            $inBlock = $false
            continue
        }
        if (-not $inBlock) { $kept.Add($line) }
    }
    if ($inBlock) { throw 'sshd_config has a win-forensics BEGIN marker without an END; fix the file by hand' }

    $firstMatch = -1
    for ($i = 0; $i -lt $kept.Count; $i++) {
        if ($kept[$i] -match '^\s*Match\s') {
            $firstMatch = $i
            break
        }
    }
    $head = New-Object System.Collections.Generic.List[string]
    $tail = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $kept.Count; $i++) {
        if ($firstMatch -ge 0 -and $i -ge $firstMatch) { $tail.Add($kept[$i]) } else { $head.Add($kept[$i]) }
    }
    while ($head.Count -gt 0 -and $head[0].Trim().Length -eq 0) { $head.RemoveAt(0) }
    while ($head.Count -gt 0 -and $head[$head.Count - 1].Trim().Length -eq 0) { $head.RemoveAt($head.Count - 1) }
    while ($tail.Count -gt 0 -and $tail[$tail.Count - 1].Trim().Length -eq 0) { $tail.RemoveAt($tail.Count - 1) }

    $out = New-Object System.Collections.Generic.List[string]
    $out.AddRange($GlobalBlock)
    $out.Add('')
    if ($head.Count -gt 0) {
        $out.AddRange($head)
        $out.Add('')
    }
    $out.AddRange($MatchBlock)
    if ($tail.Count -gt 0) {
        $out.Add('')
        $out.AddRange($tail)
    }
    return (($out.ToArray() -join $newline) + $newline)
}

function Find-WfSshdConfigConflict {
    # Things in the rest of sshd_config that change what the managed blocks mean. Returns plain
    # sentences; the installer prints them as warnings. The effective configuration check
    # (sshd -T) is what decides pass or fail.
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory = $true)][string]$AccountName
    )
    $notes = New-Object System.Collections.Generic.List[string]
    $inBlock = $false
    foreach ($line in @($Text -split "`r?`n")) {
        if ($line -match '^\s*# BEGIN win-forensics front door') { $inBlock = $true; continue }
        if ($line -match '^\s*# END win-forensics front door') { $inBlock = $false; continue }
        if ($inBlock) { continue }
        $trimmed = $line.Trim()
        if ($trimmed.Length -eq 0 -or $trimmed.StartsWith('#')) { continue }
        if ($trimmed -match '^(AllowUsers|AllowGroups)\s+(.+)$') {
            $notes.Add("sshd_config already has '$trimmed'. Allow lists add up, so those accounts may also connect, with their own rights and no forced command.")
        } elseif ($trimmed -match '^(DenyUsers|DenyGroups)\s+(.+)$') {
            $notes.Add("sshd_config already has '$trimmed'. Check it does not deny '$AccountName'.")
        } elseif ($trimmed -match '^Include\s+(.+)$') {
            $notes.Add("sshd_config includes other files ('$trimmed'); settings in them are not managed by this script.")
        } elseif ($trimmed -match '^Port\s+(\d+)$' -and $Matches[1] -ne '22') {
            $notes.Add("sshd_config sets Port $($Matches[1]). This script scopes the firewall for port 22 only; remove that line or stop.")
        } elseif ($trimmed -match '^Match\s+All\b') {
            $notes.Add("sshd_config has a 'Match All' block; its settings apply to '$AccountName' for any keyword the managed Match block does not set.")
        }
    }
    return $notes.ToArray()
}

function Get-WfDefaultShellDecision {
    # Decide what to do with HKLM\SOFTWARE\OpenSSH\DefaultShell.
    #
    # The forced command must be run by cmd.exe, the documented initial default shell:
    # https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-server-configuration#configuring-the-default-shell-for-openssh-in-windows
    # With cmd.exe sshd runs  "cmd.exe" /c "<forced command>"  and the dispatcher's exit code
    # reaches the client. With PowerShell as the default shell sshd would run the forced command
    # through  powershell.exe -c "<forced command>",  and about_PowerShell_exe documents that
    # -Command turns any exit code other than 0 into 1, which would hide the dispatcher's codes.
    # The plan suggested setting PowerShell as the default shell so that PowerShell pipelines
    # sent from the Mac would work; with a forced command the client's text is never run by any
    # shell, so that reason no longer applies.
    #
    # When the DefaultShell value is absent sshd uses System32\cmd.exe and ignores the other two
    # values; when present it also honours DefaultShellCommandOption and DefaultShellArguments:
    # https://github.com/PowerShell/openssh-portable/blob/e581929d3d0cf44e033e47bf3b75a2544918b87e/contrib/win32/win32compat/pwd.c#L76-L99
    param(
        [AllowNull()][AllowEmptyString()][string]$DefaultShell,
        [AllowNull()][AllowEmptyString()][string]$DefaultShellCommandOption,
        [Parameter(Mandatory = $true)][string]$SystemCmdPath
    )
    if ([string]::IsNullOrEmpty($DefaultShell)) {
        return @{ Action = 'none'; Reason = 'DefaultShell is not set, so sshd uses cmd.exe' }
    }
    $normalized = $DefaultShell.Replace('/', '\').ToLowerInvariant()
    $isCmd = ($normalized -eq $SystemCmdPath.ToLowerInvariant())
    $optionOk = [string]::IsNullOrEmpty($DefaultShellCommandOption) -or ($DefaultShellCommandOption -eq '/c')
    if ($isCmd -and $optionOk) {
        return @{ Action = 'none'; Reason = 'DefaultShell already names cmd.exe' }
    }
    return @{ Action = 'remove'; Reason = "DefaultShell is '$DefaultShell'; removing the DefaultShell values restores cmd.exe" }
}

function Test-WfPortSpecIncludes {
    # Does a firewall rule's LocalPort value (strings such as '22', '20-25', 'Any', 'RPC')
    # include the given port? 'Any' is reported separately by the caller.
    param(
        [AllowNull()][string[]]$Spec,
        [Parameter(Mandatory = $true)][int]$Port
    )
    foreach ($item in @($Spec)) {
        if ([string]::IsNullOrEmpty($item)) { continue }
        $text = $item.Trim()
        if ($text -match '\A([0-9]+)\z') {
            if ([int]$Matches[1] -eq $Port) { return $true }
        } elseif ($text -match '\A([0-9]+)-([0-9]+)\z') {
            if ($Port -ge [int]$Matches[1] -and $Port -le [int]$Matches[2]) { return $true }
        }
    }
    return $false
}

function Get-WfFirewallPlan {
    # Decide, from a complete inventory of the enabled inbound allow rules, which rules must be
    # disabled so that the only rule admitting TCP 22 to sshd is the one this script owns, and
    # which rules make that impossible (the caller then fails closed with sshd stopped). Windows
    # Firewall has no rule ordering: any matching allow rule lets the traffic in, so a broader
    # rule left enabled would defeat the address scoping.
    # https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules
    #
    # Each input rule is a hashtable: Name, Enabled, Direction, Action, Protocol, LocalPort
    # (string array), Program, Package, Service, PolicyStoreSourceType, and Unclassified (a reason
    # string when its filters could not be read). A rule admits TCP 22 to sshd when it is an
    # enabled inbound allow rule, its protocol is TCP, 6, or Any, its local port names 22 or is
    # Any, and it is not scoped to another program, to a packaged app, or to another service.
    # Rules are matched by what they allow, never by name; the default rule the OpenSSH Server
    # install creates is documented as OpenSSH-Server-In-TCP, but a renamed copy is caught too.
    # Returns @{ Disable = names; FailClosed = reasons }.
    param(
        [AllowNull()][object[]]$Rules,
        [Parameter(Mandatory = $true)][string]$OwnRuleName
    )
    $disable = New-Object System.Collections.Generic.List[string]
    $failClosed = New-Object System.Collections.Generic.List[string]
    foreach ($rule in @($Rules)) {
        if ($null -eq $rule) { continue }
        if ($rule.Name -eq $OwnRuleName) { continue }
        if (-not $rule.Enabled) { continue }
        if ($rule.Direction -ne 'Inbound' -or $rule.Action -ne 'Allow') { continue }
        $unclassified = ''
        if ($rule.ContainsKey('Unclassified')) { $unclassified = [string]$rule.Unclassified }
        if ($unclassified -ne '') {
            $failClosed.Add("rule '$($rule.Name)' could not be read ($unclassified)")
            continue
        }
        if (-not (Test-WfRuleAdmitsSsh -Rule $rule)) { continue }
        $source = ''
        if ($rule.ContainsKey('PolicyStoreSourceType')) { $source = [string]$rule.PolicyStoreSourceType }
        if ($source -ne '' -and $source -ne 'Local') {
            $failClosed.Add("rule '$($rule.Name)' admits inbound SSH and comes from $source policy, which this script cannot disable")
            continue
        }
        $disable.Add([string]$rule.Name)
    }
    return @{ Disable = $disable.ToArray(); FailClosed = $failClosed.ToArray() }
}

function Test-WfRuleAdmitsSsh {
    # Would this enabled inbound allow rule let a connection to TCP 22 reach sshd?
    param([Parameter(Mandatory = $true)][hashtable]$Rule)
    $protocolOk = @('TCP', '6', 'Any') -contains [string]$Rule.Protocol
    if (-not $protocolOk) { return $false }
    $ports = [string[]]@($Rule.LocalPort)
    $portOk = ($ports -contains 'Any') -or (Test-WfPortSpecIncludes -Spec $ports -Port 22)
    if (-not $portOk) { return $false }
    # A rule scoped to another program applies to that program's sockets, not to sshd's.
    $program = ''
    if ($Rule.ContainsKey('Program')) { $program = [string]$Rule.Program }
    if ($program -ne '' -and $program -ne 'Any' -and -not $program.ToLowerInvariant().EndsWith('\sshd.exe')) { return $false }
    # A rule scoped to a packaged (Store) app applies inside that app container only.
    $package = ''
    if ($Rule.ContainsKey('Package')) { $package = [string]$Rule.Package }
    if ($package -ne '' -and $package -ne 'Any') { return $false }
    # A rule scoped to another Windows service does not cover the sshd service. '*' means every
    # service, sshd included (INetFwRule::ServiceName, "*" applies the rule to all services):
    # https://learn.microsoft.com/en-us/windows/win32/api/netfw/nf-netfw-inetfwrule-get_servicename
    $service = ''
    if ($Rule.ContainsKey('Service')) { $service = [string]$Rule.Service }
    if (@('', 'Any', '*', 'sshd') -notcontains $service) { return $false }
    return $true
}

function Test-WfOwnFirewallRule {
    # Is the rule this script owns exactly what it should be? Returns the list of differences.
    param(
        [Parameter(Mandatory = $true)][hashtable]$Rule,
        [Parameter(Mandatory = $true)][string]$MacAddress
    )
    $problems = New-Object System.Collections.Generic.List[string]
    if (-not $Rule.Enabled) { $problems.Add('the rule is disabled') }
    if ($Rule.Direction -ne 'Inbound') { $problems.Add("direction is $($Rule.Direction), not Inbound") }
    if ($Rule.Action -ne 'Allow') { $problems.Add("action is $($Rule.Action), not Allow") }
    if ([string]$Rule.Profile -ne 'Private') { $problems.Add("profile is '$($Rule.Profile)', not Private only") }
    if ([string]$Rule.Protocol -ne 'TCP' -and [string]$Rule.Protocol -ne '6') { $problems.Add("protocol is $($Rule.Protocol), not TCP") }
    $ports = @($Rule.LocalPort)
    if ($ports.Count -ne 1 -or [string]$ports[0] -ne '22') { $problems.Add("local port is '$($ports -join ',')', not 22") }
    # A single address may be reported back bare or with an all ones mask.
    $remote = @($Rule.RemoteAddress)
    $accepted = @($MacAddress, "$MacAddress/32", "$MacAddress/255.255.255.255")
    if ($remote.Count -ne 1 -or $accepted -notcontains [string]$remote[0]) { $problems.Add("remote address is '$($remote -join ',')', not the Mac's address only") }
    return $problems.ToArray()
}

function ConvertFrom-WfSshdDump {
    # Parse "sshd -T" output (one "keyword value" per line, keywords in lower case) into a
    # hashtable of keyword to list of values. https://man.openbsd.org/sshd#T
    param([AllowNull()][AllowEmptyString()][string]$Text)
    $map = @{}
    if ([string]::IsNullOrEmpty($Text)) { return $map }
    foreach ($line in @($Text -split "`r?`n")) {
        $trimmed = $line.Trim()
        if ($trimmed.Length -eq 0) { continue }
        $space = $trimmed.IndexOf(' ')
        if ($space -lt 0) {
            $key = $trimmed.ToLowerInvariant()
            $value = ''
        } else {
            $key = $trimmed.Substring(0, $space).ToLowerInvariant()
            $value = $trimmed.Substring($space + 1).Trim()
        }
        if (-not $map.ContainsKey($key)) { $map[$key] = New-Object System.Collections.Generic.List[string] }
        $map[$key].Add($value)
    }
    return $map
}

function Test-WfSshdEffectiveConfig {
    # Compare what sshd says it would apply to a connection by the account from the Mac with
    # what this script configured. Problems fail the step; Notes are warnings.
    param(
        [Parameter(Mandatory = $true)][hashtable]$Dump,
        [Parameter(Mandatory = $true)][string]$AccountName,
        [Parameter(Mandatory = $true)][string]$ForcedCommand
    )
    $problems = New-Object System.Collections.Generic.List[string]
    $notes = New-Object System.Collections.Generic.List[string]
    $expectSingle = [ordered]@{
        passwordauthentication = 'no'
        pubkeyauthentication   = 'yes'
        permittty              = 'no'
        allowtcpforwarding     = 'no'
        allowagentforwarding   = 'no'
        authenticationmethods  = 'publickey'
        syslogfacility         = 'local0'
    }
    foreach ($key in $expectSingle.Keys) {
        if (-not $Dump.ContainsKey($key)) {
            $problems.Add("sshd did not report '$key'")
            continue
        }
        $actual = $Dump[$key][0].ToLowerInvariant()
        if ($actual -ne $expectSingle[$key]) { $problems.Add("$key is '$actual', expected '$($expectSingle[$key])'") }
    }
    if (-not $Dump.ContainsKey('forcecommand')) {
        $problems.Add('no ForceCommand applies to the account')
    } elseif ($Dump['forcecommand'][0] -cne $ForcedCommand) {
        $problems.Add("ForceCommand is '$($Dump['forcecommand'][0])', not the dispatcher command line")
    }
    if (-not $Dump.ContainsKey('authorizedkeysfile')) {
        $problems.Add("sshd did not report 'authorizedkeysfile'")
    } else {
        $keysFile = $Dump['authorizedkeysfile'][0].Replace('\', '/').ToLowerInvariant()
        if (-not $keysFile.EndsWith('/win-forensics/remote/authorized_keys')) {
            $problems.Add("AuthorizedKeysFile is '$($Dump['authorizedkeysfile'][0])', not the managed key file")
        }
    }
    $allowed = @()
    if ($Dump.ContainsKey('allowusers')) { $allowed = @($Dump['allowusers'] | ForEach-Object { $_ -split '\s+' } | Where-Object { $_.Length -gt 0 }) }
    if ($allowed -notcontains $AccountName) { $problems.Add("AllowUsers does not list '$AccountName'") }
    $others = @($allowed | Where-Object { $_ -ne $AccountName })
    if ($others.Count -gt 0) { $notes.Add("AllowUsers also lists: $($others -join ', '). Those accounts can connect too, without the forced command.") }
    if ($Dump.ContainsKey('allowgroups')) { $notes.Add("AllowGroups is set ($($Dump['allowgroups'] -join ' ')); members of those groups can connect too.") }
    return @{ Problems = $problems.ToArray(); Notes = $notes.ToArray() }
}

function ConvertFrom-WfPowerCfgQuery {
    # Read the AC and DC values out of "powercfg /query SCHEME_CURRENT SUB_SLEEP STANDBYIDLE".
    # The label text is localized, so this relies only on the hexadecimal values: the last two
    # on the page are the current AC and DC settings, in seconds. Returns $null when the output
    # does not have that shape.
    # https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/powercfg-command-line-options
    # https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/sleep-settings-sleep-idle-timeout
    param([AllowNull()][AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $null }
    $values = New-Object System.Collections.Generic.List[long]
    foreach ($line in @($Text -split "`r?`n")) {
        if ($line -match ':\s*0x([0-9a-fA-F]{8})\s*$') { $values.Add([System.Convert]::ToInt64($Matches[1], 16)) }
    }
    if ($values.Count -lt 2) { return $null }
    return @{ AcSeconds = $values[$values.Count - 2]; DcSeconds = $values[$values.Count - 1] }
}

function Get-WfWriteRightsMask {
    # FileSystemRights bits that let a principal change or remove a file or directory. This mask
    # is deliberately wider than the one Win32-OpenSSH applies to its own files. Win32-OpenSSH's
    # SSH_SECURE_WRITE_MASK is WriteData 0x2, AppendData 0x4, WriteExtendedAttributes 0x10,
    # WriteAttributes 0x100, Delete 0x10000, ChangePermissions 0x40000, and TakeOwnership 0x80000
    # (https://github.com/PowerShell/openssh-portable/blob/e581929d3d0cf44e033e47bf3b75a2544918b87e/contrib/win32/win32compat/w32-sshfileperm.c#L49-L53),
    # which is 0xD0116. This mask adds DeleteSubdirectoriesAndFiles 0x40 (a directory right that
    # removes the files inside), GENERIC_WRITE 0x40000000, and GENERIC_ALL 0x10000000 (generic
    # rights that map onto the specific write bits), for 0x500D0156.
    return 0x500D0156
}

function Get-WfUpstreamWriteRightsMask {
    # Win32-OpenSSH's own SSH_SECURE_WRITE_MASK, kept so a test can state how the two differ.
    return 0xD0116
}

function Test-WfAclRule {
    # Check a list of allow rules ({ Sid, Rights }) against the layout's policy. Administrators
    # (S-1-5-32-544) and SYSTEM (S-1-5-18) may hold anything. The collector account may hold
    # rights without write bits unless AccountMayWrite. Any other principal is a violation unless
    # OthersMayRead, and then only without write bits. Returns the violations as sentences.
    param(
        [AllowNull()][object[]]$Rules,
        [Parameter(Mandatory = $true)][string]$AccountSid,
        [switch]$AccountMayWrite,
        [switch]$OthersMayRead
    )
    $trusted = @('S-1-5-18', 'S-1-5-32-544')
    $mask = Get-WfWriteRightsMask
    $violations = New-Object System.Collections.Generic.List[string]
    foreach ($rule in @($Rules)) {
        if ($null -eq $rule) { continue }
        $sid = [string]$rule.Sid
        $rights = [long]$rule.Rights
        if ($trusted -contains $sid) { continue }
        $writes = (($rights -band $mask) -ne 0)
        if ($sid -eq $AccountSid) {
            if ($writes -and -not $AccountMayWrite) { $violations.Add("the collector account has write access (rights 0x$($rights.ToString('x')))") }
            continue
        }
        if (-not $OthersMayRead) {
            $violations.Add("$sid has access (rights 0x$($rights.ToString('x'))); only SYSTEM, Administrators, and the collector account may")
        } elseif ($writes) {
            $violations.Add("$sid has write access (rights 0x$($rights.ToString('x')))")
        }
    }
    return $violations.ToArray()
}

function New-WfRandomPassword {
    # A password nobody knows: generated from the system random number generator, held only as a
    # SecureString, handed straight to New-LocalUser, never printed, logged, or written to disk.
    # It exists because a local account has to have one; nothing ever uses it. Logon over SSH is
    # by key: sshd builds the session token itself (an S4U logon, no password involved), and
    # PasswordAuthentication is off:
    # https://github.com/PowerShell/openssh-portable/blob/e581929d3d0cf44e033e47bf3b75a2544918b87e/contrib/win32/win32compat/win32_usertoken_utils.c#L171-L215
    # A blank password was rejected: it would let anyone at the keyboard sign in as the account
    # (the "Limit local account use of blank passwords to console logon only" policy still allows
    # console logon), and the documentation does not say how key logon behaves for such accounts.
    # The account is created with -PasswordNeverExpires so that an expired password can never
    # become the reason key logon stops working months later.
    # https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-localpoliciessecurityoptions#accounts_limitlocalaccountuseofblankpasswordstoconsolelogononly
    param([int]$Length = 40)
    if ($Length -lt 20 -or $Length -gt 127) { throw 'password length must be between 20 and 127' }
    $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!#%+-=?@_'.ToCharArray()
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $chars = New-Object char[] $Length
    $one = New-Object byte[] 1
    # Largest multiple of the alphabet size that fits in a byte; larger draws are thrown away so
    # every character is equally likely.
    $limit = 256 - (256 % $alphabet.Length)
    try {
        while ($true) {
            for ($i = 0; $i -lt $Length; $i++) {
                do { $rng.GetBytes($one) } while ($one[0] -ge $limit)
                $chars[$i] = $alphabet[$one[0] % $alphabet.Length]
            }
            $upper = $false; $lower = $false; $digit = $false; $symbol = $false
            foreach ($c in $chars) {
                if ([char]::IsUpper($c)) { $upper = $true }
                elseif ([char]::IsLower($c)) { $lower = $true }
                elseif ([char]::IsDigit($c)) { $digit = $true }
                else { $symbol = $true }
            }
            # Satisfy the Windows complexity rule whatever the local policy is.
            if ($upper -and $lower -and $digit -and $symbol) { break }
        }
        $secure = New-Object System.Security.SecureString
        foreach ($c in $chars) { $secure.AppendChar($c) }
        $secure.MakeReadOnly()
        return $secure
    } finally {
        [System.Array]::Clear($chars, 0, $chars.Length)
        $rng.Dispose()
    }
}

function Get-WfSummaryResult {
    # Overall result from the step records ({ Status } of PASS, WARN, INCOMPLETE, FAIL, SKIP).
    # PASS needs every step to have run and verified itself; a step that could not perform an
    # essential verification is INCOMPLETE, which is not success: exit code 2, and no handoff to
    # the Mac. FAIL (a step failed, so later ones did not run) is exit code 1. WARN never
    # changes the result.
    param([AllowNull()][object[]]$Steps)
    $fail = @($Steps | Where-Object { $_.Status -eq 'FAIL' }).Count
    $skip = @($Steps | Where-Object { $_.Status -eq 'SKIP' }).Count
    $incomplete = @($Steps | Where-Object { $_.Status -eq 'INCOMPLETE' }).Count
    $warn = @($Steps | Where-Object { $_.Status -eq 'WARN' }).Count
    $result = 'PASS'
    $exitCode = 0
    if ($fail -gt 0 -or $skip -gt 0) {
        $result = 'FAIL'
        $exitCode = 1
    } elseif ($incomplete -gt 0) {
        $result = 'INCOMPLETE'
        $exitCode = 2
    }
    return @{ Result = $result; Failed = $fail; Skipped = $skip; Incomplete = $incomplete; Warnings = $warn; ExitCode = $exitCode }
}

function Get-WfTokenWellKnownSid {
    # Well known SIDs a network logon token of a local account carries, whatever its groups:
    # Everyone S-1-1-0, Authenticated Users S-1-5-11, NETWORK S-1-5-2, This Organization S-1-5-15,
    # Local account S-1-5-113, NTLM Authentication S-1-5-64-10. INTERACTIVE S-1-5-4 is included
    # too, so that a group which grants through it is looked at even though an SSH session is a
    # network logon. A local group that lists one of these grants its rights to the account.
    # https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers
    return @('S-1-1-0', 'S-1-5-11', 'S-1-5-2', 'S-1-5-15', 'S-1-5-113', 'S-1-5-64-10', 'S-1-5-4')
}

function Test-WfAccountGroupBaseline {
    # The exact permitted group baseline of the collector account, checked against the complete
    # membership of every local group ({ Sid; MemberSids } each):
    #   - direct membership of Event Log Readers (S-1-5-32-573) and of no other group;
    #   - membership through a well known SID only in Users (S-1-5-32-545), whose default
    #     members are Authenticated Users and INTERACTIVE. That one is unavoidable: Windows puts
    #     every authenticated account in it, and it is what lets the account start
    #     powershell.exe from System32. Any other group that grants through Everyone,
    #     Authenticated Users, and so on is rejected, because it would give the account that
    #     group's rights without anyone having added it there.
    # Returns the violations as sentences; an empty result means the baseline holds exactly.
    param(
        [AllowNull()][object[]]$Groups,
        [Parameter(Mandatory = $true)][string]$AccountSid
    )
    $violations = New-Object System.Collections.Generic.List[string]
    $wellKnown = @(Get-WfTokenWellKnownSid)
    $direct = New-Object System.Collections.Generic.List[string]
    foreach ($group in @($Groups)) {
        if ($null -eq $group) { continue }
        $groupSid = [string]$group.Sid
        $members = [string[]]@($group.MemberSids)
        if ($members -contains $AccountSid) { $direct.Add($groupSid) }
        $through = @($members | Where-Object { $wellKnown -contains $_ })
        if ($through.Count -gt 0 -and $groupSid -ne 'S-1-5-32-545') {
            $violations.Add("group $groupSid grants its rights to every account through $($through -join ', '); the collector account would hold them too")
        }
    }
    if ($direct -notcontains 'S-1-5-32-573') { $violations.Add('the account is not a member of Event Log Readers (S-1-5-32-573)') }
    foreach ($groupSid in $direct) {
        if ($groupSid -eq 'S-1-5-32-573') { continue }
        if ($groupSid -eq 'S-1-5-32-544') {
            $violations.Add('the account is a member of Administrators (S-1-5-32-544)')
        } else {
            $violations.Add("the account is a member of group $groupSid, which the baseline does not allow")
        }
    }
    return $violations.ToArray()
}
