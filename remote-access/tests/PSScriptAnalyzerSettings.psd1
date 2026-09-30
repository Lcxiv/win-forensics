# PSScriptAnalyzer settings for remote-access/windows. The scripts must run under Windows
# PowerShell 5.1 on Windows 10 and 11; the compatibility rules check syntax, commands, and .NET
# types against the Windows PowerShell 5.1 profile that ships with PSScriptAnalyzer.
@{
    Severity     = @('Error', 'Warning')
    ExcludeRules = @(
        # Install-FrontDoor.ps1 is an interactive console script; its coloured step output is
        # meant for the person at the PC, not for a pipeline.
        'PSAvoidUsingWriteHost',
        # Names such as Get-WfSshFirewallRule return several items by design.
        'PSUseSingularNouns',
        # The setup functions are internal steps of one script, run once, elevated, by hand.
        'PSUseShouldProcessForStateChangingFunctions'
    )
    Rules        = @{
        PSUseCompatibleSyntax   = @{
            Enable         = $true
            TargetVersions = @('5.1')
        }
        PSUseCompatibleCommands = @{
            Enable         = $true
            TargetProfiles = @('win-48_x64_10.0.17763.0_5.1.17763.316_x64_4.0.30319.42000_framework')
        }
        PSUseCompatibleTypes    = @{
            Enable         = $true
            TargetProfiles = @('win-48_x64_10.0.17763.0_5.1.17763.316_x64_4.0.30319.42000_framework')
        }
    }
}
