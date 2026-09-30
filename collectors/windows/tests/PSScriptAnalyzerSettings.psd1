# PSScriptAnalyzer settings for the collectors. The compatibility rules check
# syntax, commands and types against Windows PowerShell 5.1, which is what the
# collectors run under; the profile is the Windows 10 one that ships with
# PSScriptAnalyzer.
@{
    # The helper's functions are internal, not cmdlets for interactive use:
    # plural nouns name lists, and the New- functions build objects in memory
    # or create the bundle directory the caller asked for.
    ExcludeRules = @('PSUseSingularNouns', 'PSUseShouldProcessForStateChangingFunctions')
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
