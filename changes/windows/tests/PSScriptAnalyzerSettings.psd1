# PSScriptAnalyzer settings for the change scripts, the same rules as the
# collectors use (this area keeps its own copy and never refers to
# collectors/). The compatibility rules check syntax, commands and types
# against Windows PowerShell 5.1, which is what the change scripts run under;
# the profile is the Windows 10 one that ships with PSScriptAnalyzer.
@{
    # The library's functions are internal, not cmdlets for interactive use:
    # plural nouns name lists, and the scripts take an explicit verb instead
    # of -WhatIf (Plan is the default and reads only).
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
