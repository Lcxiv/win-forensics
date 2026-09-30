@echo off
rem win-forensics front door: double click this file at the PC, from the USB stick the kit came on.
rem It starts Start-FrontDoorSetup.ps1, which sits next to it, in Windows PowerShell 5.1. That script
rem refuses to go on unless this folder is on a removable drive (it travels with the kit and cannot
rem prove itself on any other way in), then asks for administrator permission through the normal
rem Windows prompt and does everything else in a second window. A kit that came any other way is
rem checked by hand with Get-FileHash instead: CHECKLIST.md, action 2, "any other way".
rem
rem %~dp0 is the drive and folder this file is in (the kit folder), wherever it was copied:
rem https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/call
rem -ExecutionPolicy Bypass applies to that one PowerShell process and changes nothing on the PC:
rem https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-5.1
rem "%~dp0." rather than "%~dp0": the folder ends with a backslash, and a backslash right before
rem a closing quote would escape the quote on a Windows command line:
rem https://learn.microsoft.com/en-us/cpp/c-language/parsing-c-command-line-arguments
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-FrontDoorSetup.ps1" -KitFolder "%~dp0."
echo.
rem pause keeps this window open until a key is pressed, so a message here can be read:
rem https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/pause
pause
