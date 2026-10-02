#Requires -RunAsAdministrator
<#
=============================================================================
 FIM setup test for Windows: file changes and registry changes
 Run on:   windows-endpoint, in PowerShell "Run as administrator",
           after the FIM setup steps are finished
 Usage:    powershell -ExecutionPolicy Bypass -File .\fim-test-windows.ps1
 Time:     about 18 minutes (the registry is scanned every 5 minutes)

 Steps and the alerts each one must produce (agent: windows-endpoint):
   1. create C:\fim-lab\fim-test.txt   -> 554  File added to the system.
   2. add a line                       -> 550  Integrity checksum changed.
   3. icacls /grant Users:(R)          -> 550  (permission)
   4. icacls /setowner SYSTEM          -> 550  (owner)
   5. delete the file                  -> 553  File deleted.
   6. add registry values              -> 752  Registry Value Entry Added to the System (x2)
        HKLM\Software\FimLab        LabValue   = first
        HKLM\...\CurrentVersion\Run FimLabTest = C:\Windows\System32\notepad.exe
   7. change LabValue to "second"      -> 750  Registry Value Integrity Checksum Changed
   8. delete both values               -> 751  Registry Value Entry Deleted. (x2)
 Registry alerts appear at the next scheduled scan (every 300 s in this lab).
=============================================================================
#>
$ErrorActionPreference = 'Stop'

$FimDir   = 'C:\fim-lab'
$TestFile = Join-Path $FimDir 'fim-test.txt'
$LabKey   = 'HKLM:\Software\FimLab'
$RunKey   = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
$Wait     = 10     # seconds between file steps (files use who-data, real time)
$ScanWait = 330    # seconds between registry steps (scan every 300 s + margin)

function Step([int]$Number, [string]$Text) {
    Write-Host ("[{0}/8] {1} {2}" -f $Number, (Get-Date -Format 'HH:mm:ss'), $Text)
}

function Wait-RegistryScan {
    Write-Host "      waiting $ScanWait seconds for the next registry scan..."
    Start-Sleep -Seconds $ScanWait
}

if (-not (Test-Path $FimDir)) {
    throw "$FimDir does not exist. Create it first: New-Item -ItemType Directory -Path $FimDir"
}
if (-not (Test-Path $LabKey)) {
    throw "$LabKey does not exist. Create it first: New-Item -Path $LabKey"
}

Step 1 "Create    $TestFile"
Set-Content -Path $TestFile -Value 'first line'
Start-Sleep -Seconds $Wait

Step 2 "Modify    $TestFile (add a line)"
Add-Content -Path $TestFile -Value 'second line'
Start-Sleep -Seconds $Wait

Step 3 "Permission: give the Users group read access"
icacls $TestFile /grant 'Users:(R)' | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Warning "icacls /grant failed (exit code $LASTEXITCODE)" }
Start-Sleep -Seconds $Wait

Step 4 "Owner: change the owner to SYSTEM"
icacls $TestFile /setowner 'NT AUTHORITY\SYSTEM' | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Warning "icacls /setowner failed (exit code $LASTEXITCODE)" }
Start-Sleep -Seconds $Wait

Step 5 "Delete    $TestFile"
Remove-Item -Path $TestFile -Force
Start-Sleep -Seconds $Wait

Step 6 "Registry: add FimLab\LabValue and Run\FimLabTest"
New-ItemProperty -Path $LabKey -Name 'LabValue' -Value 'first' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $RunKey -Name 'FimLabTest' -Value 'C:\Windows\System32\notepad.exe' -PropertyType String -Force | Out-Null
Wait-RegistryScan

Step 7 "Registry: change FimLab\LabValue to 'second'"
Set-ItemProperty -Path $LabKey -Name 'LabValue' -Value 'second'
Wait-RegistryScan

Step 8 "Registry: delete both values"
Remove-ItemProperty -Path $LabKey -Name 'LabValue'
Remove-ItemProperty -Path $RunKey -Name 'FimLabTest'
Wait-RegistryScan

Write-Host "Done. Check: Endpoint security > File Integrity Monitoring > Events (agent windows-endpoint)"
