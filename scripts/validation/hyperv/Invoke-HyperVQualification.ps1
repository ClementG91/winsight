#Requires -RunAsAdministrator
# HOST, elevated, started by WinSightQualRunner.ps1 from its protected harness copy: one unattended
# qualification run of the staged candidate on the Hyper-V VM. Never authenticates to the guest.
#   restore the clean checkpoint -> format the WINSIGHTQ data disk and stage the protected candidate
#   and the guest harness on it -> attach it and start the VM -> the guest runs qualify.ps1 (operator
#   decisions by operator-automation.ps1) and shuts itself down -> detach, copy the results into a new
#   sealed run directory with the harness and candidate manifests -> restore the clean checkpoint.
#
# RA-01: every input comes from an administrators-only copy the runner verified; the data disk is
# emptied by formatting, never by a recursive delete of what the guest wrote; results are copied file by
# file without entering a reparse point; the run directory is new and protected (users may read it).
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$CandidateDir,
    [Parameter(Mandatory)][string]$HarnessDir,
    [Parameter(Mandatory)][string]$EvidenceRoot,
    [string]$Root = (Join-Path ([IO.Path]::GetPathRoot($PSScriptRoot)) 'Hyper-V\WinSight-Qualification'),
    [string]$Name = 'WinSight-Qualification-HV',
    [string]$Checkpoint = 'S0-hyperv-autorun',
    [string]$RunName = ('hv-run-' + (Get-Date -Format 'yyyyMMdd-HHmm')),
    # Gates to run (01 always runs). Empty = every gate.
    [string[]]$Gates = @(),
    [int]$TimeoutMinutes = 480,
    # Memory for this run only (0 = the checkpoint's own); the checkpoint restore at the end resets it.
    [int64]$MemoryBytes = 0,
    # Collect a run whose driver was closed while the VM kept going: wait for it to power off, then seal and restore.
    [switch]$Resume
)
$ErrorActionPreference = 'Stop'
# 'a,b' arrives as one string through powershell.exe -File; accept both forms.
$Gates = @($Gates | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
Import-Module Hyper-V
Import-Module (Join-Path $HarnessDir 'WinSightHyperV.psm1') -Force
foreach ($protected in $CandidateDir, $HarnessDir, $EvidenceRoot) { Assert-ProtectedPath -Path $protected }
Assert-ProtectedPath -Path $Root -Recurse -AllowVirtualMachines
$data = Join-Path $Root 'data.vhdx'
$hostLog = Join-Path $EvidenceRoot 'host-operations.txt'
function Write-HostLog([string]$Message) { $line = "$(Get-Date -Format o) [hyper-v] $Message"; Add-Content -LiteralPath $hostLog -Value $line; Write-Host $line }
function Remove-DataDisk { Get-VMHardDiskDrive -VMName $Name | Where-Object Path -eq $data | Remove-VMHardDiskDrive }

$runDir = Join-Path $EvidenceRoot $RunName
if (-not $Resume -and (Test-Path -LiteralPath $runDir)) { throw "Run $RunName already exists; choose a new name." }
if (-not $Resume -and (Get-WinSightVmState $Name) -ne 'Off') { throw "VM $Name is $(Get-WinSightVmState $Name); turn it off first." }
$candidate = Get-Content -LiteralPath (Join-Path $CandidateDir 'candidate.json') -Raw | ConvertFrom-Json

if ($Resume) {
    Write-HostLog "$RunName resumed: waiting for $Name ($(Get-WinSightVmState $Name)) to finish"
}
else {
    # --- Stage --------------------------------------------------------------------------------------
    Restore-VMCheckpoint -VMName $Name -Name $Checkpoint -Confirm:$false
    Remove-DataDisk
    $letter = Mount-WinSightData $data
    try {
        Clear-WinSightDataVolume $letter
        $staged = "${letter}:\candidate"
        [void](New-Item -ItemType Directory -Path $staged)
        Copy-Item -Path (Join-Path $CandidateDir '*') -Destination $staged -Recurse
        foreach ($guestFile in 'qualify.ps1', 'operator-automation.ps1') {
            Copy-Item -LiteralPath (Join-Path $HarnessDir "guest\$guestFile") -Destination $staged
        }
        $candidateJson = Join-Path $staged 'candidate.json'
        $stagedCandidate = Get-Content -LiteralPath $candidateJson -Raw | ConvertFrom-Json
        $stagedCandidate.PSObject.Properties.Remove('gates')
        if ($Gates.Count -gt 0) { $stagedCandidate | Add-Member -NotePropertyName gates -NotePropertyValue $Gates }
        $stagedCandidate | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $candidateJson -Encoding UTF8
        Copy-Item -LiteralPath (Join-Path $HarnessDir 'guest\run-guest-checks.ps1') -Destination "${letter}:\run-guest-checks.ps1"
        'qualify' | Set-Content -LiteralPath "${letter}:\mode.txt"
    }
    finally { Dismount-WinSightData $data }
    $gateText = if ($Gates.Count -gt 0) { $Gates -join ',' } else { 'all' }
    Write-HostLog "$RunName on $($candidate.commit.Substring(0, 7)): gates $gateText, checkpoint $Checkpoint"

    # --- Run ----------------------------------------------------------------------------------------
    Add-VMHardDiskDrive -VMName $Name -Path $data
    if ($MemoryBytes -gt 0) { Set-VMMemory -VMName $Name -StartupBytes $MemoryBytes; Write-HostLog ("memory for this run: {0:N1} GB" -f ($MemoryBytes / 1GB)) }
    $freeBytes = (Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory * 1KB
    $vmBytes = (Get-VMMemory -VMName $Name).Startup
    if ($freeBytes -lt $vmBytes + 512MB) {
        Write-Warning ("Only {0:N1} GB of RAM free for a {1:N1} GB VM: close memory-heavy applications first, or Hyper-V may refuse to start it." -f ($freeBytes / 1GB), ($vmBytes / 1GB))
    }
    Start-VM -Name $Name
}
$started = Get-Date
$deadline = $started.AddMinutes($TimeoutMinutes)
while ((Get-WinSightVmState $Name) -ne 'Off' -and (Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 60
    Write-Host ("  running {0:N0} min" -f ((Get-Date) - $started).TotalMinutes)
}
$timedOut = (Get-WinSightVmState $Name) -ne 'Off'
if ($timedOut) { Stop-VM -Name $Name -TurnOff -Force; Write-HostLog "timeout after $TimeoutMinutes minutes: VM turned off" }
else { Write-HostLog "the guest shut itself down after $([int]((Get-Date) - $started).TotalMinutes) minutes" }

# --- Collect and seal (kit section 8: before restoring) --------------------------------------------------
Remove-DataDisk
if (-not (Test-Path -LiteralPath $runDir)) { [void](New-Item -ItemType Directory -Path $runDir) }
Assert-ProtectedPath -Path $runDir
$letter = Mount-WinSightData $data
try {
    $refused = @(Copy-GuestResults -From "${letter}:\candidate\guest-results" -To $runDir)
    if ($refused.Count -gt 0) { $refused | Set-Content -LiteralPath (Join-Path $runDir 'collection-refused.txt') }
}
finally { Dismount-WinSightData $data }
# What ran: the protected harness and candidate, by SHA-256 and git blob id, for the verifier.
@("# harness $HarnessDir") + @(Get-FileManifest $HarnessDir) | Set-Content -LiteralPath (Join-Path $runDir 'provenance-harness.txt')
@("# candidate $CandidateDir, claimed commit $($candidate.commit)") + @(Get-FileManifest $CandidateDir) |
    Set-Content -LiteralPath (Join-Path $runDir 'provenance-candidate.txt')
Get-ChildItem -LiteralPath $runDir -Recurse -File | Where-Object Name -ne 'SHA256SUMS.txt' | Sort-Object FullName |
    ForEach-Object { "$((Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash)  $($_.FullName.Substring($runDir.Length + 1))" } |
    Set-Content -LiteralPath (Join-Path $runDir 'SHA256SUMS.txt')
Write-HostLog "evidence sealed in $runDir"
Restore-VMCheckpoint -VMName $Name -Name $Checkpoint -Confirm:$false
Write-HostLog "VM restored to $Checkpoint"

# --- Summary --------------------------------------------------------------------------------------------
$resultsFile = Join-Path $runDir 'results.json'
if (-not (Test-Path -LiteralPath $resultsFile)) { Write-Warning 'No results.json: the harness never started or never saved.'; exit 2 }
$final = Get-Content -LiteralPath $resultsFile -Raw | ConvertFrom-Json
$rows = foreach ($gate in $final.gates.PSObject.Properties) {
    [pscustomobject]@{ Gate = $gate.Name; Status = $gate.Value.status; Seconds = $gate.Value.seconds }
}
$rows | Format-Table -AutoSize | Out-String | Write-Host
$failed = @($rows | Where-Object Status -eq 'FAIL').Count
Write-HostLog "$RunName finished: $(@($rows).Count) gates, $failed FAIL, $(@($rows | Where-Object Status -eq 'NOT_RUN').Count) NOT_RUN"
if ($failed -gt 0 -or $timedOut -or -not $final.finishedUtc) { exit 1 }
exit 0
