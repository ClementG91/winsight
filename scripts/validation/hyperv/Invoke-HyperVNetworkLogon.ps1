#Requires -RunAsAdministrator
# HOST, elevated: gate 36 (IPC by network logon, kit section 7) with two Hyper-V VMs on the private
# switch. The target runs the harness with gate 36 only; the control VM logs on to it over WinRM
# HTTPS with a disposable standard account.
#
# By default THE OPERATOR types one disposable password twice, in each VM's credential dialog:
# first on the target (it creates the account), then on the control (it logs on with it). Nothing on
# the host sees it, and both VMs are restored to their clean checkpoints afterwards, so the account,
# the listener and the certificate never outlive the run. -AutomaticCredential instead generates
# a new test-only password and stages ACL-protected, consumed fixtures on the offline VM disks.
#
# RA-01: started by WinSightQualRunner.ps1 from its protected copies; both data disks are emptied by
# formatting, results are copied without entering a reparse point into a new protected run directory.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$CandidateDir,
    [Parameter(Mandatory)][string]$HarnessDir,
    [Parameter(Mandatory)][string]$EvidenceRoot,
    [Parameter(Mandatory)][string]$BootstrapReceipt,
    [string]$Name = 'WinSight-Qualification-HV',
    [string]$ControlName = 'WinSight-Control-HV',
    # Default locations, resolved below, are at the root of the volume this script runs from; pass a path to use another.
    [string]$Root,
    [string]$Checkpoint = 'S0-hyperv-autorun',
    [string]$ControlCheckpoint = 'C0-control',
    [string]$Switch = 'WinSight-Qual-Private',
    [string]$RunName = ('hv-network-' + [DateTime]::Now.ToString('yyyyMMdd-HHmm', [Globalization.CultureInfo]::InvariantCulture)),
    [int64]$TargetMemoryBytes = 4GB,
    # The control only logs on over the network. It runs with less memory than it was built with
    # (3 GB), so that both VMs fit in the host's memory together.
    [int64]$ControlMemoryBytes = 2GB,
    [int]$TimeoutMinutes = 120,
    [switch]$AutomaticCredential,
    # Collect a run whose driver was closed while both VMs kept going: wait for both to power off,
    # then collect, seal and restore. Nothing is staged or started.
    [switch]$Resume
)

# Do not resolve system cmdlets or Hyper-V through user-controlled module search directories.
$env:PSModulePath = [IO.Path]::Combine([Environment]::GetFolderPath('System'), 'WindowsPowerShell\v1.0\Modules')

# Resolved here rather than as parameter defaults: Windows PowerShell 5.1 leaves $PSScriptRoot
# empty in the defaults of an advanced script started with -File.
if (-not $Root) { $Root = (Join-Path ([IO.Path]::GetPathRoot($PSScriptRoot)) 'Hyper-V\WinSight-Qualification') }

$ErrorActionPreference = 'Stop'
Import-Module Hyper-V
Import-Module (Join-Path $HarnessDir 'WinSightHyperV.psm1') -Force
Import-Module (Join-Path $HarnessDir 'guest\NetworkProbeCredential.psm1') -Force
Set-AdministratorsDefaultOwner
foreach ($protected in $CandidateDir, $HarnessDir, $EvidenceRoot) { Assert-ProtectedPath -Path $protected }
Assert-ProtectedPath -Path $BootstrapReceipt
Assert-ProtectedPath -Path $Root -Recurse -AllowVirtualMachines
$data = Join-Path $Root 'data.vhdx'
$controlData = Join-Path $Root 'control-data.vhdx'
$hostLog = Join-Path $EvidenceRoot 'host-operations.txt'
function Write-HostLog([string]$Message) { $line = "$(Get-Date -Format o) [network] $Message"; Add-SharedLine -Path $hostLog -Line $line; Write-Host $line }
function Remove-DataDisks {
    $failures = @()
    try {
        $found = Remove-WinSightDataDisk -VMName $Name -Path $data
        if ($found) { Write-HostLog "$Name was $found, not off, when its data disk was detached: turned off" }
    }
    catch { $failures += 'target data disk' }
    try {
        $found = Remove-WinSightDataDisk -VMName $ControlName -Path $controlData
        if ($found) { Write-HostLog "$ControlName was $found, not off, when its data disk was detached: turned off" }
    }
    catch { $failures += 'control data disk' }
    if ($failures.Count) { throw ('Data disk detachment failed for: ' + ($failures -join ', ')) }
}
function Remove-StagedNetworkFixtures {
    $failures = @()
    foreach ($disk in $data, $controlData) {
        try {
            $cleanupLetter = Mount-WinSightData $disk
            try { Remove-NetworkProbeFixture -Path "${cleanupLetter}:\network-credential.json" }
            finally { Dismount-WinSightData $disk }
        }
        catch { $failures += [IO.Path]::GetFileName($disk) }
    }
    if ($failures.Count) { throw ('Disposable fixture cleanup failed for: ' + ($failures -join ', ')) }
}
# Puts both VMs back as they were: their checkpoints, the target's own network instead of the private
# switch, and the memory each had.
function Restore-BothVms {
    $failures = @()
    try { Restore-VMCheckpoint -VMName $Name -Name $Checkpoint -Confirm:$false }
    catch { $failures += 'target checkpoint' }
    try { Restore-VMCheckpoint -VMName $ControlName -Name $ControlCheckpoint -Confirm:$false }
    catch { $failures += 'control checkpoint' }
    if ($failures.Count) { throw ('VM restoration failed for: ' + ($failures -join ', ')) }
    # The checkpoint restores the configuration too. This only makes sure, since the full
    # qualification needs the target's own network (gates 23 and 33). Each query is retried: right
    # after a restore, Hyper-V can answer "object not found" for a moment.
    Invoke-WinSightVmRetry { Get-VMNetworkAdapter -VMName $Name | Where-Object Name -eq 'WinSightPrivate' | Remove-VMNetworkAdapter }
    foreach ($adapter in $originalAdapters) {
        Invoke-WinSightVmRetry { if ($adapter.SwitchName -and -not (Get-VMNetworkAdapter -VMName $Name -Name $adapter.Name).SwitchName) { Connect-VMNetworkAdapter -VMName $Name -Name $adapter.Name -SwitchName $adapter.SwitchName } }
    }
    Invoke-WinSightVmRetry { if ($originalMemory -gt 0 -and (Get-VMMemory -VMName $Name).Startup -ne $originalMemory) { Set-VMMemory -VMName $Name -StartupBytes $originalMemory } }
    Invoke-WinSightVmRetry { if ($originalControlMemory -gt 0 -and (Get-VMMemory -VMName $ControlName).Startup -ne $originalControlMemory) { Set-VMMemory -VMName $ControlName -StartupBytes $originalControlMemory } }
}
$network = [ordered]@{
    targetAddress = '192.168.250.10'; controlAddress = '192.168.250.20'; prefixLength = 24; httpPort = 8088
    targetMac = '00155D5AFA10'; controlMac = '00155D5AFA20'
}

if (-not $Resume) {
foreach ($vm in $Name, $ControlName) { if ((Get-WinSightVmState $vm) -ne 'Off') { throw "VM $vm is $(Get-WinSightVmState $vm); turn it off first." } }
$privateSwitch = Get-VMSwitch -Name $Switch -ErrorAction SilentlyContinue
if (-not $privateSwitch -or $privateSwitch.SwitchType -ne 'Private') { throw 'Network qualification requires an existing Private VM-only switch.' }
# Both VMs start together. This is checked before anything changes: in the first network run the
# target started, the control could not get its memory, and the target stayed on with its run staged.
Assert-WinSightHostMemory -Bytes ($TargetMemoryBytes + $ControlMemoryBytes + 512MB) -Advice 'close applications on the host, or ask for less memory for the target ("memoryGB":3).'
$originalAdapters = @(Get-VMNetworkAdapter -VMName $Name | Where-Object Name -ne 'WinSightPrivate' | Select-Object Name, SwitchName)
$originalMemory = (Get-VMMemory -VMName $Name).Startup
$originalControlMemory = (Get-VMMemory -VMName $ControlName).Startup

# --- Stage both data disks --------------------------------------------------------------------------
Restore-VMCheckpoint -VMName $Name -Name $Checkpoint -Confirm:$false
Restore-VMCheckpoint -VMName $ControlName -Name $ControlCheckpoint -Confirm:$false
Remove-DataDisks
$envelope = if ($AutomaticCredential) { New-NetworkProbeEnvelope } else { $null }
if ($AutomaticCredential) { $network.credentialMode = 'automatic' }
try {
$letter = Mount-WinSightData $data
try {
    Clear-WinSightDataVolume $letter
    if ($AutomaticCredential) { Set-NetworkProbeVolumeProtection -Root "${letter}:\" }
    $staged = "${letter}:\candidate"
    New-Item -ItemType Directory -Path $staged | Out-Null
    Get-ChildItem -LiteralPath $CandidateDir | Where-Object Name -ne 'previous' |
        ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $staged -Recurse }
    foreach ($guestFile in 'qualify.ps1', 'operator-automation.ps1', 'NetworkProbeCredential.psm1') {
        Copy-Item -LiteralPath (Join-Path $HarnessDir "guest\$guestFile") -Destination $staged
    }
    $candidateJson = Join-Path $staged 'candidate.json'
    $candidate = Get-Content -LiteralPath $candidateJson -Raw | ConvertFrom-Json
    $candidate.PSObject.Properties.Remove('gates')
    $candidate | Add-Member -NotePropertyName gates -NotePropertyValue @('36-ipc-network-logon', '99-residue')
    $candidate | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $candidateJson -Encoding UTF8
    $network | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $staged 'network.json') -Encoding UTF8
    if ($AutomaticCredential) { Write-NetworkProbeFixture -Path "${letter}:\network-credential.json" -Envelope $envelope }
    Copy-Item -LiteralPath (Join-Path $HarnessDir 'guest\run-guest-checks.ps1') -Destination "${letter}:\run-guest-checks.ps1"
    'qualify' | Set-Content -LiteralPath "${letter}:\mode.txt"
}
finally { Dismount-WinSightData $data }
$letter = Mount-WinSightData $controlData
try {
    Clear-WinSightDataVolume $letter
    if ($AutomaticCredential) { Set-NetworkProbeVolumeProtection -Root "${letter}:\" }
    Copy-Item -LiteralPath (Join-Path $HarnessDir 'guest\run-guest-checks.ps1'), (Join-Path $HarnessDir 'guest\control-network-logon.ps1'), (Join-Path $HarnessDir 'guest\NetworkProbeCredential.psm1') -Destination "${letter}:\"
    $network | ConvertTo-Json | Set-Content -LiteralPath "${letter}:\network.json" -Encoding UTF8
    if ($AutomaticCredential) { Write-NetworkProbeFixture -Path "${letter}:\network-credential.json" -Envelope $envelope }
    'control' | Set-Content -LiteralPath "${letter}:\mode.txt"
}
finally { Dismount-WinSightData $controlData }
}
catch {
    try { Remove-StagedNetworkFixtures }
    finally { Restore-BothVms }
    throw 'Network staging failed; cleanup and restoration were attempted.'
}
finally { $envelope = $null }

# --- Wire the target to the private switch only, for this run -------------------------------------
try {
    Get-VMNetworkAdapter -VMName $Name | Where-Object Name -ne 'WinSightPrivate' | Disconnect-VMNetworkAdapter
    Get-VMNetworkAdapter -VMName $Name | Where-Object Name -eq 'WinSightPrivate' | Remove-VMNetworkAdapter
    Add-VMNetworkAdapter -VMName $Name -Name 'WinSightPrivate' -SwitchName $Switch -StaticMacAddress $network.targetMac
    Set-VMMemory -VMName $Name -StartupBytes $TargetMemoryBytes
    Set-VMMemory -VMName $ControlName -StartupBytes $ControlMemoryBytes
    Add-VMHardDiskDrive -VMName $Name -Path $data
    Add-VMHardDiskDrive -VMName $ControlName -Path $controlData
    Write-HostLog ("$RunName on $($candidate.commit.Substring(0, 7)): target $Name ({0:N1} GB) + control $ControlName ({1:N1} GB) on $Switch" -f ($TargetMemoryBytes / 1GB), ($ControlMemoryBytes / 1GB))
    Start-VM -Name $Name
    Start-VM -Name $ControlName
}
catch {
    # Half a run - one VM on, or the target rewired - waits for nobody. Turn both off, put both back,
    # then fail with the cause.
    $failure = $_
    Write-HostLog "$RunName did not start: $($failure.Exception.Message)"
    try {
        try { Remove-DataDisks }
        finally { Remove-StagedNetworkFixtures }
    }
    finally { Restore-BothVms }
    Write-HostLog "$RunName stopped before it began, both VMs off and restored ($Checkpoint, $ControlCheckpoint)"
    throw $failure
}
if ($AutomaticCredential) {
    Write-HostLog 'automatic disposable credentials staged; no operator password dialog required'
}
else {
Write-Host ''
Write-Host '================================================================================' -ForegroundColor Yellow
Write-Host ' Both VMs are starting. Open their screens:' -ForegroundColor Yellow
Write-Host "   vmconnect.exe localhost `"$Name`"" -ForegroundColor Yellow
Write-Host "   vmconnect.exe localhost `"$ControlName`"" -ForegroundColor Yellow
Write-Host ' 1. On the TARGET, a Windows credential dialog asks for a password for WinSightNetworkProbe' -ForegroundColor Yellow
Write-Host '    (after a few minutes of staging). Type a disposable one you will not reuse anywhere.' -ForegroundColor Yellow
Write-Host ' 2. Then on the CONTROL, a second dialog asks for it: type the same password.' -ForegroundColor Yellow
Write-Host ' Both VMs shut themselves down when done; this window then collects and seals the evidence.' -ForegroundColor Yellow
Write-Host '================================================================================' -ForegroundColor Yellow
vmconnect.exe localhost $Name
vmconnect.exe localhost $ControlName
}
}
else {
    # The disconnected adapters are the VM's own, on the Default Switch it was built with.
    $originalAdapters = @(Get-VMNetworkAdapter -VMName $Name | Where-Object Name -ne 'WinSightPrivate' | ForEach-Object { [pscustomobject]@{ Name = $_.Name; SwitchName = 'Default Switch' } })
    $originalMemory = 0
    $originalControlMemory = 0
    Write-HostLog "$RunName resumed: target $(Get-WinSightVmState $Name), control $(Get-WinSightVmState $ControlName)"
}

try {
$started = Get-Date
$deadline = $started.AddMinutes($TimeoutMinutes)
while (((Get-WinSightVmState $Name) -ne 'Off' -or (Get-WinSightVmState $ControlName) -ne 'Off') -and (Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 30
    Write-Host ("  running {0:N0} min (target {1}, control {2})" -f ((Get-Date) - $started).TotalMinutes, (Get-WinSightVmState $Name), (Get-WinSightVmState $ControlName))
}
$timedOut = $false
foreach ($vm in $Name, $ControlName) {
    if ((Get-WinSightVmState $vm) -ne 'Off') { Stop-VM -Name $vm -TurnOff -Force; $timedOut = $true; Write-HostLog "timeout: $vm turned off" }
}

# --- Collect and seal both evidence sets, then restore ---------------------------------------------
Remove-DataDisks
Remove-StagedNetworkFixtures
$runDir = Join-Path $EvidenceRoot $RunName
if (-not $Resume -and (Test-Path -LiteralPath $runDir)) { throw "Run $RunName already exists; choose a new name." }
foreach ($side in 'target', 'control') {
    $sideDir = Join-Path $runDir $side
    if (-not (Test-Path -LiteralPath $sideDir)) { New-Item -ItemType Directory -Path $sideDir -Force | Out-Null }
}
Assert-ProtectedPath -Path $runDir -Recurse
$letter = Mount-WinSightData $data
try {
    $refused = @(Copy-GuestResults -From "${letter}:\candidate\guest-results" -To (Join-Path $runDir 'target'))
}
finally { Dismount-WinSightData $data }
$letter = Mount-WinSightData $controlData
try {
    $refused += @(Copy-GuestResults -From "${letter}:\control-results" -To (Join-Path $runDir 'control'))
}
finally { Dismount-WinSightData $controlData }
if ($refused.Count -gt 0) { $refused | Set-Content -LiteralPath (Join-Path $runDir 'collection-refused.txt') }
@("# harness $HarnessDir") + @(Get-FileManifest $HarnessDir) | Set-Content -LiteralPath (Join-Path $runDir 'provenance-harness.txt')
Copy-Item -LiteralPath $BootstrapReceipt -Destination (Join-Path $runDir 'provenance-bootstrap.json')
@("# candidate $CandidateDir, claimed commit $($candidate.commit)") + @(Get-FileManifest $CandidateDir) |
    Set-Content -LiteralPath (Join-Path $runDir 'provenance-candidate.txt')
Get-ChildItem -LiteralPath $runDir -Recurse -File | Where-Object Name -ne 'SHA256SUMS.txt' | Sort-Object FullName |
    ForEach-Object { "$((Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash)  $($_.FullName.Substring($runDir.Length + 1))" } |
    Set-Content -LiteralPath (Join-Path $runDir 'SHA256SUMS.txt')
Write-HostLog "evidence sealed in $runDir"
}
finally {
    # Idempotent recovery also covers an exception while querying the running VMs or collecting.
    try {
        try { Remove-DataDisks }
        finally { Remove-StagedNetworkFixtures }
    }
    finally { Restore-BothVms }
}
Write-HostLog "both VMs restored ($Checkpoint, $ControlCheckpoint), target network: $(Invoke-WinSightVmRetry { (Get-VMNetworkAdapter -VMName $Name | ForEach-Object { "$($_.Name)=$($_.SwitchName)" }) -join ', ' })"

$resultsFile = Join-Path $runDir 'target\results.json'
if (-not (Test-Path -LiteralPath $resultsFile)) { Write-Warning 'No target results.json.'; exit 2 }
$final = Get-Content -LiteralPath $resultsFile -Raw | ConvertFrom-Json
$final.gates.PSObject.Properties | ForEach-Object { [pscustomobject]@{ Gate = $_.Name; Status = $_.Value.status; Seconds = $_.Value.seconds } } |
    Format-Table -AutoSize | Out-String | Write-Host
$control = Join-Path $runDir 'control\control-result.json'
if (Test-Path -LiteralPath $control) { Write-Host "control: $((Get-Content -LiteralPath $control -Raw | ConvertFrom-Json).status)" }
$gate = $final.gates.'36-ipc-network-logon'.status
Write-HostLog "$RunName finished: gate 36 $gate"
if ($gate -ne 'PASS' -or $timedOut) { exit 1 }
exit 0
