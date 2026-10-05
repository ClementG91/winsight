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
    [string]$DriverHeartbeat,
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
# Preserve the original error through recovery, but never let PowerShell's final formatter copy an
# arbitrary exception message (potentially fixture content) into the runner's readable stderr log.
trap { [Console]::Error.WriteLine('Network qualification failed; inspect the sanitized host operation diagnostics.'); exit 1 }
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
function Write-HostLog([string]$Message) {
    $line = "$(Get-Date -Format o) [network] $Message"
    try { Add-SharedLine -Path $hostLog -Line $line }
    catch { [Console]::Error.WriteLine('Network host log unavailable; recovery continues.') }
    Write-Host $line
}
function Write-SafeFailure([string]$Phase, $Failure) {
    if ($Phase -notin 'staging','starting','detaching','fixtures','restoring','observing','collect-target','collect-control','fixture-target','fixture-control','dismount-target','dismount-control') { $Phase = 'operation' }
    $exception = $Failure.Exception
    $type = if ($exception -is [IO.IOException]) { 'IOException' } elseif ($exception -is [UnauthorizedAccessException]) { 'UnauthorizedAccessException' } elseif ($exception -is [Runtime.InteropServices.COMException]) { 'COMException' } else { 'Exception' }
    $message = "$Phase failed ($type; HRESULT 0x{0:X8}); arbitrary error text omitted" -f $exception.HResult
    try { Write-HostLog $message } catch { [Console]::Error.WriteLine($message + '; host log unavailable, recovery continues') }
}
function Write-ResumeGuidance {
    $values = @((Join-Path $HarnessDir 'Invoke-HyperVNetworkLogon.ps1'), $CandidateDir, $HarnessDir, $EvidenceRoot, $BootstrapReceipt, $Root, $Name, $ControlName, $Checkpoint, $ControlCheckpoint, $Switch, $RunName) |
        ForEach-Object { "'" + ([string]$_).Replace("'", "''") + "'" }
    $message = "campaign preserved; resume with: powershell.exe -NoProfile -NonInteractive -File {0} -CandidateDir {1} -HarnessDir {2} -EvidenceRoot {3} -BootstrapReceipt {4} -Root {5} -Name {6} -ControlName {7} -Checkpoint {8} -ControlCheckpoint {9} -Switch {10} -RunName {11} -Resume" -f $values
    try { Write-HostLog $message } catch { [Console]::Error.WriteLine($message) }
}
if ($DriverHeartbeat) { Assert-ProtectedPath -Path (Split-Path -Parent $DriverHeartbeat) }
Write-WinSightDriverHeartbeat -Path $DriverHeartbeat -Phase 'initializing'
if ($RunName -notmatch '^[A-Za-z0-9][A-Za-z0-9-]{0,39}$') { throw 'Invalid network run name.' }
$candidate = Get-Content -LiteralPath (Join-Path $CandidateDir 'candidate.json') -Raw | ConvertFrom-Json
$candidateManifest = @(Get-FileManifest $CandidateDir)
$harnessManifest = @(Get-FileManifest $HarnessDir)
$bootstrapSha256 = (Get-FileHash -LiteralPath $BootstrapReceipt -Algorithm SHA256).Hash
$statePath = Join-Path $EvidenceRoot "network-state-$RunName.json"
$startedPath = Join-Path $EvidenceRoot "network-started-$RunName.json"
$timeoutPath = Join-Path $EvidenceRoot "network-timeout-$RunName.json"
$runDir = Join-Path $EvidenceRoot $RunName
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
        $current = Invoke-WinSightVmRetry { Get-VMNetworkAdapter -VMName $Name -Name $adapter.Name }
        if ([string]$current.SwitchName -cne [string]$adapter.SwitchName) {
            Invoke-WinSightVmRetry {
                if ($adapter.SwitchName) { Connect-VMNetworkAdapter -VMName $Name -Name $adapter.Name -SwitchName $adapter.SwitchName }
                else { Disconnect-VMNetworkAdapter -VMName $Name -Name $adapter.Name }
            }
        }
        Invoke-WinSightVmRetry { if ([string](Get-VMNetworkAdapter -VMName $Name -Name $adapter.Name).SwitchName -cne [string]$adapter.SwitchName) { throw 'Recorded target adapter configuration was not restored.' } }
    }
    Invoke-WinSightVmRetry { if ($originalMemory -gt 0 -and (Get-VMMemory -VMName $Name).Startup -ne $originalMemory) { Set-VMMemory -VMName $Name -StartupBytes $originalMemory } }
    Invoke-WinSightVmRetry { if ($originalControlMemory -gt 0 -and (Get-VMMemory -VMName $ControlName).Startup -ne $originalControlMemory) { Set-VMMemory -VMName $ControlName -StartupBytes $originalControlMemory } }
}
$network = [ordered]@{
    targetAddress = '192.168.250.10'; controlAddress = '192.168.250.20'; prefixLength = 24; httpPort = 8088
    targetMac = '00155D5AFA10'; controlMac = '00155D5AFA20'
}

if (-not $Resume) {
if ((Test-Path -LiteralPath $runDir) -or (Test-Path -LiteralPath $statePath)) { throw 'Network run already exists; use its Resume path or choose a new name.' }
foreach ($vm in $Name, $ControlName) { if ((Get-WinSightVmState $vm) -ne 'Off') { throw "VM $vm is $(Get-WinSightVmState $vm); turn it off first." } }
$privateSwitch = Get-VMSwitch -Name $Switch -ErrorAction SilentlyContinue
if (-not $privateSwitch -or $privateSwitch.SwitchType -ne 'Private') { throw 'Network qualification requires an existing Private VM-only switch.' }
# Both VMs start together. This is checked before anything changes: in the first network run the
# target started, the control could not get its memory, and the target stayed on with its run staged.
Assert-WinSightHostMemory -Bytes ($TargetMemoryBytes + $ControlMemoryBytes + 512MB) -Advice 'close applications on the host, or ask for less memory for the target ("memoryGB":3).'
# --- Stage both data disks --------------------------------------------------------------------------
Restore-VMCheckpoint -VMName $Name -Name $Checkpoint -Confirm:$false
Restore-VMCheckpoint -VMName $ControlName -Name $ControlCheckpoint -Confirm:$false
$originalAdapters = @(Invoke-WinSightVmRetry { Get-VMNetworkAdapter -VMName $Name | Where-Object Name -ne 'WinSightPrivate' | Select-Object Name, SwitchName })
$originalMemory = Invoke-WinSightVmRetry { (Get-VMMemory -VMName $Name).Startup }
$originalControlMemory = Invoke-WinSightVmRetry { (Get-VMMemory -VMName $ControlName).Startup }
$runState = [ordered]@{ version = 1; runId = [Guid]::NewGuid().ToString('D'); candidateCommit = $candidate.commit; candidateManifest = $candidateManifest; harnessManifest = $harnessManifest; bootstrapSha256 = $bootstrapSha256; automatic = [bool]$AutomaticCredential; root = $Root; target = $Name; control = $ControlName; checkpoint = $Checkpoint; controlCheckpoint = $ControlCheckpoint; adapters = $originalAdapters; memory = $originalMemory; controlMemory = $originalControlMemory }
$stateBytes = (New-Object Text.UTF8Encoding $false).GetBytes(($runState | ConvertTo-Json -Depth 6))
$stateStream = New-Object IO.FileStream($statePath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
try { $stateStream.Write($stateBytes, 0, $stateBytes.Length); $stateStream.Flush($true) } finally { $stateStream.Dispose() }
Remove-DataDisks
Write-WinSightDriverHeartbeat -Path $DriverHeartbeat -Phase 'staging'
$envelope = if ($AutomaticCredential) { New-NetworkProbeEnvelope } else { $null }
$network.qualificationRunId = $runState.runId
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
    $candidate | Add-Member -NotePropertyName qualificationRunId -NotePropertyValue $runState.runId -Force
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
    $failure = $_
    Write-SafeFailure 'staging' $failure
    if ($AutomaticCredential) { try { Remove-StagedNetworkFixtures } catch { Write-SafeFailure 'fixtures' $_ } }
    try { Restore-BothVms } catch { Write-SafeFailure 'restoring' $_ }
    throw $failure
}
finally { $envelope = $null }

# --- Wire the target to the private switch only, for this run -------------------------------------
try {
    Write-WinSightDriverHeartbeat -Path $DriverHeartbeat -Phase 'starting'
    # Only published after both data volumes were formatted and staged. A Resume without this
    # receipt must not attribute old on-disk results to a new run whose staging never completed.
    $startedBytes = (New-Object Text.UTF8Encoding $false).GetBytes((@{ runId = $runState.runId } | ConvertTo-Json))
    $startedStream = New-Object IO.FileStream($startedPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try { $startedStream.Write($startedBytes, 0, $startedBytes.Length); $startedStream.Flush($true) } finally { $startedStream.Dispose() }
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
    Write-SafeFailure 'starting' $failure
    try { Remove-DataDisks } catch { Write-SafeFailure 'detaching' $_ }
    if ($AutomaticCredential) { try { Remove-StagedNetworkFixtures } catch { Write-SafeFailure 'fixtures' $_ } }
    try { Restore-BothVms } catch { Write-SafeFailure 'restoring' $_ }
    try { Write-HostLog "$RunName failed before observation; independent detachment, cleanup and restoration attempts recorded" } catch { Write-SafeFailure 'starting' $_ }
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
    Assert-ProtectedPath -Path $statePath
    $runState = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    if ($runState.version -ne 1 -or $runState.candidateCommit -cne $candidate.commit -or
        (@($runState.candidateManifest) -join "`n") -cne ($candidateManifest -join "`n") -or
        (@($runState.harnessManifest) -join "`n") -cne ($harnessManifest -join "`n") -or $runState.bootstrapSha256 -cne $bootstrapSha256 -or
        $runState.root -cne $Root -or $runState.target -cne $Name -or $runState.control -cne $ControlName -or
        $runState.checkpoint -cne $Checkpoint -or $runState.controlCheckpoint -cne $ControlCheckpoint) {
        throw 'Resume identity mismatch; campaign preserved, use its original protected candidate and run state.'
    }
    Assert-ProtectedPath -Path $startedPath
    $startedReceipt = Get-Content -LiteralPath $startedPath -Raw | ConvertFrom-Json
    if ($runState.runId -notmatch '^[0-9a-f-]{36}$' -or $startedReceipt.runId -cne $runState.runId) { throw 'No matching staged network campaign; preserve the disks and inspect the original run state.' }
    $originalAdapters = @($runState.adapters)
    $originalMemory = [int64]$runState.memory
    $originalControlMemory = [int64]$runState.controlMemory
    $AutomaticCredential = [bool]$runState.automatic
    Write-HostLog "$RunName resumed with its original candidate and checkpoint configuration"
}

$safeToRestore = $false
$primaryFailure = $null
try {
$started = Get-Date
$deadline = $started.AddMinutes($TimeoutMinutes)
while ($true) {
    Write-WinSightDriverHeartbeat -Path $DriverHeartbeat -Phase 'observing'
    $targetState = Invoke-WinSightVmRetry { Get-WinSightVmState $Name }
    $controlState = Invoke-WinSightVmRetry { Get-WinSightVmState $ControlName }
    if (($targetState -eq 'Off' -and $controlState -eq 'Off') -or (Get-Date) -ge $deadline) { break }
    Start-Sleep -Seconds 30
    Write-Host ("  running {0:N0} min (target {1}, control {2})" -f ((Get-Date) - $started).TotalMinutes, $targetState, $controlState)
}
$timedOut = $false
if (Test-Path -LiteralPath $timeoutPath) {
    Assert-ProtectedPath -Path $timeoutPath
    $timeoutReceipt = Get-Content -LiteralPath $timeoutPath -Raw | ConvertFrom-Json
    if ($timeoutReceipt.version -ne 1 -or $timeoutReceipt.runId -cne $runState.runId -or $timeoutReceipt.reason -cne 'forced-timeout') { throw 'Network timeout receipt mismatch; preserve the campaign for inspection.' }
    $timedOut = $true
}
foreach ($vm in $Name, $ControlName) {
    if ((Invoke-WinSightVmRetry { Get-WinSightVmState $vm }) -ne 'Off') {
        if (-not $timedOut) {
            # Record the intent before forcing shutdown. A failed stop, collection or driver crash
            # must not turn this run into a PASS when a subsequent Resume observes both VMs Off.
            $timeoutBytes = (New-Object Text.UTF8Encoding $false).GetBytes((@{ version = 1; runId = $runState.runId; reason = 'forced-timeout' } | ConvertTo-Json))
            $timeoutStream = New-Object IO.FileStream($timeoutPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
            try { $timeoutStream.Write($timeoutBytes, 0, $timeoutBytes.Length); $timeoutStream.Flush($true) } finally { $timeoutStream.Dispose() }
            $timedOut = $true
        }
        Stop-VM -Name $vm -TurnOff -Force
        Write-HostLog "timeout: $vm turned off"
    }
    if ((Invoke-WinSightVmRetry { Get-WinSightVmState $vm }) -ne 'Off') { throw 'VM shutdown not confirmed; campaign preserved.' }
}

# --- Collect and seal both evidence sets, then restore ---------------------------------------------
Remove-DataDisks
$runDir = Join-Path $EvidenceRoot $RunName
if (-not $Resume -and (Test-Path -LiteralPath $runDir)) { throw "Run $RunName already exists; choose a new name." }
foreach ($side in 'target', 'control') {
    $sideDir = Join-Path $runDir $side
    if (-not (Test-Path -LiteralPath $sideDir)) { New-Item -ItemType Directory -Path $sideDir -Force | Out-Null }
}
Assert-ProtectedPath -Path $runDir -Recurse
$mounted = @()
$refused = @()
$collectionFailure = $null
$cleanupFailure = $null
Write-WinSightDriverHeartbeat -Path $DriverHeartbeat -Phase 'collecting'
try {
    foreach ($side in @(@{ name = 'target'; disk = $data; source = 'candidate\guest-results' }, @{ name = 'control'; disk = $controlData; source = 'control-results' })) {
        try {
            $letter = Mount-WinSightData $side.disk
            $mounted += @{ name = $side.name; disk = $side.disk; letter = $letter }
            $refused += @(Copy-GuestResults -From ("${letter}:\" + $side.source) -To (Join-Path $runDir $side.name) -Resume:$Resume)
        }
        catch { if (-not $collectionFailure) { $collectionFailure = $_ }; Write-SafeFailure ("collect-" + $side.name) $_ }
    }
    # Both evidence copies are attempted before cleanup. Reuse these mounts, including when the
    # first copy or fixture removal fails; interactive runs never have staged host fixtures.
    if ($AutomaticCredential) {
        foreach ($side in $mounted) {
            try { Remove-NetworkProbeFixture -Path ("$($side.letter):\network-credential.json") }
            catch { if (-not $cleanupFailure) { $cleanupFailure = $_ }; Write-SafeFailure ("fixture-" + $side.name) $_ }
        }
    }
}
finally {
    foreach ($side in $mounted) {
        try { Dismount-WinSightData $side.disk }
        catch { if (-not $cleanupFailure) { $cleanupFailure = $_ }; Write-SafeFailure ("dismount-" + $side.name) $_ }
    }
}
if ($collectionFailure) { throw $collectionFailure }
$targetResults = Get-Content -LiteralPath (Join-Path $runDir 'target\results.json') -Raw | ConvertFrom-Json
$controlResults = Get-Content -LiteralPath (Join-Path $runDir 'control\control-result.json') -Raw | ConvertFrom-Json
if ($targetResults.candidate.commit -cne $candidate.commit -or $targetResults.candidate.qualificationRunId -cne $runState.runId -or
    $controlResults.qualificationRunId -cne $runState.runId) { throw 'Collected guest results do not identify this exact candidate and network campaign; evidence preserved without attribution.' }
if ($refused.Count -gt 0) { $refused | Set-Content -LiteralPath (Join-Path $runDir 'collection-refused.txt') }
@("# harness $HarnessDir") + @(Get-FileManifest $HarnessDir) | Set-Content -LiteralPath (Join-Path $runDir 'provenance-harness.txt')
Copy-Item -LiteralPath $BootstrapReceipt -Destination (Join-Path $runDir 'provenance-bootstrap.json')
Copy-Item -LiteralPath $statePath -Destination (Join-Path $runDir 'provenance-network-state.json')
Copy-Item -LiteralPath $startedPath -Destination (Join-Path $runDir 'provenance-network-started.json')
if ($timedOut) { Copy-Item -LiteralPath $timeoutPath -Destination (Join-Path $runDir 'provenance-network-timeout.json') }
@("# candidate $CandidateDir, claimed commit $($candidate.commit)") + @(Get-FileManifest $CandidateDir) |
    Set-Content -LiteralPath (Join-Path $runDir 'provenance-candidate.txt')
Get-ChildItem -LiteralPath $runDir -Recurse -File | Where-Object Name -ne 'SHA256SUMS.txt' | Sort-Object FullName |
    ForEach-Object { "$((Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash)  $($_.FullName.Substring($runDir.Length + 1))" } |
    Set-Content -LiteralPath (Join-Path $runDir 'SHA256SUMS.txt')
$safeToRestore = $true
try { Write-HostLog "evidence sealed in $runDir" } catch { Write-SafeFailure 'observing' $_ }
if ($cleanupFailure) { throw $cleanupFailure }
}
catch { $primaryFailure = $_; Write-SafeFailure 'observing' $_ }
finally {
    if ($safeToRestore) {
        Write-WinSightDriverHeartbeat -Path $DriverHeartbeat -Phase 'restoring'
        try { Restore-BothVms }
        catch { if (-not $primaryFailure) { $primaryFailure = $_ }; Write-SafeFailure 'restoring' $_ }
    }
    else { Write-ResumeGuidance }
}
if ($primaryFailure) { throw $primaryFailure }
Write-WinSightDriverHeartbeat -Path $DriverHeartbeat -Phase 'finished'
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
