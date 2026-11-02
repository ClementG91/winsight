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
    [Parameter(Mandatory)][string]$BootstrapReceipt,
    # Default locations, resolved below, are at the root of the volume this script runs from; pass a path to use another.
    [string]$Root,
    [string]$Name = 'WinSight-Qualification-HV',
    [string]$Checkpoint = 'S0-hyperv-autorun',
    [string]$RunName = ('hv-run-' + [DateTime]::Now.ToString('yyyyMMdd-HHmm', [Globalization.CultureInfo]::InvariantCulture)),
    # Gates to run (01 and99 mandatory). Empty = every gate except paired network gate36.
    [string[]]$Gates = @(),
    [ValidateRange(1,20160)][int]$TimeoutMinutes = 480,
    # Memory for this run only (0 = the checkpoint's own); the checkpoint restore at the end resets it.
    [int64]$MemoryBytes = 0,
    [string]$DriverHeartbeat,
    # Collect a run whose driver was closed while the VM kept going: wait for it to power off, then seal and restore.
    [switch]$Resume
)

# Do not resolve system cmdlets or Hyper-V through user-controlled module search directories.
$env:PSModulePath = [IO.Path]::Combine([Environment]::GetFolderPath('System'), 'WindowsPowerShell\v1.0\Modules')

# Resolved here rather than as parameter defaults: Windows PowerShell 5.1 leaves $PSScriptRoot
# empty in the defaults of an advanced script started with -File.
if (-not $Root) { $Root = (Join-Path ([IO.Path]::GetPathRoot($PSScriptRoot)) 'Hyper-V\WinSight-Qualification') }

$ErrorActionPreference = 'Stop'
$trustedHostLog = $false
function Write-FullFailure([string]$Phase, $Failure) {
    $message = '{0} failed (HRESULT 0x{1:X8}): {2}' -f $Phase,$Failure.Exception.HResult,$Failure.Exception.Message
    try { [Console]::Error.WriteLine($message) } catch { }
    try { Write-HostLog $message } catch { }
}
trap { Write-FullFailure 'qualification' $_; exit 1 }

# 'a,b' arrives as one string through powershell.exe -File; accept both forms.
$Gates = @($Gates | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
Import-Module Hyper-V
Import-Module (Join-Path $HarnessDir 'WinSightHyperV.psm1') -Force
Set-AdministratorsDefaultOwner
if ([IO.Path]::GetFullPath($Root).TrimEnd('\') -ceq [IO.Path]::GetPathRoot([IO.Path]::GetFullPath($Root)).TrimEnd('\')) { throw 'Qualification storage must be a dedicated directory, never a drive root.' }
foreach ($protected in $CandidateDir, $HarnessDir, $EvidenceRoot) { Assert-ProtectedPath -Path $protected }
Assert-ProtectedPath -Path $BootstrapReceipt
Assert-ProtectedPath -Path $Root -Recurse -AllowVirtualMachines
$data = Join-Path $Root 'data.vhdx'
$hostLog = Join-Path $EvidenceRoot 'host-operations.txt'
if ($DriverHeartbeat) { Assert-ProtectedPath -Path (Split-Path -Parent $DriverHeartbeat) }
Write-WinSightDriverHeartbeat -Path $DriverHeartbeat -Phase 'initializing'
function Write-HostLog([string]$Message) {
    $line = "$(Get-Date -Format o) [hyper-v] $Message"
    if ($trustedHostLog) { try { Add-SharedLine -Path $hostLog -Line $line } catch { try { [Console]::Error.WriteLine('Protected full host log unavailable; recovery continues.') } catch { } } }
    try { Write-Host $line } catch { }
}
$trustedHostLog = $true
function Restore-FullVm([switch]$CloseCampaign) {
    if ($CloseCampaign) { Confirm-WinSightQualificationSeal -RunDir $runDir }
    Invoke-WinSightVmRetry { Restore-VMCheckpoint -VMName $Name -Name $Checkpoint -Confirm:$false }
    Invoke-WinSightVmRetry { if ((Get-WinSightVmState $Name) -cne 'Off') { throw 'Full checkpoint recovery did not leave the VM Off.' } }
    if ($campaignLease -and $campaignLease.State.resources) {
        Invoke-WinSightVmRetry { if ((Get-VMMemory -VMName $Name).Startup -ne $campaignLease.State.resources.memory) { throw 'Full checkpoint memory was not restored.' } }
    }
    if ($CloseCampaign) { Close-WinSightCampaign -Lease $campaignLease -SealPath (Join-Path $runDir 'SHA256SUMS.txt') }
}

function Remove-DataDisk {
    $found = Remove-WinSightDataDisk -VMName $Name -Path $data
    if ($found) { Write-HostLog "$Name was $found, not off, when its data disk was detached: turned off" }
}

$runDir = Join-Path $EvidenceRoot $RunName
if ($RunName -notmatch '^[A-Za-z0-9][A-Za-z0-9-]{0,39}$') { throw 'Invalid full run name.' }
if (-not $Resume -and (Test-Path -LiteralPath $runDir)) { throw "Run $RunName already exists; choose a new name." }
if (-not $Resume -and (Get-WinSightVmState $Name) -ne 'Off') { throw 'The qualification VM must be Off before staging.' }
$candidate = Get-Content -LiteralPath (Join-Path $CandidateDir 'candidate.json') -Raw | ConvertFrom-Json
# Exact expected gates come from this protected guest harness, never from a possibly partial result.
$guestErrors = $null
$guestAst = [Management.Automation.Language.Parser]::ParseFile((Join-Path $HarnessDir 'guest\qualify.ps1'),[ref]$null,[ref]$guestErrors)
if ($guestErrors.Count) { throw 'Protected guest qualification script does not parse.' }
$knownGates = @($guestAst.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -ceq 'Invoke-Gate'},$true) |
    ForEach-Object { if ($_.CommandElements[1] -isnot [Management.Automation.Language.StringConstantExpressionAst]) { throw 'Unrecognized protected guest gate declaration.' }; $_.CommandElements[1].Value })
if ($knownGates.Count -eq 0) { throw 'The protected guest has no recognized qualification gates.' }
foreach ($gate in $Gates) { if ($gate -cnotin $knownGates -or $gate -ceq '36-ipc-network-logon') { throw 'Unknown or network-only gate; use the separate paired network campaign.' } }
# Gate36 requires the paired private-network/control contract. Default full covers every other gate.
$expectedGates = @($knownGates | Where-Object { $_ -cne '36-ipc-network-logon' -and ($Gates.Count -eq 0 -or $_ -cin $Gates -or $_ -cin @('01-identity-and-protected-root','99-residue')) })
$candidateManifest = @(Get-FileManifest $CandidateDir)
$harnessManifest = @(Get-FileManifest $HarnessDir)
$contract = [ordered]@{version=1;kind='qualification';runName=$RunName;evidenceRoot=[IO.Path]::GetFullPath($EvidenceRoot).TrimEnd('\').ToUpperInvariant();candidateDir=[IO.Path]::GetFullPath($CandidateDir).TrimEnd('\');harnessDir=[IO.Path]::GetFullPath($HarnessDir).TrimEnd('\');bootstrapReceipt=[IO.Path]::GetFullPath($BootstrapReceipt);candidateCommit=$candidate.commit;candidateDigest=(Get-WinSightTextDigest ($candidateManifest -join "`n"));harnessDigest=(Get-WinSightTextDigest ($harnessManifest -join "`n"));bootstrapDigest=(Get-FileHash -LiteralPath $BootstrapReceipt -Algorithm SHA256).Hash;vm=$Name;checkpoint=$Checkpoint;gates=$expectedGates;timeoutMinutes=$TimeoutMinutes;memoryBytes=$MemoryBytes}
$campaignLease = Enter-WinSightCampaign -Root $Root -Contract $contract -Resume:$Resume
$runState = [pscustomobject]@{runId=$campaignLease.RunId}
$statePath = Join-Path $EvidenceRoot "qualification-state-$RunName.json"
$startedPath = Join-Path $EvidenceRoot "qualification-started-$RunName.json"
$timeoutPath = Join-Path $EvidenceRoot "qualification-timeout-$RunName.json"
if ($Resume) {
    $persisted = (Read-WinSightBoundedText -Path $statePath)|ConvertFrom-Json
    $startReceipt = (Read-WinSightBoundedText -Path $startedPath)|ConvertFrom-Json
    if ($persisted.runId -cne $runState.runId -or $persisted.contractDigest -cne $campaignLease.State.contractDigest -or $startReceipt.runId -cne $runState.runId) { throw 'Full Resume has no matching committed staging; preserve transports and request owner recovery.' }
    Write-HostLog "$RunName resumed with its original protected candidate and deadline"
}
else {
    Write-WinSightAtomicText -Path $statePath -Text (@{runId=$runState.runId;contractDigest=$campaignLease.State.contractDigest}|ConvertTo-Json -Compress)
    Write-WinSightDriverHeartbeat -Path $DriverHeartbeat -Phase 'staging'
    Restore-VMCheckpoint -VMName $Name -Name $Checkpoint -Confirm:$false
    $campaignLease.State.resources = [pscustomobject]@{memory=[int64](Get-VMMemory -VMName $Name).Startup}
    Set-WinSightCampaignStage -Lease $campaignLease -Stage staging
    Remove-DataDisk
    $letter = Mount-WinSightData $data
    $stagingCompleted = $false
    try {
        Clear-WinSightDataVolume $letter
        $staged = "${letter}:\candidate"
        [void](New-Item -ItemType Directory -Path $staged)
        Copy-Item -Path (Join-Path $CandidateDir '*') -Destination $staged -Recurse
        foreach ($guestFile in 'qualify.ps1','operator-automation.ps1') { Copy-Item -LiteralPath (Join-Path $HarnessDir "guest\$guestFile") -Destination $staged }
        $candidateJson = Join-Path $staged 'candidate.json'
        $stagedCandidate = Get-Content -LiteralPath $candidateJson -Raw | ConvertFrom-Json
        $stagedCandidate | Add-Member -NotePropertyName gates -NotePropertyValue $expectedGates -Force
        $stagedCandidate | Add-Member -NotePropertyName qualificationRunId -NotePropertyValue $runState.runId -Force
        $stagedCandidate | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $candidateJson -Encoding UTF8
        Copy-Item -LiteralPath (Join-Path $HarnessDir 'guest\run-guest-checks.ps1') -Destination "${letter}:\run-guest-checks.ps1"
        'qualify' | Set-Content -LiteralPath "${letter}:\mode.txt"
        $stagingCompleted = $true
    }
    finally {
        try { Dismount-WinSightData $data }
        catch { Write-FullFailure 'staging-dismount' $_; if ($stagingCompleted) { throw } }
    }
    # Persist intent and original absolute deadline BEFORE attachment/resource changes or Start-VM.
    Set-WinSightCampaignStage -Lease $campaignLease -Stage starting -TimeoutMinutes $TimeoutMinutes
    Write-WinSightAtomicText -Path $startedPath -Text (@{runId=$runState.runId}|ConvertTo-Json -Compress)
    try {
        Add-VMHardDiskDrive -VMName $Name -Path $data
        if ($MemoryBytes -gt 0) { Set-VMMemory -VMName $Name -StartupBytes $MemoryBytes }
        $needed = [int64](Get-VMMemory -VMName $Name).Startup + 512MB
        Assert-WinSightHostMemory -Bytes $needed -Advice 'close applications or select an admitted VM memory budget'
        Write-WinSightDriverHeartbeat -Path $DriverHeartbeat -Phase 'starting'
        Start-VM -Name $Name
    }
    catch {
        $failure = $_; Write-FullFailure 'starting' $failure
        try { Remove-DataDisk } catch { Write-FullFailure 'detaching' $_ }
        try { Restore-FullVm } catch { Write-FullFailure 'restoring' $_ }
        throw $failure
    }
}
$started = Get-Date
$deadline = [DateTimeOffset]::Parse($campaignLease.State.deadlineUtc,[Globalization.CultureInfo]::InvariantCulture).UtcDateTime
while ((Get-WinSightVmState $Name) -ne 'Off' -and [DateTime]::UtcNow -lt $deadline) {
    Write-WinSightDriverHeartbeat -Path $DriverHeartbeat -Phase 'waiting'
    Start-Sleep -Seconds 60
}
$timedOut = [bool]$campaignLease.State.timedOut -or [bool]$campaignLease.State.observationIncomplete
if ((Get-WinSightVmState $Name) -ne 'Off') {
    Set-WinSightCampaignStage -Lease $campaignLease -Stage collecting -TimedOut
    if (-not $campaignLease.State.timedOut) { throw 'Timeout intent was not durably persisted.' }
    try { $timeoutReceipt = (Read-WinSightBoundedText $timeoutPath)|ConvertFrom-Json }
    catch [IO.FileNotFoundException] { Write-WinSightAtomicText -Path $timeoutPath -Text (@{runId=$runState.runId;reason='forced-timeout'}|ConvertTo-Json -Compress); $timeoutReceipt = [pscustomobject]@{runId=$runState.runId;reason='forced-timeout'} }
    if ($timeoutReceipt.runId -cne $runState.runId -or $timeoutReceipt.reason -cne 'forced-timeout') { throw 'Timeout evidence differs; preserve the active campaign.' }
    Stop-VM -Name $Name -TurnOff -Force
    $timedOut = $true
}
elseif ($Resume -and [DateTime]::UtcNow -gt $deadline -and $campaignLease.State.stage -cne 'collecting') {
    # No observation while the driver was absent can prove that Off happened inside the deadline.
    Set-WinSightCampaignStage -Lease $campaignLease -Stage collecting -ObservationIncomplete
    $timedOut = $true
}
if ((Get-WinSightVmState $Name) -ne 'Off') { throw 'VM stop was not confirmed; preserve the campaign and use its exact Resume.' }
Set-WinSightCampaignStage -Lease $campaignLease -Stage collecting

# --- Collect and seal (before independent restoration) -------------------------------------------------
$collectionFailure = $null; $fullResults = $null; $refused = @(); $collectionCompleted = $false
Remove-DataDisk
Write-WinSightDriverHeartbeat -Path $DriverHeartbeat -Phase 'collecting'
if (-not (Test-Path -LiteralPath $runDir)) { [void](New-Item -ItemType Directory -Path $runDir) }
Assert-ProtectedPath -Path $runDir
$letter = Mount-WinSightData $data
try {
    $refused = @(Copy-GuestResults -From "${letter}:\candidate\guest-results" -To $runDir -Resume:$Resume)
    if ($refused.Count -gt 0) { $refused | Set-Content -LiteralPath (Join-Path $runDir 'collection-refused.txt'); throw 'Guest evidence collection refused entries; preserve the campaign for exact Resume/owner recovery.' }
    $collectionCompleted = $true
}
catch { $collectionFailure = $_ }
finally {
    try { Dismount-WinSightData $data }
    catch { Write-FullFailure 'collection-dismount' $_; if (-not $collectionFailure) { $collectionFailure = $_ } }
}
if ($collectionFailure) { throw $collectionFailure }
if (-not $collectionCompleted) { throw 'Evidence collection did not complete.' }
$fullResults = Read-WinSightQualificationResult -Path (Join-Path $runDir 'results.json') -Commit $candidate.commit -RunId $runState.runId
if ($null -eq $fullResults) {
    Write-WinSightImmutableText -Path (Join-Path $runDir 'missing-results.json') -Text ([ordered]@{version=1;runId=$runState.runId;candidateCommit=$candidate.commit;status='NOT_RUN';reason='result-file-missing'}|ConvertTo-Json -Compress)
}
@("# harness $HarnessDir") + @(Get-FileManifest $HarnessDir) | Set-Content -LiteralPath (Join-Path $runDir 'provenance-harness.txt')
Copy-Item -LiteralPath $BootstrapReceipt -Destination (Join-Path $runDir 'provenance-bootstrap.json')
Copy-Item -LiteralPath $statePath -Destination (Join-Path $runDir 'provenance-qualification-state.json')
Copy-Item -LiteralPath $startedPath -Destination (Join-Path $runDir 'provenance-qualification-started.json')
@("# candidate $CandidateDir, claimed commit $($candidate.commit)") + @(Get-FileManifest $CandidateDir) | Set-Content -LiteralPath (Join-Path $runDir 'provenance-candidate.txt')
Write-WinSightQualificationSeal -RunDir $runDir
Write-HostLog "evidence sealed in $runDir"
Write-WinSightDriverHeartbeat -Path $DriverHeartbeat -Phase 'restoring'
Restore-FullVm -CloseCampaign

$resultsFile = Join-Path $runDir 'results.json'
$final = $fullResults
Write-WinSightDriverHeartbeat -Path $DriverHeartbeat -Phase 'finished'
if ($null -ne $final) {
    $final.gates.PSObject.Properties | ForEach-Object { [pscustomobject]@{Gate=$_.Name;Status=$_.Value.status;Seconds=$_.Value.seconds} } | Format-Table -AutoSize | Out-String | Write-Host
}
Write-HostLog "$RunName finished: mandatory gates require PASS and actual UTC completion"
exit (Get-WinSightQualificationExitCode -Result $final -Commit $candidate.commit -RunId $runState.runId -ExpectedGates $expectedGates -TimedOut $timedOut -RefusedCount $refused.Count)
