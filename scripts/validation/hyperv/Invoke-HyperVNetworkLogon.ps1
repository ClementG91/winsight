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

$ErrorActionPreference = 'Stop'
$env:PSModulePath = [IO.Path]::Combine([Environment]::GetFolderPath('System'), 'WindowsPowerShell\v1.0\Modules')
$operationPhase = 'preflight'
$trustedHostLog = $false
$hostLog = $null

function Write-SafeFailure([string]$Phase, $Failure) {
    if ($Phase -notin 'preflight','staging','starting','detaching','fixtures','restoring','observing','collect-target','collect-control','fixture-target','fixture-control','dismount-target','dismount-control','receipt','receipt-cleanup') { $Phase = 'operation' }
    $exception = $Failure.Exception
    $type = if ($exception -is [IO.IOException]) { 'IOException' } elseif ($exception -is [UnauthorizedAccessException]) { 'UnauthorizedAccessException' } elseif ($exception -is [Runtime.InteropServices.COMException]) { 'COMException' } else { 'Exception' }
    $detail = if ($exception.Data['WinSightNetworkCredentialBoundary']) { 'credential operation detail omitted' } else { $exception.Message }
    $message = '{0} failed ({1}; HRESULT 0x{2:X8}): {3}' -f $Phase, $type, $exception.HResult, $detail
    # Never format ErrorRecord, InvocationInfo or InnerException. The actual credential call sites
    # mark their exception before rethrow; all other native causes remain available verbatim.
    try { [Console]::Error.WriteLine($message) } catch { }
    try { Write-HostLog $message }
    catch { try { [Console]::Error.WriteLine('Network host diagnostic failed; original failure and recovery are preserved.') } catch { } }
}
function Invoke-NetworkCredentialOperation([scriptblock]$Action) {
    try { & $Action }
    catch {
        $failure = $_
        $failure.Exception.Data['WinSightNetworkCredentialBoundary'] = $true
        throw $failure
    }
}
trap { Write-SafeFailure $operationPhase $_; exit 1 }

# Definitions precede preflight: even a failed module import has a usable stderr diagnostic.
# Do not resolve system cmdlets or Hyper-V through user-controlled module search directories.
if (-not $Root) { $Root = (Join-Path ([IO.Path]::GetPathRoot($PSScriptRoot)) 'Hyper-V\WinSight-Qualification') }
Import-Module (Join-Path $HarnessDir 'WinSightHyperV.psm1') -Force
Set-AdministratorsDefaultOwner
if ([IO.Path]::GetFullPath($Root).TrimEnd('\') -ceq [IO.Path]::GetPathRoot([IO.Path]::GetFullPath($Root)).TrimEnd('\')) { throw 'Qualification storage must be a dedicated directory, never a drive root.' }
function Write-HostLog([string]$Message) {
    $line = "$(Get-Date -Format o) [network] $Message"
    if ($trustedHostLog) {
        try { Add-SharedLine -Path $hostLog -Line $line }
        catch { try { [Console]::Error.WriteLine('Network protected host log unavailable; diagnostics remain in stderr and recovery continues.') } catch { } }
    }
    else { try { [Console]::Error.WriteLine('Network protected host log root is not verified; diagnostics remain in stderr.') } catch { } }
    try { Write-Host $line } catch { }
}
Assert-ProtectedPath -Path $EvidenceRoot
$hostLog = Join-Path $EvidenceRoot 'host-operations.txt'
$trustedHostLog = $true
Import-Module Hyper-V
Import-Module (Join-Path $HarnessDir 'guest\NetworkProbeCredential.psm1') -Force
foreach ($protected in $CandidateDir, $HarnessDir) { Assert-ProtectedPath -Path $protected }
Assert-ProtectedPath -Path $BootstrapReceipt
Assert-ProtectedPath -Path $Root -Recurse -AllowVirtualMachines
$data = Join-Path $Root 'data.vhdx'
$controlData = Join-Path $Root 'control-data.vhdx'

function Get-NetworkResultStatus($Result, [string]$Side) {
    if ($null -eq $Result) { return 'NOT_RUN' }
    if ($Side -ceq 'control') {
        if ($Result.status -is [string] -and $Result.status -ceq 'FAIL') { return 'FAIL' }
        if ($Result.status -is [string] -and $Result.status -ceq 'PASS' -and (Test-WinSightCompletion $Result)) { return 'PASS' }
        return 'NOT_RUN'
    }
    return Get-WinSightQualificationStatus $Result @('01-identity-and-protected-root','36-ipc-network-logon','99-residue')
}

function Assert-NetworkResultJsonMembers([string]$Raw) {
    # PS5 ConvertFrom-Json keeps the last physical member. Inspect the Framework JSON reader's
    # uncollapsed object members first, including decoded escaped names, with bounded depth/size.
    Add-Type -AssemblyName System.Runtime.Serialization
    $quotas = New-Object Xml.XmlDictionaryReaderQuotas
    $quotas.MaxDepth = 64
    $quotas.MaxStringContentLength = 16MB
    $quotas.MaxNameTableCharCount = 16MB
    $quotas.MaxArrayLength = 16MB
    $bytes = [Text.Encoding]::UTF8.GetBytes($Raw)
    if ($bytes.Length -gt 16MB) { throw 'Collected network result exceeds its UTF8 byte bound; campaign preserved.' }
    $reader = [Runtime.Serialization.Json.JsonReaderWriterFactory]::CreateJsonReader($bytes, $quotas)
    $frames = New-Object Collections.Stack
    try {
        while ($reader.Read()) {
            if ($reader.NodeType -eq [Xml.XmlNodeType]::Element) {
                if ($frames.Count -gt 0 -and $frames.Peek().kind -ceq 'object') {
                    # Escaped/non-XML names use the item attribute; ordinary LocalName is already
                    # the original JSON name. XmlConvert.DecodeName would corrupt literal _xNNNN_.
                    $key = $reader.GetAttribute('item')
                    if ($null -eq $key) { $key = $reader.LocalName }
                    if (-not $frames.Peek().keys.Add($key)) { throw 'Collected network result has duplicate decoded object members; campaign preserved.' }
                }
                if (-not $reader.IsEmptyElement) {
                    $keys = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                    if ($null -ne $reader.GetAttribute('__type')) { [void]$keys.Add('__type') }
                    $frames.Push([pscustomobject]@{ kind = $reader.GetAttribute('type'); keys = $keys })
                }
            }
            elseif ($reader.NodeType -eq [Xml.XmlNodeType]::EndElement) { [void]$frames.Pop() }
        }
    }
    finally { $reader.Dispose() }
}
function Read-NetworkGuestResult([string]$Path, [ValidateSet('target','control')][string]$Side) {
    # A size/shape precheck bounds real collected files. A missing precheck is not an absence
    # oracle: still perform Get-Content, including when a later publication appeared in between.
    try {
        $entry = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if ($entry.PSIsContainer -or ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $entry.Length -gt 16MB) { throw 'Collected network result is not an ordinary bounded file; campaign preserved.' }
    }
    catch [Management.Automation.ItemNotFoundException] { }
    try { $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop }
    catch [Management.Automation.ItemNotFoundException] { return $null }
    if ($raw -isnot [string] -or $raw.Length -gt 16MB -or -not $raw.TrimStart().StartsWith('{')) { throw 'Collected network result root is unrecognized; campaign preserved.' }
    Assert-NetworkResultJsonMembers $raw
    $value = $raw | ConvertFrom-Json -ErrorAction Stop
    if ($value -isnot [pscustomobject]) { throw 'Collected network result must be an object; campaign preserved.' }
    if ($Side -ceq 'target') {
        if ($value.candidate -isnot [pscustomobject] -or $value.candidate.commit -isnot [string] -or
            $value.candidate.qualificationRunId -isnot [string] -or $value.candidate.commit -cne $candidate.commit -or
            $value.candidate.qualificationRunId -cne $runState.runId -or $value.gates -isnot [pscustomobject]) {
            throw 'Collected target result does not identify this candidate, campaign and gate schema; evidence preserved without attribution.'
        }
        foreach ($gate in $value.gates.PSObject.Properties) {
            if ($gate.Value -isnot [pscustomobject] -or $gate.Value.status -isnot [string] -or
                $gate.Value.status -cnotin 'PASS','FAIL','NOT_RUN') { throw 'Collected target gate status is unrecognized; campaign preserved.' }
        }
    }
    elseif ($value.qualificationRunId -isnot [string] -or $value.qualificationRunId -cne $runState.runId -or
        $value.status -isnot [string] -or $value.status -cnotin 'PASS','FAIL','NOT_RUN') {
        throw 'Collected control result does not identify this campaign and a recognized status; evidence preserved without attribution.'
    }
    return $value
}
function Write-NetworkMissingReceipt([string]$Path, $Receipt) {
    $bytes = (New-Object Text.UTF8Encoding $false).GetBytes(($Receipt | ConvertTo-Json -Depth 6 -Compress))
    if ($bytes.Length -gt 8192) { throw 'Network missing-result receipt exceeds its bound.' }
    $temp = Join-Path ([IO.Path]::GetDirectoryName($Path)) ('.network-receipt-' + [Guid]::NewGuid().ToString('N') + '.tmp')
    $owned = $false
    $stream = $null
    try {
        $stream = New-Object IO.FileStream($temp, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $owned = $true
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
        $stream.Dispose(); $stream = $null
        try { [IO.File]::Move($temp, $Path); $owned = $false }
        catch [IO.IOException] {
            # File.Move never replaces. Reuse only byte-identical canonical evidence, acquired
            # once with a length check before allocation; foreign or unreadable bytes survive.
            $existing = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
            try {
                if ($existing.Length -ne $bytes.Length) { throw 'Existing network missing-result receipt differs; preserve the campaign.' }
                $buffer = New-Object byte[] $bytes.Length
                $offset = 0
                while ($offset -lt $buffer.Length) {
                    $read = $existing.Read($buffer, $offset, $buffer.Length - $offset)
                    if ($read -eq 0) { throw 'Existing network missing-result receipt ended unexpectedly; preserve the campaign.' }
                    $offset += $read
                }
                if ([Convert]::ToBase64String($buffer) -cne [Convert]::ToBase64String($bytes)) { throw 'Existing network missing-result receipt differs; preserve the campaign.' }
            }
            finally { $existing.Dispose() }
        }
    }
    finally {
        if ($stream) { $stream.Dispose() }
        if ($owned) { try { [IO.File]::Delete($temp) } catch { Write-SafeFailure 'receipt-cleanup' $_ } }
    }
}
function Get-NetworkQualificationExitCode($Target, $Control, [bool]$TimedOut, [int]$RefusedCount) {
    if ($null -eq $Target -or $null -eq $Control) { return 2 }
    if ($TimedOut -or $RefusedCount -ne 0 -or (Get-NetworkResultStatus $Target 'target') -cne 'PASS' -or
        (Get-NetworkResultStatus $Control 'control') -cne 'PASS') { return 1 }
    return 0
}
function Write-ResumeGuidance {
    $values = @((Join-Path $HarnessDir 'Invoke-HyperVNetworkLogon.ps1'), $CandidateDir, $HarnessDir, $EvidenceRoot, $BootstrapReceipt, $Root, $Name, $ControlName, $Checkpoint, $ControlCheckpoint, $Switch, $RunName) |
        ForEach-Object { "'" + ([string]$_).Replace("'", "''") + "'" }
    $message = "campaign preserved; resume with: powershell.exe -NoProfile -NonInteractive -File {0} -CandidateDir {1} -HarnessDir {2} -EvidenceRoot {3} -BootstrapReceipt {4} -Root {5} -Name {6} -ControlName {7} -Checkpoint {8} -ControlCheckpoint {9} -Switch {10} -RunName {11} -TimeoutMinutes $TimeoutMinutes -TargetMemoryBytes $TargetMemoryBytes -ControlMemoryBytes $ControlMemoryBytes $(if ($AutomaticCredential) { '-AutomaticCredential' }) -Resume" -f $values
    try { Write-HostLog $message } catch { try { [Console]::Error.WriteLine($message) } catch { } }
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
    $firstFailure = $null
    # Detachment is independently recoverable even if an early/preflight diagnostic definition is
    # unavailable. Diagnostics must never prevent the second VM from being attempted.
    $logFailure = {
        param($Failure)
        try { Write-SafeFailure 'detaching' $Failure }
        catch {
            $detail = if ($Failure.Exception.Data['WinSightNetworkCredentialBoundary']) { 'credential operation detail omitted' } else { $Failure.Exception.Message }
            $message = 'detaching failed (HRESULT 0x{0:X8}): {1}' -f $Failure.Exception.HResult,$detail
            try { [Console]::Error.WriteLine($message) } catch { }
            try { Write-HostLog $message } catch { }
        }
    }
    try {
        $found = Remove-WinSightDataDisk -VMName $Name -Path $data
        if ($found) { Write-HostLog "$Name was $found, not off, when its data disk was detached: turned off" }
    }
    catch { if (-not $firstFailure) { $firstFailure = $_ }; & $logFailure $_ }
    try {
        $found = Remove-WinSightDataDisk -VMName $ControlName -Path $controlData
        if ($found) { Write-HostLog "$ControlName was $found, not off, when its data disk was detached: turned off" }
    }
    catch { if (-not $firstFailure) { $firstFailure = $_ }; & $logFailure $_ }
    if ($firstFailure) { throw $firstFailure }
}
function Remove-StagedNetworkFixtures {
    $firstFailure = $null
    foreach ($disk in $data, $controlData) {
        $fixtureFailure = $null
        try {
            $cleanupLetter = Mount-WinSightData $disk
            try { Remove-NetworkProbeFixture -Path "${cleanupLetter}:\network-credential.json" }
            catch { $fixtureFailure = $_; throw }
            finally {
                try { Dismount-WinSightData $disk }
                catch { Write-SafeFailure 'fixtures' $_; if (-not $fixtureFailure) { throw } }
            }
        }
        catch { if (-not $firstFailure) { $firstFailure = $_ }; Write-SafeFailure 'fixtures' $_ }
    }
    if ($firstFailure) { throw $firstFailure }
}
function Restore-BothVms([switch]$RequireSeal) {
    if ($RequireSeal) { Confirm-WinSightQualificationSeal -RunDir $runDir }
    $failures = @()
    try { Restore-VMCheckpoint -VMName $Name -Name $Checkpoint -Confirm:$false }
    catch { Write-SafeFailure 'restoring' $_; $failures += 'target checkpoint' }
    try { Restore-VMCheckpoint -VMName $ControlName -Name $ControlCheckpoint -Confirm:$false }
    catch { Write-SafeFailure 'restoring' $_; $failures += 'control checkpoint' }
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
$campaignContract = [ordered]@{version=1;kind='network';runName=$RunName;evidenceRoot=[IO.Path]::GetFullPath($EvidenceRoot).TrimEnd('\').ToUpperInvariant();candidateDir=[IO.Path]::GetFullPath($CandidateDir).TrimEnd('\');harnessDir=[IO.Path]::GetFullPath($HarnessDir).TrimEnd('\');bootstrapReceipt=[IO.Path]::GetFullPath($BootstrapReceipt);candidateCommit=$candidate.commit;candidateDigest=(Get-WinSightTextDigest ($candidateManifest -join "`n"));harnessDigest=(Get-WinSightTextDigest ($harnessManifest -join "`n"));bootstrapDigest=$bootstrapSha256;vm=$Name;controlVm=$ControlName;checkpoint=$Checkpoint;controlCheckpoint=$ControlCheckpoint;switch=$Switch;gates=@('01-identity-and-protected-root','36-ipc-network-logon','99-residue');timeoutMinutes=$TimeoutMinutes;memoryBytes=$TargetMemoryBytes;controlMemoryBytes=$ControlMemoryBytes;automatic=[bool]$AutomaticCredential}
$campaignLease = Enter-WinSightCampaign -Root $Root -Contract $campaignContract -Resume:$Resume

# --- Stage both data disks --------------------------------------------------------------------------
Restore-VMCheckpoint -VMName $Name -Name $Checkpoint -Confirm:$false
Restore-VMCheckpoint -VMName $ControlName -Name $ControlCheckpoint -Confirm:$false
$originalAdapters = @(Invoke-WinSightVmRetry { Get-VMNetworkAdapter -VMName $Name | Where-Object Name -ne 'WinSightPrivate' | Select-Object Name, SwitchName })
$originalMemory = Invoke-WinSightVmRetry { (Get-VMMemory -VMName $Name).Startup }
$originalControlMemory = Invoke-WinSightVmRetry { (Get-VMMemory -VMName $ControlName).Startup }
$runState = [ordered]@{ version = 1; runId = $campaignLease.RunId; candidateCommit = $candidate.commit; candidateManifest = $candidateManifest; harnessManifest = $harnessManifest; bootstrapSha256 = $bootstrapSha256; automatic = [bool]$AutomaticCredential; root = $Root; target = $Name; control = $ControlName; checkpoint = $Checkpoint; controlCheckpoint = $ControlCheckpoint; adapters = $originalAdapters; memory = $originalMemory; controlMemory = $originalControlMemory }
$stateBytes = (New-Object Text.UTF8Encoding $false).GetBytes(($runState | ConvertTo-Json -Depth 6))
$stateStream = New-Object IO.FileStream($statePath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
try { $stateStream.Write($stateBytes, 0, $stateBytes.Length); $stateStream.Flush($true) } finally { $stateStream.Dispose() }
$operationPhase = 'staging'
$envelope = $null
$network.qualificationRunId = $runState.runId
if ($AutomaticCredential) { $network.credentialMode = 'automatic' }
try {
Remove-DataDisks
Write-WinSightDriverHeartbeat -Path $DriverHeartbeat -Phase 'staging'
$envelope = if ($AutomaticCredential) { Invoke-NetworkCredentialOperation { New-NetworkProbeEnvelope } } else { $null }
$letter = Mount-WinSightData $data
# Let an in-flight body exception propagate unchanged after best-effort dismount.
$stagingVolumeCompleted = $false
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
    if ($AutomaticCredential) { Invoke-NetworkCredentialOperation { Write-NetworkProbeFixture -Path "${letter}:\network-credential.json" -Envelope $envelope } }
    Copy-Item -LiteralPath (Join-Path $HarnessDir 'guest\run-guest-checks.ps1') -Destination "${letter}:\run-guest-checks.ps1"
    'qualify' | Set-Content -LiteralPath "${letter}:\mode.txt"
    $stagingVolumeCompleted = $true
}
finally {
    try { Dismount-WinSightData $data }
    catch { Write-SafeFailure 'staging' $_; if ($stagingVolumeCompleted) { throw } }
}
$letter = Mount-WinSightData $controlData
# Let an in-flight body exception propagate unchanged after best-effort dismount.
$stagingVolumeCompleted = $false
try {
    Clear-WinSightDataVolume $letter
    if ($AutomaticCredential) { Set-NetworkProbeVolumeProtection -Root "${letter}:\" }
    Copy-Item -LiteralPath (Join-Path $HarnessDir 'guest\run-guest-checks.ps1'), (Join-Path $HarnessDir 'guest\control-network-logon.ps1'), (Join-Path $HarnessDir 'guest\NetworkProbeCredential.psm1') -Destination "${letter}:\"
    $network | ConvertTo-Json | Set-Content -LiteralPath "${letter}:\network.json" -Encoding UTF8
    if ($AutomaticCredential) { Invoke-NetworkCredentialOperation { Write-NetworkProbeFixture -Path "${letter}:\network-credential.json" -Envelope $envelope } }
    'control' | Set-Content -LiteralPath "${letter}:\mode.txt"
    $stagingVolumeCompleted = $true
}
finally {
    try { Dismount-WinSightData $controlData }
    catch { Write-SafeFailure 'staging' $_; if ($stagingVolumeCompleted) { throw } }
}
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
$operationPhase = 'starting'
try {
    Write-WinSightDriverHeartbeat -Path $DriverHeartbeat -Phase 'starting'
    # Only published after both data volumes were formatted and staged. A Resume without this
    # receipt must not attribute old on-disk results to a new run whose staging never completed.
    Set-WinSightCampaignStage -Lease $campaignLease -Stage starting -TimeoutMinutes $TimeoutMinutes
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
    $campaignContract = [ordered]@{version=1;kind='network';runName=$RunName;evidenceRoot=[IO.Path]::GetFullPath($EvidenceRoot).TrimEnd('\').ToUpperInvariant();candidateDir=[IO.Path]::GetFullPath($CandidateDir).TrimEnd('\');harnessDir=[IO.Path]::GetFullPath($HarnessDir).TrimEnd('\');bootstrapReceipt=[IO.Path]::GetFullPath($BootstrapReceipt);candidateCommit=$candidate.commit;candidateDigest=(Get-WinSightTextDigest ($candidateManifest -join "`n"));harnessDigest=(Get-WinSightTextDigest ($harnessManifest -join "`n"));bootstrapDigest=$bootstrapSha256;vm=$Name;controlVm=$ControlName;checkpoint=$Checkpoint;controlCheckpoint=$ControlCheckpoint;switch=$Switch;gates=@('01-identity-and-protected-root','36-ipc-network-logon','99-residue');timeoutMinutes=$TimeoutMinutes;memoryBytes=$TargetMemoryBytes;controlMemoryBytes=$ControlMemoryBytes;automatic=[bool]$AutomaticCredential}
    $campaignLease = Enter-WinSightCampaign -Root $Root -Contract $campaignContract -Resume:$Resume
    Assert-ProtectedPath -Path $statePath
    $runState = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    if ($runState.version -ne 1 -or $runState.candidateCommit -cne $candidate.commit -or
        (@($runState.candidateManifest) -join "`n") -cne ($candidateManifest -join "`n") -or
        (@($runState.harnessManifest) -join "`n") -cne ($harnessManifest -join "`n") -or $runState.bootstrapSha256 -cne $bootstrapSha256 -or
        [IO.Path]::GetFullPath([string]$runState.root).TrimEnd('\').ToUpperInvariant() -cne [IO.Path]::GetFullPath($Root).TrimEnd('\').ToUpperInvariant() -or $runState.target -cne $Name -or $runState.control -cne $ControlName -or
        $runState.checkpoint -cne $Checkpoint -or $runState.controlCheckpoint -cne $ControlCheckpoint) {
        throw 'Resume identity mismatch; campaign preserved, use its original protected candidate and run state.'
    }
    Assert-ProtectedPath -Path $startedPath
    $startedReceipt = Get-Content -LiteralPath $startedPath -Raw | ConvertFrom-Json
    if ($runState.runId -cne $campaignLease.RunId -or $runState.runId -notmatch '^[0-9a-f-]{36}$' -or $startedReceipt.runId -cne $runState.runId) { throw 'No matching staged network campaign; preserve the disks and inspect the original run state.' }
    $originalAdapters = @($runState.adapters)
    $originalMemory = [int64]$runState.memory
    $originalControlMemory = [int64]$runState.controlMemory
    $AutomaticCredential = [bool]$runState.automatic
    Write-HostLog "$RunName resumed with its original candidate and checkpoint configuration"
}

$operationPhase = 'observing'
$safeToRestore = $false
$primaryFailure = $null
try {
$started = Get-Date
$deadline = $started.AddMinutes($TimeoutMinutes)
if ($campaignLease) { $deadline = [DateTimeOffset]::Parse($campaignLease.State.deadlineUtc,[Globalization.CultureInfo]::InvariantCulture).LocalDateTime }
while ($true) {
    Write-WinSightDriverHeartbeat -Path $DriverHeartbeat -Phase 'observing'
    $targetState = Invoke-WinSightVmRetry { Get-WinSightVmState $Name }
    $controlState = Invoke-WinSightVmRetry { Get-WinSightVmState $ControlName }
    if (($targetState -eq 'Off' -and $controlState -eq 'Off') -or (Get-Date) -ge $deadline) { break }
    Start-Sleep -Seconds 30
    Write-Host ("  running {0:N0} min (target {1}, control {2})" -f ((Get-Date) - $started).TotalMinutes, $targetState, $controlState)
}
$timedOut = $false
if ($campaignLease) {
    $timedOut = [bool]$campaignLease.State.timedOut -or [bool]$campaignLease.State.observationIncomplete
    if ($Resume -and (Get-Date) -gt $deadline -and $campaignLease.State.stage -cne 'collecting') { Set-WinSightCampaignStage -Lease $campaignLease -Stage collecting -ObservationIncomplete; $timedOut = $true }
}
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
        if ($campaignLease) { Set-WinSightCampaignStage -Lease $campaignLease -Stage collecting -TimedOut }
        Stop-VM -Name $vm -TurnOff -Force
        Write-HostLog "timeout: $vm turned off"
    }
    if ((Invoke-WinSightVmRetry { Get-WinSightVmState $vm }) -ne 'Off') { throw 'VM shutdown not confirmed; campaign preserved.' }
}

# --- Collect and seal both evidence sets, then restore ---------------------------------------------
Remove-DataDisks
if ($campaignLease) { Set-WinSightCampaignStage -Lease $campaignLease -Stage collecting }
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
$targetResults = Read-NetworkGuestResult -Path (Join-Path $runDir 'target\results.json') -Side 'target'
$controlResults = Read-NetworkGuestResult -Path (Join-Path $runDir 'control\control-result.json') -Side 'control'
if ($null -eq $targetResults -or $null -eq $controlResults) {
    # Publish only after every present side has passed identity/schema validation. Missing means
    # no attributable result was collected, not proof that the guest/gate never executed.
    $receipt = [ordered]@{
        version = 1; runId = $runState.runId; candidateCommit = $candidate.commit
        target = [ordered]@{ status = (Get-NetworkResultStatus $targetResults 'target'); reason = $(if ($null -eq $targetResults) { 'result-file-missing' } else { 'result-present' }) }
        control = [ordered]@{ status = (Get-NetworkResultStatus $controlResults 'control'); reason = $(if ($null -eq $controlResults) { 'result-file-missing' } else { 'result-present' }) }
        timedOut = [bool]$timedOut
    }
    Write-NetworkMissingReceipt -Path (Join-Path $runDir 'network-missing-results.json') -Receipt $receipt
}
if ($refused.Count -gt 0) { $refused | Set-Content -LiteralPath (Join-Path $runDir 'collection-refused.txt'); throw 'Guest collection refused entries; preserve the common-root Active campaign.' }
@("# harness $HarnessDir") + @(Get-FileManifest $HarnessDir) | Set-Content -LiteralPath (Join-Path $runDir 'provenance-harness.txt')
Copy-Item -LiteralPath $BootstrapReceipt -Destination (Join-Path $runDir 'provenance-bootstrap.json')
Copy-Item -LiteralPath $statePath -Destination (Join-Path $runDir 'provenance-network-state.json')
Copy-Item -LiteralPath $startedPath -Destination (Join-Path $runDir 'provenance-network-started.json')
if ($timedOut -and (Test-Path -LiteralPath $timeoutPath)) { Copy-Item -LiteralPath $timeoutPath -Destination (Join-Path $runDir 'provenance-network-timeout.json') }
if ($campaignLease -and $campaignLease.State.observationIncomplete) {
    Write-WinSightImmutableText -Path (Join-Path $runDir 'network-observation-gap.json') -Text ([ordered]@{version=1;runId=$runState.runId;candidateCommit=$candidate.commit;status='NOT_RUN';reason='deadline-observation-missing'}|ConvertTo-Json -Compress)
}
@("# candidate $CandidateDir, claimed commit $($candidate.commit)") + @(Get-FileManifest $CandidateDir) |
    Set-Content -LiteralPath (Join-Path $runDir 'provenance-candidate.txt')
Write-WinSightQualificationSeal -RunDir $runDir -SealPath (Join-Path $runDir 'SHA256SUMS.txt')
$safeToRestore = $true
try { Write-HostLog "evidence sealed in $runDir" } catch { Write-SafeFailure 'observing' $_ }
if ($cleanupFailure) { throw $cleanupFailure }
}
catch { $primaryFailure = $_; Write-SafeFailure 'observing' $_ }
finally {
    if ($safeToRestore) {
        Write-WinSightDriverHeartbeat -Path $DriverHeartbeat -Phase 'restoring'
        try { Restore-BothVms -RequireSeal }
        catch { if (-not $primaryFailure) { $primaryFailure = $_ }; Write-SafeFailure 'restoring' $_ }
    }
    else { Write-ResumeGuidance }
}
if ($primaryFailure) { throw $primaryFailure }
if ($refused.Count -gt 0) { throw 'Collection refused entries; common transport ownership remains Active.' }
Close-WinSightCampaign -Lease $campaignLease -SealPath (Join-Path $runDir 'SHA256SUMS.txt')
Write-WinSightDriverHeartbeat -Path $DriverHeartbeat -Phase 'finished'
Write-HostLog "both VMs restored ($Checkpoint, $ControlCheckpoint), target network: $(Invoke-WinSightVmRetry { (Get-VMNetworkAdapter -VMName $Name | ForEach-Object { "$($_.Name)=$($_.SwitchName)" }) -join ', ' })"

$resultsFile = Join-Path $runDir 'target\results.json'
$final = $targetResults
if ($null -ne $final) {
    $final.gates.PSObject.Properties | ForEach-Object { [pscustomobject]@{ Gate = $_.Name; Status = $_.Value.status; Seconds = $_.Value.seconds } } |
        Format-Table -AutoSize | Out-String | Write-Host
}
if ($null -ne $controlResults) { Write-Host "control: $($controlResults.status)" }
$gate = Get-NetworkResultStatus $final 'target'
Write-HostLog "$RunName finished: gate 36 $gate"
exit (Get-NetworkQualificationExitCode -Target $targetResults -Control $controlResults -TimedOut $timedOut -RefusedCount $refused.Count)
