#Requires -RunAsAdministrator
# HOST, elevated, Windows PowerShell 5.1, started once by the operator (UAC). Runs the Hyper-V
# qualification actions a non-elevated session queues as small JSON files, one at a time, and nothing
# else. See README.md beside this script.
#
# RA-01. The first runner hashed a copy of scripts taken from a folder any authenticated user could
# modify, staged a candidate from one, sealed evidence into one, kept its own log, status and request
# archive in one, and began by deleting its previous copy recursively - which Windows PowerShell 5.1
# does through a junction. The trust boundary is now:
#
#   $Requests   user-writable. Read-only here: a request is parsed, never moved, rewritten or deleted.
#   $Root       created by this runner with an administrators-only DACL, or refused:
#     harness\<stamp>\   scripts copied from the authenticated installation (no user access)
#     candidates\<id>\   a candidate staged from $Requests\candidates\<name> (no user access)
#     sealed\            manifests and evidence (Authenticated Users: read)
#     runner\            status, log, action logs, processed request names (Authenticated Users: read)
#   $VmRoot     the VM disks: must already be administrators-only (Protect-WinSightVmStorage.ps1).
#
# RB-01: launch only from the installation made by the externally authenticated standalone
# bootstrap. The runner and its imports must already be protected before the first instruction.
# The protected bootstrap receipt is carried into each run for the independently pinned verifier.
#
# Requests (unique file names; a name is processed once):
#   {"action":"ping"}
#   {"action":"stage","candidate":"<folder under $Requests\candidates>"}
#   {"action":"qualify","runName":"...","gates":["17-cloud-files"],"memoryGB":4}
#   {"action":"collect","runName":"..."}
#   {"action":"control"}
#   {"action":"network","runName":"..."}   {"action":"network-collect","runName":"..."}
#   {"action":"stop"}
[CmdletBinding()]
param(
    # Default locations, resolved below, are at the root of the volume this script runs from; pass a path to use another.
    [string]$Root,
    [string]$Requests,
    [string]$VmRoot,
    [int]$Hours = 24
)

# Do not resolve system cmdlets or Hyper-V through user-controlled module search directories.
$env:PSModulePath = [IO.Path]::Combine([Environment]::GetFolderPath('System'), 'WindowsPowerShell\v1.0\Modules')

# Resolved here rather than as parameter defaults: Windows PowerShell 5.1 leaves $PSScriptRoot
# empty in the defaults of an advanced script started with -File.
if (-not $Root) { $Root = (Join-Path ([IO.Path]::GetPathRoot($PSScriptRoot)) 'WinSight-Qualification') }
if (-not $Requests) { $Requests = (Join-Path ([IO.Path]::GetPathRoot($PSScriptRoot)) 'WinSight-Qualification-Requests') }
if (-not $VmRoot) { $VmRoot = (Join-Path ([IO.Path]::GetPathRoot($PSScriptRoot)) 'Hyper-V\WinSight-Qualification') }

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
$Host.UI.RawUI.WindowTitle = 'WinSight qualification runner (elevated) - leave open'
Import-Module (Join-Path $PSScriptRoot 'WinSightHyperV.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'QualificationProvenance.psm1') -Force
Assert-ProtectedPath -Path $PSScriptRoot -Recurse
$bootstrapReceiptPath = Join-Path $PSScriptRoot 'bootstrap-provenance.json'
$bootstrap = Get-Content -LiteralPath $bootstrapReceiptPath -Raw | ConvertFrom-Json
$sourceEntries = @(Get-FileManifest $PSScriptRoot | Where-Object { $_ -notmatch '  bootstrap-provenance\.json$' } | ForEach-Object {
        $parts = $_ -split '  ', 3
        [pscustomobject]@{ Sha256 = $parts[0]; Blob = $parts[1]; Relative = $parts[2] }
    })
if (-not (Test-QualificationBootstrap -Receipt $bootstrap -HarnessEntries $sourceEntries -ExpectedCommit $bootstrap.harnessCommit -ExpectedLauncherSha256 $bootstrap.launcherSha256)) {
    throw 'The protected installation does not match its authenticated bootstrap receipt.'
}
$bootstrapHash = (Get-FileHash -LiteralPath $bootstrapReceiptPath -Algorithm SHA256).Hash
Set-AdministratorsDefaultOwner

# The files the harness consists of, relative to scripts\validation\hyperv. Nothing else is copied.
$HarnessFiles = @(Get-QualificationHarnessFiles)
$HarnessSource = $PSScriptRoot
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'

# --- The protected root ---------------------------------------------------------------------------------
New-ProtectedDirectory -Path $Root -UsersRead
foreach ($child in 'sealed', 'runner') { New-ProtectedDirectory -Path (Join-Path $Root $child) -UsersRead }
foreach ($child in 'harness', 'candidates') { New-ProtectedDirectory -Path (Join-Path $Root $child) }
New-ProtectedDirectory -Path (Join-Path $Root 'runner\logs') -UsersRead
$runnerDir = Join-Path $Root 'runner'
$sealed = Join-Path $Root 'sealed'
$statusPath = Join-Path $runnerDir 'status.json'
$processedPath = Join-Path $runnerDir 'processed.txt'
function Say([string]$Message) {
    $line = "$(Get-Date -Format o) $Message"
    Add-SharedLine -Path (Join-Path $runnerDir 'runner.log') -Line $line
    Write-Host $line
}

# The VM disks run the guest that produces the evidence: a disk anyone could replace would make every
# result meaningless, so nothing starts until they are protected.
try { Assert-ProtectedPath -Path $VmRoot -Recurse -AllowVirtualMachines }
catch {
    Say "refused to start: $VmRoot is not administrators-only ($($_.Exception.Message)). Run Protect-WinSightVmStorage.ps1 first."
    exit 3
}

# --- The protected harness ------------------------------------------------------------------------------
$harness = Join-Path $Root "harness\$stamp"
New-ProtectedDirectory -Path $harness
foreach ($file in $HarnessFiles) { Copy-ListedFile -SourceRoot $HarnessSource -Relative $file -DestinationRoot $harness -MaximumBytes 1MB }
Assert-ProtectedPath -Path $harness -Recurse
$harnessManifest = @(Get-FileManifest $harness)
$manifestPath = Join-Path $sealed "harness-$stamp.txt"
@("# harness copied $stamp from authenticated installation $HarnessSource", "# authenticated commit: $($bootstrap.harnessCommit)",
  "# runner: $(Get-GitBlobId $PSCommandPath)  $PSCommandPath") + $harnessManifest | Set-Content -LiteralPath $manifestPath
Say "harness $stamp copied ($($HarnessFiles.Count) files); manifest $manifestPath"
function Assert-Harness {
    if (@(Get-FileManifest $harness) -join "`n" -ne ($harnessManifest -join "`n")) { throw 'The protected harness changed.' }
    if ((Get-FileHash -LiteralPath $bootstrapReceiptPath -Algorithm SHA256).Hash -ne $bootstrapHash) { throw 'The bootstrap receipt changed.' }
}

# --- Requests -------------------------------------------------------------------------------------------
$processed = New-Object System.Collections.Generic.HashSet[string]
if (Test-Path -LiteralPath $processedPath) { foreach ($name in Get-Content -LiteralPath $processedPath) { [void]$processed.Add($name) } }
$status = [ordered]@{ runnerPid = $PID; startedUtc = [DateTime]::UtcNow.ToString('o'); heartbeatUtc = $null; harness = $stamp; candidate = $null; current = $null; history = @() }
function Save-Status { $status.heartbeatUtc = [DateTime]::UtcNow.ToString('o'); Write-SharedText -Path $statusPath -Text ($status | ConvertTo-Json -Depth 5) }

# One request file, or $null when it is not a well-formed one. Its content is never echoed: a request
# that is really a hard link to something else must not have that something copied into a readable log.
function Read-Request([System.IO.FileInfo]$File) {
    if ($File.Attributes -band [IO.FileAttributes]::ReparsePoint) { return $null }
    if ($File.Length -gt 4096) { return $null }
    try { return (Get-Content -LiteralPath $File.FullName -Raw -Encoding UTF8 | ConvertFrom-Json) } catch { return $null }
}

# An optional field of a request: strict mode throws on a property the JSON did not have.
function Get-Field($Request, [string]$Name) {
    $property = $Request.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    return $null
}

function Get-Arguments($Request) {
    $action = [string](Get-Field $Request 'action')
    if ($action -notin 'ping', 'stage', 'qualify', 'collect', 'control', 'network', 'network-collect', 'stop') { throw 'unknown action' }
    $arguments = @()
    if ($action -in 'qualify', 'collect', 'network', 'network-collect') {
        $runName = [string](Get-Field $Request 'runName')
        if ($runName -notmatch '^[A-Za-z0-9][A-Za-z0-9-]{0,39}$') { throw 'invalid runName' }
        $arguments += @('-RunName', $runName)
    }
    if ($action -eq 'qualify') {
        $gates = @(Get-Field $Request 'gates' | Where-Object { $_ })
        if ($gates.Count -gt 40) { throw 'too many gates' }
        foreach ($gate in $gates) { if ([string]$gate -notmatch '^\d{2}-[a-z0-9-]{1,40}$') { throw 'invalid gate' } }
        if ($gates.Count -gt 0) { $arguments += @('-Gates', ($gates -join ',')) }
    }
    if ($action -in 'qualify', 'network') {
        # The memory of the VM under test: the target, beside the control, in the network run.
        $gb = if (Get-Field $Request 'memoryGB') { [int](Get-Field $Request 'memoryGB') } else { 4 }
        if ($gb -lt 3 -or $gb -gt 8) { throw 'invalid memoryGB' }
        $parameter = if ($action -eq 'qualify') { '-MemoryBytes' } else { '-TargetMemoryBytes' }
        $arguments += @($parameter, ([int64]$gb * 1GB))
    }
    if ($action -in 'collect', 'network-collect') { $arguments += '-Resume' }
    $modeProperty = $Request.PSObject.Properties['credentialMode']
    if ($modeProperty) {
        if ($action -ne 'network' -or $modeProperty.Value -isnot [string] -or
            $modeProperty.Value -cnotin 'automatic', 'interactive') { throw 'invalid credentialMode' }
        if ($modeProperty.Value -ceq 'automatic') { $arguments += '-AutomaticCredential' }
    }
    return , $arguments
}

# Copies requests\candidates\<name> into candidates\<id>: the three artifacts, their .sha256 files,
# candidate.json, the published installer the upgrade gate starts from, and the repository scripts the
# gates run - by pattern, one file at a time, never a directory copy.
function Invoke-Stage($Request) {
    $name = [string](Get-Field $Request 'candidate')
    if ($name -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$') { throw 'invalid candidate' }
    $candidatesRoot = Join-Path $Requests 'candidates'
    $source = Join-Path $candidatesRoot $name
    Assert-NoReparseBetween -Root $Requests -Path $source
    $id = "$stamp-$name"
    $destination = Join-Path $Root "candidates\$id"
    New-ProtectedDirectory -Path $destination
    $sourceFull = [IO.Path]::GetFullPath($source).TrimEnd('\')
    $files = @(Get-ChildItem -LiteralPath $sourceFull -File -Force | Where-Object {
            $_.Name -match '^winsight-v[0-9][0-9A-Za-z.+-]*-win-(x64|arm64)(-setup\.exe|\.zip|\.spdx\.json)(\.sha256)?$' -or $_.Name -eq 'candidate.json'
        } | ForEach-Object Name)
    foreach ($sub in 'previous', 'source\scripts') {
        $folder = Join-Path $sourceFull $sub
        if (-not (Test-Path -LiteralPath $folder)) { continue }
        Assert-NoReparseBetween -Root $Requests -Path $folder
        $pending = New-Object System.Collections.Generic.Stack[string]
        $pending.Push($folder)
        while ($pending.Count -gt 0) {
            foreach ($entry in [IO.Directory]::EnumerateFileSystemEntries($pending.Pop())) {
                $attributes = [IO.File]::GetAttributes($entry)
                if ($attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'reparse point in the candidate' }
                if ($attributes -band [IO.FileAttributes]::Directory) { $pending.Push($entry) }
                else { $files += $entry.Substring($sourceFull.Length + 1) }
            }
        }
    }
    if ('candidate.json' -notin $files) { throw 'no candidate.json' }
    if ($files.Count -gt 400) { throw 'too many candidate files' }
    foreach ($file in $files) { Copy-ListedFile -SourceRoot $sourceFull -Relative $file -DestinationRoot $destination }
    Assert-ProtectedPath -Path $destination -Recurse
    $manifest = @(Get-FileManifest $destination)
    $candidate = Get-Content -LiteralPath (Join-Path $destination 'candidate.json') -Raw | ConvertFrom-Json
    @("# candidate $id staged $([DateTime]::UtcNow.ToString('o')) from $sourceFull", "# claimed commit: $($candidate.commit)") + $manifest |
        Set-Content -LiteralPath (Join-Path $sealed "candidate-$id.txt")
    $script:candidateManifest = $manifest
    $status.candidate = $id
    return $id
}

function Assert-Candidate {
    if (-not $status.candidate) { throw 'no candidate staged' }
    $dir = Join-Path $Root "candidates\$($status.candidate)"
    if (@(Get-FileManifest $dir) -join "`n" -ne ($script:candidateManifest -join "`n")) { throw 'The staged candidate changed.' }
    return $dir
}

$scripts = @{
    qualify = 'Invoke-HyperVQualification.ps1'; collect = 'Invoke-HyperVQualification.ps1'
    control = 'New-WinSightControlVm.ps1'
    network = 'Invoke-HyperVNetworkLogon.ps1'; 'network-collect' = 'Invoke-HyperVNetworkLogon.ps1'
}

Say "runner started (pid $PID): requests $Requests, root $Root, VM storage $VmRoot"
Save-Status
$deadline = (Get-Date).AddHours($Hours)
while ((Get-Date) -lt $deadline) {
    $next = $null
    if ((Test-Path -LiteralPath $Requests -PathType Container) -and
        -not ((Get-Item -LiteralPath $Requests -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        $next = Get-ChildItem -LiteralPath $Requests -Filter '*.json' -File -Force |
            Where-Object { -not $processed.Contains($_.Name) } | Sort-Object LastWriteTimeUtc | Select-Object -First 1
    }
    if (-not $next) { Save-Status; Start-Sleep -Seconds 5; continue }
    [void]$processed.Add($next.Name)
    Add-SharedLine -Path $processedPath -Line $next.Name
    $id = ([IO.Path]::GetFileNameWithoutExtension($next.Name) -replace '[^A-Za-z0-9-]', '')
    if (-not $id) { $id = 'request' }
    $entry = [ordered]@{ id = $id; action = $null; arguments = $null; exit = $null; startedUtc = [DateTime]::UtcNow.ToString('o'); finishedUtc = $null; log = $null; error = $null; driverPid = $null; driverHeartbeatUtc = $null; driverPhase = $null; driverHeartbeatAgeSeconds = $null; driverHeartbeatUnavailable = $true }
    try {
        $request = Read-Request $next
        if ($null -eq $request) { throw 'not a well-formed request' }
        $arguments = Get-Arguments $request
        $entry.action = [string](Get-Field $request 'action')
        $entry.arguments = $arguments -join ' '
        if ($entry.action -eq 'stop') { Say 'stop requested'; break }
        if ($entry.action -eq 'ping') { Say "ping $id"; continue }
        Assert-Harness
        if ($entry.action -eq 'stage') { Say "staged candidate $(Invoke-Stage $request)"; continue }
        # Checked again before every run, not only at start: the disks are what the evidence comes from.
        Assert-ProtectedPath -Path $VmRoot -Recurse -AllowVirtualMachines
        if ($entry.action -ne 'control') { $arguments += @('-CandidateDir', (Assert-Candidate), '-BootstrapReceipt', $bootstrapReceiptPath) }
        $arguments += @('-HarnessDir', $harness, '-EvidenceRoot', $sealed, '-Root', $VmRoot)
        $log = Join-Path $runnerDir "logs\$id-$stamp.log"
        $driverHeartbeat = Join-Path $runnerDir "logs\$id-$stamp-heartbeat.json"
        $arguments += @('-DriverHeartbeat', $driverHeartbeat)
        $entry.log = $log
        $status.current = $entry
        Save-Status
        Say "running $($entry.action) $($entry.arguments)"
        $argumentList = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', "`"$(Join-Path $harness $scripts[$entry.action])`"") +
            ($arguments | ForEach-Object { if ("$_" -match '\s') { "`"$_`"" } else { "$_" } })
        $process = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList $argumentList `
            -RedirectStandardOutput $log -RedirectStandardError "$log.err" -WindowStyle Hidden -PassThru
        $null = $process.Handle
        $entry.driverPid = $process.Id
        $staleReported = $false
        do {
            $exited = $process.WaitForExit(30000)
            $beat = Read-WinSightDriverHeartbeat -Path $driverHeartbeat -ExpectedProcessId $process.Id
            $entry.driverHeartbeatUnavailable = $null -eq $beat
            $entry.driverHeartbeatUtc = if ($beat) { $beat.heartbeatUtc } else { $null }
            $entry.driverPhase = if ($beat) { $beat.phase } else { $null }
            $entry.driverHeartbeatAgeSeconds = if ($beat) { $beat.ageSeconds } else { $null }
            $age = if ($beat) { $beat.ageSeconds } else { ([DateTime]::UtcNow - [DateTime]::Parse($entry.startedUtc)).TotalSeconds }
            if (-not $exited -and $age -gt 120 -and -not $staleReported) {
                Say "driver $($process.Id) has no recent child heartbeat; inspect phase/status and its log (campaign is preserved)"
                $staleReported = $true
            }
            Save-Status
        } while (-not $exited)
        $entry.exit = $process.ExitCode
        Say "$($entry.action) finished with exit $($entry.exit)"
    }
    catch {
        $entry.error = $_.Exception.Message
        Say "request $id refused or failed: $($entry.error)"
    }
    finally {
        $entry.finishedUtc = [DateTime]::UtcNow.ToString('o')
        $status.current = $null
        $status.history += $entry
        Save-Status
    }
}
Say 'runner exiting'
$status.current = $null
Save-Status
