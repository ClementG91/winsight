# Run as an ORDINARY user (not elevated). Verifies that a sealed qualification run can be cited:
#   1. its evidence matches its own SHA256SUMS, with nothing added;
#   2. the harness it ran is, file for file, the one in the reviewed commit (git blob ids);
#   3. the candidate scripts it ran are the ones in the candidate's claimed commit, and the artifact
#      hashes the guest checked are the ones the runner staged;
#   4. nobody but an administrator can change the evidence, the protected harness and candidates, or
#      the VM disks: each write is attempted and must be refused.
# Prints PASS / FAIL per check and exits 1 on any FAIL. RA-01.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RunDir,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$HarnessCommit,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$LauncherSha256,
    [Parameter(Mandatory)][string]$Repository,
    # Default locations, resolved below, are at the root of the volume this script runs from; pass a path to use another.
    [string]$Root,
    [string]$VmRoot
)

# Do not resolve system cmdlets or Hyper-V through user-controlled module search directories.
$env:PSModulePath = [IO.Path]::Combine([Environment]::GetFolderPath('System'), 'WindowsPowerShell\v1.0\Modules')

# Resolved here rather than as parameter defaults: Windows PowerShell 5.1 leaves $PSScriptRoot
# empty in the defaults of an advanced script started with -File.
if (-not $Root) { $Root = (Join-Path ([IO.Path]::GetPathRoot($PSScriptRoot)) 'WinSight-Qualification') }
if (-not $VmRoot) { $VmRoot = (Join-Path ([IO.Path]::GetPathRoot($PSScriptRoot)) 'Hyper-V\WinSight-Qualification') }

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'WinSightHyperV.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'QualificationProvenance.psm1') -Force
Assert-ProtectedPath -Path $PSScriptRoot -Recurse
$failures = 0
function Report([bool]$Passed, [string]$Check, [string]$Detail = '') {
    $script:failures += [int](-not $Passed)
    '{0} {1}{2}' -f $(if ($Passed) { 'PASS' } else { 'FAIL' }), $Check, $(if ($Detail) { ": $Detail" } else { '' })
}
$git = (Get-Command git -ErrorAction Stop).Source
function Get-BlobAt([string]$Commit, [string]$Path) {
    $blob = & $git --no-replace-objects -C $Repository rev-parse --verify --quiet "${Commit}:$Path" 2>$null
    if ($LASTEXITCODE -ne 0) { return $null }
    return [string]$blob
}
function Read-Manifest([string]$Path) {
    Get-Content -LiteralPath $Path | Where-Object { $_ -and -not $_.StartsWith('#') } | ForEach-Object {
        $parts = $_ -split '  ', 3
        [pscustomobject]@{ Sha256 = $parts[0]; Blob = $parts[1]; Relative = $parts[2] }
    }
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this unelevated: the write checks must be made as an ordinary user.'
}
$RunDir = [IO.Path]::GetFullPath($RunDir).TrimEnd('\')
Assert-ProtectedPath -Path $RunDir -Recurse

# Both the verifier being executed and the runner's receipt must match the operator's independent
# launcher digest. Old runs without this pre-launch receipt fail closed; no retrospective attestation.
$installationReceipt = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'bootstrap-provenance.json') -Raw | ConvertFrom-Json
$installation = @(Get-FileManifest $PSScriptRoot | Where-Object { $_ -notmatch '  bootstrap-provenance\.json$' } | ForEach-Object {
        $parts = $_ -split '  ', 3
        [pscustomobject]@{ Sha256 = $parts[0]; Blob = $parts[1]; Relative = $parts[2] }
    })
if (-not (Test-QualificationBootstrap -Receipt $installationReceipt -HarnessEntries $installation -ExpectedCommit $HarnessCommit -ExpectedLauncherSha256 $LauncherSha256)) {
    throw 'Verifier installation does not match the independently pinned launcher.'
}

# --- 1. Seal ------------------------------------------------------------------------------------------
$sums = Join-Path $RunDir 'SHA256SUMS.txt'
$listed = @{}
foreach ($line in Get-Content -LiteralPath $sums) { $hash, $relative = $line -split '  ', 2; $listed[$relative] = $hash }
$actual = @(Get-ChildItem -LiteralPath $RunDir -Recurse -File -Force | Where-Object FullName -ne $sums)
$mismatch = @($actual | Where-Object {
        $relative = $_.FullName.Substring($RunDir.Length + 1)
        -not $listed.ContainsKey($relative) -or $listed[$relative] -ne (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
    } | ForEach-Object Name)
Report ($mismatch.Count -eq 0 -and $actual.Count -eq $listed.Count) 'evidence matches SHA256SUMS' (($mismatch | Select-Object -First 5) -join ', ')

# --- 2. Harness -----------------------------------------------------------------------------------------
$harness = @(Read-Manifest (Join-Path $RunDir 'provenance-harness.txt'))
$drift = @($harness | Where-Object { (Get-BlobAt $HarnessCommit ("scripts/validation/hyperv/" + ($_.Relative -replace '\\', '/'))) -ne $_.Blob } | ForEach-Object Relative)
Report ((Test-QualificationManifest -Entries $harness -ExpectedPaths @(Get-QualificationHarnessFiles)) -and $drift.Count -eq 0) "complete harness is commit $($HarnessCommit.Substring(0, 12))" ($drift -join ', ')
$bootstrapFile = Join-Path $RunDir 'provenance-bootstrap.json'
$bootstrap = if (Test-Path -LiteralPath $bootstrapFile) { Get-Content -LiteralPath $bootstrapFile -Raw | ConvertFrom-Json } else { $null }
Report (Test-QualificationBootstrap -Receipt $bootstrap -HarnessEntries $harness -ExpectedCommit $HarnessCommit -ExpectedLauncherSha256 $LauncherSha256) 'runner bootstrap matches the independently pinned launcher'

# --- 3. Candidate ---------------------------------------------------------------------------------------
$candidateFile = Join-Path $RunDir 'provenance-candidate.txt'
$claimed = ((Get-Content -LiteralPath $candidateFile -TotalCount 1) -replace '^.*claimed commit ', '').Trim()
$candidate = @(Read-Manifest $candidateFile)
$scripts = @($candidate | Where-Object { $_.Relative -like 'source\scripts\*' })
$scriptDrift = @($scripts | Where-Object {
        (Get-BlobAt $claimed ('scripts/' + ($_.Relative.Substring('source\scripts\'.Length) -replace '\\', '/'))) -ne $_.Blob
    } | ForEach-Object Relative)
$expectedScripts = @()
if ($claimed -cmatch '^[0-9a-f]{40}$') {
    $trackedScripts = @(& $git --no-replace-objects -C $Repository ls-tree -r --name-only $claimed -- scripts 2>$null)
    if ($LASTEXITCODE -eq 0) { $expectedScripts = @($trackedScripts | ForEach-Object { 'source\' + ($_ -replace '/', '\') }) }
}
Report ((Test-QualificationManifest -Entries $scripts -ExpectedPaths $expectedScripts) -and $scriptDrift.Count -eq 0) "complete candidate scripts are commit $($claimed.Substring(0, [Math]::Min(12, $claimed.Length)))" ($scriptDrift -join ', ')
# A qualification run keeps the guest's results at its root, a network run keeps the target's under target\.
$resultsFile = @('results.json', 'target\results.json' | ForEach-Object { Join-Path $RunDir $_ } | Where-Object { Test-Path -LiteralPath $_ })[0]
$results = if ($resultsFile) { Get-Content -LiteralPath $resultsFile -Raw | ConvertFrom-Json } else { $null }
Report (Test-QualificationArtifacts -Entries $candidate -Results $results -ExpectedCommit $claimed) 'successful identity gate checked the complete staged artifact triplet' $(if (-not $results) { 'no results.json in the run' })

# --- 4. Nobody else can write --------------------------------------------------------------------------
function Test-WriteRefused([string]$Check, [scriptblock]$Attempt) {
    try {
        & $Attempt
        Report $false $Check 'the write succeeded'
    }
    catch [UnauthorizedAccessException] { Report $true $Check }
    catch { Report ($_.Exception.InnerException -is [UnauthorizedAccessException]) $Check $_.Exception.Message }
}
$probe = 'winsight-provenance-probe-' + [Guid]::NewGuid().ToString('N')
# Existing evidence is only opened for writing and closed: a check must not damage what it checks.
function Open-ForWrite([string]$Path) { [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite).Dispose() }
Test-WriteRefused 'a new file in the run is refused' { [IO.File]::WriteAllText((Join-Path $RunDir $probe), 'x') }
Test-WriteRefused 'the seal cannot be opened for writing' { Open-ForWrite $sums }
Test-WriteRefused 'the results cannot be opened for writing' { Open-ForWrite $resultsFile }
Test-WriteRefused 'the protected harness is refused' { [IO.File]::WriteAllText((Join-Path $Root "harness\$probe"), 'x') }
Test-WriteRefused 'the staged candidates are refused' { [IO.File]::WriteAllText((Join-Path $Root "candidates\$probe"), 'x') }
Test-WriteRefused 'the VM storage is refused' { [IO.File]::WriteAllText((Join-Path $VmRoot $probe), 'x') }
Test-WriteRefused 'the protected root is refused' { [IO.Directory]::CreateDirectory((Join-Path $Root $probe)) | Out-Null }
# Every probe name is unique: one that did get written is left in plain sight for the operator.

if ($failures -gt 0) { "$failures check(s) failed: this run cannot be cited as provenance-bound evidence."; exit 1 }
'All checks passed.'
exit 0
