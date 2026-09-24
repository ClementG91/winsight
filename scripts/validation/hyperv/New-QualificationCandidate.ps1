# Run UNELEVATED. Assembles a qualification candidate in the runner's request folder from a local
# release build, for a {"action":"stage","candidate":"<Name>"} request (README.md, "Each campaign").
#
# The candidate is: the x64 artifacts Build-Release.ps1 produced, the repository's scripts at the same
# commit (the gates run them), the published installer the upgrade gate starts from, and
# candidate.json binding them all by SHA-256 to that commit. The build tree must be a clean checkout
# of the commit, or nothing is assembled.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$BuildTree,
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$')][string]$Name,
    [Parameter(Mandatory)][string]$PreviousInstaller,
    [Parameter(Mandatory)][ValidatePattern('^[0-9A-Fa-f]{64}$')][string]$PreviousSha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$PreviousCommit,
    [string]$PreviousVersion = '0.13.0',
    [string]$Requests = (Join-Path ([IO.Path]::GetPathRoot($PSScriptRoot)) 'WinSight-Qualification-Requests'),
    [string]$Architecture = 'x64'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$commit = (& git -C $BuildTree rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0) { throw "Not a git checkout: $BuildTree" }
$dirty = @(& git -C $BuildTree status --porcelain --untracked-files=no)
if ($dirty.Count -gt 0) { throw "The build tree has uncommitted changes; build from a clean checkout of the commit." }
$version = (Select-Xml -Path (Join-Path $BuildTree 'Directory.Build.props') -XPath '//Version').Node.InnerText
if (-not $version) { throw 'No <Version> in Directory.Build.props.' }
$release = Join-Path $BuildTree 'out\release'
$artifactNames = @(
    "winsight-v$version-win-$Architecture-setup.exe",
    "winsight-v$version-win-$Architecture.zip",
    "winsight-v$version-win-$Architecture.spdx.json"
)

$candidate = Join-Path $Requests "candidates\$Name"
if (Test-Path -LiteralPath $candidate) { throw "Candidate $Name already exists; choose a new name." }
[void](New-Item -ItemType Directory -Path (Join-Path $candidate 'previous') -Force)
function Get-Sha256([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash }

$artifacts = [ordered]@{}
foreach ($artifact in $artifactNames) {
    $path = Join-Path $release $artifact
    if (-not (Test-Path -LiteralPath $path)) { throw "Missing artifact: $path" }
    Copy-Item -LiteralPath $path -Destination $candidate
    $artifacts[$artifact] = Get-Sha256 (Join-Path $candidate $artifact)
    $sidecar = "$path.sha256"
    if (Test-Path -LiteralPath $sidecar) { Copy-Item -LiteralPath $sidecar -Destination $candidate }
}

# The repository's scripts at the commit, tracked files only, as the gates will run them.
$source = [ordered]@{}
foreach ($relative in @(& git -C $BuildTree ls-files -- scripts) | Sort-Object) {
    $windowsRelative = $relative -replace '/', '\'
    $destination = Join-Path $candidate "source\$windowsRelative"
    [void](New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force)
    Copy-Item -LiteralPath (Join-Path $BuildTree $windowsRelative) -Destination $destination
    $source[$windowsRelative] = Get-Sha256 $destination
}

$previousName = Split-Path -Leaf $PreviousInstaller
Copy-Item -LiteralPath $PreviousInstaller -Destination (Join-Path $candidate 'previous')
if ((Get-Sha256 (Join-Path $candidate "previous\$previousName")) -ne $PreviousSha256.ToUpperInvariant()) {
    throw "The previous installer does not have the pinned hash $PreviousSha256."
}

[ordered]@{
    version = $version
    commit = $commit
    runId = 'local-unsigned-rehearsal'
    runUrl = $null
    note = "Local Build-Release.ps1 -DisableSignature -Architectures $Architecture build of $commit; a rehearsal, not CI-attested release evidence. Staged through the protected runner (scripts/validation/hyperv)."
    stagedUtc = [DateTime]::UtcNow.ToString('o')
    artifacts = $artifacts
    source = $source
    previous = [ordered]@{ file = $previousName; sha256 = $PreviousSha256.ToUpperInvariant(); version = $PreviousVersion; commit = $PreviousCommit }
} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $candidate 'candidate.json') -Encoding UTF8

"Candidate $Name ($commit, $version): $($artifacts.Count) artifacts, $($source.Count) scripts, previous $previousName."
$artifacts.GetEnumerator() | ForEach-Object { "  $($_.Value)  $($_.Key)" }
