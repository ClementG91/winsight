# WinSight qualification on a clean VM

This protocol qualifies one exact commit, CI run, pair of artifacts, and native architecture. It
fails closed: a placeholder value, ambiguous file, missing hash, modified script, unreadable ETW
inventory, or unexported evidence means **STOP / RED**.

> [!CAUTION]
> Run privileged phases only in an isolated, disposable VM. Never install the service, modify WFP,
> or stop an ETW session on the development workstation.

## 0. Do not confuse version, tag, and candidate

The VM report from 29 July 2026 tested `main` commit
`a9fd4fbf783a3aabfca3682b9509be5d7330abcb`, built by CI run `30451063612`. Its files reported
version 0.10.5, but that commit differs from the historical `v0.10.5` tag (`51c8417...`). That
candidate exposed the `0x800705AA` ETW crash; neither identity denotes the corrected candidate.

## 1. Bind identity and preserve evidence

Enter the values from the new successful CI run:

```powershell
$Repo = 'ClementG91/winsight'
$CandidateSha = '<full 40-character SHA>'
# 'release' qualifies the published binary; 'ci' qualifies a pre-publication commit.
# See "Which artifact to qualify" in section 2: they are not interchangeable.
$ArtifactKind = 'release'
$RunId = '<id of successful run corresponding to ArtifactKind>'
$ProductVersion = '<product version>'
$ExpectedZipSha256 = '<SHA-256 of the portable ZIP>'
$ExpectedInstallerSha256 = '<SHA-256 of the installer>'
$RequireSigned = $false
$AcceptUnsignedDistribution = $true
$ExpectedPublisher = $null

# Volume mounted outside the VM snapshot, or durable network storage.
$EvidenceRoot = 'E:\WinSight-Evidence'
$EvidenceStorageOutsideSnapshot = $true
```

Mandatory checks:

```powershell
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($CandidateSha -notmatch '^[0-9a-fA-F]{40}$') { throw 'CandidateSha is not bound.' }
if ($Repo -cne 'ClementG91/winsight') { throw 'Repository is not bound.' }
if ([string]$RunId -notmatch '^[0-9]+$') { throw 'RunId is not bound.' }
if ($ArtifactKind -cnotin @('release', 'ci')) { throw 'ArtifactKind is not bound.' }
if ($ProductVersion -notmatch '^[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.-]+)?$') {
    throw 'ProductVersion is not bound.'
}
if ($ExpectedZipSha256 -notmatch '^[0-9a-fA-F]{64}$') { throw 'ZIP hash is not bound.' }
if ($ExpectedInstallerSha256 -notmatch '^[0-9a-fA-F]{64}$') {
    throw 'Installer hash is not bound.'
}
if (-not $EvidenceStorageOutsideSnapshot) { throw 'Evidence will not survive the restore.' }
$SystemVolumeRoot = [IO.Path]::GetPathRoot([Environment]::SystemDirectory)
$EvidenceFullPath = [IO.Path]::GetFullPath($EvidenceRoot)
if ([string]::Equals(
        [IO.Path]::GetPathRoot($EvidenceFullPath),
        $SystemVolumeRoot,
        [StringComparison]::OrdinalIgnoreCase)) {
    throw 'EvidenceRoot must be outside the volume restored with the VM.'
}
if ($RequireSigned -and [string]::IsNullOrWhiteSpace($ExpectedPublisher)) {
    throw 'An exact ExpectedPublisher is required for a signed candidate.'
}
if (-not $RequireSigned -and -not $AcceptUnsignedDistribution) {
    throw 'The Authenticode policy must be chosen explicitly.'
}

New-Item -ItemType Directory -Force $EvidenceRoot | Out-Null
$evidenceProbe = Join-Path $EvidenceRoot 'write-test.tmp'
[IO.File]::WriteAllText($evidenceProbe, 'external-evidence')
Remove-Item -LiteralPath $evidenceProbe -Force
```

Every transcript must begin with the SHA, run ID, both hashes, native architecture, snapshot name,
and UTC time. Before each snapshot restore, close the transcript, generate its SHA-256 manifest on
external storage, and verify from the hypervisor that the evidence was exported.

## 2. S0 snapshot and prerequisites

Snapshots are never created or restored from inside the guest. `VBoxManage` is a VirtualBox host
tool; its absence from the VM is expected.

### HOST ONLY — create and prove S0

Shut down the clean VM gracefully, then run the following on the host. For Hyper-V, VMware, or
another hypervisor, use the equivalent operation and retain host evidence containing the VM name,
snapshot name/identifier, powered-off state, command, exit code, and UTC time.

```powershell
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$VmName = '<exact VM name>'
$SnapshotName = 'S0-clean-before-winsight'
$HostEvidenceRoot = '<host directory outside the VM disk>'
$VBoxManage = Join-Path (
    [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)) `
    'Oracle\VirtualBox\VBoxManage.exe'

if (-not (Test-Path -LiteralPath $VBoxManage -PathType Leaf)) {
    throw 'VBoxManage.exe is missing on the host.'
}
if ((Get-AuthenticodeSignature -LiteralPath $VBoxManage).Status -ne 'Valid') {
    throw 'VBoxManage.exe has an invalid signature.'
}
New-Item -ItemType Directory -Force $HostEvidenceRoot | Out-Null
$before = @(& $VBoxManage showvminfo $VmName --machinereadable 2>&1)
if ($LASTEXITCODE -ne 0 -or ($before -join "`n") -notmatch 'VMState="poweroff"') {
    throw 'The VM must be turned off before the snapshot.'
}
@(& $VBoxManage snapshot $VmName take $SnapshotName 2>&1) | Out-Host
if ($LASTEXITCODE -ne 0) { throw 'S0 creation failed.' }
$snapshotInfo = @(& $VBoxManage snapshot $VmName showvminfo $SnapshotName 2>&1)
if ($LASTEXITCODE -ne 0) { throw 'Reading S0 evidence failed.' }
$machineInfo = @(& $VBoxManage showvminfo $VmName --machinereadable 2>&1)
if ($LASTEXITCODE -ne 0) { throw 'Reading VM configuration failed.' }
$record = Join-Path $HostEvidenceRoot "$SnapshotName.txt"
@(
    "utc=$([DateTime]::UtcNow.ToString('O'))"
    "vm=$VmName"
    "snapshot=$SnapshotName"
    'operation=take'
    '--- snapshot ---'
    $snapshotInfo
    '--- vm ---'
    $machineInfo
) | Set-Content -LiteralPath $record
Get-FileHash -LiteralPath $record -Algorithm SHA256
```

Copy or expose this file and its hash at
`$EvidenceRoot\host-snapshots\S0-clean-before-winsight.txt`. Without this host evidence, classify S0
as `NOT_RUN` and stop qualification; never attempt to run `VBoxManage` in the guest.

### GUEST — verify S0 and install prerequisites

```powershell
$S0HostRecord = Join-Path $EvidenceRoot 'host-snapshots\S0-clean-before-winsight.txt'
if (-not (Test-Path -LiteralPath $S0HostRecord -PathType Leaf)) {
    throw 'STOP: S0 host evidence is missing; snapshot is NOT_RUN.'
}
Get-FileHash -LiteralPath $S0HostRecord -Algorithm SHA256
```

The qualification shell must be native Windows PowerShell launched with `-NoProfile`. From the
first non-elevated shell, install the prerequisites, then immediately relaunch the exact shell:

```powershell
winget install --id Git.Git --source winget --accept-package-agreements --accept-source-agreements
winget install --id GitHub.cli --source winget --accept-package-agreements --accept-source-agreements

$NativeSystemDirectory = [Environment]::SystemDirectory
$NativePowerShellExe = Join-Path $NativeSystemDirectory 'WindowsPowerShell\v1.0\powershell.exe'
if (-not (Test-Path -LiteralPath $NativePowerShellExe -PathType Leaf)) {
    throw 'Native Windows PowerShell is missing.'
}
Start-Process -FilePath $NativePowerShellExe -ArgumentList @('-NoProfile', '-NoExit')
exit
```

In this new `-NoProfile` shell, derive every critical path from OS APIs and verify signatures before
use. Neither a `SystemRoot` value nor `PATH` resolution crosses the trust boundary:

```powershell
$NativeSystemDirectory = [Environment]::SystemDirectory
$ProgramFilesRoot = [Environment]::GetFolderPath(
    [Environment+SpecialFolder]::ProgramFiles)
$NativePowerShellExe = Join-Path $NativeSystemDirectory 'WindowsPowerShell\v1.0\powershell.exe'
$ScExe = Join-Path $NativeSystemDirectory 'sc.exe'
$CurlExe = Join-Path $NativeSystemDirectory 'curl.exe'
$GitExe = Join-Path $ProgramFilesRoot 'Git\cmd\git.exe'
$GhExe = Join-Path $ProgramFilesRoot 'GitHub CLI\gh.exe'

foreach ($tool in @($NativePowerShellExe, $ScExe, $CurlExe, $GitExe, $GhExe)) {
    if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) { throw "Exact tool is missing: $tool" }
    if ((Get-AuthenticodeSignature -LiteralPath $tool).Status -ne 'Valid') {
        throw "Tool has an invalid Authenticode signature: $tool"
    }
}
& $GhExe auth login --hostname github.com --git-protocol https --web
if ($LASTEXITCODE -ne 0) { throw 'gh authentication failed.' }
```

Determine hardware architecture with CIM, not from the process architecture:

```powershell
$cpuArchitectures = @(
    Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop |
        ForEach-Object { [int]$_.Architecture } |
        Sort-Object -Unique
)
if ($cpuArchitectures.Count -ne 1) { throw 'Ambiguous native architecture.' }
$NativeArchitecture = switch ($cpuArchitectures[0]) {
    9 { 'x64' }
    12 { 'arm64' }
    default { throw "Native architecture not supported: $($cpuArchitectures[0])." }
}
$ArtifactName = switch ($ArtifactKind) {
    'release' { "release-$NativeArchitecture" }
    'ci'      { "winsight-win-$NativeArchitecture" }
    default   { throw "Unbound ArtifactKind: '$ArtifactKind'." }
}
"native=$NativeArchitecture process=$env:PROCESSOR_ARCHITECTURE kind=$ArtifactKind artifact=$ArtifactName"
```

### Which artifact to qualify, and why the choice matters

`ci.yml` and `release.yml` build and package separately, and packaging is not bit-for-bit
reproducible: on candidate `3c8066f9`, the CI ZIP was `C6D28EEB…` while the published ZIP was
`CEC7D469…`. Each matched its own `.sha256`, but **qualifying one does not qualify the other**.

- `$ArtifactKind = 'release'` binds `$RunId` to the tag's `release.yml` run and retrieves
  `release-<arch>`. The `publish` job republishes those exact files (`files: release-assets/*`), so
  the qualified artifact is **byte-for-byte what the user downloads**. This is the only mode that
  produces evidence about the distributed binary.
- `$ArtifactKind = 'ci'` binds `$RunId` to a `ci.yml` run. It is useful for qualifying a commit
  before publication, but makes no claim about release assets.

A report must state its `ArtifactKind`. Omitting it invites the reader to assume the broadest scope,
which may be precisely the scope the evidence does not cover.

For an x64-on-Arm64 emulation test, use a separate evidence directory and title. Never change
`$NativeArchitecture` to present an x64 artifact as native Arm64 evidence.

## 3. Download without executing, then establish the protected root

Download into an untrusted landing area first. No candidate binary is executed at this stage:

```powershell
$SystemVolumeRoot = [IO.Path]::GetPathRoot([Environment]::SystemDirectory)
$LandingRoot = Join-Path $SystemVolumeRoot 'WinSight-Qualification-Landing'
New-Item -ItemType Directory -Force $LandingRoot | Out-Null

$run = & $GhExe api "repos/$Repo/actions/runs/$RunId" | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'Reading the CI run failed.' }
if ($run.head_sha -cne $CandidateSha -or $run.conclusion -cne 'success') {
    throw 'The CI run does not match the successful candidate.'
}
& $GhExe run download $RunId --repo $Repo -n $ArtifactName -D $LandingRoot
if ($LASTEXITCODE -ne 0) { throw 'Artifact download failed.' }

$portableZips = @(Get-ChildItem -LiteralPath $LandingRoot -Recurse -File -Filter 'winsight-*-win-*.zip')
$installers = @(Get-ChildItem -LiteralPath $LandingRoot -Recurse -File -Filter 'winsight-*-setup.exe')
if ($portableZips.Count -ne 1) { throw "Portable ZIP cardinality: $($portableZips.Count)." }
if ($installers.Count -ne 1) { throw "Setup: cardinality $($installers.Count)." }
if ((Get-FileHash $portableZips[0].FullName -Algorithm SHA256).Hash -cne
    $ExpectedZipSha256.ToUpperInvariant()) { throw 'ZIP hash mismatch in landing area.' }
if ((Get-FileHash $installers[0].FullName -Algorithm SHA256).Hash -cne
    $ExpectedInstallerSha256.ToUpperInvariant()) { throw 'Installer hash mismatch in landing area.' }
```

Open an elevated console from the exact shell, without a profile:

```powershell
Start-Process -FilePath $NativePowerShellExe -Verb RunAs `
    -ArgumentList @('-NoProfile', '-NoExit')
```

`Start-Process -Verb RunAs` does not carry PowerShell variables across elevation. In the new
console, execute the following bootstrap in full, re-entering **the same exact values** used in
section 1. Never replace this block with inherited variables, a profile, or a command resolved from
`PATH`:

```powershell
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Repo = 'ClementG91/winsight'
$CandidateSha = '<same full 40-character SHA>'
$ArtifactKind = '<same value: release or ci>'
$RunId = '<same successful run id>'
$ProductVersion = '<same product version>'
$ExpectedZipSha256 = '<same SHA-256 of the portable ZIP>'
$ExpectedInstallerSha256 = '<same SHA-256 of the setup>'
$RequireSigned = $false
$AcceptUnsignedDistribution = $true
$ExpectedPublisher = $null
$EvidenceRoot = 'E:\WinSight-Evidence'
$EvidenceStorageOutsideSnapshot = $true

if ($CandidateSha -notmatch '^[0-9a-fA-F]{40}$') { throw 'CandidateSha is not bound.' }
if ($Repo -cne 'ClementG91/winsight') { throw 'Repository is not bound.' }
if ([string]$RunId -notmatch '^[0-9]+$') { throw 'RunId is not bound.' }
if ($ArtifactKind -cnotin @('release', 'ci')) { throw 'ArtifactKind is not bound.' }
if ($ProductVersion -notmatch '^[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.-]+)?$') {
    throw 'ProductVersion is not bound.'
}
if ($ExpectedZipSha256 -notmatch '^[0-9a-fA-F]{64}$') { throw 'ZIP hash is not bound.' }
if ($ExpectedInstallerSha256 -notmatch '^[0-9a-fA-F]{64}$') {
    throw 'Installer hash is not bound.'
}
if (-not $EvidenceStorageOutsideSnapshot) { throw 'Evidence will not survive the restore.' }
if ($RequireSigned -and [string]::IsNullOrWhiteSpace($ExpectedPublisher)) {
    throw 'An exact ExpectedPublisher is required for a signed candidate.'
}
if (-not $RequireSigned -and -not $AcceptUnsignedDistribution) {
    throw 'The Authenticode policy must be chosen explicitly.'
}

$NativeSystemDirectory = [Environment]::SystemDirectory
$SystemVolumeRoot = [IO.Path]::GetPathRoot($NativeSystemDirectory)
$ProgramFilesRoot = [Environment]::GetFolderPath(
    [Environment+SpecialFolder]::ProgramFiles)
$NativePowerShellExe = Join-Path $NativeSystemDirectory 'WindowsPowerShell\v1.0\powershell.exe'
$ScExe = Join-Path $NativeSystemDirectory 'sc.exe'
$CurlExe = Join-Path $NativeSystemDirectory 'curl.exe'
$GitExe = Join-Path $ProgramFilesRoot 'Git\cmd\git.exe'
$GhExe = Join-Path $ProgramFilesRoot 'GitHub CLI\gh.exe'

foreach ($tool in @($NativePowerShellExe, $ScExe, $CurlExe, $GitExe, $GhExe)) {
    if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) { throw "Exact tool is missing: $tool" }
    if ((Get-AuthenticodeSignature -LiteralPath $tool).Status -ne 'Valid') {
        throw "Tool has an invalid Authenticode signature: $tool"
    }
}

$cpuArchitectures = @(
    Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop |
        ForEach-Object { [int]$_.Architecture } |
        Sort-Object -Unique
)
if ($cpuArchitectures.Count -ne 1) { throw 'Ambiguous native architecture after elevation.' }
$NativeArchitecture = switch ($cpuArchitectures[0]) {
    9 { 'x64' }
    12 { 'arm64' }
    default { throw "Native architecture not supported: $($cpuArchitectures[0])." }
}
$ArtifactName = switch ($ArtifactKind) {
    'release' { "release-$NativeArchitecture" }
    'ci'      { "winsight-win-$NativeArchitecture" }
    default   { throw "Unbound ArtifactKind after elevation: '$ArtifactKind'." }
}

$EvidenceFullPath = [IO.Path]::GetFullPath($EvidenceRoot)
if ([string]::Equals(
        [IO.Path]::GetPathRoot($EvidenceFullPath),
        $SystemVolumeRoot,
        [StringComparison]::OrdinalIgnoreCase)) {
    throw 'EvidenceRoot must be outside the volume restored with the VM.'
}
if (-not (Test-Path -LiteralPath $EvidenceRoot -PathType Container)) {
    throw 'External EvidenceRoot is not mounted in the elevated console.'
}
$evidenceProbe = Join-Path $EvidenceRoot 'elevated-write-test.tmp'
[IO.File]::WriteAllText($evidenceProbe, 'external-evidence')
Remove-Item -LiteralPath $evidenceProbe -Force

$LandingRoot = Join-Path $SystemVolumeRoot 'WinSight-Qualification-Landing'
$portableZips = @(
    Get-ChildItem -LiteralPath $LandingRoot -Recurse -File -Filter 'winsight-*-win-*.zip')
$installers = @(
    Get-ChildItem -LiteralPath $LandingRoot -Recurse -File -Filter 'winsight-*-setup.exe')
if ($portableZips.Count -ne 1) { throw "Portable ZIP cardinality: $($portableZips.Count)." }
if ($installers.Count -ne 1) { throw "Setup: cardinality $($installers.Count)." }
if ((Get-FileHash $portableZips[0].FullName -Algorithm SHA256).Hash -cne
    $ExpectedZipSha256.ToUpperInvariant()) { throw 'ZIP hash mismatch after elevation.' }
if ((Get-FileHash $installers[0].FullName -Algorithm SHA256).Hash -cne
    $ExpectedInstallerSha256.ToUpperInvariant()) { throw 'Installer hash mismatch after elevation.' }
```

Only after this bootstrap may you create the protected root under the real `Program Files`, clone
the exact commit with the absolute signed Git executable, and copy and re-hash the artifacts before
extraction:

```powershell
$ProtectedRoot = Join-Path $ProgramFilesRoot 'WinSight-Qualification'
$ProtectedArtifactRoot = Join-Path $ProtectedRoot 'artifacts'
$ProtectedPayloadRoot = Join-Path $ProtectedRoot 'payload'
$ProtectedSourceRoot = Join-Path $ProtectedRoot 'source'
if (Test-Path -LiteralPath $ProtectedRoot) {
    throw 'The protected root must be absent on the clean snapshot.'
}
New-Item -ItemType Directory -Path @($ProtectedArtifactRoot, $ProtectedPayloadRoot) | Out-Null

$ProtectedZip = Join-Path $ProtectedArtifactRoot $portableZips[0].Name
$ProtectedInstaller = Join-Path $ProtectedArtifactRoot $installers[0].Name
Copy-Item -LiteralPath $portableZips[0].FullName -Destination $ProtectedZip -Force
Copy-Item -LiteralPath $installers[0].FullName -Destination $ProtectedInstaller -Force
if ((Get-FileHash $ProtectedZip -Algorithm SHA256).Hash -cne
    $ExpectedZipSha256.ToUpperInvariant()) { throw 'Protected ZIP hash mismatch.' }
if ((Get-FileHash $ProtectedInstaller -Algorithm SHA256).Hash -cne
    $ExpectedInstallerSha256.ToUpperInvariant()) { throw 'Protected installer hash mismatch.' }

& $GitExe clone "https://github.com/$Repo.git" $ProtectedSourceRoot
if ($LASTEXITCODE -ne 0) { throw 'Candidate clone failed.' }
& $GitExe -C $ProtectedSourceRoot checkout --detach $CandidateSha
if ($LASTEXITCODE -ne 0) { throw 'Candidate checkout failed.' }
$sourceHead = & $GitExe -C $ProtectedSourceRoot rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'Candidate rev-parse failed.' }
if ($sourceHead -cne $CandidateSha) { throw 'Scripts are not bound to the candidate.' }

# Recheck the protected ZIP immediately before protected extraction.
if ((Get-FileHash $ProtectedZip -Algorithm SHA256).Hash -cne
    $ExpectedZipSha256.ToUpperInvariant()) { throw 'ZIP modified before extraction.' }
Expand-Archive -LiteralPath $ProtectedZip -DestinationPath $ProtectedPayloadRoot -Force
```

The Actions ZIP may be flat. Discover exactly one `winsight.exe`, then its two sibling EXEs:

```powershell
$cliCandidates = @(Get-ChildItem $ProtectedPayloadRoot -Recurse -File -Filter 'winsight.exe')
if ($cliCandidates.Count -ne 1) { throw "winsight.exe cardinality: $($cliCandidates.Count)." }
$PackageRoot = $cliCandidates[0].Directory.FullName
$Cli = Join-Path $PackageRoot 'winsight.exe'
$Dashboard = Join-Path $PackageRoot 'winsight-dashboard.exe'
$Service = Join-Path $PackageRoot 'winsight-firewall-service.exe'
$CandidateExecutables = @($Cli, $Dashboard, $Service)
foreach ($path in $CandidateExecutables) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "EXE is missing: $path" }
}
```

Before the first execution, run `Test-PeArchitecture.ps1` from the exact protected clone against
all three EXEs. Any mismatch stops the protocol:

```powershell
$PeScript = Join-Path $ProtectedSourceRoot 'scripts\Test-PeArchitecture.ps1'
$protectedStatus = @(& $GitExe -C $ProtectedSourceRoot status --porcelain)
if ($LASTEXITCODE -ne 0 -or $protectedStatus.Count -ne 0) {
    throw 'The protected clone was modified before the PE check.'
}
foreach ($path in $CandidateExecutables) {
    & $NativePowerShellExe `
        -NoProfile -NonInteractive -ExecutionPolicy Bypass `
        -File $PeScript -Path $path -Architecture $NativeArchitecture
    if ($LASTEXITCODE -ne 0) { throw "PE architecture mismatch: $path" }
}
```

Create protected manifests for the three EXEs and every script/module that will be executed:

```powershell
$ValidationFiles = @(
    $PeScript,
    (Join-Path $ProtectedSourceRoot 'scripts\Test-Installer.ps1'),
    (Join-Path $ProtectedSourceRoot 'scripts\Test-McpServer.ps1'),
    (Join-Path $ProtectedSourceRoot 'scripts\WinSightEtwValidation.psm1'),
    (Join-Path $PackageRoot 'Test-WfpValidation.ps1'),
    (Join-Path $PackageRoot 'Test-TrustBoundary.ps1'),
    (Join-Path $PackageRoot 'Test-IpcBoundary.ps1'),
    (Join-Path $PackageRoot 'Test-IpcNetworkObserver.ps1')
)
$CandidateHash = @{}
foreach ($path in $CandidateExecutables + $ValidationFiles) {
    $resolved = (Resolve-Path -LiteralPath $path).Path
    $CandidateHash[$resolved] = (Get-FileHash $resolved -Algorithm SHA256).Hash
}
$CandidateHash.GetEnumerator() | Sort-Object Name |
    ForEach-Object { "$($_.Value) *$($_.Name)" } |
    Set-Content (Join-Path $EvidenceRoot 'protected-candidate.sha256')

function Assert-CandidateFiles {
    foreach ($entry in $CandidateHash.GetEnumerator()) {
        if ((Get-FileHash -LiteralPath $entry.Key -Algorithm SHA256).Hash -cne $entry.Value) {
            throw "Protected candidate/script was modified: $($entry.Key)"
        }
    }
    if ((Get-FileHash $ProtectedZip -Algorithm SHA256).Hash -cne
        $ExpectedZipSha256.ToUpperInvariant()) { throw 'Protected ZIP modified.' }
    if ((Get-FileHash $ProtectedInstaller -Algorithm SHA256).Hash -cne
        $ExpectedInstallerSha256.ToUpperInvariant()) { throw 'Protected installer was modified.' }
}
```

Call `Assert-CandidateFiles` **immediately before every** `Start-Process`, module import, WinSight
command, SCM installation, WFP operation, or installer execution.

## 4. Authenticode and installer

On 29 July 2026, SignPath Foundation declined the free-program application because the project did
not yet show sufficient public adoption. The current policy is therefore explicit:
`$RequireSigned=$false` / `$AcceptUnsignedDistribution=$true`. This permits a clearly disclosed
unsigned distribution; hashes and attestations still do not provide a Windows publisher identity.
All four targets must be exactly `NotSigned`, with no signer or timestamp. Any other signature error
is RED.

The signed path remains available for a future certificate. With `$RequireSigned=$true`, the setup
and all three portable EXEs must be `Valid`, timestamped, and carry exactly the same
`$ExpectedPublisher` subject:

```powershell
function Assert-ExpectedSignature([string]$Path) {
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid' -or
        $null -eq $signature.SignerCertificate -or
        $signature.SignerCertificate.Subject -cne $ExpectedPublisher -or
        $null -eq $signature.TimeStamperCertificate) {
        throw "Invalid publisher/timestamp signature: $Path"
    }
}

Assert-CandidateFiles
$SignatureTargets = @($ProtectedInstaller) + $CandidateExecutables
if ($RequireSigned) {
    foreach ($path in $SignatureTargets) { Assert-ExpectedSignature $path }
}
else {
    $SignatureTargets | ForEach-Object {
        $sig = Get-AuthenticodeSignature $_
        if ($sig.Status -ne 'NotSigned' -or
            $null -ne $sig.SignerCertificate -or
            $null -ne $sig.TimeStamperCertificate) {
            throw "Unexpected unsigned state: $($_) status=$($sig.Status)"
        }
        $signer = if ($null -eq $sig.SignerCertificate) { '<none>' }
            else { $sig.SignerCertificate.Subject }
        $timestamp = if ($null -eq $sig.TimeStamperCertificate) { '<none>' }
            else { $sig.TimeStamperCertificate.Subject }
        "$($_) status=$($sig.Status) signer=$signer timestamp=$timestamp"
    } | Set-Content (Join-Path $EvidenceRoot 'unsigned-signature-status.txt')
}
```

Then validate the read-only report. An `integrity` exit code of 1 means "findings present", not a
crash:

```powershell
Assert-CandidateFiles
$integrityPath = Join-Path $EvidenceRoot 'integrity.json'
& $Cli integrity --json > $integrityPath
$integrityExit = $LASTEXITCODE
if ($integrityExit -notin @(0, 1)) { throw "Unexpected integrity exit: $integrityExit" }
$envelope = Get-Content $integrityPath -Raw | ConvertFrom-Json
# Verify the envelope before its contents: accepting an unknown version and merely hoping its shape
# matches would certify a report the protocol did not understand.
if ($envelope.schemaVersion -ne 1 -or $null -eq $envelope.generatedAt) {
    throw 'JSON envelope is missing or has an unexpected version.'
}
$integrity = @($envelope.reports)
if ($integrity.Count -ne 1 -or $integrity[0].tool -cne 'integrity' -or
    $null -eq $integrity[0].items -or $null -eq $integrity[0].notableCount -or
    $null -eq $integrity[0].unverifiedCount) {
    throw 'JSON integrity contract invalid.'
}
```

The exact protected script also verifies native architecture, the installer, and all three
**installed** EXEs. In signed mode it requires `Valid`, a non-zero timestamp, and one exact common
publisher:

```powershell
Assert-CandidateFiles
$installerArguments = @(
    '-NoProfile',
    '-NonInteractive',
    '-ExecutionPolicy', 'Bypass',
    '-File', (Join-Path $ProtectedSourceRoot 'scripts\Test-Installer.ps1'),
    '-InstallerPath', $ProtectedInstaller,
    '-Version', $ProductVersion,
    '-Architecture', $NativeArchitecture
)
if ($RequireSigned) {
    $installerArguments += @('-ExpectedPublisher', $ExpectedPublisher)
    $installerArguments += '-RequireSigned'
}
& $NativePowerShellExe @installerArguments
if ($LASTEXITCODE -ne 0) { throw 'Installer lifecycle failed.' }
```

## 5. Continuity across restores

Seal evidence from sections 1 through 4 under `$EvidenceRoot`. Shut down the VM, then restore
`S0-clean-before-winsight` **from the host only**. VirtualBox example, from the same protected host
shell used in section 2:

```powershell
$SnapshotName = 'S0-clean-before-winsight'
@(& $VBoxManage snapshot $VmName restore $SnapshotName 2>&1) | Out-Host
if ($LASTEXITCODE -ne 0) { throw 'Restore S0 failed.' }
$restoredInfo = @(& $VBoxManage showvminfo $VmName --machinereadable 2>&1)
if ($LASTEXITCODE -ne 0 -or
    ($restoredInfo -join "`n") -notmatch 'CurrentSnapshotName="S0-clean-before-winsight"') {
    throw 'Restore S0 not proven.'
}
$restoreRecord = Join-Path $HostEvidenceRoot 'restore-S0-clean-before-winsight.txt'
@(
    "utc=$([DateTime]::UtcNow.ToString('O'))"
    "vm=$VmName"
    "snapshot=$SnapshotName"
    'operation=restore'
    $restoredInfo
) | Set-Content -LiteralPath $restoreRecord
Get-FileHash -LiteralPath $restoreRecord -Algorithm SHA256
```

Export this host evidence to `$EvidenceRoot\host-restores\` before restarting the VM. If the
hypervisor or its record is unavailable from the host, the restore is `NOT_RUN`; an agent inside the
guest must neither invent evidence nor continue as if the disk had been restored. A restore removes
the prerequisites, variables, downloads, and protected root: do not continue with assumed paths.

After the restore:

1. remount `$EvidenceRoot`, verify it from outside the snapshot, and verify the host evidence
   `restore-S0-clean-before-winsight.txt`;
2. explicitly reset every variable from section 1;
3. reinstall Git/gh, reauthenticate, and recalculate `$NativeArchitecture`;
4. repeat sections 3 and 4 in full using the same run and hashes, including the executable bootstrap
   in every new elevated console;
5. compare the new `protected-candidate.sha256` with the exported manifest;
6. shut down the VM and only then create `S1-candidate-protected` from the host, using the same
   `take` + `showvminfo` + hash procedure used for S0.

Every privileged section below restores `S1` from the host, requires host evidence containing
`operation=restore`, opens native Windows PowerShell in the guest with `-NoProfile`, re-enters the
exact section 1 values, and executes only the recovery bootstrap below. Never replay section 3's
creation bootstrap on `S1`: it correctly requires an absent root and exists only to build the
snapshot.

### S1 recovery bootstrap

This block does not clone, download, or extract anything. It reconstructs the PowerShell context
lost during restore from S1's protected state, then compares all 11 protected candidate/script
files with the SHA-256 manifest sealed outside the snapshot. Any extra, missing, duplicate,
out-of-root, non-canonical, or modified entry invalidates the snapshot.

```powershell
# S1-RESUME-BOOTSTRAP
function Initialize-WinSightS1QualificationContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CandidateSha,
        [Parameter(Mandatory)][ValidateSet('release', 'ci')][string]$ArtifactKind,
        [Parameter(Mandatory)][string]$ExpectedZipSha256,
        [Parameter(Mandatory)][string]$ExpectedInstallerSha256,
        [Parameter(Mandatory)][string]$EvidenceRoot
    )

    if ($CandidateSha -notmatch '^[0-9a-fA-F]{40}$' -or
        $ExpectedZipSha256 -notmatch '^[0-9a-fA-F]{64}$' -or
        $ExpectedInstallerSha256 -notmatch '^[0-9a-fA-F]{64}$') {
        throw 'Unbound S1 identity.'
    }

    $NativeSystemDirectory = [Environment]::SystemDirectory
    $SystemVolumeRoot = [IO.Path]::GetPathRoot($NativeSystemDirectory)
    $ProgramFilesRoot = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::ProgramFiles)
    $NativePowerShellExe = Join-Path $NativeSystemDirectory `
        'WindowsPowerShell\v1.0\powershell.exe'
    $ScExe = Join-Path $NativeSystemDirectory 'sc.exe'
    $CurlExe = Join-Path $NativeSystemDirectory 'curl.exe'
    $GitExe = Join-Path $ProgramFilesRoot 'Git\cmd\git.exe'
    foreach ($tool in @($NativePowerShellExe, $ScExe, $CurlExe, $GitExe)) {
        if (-not (Test-Path -LiteralPath $tool -PathType Leaf) -or
            (Get-AuthenticodeSignature -LiteralPath $tool).Status -ne 'Valid') {
            throw "S1 tool is missing or not signed: $tool"
        }
    }
    $evidenceFullPath = [IO.Path]::GetFullPath($EvidenceRoot)
    if (-not (Test-Path -LiteralPath $evidenceFullPath -PathType Container) -or
        [string]::Equals(
            [IO.Path]::GetPathRoot($evidenceFullPath),
            $SystemVolumeRoot,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'S1 EvidenceRoot is missing or located on the restored volume.'
    }

    $cpuArchitectures = @(
        Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop |
            ForEach-Object { [int]$_.Architecture } |
            Sort-Object -Unique
    )
    if ($cpuArchitectures.Count -ne 1) { throw 'S1 architecture is ambiguous.' }
    $NativeArchitecture = switch ($cpuArchitectures[0]) {
        9 { 'x64' }
        12 { 'arm64' }
        default { throw "Unsupported S1 architecture: $($cpuArchitectures[0])." }
    }
    $ArtifactName = switch ($ArtifactKind) {
        'release' { "release-$NativeArchitecture" }
        'ci'      { "winsight-win-$NativeArchitecture" }
    }

    $ProtectedRoot = Join-Path $ProgramFilesRoot 'WinSight-Qualification'
    $ProtectedArtifactRoot = Join-Path $ProtectedRoot 'artifacts'
    $ProtectedPayloadRoot = Join-Path $ProtectedRoot 'payload'
    $ProtectedSourceRoot = Join-Path $ProtectedRoot 'source'
    foreach ($directory in @(
        $ProtectedRoot, $ProtectedArtifactRoot, $ProtectedPayloadRoot, $ProtectedSourceRoot)) {
        if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
            throw "Protected S1 directory is missing: $directory"
        }
    }

    $protectedZips = @(
        Get-ChildItem -LiteralPath $ProtectedArtifactRoot -File -Filter 'winsight-*-win-*.zip')
    $protectedInstallers = @(
        Get-ChildItem -LiteralPath $ProtectedArtifactRoot -File -Filter 'winsight-*-setup.exe')
    if ($protectedZips.Count -ne 1 -or $protectedInstallers.Count -ne 1) {
        throw 'Invalid S1 ZIP/installer cardinality.'
    }
    $ProtectedZip = $protectedZips[0].FullName
    $ProtectedInstaller = $protectedInstallers[0].FullName
    if ((Get-FileHash -LiteralPath $ProtectedZip -Algorithm SHA256).Hash -cne
        $ExpectedZipSha256.ToUpperInvariant() -or
        (Get-FileHash -LiteralPath $ProtectedInstaller -Algorithm SHA256).Hash -cne
        $ExpectedInstallerSha256.ToUpperInvariant()) {
        throw 'Invalid S1 ZIP/installer hash.'
    }

    $cliCandidates = @(
        Get-ChildItem -LiteralPath $ProtectedPayloadRoot -Recurse -File -Filter 'winsight.exe')
    if ($cliCandidates.Count -ne 1) { throw 'Invalid S1 winsight.exe cardinality.' }
    $PackageRoot = $cliCandidates[0].Directory.FullName
    $Cli = Join-Path $PackageRoot 'winsight.exe'
    $Dashboard = Join-Path $PackageRoot 'winsight-dashboard.exe'
    $Service = Join-Path $PackageRoot 'winsight-firewall-service.exe'
    $CandidateExecutables = @($Cli, $Dashboard, $Service)
    $PeScript = Join-Path $ProtectedSourceRoot 'scripts\Test-PeArchitecture.ps1'
    $ValidationFiles = @(
        $PeScript,
        (Join-Path $ProtectedSourceRoot 'scripts\Test-Installer.ps1'),
        (Join-Path $ProtectedSourceRoot 'scripts\Test-McpServer.ps1'),
        (Join-Path $ProtectedSourceRoot 'scripts\WinSightEtwValidation.psm1'),
        (Join-Path $PackageRoot 'Test-WfpValidation.ps1'),
        (Join-Path $PackageRoot 'Test-TrustBoundary.ps1'),
        (Join-Path $PackageRoot 'Test-IpcBoundary.ps1'),
        (Join-Path $PackageRoot 'Test-IpcNetworkObserver.ps1')
    )
    $ExpectedCandidatePaths = @(
        $CandidateExecutables + $ValidationFiles |
            ForEach-Object { (Resolve-Path -LiteralPath $_ -ErrorAction Stop).Path })
    if ($ExpectedCandidatePaths.Count -ne 11) {
        throw "The S1 candidate set must contain 11 files, not $($ExpectedCandidatePaths.Count)."
    }

    $resolvedProtectedRoot = (Resolve-Path -LiteralPath $ProtectedRoot).Path.TrimEnd('\')
    $protectedPrefix = $resolvedProtectedRoot + '\'
    foreach ($path in $ExpectedCandidatePaths) {
        if (-not $path.StartsWith($protectedPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Candidate path is outside ProtectedRoot: $path"
        }
    }

    $sourceHead = @(& $GitExe -C $ProtectedSourceRoot rev-parse HEAD)
    if ($LASTEXITCODE -ne 0 -or $sourceHead.Count -ne 1 -or
        $sourceHead[0] -cne $CandidateSha) {
        throw 'S1 source HEAD differs from the candidate.'
    }
    $sourceStatus = @(& $GitExe -C $ProtectedSourceRoot status --porcelain)
    if ($LASTEXITCODE -ne 0 -or $sourceStatus.Count -ne 0) {
        throw 'Protected S1 source was modified.'
    }

    $manifestPath = Join-Path $EvidenceRoot 'protected-candidate.sha256'
    $manifestLines = @(
        Get-Content -LiteralPath $manifestPath -ErrorAction Stop |
            Where-Object { $_.Length -gt 0 })
    if ($manifestLines.Count -ne 11) {
        throw "The manifest S1 must contain 11 entries, not $($manifestLines.Count)."
    }

    $CandidateHash = @{}
    foreach ($line in $manifestLines) {
        if ($line -cnotmatch '^(?<hash>[0-9A-F]{64}) \*(?<path>.+)$') {
            throw 'S1 manifest entry is non-canonical.'
        }
        $manifestPathValue = (Resolve-Path -LiteralPath $Matches.path -ErrorAction Stop).Path
        if ($manifestPathValue -cne $Matches.path -or
            -not $manifestPathValue.StartsWith(
                $protectedPrefix, [StringComparison]::OrdinalIgnoreCase) -or
            $ExpectedCandidatePaths -notcontains $manifestPathValue -or
            $CandidateHash.ContainsKey($manifestPathValue)) {
            throw "Unexpected or duplicated S1 manifest path: $manifestPathValue"
        }
        $actualHash = (Get-FileHash -LiteralPath $manifestPathValue -Algorithm SHA256).Hash
        if ($actualHash -cne $Matches.hash) {
            throw "S1 manifest hash mismatch: $manifestPathValue"
        }
        $CandidateHash[$manifestPathValue] = $Matches.hash
    }
    if ($CandidateHash.Count -ne 11 -or
        @($ExpectedCandidatePaths | Where-Object {
            -not $CandidateHash.ContainsKey($_)
        }).Count -ne 0) {
        throw 'The S1 manifest does not cover the candidate set exactly.'
    }

    [pscustomobject]@{
        NativeArchitecture = $NativeArchitecture
        ArtifactName = $ArtifactName
        NativePowerShellExe = $NativePowerShellExe
        ScExe = $ScExe
        CurlExe = $CurlExe
        GitExe = $GitExe
        ProtectedRoot = $ProtectedRoot
        ProtectedZip = $ProtectedZip
        ProtectedInstaller = $ProtectedInstaller
        ProtectedSourceRoot = $ProtectedSourceRoot
        PackageRoot = $PackageRoot
        Cli = $Cli
        Dashboard = $Dashboard
        Service = $Service
        CandidateExecutables = $CandidateExecutables
        ValidationFiles = $ValidationFiles
        CandidateHash = $CandidateHash
    }
}

$S1 = Initialize-WinSightS1QualificationContext `
    -CandidateSha $CandidateSha `
    -ArtifactKind $ArtifactKind `
    -ExpectedZipSha256 $ExpectedZipSha256 `
    -ExpectedInstallerSha256 $ExpectedInstallerSha256 `
    -EvidenceRoot $EvidenceRoot
foreach ($property in $S1.PSObject.Properties) {
    Set-Variable -Name $property.Name -Value $property.Value -Scope Local
}

function Assert-CandidateFiles {
    foreach ($entry in $CandidateHash.GetEnumerator()) {
        if ((Get-FileHash -LiteralPath $entry.Key -Algorithm SHA256).Hash -cne $entry.Value) {
            throw "Protected candidate/script was modified: $($entry.Key)"
        }
    }
    if ((Get-FileHash -LiteralPath $ProtectedZip -Algorithm SHA256).Hash -cne
        $ExpectedZipSha256.ToUpperInvariant() -or
        (Get-FileHash -LiteralPath $ProtectedInstaller -Algorithm SHA256).Hash -cne
        $ExpectedInstallerSha256.ToUpperInvariant()) {
        throw 'Protected ZIP/setup modified after S1 recovery.'
    }
}

Assert-CandidateFiles
$PeScript = Join-Path $ProtectedSourceRoot 'scripts\Test-PeArchitecture.ps1'
foreach ($path in $CandidateExecutables) {
    & $NativePowerShellExe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
        -File $PeScript -Path $path -Architecture $NativeArchitecture
    if ($LASTEXITCODE -ne 0) { throw "S1 PE architecture mismatch: $path" }
}
$EtwModule = Join-Path $ProtectedSourceRoot 'scripts\WinSightEtwValidation.psm1'
Import-Module $EtwModule -Force
```

After every `S1` restore, retain this bootstrap's transcript under a unique phase name in
`$EvidenceRoot`. A restore that does not complete this block is `NOT_RUN`, never PASS.

## 6. Native ETW inventory and recovery

The exact cloned module retries only the transient Windows error `0x800705AA` (`-2147020696`): at
most eight attempts, 250 ms apart. Any other non-zero code fails on the first attempt, and exhausting
all eight attempts also fails. It accepts tabular, multi-column, or localized tool output, but
returns only closed canonical legacy/v2 tokens:

```powershell
Assert-CandidateFiles
$EtwModule = Join-Path $ProtectedSourceRoot 'scripts\WinSightEtwValidation.psm1'
Import-Module $EtwModule -Force
$EtwGateStart = Get-Date
Start-Transcript (Join-Path $EvidenceRoot 'etw-resilience.txt') -Force
$before = @(Get-WinSightEtwSessionNames)
$before | Set-Content (Join-Path $EvidenceRoot 'etw-before.txt')
if ($before.Count -ne 0) { throw 'ETW snapshot is not clean.' }
```

### Dashboard attribution

The dashboard has no single-instance mutex. The elevated console passes its token to child
processes:

```powershell
Assert-CandidateFiles
$dashboardOne = Start-Process -FilePath $Dashboard -PassThru
Assert-CandidateFiles
$dashboardTwo = Start-Process -FilePath $Dashboard -PassThru
Start-Sleep -Seconds 15

function Get-AttributionSession([Diagnostics.Process]$Process) {
    $Process.Refresh()
    if ($Process.HasExited) { throw "Dashboard $($Process.Id) stopped." }
    Get-WinSightEtwSessionForProcess -Family Attribution -ProcessId $Process.Id
}
$sessionOne = Get-AttributionSession $dashboardOne
$sessionTwo = Get-AttributionSession $dashboardTwo
```

Close the first window with **X**: the captured process and `$sessionOne` must remain. Only then
force-stop **that captured process**:

```powershell
$dashboardOne.Refresh()
if ($dashboardOne.HasExited) { throw 'X exited the dashboard instead of hiding it.' }
if ((Get-WinSightEtwSessionNames) -notcontains $sessionOne) { throw 'Tray session is missing.' }
Stop-Process -InputObject $dashboardOne -Force
Start-Sleep -Seconds 2
if ((Get-WinSightEtwSessionNames) -notcontains $sessionOne) {
    throw 'The kill did not leave the expected orphan: result is inconclusive.'
}

Assert-CandidateFiles
$dashboardThree = Start-Process -FilePath $Dashboard -PassThru
Start-Sleep -Seconds 15
$sessionThree = Get-AttributionSession $dashboardThree
$dashboardTwo.Refresh()
if ($dashboardTwo.HasExited -or
    (Get-WinSightEtwSessionNames) -contains $sessionOne -or
    (Get-WinSightEtwSessionNames) -notcontains $sessionTwo) {
    throw 'Orphan recovery or live-session preservation failed.'
}
```

Repeat two kill/relaunch cycles using captured `Process` objects. The session count must never exceed
the number of live dashboards. Close survivors through the tray **Exit** command, wait for
`HasExited`, then require zero attribution sessions.

### DNS

Launch and retain the CLI process object, then use that object exclusively:

```powershell
Assert-CandidateFiles
$dnsOne = Start-Process -FilePath $Cli -ArgumentList @('dns', '--watch') -PassThru
Start-Sleep -Seconds 10
$dnsOne.Refresh()
if ($dnsOne.HasExited) { throw "The original DNS watcher exited with $($dnsOne.ExitCode)." }
$dnsSession = Get-WinSightEtwSessionForProcess -Family DNS -ProcessId $dnsOne.Id
Stop-Process -InputObject $dnsOne -Force
if ((Get-WinSightEtwSessionNames) -notcontains $dnsSession) {
    throw 'Expected DNS orphan is missing.'
}

Assert-CandidateFiles
$dnsTwo = Start-Process -FilePath $Cli -ArgumentList @('dns', '--watch') -PassThru
Start-Sleep -Seconds 10
$dnsTwo.Refresh()
if ($dnsTwo.HasExited) { throw "The restarted DNS watcher exited with $($dnsTwo.ExitCode)." }
$dnsTwoSession = Get-WinSightEtwSessionForProcess -Family DNS -ProcessId $dnsTwo.Id
if ((Get-WinSightEtwSessionNames) -contains $dnsSession) {
    throw 'The previous DNS orphan remains after the replacement watcher started.'
}
```

Send Ctrl+C to `$dnsTwo`'s console; do not replace it with a kill when proving graceful shutdown.
Then require bounded output, exit 0, and absence of the captured session:

```powershell
if (-not $dnsTwo.WaitForExit(30000)) { throw 'dnsTwo did not exit within 30 seconds after Ctrl+C.' }
if ($dnsTwo.ExitCode -ne 0) { throw "Unexpected dnsTwo exit: $($dnsTwo.ExitCode)." }
if ((Get-WinSightEtwSessionNames) -contains $dnsTwoSession) {
    throw 'Graceful DNS shutdown left its ETW session behind.'
}
```

### Outbound service

Restore `S1`. Explicitly install and start in AuditOnly mode with empty WFP state:

```powershell
Assert-CandidateFiles
& $Service install
if ($LASTEXITCODE -ne 0) { throw 'Install service failed.' }
& $ScExe start WinSightFirewall
if ($LASTEXITCODE -ne 0) { throw 'Start service failed.' }

$deadline = (Get-Date).AddSeconds(30)
do {
    $svc = Get-CimInstance Win32_Service -Filter "Name='WinSightFirewall'"
    if ($svc.State -eq 'Running' -and $svc.ProcessId -gt 0) { break }
    Start-Sleep -Milliseconds 250
} while ((Get-Date) -lt $deadline)
if ($svc.State -ne 'Running') { throw 'Service not running.' }

Assert-CandidateFiles
$mode = @(& $Service enforce-status); $modeExit = $LASTEXITCODE
Assert-CandidateFiles
$wfp = @(& $Service wfp-status); $wfpExit = $LASTEXITCODE
Assert-CandidateFiles
$ipc = @(& $Cli firewall-ipc-selftest); $ipcExit = $LASTEXITCODE
if ($modeExit -ne 0 -or ($mode -join "`n") -notmatch 'mode: AuditOnly\.' -or
    $wfpExit -ne 0 -or
    ($wfp -join "`n") -notmatch 'provider: absent, sublayer: absent, permit-filter: absent' -or
    $ipcExit -ne 0 -or ($ipc -join "`n") -notmatch 'serviceAvailable=true') {
    throw 'Precondition AuditOnly/WFP/IPC invalid.'
}
```

Rebind the PID immediately before the kill: CIM must still report the same PID, `Get-Process` must
succeed, and its canonical path must equal `$Service` exactly.

```powershell
$svcNow = Get-CimInstance Win32_Service -Filter "Name='WinSightFirewall'"
if ($svcNow.State -ne 'Running' -or $svcNow.ProcessId -ne $svc.ProcessId) {
    throw 'The SCM service PID changed before rebinding.'
}
$serviceProcess = Get-Process -Id ([int]$svcNow.ProcessId) -ErrorAction Stop
$canonicalOwnerPath = (Resolve-Path -LiteralPath $serviceProcess.Path).Path
$canonicalServicePath = (Resolve-Path -LiteralPath $Service).Path
if ($canonicalOwnerPath -cne $canonicalServicePath) { throw 'PID SCM does not point at the candidate.' }
$oldOutbound = Get-WinSightEtwSessionForProcess `
    -Family Outbound -ProcessId $serviceProcess.Id

# Final rebind with no intervening operation between verification and kill.
$svcKill = Get-CimInstance Win32_Service -Filter "Name='WinSightFirewall'"
if ($svcKill.ProcessId -ne $serviceProcess.Id -or
    (Resolve-Path -LiteralPath (Get-Process -Id $serviceProcess.Id -ErrorAction Stop).Path).Path -cne
    $canonicalServicePath) { throw 'PID/path changed before kill.' }
Stop-Process -InputObject $serviceProcess -Force
```

Wait for SCM to report Stopped, require the orphan, restart, require a new PID/session and absence of
the old one, AuditOnly with empty WFP state, available IPC, and HTTP 200 through System32
`curl.exe`. Then stop and uninstall:

```powershell
$deadline = (Get-Date).AddSeconds(30)
do {
    $svc = Get-CimInstance Win32_Service -Filter "Name='WinSightFirewall'"
    if ($svc.State -eq 'Stopped') { break }
    Start-Sleep -Milliseconds 250
} while ((Get-Date) -lt $deadline)
if ($svc.State -ne 'Stopped') { throw 'SCM did not observe the kill.' }
if ((Get-WinSightEtwSessionNames) -notcontains $oldOutbound) {
    throw 'Expected outbound orphan is missing: run is inconclusive.'
}

Assert-CandidateFiles
& $ScExe start WinSightFirewall
if ($LASTEXITCODE -ne 0) { throw 'Restart service failed.' }
$deadline = (Get-Date).AddSeconds(30)
do {
    $svcNew = Get-CimInstance Win32_Service -Filter "Name='WinSightFirewall'"
    if ($svcNew.State -eq 'Running' -and
        $svcNew.ProcessId -gt 0 -and
        $svcNew.ProcessId -ne $serviceProcess.Id) { break }
    Start-Sleep -Milliseconds 250
} while ((Get-Date) -lt $deadline)
if ($svcNew.State -ne 'Running' -or $svcNew.ProcessId -eq $serviceProcess.Id) {
    throw 'Service not restarted under a new PID.'
}
Start-Sleep -Seconds 10
$newOutbound = Get-WinSightEtwSessionForProcess `
    -Family Outbound -ProcessId ([int]$svcNew.ProcessId)
if ((Get-WinSightEtwSessionNames) -contains $oldOutbound) {
    throw 'Outbound recovery or the new session is incorrect.'
}

Assert-CandidateFiles
$mode = @(& $Service enforce-status); $modeExit = $LASTEXITCODE
Assert-CandidateFiles
$wfp = @(& $Service wfp-status); $wfpExit = $LASTEXITCODE
Assert-CandidateFiles
$ipc = @(& $Cli firewall-ipc-selftest); $ipcExit = $LASTEXITCODE
$http = & $CurlExe -s -o NUL -w '%{http_code}' `
    --max-time 20 https://example.com
$httpExit = $LASTEXITCODE
if ($modeExit -ne 0 -or ($mode -join "`n") -notmatch 'mode: AuditOnly\.' -or
    $wfpExit -ne 0 -or
    ($wfp -join "`n") -notmatch 'provider: absent, sublayer: absent, permit-filter: absent' -or
    $ipcExit -ne 0 -or ($ipc -join "`n") -notmatch 'serviceAvailable=true' -or
    $httpExit -ne 0 -or $http -ne '200') {
    throw 'AuditOnly/WFP/IPC/connectivity state is invalid after restart.'
}

& $ScExe stop WinSightFirewall | Out-Host
$deadline = (Get-Date).AddSeconds(30)
do {
    $svcNew = Get-CimInstance Win32_Service -Filter "Name='WinSightFirewall'"
    if ($svcNew.State -eq 'Stopped') { break }
    Start-Sleep -Milliseconds 250
} while ((Get-Date) -lt $deadline)
if ($svcNew.State -ne 'Stopped') { throw 'Service not stopped after recovery.' }
Assert-CandidateFiles
& $Service uninstall
if ($LASTEXITCODE -ne 0) { throw 'Uninstall service failed.' }
& $ScExe query WinSightFirewall 2>&1 | Out-Host
if ($LASTEXITCODE -ne 1060) { throw 'SCM error 1060 absence is not proven.' }
Start-Sleep -Seconds 3
$outboundAfter = @(Get-WinSightEtwSessionNames |
    Where-Object { $_ -cmatch '^WinSight-Outbound-(v2-)?' })
if ($outboundAfter.Count -ne 0) { throw 'Unexpected persistent outbound session.' }
```

The intermediate restart/reassertion block must be transcribed in full; any omission is `NOT_RUN`,
not PASS.

The native legacy PID-only scenario remains **externally NOT_RUN** in this kit: fabricating it with
an arbitrary `logman` command would not exercise the real TraceEvent legacy path. It requires a
separate allowlisted fixture bound to the candidate. Do not exhaust the ETW quota to simulate it.

Finish the gate with the module helper. Its Application log read uses `-ErrorAction Stop`; any read
exception aborts the run and can never become "zero crashes":

```powershell
Assert-WinSightEtwSessionsAbsent
$crashes = @(Get-WinSightRuntimeCrashEvents -StartTime $EtwGateStart)
if ($crashes.Count -ne 0) { throw 'WinSight .NET Runtime crash occurred during the ETW gate.' }
Stop-Transcript
```

## 7. WFP, trust, and IPC gates

Restore `S1` before each family and call `Assert-CandidateFiles` before every EXE/script.

```powershell
$wfpScript = Join-Path $PackageRoot 'Test-WfpValidation.ps1'
Assert-CandidateFiles
& $wfpScript -ContractSelfTest                   # expected 26/26, exit 0
if ($LASTEXITCODE -ne 0) { throw 'Contract SelfTest failed.' }
Assert-CandidateFiles
& $wfpScript -ContractSelfTest -ContractNegativeControl # expected 26/1, exit 1
if ($LASTEXITCODE -ne 1) { throw 'NegativeControl did not produce the exact RED result.' }
Assert-CandidateFiles
& $wfpScript -ServicePath $Service -SkipEnforcement     # expected 17/17
if ($LASTEXITCODE -ne 0) { throw 'Pre-arm 17/17 failed.' }
```

Shut down the VM and have the host create `S2-before-WFP` with sealed `take` evidence. Restart only
after exporting that host evidence, then run the full WFP gate: expected 35/35, exact SCM profile
(service SID, three required privileges, and recovery actions), target curl 200→000, control curl
200, armed stop with dynamic removal and return to 200, restart with blocking back at 000 while the
control remains 200, AuditOnly rollback, empty WFP state, restored connectivity, and SCM 1060. Any
S2 restore after failure is also a host operation requiring its own `operation=restore` evidence.
Then run trust: expected 13/13 with no skip and a real standard account supplied to
`-HostileAccount`.

```powershell
Assert-CandidateFiles
& $wfpScript -ServicePath $Service
if ($LASTEXITCODE -ne 0) { throw 'Full WFP 35/35 failed; restore S2.' }
Assert-CandidateFiles
& (Join-Path $PackageRoot 'Test-TrustBoundary.ps1') -ServicePath $Service `
    -HostileAccount '<dedicated standard account>'
if ($LASTEXITCODE -ne 0) { throw 'Trust 13/13 failed.' }
```

The final IPC gate starts from an `S1` restore and provides its own complete sequence:

```powershell
Assert-CandidateFiles
& $Service install
if ($LASTEXITCODE -ne 0) { throw 'IPC install failed.' }
& $ScExe start WinSightFirewall
if ($LASTEXITCODE -ne 0) { throw 'IPC start failed.' }
$deadline = (Get-Date).AddSeconds(30)
do {
    $ipcService = Get-CimInstance Win32_Service -Filter "Name='WinSightFirewall'"
    if ($ipcService.State -eq 'Running' -and $ipcService.ProcessId -gt 0) { break }
    Start-Sleep -Milliseconds 250
} while ((Get-Date) -lt $deadline)
if ($ipcService.State -ne 'Running' -or $ipcService.ProcessId -le 0) {
    throw 'IPC service not Running.'
}
Assert-CandidateFiles
$mode = @(& $Service enforce-status)
if ($LASTEXITCODE -ne 0 -or ($mode -join "`n") -notmatch 'mode: AuditOnly\.') {
    throw 'IPC service not AuditOnly.'
}
Assert-CandidateFiles
$wfp = @(& $Service wfp-status)
if ($LASTEXITCODE -ne 0 -or
    ($wfp -join "`n") -notmatch 'provider: absent, sublayer: absent, permit-filter: absent') {
    throw 'IPC WFP state is not empty.'
}
& (Join-Path $PackageRoot 'Test-IpcBoundary.ps1') -CliPath $Cli -ServicePath $Service
if ($LASTEXITCODE -ne 0) { throw 'IPC 7/7 failed.' }
# Elevated must be CanMutate; restricted must be CanReadOnly/Unauthorized.
# ReadableMutateSkipped is not an AuditOnly PASS.
```

### Network Logon — mandatory second control machine

A local process created with `LOGON32_LOGON_NETWORK` is not a reliable substitute. Literal evidence
must come through WinRM from a real second control machine on the same isolated private network. A
WinRM loop back to the same VM is not accepted. Without a second machine, classify this gate as
`NOT_RUN`.

In a workgroup, `Negotiate` permits only the built-in Administrator by default, so it cannot qualify
this scenario with a standard local account. Use a temporary HTTPS listener and `Basic`
**only over TLS**, with an ephemeral server certificate explicitly trusted by the control machine.
Never enable `AllowUnencrypted`, disable `LocalAccountTokenFilterPolicy`, or use `TrustedHosts` to
bypass this limit.

In the disposable S1 target guest, from elevated Windows PowerShell, assign static addresses on the
host-only network, verify its profile is `Private`, then create the standard account. The account
must belong only to `Users` and `Remote Management Users` (localized from SID `S-1-5-32-580`):

```powershell
$TargetAddress = '<exact host-only IPv4 address of target>'
$ControlAddress = '<exact host-only IPv4 address of control>'
$NetworkProbeUser = 'WinSightNetworkProbe'
$ControlEvidenceRoot = '<evidence storage outside snapshots, visible to both VMs>'
$CertificatePath = Join-Path $ControlEvidenceRoot 'winrm-network-probe.cer'
$NetworkProbePassword = Read-Host 'Disposable random password' -AsSecureString
$RemoteManagementGroup = Get-LocalGroup -SID 'S-1-5-32-580'

$TargetInterface = Get-NetIPAddress -AddressFamily IPv4 -IPAddress $TargetAddress -ErrorAction Stop
$OriginalNetworkCategory = (Get-NetConnectionProfile `
    -InterfaceIndex $TargetInterface.InterfaceIndex).NetworkCategory
Set-NetConnectionProfile -InterfaceIndex $TargetInterface.InterfaceIndex -NetworkCategory Private

New-LocalUser -Name $NetworkProbeUser -Password $NetworkProbePassword `
    -Description 'Disposable account for Network Logon qualification' | Out-Null
Add-LocalGroupMember -Group $RemoteManagementGroup.Name -Member $NetworkProbeUser
Enable-PSRemoting -SkipNetworkProfileCheck -Force

$RootSddlPath = 'WSMan:\localhost\Service\RootSDDL'
$OriginalRootSddl = [string](Get-Item -LiteralPath $RootSddlPath).Value
if ($OriginalRootSddl -notmatch [regex]::Escape('(A;;GR;;;RM)')) {
    if ($OriginalRootSddl -notmatch 'S:') { throw 'Unexpected RootSDDL: SACL is missing.' }
    $NetworkRootSddl = $OriginalRootSddl -replace 'S:', '(A;;GR;;;RM)S:'
    Set-Item -LiteralPath $RootSddlPath -Value $NetworkRootSddl -Force
}

$OriginalServiceBasic = [bool](Get-Item 'WSMan:\localhost\Service\Auth\Basic').Value
$Certificate = New-SelfSignedCertificate -Type SSLServerAuthentication `
    -Subject "CN=$env:COMPUTERNAME" `
    -TextExtension @("2.5.29.17={text}IPAddress=$TargetAddress&DNS=$env:COMPUTERNAME") `
    -CertStoreLocation 'Cert:\LocalMachine\My' -KeyAlgorithm RSA -KeyLength 2048 `
    -HashAlgorithm SHA256 -NotAfter (Get-Date).AddDays(1)
Export-Certificate -Cert $Certificate -FilePath $CertificatePath -Force | Out-Null
New-WSManInstance -ResourceURI 'winrm/config/Listener' `
    -SelectorSet @{ Address = '*'; Transport = 'HTTPS' } `
    -ValueSet @{ Hostname = $env:COMPUTERNAME; CertificateThumbprint = $Certificate.Thumbprint } |
    Out-Null
Set-Item 'WSMan:\localhost\Service\Auth\Basic' -Value $true -Force
$WinRmFirewallRule = 'WinSight qualification WinRM HTTPS'
New-NetFirewallRule -DisplayName $WinRmFirewallRule -Direction Inbound -Action Allow `
    -Protocol TCP -LocalPort 5986 -LocalAddress $TargetAddress `
    -RemoteAddress $ControlAddress -Profile Any | Out-Null
Restart-Service WinRM -Force
```

SCM and WMI normally deny their information to the standard Network account. The evidence is
therefore split without weakening ACLs: the remote probe performs 7 checks against its own token and
the IPC contract, while the supplied elevated observer performs 3 independent checks against the
target service. In the target's elevated console, always arm the observer before the remote
connection:

```powershell
$ObserverReady = Join-Path $ControlEvidenceRoot 'network-observer-ready.json'
$CompletionSignal = Join-Path $ControlEvidenceRoot 'network-probe-complete.signal'
$ObserverResult = Join-Path $ControlEvidenceRoot 'network-observer-result.json'
Remove-Item $ObserverReady,$CompletionSignal,$ObserverResult -Force -ErrorAction SilentlyContinue
$ObserverJob = Start-Job -ScriptBlock {
    param($Script, $Service, $Ready, $Complete, $Result)
    & $Script -ServicePath $Service -ReadyPath $Ready `
        -CompletionSignalPath $Complete -ResultPath $Result
} -ArgumentList (Join-Path $PackageRoot 'Test-IpcNetworkObserver.ps1'), `
    $Service, $ObserverReady, $CompletionSignal, $ObserverResult
$deadline = (Get-Date).AddSeconds(30)
while (-not (Test-Path $ObserverReady) -and (Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds 250
}
if (-not (Test-Path $ObserverReady)) { throw 'The network observer did not arm.' }
```

On the second machine, open elevated Windows PowerShell with `-NoProfile`. Import only the ephemeral
public certificate, use the simple local SAM name with `Basic`, execute the script with native
Windows PowerShell and `ExecutionPolicy Bypass`, then restore client configuration in a `finally`
block:

```powershell
$GuestAddress = '<exact host-only IPv4 address of target>'
$GuestPackageRoot = 'C:\Program Files\WinSight-Qualification\payload'
$ControlEvidenceRoot = '<same evidence storage outside snapshots>'
$CertificatePath = Join-Path $ControlEvidenceRoot 'winrm-network-probe.cer'
$CompletionSignal = Join-Path $ControlEvidenceRoot 'network-probe-complete.signal'
$credential = Get-Credential 'WinSightNetworkProbe'
Set-Service WinRM -StartupType Manual
Start-Service WinRM
Import-Module Microsoft.WSMan.Management
$importedCertificate = Import-Certificate -FilePath $CertificatePath `
    -CertStoreLocation 'Cert:\LocalMachine\Root'
$clientBasicPath = 'WSMan:\localhost\Client\Auth\Basic'
$previousClientBasic = [bool](Get-Item -LiteralPath $clientBasicPath).Value
$networkResult = $null

try {
    Set-Item -LiteralPath $clientBasicPath -Value $true -Force
    $networkResult = Invoke-Command -ComputerName $GuestAddress -Credential $credential `
        -UseSSL -Authentication Basic -ScriptBlock {
            param($RemotePackageRoot)
            $scriptPath = Join-Path $RemotePackageRoot 'Test-IpcBoundary.ps1'
            $cliPath = Join-Path $RemotePackageRoot 'winsight.exe'
            $servicePath = Join-Path $RemotePackageRoot 'winsight-firewall-service.exe'
            $nativePowerShell = Join-Path ([Environment]::SystemDirectory) `
                'WindowsPowerShell\v1.0\powershell.exe'
            $output = @(& $nativePowerShell -NoProfile -NonInteractive -ExecutionPolicy Bypass `
                -File $scriptPath -CliPath $cliPath -ServicePath $servicePath -NetworkLogon *>&1 |
                ForEach-Object { $_.ToString() })
            [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $output }
        } -ArgumentList $GuestPackageRoot
}
finally {
    [DateTime]::UtcNow.ToString('O') | Set-Content -LiteralPath $CompletionSignal
    Set-Item -LiteralPath $clientBasicPath -Value $previousClientBasic -Force
    Remove-Item -LiteralPath ("Cert:\LocalMachine\Root\{0}" -f `
        $importedCertificate.Thumbprint) -Force
}

$networkText = @($networkResult.Output) -join [Environment]::NewLine
$networkText | Set-Content (Join-Path $ControlEvidenceRoot 'ipc-network-logon.txt')
if ($networkResult.ExitCode -ne 0 -or
    $networkText -notmatch [regex]::Escape('Result: 7 checks, 0 failure(s).')) {
    throw 'Network Logon 7/7 failed.'
}
foreach ($required in @('S-1-5-2=true', 'S-1-5-4=false', 'serviceAvailable=false',
        'outcome=ServiceUnavailable', 'mutation=none')) {
    if ($networkText -notmatch [regex]::Escape($required)) {
        throw "Network Logon evidence is missing: $required"
    }
}
```

Return to the target, wait for the observer, and require its 3/3 result. The combined gate is 10/10,
but the two evidence sets remain distinct and attributed to their respective tokens:

```powershell
$ObserverJob | Wait-Job -Timeout 330 | Receive-Job
if ($ObserverJob.State -ne 'Completed') { throw 'Network observer not completed.' }
$ObserverEvidence = Get-Content -LiteralPath $ObserverResult -Raw | ConvertFrom-Json
if ($ObserverEvidence.Result -ne 'PASS' -or $ObserverEvidence.Checks -ne '3/3') {
    throw 'Target observer 3/3 failed.'
}
Write-Host 'Result: 3 checks, 0 failure(s).'
```

After exporting evidence, remove the listener, certificate, rule, and account, and restore the
saved values. The final S1 restore remains the authoritative proof that no state persists:

```powershell
Remove-WSManInstance -ResourceURI 'winrm/config/Listener' `
    -SelectorSet @{ Address = '*'; Transport = 'HTTPS' }
Set-Item 'WSMan:\localhost\Service\Auth\Basic' -Value $OriginalServiceBasic -Force
Set-Item -LiteralPath $RootSddlPath -Value $OriginalRootSddl -Force
Remove-NetFirewallRule -DisplayName $WinRmFirewallRule
Remove-Item -LiteralPath ("Cert:\LocalMachine\My\{0}" -f $Certificate.Thumbprint) -Force
Remove-LocalUser -Name $NetworkProbeUser
Set-NetConnectionProfile -InterfaceIndex $TargetInterface.InterfaceIndex `
    -NetworkCategory $OriginalNetworkCategory
Restart-Service WinRM -Force
```

Then return to the guest's elevated console:

```powershell
& $ScExe stop WinSightFirewall | Out-Host
$deadline = (Get-Date).AddSeconds(30)
do {
    $ipcService = Get-CimInstance Win32_Service -Filter "Name='WinSightFirewall'"
    if ($ipcService.State -eq 'Stopped') { break }
    Start-Sleep -Milliseconds 250
} while ((Get-Date) -lt $deadline)
if ($ipcService.State -ne 'Stopped') { throw 'IPC service is not stopped.' }
Assert-CandidateFiles
& $Service uninstall
if ($LASTEXITCODE -ne 0) { throw 'IPC uninstall failed.' }
& $ScExe query WinSightFirewall 2>&1 | Out-Host
if ($LASTEXITCODE -ne 1060) { throw 'IPC cleanup SCM 1060 not proven.' }
Assert-WinSightEtwSessionsAbsent
```

The script's elevated/restricted results, the UAC-filtered administrator, and the remote Network
Logon are four separate evidence sets. One token does not prove the others.

## 8. Seal, export, and restore

For every phase, the external directory must contain: SHA/run, artifact hashes, native and process
architectures, snapshot, commands/exits/accounts, candidate/script manifests, signatures/timestamps,
before/after ETW/SCM/WFP inventories, connectivity, tokens, and human actions.

```powershell
$manifest = Join-Path $EvidenceRoot 'MANIFEST.sha256.txt'
Get-ChildItem $EvidenceRoot -Recurse -File |
    Where-Object { $_.FullName -cne $manifest } |
    Get-FileHash -Algorithm SHA256 |
    Sort-Object Path |
    ForEach-Object { "$($_.Hash) *$($_.Path)" } |
    Set-Content $manifest
```

Export and seal outside the VM **before** restoring `S0`. Verify the manifest on the host, and only
then restore. Manual cleanup after uncertain state never turns a RED run into PASS.

x64, native Arm64, and x64 emulated on Arm64 are three distinct evidence scopes. Until the exact CI,
CodeQL, package, native/session variants, and human EN/FR/ES review are recorded,
`production_ready` remains false. Missing Authenticode is an accepted and visible distribution
limitation (`Unknown publisher`), not evidence of safety; enabling it later requires rerunning the
entire signed path.
