# Run UNELEVATED with Windows PowerShell 5.1. All fixtures are in memory; no VM, ACL, or disk writes.
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'QualificationProvenance.psm1') -Force
$failures = 0
$checks = 0
function Check([bool]$Passed, [string]$Name) {
    $script:checks++
    if (-not $Passed) { $script:failures++ }
    '{0} {1}' -f $(if ($Passed) { 'PASS' } else { 'FAIL' }), $Name
}
function Entry([string]$Relative, [string]$Hash = ('A' * 64)) {
    [pscustomobject]@{ Relative = $Relative; Sha256 = $Hash; Blob = ('b' * 40) }
}
function Results([string]$Status = 'PASS') {
    $map = [ordered]@{}
    foreach ($entry in $script:artifacts) { $map[$entry.Relative] = $entry.Sha256 }
    [pscustomobject]@{
        candidate = [pscustomobject]@{ commit = $script:commit; artifacts = [pscustomobject]$map }
        gates = [pscustomobject]@{ '01-identity-and-protected-root' = [pscustomobject]@{ status = $Status } }
    }
}
$paths = @(Get-QualificationHarnessFiles)
$manifest = @($paths | ForEach-Object { Entry $_ })
Check (Test-QualificationManifest -Entries $manifest -ExpectedPaths $paths) 'complete harness manifest accepted'
Check (-not (Test-QualificationManifest -Entries @() -ExpectedPaths $paths)) 'empty harness manifest refused'
Check (-not (Test-QualificationManifest -Entries @($manifest | Select-Object -Skip 1) -ExpectedPaths $paths)) 'harness subset refused'
Check (-not (Test-QualificationManifest -Entries ($manifest + (Entry 'extra.ps1')) -ExpectedPaths $paths)) 'unexpected harness entry refused'
Check (-not (Test-QualificationManifest -Entries ($manifest + $manifest[0]) -ExpectedPaths $paths)) 'duplicate harness entry refused'
$badHash = @($paths | ForEach-Object { Entry $_ })
$badHash[0].Sha256 = 'not-a-sha256'
Check (-not (Test-QualificationManifest -Entries $badHash -ExpectedPaths $paths)) 'malformed harness SHA256 refused'
$badBlob = @($paths | ForEach-Object { Entry $_ })
$badBlob[0].Blob = 'not-a-git-blob'
Check (-not (Test-QualificationManifest -Entries $badBlob -ExpectedPaths $paths)) 'malformed harness blob refused'

$commit = 'c' * 40
$artifacts = @(
    Entry 'winsight-v0.14.1-win-x64.zip'
    Entry 'winsight-v0.14.1-win-x64-setup.exe'
    Entry 'winsight-v0.14.1-win-x64.spdx.json'
)
$valid = Results
Check (Test-QualificationArtifacts -Entries $artifacts -Results $valid -ExpectedCommit $commit) 'complete matching artifacts and successful identity gate accepted'
$empty = Results
$empty.candidate.artifacts = [pscustomobject]@{}
Check (-not (Test-QualificationArtifacts -Entries $artifacts -Results $empty -ExpectedCommit $commit)) 'empty guest artifact map refused'
$subset = Results
$subset.candidate.artifacts.PSObject.Properties.Remove($artifacts[0].Relative)
Check (-not (Test-QualificationArtifacts -Entries $artifacts -Results $subset -ExpectedCommit $commit)) 'guest artifact subset refused'
$extra = Results
$extra.candidate.artifacts | Add-Member -NotePropertyName 'extra.zip' -NotePropertyValue ('A' * 64)
Check (-not (Test-QualificationArtifacts -Entries $artifacts -Results $extra -ExpectedCommit $commit)) 'extra guest artifact refused'
$wrongHash = Results
$wrongHash.candidate.artifacts.PSObject.Properties[$artifacts[0].Relative].Value = 'D' * 64
Check (-not (Test-QualificationArtifacts -Entries $artifacts -Results $wrongHash -ExpectedCommit $commit)) 'guest artifact hash mismatch refused'
foreach ($status in 'FAIL', 'NOT_RUN') {
    Check (-not (Test-QualificationArtifacts -Entries $artifacts -Results (Results $status) -ExpectedCommit $commit)) "identity gate $status refused"
}
$noGate = Results
$noGate.gates = [pscustomobject]@{}
Check (-not (Test-QualificationArtifacts -Entries $artifacts -Results $noGate -ExpectedCommit $commit)) 'missing identity gate refused'
Check (-not (Test-QualificationArtifacts -Entries $artifacts -Results $valid -ExpectedCommit ('d' * 40))) 'different candidate commit refused'
$duplicate = $artifacts + $artifacts[0]
Check (-not (Test-QualificationArtifacts -Entries $duplicate -Results $valid -ExpectedCommit $commit)) 'duplicate staged artifact refused'
$incompleteStage = @($artifacts | Select-Object -Skip 1)
$incompleteGuest = Results
$incompleteGuest.candidate.artifacts.PSObject.Properties.Remove($artifacts[0].Relative)
Check (-not (Test-QualificationArtifacts -Entries $incompleteStage -Results $incompleteGuest -ExpectedCommit $commit)) 'matching incomplete release artifact triplet refused'
$malformedStage = @($artifacts | ForEach-Object { Entry $_.Relative 'bad-hash' })
$malformedGuest = Results
foreach ($property in $malformedGuest.candidate.artifacts.PSObject.Properties) { $property.Value = 'bad-hash' }
Check (-not (Test-QualificationArtifacts -Entries $malformedStage -Results $malformedGuest -ExpectedCommit $commit)) 'matching malformed artifact hashes refused'
$receipt = [pscustomobject]@{ schemaVersion = 1; harnessCommit = $commit; launcherSha256 = ('e' * 64); files = $manifest }
Check (Test-QualificationBootstrap -Receipt $receipt -HarnessEntries $manifest -ExpectedCommit $commit -ExpectedLauncherSha256 ('e' * 64)) 'matching externally pinned bootstrap accepted'
Check (-not (Test-QualificationBootstrap -Receipt $null -HarnessEntries $manifest -ExpectedCommit $commit -ExpectedLauncherSha256 ('e' * 64))) 'historical run without bootstrap receipt refused'
Check (-not (Test-QualificationBootstrap -Receipt $receipt -HarnessEntries $manifest -ExpectedCommit $commit -ExpectedLauncherSha256 ('f' * 64))) 'different external launcher digest refused'
Check (-not (Test-QualificationBootstrap -Receipt $receipt -HarnessEntries $manifest -ExpectedCommit ('d' * 40) -ExpectedLauncherSha256 ('e' * 64))) 'different bootstrap commit refused'
$changedManifest = @($paths | ForEach-Object { Entry $_ })
$changedManifest[0].Sha256 = 'F' * 64
Check (-not (Test-QualificationBootstrap -Receipt $receipt -HarnessEntries $changedManifest -ExpectedCommit $commit -ExpectedLauncherSha256 ('e' * 64))) 'post-bootstrap harness change refused'
$receipt.files = @($manifest | Select-Object -Skip 1)
Check (-not (Test-QualificationBootstrap -Receipt $receipt -HarnessEntries $manifest -ExpectedCommit $commit -ExpectedLauncherSha256 ('e' * 64))) 'incomplete bootstrap inventory refused'
"$checks checks, $failures failures."
if ($failures -gt 0) { exit 1 }
exit 0
