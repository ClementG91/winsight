# Pure checks shared by the protected verifier and the unelevated behavioral tests.
function Get-QualificationHarnessFiles {
    @(
        'WinSightHyperV.psm1', 'QualificationProvenance.psm1', 'WinSightQualRunner.ps1',
        'Invoke-HyperVQualification.ps1', 'Invoke-HyperVNetworkLogon.ps1',
        'New-WinSightHyperVVm.ps1', 'New-WinSightControlVm.ps1', 'Protect-WinSightVmStorage.ps1',
        'Verify-QualificationProvenance.ps1', 'guest\run-guest-checks.ps1',
        'guest\control-network-logon.ps1', 'guest\qualify.ps1', 'guest\operator-automation.ps1'
    )
}

function Test-QualificationManifest {
    param([AllowEmptyCollection()][object[]]$Entries, [string[]]$ExpectedPaths)
    if (-not $ExpectedPaths -or $Entries.Count -ne $ExpectedPaths.Count) { return $false }
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $Entries) {
        if (-not $entry -or $entry.Relative -notin $ExpectedPaths -or
            -not $seen.Add([string]$entry.Relative) -or
            [string]$entry.Sha256 -notmatch '^[0-9a-fA-F]{64}$' -or
            [string]$entry.Blob -notmatch '^[0-9a-fA-F]{40}$') { return $false }
    }
    return $seen.Count -eq $ExpectedPaths.Count
}

function Test-QualificationArtifacts {
    param([AllowEmptyCollection()][object[]]$Entries, $Results, [string]$ExpectedCommit)
    try {
        if (-not $Results -or $ExpectedCommit -notmatch '^[0-9a-f]{40}$' -or
            $Results.candidate.commit -cne $ExpectedCommit -or
            $Results.gates.'01-identity-and-protected-root'.status -cne 'PASS') { return $false }
        $artifacts = @($Entries | Where-Object {
                $_.Relative -match '^winsight-v[0-9][0-9A-Za-z.+-]*-win-(x64|arm64)(-setup\.exe|\.zip|\.spdx\.json)$'
            })
        if ($artifacts.Count -ne 3) { return $false }
        $stem = [regex]::Replace([string]$artifacts[0].Relative, '(-setup\.exe|\.zip|\.spdx\.json)$', '')
        $expected = @("$stem.zip", "$stem-setup.exe", "$stem.spdx.json")
        if (-not (Test-QualificationManifest -Entries $artifacts -ExpectedPaths $expected)) { return $false }
        $reported = @($Results.candidate.artifacts.PSObject.Properties)
        if ($reported.Count -ne $expected.Count) { return $false }
        foreach ($property in $reported) {
            if ($property.Name -notin $expected -or [string]$property.Value -notmatch '^[0-9a-fA-F]{64}$') { return $false }
            $staged = @($artifacts | Where-Object Relative -eq $property.Name)
            if ($staged.Count -ne 1 -or $staged[0].Sha256 -ine $property.Value) { return $false }
        }
        return $true
    }
    catch { return $false }
}

function Test-QualificationBootstrap {
    param($Receipt, [object[]]$HarnessEntries, [string]$ExpectedCommit, [string]$ExpectedLauncherSha256)
    try {
        if (-not $Receipt -or $Receipt.schemaVersion -ne 1 -or
            $ExpectedCommit -notmatch '^[0-9a-f]{40}$' -or $Receipt.harnessCommit -cne $ExpectedCommit -or
            $ExpectedLauncherSha256 -notmatch '^[0-9a-fA-F]{64}$' -or
            $Receipt.launcherSha256 -ine $ExpectedLauncherSha256) { return $false }
        $paths = @(Get-QualificationHarnessFiles)
        if (-not (Test-QualificationManifest -Entries @($Receipt.files) -ExpectedPaths $paths) -or
            -not (Test-QualificationManifest -Entries $HarnessEntries -ExpectedPaths $paths)) { return $false }
        foreach ($entry in $HarnessEntries) {
            $installed = @($Receipt.files | Where-Object Relative -eq $entry.Relative)
            if ($installed.Count -ne 1 -or $installed[0].Sha256 -ine $entry.Sha256 -or
                $installed[0].Blob -ine $entry.Blob) { return $false }
        }
        return $true
    }
    catch { return $false }
}

Export-ModuleMember -Function Get-QualificationHarnessFiles, Test-QualificationManifest, Test-QualificationArtifacts, Test-QualificationBootstrap
