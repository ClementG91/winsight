[CmdletBinding()]
param(
    [string]$Solution = "winsight.sln"
)

$ErrorActionPreference = "Stop"
$json = & dotnet list $Solution package --vulnerable --include-transitive --format json
if ($LASTEXITCODE -ne 0) {
    throw "NuGet vulnerability audit failed to execute."
}

$report = ($json -join [Environment]::NewLine) | ConvertFrom-Json
$findings = @()
foreach ($project in $report.projects) {
    foreach ($framework in @($project.frameworks)) {
        foreach ($group in @("topLevelPackages", "transitivePackages")) {
            foreach ($package in @($framework.$group)) {
                foreach ($vulnerability in @($package.vulnerabilities)) {
                    if ($null -ne $vulnerability) {
                        $findings += [pscustomobject]@{
                            Project = $project.path
                            Package = $package.id
                            Version = $package.resolvedVersion
                            Severity = $vulnerability.severity
                            Advisory = $vulnerability.advisoryUrl
                        }
                    }
                }
            }
        }
    }
}

if ($findings.Count -gt 0) {
    $findings | Format-Table -AutoSize | Out-String | Write-Error
    throw "$($findings.Count) vulnerable NuGet package(s) detected."
}

Write-Host "NuGet audit passed: no known vulnerable direct or transitive packages."
