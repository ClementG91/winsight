[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Import-Module (Join-Path $PSScriptRoot 'WinSightEtwValidation.psm1') -Force

$savedSystemRoot = $env:SystemRoot
$savedPath = $env:Path
try
{
    $env:SystemRoot = 'C:\hostile-system-root'
    $env:Path = 'C:\hostile-path'
    $expectedLogman = [IO.Path]::Combine([Environment]::SystemDirectory, 'logman.exe')
    if ((Get-WinSightSystemLogmanPath) -cne $expectedLogman) {
        throw 'SystemDirectory logman resolver used poisoned environment state.'
    }
}
finally
{
    $env:SystemRoot = $savedSystemRoot
    $env:Path = $savedPath
}

$switchFixture = Join-Path $PSScriptRoot 'fixtures\RequireSignedBindingFixture.ps1'
$nativePowerShell = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
$absentArguments = @('-NoProfile', '-NonInteractive', '-File', $switchFixture)
$presentArguments = @('-NoProfile', '-NonInteractive', '-File', $switchFixture, '-RequireSigned')
$absentBound = [Convert]::ToBoolean([string](& $nativePowerShell @absentArguments))
$presentBound = [Convert]::ToBoolean([string](& $nativePowerShell @presentArguments))
if ($absentBound -or -not $presentBound) {
    throw 'PowerShell 5.1 array argument binding did not preserve RequireSigned absent/present.'
}

$names = @(Get-WinSightEtwSessionNames -Lines @(
    'WinSight-Attribution-v2-71-0123456789ABCDEF  Trace  Running',
    'Nom de la session : WinSight-DNS-72',
    'WinSight-Outbound-v2-73-FEDCBA9876543210 running',
    'WinSight-Attribution-v2-74-0123456789abcdef',
    'prefixWinSight-DNS-75',
    'WinSight-DNS-v2-0-0123456789ABCDEF',
    'WinSight-DNS-v2-76-0123456789ABCDEF-extra',
    'WinSight-DNS-v2-77-0123456789ABCDEF_extra'
))
$expected = @(
    'WinSight-Attribution-v2-71-0123456789ABCDEF',
    'WinSight-DNS-72',
    'WinSight-Outbound-v2-73-FEDCBA9876543210'
)
if ((@($names) -join '|') -cne ($expected -join '|'))
{
    throw "Exact ETW token extraction failed: $($names -join ', ')."
}

try
{
    Get-WinSightEtwSessionNames -Lines @('WinSight-DNS-77') -ExitCode 1 | Out-Null
    throw 'A nonzero logman exit code was accepted.'
}
catch [System.Management.Automation.RuntimeException]
{
    if ($_.Exception.Message -notlike 'logman query -ets failed*') { throw }
}

Assert-WinSightEtwSessionsAbsent -Lines @()
try
{
    Assert-WinSightEtwSessionsAbsent -Lines @('Type WinSight-Attribution-78 Running')
    throw 'A remaining exact session was accepted.'
}
catch [System.Management.Automation.RuntimeException]
{
    if ($_.Exception.Message -notlike 'WinSight ETW sessions remain*') { throw }
}

$session = Get-WinSightEtwSessionForProcess -Family Attribution -ProcessId 91 -Lines @(
    'WinSight-Attribution-v2-91-0123456789ABCDEF'
)
if ($session -cne 'WinSight-Attribution-v2-91-0123456789ABCDEF') {
    throw 'Exact v2 process session was not returned.'
}
foreach ($lines in @(
    @('WinSight-Attribution-91'),
    @('WinSight-Attribution-v2-92-0123456789ABCDEF')
)) {
    try {
        Get-WinSightEtwSessionForProcess -Family Attribution -ProcessId 91 -Lines $lines | Out-Null
        throw 'Missing/replaced v2 process session was accepted.'
    }
    catch [System.Management.Automation.RuntimeException] {
        if ($_.Exception.Message -notlike 'Expected exactly one WinSight Attribution v2 ETW session*') { throw }
    }
}

$start = [datetime]::UtcNow
if (@(Get-WinSightRuntimeCrashEvents -StartTime $start -Query { param($filter) @() }).Count -ne 0) {
    throw 'Empty Runtime 1026 query was not accepted as empty.'
}
$crashes = @(Get-WinSightRuntimeCrashEvents -StartTime $start -Query {
    param($filter)
    [pscustomobject]@{ Message = 'WinSight ETW crash 0x800705AA' }
})
if ($crashes.Count -ne 1) { throw 'Matching Runtime 1026 crash was not returned.' }
if (@(Get-WinSightRuntimeCrashEvents -StartTime $start -Query {
    param($filter)
    throw [System.Management.Automation.ErrorRecord]::new(
        [InvalidOperationException]::new('none'),
        'NoMatchingEventsFound,Microsoft.PowerShell.Commands.GetWinEventCommand',
        [System.Management.Automation.ErrorCategory]::ObjectNotFound, $null)
}).Count -ne 0) {
    throw 'NoMatchingEventsFound was not accepted as a valid empty query.'
}
try {
    Get-WinSightRuntimeCrashEvents -StartTime $start -Query { param($filter) throw 'access denied' } | Out-Null
    throw 'Runtime event query failure was accepted.'
}
catch [System.Management.Automation.RuntimeException] {
    if ($_.Exception.Message -cne 'Unable to query .NET Runtime event 1026; ETW crash gate is STOP.') { throw }
}

Write-Output 'WinSight ETW validation module contract passed.'
