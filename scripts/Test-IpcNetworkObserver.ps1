<#
.SYNOPSIS
    Observes the privileged service while a separate machine runs the Network-logon IPC probe.

.DESCRIPTION
    Run elevated on the target VM. The Network-only account is deliberately unable to query the
    Service Control Manager or WMI on a hardened machine, so this target-side observer records the
    service PID and command line before the remote attempt and proves that the exact instance is
    still running afterwards. Evidence paths should point to storage outside the target snapshot.
#>
[CmdletBinding()]
param(
    [string]$ServicePath = (Join-Path $PSScriptRoot 'winsight-firewall-service.exe'),

    [Parameter(Mandatory)]
    [string]$ReadyPath,

    [Parameter(Mandatory)]
    [string]$CompletionSignalPath,

    [Parameter(Mandatory)]
    [string]$ResultPath,

    [ValidateRange(10, 1800)]
    [int]$TimeoutSeconds = 300
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-JsonEvidence([object]$Value, [string]$Path) {
    $parent = Split-Path -Parent $Path
    if ([string]::IsNullOrWhiteSpace($parent) -or -not (Test-Path -LiteralPath $parent -PathType Container)) {
        throw "Evidence directory does not exist: $parent"
    }
    $Value | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $Path -Encoding utf8
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
try {
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'The target-side Network observer requires an elevated token.'
    }

    $resolvedServicePath = (Resolve-Path -LiteralPath $ServicePath).Path
    $expectedCommand = '"{0}" run' -f $resolvedServicePath
    $before = Get-CimInstance Win32_Service -Filter "Name='WinSightFirewall'" -ErrorAction Stop
    if ($null -eq $before -or $before.State -ne 'Running' -or [uint32]$before.ProcessId -eq 0) {
        throw 'WinSightFirewall is not running before the Network-logon probe.'
    }
    if (-not [string]::Equals(
            [string]$before.PathName,
            $expectedCommand,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'SCM is not bound to the selected protected service executable.'
    }

    Write-JsonEvidence ([pscustomobject]@{
            Result = 'READY'
            Checks = '2/3'
            ProcessId = [uint32]$before.ProcessId
            PathName = [string]$before.PathName
            Utc = [DateTime]::UtcNow.ToString('O')
        }) $ReadyPath

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while (-not (Test-Path -LiteralPath $CompletionSignalPath -PathType Leaf) -and
        [DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 250
    }
    if (-not (Test-Path -LiteralPath $CompletionSignalPath -PathType Leaf)) {
        throw 'Timed out waiting for the Network-logon probe completion signal.'
    }

    $after = Get-CimInstance Win32_Service -Filter "Name='WinSightFirewall'" -ErrorAction Stop
    $sameInstance = $null -ne $after -and $after.State -eq 'Running' -and
        [uint32]$after.ProcessId -eq [uint32]$before.ProcessId -and
        [string]::Equals(
            [string]$after.PathName,
            [string]$before.PathName,
            [StringComparison]::OrdinalIgnoreCase)
    if (-not $sameInstance) {
        throw 'The denied Network-logon attempt did not preserve the exact running service instance.'
    }

    Write-JsonEvidence ([pscustomobject]@{
            Result = 'PASS'
            Checks = '3/3'
            BeforeProcessId = [uint32]$before.ProcessId
            AfterProcessId = [uint32]$after.ProcessId
            PathName = [string]$after.PathName
            Utc = [DateTime]::UtcNow.ToString('O')
        }) $ResultPath
    Write-Host 'Result: 3 checks, 0 failure(s).'
}
finally {
    $identity.Dispose()
}
