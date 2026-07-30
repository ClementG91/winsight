<#
.SYNOPSIS
    Multi-user validation of the authenticated firewall IPC pipe.

.DESCRIPTION
    CI cannot open the real pipe under two different Windows tokens at once, so this is a VM-only gate.
    It drives the shipped `winsight.exe firewall-ipc-selftest` diagnostic, which asks the running
    service what capability the caller's identity is granted and reports one stable token line. The
    diagnostic never changes machine state: it reads status, and its single mutation probe removes the
    policy for a path that is never a real policed executable (a no-op for an authorized caller), and
    is skipped entirely when the machine is armed.

    The default mode runs two passes against one service:
      * elevated - the current administrator console. Expected to read or mutate.
      * restricted - the same executable under a SAFER basic-user token via `runas /trustlevel`,
        password-free. This is the security-critical leg: an unprivileged caller must be able to READ
        status but must be refused a mutation, i.e. outcome=CanReadOnly.

    -NetworkLogon is a separate, fail-closed pass for a real network logon token. Run it remotely
    from a second isolated control machine through WinRM. It requires the Network SID, rejects the
    Interactive SID, expects the pipe to be unavailable (exit 3), and proves the same service process
    and command line stayed running before and after the denied attempt.

    The service must already be installed and running (its pipe must exist). Install it with the WFP
    kit's pre-arm step first; this gate does not install or arm anything.

    Uses no closures on purpose (GetNewClosure captures variables, not functions, which killed the WFP
    protocol on a real VM). ASCII only, so Windows PowerShell 5.1 does not re-read it as ANSI.

.EXAMPLE
    ./Test-IpcBoundary.ps1
    ./Test-IpcBoundary.ps1 -CliPath 'C:\Program Files\WinSight-Qualification\payload\winsight.exe'
    ./Test-IpcBoundary.ps1 -NetworkLogon
#>
[CmdletBinding()]
param(
    # The shipped CLI and service default to the protected package beside this script.
    [string]$CliPath = (Join-Path $PSScriptRoot 'winsight.exe'),
    [string]$ServicePath = (Join-Path $PSScriptRoot 'winsight-firewall-service.exe'),
    [switch]$NetworkLogon
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$script:Checks = 0
$script:Failures = 0

function Write-Check([string]$name, [bool]$ok, [string]$expectation, [string]$observed) {
    $script:Checks++
    if ($ok) {
        Write-Host ('  [PASS] {0}' -f $name)
    }
    else {
        $script:Failures++
        Write-Host ('  [FAIL] {0}: expected {1}, observed {2}' -f $name, $expectation, $observed)
    }
}

# Runs the diagnostic and returns the parsed token line as an object. Native output is captured, not
# treated as a terminating error; the token line is extracted by name so any decoration is ignored.
function Invoke-SelfTest([string]$outputText, [int]$exitCode = -1) {
    $outcome = [regex]::Match($outputText, 'outcome=(\w+)').Groups[1].Value
    $available = [regex]::Match($outputText, 'serviceAvailable=(\w+)').Groups[1].Value
    $mutation = [regex]::Match($outputText, 'mutation=(\w+)').Groups[1].Value
    return [pscustomobject]@{
        Outcome = $outcome
        Available = $available
        Mutation = $mutation
        ExitCode = $exitCode
        Raw = $outputText.Trim()
    }
}

function Invoke-Current([string]$cli) {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $raw = @(& $cli firewall-ipc-selftest 2>&1)
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previous
    }
    return Invoke-SelfTest (($raw | Out-String)) $exitCode
}

# Launches the same exe under a SAFER basic-user (non-administrator) token. runas /trustlevel needs no
# password. Output is redirected to a file by a tiny cmd wrapper because the restricted process runs
# detached. The wrapper writes a separate DONE marker only after the diagnostic has fully exited:
# cmd creates the redirect target the instant the line starts, so waiting on the output file itself
# would read it empty. Waiting on the marker waits for completion.
function Invoke-Restricted([string]$cli) {
    $token = [guid]::NewGuid().ToString('N')
    $outFile = Join-Path $env:TEMP ("winsight-ipc-out-$token.txt")
    $doneFile = Join-Path $env:TEMP ("winsight-ipc-done-$token.txt")
    $wrapper = Join-Path $env:TEMP ("winsight-ipc-run-$token.cmd")
    try {
        Set-Content -Path $wrapper -Encoding Ascii -Value @(
            '@echo off',
            ('"{0}" firewall-ipc-selftest > "{1}" 2>&1' -f $cli, $outFile),
            ('echo done> "{0}"' -f $doneFile))
        & (Join-Path ([Environment]::SystemDirectory) 'runas.exe') /trustlevel:0x20000 $wrapper |
            Out-Null
        $deadline = (Get-Date).AddSeconds(20)
        while (-not (Test-Path -LiteralPath $doneFile) -and (Get-Date) -lt $deadline) {
            Start-Sleep -Milliseconds 200
        }
        if (-not (Test-Path -LiteralPath $doneFile)) {
            return [pscustomobject]@{
                Outcome = ''; Available = ''; Mutation = ''
                Raw = '(restricted launch did not complete; is the Secondary Logon service running?)'
            }
        }
        $text = if (Test-Path -LiteralPath $outFile) { Get-Content -LiteralPath $outFile -Raw } else { '' }
        return Invoke-SelfTest $text
    }
    finally {
        Remove-Item -LiteralPath $outFile, $doneFile, $wrapper -Force -ErrorAction SilentlyContinue
    }
}

Write-Host '== firewall IPC multi-user boundary =='

$cli = [IO.Path]::GetFullPath($CliPath)
Write-Check 'shipped CLI exists' (Test-Path -LiteralPath $cli -PathType Leaf) `
    'winsight.exe beside the shipped validation script or at -CliPath' $cli
if ($script:Failures -gt 0) {
    Write-Host ('Result: {0} checks, {1} failure(s).' -f $script:Checks, $script:Failures)
    exit 1
}

if ($NetworkLogon) {
    $service = [IO.Path]::GetFullPath($ServicePath)
    Write-Check 'shipped service exists' (Test-Path -LiteralPath $service -PathType Leaf) `
        'winsight-firewall-service.exe beside the script or at -ServicePath' $service

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $groupSids = @($identity.Groups | ForEach-Object { $_.Value })
    $hasNetworkSid = $groupSids -contains 'S-1-5-2'
    $hasInteractiveSid = $groupSids -contains 'S-1-5-4'
    $isNetworkOnly = $hasNetworkSid -and -not $hasInteractiveSid
    $identity.Dispose()
    Write-Host ('  token:      S-1-5-2={0} S-1-5-4={1}' -f
        $hasNetworkSid.ToString().ToLowerInvariant(),
        $hasInteractiveSid.ToString().ToLowerInvariant())
    Write-Check 'caller is a Network logon, not an Interactive logon' $isNetworkOnly `
        'S-1-5-2 present and S-1-5-4 absent' ($groupSids -join ',')

    $before = Get-CimInstance Win32_Service -Filter "Name='WinSightFirewall'" -ErrorAction Stop
    $beforeRunning = $null -ne $before -and $before.State -eq 'Running' -and
        [uint32]$before.ProcessId -gt 0
    $beforeObserved = if ($null -eq $before) { '<service absent>' }
        else { "State={0}; ProcessId={1}" -f $before.State, $before.ProcessId }
    Write-Check 'service is running before the denied attempt' $beforeRunning `
        'State=Running and ProcessId>0' $beforeObserved

    $expectedCommand = '"{0}" run' -f $service
    $beforePath = if ($null -eq $before) { '' } else { [string]$before.PathName }
    $pathMatches = $null -ne $before -and [string]::Equals(
        $beforePath,
        $expectedCommand,
        [StringComparison]::OrdinalIgnoreCase)
    Write-Check 'SCM is bound to the protected service executable' $pathMatches `
        $expectedCommand $beforePath

    if ($script:Failures -gt 0) {
        Write-Host ('Result: {0} checks, {1} failure(s).' -f $script:Checks, $script:Failures)
        exit 1
    }

    $networkRun = Invoke-Current $cli
    Write-Host ('  network:    {0}' -f $networkRun.Raw)
    Write-Check 'network logon receives the unavailable exit code' ($networkRun.ExitCode -eq 3) `
        'exit 3' $networkRun.ExitCode
    Write-Check 'network logon cannot reach the authenticated pipe' `
        ($networkRun.Available -eq 'false') 'serviceAvailable=false' $networkRun.Raw
    Write-Check 'network logon reports ServiceUnavailable' `
        ($networkRun.Outcome -eq 'ServiceUnavailable') 'outcome=ServiceUnavailable' $networkRun.Outcome
    Write-Check 'network logon performs no mutation' ($networkRun.Mutation -eq 'none') `
        'mutation=none' $networkRun.Mutation

    $after = Get-CimInstance Win32_Service -Filter "Name='WinSightFirewall'" -ErrorAction Stop
    $sameService = $null -ne $after -and $after.State -eq 'Running' -and
        [uint32]$after.ProcessId -eq [uint32]$before.ProcessId -and
        [string]::Equals(
            [string]$after.PathName,
            [string]$before.PathName,
            [StringComparison]::OrdinalIgnoreCase)
    $afterObserved = if ($null -eq $after) { '<service absent>' }
        else {
            "State={0}; ProcessId={1}; PathName={2}" -f
                $after.State, $after.ProcessId, $after.PathName
        }
    Write-Check 'denial preserves the exact running service instance' $sameService `
        ("State=Running; ProcessId={0}; PathName unchanged" -f $before.ProcessId) `
        $afterObserved

    Write-Host ('Result: {0} checks, {1} failure(s).' -f $script:Checks, $script:Failures)
    if ($script:Failures -gt 0) { exit 1 }
    exit 0
}

$elevated = (New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Check 'console is elevated' $elevated 'an elevated VM console' $elevated
if (-not $elevated) {
    Write-Host 'STOP: the elevated leg needs an administrator console.'
    Write-Host ('Result: {0} checks, {1} failure(s).' -f $script:Checks, $script:Failures)
    exit 1
}

# Elevated leg. An administrator either mutates, or - if the machine is armed - reads and the mutation
# leg is deliberately skipped. Either way the service must be reachable.
$adminRun = Invoke-Current $cli
Write-Host ('  elevated:   {0}' -f $adminRun.Raw)
if ($adminRun.Available -ne 'true') {
    Write-Check 'service is reachable from the elevated console' $false 'serviceAvailable=true' $adminRun.Raw
    Write-Host 'STOP: install and start the service first (WFP kit pre-arm step), then re-run.'
    Write-Host ('Result: {0} checks, {1} failure(s).' -f $script:Checks, $script:Failures)
    exit 1
}
Write-Check 'service is reachable from the elevated console' $true 'serviceAvailable=true' $adminRun.Raw
Write-Check 'the elevated caller may mutate or reads an armed machine' `
    ($adminRun.Outcome -eq 'CanMutate' -or $adminRun.Outcome -eq 'ReadableMutateSkipped') `
    'outcome=CanMutate or ReadableMutateSkipped' $adminRun.Outcome

# Restricted leg - the security-critical one. A non-administrator token must read status yet be
# refused the mutation.
$userRun = Invoke-Restricted $cli
Write-Host ('  restricted: {0}' -f $userRun.Raw)
Write-Check 'the unprivileged caller can still read status' ($userRun.Available -eq 'true') `
    'serviceAvailable=true' $userRun.Raw
Write-Check 'the unprivileged caller is refused the mutation' ($userRun.Outcome -eq 'CanReadOnly') `
    'outcome=CanReadOnly' $userRun.Outcome
Write-Check 'the refused mutation reported Unauthorized' ($userRun.Mutation -eq 'Unauthorized') `
    'mutation=Unauthorized' $userRun.Mutation

Write-Host ('Result: {0} checks, {1} failure(s).' -f $script:Checks, $script:Failures)
if ($script:Failures -gt 0) { exit 1 }
exit 0
