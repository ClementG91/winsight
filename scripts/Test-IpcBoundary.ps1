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

    Two passes, one service:
      * elevated - the current administrator console. Expected to read or mutate.
      * restricted - the same executable under a SAFER basic-user token via `runas /trustlevel`,
        password-free. This is the security-critical leg: an unprivileged caller must be able to READ
        status but must be refused a mutation, i.e. outcome=CanReadOnly.

    The service must already be installed and running (its pipe must exist). Install it with the WFP
    kit's pre-arm step first; this gate does not install or arm anything.

    Uses no closures on purpose (GetNewClosure captures variables, not functions, which killed the WFP
    protocol on a real VM). ASCII only, so Windows PowerShell 5.1 does not re-read it as ANSI.

.EXAMPLE
    ./Test-IpcBoundary.ps1
    ./Test-IpcBoundary.ps1 -CliPath 'C:\Program Files\WinSight-VM\winsight.exe'
#>
[CmdletBinding()]
param(
    # The shipped CLI. Defaults to the VM install location the WFP kit deploys to.
    [string]$CliPath = 'C:\Program Files\WinSight-VM\winsight.exe'
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
function Invoke-SelfTest([string]$outputText) {
    $outcome = [regex]::Match($outputText, 'outcome=(\w+)').Groups[1].Value
    $available = [regex]::Match($outputText, 'serviceAvailable=(\w+)').Groups[1].Value
    $mutation = [regex]::Match($outputText, 'mutation=(\w+)').Groups[1].Value
    return [pscustomobject]@{ Outcome = $outcome; Available = $available; Mutation = $mutation; Raw = $outputText.Trim() }
}

function Invoke-Elevated([string]$cli) {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { $raw = & $cli firewall-ipc-selftest 2>&1 } finally { $ErrorActionPreference = $previous }
    return Invoke-SelfTest (($raw | Out-String))
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
        & (Join-Path $env:SystemRoot 'System32\runas.exe') /trustlevel:0x20000 $wrapper | Out-Null
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

$elevated = (New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Check 'console is elevated' $elevated 'an elevated VM console' $elevated
if (-not $elevated) {
    Write-Host 'STOP: the elevated leg needs an administrator console.'
    Write-Host ('Result: {0} checks, {1} failure(s).' -f $script:Checks, $script:Failures)
    exit 1
}

$cli = [IO.Path]::GetFullPath($CliPath)
Write-Check 'shipped CLI exists' (Test-Path -LiteralPath $cli) 'winsight.exe at the deployed path' $cli
if ($script:Failures -gt 0) {
    Write-Host ('Result: {0} checks, {1} failure(s).' -f $script:Checks, $script:Failures)
    exit 1
}

# Elevated leg. An administrator either mutates, or - if the machine is armed - reads and the mutation
# leg is deliberately skipped. Either way the service must be reachable.
$adminRun = Invoke-Elevated $cli
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
