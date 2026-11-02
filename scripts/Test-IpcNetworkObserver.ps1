<#
.SYNOPSIS
    Observes the privileged service while a separate machine runs the Network-logon IPC probe.

.DESCRIPTION
    Run elevated on the target VM. The Network-only account is deliberately unable to query the
    Service Control Manager or WMI on a hardened machine, so this target-side observer records the
    service PID and command line before the remote attempt and proves that the exact instance is
    still running afterwards. Evidence paths should point to storage outside the target snapshot.
#>
[CmdletBinding(DefaultParameterSetName = 'Observe')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Functions')]
    [switch]$FunctionsOnly,

    [string]$ServicePath,

    [Parameter(Mandatory, ParameterSetName = 'Observe')]
    [string]$CliPath,

    [Parameter(Mandatory, ParameterSetName = 'Observe')]
    [ValidatePattern('^[a-f0-9]{32}$')]
    [string]$ObservationId,

    [Parameter(Mandatory, ParameterSetName = 'Observe')]
    [string]$ReadyPath,

    [Parameter(Mandatory, ParameterSetName = 'Observe')]
    [string]$CompletionSignalPath,

    [Parameter(Mandatory, ParameterSetName = 'Observe')]
    [string]$ResultPath,

    [ValidateRange(10, 1800)]
    [int]$TimeoutSeconds = 300
)

function Write-JsonEvidence([object]$Value, [string]$Path) {
    $parent = Split-Path -Parent $Path
    if ([string]::IsNullOrWhiteSpace($parent) -or -not (Test-Path -LiteralPath $parent -PathType Container -ErrorAction Stop)) {
        throw "Evidence directory does not exist: $parent"
    }
    $bytes = [Text.UTF8Encoding]::new($false, $true).GetBytes(($Value | ConvertTo-Json -Depth 4 -Compress -ErrorAction Stop))
    if ($bytes.Length -gt 4096) { throw 'Network observer evidence exceeds its byte limit.' }
    # The caller supplies its protected evidence directory. Only our fresh adjacent temporary file
    # is cleaned up; Move never replaces an existing result or a receipt from another attempt.
    $temporary = $Path + '.part.' + [guid]::NewGuid().ToString('N')
    $created = $false
    $file = $null; $primary = $null
    $cleanupFailures = [Collections.Generic.List[Exception]]::new()
    try {
        $file = [IO.File]::Open($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $created = $true
        $file.Write($bytes, 0, $bytes.Length)
        $file.Flush($true)
    }
    catch { $primary = $_ }
    finally {
        if ($null -ne $file) {
            try { $file.Dispose() }
            catch {
                if ($null -eq $primary) { $primary = $_ } else { $cleanupFailures.Add($_.Exception) }
            }
        }
    }
    if ($null -eq $primary) {
        try { [IO.File]::Move($temporary, $Path); $created = $false }
        catch { $primary = $_ }
    }
    if ($created) {
        try { [IO.File]::Delete($temporary) }
        catch { $cleanupFailures.Add($_.Exception) }
    }
    if ($primary) {
        if ($cleanupFailures.Count) {
            $all = [Collections.Generic.List[Exception]]::new()
            $all.Add($primary.Exception)
            foreach ($failure in $cleanupFailures) { $all.Add($failure) }
            throw [AggregateException]::new('Network observer publication and cleanup failed.', $all)
        }
        throw $primary
    }
}

function Read-NetworkObservation([string]$Path, [string]$ObservationId, [string]$Stage) {
    try {
        $file = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        try {
            if ($file.Length -gt 4096) { throw 'size' }
            $bytes = [byte[]]::new(4097); $count = 0
            while ($count -lt $bytes.Length) {
                $read = $file.Read($bytes, $count, $bytes.Length - $count)
                if ($read -eq 0) { break }
                $count += $read
            }
            if ($count -eq 0 -or $count -gt 4096) { throw 'size' }
        }
        finally { $file.Dispose() }
        $raw = [Text.UTF8Encoding]::new($false, $true).GetString($bytes, 0, $count)
        $value = $raw | ConvertFrom-Json -ErrorAction Stop
        # Closed internal protocol: accept only the writer's canonical JSON, rejecting duplicate
        # members, arrays, extra whitespace, alternate number forms and undecodable UTF8.
        if ($null -eq $value -or $value -is [array] -or $raw -cne ($value | ConvertTo-Json -Depth 4 -Compress -ErrorAction Stop)) { throw 'canonical' }
        if ($ObservationId -cnotmatch '^[a-f0-9]{32}$' -or $value.SchemaVersion -isnot [int] -or $value.SchemaVersion -ne 1 -or
            $value.ObservationId -isnot [string] -or $value.ObservationId -cne $ObservationId -or $value.Stage -cne $Stage) { throw 'identity' }
        $members = @('SchemaVersion', 'ObservationId', 'Stage', 'Utc')
        switch ($Stage) {
            'COMPLETE' { }
            'READY' { $members += @('Result', 'Checks', 'ProcessId', 'PathName', 'PreCanary') }
            'PASS' { $members += @('Result', 'Checks', 'BeforeProcessId', 'AfterProcessId', 'PathName', 'PreCanary', 'PostCanary') }
            default { throw 'stage' }
        }
        $actual = @($value.PSObject.Properties.Name)
        if ($actual.Count -ne $members.Count -or @($actual | Where-Object { $members -cnotcontains $_ }).Count) { throw 'members' }
        $utc = [DateTime]::MinValue
        if ($value.Utc -isnot [string] -or -not $value.Utc.EndsWith('Z', [StringComparison]::Ordinal) -or
            -not [DateTime]::TryParseExact($value.Utc, 'O', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind, [ref]$utc)) { throw 'time' }
        if ($Stage -ne 'COMPLETE') {
            $checks = if ($Stage -eq 'READY') { '3/5' } else { '5/5' }
            if ($value.Result -cne $Stage -or $value.Checks -cne $checks -or $value.PreCanary -cne 'PASS' -or
                $value.PathName -isnot [string] -or [string]::IsNullOrWhiteSpace($value.PathName) -or $value.PathName.Length -gt 2048) { throw 'proof' }
            $pids = if ($Stage -eq 'READY') { @($value.ProcessId) } else { @($value.BeforeProcessId, $value.AfterProcessId) }
            foreach ($observedPid in $pids) {
                if (($observedPid -isnot [int] -and $observedPid -isnot [long]) -or $observedPid -le 0 -or $observedPid -gt [uint32]::MaxValue) { throw 'pid' }
            }
            if ($Stage -eq 'PASS' -and ($value.PostCanary -cne 'PASS' -or $value.BeforeProcessId -ne $value.AfterProcessId)) { throw 'post' }
        }
        return $value
    }
    catch { throw 'Network observer receipt rejected.' }
}

function Invoke-IpcProbeProcess([string]$CliPath) {
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $CliPath
    $start.Arguments = 'firewall-ipc-readonly'
    $start.UseShellExecute = $false; $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true; $start.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new(); $process.StartInfo = $start
    $started = $false
    $outRead = $null; $errRead = $null; $answer = $null
    $primary = $null; $cleanupFailure = $null
    try {
        if (-not $process.Start()) { throw 'Read-only IPC child did not start.' }
        $started = $true
        $clock = [Diagnostics.Stopwatch]::StartNew()
        $outBuffer = [char[]]::new(1025); $errBuffer = [char[]]::new(1025)
        $stdout = [Text.StringBuilder]::new(); $stderr = [Text.StringBuilder]::new()
        $outRead = $process.StandardOutput.ReadAsync($outBuffer, 0, $outBuffer.Length)
        $errRead = $process.StandardError.ReadAsync($errBuffer, 0, $errBuffer.Length)
        $outEof = $false; $errEof = $false
        while ($true) {
            if (-not $outEof -and $outRead.IsCompleted) {
                $count = $outRead.GetAwaiter().GetResult()
                if ($stdout.Length + $count -gt 1024) { throw 'Read-only IPC output limit exceeded.' }
                [void]$stdout.Append($outBuffer, 0, $count)
                $outEof = $count -eq 0
                if (-not $outEof) { $outRead = $process.StandardOutput.ReadAsync($outBuffer, 0, $outBuffer.Length) }
            }
            if (-not $errEof -and $errRead.IsCompleted) {
                $count = $errRead.GetAwaiter().GetResult()
                if ($stderr.Length + $count -gt 1024) { throw 'Read-only IPC error limit exceeded.' }
                [void]$stderr.Append($errBuffer, 0, $count)
                $errEof = $count -eq 0
                if (-not $errEof) { $errRead = $process.StandardError.ReadAsync($errBuffer, 0, $errBuffer.Length) }
            }
            if ($process.HasExited -and $outEof -and $errEof) { break }
            if ($clock.Elapsed.TotalSeconds -ge 30) { throw [TimeoutException]::new('Read-only IPC child timed out.') }
            Start-Sleep -Milliseconds 10
        }
        $answer = [pscustomobject]@{ ExitCode = $process.ExitCode; Stdout = $stdout.ToString(); Stderr = $stderr.ToString() }
    }
    catch { $primary = $_ }
    finally {
        # The CLI has no descendants. Cleanup is separately bounded and never turns a failed
        # observation into success, including when a child retains redirected output handles.
        try {
            $cleanupClock = [Diagnostics.Stopwatch]::StartNew()
            if ($started -and -not $process.HasExited) {
                $process.Kill()
                $remaining = 5000 - [int]$cleanupClock.Elapsed.TotalMilliseconds
                if ($remaining -le 0 -or -not $process.WaitForExit($remaining)) { throw 'Read-only IPC child cleanup timed out.' }
            }
            foreach ($readTask in @($outRead, $errRead)) {
                if ($null -eq $readTask) { continue }
                if (-not $readTask.IsCompleted) {
                    $remaining = 5000 - [int]$cleanupClock.Elapsed.TotalMilliseconds
                    if ($remaining -le 0 -or -not $readTask.Wait($remaining)) { throw 'Read-only IPC output cleanup timed out.' }
                }
                $null = $readTask.GetAwaiter().GetResult()
            }
        }
        catch { $cleanupFailure = $_ }
        finally {
            $process.Dispose()
            # Observe any fault that became available during disposal even when bounded cleanup
            # failed. Such failure is reported; it is never a successful endpoint observation.
            foreach ($readTask in @($outRead, $errRead)) {
                if ($null -ne $readTask -and $readTask.IsFaulted) { $null = $readTask.Exception }
            }
        }
    }
    if ($primary -and $cleanupFailure) {
        throw [AggregateException]::new('Read-only IPC observation and cleanup failed.', [Exception[]]@($primary.Exception, $cleanupFailure.Exception))
    }
    if ($primary) { throw $primary }
    if ($cleanupFailure) { throw $cleanupFailure }
    return $answer
}

function Invoke-ReadOnlyIpcProbe([string]$CliPath) {
    $result = Invoke-IpcProbeProcess -CliPath $CliPath
    $expected = '[IPC_READONLY] schema=1 command=GetStatus serviceAvailable=true mutation=none'
    if ($result.ExitCode -ne 0 -or $result.Stderr.Length -ne 0 -or $result.Stdout.Length -gt 1024 -or
        ($result.Stdout -cne ($expected + "`r`n") -and $result.Stdout -cne ($expected + "`n"))) {
        throw 'Read-only IPC canary failed.'
    }
}

# Dot-sourcing the verified package in this mode defines helpers only. It does not change the
# caller's preferences/strictness or inspect identity, SCM, a process, or an endpoint.
if ($FunctionsOnly) { return }
if (-not $ServicePath) { $ServicePath = (Join-Path $PSScriptRoot 'winsight-firewall-service.exe') }
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

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

    Invoke-ReadOnlyIpcProbe -CliPath $CliPath
    Write-JsonEvidence ([pscustomobject]@{
            SchemaVersion = 1
            ObservationId = $ObservationId
            Stage = 'READY'
            Result = 'READY'
            Checks = '3/5'
            PreCanary = 'PASS'
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
    $null = Read-NetworkObservation -Path $CompletionSignalPath -ObservationId $ObservationId -Stage 'COMPLETE'

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

    Invoke-ReadOnlyIpcProbe -CliPath $CliPath
    Write-JsonEvidence ([pscustomobject]@{
            SchemaVersion = 1
            ObservationId = $ObservationId
            Stage = 'PASS'
            Result = 'PASS'
            Checks = '5/5'
            PreCanary = 'PASS'
            PostCanary = 'PASS'
            BeforeProcessId = [uint32]$before.ProcessId
            AfterProcessId = [uint32]$after.ProcessId
            PathName = [string]$after.PathName
            Utc = [DateTime]::UtcNow.ToString('O')
        }) $ResultPath
    Write-Host 'Result: 5 checks, 0 failure(s).'
}
finally {
    $identity.Dispose()
}
