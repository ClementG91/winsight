<#
.SYNOPSIS
    Measures what WinSight's command-line scans and idle watches cost on this machine.

.DESCRIPTION
    Runs each scanner through the built CLI several times with --json --no-network and records, per
    run, wall time, CPU time, peak working set, peak thread and handle counts, exit code and output
    size; the report keeps every run and the median. Optionally measures the steady-state CPU of a
    watch (camera/microphone and keyboard/mouse filters need no elevation) over a fixed window.

    These are observations of one machine at one commit, recorded with that context, not portable
    budgets: compare runs of this script on the same machine, before and after a change. Nothing is
    sent anywhere and no scanner is given network access.

.EXAMPLE
    ./scripts/Measure-Performance.ps1 -Repeat 3 -WatchSeconds 30 -OutputPath out/perf/baseline.json
#>
[CmdletBinding()]
param(
    [string]$CliPath = (Join-Path $PSScriptRoot "..\src\WinSight.Cli\bin\Release\net10.0-windows10.0.19041.0\winsight.exe"),

    [string[]]$Scanners = @("persistence", "net", "dns", "extensions", "hosts", "certs", "input",
        "integrity", "drivers", "hijack", "processes", "all"),

    [ValidateRange(1, 20)]
    [int]$Repeat = 3,

    [ValidateRange(0, 3600)]
    [int]$WatchSeconds = 0,

    [string[]]$Watches = @("av", "input"),

    [string]$OutputPath
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$cli = (Resolve-Path -LiteralPath $CliPath).Path

# `pwsh -File script.ps1 -Scanners a,b` passes one string "a,b"; accept both spellings.
$Scanners = @($Scanners | ForEach-Object { $_ -split ',' } | ForEach-Object Trim | Where-Object { $_ })
$Watches = @($Watches | ForEach-Object { $_ -split ',' } | ForEach-Object Trim | Where-Object { $_ })

function Measure-Run([string[]]$Arguments, [int]$StopAfterSeconds = 0)
{
    $psi = [System.Diagnostics.ProcessStartInfo]::new($cli)
    foreach ($argument in $Arguments) { $psi.ArgumentList.Add($argument) }
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardInput = $true
    $psi.CreateNoWindow = $true

    $clock = [System.Diagnostics.Stopwatch]::StartNew()
    $process = [System.Diagnostics.Process]::Start($psi)
    try
    {
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $peakThreads = 0
        $peakHandles = 0
        $cpuAtWarmup = $null
        $cpuAtEnd = $null
        $warmupAt = [TimeSpan]::FromSeconds(5)
        while (-not $process.HasExited)
        {
            try
            {
                $process.Refresh()
                $peakThreads = [Math]::Max($peakThreads, $process.Threads.Count)
                $peakHandles = [Math]::Max($peakHandles, $process.HandleCount)
                if ($StopAfterSeconds -gt 0 -and $null -eq $cpuAtWarmup -and $clock.Elapsed -ge $warmupAt)
                {
                    $cpuAtWarmup = $process.TotalProcessorTime
                }
                if ($StopAfterSeconds -gt 0 -and $clock.Elapsed.TotalSeconds -ge $StopAfterSeconds)
                {
                    $cpuAtEnd = $process.TotalProcessorTime
                    $process.Kill()
                    break
                }
            }
            catch [System.InvalidOperationException]
            {
                break
            }
            Start-Sleep -Milliseconds 50
        }
        $process.WaitForExit()
        $clock.Stop()

        $idleCpuPercent = $null
        if ($StopAfterSeconds -gt 0 -and $null -ne $cpuAtWarmup -and $null -ne $cpuAtEnd)
        {
            # CPU after start-up only, as a share of one core over the measured window.
            $window = $StopAfterSeconds - $warmupAt.TotalSeconds
            $idleCpuPercent = [Math]::Round(100 * ($cpuAtEnd - $cpuAtWarmup).TotalSeconds / $window, 3)
        }

        [pscustomobject]@{
            Arguments = ($Arguments -join ' ')
            WallSeconds = [Math]::Round($clock.Elapsed.TotalSeconds, 2)
            CpuSeconds = [Math]::Round($process.TotalProcessorTime.TotalSeconds, 2)
            PeakWorkingSetMB = [Math]::Round($process.PeakWorkingSet64 / 1MB, 1)
            PeakThreads = $peakThreads
            PeakHandles = $peakHandles
            ExitCode = if ($StopAfterSeconds -gt 0) { $null } else { $process.ExitCode }
            OutputKB = [Math]::Round($stdout.Result.Length / 1KB, 1)
            IdleCpuPercentOfOneCore = $idleCpuPercent
        }
    }
    finally
    {
        $process.Dispose()
    }
}

function Get-Median([double[]]$Values)
{
    $sorted = @($Values | Sort-Object)
    if ($sorted.Count -eq 0) { return $null }
    $middle = [int][Math]::Floor($sorted.Count / 2)
    if ($sorted.Count % 2 -eq 1) { return $sorted[$middle] }
    return ($sorted[$middle - 1] + $sorted[$middle]) / 2
}

$scans = foreach ($scanner in $Scanners)
{
    $runs = @(for ($run = 1; $run -le $Repeat; $run++)
    {
        Write-Verbose "scan $scanner, run $run of $Repeat"
        Measure-Run @($scanner, "--json", "--no-network")
    })
    if ($runs | Where-Object ExitCode -eq 2)
    {
        # Exit code 2 is the CLI's usage error: the measurement describes a refused command.
        Write-Warning "'winsight $scanner' was refused as a usage error; its numbers measure nothing."
    }
    [pscustomobject]@{
        Scanner = $scanner
        MedianWallSeconds = Get-Median ($runs | ForEach-Object WallSeconds)
        MedianCpuSeconds = Get-Median ($runs | ForEach-Object CpuSeconds)
        MedianPeakWorkingSetMB = Get-Median ($runs | ForEach-Object PeakWorkingSetMB)
        MaxThreads = ($runs | Measure-Object PeakThreads -Maximum).Maximum
        MaxHandles = ($runs | Measure-Object PeakHandles -Maximum).Maximum
        OutputKB = $runs[-1].OutputKB
        ExitCodes = (@($runs | ForEach-Object ExitCode) | Sort-Object -Unique) -join ','
        Runs = $runs
    }
}

$watchResults = @()
if ($WatchSeconds -gt 5)
{
    $watchResults = foreach ($watch in $Watches)
    {
        Write-Verbose "watch $watch for $WatchSeconds s"
        Measure-Run @($watch, "--watch") -StopAfterSeconds $WatchSeconds
    }
}

$commit = $null
try
{
    $commit = (& git -C (Join-Path $PSScriptRoot "..") rev-parse --short HEAD 2>$null)
    if ($LASTEXITCODE -ne 0) { $commit = $null }
    elseif (& git -C (Join-Path $PSScriptRoot "..") status --porcelain 2>$null) { $commit = "$commit+dirty" }
}
catch
{
    $commit = $null
}

$report = [pscustomobject]@{
    MeasuredAtUtc = [DateTimeOffset]::UtcNow.ToString("o")
    Commit = $commit
    CliVersion = (& $cli --version)
    Machine = [pscustomobject]@{
        OsVersion = [Environment]::OSVersion.Version.ToString()
        Architecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
        LogicalProcessors = [Environment]::ProcessorCount
        Elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    Repeat = $Repeat
    Scans = @($scans)
    Watches = @($watchResults)
}

$scans | Select-Object Scanner, MedianWallSeconds, MedianCpuSeconds, MedianPeakWorkingSetMB, MaxThreads,
    MaxHandles, OutputKB, ExitCodes | Format-Table -AutoSize | Out-String -Width 200 | Write-Output
if ($watchResults) { $watchResults | Format-Table Arguments, IdleCpuPercentOfOneCore, PeakWorkingSetMB, PeakThreads | Out-String -Width 200 | Write-Output }

if ($OutputPath)
{
    $directory = Split-Path -Parent ([System.IO.Path]::GetFullPath($OutputPath))
    if (-not (Test-Path -LiteralPath $directory)) { New-Item -ItemType Directory -Path $directory | Out-Null }
    $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutputPath -Encoding utf8
    Write-Output "Report written to $OutputPath"
}
