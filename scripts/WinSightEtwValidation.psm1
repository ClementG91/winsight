Set-StrictMode -Version Latest

$script:WinSightEtwSessionPattern = [regex]::new(
    '(?<!\S)WinSight-(?:Attribution|Outbound|DNS)-(?:[1-9][0-9]*|v2-[1-9][0-9]*-[0-9A-F]{16})(?=\s|$)',
    [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)

function Get-WinSightSystemLogmanPath
{
    [CmdletBinding()]
    param()

    $systemDirectory = [Environment]::SystemDirectory
    if ([string]::IsNullOrWhiteSpace($systemDirectory))
    {
        throw 'Windows SystemDirectory is unavailable; refusing logman resolution.'
    }
    $logmanPath = [IO.Path]::Combine($systemDirectory, 'logman.exe')
    if (-not [IO.File]::Exists($logmanPath))
    {
        throw 'Required SystemDirectory logman.exe is unavailable.'
    }

    return $logmanPath
}

function Get-WinSightEtwSessionNames
{
    [CmdletBinding()]
    param(
        [string[]]$Lines,

        [int]$ExitCode = 0
    )

    if (-not $PSBoundParameters.ContainsKey('Lines'))
    {
        $logmanPath = Get-WinSightSystemLogmanPath
        $Lines = @(& $logmanPath query -ets 2>&1 | ForEach-Object { $_.ToString() })
        $ExitCode = $LASTEXITCODE
    }
    if ($ExitCode -ne 0)
    {
        throw "logman query -ets failed with exit code $ExitCode."
    }

    $names = New-Object 'System.Collections.Generic.List[string]'
    foreach ($line in $Lines)
    {
        if ($null -eq $line)
        {
            continue
        }
        foreach ($match in $script:WinSightEtwSessionPattern.Matches([string]$line))
        {
            $names.Add($match.Value)
        }
    }

    return @($names | Sort-Object -Unique)
}

function Get-WinSightEtwSessionForProcess
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Attribution', 'Outbound', 'DNS')]
        [string]$Family,

        [Parameter(Mandatory)]
        [int]$ProcessId,

        [string[]]$Lines,

        [int]$ExitCode = 0
    )

    if ($ProcessId -le 0)
    {
        throw 'ETW owner PID must be positive.'
    }
    $parameters = @{ ExitCode = $ExitCode }
    if ($PSBoundParameters.ContainsKey('Lines'))
    {
        $parameters.Lines = $Lines
    }
    $matches = @(Get-WinSightEtwSessionNames @parameters | Where-Object {
        $_ -cmatch ("^WinSight-{0}-v2-{1}-[0-9A-F]{{16}}$" -f $Family, $ProcessId)
    })
    if ($matches.Count -ne 1)
    {
        throw "Expected exactly one WinSight $Family v2 ETW session for PID $ProcessId; found $($matches.Count)."
    }

    return $matches[0]
}

function Get-WinSightRuntimeCrashEvents
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [datetime]$StartTime,

        [scriptblock]$Query
    )

    $filter = @{
        LogName = 'Application'
        ProviderName = '.NET Runtime'
        Id = 1026
        StartTime = $StartTime
    }
    try
    {
        $events = if ($null -eq $Query) {
            @(Microsoft.PowerShell.Diagnostics\Get-WinEvent -FilterHashtable $filter -ErrorAction Stop)
        }
        else {
            @(& $Query $filter)
        }
    }
    catch
    {
        if ($_.FullyQualifiedErrorId -ceq 'NoMatchingEventsFound,Microsoft.PowerShell.Commands.GetWinEventCommand')
        {
            return @()
        }
        throw 'Unable to query .NET Runtime event 1026; ETW crash gate is STOP.'
    }

    return @($events | Where-Object {
        $_.Message -match '0x800705AA|WinSight'
    })
}

function Assert-WinSightEtwSessionsAbsent
{
    [CmdletBinding()]
    param(
        [string[]]$Lines,

        [int]$ExitCode = 0
    )

    $parameters = @{}
    if ($PSBoundParameters.ContainsKey('Lines'))
    {
        $parameters.Lines = $Lines
    }
    if ($PSBoundParameters.ContainsKey('ExitCode'))
    {
        $parameters.ExitCode = $ExitCode
    }
    $names = @(Get-WinSightEtwSessionNames @parameters)
    if ($names.Count -ne 0)
    {
        throw "WinSight ETW sessions remain: $($names -join ', ')."
    }
}

Export-ModuleMember -Function Get-WinSightSystemLogmanPath, Get-WinSightEtwSessionNames, `
    Get-WinSightEtwSessionForProcess, Get-WinSightRuntimeCrashEvents, Assert-WinSightEtwSessionsAbsent
