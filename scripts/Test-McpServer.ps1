[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ServerPath,

    [Parameter(Mandatory)]
    [ValidatePattern('^\d+\.\d+\.\d+([-.][0-9A-Za-z.-]+)?$')]
    [string]$Version
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$server = (Resolve-Path -LiteralPath $ServerPath).Path
$reportedVersion = & $server --version
if ($LASTEXITCODE -ne 0 -or $reportedVersion -ne "winsight $Version")
{
    throw "Expected winsight $Version, got '$reportedVersion'."
}

$start = [Diagnostics.ProcessStartInfo]::new()
$start.FileName = $server
$start.ArgumentList.Add("mcp")
$start.UseShellExecute = $false
$start.CreateNoWindow = $true
$start.RedirectStandardInput = $true
$start.RedirectStandardOutput = $true
$start.RedirectStandardError = $true
$process = [Diagnostics.Process]::new()
$process.StartInfo = $start
$null = $process.Start()

function Send-McpMessage([hashtable]$Message)
{
    $process.StandardInput.WriteLine(($Message | ConvertTo-Json -Depth 12 -Compress))
    $process.StandardInput.Flush()
}

function Receive-McpMessage
{
    $read = $process.StandardOutput.ReadLineAsync()
    if (-not $read.Wait(10000))
    {
        throw "MCP response timed out."
    }
    if ($null -eq $read.Result)
    {
        throw "MCP server closed stdout: $($process.StandardError.ReadToEnd())"
    }
    return $read.Result | ConvertFrom-Json
}

try
{
    Send-McpMessage @{
        jsonrpc = "2.0"
        id = 1
        method = "initialize"
        params = @{
            protocolVersion = "2025-11-25"
            capabilities = @{}
            clientInfo = @{ name = "winsight-package-smoke"; version = "1.0" }
        }
    }
    $initialize = Receive-McpMessage
    if ($initialize.result.protocolVersion -ne "2025-11-25" -or
        $initialize.result.serverInfo.name -ne "winsight" -or
        $initialize.result.serverInfo.version -ne $Version)
    {
        throw "MCP initialization response is inconsistent."
    }

    Send-McpMessage @{ jsonrpc = "2.0"; method = "notifications/initialized" }
    Send-McpMessage @{ jsonrpc = "2.0"; id = 2; method = "tools/list"; params = @{} }
    $toolList = Receive-McpMessage
    $tools = @($toolList.result.tools)
    $expectedTools = @("winsight_get_capabilities", "winsight_overview", "winsight_scan", "winsight_alerts")
    if ($tools.Count -ne $expectedTools.Count)
    {
        throw "Expected $($expectedTools.Count) MCP tools, got $($tools.Count)."
    }
    foreach ($expected in $expectedTools)
    {
        $tool = $tools | Where-Object name -EQ $expected
        if ($null -eq $tool -or -not $tool.annotations.readOnlyHint -or
            $tool.annotations.destructiveHint -or $tool.annotations.openWorldHint)
        {
            throw "MCP tool '$expected' does not preserve the read-only security contract."
        }
    }

    Send-McpMessage @{
        jsonrpc = "2.0"
        id = 3
        method = "tools/call"
        params = @{ name = "winsight_get_capabilities"; arguments = @{} }
    }
    $capabilities = Receive-McpMessage
    if (-not $capabilities.result.structuredContent.readOnly -or
        $capabilities.result.structuredContent.networkListener -or
        $capabilities.result.structuredContent.networkReputationLookups -or
        @($capabilities.result.structuredContent.scanners).Count -ne 11)
    {
        throw "MCP capability result violates the local read-only contract."
    }

    Send-McpMessage @{
        jsonrpc = "2.0"
        id = 4
        method = "tools/call"
        params = @{ name = "winsight_scan"; arguments = @{ scanner = "hosts" } }
    }
    $scan = Receive-McpMessage
    $reports = @($scan.result.structuredContent.reports)
    if ($scan.result.structuredContent.evidenceIncluded -or
        $reports.Count -ne 1 -or $reports[0].tool -ne "hosts" -or
        $reports[0].returnedItemCount -ne 0 -or @($reports[0].items).Count -ne 0)
    {
        throw "MCP default scan did not preserve the summary-only disclosure contract."
    }

    Send-McpMessage @{
        jsonrpc = "2.0"
        id = 5
        method = "tools/call"
        params = @{ name = "winsight_alerts"; arguments = @{} }
    }
    $alerts = Receive-McpMessage
    $alertReports = @($alerts.result.structuredContent.reports)
    if ($alerts.result.structuredContent.evidenceIncluded -or
        $alertReports.Count -ne 1 -or $alertReports[0].tool -ne "alerts")
    {
        throw "MCP alerts tool did not preserve the summary-only disclosure contract."
    }
}
finally
{
    $process.StandardInput.Close()
    if (-not $process.WaitForExit(5000))
    {
        $process.Kill($true)
    }
    $process.Dispose()
}

Write-Output "MCP $Version stdio negotiation and read-only tool contract passed."
