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
# .Arguments, not .ArgumentList: the collection form only exists on .NET (Core), so ArgumentList
# throws under Windows PowerShell 5.1, which runs on .NET Framework. CI uses pwsh and never sees it,
# but a maintainer building a release in the console Windows opens by default would. One token with
# no spaces makes the two forms equivalent.
$start.Arguments = "mcp"
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

# The budget is per response, not per script, and it is tight on purpose: a handshake or a listing
# that has not answered in ten seconds has hung, and failing fast is the point of a smoke test.
#
# One call legitimately costs far more. The per-process pivot takes a full process snapshot and
# verifies a signature for every entry -- measured at about four seconds on a warm desktop, and it
# overran ten on a cold CI runner whose Authenticode cache is empty, which is exactly how this
# surfaced. Its budget is the server's own 90-second scan limit plus margin, so a genuinely stuck
# scan is still caught while the server's own timeout error gets the chance to arrive and be read as
# a response rather than as silence.
function Receive-McpResponse([int]$ExpectedId, [int]$TimeoutMs = 10000)
{
    $deadline = [Diagnostics.Stopwatch]::StartNew()
    while ($true)
    {
        $remaining = $TimeoutMs - [int]$deadline.ElapsedMilliseconds
        if ($remaining -le 0)
        {
            throw "MCP response $ExpectedId timed out after $TimeoutMs ms."
        }
        $read = $process.StandardOutput.ReadLineAsync()
        if (-not $read.Wait($remaining))
        {
            throw "MCP response $ExpectedId timed out after $TimeoutMs ms."
        }
        if ($null -eq $read.Result)
        {
            throw "MCP server closed stdout: $($process.StandardError.ReadToEnd())"
        }
        $message = $read.Result | ConvertFrom-Json
        $id = $message.PSObject.Properties['id']
        if ($null -eq $id)
        {
            if ($null -ne $message.PSObject.Properties['method'] -and
                $message.method -like 'notifications/*')
            {
                continue
            }
            throw "Unexpected MCP message without an id: $($message | ConvertTo-Json -Depth 12 -Compress)"
        }
        if ([int]$message.id -ne $ExpectedId)
        {
            throw "Expected MCP response $ExpectedId, got $($message.id)."
        }
        if ($null -ne $message.PSObject.Properties['error'])
        {
            throw "MCP response $ExpectedId returned an error: $($message.error | ConvertTo-Json -Depth 12 -Compress)"
        }
        if ($null -eq $message.PSObject.Properties['result'])
        {
            throw "MCP response $ExpectedId has no result."
        }
        return $message
    }
}

try
{
    # The server must be reachable both ways, and only exercising one hides a real break. Pinning a
    # single revision into the server options once made it answer every handshake-based client with
    # "Protocol version '2026-07-28' is not available through the initialize handshake", which the
    # handshake leg below catches and a stateless-only contract would not.
    #
    # server/discover is a 2026-07-28 method, so it carries the per-request metadata that revision
    # requires: the protocol version, the client capabilities and the client identity all travel in
    # `_meta` because there is no handshake left to carry them.
    $statelessMeta = @{
        "io.modelcontextprotocol/protocolVersion" = "2026-07-28"
        "io.modelcontextprotocol/clientCapabilities" = @{}
        "io.modelcontextprotocol/clientInfo" = @{ name = "winsight-package-smoke"; version = "1.0" }
    }
    Send-McpMessage @{
        jsonrpc = "2.0"
        id = 100
        method = "server/discover"
        params = @{ _meta = $statelessMeta }
    }
    $discover = Receive-McpResponse -ExpectedId 100
    if (@($discover.result.supportedVersions) -notcontains "2026-07-28")
    {
        throw "server/discover does not advertise the 2026-07-28 protocol revision."
    }
    if ($discover.result._meta."io.modelcontextprotocol/serverInfo".name -ne "winsight" -or
        $discover.result._meta."io.modelcontextprotocol/serverInfo".version -ne $Version)
    {
        throw "server/discover identity does not match the packaged build."
    }

    # The same tool surface must be reachable without a handshake, or the stateless path advertises a
    # server that cannot actually be used.
    Send-McpMessage @{
        jsonrpc = "2.0"
        id = 101
        method = "tools/list"
        params = @{ _meta = $statelessMeta }
    }
    $statelessTools = @((Receive-McpResponse -ExpectedId 101).result.tools | ForEach-Object { $_.name })
    foreach ($expected in @("winsight_get_capabilities", "winsight_overview", "winsight_scan", "winsight_process", "winsight_alerts", "winsight_outbound_firewall"))
    {
        if ($statelessTools -notcontains $expected)
        {
            throw "Stateless tools/list is missing $expected."
        }
    }

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
    $initialize = Receive-McpResponse -ExpectedId 1
    if ($initialize.result.protocolVersion -ne "2025-11-25" -or
        $initialize.result.serverInfo.name -ne "winsight" -or
        $initialize.result.serverInfo.version -ne $Version)
    {
        throw "MCP initialization response is inconsistent."
    }

    Send-McpMessage @{ jsonrpc = "2.0"; method = "notifications/initialized" }
    Send-McpMessage @{ jsonrpc = "2.0"; id = 2; method = "tools/list"; params = @{} }
    $toolList = Receive-McpResponse -ExpectedId 2
    $tools = @($toolList.result.tools)
    $expectedTools = @("winsight_get_capabilities", "winsight_overview", "winsight_scan", "winsight_process", "winsight_alerts", "winsight_outbound_firewall")
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
    $capabilities = Receive-McpResponse -ExpectedId 3
    if (-not $capabilities.result.structuredContent.readOnly -or
        $capabilities.result.structuredContent.networkListener -or
        $capabilities.result.structuredContent.networkReputationLookups -or
        @($capabilities.result.structuredContent.scanners).Count -ne 15)
    {
        throw "MCP capability result violates the local read-only contract."
    }
    # The firewall pipe is the one channel this process opens, and the capability document is where
    # an operator reads that. Undeclaring it would make the document understate the process.
    if (-not $capabilities.result.structuredContent.firewallServiceIpc)
    {
        throw "MCP capability result does not declare the firewall service channel."
    }

    Send-McpMessage @{
        jsonrpc = "2.0"
        id = 4
        method = "tools/call"
        params = @{ name = "winsight_scan"; arguments = @{ scanner = "hosts" } }
    }
    $scan = Receive-McpResponse -ExpectedId 4
    $reports = @($scan.result.structuredContent.reports)
    if ($scan.result.structuredContent.evidenceIncluded -or
        $reports.Count -ne 1 -or $reports[0].tool -ne "hosts" -or
        $reports[0].returnedItemCount -ne 0 -or @($reports[0].items).Count -ne 0)
    {
        throw "MCP default scan did not preserve the summary-only disclosure contract."
    }

    # The scanner names must travel in the published schema, because that is what a model reads to
    # decide what it may ask for. They were once prose that listed ten of the fifteen, leaving five
    # scanners reachable and undiscoverable, so the packaged surface pins the enumeration itself.
    $scannerSchema = ($tools | Where-Object name -EQ "winsight_scan").inputSchema.properties.scanner
    $offeredScanners = @($scannerSchema.enum)
    if ($offeredScanners.Count -ne 15)
    {
        throw "winsight_scan publishes $($offeredScanners.Count) scanners in its schema, expected 15."
    }
    foreach ($required in @("hijack", "integrity", "drivers", "input", "presence"))
    {
        if ($offeredScanners -notcontains $required)
        {
            throw "winsight_scan schema does not offer '$required'."
        }
    }

    # A pid that cannot be running must answer "not running" rather than describing an absent
    # process as one with nothing wrong.
    Send-McpMessage @{
        jsonrpc = "2.0"
        id = 7
        method = "tools/call"
        params = @{ name = "winsight_process"; arguments = @{ pid = 999999 } }
    }
    $drillDown = Receive-McpResponse -ExpectedId 7 -TimeoutMs 100000
    $processReports = @($drillDown.result.structuredContent.reports)
    if ($drillDown.result.structuredContent.evidenceIncluded -or
        $processReports.Count -ne 1 -or $processReports[0].tool -ne "process" -or
        $processReports[0].summary -notmatch "not running")
    {
        throw "MCP process tool did not report an absent pid honestly."
    }

    # Prompts carry the two interpretation rules whose wrong answer reads as a confident one, so an
    # empty prompt surface is a regression even though every tool still works.
    Send-McpMessage @{ jsonrpc = "2.0"; id = 8; method = "prompts/list"; params = @{} }
    $promptNames = @((Receive-McpResponse -ExpectedId 8).result.prompts | ForEach-Object { $_.name })
    foreach ($expected in @("winsight_triage_machine", "winsight_explain_alert"))
    {
        if ($promptNames -notcontains $expected)
        {
            throw "MCP prompt '$expected' is not published by the packaged server."
        }
    }

    Send-McpMessage @{ jsonrpc = "2.0"; id = 9; method = "resources/list"; params = @{} }
    $resourceUris = @((Receive-McpResponse -ExpectedId 9).result.resources | ForEach-Object { $_.uri })
    foreach ($expected in @("winsight://capabilities", "winsight://security-model", "winsight://verdict-model"))
    {
        if ($resourceUris -notcontains $expected)
        {
            throw "MCP resource '$expected' is not published by the packaged server."
        }
    }

    Send-McpMessage @{
        jsonrpc = "2.0"
        id = 5
        method = "tools/call"
        params = @{ name = "winsight_alerts"; arguments = @{} }
    }
    $alerts = Receive-McpResponse -ExpectedId 5
    $alertReports = @($alerts.result.structuredContent.reports)
    if ($alerts.result.structuredContent.evidenceIncluded -or
        $alertReports.Count -ne 1 -or $alertReports[0].tool -ne "alerts")
    {
        throw "MCP alerts tool did not preserve the summary-only disclosure contract."
    }

    # Posture must answer on a machine where the privileged firewall service is not installed, which
    # is the packaging runner and most first launches. The summary vocabulary is pinned because the
    # difference between "Unavailable" and "AuditOnly" is the difference between "WinSight could not
    # see the service" and "the service is up and blocking nothing", and a client will repeat it.
    Send-McpMessage @{
        jsonrpc = "2.0"
        id = 6
        method = "tools/call"
        params = @{ name = "winsight_outbound_firewall"; arguments = @{} }
    }
    $posture = Receive-McpResponse -ExpectedId 6
    $postureReports = @($posture.result.structuredContent.reports)
    if ($posture.result.structuredContent.evidenceIncluded -or
        $postureReports.Count -ne 1 -or $postureReports[0].tool -ne "outbound-firewall" -or
        @("Unavailable", "AuditOnly", "Active", "Degraded") -notcontains $postureReports[0].summary)
    {
        throw "MCP outbound firewall tool did not report a bounded read-only posture."
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
