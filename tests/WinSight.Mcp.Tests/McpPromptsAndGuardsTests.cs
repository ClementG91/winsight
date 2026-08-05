using ModelContextProtocol;
using WinSight.Application;
using WinSight.Firewall;
using Xunit;

namespace WinSight.Mcp.Tests;

/// <summary>
/// The prompt bodies and the process tool's input guard, pinned in-process.
/// </summary>
/// <remarks>
/// Both were reachable only through the protocol integration test, which spawns the real server and
/// is budgeted at a hundred seconds a response because one of its calls genuinely takes that long.
/// That test is worth having — it is the only thing proving the wire format — but it is the wrong
/// place to be the sole guardian of a string constant or an argument check. These run in
/// milliseconds and fail with a message naming what changed.
/// </remarks>
public sealed class McpPromptsAndGuardsTests
{
    /// <summary>
    /// A prompt that lists in the client's menu and carries none of its rules is decoration. Each
    /// assertion below is the specific correction that prompt exists to make.
    /// </summary>
    [Fact]
    public void TriagePrompt_CarriesTheRulesThatStopAnOverstatedReport()
    {
        var prompt = WinSightMcpPrompts.TriageMachine();

        // Order matters: the cheap complete picture first, then evidence only where warranted.
        Assert.Contains("winsight_overview", prompt, StringComparison.Ordinal);
        // The pair that must never be merged into one sentence.
        Assert.Contains("effectiveState", prompt, StringComparison.Ordinal);
        Assert.Contains("Degraded", prompt, StringComparison.Ordinal);
        // WinSight observes; it does not remediate.
        Assert.Contains("blocked, removed", prompt, StringComparison.Ordinal);
        // A valid signature does not clear the command line.
        Assert.Contains("commandLineConcern", prompt, StringComparison.Ordinal);
    }

    /// <summary>A focus is woven in rather than replacing the method.</summary>
    [Fact]
    public void TriagePrompt_HonoursAFocusWithoutDroppingTheFirstStep()
    {
        var focused = WinSightMcpPrompts.TriageMachine("ransomware");

        Assert.Contains("ransomware", focused, StringComparison.Ordinal);
        Assert.Contains("winsight_overview", focused, StringComparison.Ordinal);
    }

    /// <summary>
    /// The distinction this prompt exists for: "I was not allowed to look" is not "nobody knows".
    /// </summary>
    [Fact]
    public void ExplainAlertPrompt_KeepsTheTwoAttributionStatesApart()
    {
        var prompt = WinSightMcpPrompts.ExplainAlert();

        Assert.Contains("attribution needs Administrator", prompt, StringComparison.Ordinal);
        Assert.Contains("no matching write seen", prompt, StringComparison.Ordinal);
    }

    [Fact]
    public void ExplainAlertPrompt_NamesTheAlertItWasGiven()
    {
        var prompt = WinSightMcpPrompts.ExplainAlert("Guardian/RunKey");

        Assert.Contains("Guardian/RunKey", prompt, StringComparison.Ordinal);
    }

    /// <summary>
    /// Zero is the System Idle Process. Answering "not running" about it would be false, and
    /// negative ids are not process ids at all.
    /// </summary>
    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public async Task ProcessTool_RefusesAnImpossibleProcessId(int pid)
    {
        var error = await Assert.ThrowsAsync<McpException>(() => Tools().ProcessAsync(pid));

        Assert.Contains("greater than zero", error.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// The disclosure rules apply to this tool exactly as they do to the scanners, and they are
    /// checked before any work starts rather than after a scan has already run.
    /// </summary>
    [Fact]
    public async Task ProcessTool_RefusesSensitiveEvidenceWhenTheServerGateIsClosed()
    {
        var error = await Assert.ThrowsAsync<McpException>(() =>
            Tools().ProcessAsync(1234, includeEvidence: true, includeSensitive: true));

        Assert.Contains("WINSIGHT_MCP_ALLOW_SENSITIVE", error.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(201)]
    public async Task ProcessTool_RejectsAnOutOfRangeEvidenceLimit(int maxItems)
    {
        var error = await Assert.ThrowsAsync<McpException>(() =>
            Tools().ProcessAsync(1234, maxItems: maxItems));

        Assert.Contains("between 1 and 200", error.Message, StringComparison.Ordinal);
    }

    /// <summary>The verdict model has to state the distinction it exists for.</summary>
    [Fact]
    public void VerdictModelResource_SaysWhatFileMissingDoesNotMean()
    {
        var model = WinSightMcpResources.GetVerdictModel();

        Assert.Contains("Never describe it as unsigned", model, StringComparison.Ordinal);
        Assert.Contains("signature was never checked", model, StringComparison.Ordinal);
        Assert.Contains("commandLineConcern", model, StringComparison.Ordinal);
    }

    private static WinSightMcpTools Tools() => new(
        new McpScanService(),
        new McpSecurityOptions(AllowSensitiveEvidence: false),
        new McpFirewallPostureService(new UnreachableReader()));

    /// <summary>No posture call is made by these tests; the reader exists to satisfy the ctor.</summary>
    private sealed class UnreachableReader : IFirewallPostureReader
    {
        public Task<FirewallServiceView> GetViewAsync(CancellationToken cancellationToken = default) =>
            throw new NotSupportedException("These tests never read firewall posture.");
    }
}
