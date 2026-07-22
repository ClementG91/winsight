using WinSight.Application;
using WinSight.Core;
using WinSight.Modules;
using WinSight.NetMonitor;
using WinSight.Processes;
using WinSight.Reporting;

using Xunit;

namespace WinSight.Application.Tests;

/// <summary>
/// Rendering a per-process insight into the shared report shape the CLI, JSON and MCP all consume.
/// </summary>
/// <remarks>
/// The pivot decides what is true; this decides what is said. It is kept separate and tested here
/// because the rendering is where a correct finding becomes a misleading sentence — a process with
/// nothing wrong must not read as cleared, and an absent process must not read as a quiet one.
/// </remarks>
public sealed class ProcessInsightReportTests
{
    private static readonly SignatureVerdict Trusted = new(SignatureState.SignedTrusted, "CN=Contoso");

    private static ProcessInfo Process(int pid, string name = "app.exe", int parentPid = 100) =>
        new(pid, name, $@"C:\Program Files\App\{name}", parentPid, $"{name} --run", Trusted);

    private static ProcessInsight Insight(
        ProcessInfo process,
        ProcessInfo? parent = null,
        IReadOnlyList<ProcessInfo>? children = null,
        IReadOnlyList<LoadedModule>? modules = null,
        IReadOnlyList<Connection>? connections = null) =>
        new(process, parent, children ?? [], modules ?? [], connections ?? []);

    [Fact]
    public void AnAbsentProcessIsReportedAsNotRunningRatherThanAsClean()
    {
        // "pid 4242 has nothing wrong with it" about a process that does not exist is the worst
        // possible answer: it is reassuring and it is about nothing.
        var report = ProcessInsightReport.Render(4242, insight: null);

        Assert.Equal("process", report.Tool);
        Assert.Empty(report.Items);
        Assert.Contains("4242", report.Summary, StringComparison.Ordinal);
        Assert.Contains("not running", report.Summary, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TheProcessItselfIsAlwaysTheFirstItem()
    {
        var report = ProcessInsightReport.Render(4242, Insight(Process(4242, "svc.exe")));

        Assert.NotEmpty(report.Items);
        Assert.Contains("svc.exe", report.Items[0].Title, StringComparison.Ordinal);
        Assert.Equal("4242", report.Items[0].Fields["pid"]);
    }

    [Fact]
    public void LineageNamesTheParentAndSaysWhenItHasExited()
    {
        var withParent = ProcessInsightReport.Render(
            4242, Insight(Process(4242), parent: Process(100, "explorer.exe", parentPid: 4)));
        var orphan = ProcessInsightReport.Render(4242, Insight(Process(4242, parentPid: 100)));

        Assert.Contains(
            withParent.Items, item => item.Detail.Contains("explorer.exe", StringComparison.Ordinal));
        // The pid is still named: an exited parent is the interesting case, not a missing field.
        Assert.Contains(
            orphan.Items,
            item => item.Detail.Contains("100", StringComparison.Ordinal)
                 && item.Detail.Contains("no longer running", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void OnlyUnsignedModulesAreListedIndividually()
    {
        // A process loads hundreds of modules. Listing them all would make this view unreadable and
        // bury the one that matters; the count is reported, the outliers are named.
        var modules = new[]
        {
            new LoadedModule(4242, "app.exe", "evil.dll", @"C:\Temp\evil.dll", SignatureVerdict.Unsigned),
            new LoadedModule(4242, "app.exe", "ok.dll", @"C:\Windows\System32\ok.dll", Trusted),
        };

        var report = ProcessInsightReport.Render(4242, Insight(Process(4242), modules: modules));

        Assert.Contains(report.Items, item => item.Title.Contains("evil.dll", StringComparison.Ordinal));
        Assert.DoesNotContain(report.Items, item => item.Title.Contains("ok.dll", StringComparison.Ordinal));
        Assert.Contains("2", report.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public void AnUnsignedModuleIsNotableAndASignedProcessIsNot()
    {
        var clean = ProcessInsightReport.Render(4242, Insight(Process(4242)));
        var dirty = ProcessInsightReport.Render(
            4242,
            Insight(
                Process(4242),
                modules: [new LoadedModule(4242, "app.exe", "evil.dll", @"C:\Temp\evil.dll", SignatureVerdict.Unsigned)]));

        Assert.Equal(0, clean.NotableCount);
        Assert.True(dirty.NotableCount > 0);
    }

    [Fact]
    public void ExternalConnectionsAreListedAndLocalOnesAreCounted()
    {
        var connections = new[]
        {
            new Connection("TCP", "10.0.0.5:51000", "93.184.216.34:443", "ESTABLISHED", 4242, "app.exe", null, Trusted),
            new Connection("TCP", "127.0.0.1:5000", "127.0.0.1:5001", "ESTABLISHED", 4242, "app.exe", null, Trusted),
        };

        var report = ProcessInsightReport.Render(4242, Insight(Process(4242), connections: connections));

        Assert.Contains(report.Items, item => item.Detail.Contains("93.184.216.34:443", StringComparison.Ordinal));
        Assert.DoesNotContain(report.Items, item => item.Detail.Contains("127.0.0.1:5001", StringComparison.Ordinal));
    }

    [Fact]
    public void ChildrenAreNamedBecauseTheyOutliveTheProcessThatSpawnedThem()
    {
        var report = ProcessInsightReport.Render(
            4242, Insight(Process(4242), children: [Process(5001, "child.exe", parentPid: 4242)]));

        Assert.Contains(report.Items, item => item.Detail.Contains("child.exe", StringComparison.Ordinal));
    }

    /// <summary>
    /// Every field the JSON contract exposes must be present, or a consumer sees a hole.
    /// </summary>
    [Fact]
    public void TheProcessItemCarriesTheStructuredFieldsTheJsonContractPromises()
    {
        var report = ProcessInsightReport.Render(4242, Insight(Process(4242, "svc.exe")));

        var fields = report.Items[0].Fields;
        Assert.Equal("4242", fields["pid"]);
        Assert.Equal("svc.exe", fields["name"]);
        Assert.Equal(@"C:\Program Files\App\svc.exe", fields["path"]);
        Assert.Equal("100", fields["parentPid"]);
        Assert.Equal(nameof(SignatureState.SignedTrusted), fields["signature"]);
    }
}
