using WinSight.Core;

using Xunit;

namespace WinSight.Application.Tests;

/// <summary>
/// How the four lookups a scan is allowed get spent.
/// </summary>
/// <remarks>
/// <b>Three ways the budget was wasted.</b>
///
/// <list type="bullet">
/// <item>Every candidate was SHA-256'd before four groups were taken. On a persistence scan that
/// meant reading every flagged executable end to end - a several-hundred-megabyte installer among
/// them - to use four digests and discard the rest. The work happened before anything could decide
/// it was unnecessary.</item>
/// <item>The four went to whatever the enumerator reached first, so an unsigned DLL registered as an
/// IFEO debugger could lose its lookup to four orphaned registrations whose only fault is a missing
/// target.</item>
/// <item>Every scan asked again. The dashboard re-runs the same scan on a timer, and a Community key
/// allows four lookups a minute, so the whole allowance went on re-establishing verdicts the process
/// already had - leaving nothing for a file it had never seen.</item>
/// </list>
///
/// These tests use the injected lookup, so none of them reaches the network or the operator's real
/// quota.
/// </remarks>
[Collection(VirusTotalEnvironmentCollection.Name)]
public sealed class VirusTotalBudgetTests : IDisposable
{
    private const string KeyVariable = "WINSIGHT_VT_KEY";
    private static readonly string UnusableKey = new('a', 64);

    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), $"winsight-vt-{Guid.NewGuid():N}");
    private readonly string? _originalKey = Environment.GetEnvironmentVariable(KeyVariable);

    public VirusTotalBudgetTests()
    {
        Directory.CreateDirectory(_directory);
        Environment.SetEnvironmentVariable(KeyVariable, UnusableKey);
        VirusTotalVerdictCache.Clear();
    }

    public void Dispose()
    {
        Environment.SetEnvironmentVariable(KeyVariable, _originalKey);
        VirusTotalVerdictCache.Clear();
        try { Directory.Delete(_directory, recursive: true); }
        catch (IOException) { }
    }

    /// <summary>
    /// A quota that always allows. The real limiter is cross-process, persistent and fails closed,
    /// so leaving it in would make every assertion below pass for the wrong reason - the lookup
    /// never happening at all.
    /// </summary>
    private static bool Allow() => true;

    /// <summary>A file whose content is its name, so each is a distinct hash.</summary>
    private string File_(string name)
    {
        var path = Path.Combine(_directory, name);
        File.WriteAllText(path, name);
        return path;
    }

    /// <summary>
    /// Nothing beyond the four the enricher can act on is hashed. Proved by giving it a path that
    /// cannot be read: if it were reached, it would be skipped silently either way, so the
    /// assertion is on where the reading stops rather than on the result.
    /// </summary>
    [Fact]
    public void HashingStopsOnceTheBudgetIsSpent()
    {
        var probe = new RecordingLookup();
        string[] candidates =
        [
            File_("one.bin"), File_("two.bin"), File_("three.bin"), File_("four.bin"),
            File_("five.bin"), File_("six.bin"),
        ];

        var results = VirusTotalEnricher.Lookup(
            candidates, allowNetworkLookups: true, probe.Lookup, CancellationToken.None, Allow);

        Assert.Equal(4, probe.Calls.Count);
        // The fifth and sixth were never asked about, so they carry no verdict.
        Assert.DoesNotContain(candidates[4], results.Keys);
        Assert.DoesNotContain(candidates[5], results.Keys);
    }

    /// <summary>
    /// The order the caller gives is the order the budget is spent in, which is what makes the
    /// callers' "most adverse first" ordering mean anything.
    /// </summary>
    [Fact]
    public void TheBudgetIsSpentInTheOrderTheCallerGave()
    {
        var probe = new RecordingLookup();
        var first = File_("first.bin");
        var second = File_("second.bin");

        var results = VirusTotalEnricher.Lookup(
            [first, second, File_("third.bin"), File_("fourth.bin"), File_("fifth.bin")],
            allowNetworkLookups: true,
            probe.Lookup,
            CancellationToken.None,
            Allow);

        Assert.Contains(first, results.Keys);
        Assert.Contains(second, results.Keys);
    }

    /// <summary>
    /// Two paths holding identical content are one lookup, and both get the answer. That is what
    /// makes stopping at four distinct hashes correct rather than merely cheap.
    /// </summary>
    [Fact]
    public void DuplicateContentCostsOneLookupAndBothPathsGetTheVerdict()
    {
        var probe = new RecordingLookup();
        var original = Path.Combine(_directory, "a.bin");
        var copy = Path.Combine(_directory, "b.bin");
        File.WriteAllText(original, "identical");
        File.WriteAllText(copy, "identical");

        var results = VirusTotalEnricher.Lookup(
            [original, copy], allowNetworkLookups: true, probe.Lookup, CancellationToken.None, Allow);

        Assert.Single(probe.Calls);
        Assert.Equal(2, results.Count);
        Assert.Equal(results[original], results[copy]);
    }

    /// <summary>
    /// A duplicate found after the budget is spent still joins its group, because it costs nothing:
    /// the hash is already known. Only starting a fifth group stops.
    /// </summary>
    [Fact]
    public void ADuplicateOfAnAlreadyBudgetedFileIsStillEnriched()
    {
        var probe = new RecordingLookup();
        var first = File_("1.bin");
        var late = Path.Combine(_directory, "late.bin");
        File.WriteAllText(late, "1.bin");

        var results = VirusTotalEnricher.Lookup(
            [first, File_("2.bin"), File_("3.bin"), File_("4.bin"), late],
            allowNetworkLookups: true,
            probe.Lookup,
            CancellationToken.None,
            Allow);

        Assert.Equal(4, probe.Calls.Count);
        Assert.Contains(late, results.Keys);
        Assert.Equal(results[first], results[late]);
    }

    /// <summary>
    /// A second scan over the same file spends no lookup. This is the one that protects a Community
    /// key from a dashboard on a timer.
    /// </summary>
    [Fact]
    public void ASecondScanOfTheSameFileCostsNothing()
    {
        var probe = new RecordingLookup();
        var path = File_("repeat.bin");

        var first = VirusTotalEnricher.Lookup(
            [path], allowNetworkLookups: true, probe.Lookup, CancellationToken.None, Allow);
        var second = VirusTotalEnricher.Lookup(
            [path], allowNetworkLookups: true, probe.Lookup, CancellationToken.None, Allow);

        Assert.Single(probe.Calls);
        Assert.Equal(first[path], second[path]);
    }

    /// <summary>
    /// The cached answer expires. A file that was clean this morning and is detected this afternoon
    /// is the transition an operator most needs to see, so the cache must not hide it for ever.
    /// </summary>
    [Fact]
    public void AnExpiredVerdictIsAskedForAgain()
    {
        var now = new DateTimeOffset(2026, 8, 29, 12, 0, 0, TimeSpan.Zero);
        using var clock = VirusTotalVerdictCache.UseClock(() => now);
        var probe = new RecordingLookup();
        var path = File_("expiring.bin");

        VirusTotalEnricher.Lookup(
            [path], allowNetworkLookups: true, probe.Lookup, CancellationToken.None, Allow);
        now += VirusTotalVerdictCache.Lifetime + TimeSpan.FromMinutes(1);
        VirusTotalEnricher.Lookup(
            [path], allowNetworkLookups: true, probe.Lookup, CancellationToken.None, Allow);

        Assert.Equal(2, probe.Calls.Count);
    }

    /// <summary>
    /// A different file at the same path is a different hash, so it is asked about rather than
    /// answered from the cache. That is the case where a stale answer would matter most.
    /// </summary>
    [Fact]
    public void ReplacingTheFileAtAPathAsksAgain()
    {
        var probe = new RecordingLookup();
        var path = Path.Combine(_directory, "swapped.bin");

        File.WriteAllText(path, "before");
        VirusTotalEnricher.Lookup(
            [path], allowNetworkLookups: true, probe.Lookup, CancellationToken.None, Allow);
        File.WriteAllText(path, "after");
        VirusTotalEnricher.Lookup(
            [path], allowNetworkLookups: true, probe.Lookup, CancellationToken.None, Allow);

        Assert.Equal(2, probe.Calls.Count);
    }

    private sealed class RecordingLookup
    {
        public List<string> Calls { get; } = [];

        public VtVerdict? Lookup(string sha256, CancellationToken cancellationToken)
        {
            Calls.Add(sha256);
            return new VtVerdict(
                Malicious: 0, Suspicious: 0, Total: 70,
                Permalink: $"https://example.invalid/{sha256}");
        }
    }
}
