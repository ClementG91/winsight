using WinSight.Hijack;
using Xunit;

namespace WinSight.Hijack.Tests;

/// <summary>
/// The side-by-side store, and specifically what it does when it cannot finish looking.
/// </summary>
/// <remarks>
/// <b>Why this class exists at all.</b> A binary whose manifest binds a side-by-side assembly - the
/// Visual C++ redistributables, MFC, ATL - has those imports resolved by the loader out of WinSxS
/// through an activation context. That store appears in no DLL search path, so "no directory in the
/// search order holds this file" was reported as a phantom import for every such binary: a
/// confident, repeated accusation against ordinary software, made by a SYSTEM-service scanner.
///
/// <b>Why the incomplete case is the one worth pinning.</b> The walk stops at a time budget and an
/// entry cap, and everything after that turns on one decision: an index that did not finish must
/// answer "unknown", never "absent". Answering "absent" from a partial index puts the false positive
/// straight back, and does it precisely on the machines where the store is largest. That path was
/// unreachable from a test until the limits were made injectable, so the safety property the class
/// documents had never once been executed.
/// </remarks>
public sealed class SideBySideStoreTests : IDisposable
{
    private readonly string _root = Path.Combine(
        Path.GetTempPath(), "winsight-sxs-" + Guid.NewGuid().ToString("n"));

    public SideBySideStoreTests() => Directory.CreateDirectory(Path.Combine(_root, "WinSxS"));

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    private void Plant(params string[] names)
    {
        foreach (var name in names)
        {
            var directory = Path.Combine(_root, "WinSxS", Path.GetFileNameWithoutExtension(name));
            Directory.CreateDirectory(directory);
            File.WriteAllBytes(Path.Combine(directory, name), []);
        }
    }

    /// <summary>A complete index answers both questions, and answers "absent" with authority.</summary>
    [Fact]
    public void ACompleteIndexAnswersPresentAndAbsent()
    {
        Plant("msvcp140.dll", "mfc140u.dll");
        var store = new SideBySideStore(_root);

        Assert.True(store.Contains("msvcp140.dll"));
        Assert.True(store.Contains("MSVCP140.DLL"));
        Assert.False(store.Contains("definitely-not-here.dll"));
        Assert.Equal(0, store.UnansweredLookups);
    }

    /// <summary>
    /// An index stopped by the entry cap answers "unknown" for a name it did not see, and says so.
    /// </summary>
    /// <remarks>
    /// This is the whole safety property: a name absent from a partial index has not been shown to
    /// be absent from the store. Returning false here would report a phantom import for a DLL that
    /// is sitting in WinSxS, on exactly the machines whose store was too large to finish indexing.
    /// </remarks>
    [Fact]
    public void AnIndexStoppedByTheEntryCapAnswersUnknownRatherThanAbsent()
    {
        Plant("a.dll", "b.dll", "c.dll", "d.dll");
        var store = new SideBySideStore(_root, TimeSpan.FromMinutes(1), maxEntries: 1);

        Assert.Null(store.Contains("definitely-not-here.dll"));
        Assert.Equal(1, store.UnansweredLookups);
    }

    /// <summary>An index stopped by the time budget behaves the same way.</summary>
    [Fact]
    public void AnIndexStoppedByTheTimeBudgetAnswersUnknownRatherThanAbsent()
    {
        Plant("a.dll", "b.dll", "c.dll", "d.dll");
        var store = new SideBySideStore(_root, TimeSpan.Zero, maxEntries: int.MaxValue);

        Assert.Null(store.Contains("definitely-not-here.dll"));
        Assert.True(store.UnansweredLookups > 0);
    }

    /// <summary>
    /// A name the partial index did happen to see is still answered, because seeing it is proof.
    /// </summary>
    /// <remarks>
    /// Incompleteness only invalidates absence. A file the walk actually reached is in the store
    /// whether or not the walk finished, and throwing that away would suppress nothing and cost a
    /// real answer.
    /// </remarks>
    [Fact]
    public void APartialIndexStillAnswersForANameItReached()
    {
        Plant("only.dll");
        var store = new SideBySideStore(_root, TimeSpan.FromMinutes(1), maxEntries: 1);

        Assert.True(store.Contains("only.dll"));
        Assert.Equal(0, store.UnansweredLookups);
    }

    /// <summary>
    /// A machine with no store at all is a complete answer, not an unknown one.
    /// </summary>
    /// <remarks>
    /// Nothing resolves through a store that does not exist, so every import genuinely is absent
    /// from it. Reporting "unknown" here would suppress the phantom-import finding on every machine
    /// without WinSxS rather than on the ones that need it.
    /// </remarks>
    [Fact]
    public void AMachineWithNoStoreAnswersAbsentWithAuthority()
    {
        var absent = Path.Combine(_root, "no-such-windows");
        var store = new SideBySideStore(absent);

        Assert.False(store.Contains("msvcp140.dll"));
        Assert.Equal(0, store.UnansweredLookups);
    }

    /// <summary>The index is built once, however many times it is asked.</summary>
    /// <remarks>
    /// The first version searched the tree per lookup and took the hijack suite from 70 ms to 75
    /// seconds - a fix for a false positive turning into a scan nobody would wait for. Planting a
    /// file after the first question and finding it still unseen is what proves the walk did not
    /// run again.
    /// </remarks>
    [Fact]
    public void TheStoreIsIndexedOnceRatherThanPerLookup()
    {
        Plant("first.dll");
        var store = new SideBySideStore(_root);
        Assert.True(store.Contains("first.dll"));

        Plant("second.dll");

        Assert.False(store.Contains("second.dll"));
    }
}
