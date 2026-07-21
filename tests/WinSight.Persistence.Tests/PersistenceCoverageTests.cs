using WinSight.Core;
using WinSight.Persistence;

using Xunit;

namespace WinSight.Persistence.Tests;

/// <summary>
/// A scan must be able to say what it was not allowed to read.
/// </summary>
/// <remarks>
/// Measured on a real desktop: the same scan returned 8 546 autostart items unelevated and 8 756
/// elevated. The 210 missing ones were scheduled tasks under
/// <c>C:\Windows\System32\Tasks</c> — Brave, Edge, NVIDIA, OneDrive and Google updaters — and one
/// of them was already flagged as suspicious. Nothing in the report said anything had been skipped,
/// so an unelevated operator read a complete, clean scan of a surface nobody had actually looked at.
/// "No findings" and "not allowed to look" must never render the same.
/// </remarks>
public sealed class PersistenceCoverageTests
{
    [Fact]
    public void Scan_ReportsNothingSkipped_WhenEverySurfaceWasReadable()
    {
        var scan = new PersistenceScanner([new FakeSurface("Run keys")], new NoSignatures())
            .ScanWithCoverage();

        Assert.False(scan.Coverage.IsPartial);
        Assert.Equal(0, scan.Coverage.UnreadableLocations);
        Assert.Empty(scan.Coverage.UnreadableSurfaces);
    }

    [Fact]
    public void Scan_CountsTheDefinitionsASurfaceCouldNotOpen()
    {
        var scan = new PersistenceScanner(
                [new FakeSurface("Scheduled tasks", unreadableLocations: 210)], new NoSignatures())
            .ScanWithCoverage();

        Assert.True(scan.Coverage.IsPartial);
        Assert.Equal(210, scan.Coverage.UnreadableLocations);
        Assert.Equal("Scheduled tasks", Assert.Single(scan.Coverage.UnreadableSurfaces));
    }

    // A surface that threw contributed nothing at all — the larger blind spot of the two, and
    // previously invisible: the scan swallowed the exception to keep going and never said which
    // surface had gone missing.
    [Fact]
    public void Scan_NamesASurfaceThatFailedOutright()
    {
        var scan = new PersistenceScanner(
                [new ThrowingSurface("Services"), new FakeSurface("Run keys")], new NoSignatures())
            .ScanWithCoverage();

        Assert.True(scan.Coverage.IsPartial);
        Assert.Equal("Services", Assert.Single(scan.Coverage.UnreadableSurfaces));
        // The rest of the scan still ran: isolating a failing surface was always right, only the
        // silence about it was wrong.
        Assert.Single(scan.Entries);
    }

    [Fact]
    public void Scan_KeepsReturningEntriesFromAPartiallyReadableSurface()
    {
        var scan = new PersistenceScanner(
                [new FakeSurface("Scheduled tasks", unreadableLocations: 5)], new NoSignatures())
            .ScanWithCoverage();

        // A refusal must never suppress what WAS readable.
        Assert.Single(scan.Entries);
    }

    private sealed class FakeSurface(string surface, int unreadableLocations = 0) : IAutostartEnumerator
    {
        public string Surface => surface;

        public int UnreadableLocations => unreadableLocations;

        public IEnumerable<RawAutostart> Enumerate() =>
            [new RawAutostart(AutostartVector.RunKey, "Thing", $"loc:{surface}", @"C:\thing.exe")];
    }

    private sealed class ThrowingSurface(string surface) : IAutostartEnumerator
    {
        public string Surface => surface;

        public IEnumerable<RawAutostart> Enumerate() =>
            throw new UnauthorizedAccessException("access is denied");
    }

    private sealed class NoSignatures : ISignatureVerifier
    {
        public SignatureVerdict Verify(string path, CancellationToken cancellationToken = default) =>
            SignatureVerdict.Missing;

        public IReadOnlyDictionary<string, SignatureVerdict> VerifyMany(
            IReadOnlyCollection<string> paths, CancellationToken cancellationToken = default) =>
            new Dictionary<string, SignatureVerdict>(StringComparer.OrdinalIgnoreCase);
    }
}
