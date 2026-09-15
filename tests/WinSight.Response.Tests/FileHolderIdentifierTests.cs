using Xunit;

namespace WinSight.Response.Tests;

public sealed class FileHolderIdentifierTests
{
    private static readonly string[] Touched = [@"C:\Users\me\Documents\decoy.docx"];

    [Fact]
    public void OneNonProtectedHolderIsHighConfidence()
    {
        var locks = new FakeLocks { Holders = [Holder(100, 555)] };
        var inspector = new MapInspector();
        inspector.Add(100, Identity(100, 555, @"C:\evil\enc.exe"), "enc.exe");

        var id = new FileHolderIdentifier(locks, inspector).Identify(Touched);

        Assert.Equal(IdentificationConfidence.High, id.Confidence);
        var candidate = Assert.Single(id.Candidates);
        Assert.Equal(100, candidate.Identity.Pid);
        Assert.Equal("App 100", candidate.AppName); // the Restart Manager's friendly name is preferred
    }

    [Fact]
    public void TheImageNameIsUsedWhenTheRestartManagerGivesNoFriendlyName()
    {
        var locks = new FakeLocks { Holders = [new RestartManagerProcess(100, 555, string.Empty)] };
        var inspector = new MapInspector();
        inspector.Add(100, Identity(100, 555, @"C:\evil\enc.exe"), "enc.exe");

        var id = new FileHolderIdentifier(locks, inspector).Identify(Touched);

        Assert.Equal("enc.exe", Assert.Single(id.Candidates).AppName);
    }

    [Fact]
    public void SeveralNonProtectedHoldersAreAmbiguousAndNoneIsAutoActioned()
    {
        var locks = new FakeLocks { Holders = [Holder(100, 1), Holder(200, 2)] };
        var inspector = new MapInspector();
        inspector.Add(100, Identity(100, 1, @"C:\a.exe"), "a.exe");
        inspector.Add(200, Identity(200, 2, @"C:\b.exe"), "b.exe");

        var id = new FileHolderIdentifier(locks, inspector).Identify(Touched);

        Assert.Equal(IdentificationConfidence.Ambiguous, id.Confidence);
        Assert.Equal(2, id.Candidates.Count);
    }

    [Fact]
    public void NoHolderIsNoneWithElevatedAttributionHint()
    {
        var id = new FileHolderIdentifier(new FakeLocks(), new MapInspector()).Identify(Touched);

        Assert.Equal(IdentificationConfidence.None, id.Confidence);
        Assert.Empty(id.Candidates);
        Assert.Contains("elevated attribution", id.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void AProtectedHolderIsRefusedNotOffered()
    {
        var locks = new FakeLocks { Holders = [Holder(9000, 1)] };
        var inspector = new MapInspector();
        inspector.Add(9000, Identity(9000, 1, @"C:\Windows\System32\lsass.exe"), "lsass.exe");

        var id = new FileHolderIdentifier(locks, inspector).Identify(Touched);

        Assert.Equal(IdentificationConfidence.None, id.Confidence);
        Assert.Empty(id.Candidates);
        Assert.Contains("protected", id.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void APidRecycledSinceTheQueryIsDropped()
    {
        var locks = new FakeLocks { Holders = [Holder(100, 555)] };
        var inspector = new MapInspector();
        // The live process at pid 100 started at a different time: the RM-named pid was recycled.
        inspector.Add(100, Identity(100, 999, @"C:\other.exe"), "other.exe");

        var id = new FileHolderIdentifier(locks, inspector).Identify(Touched);

        Assert.Equal(IdentificationConfidence.None, id.Confidence);
        Assert.Empty(id.Candidates);
    }

    private static ProcessIdentity Identity(int pid, long start, string path) => new(pid, start, path, null);

    private static RestartManagerProcess Holder(int pid, long start) => new(pid, start, $"App {pid}");

    private sealed class FakeLocks : IFileLockInspector
    {
        public List<RestartManagerProcess> Holders { get; init; } = [];
        public IReadOnlyList<RestartManagerProcess> ProcessesHolding(IReadOnlyCollection<string> files) => Holders;
    }

    private sealed class MapInspector : IProcessInspector
    {
        private readonly Dictionary<int, ProcessIdentity?> _identities = [];
        private readonly Dictionary<int, string?> _names = [];

        public void Add(int pid, ProcessIdentity identity, string fileName)
        {
            _identities[pid] = identity;
            _names[pid] = fileName;
        }

        public ProcessIdentity? Capture(int pid, bool hashImage = false) =>
            _identities.TryGetValue(pid, out var v) ? v : null;

        public string? ImageFileName(int pid) => _names.TryGetValue(pid, out var v) ? v : null;
    }
}
