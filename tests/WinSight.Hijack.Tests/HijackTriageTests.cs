using WinSight.Hijack;

using Xunit;

namespace WinSight.Hijack.Tests;

/// <summary>
/// Grading exists so the two findings that matter are not buried under the many that do not.
/// Unquoted service paths are common on Windows; almost all of them sit under Program Files, where
/// an unprivileged user cannot create the earlier candidate.
/// </summary>
public sealed class HijackTriageTests
{
    private const string Unquoted = @"C:\Program Files\My App\svc.exe -k net";

    [Fact]
    public void AQuotedServiceIsNotAFindingAtAll()
    {
        var triage = new HijackTriage(new NothingWritable());

        Assert.Null(triage.AssessCommandLine("Svc", @"""C:\Program Files\My App\svc.exe"" -k net"));
    }

    [Fact]
    public void UnquotedButUnwritableIsLatent()
    {
        // The common case on a healthy machine. It is real, and it is not urgent.
        var finding = new HijackTriage(new NothingWritable()).AssessCommandLine("Svc", Unquoted);

        Assert.Equal(HijackExposure.Latent, finding?.Exposure);
        Assert.Null(finding?.ActionablePath);
        Assert.Equal([@"C:\Program.exe", @"C:\Program Files\My.exe"], finding?.Candidates);
    }

    [Fact]
    public void UnquotedAndWritableIsExploitable()
    {
        var finding = new HijackTriage(new Writable(@"C:\Program.exe")).AssessCommandLine("Svc", Unquoted);

        Assert.Equal(HijackExposure.Exploitable, finding?.Exposure);
        // The operator needs the exact path, not just the verdict.
        Assert.Equal(@"C:\Program.exe", finding?.ActionablePath);
    }

    [Fact]
    public void ReportsTheFirstWritableCandidate_BecauseThatIsTheOneWindowsWouldRun()
    {
        var finding = new HijackTriage(new Writable(@"C:\Program.exe", @"C:\Program Files\My.exe"))
            .AssessCommandLine("Svc", Unquoted);

        Assert.Equal(@"C:\Program.exe", finding?.ActionablePath);
    }

    [Fact]
    public void AWritableLaterCandidateStillCounts()
    {
        // Only one of the candidates needs to be plantable for the service to be hijackable.
        var finding = new HijackTriage(new Writable(@"C:\Program Files\My.exe")).AssessCommandLine("Svc", Unquoted);

        Assert.Equal(HijackExposure.Exploitable, finding?.Exposure);
        Assert.Equal(@"C:\Program Files\My.exe", finding?.ActionablePath);
    }

    // A candidate that already exists outranks a writable one: the file is there, so the question is
    // no longer whether somebody could plant it.
    [Fact]
    public void AnExistingCandidateIsOccupied_AndOutranksWritability()
    {
        var existing = Path.Combine(Path.GetTempPath(), $"winsight-hijack-{Guid.NewGuid():N}.exe");
        File.WriteAllText(existing, "");
        try
        {
            var commandLine = $"{existing[..^4]} extra\\svc.exe";
            var finding = new HijackTriage(new Writable(existing)).AssessCommandLine("Svc", commandLine);

            Assert.Equal(HijackExposure.Occupied, finding?.Exposure);
            Assert.Equal(existing, finding?.ActionablePath);
        }
        finally
        {
            File.Delete(existing);
        }
    }

    private sealed class NothingWritable : IWritabilityProbe
    {
        public bool CanCreate(string path) => false;
    }

    private sealed class Writable(params string[] paths) : IWritabilityProbe
    {
        public bool CanCreate(string path) =>
            paths.Contains(path, StringComparer.OrdinalIgnoreCase);
    }
}
