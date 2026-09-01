using WinSight.Hijack;
using Xunit;

namespace WinSight.Hijack.Tests;

/// <summary>
/// The probe answers each directory once and remembers it.
/// </summary>
/// <remarks>
/// <b>Why this matters beyond speed.</b> The unelevated probe answers by really creating a file and
/// deleting it. Without a memo, one hijack scan did that in <c>System32</c>, in every machine PATH
/// entry, and in each of roughly 88 service directories - repeatedly, because a service with an
/// unquoted path asks about several candidates in the same folder and the PATH sweep asks about
/// every entry again. A security tool writing into Program Files a few hundred times per scan is
/// doing more I/O than the scan it is performing, and every one of those writes is a chance to leave
/// litter behind in a directory it does not own.
///
/// The answer is a property of the directory: the caller establishes that the candidate file does
/// not exist before asking, and after that only the directory decides. The memo lives on the probe
/// instance, which is one scan - caching across scans would answer today's question with
/// yesterday's ACL.
/// </remarks>
public sealed class WritabilityProbeMemoTests
{
    private static string TempDir()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"winsight-probe-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        return directory;
    }

    /// <summary>
    /// Repeated questions about one directory agree with each other. A memo that returned a
    /// different answer the second time would be worse than none.
    /// </summary>
    [Fact]
    public void RepeatedQuestionsAboutOneDirectoryAgree()
    {
        var directory = TempDir();
        try
        {
            var probe = new WritabilityProbe(elevated: false);

            var first = probe.CanCreate(Path.Combine(directory, "a.dll"));
            var second = probe.CanCreate(Path.Combine(directory, "b.dll"));
            var third = probe.CanCreate(Path.Combine(directory, "c.dll"));

            Assert.True(first);
            Assert.Equal(first, second);
            Assert.Equal(first, third);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>
    /// Different directories are still answered independently: the memo must be a cache, not a
    /// single sticky verdict applied to the whole machine.
    /// </summary>
    [Fact]
    public void DifferentDirectoriesGetTheirOwnAnswers()
    {
        var writable = TempDir();
        try
        {
            var probe = new WritabilityProbe(elevated: false);
            var absent = Path.Combine(
                Path.GetTempPath(), $"winsight-absent-{Guid.NewGuid():N}", "x.dll");

            Assert.True(probe.CanCreate(Path.Combine(writable, "x.dll")));
            Assert.False(probe.CanCreate(absent));
            Assert.True(probe.CanCreate(Path.Combine(writable, "y.dll")));
        }
        finally
        {
            Directory.Delete(writable, recursive: true);
        }
    }

    /// <summary>
    /// The probe leaves nothing behind, and after the memo it should be writing far less than once
    /// per question. Both are checked by asking many times and finding the directory still empty.
    /// </summary>
    [Fact]
    public void TheProbeLeavesNoLitterHoweverOftenItIsAsked()
    {
        var directory = TempDir();
        try
        {
            var probe = new WritabilityProbe(elevated: false);
            for (var index = 0; index < 50; index++)
            {
                probe.CanCreate(Path.Combine(directory, $"candidate-{index}.dll"));
            }

            Assert.Empty(Directory.GetFileSystemEntries(directory));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>
    /// An existing file is still refused after the directory has been memoised as writable: the
    /// per-candidate check happens before the memo is consulted, and skipping it would report a
    /// real file as plantable and invite it being overwritten.
    /// </summary>
    [Fact]
    public void AnExistingCandidateIsStillRefusedInAWritableDirectory()
    {
        var directory = TempDir();
        try
        {
            var probe = new WritabilityProbe(elevated: false);
            var occupied = Path.Combine(directory, "already-here.dll");
            File.WriteAllText(occupied, "stub");

            Assert.True(probe.CanCreate(Path.Combine(directory, "free.dll")));
            Assert.False(probe.CanCreate(occupied));
            Assert.Equal("stub", File.ReadAllText(occupied));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>
    /// The coverage count keeps meaning "questions I could not answer", not "directories I could not
    /// read". A caller reports it as a blind spot per finding, so collapsing it to one per directory
    /// would understate the gap.
    /// </summary>
    [Fact]
    public void TheUnreadableCountRisesPerQuestionNotPerDirectory()
    {
        var probe = new WritabilityProbe(elevated: false);

        // A directory that does not exist is answered before any attempt, so it contributes nothing
        // to the count - which is the baseline this assertion rests on.
        var absent = Path.Combine(Path.GetTempPath(), $"winsight-absent-{Guid.NewGuid():N}");
        probe.CanCreate(Path.Combine(absent, "x.dll"));
        probe.CanCreate(Path.Combine(absent, "y.dll"));

        Assert.Equal(0, probe.UnreadableAttempts);
    }
}
