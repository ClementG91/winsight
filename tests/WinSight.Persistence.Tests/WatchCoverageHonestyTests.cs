using WinSight.Persistence;
using Xunit;

namespace WinSight.Persistence.Tests;

/// <summary>
/// The watcher must never report coverage it does not have.
/// </summary>
/// <remarks>
/// <b>What was wrong.</b> This is the watcher that tells Guardian a file appeared in a Startup
/// folder. It had no <see cref="FileSystemWatcher.Error"/> handler at all, and its kernel buffer was
/// the 8 KiB default - roughly 250 pending events - while watching <c>\System32\Tasks</c>
/// recursively. An overflow tears the watch down, so the first burst of task churn ended monitoring
/// of that directory for the lifetime of the process, and <c>ArmedLocations</c> kept counting it.
///
/// The ransomware watcher was rebuilt around exactly this failure and carries a long comment
/// explaining it. This one, three files away, still had the defect: the same silent false negative,
/// in the surface where persistence actually lives.
/// </remarks>
public sealed class WatchCoverageHonestyTests
{
    private static string TempDir()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"winsight-watchcov-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        return directory;
    }

    [Fact]
    public void ADirectoryThatCannotBeWatchedIsNotCountedAsArmed()
    {
        using var watcher = new FileSystemPersistenceWatcher(
        [
            PersistenceWatchTarget.FileSystem(
                Path.Combine(Path.GetTempPath(), $"absent-{Guid.NewGuid():N}")),
        ]);

        watcher.Start();

        Assert.Equal(1, watcher.RequestedLocations);
        Assert.Equal(0, watcher.ArmedLocations);
    }

    /// <summary>
    /// The gap between what was asked for and what is observed is the number an operator needs, and
    /// it must be non-zero exactly when something is not being watched.
    /// </summary>
    [Fact]
    public void TheRequestedAndArmedCountsAgreeWhenEverythingIsWatched()
    {
        var directory = TempDir();
        try
        {
            using var watcher = new FileSystemPersistenceWatcher(
                [PersistenceWatchTarget.FileSystem(directory)]);

            watcher.Start();

            Assert.Equal(watcher.RequestedLocations, watcher.ArmedLocations);
            Assert.Equal(0, watcher.OverflowCount);
            Assert.Equal(0, watcher.LostWatchCount);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>
    /// A watch whose directory disappears cannot be re-armed after an overflow, and must stop
    /// counting as armed. Driven through the real watcher rather than a fake: the point is that the
    /// handler exists and is wired, which a fake cannot demonstrate.
    /// </summary>
    [Fact]
    public void AWatchOnADeletedDirectoryStopsCountingAsArmed()
    {
        var directory = TempDir();
        var watcher = new FileSystemPersistenceWatcher(
            [PersistenceWatchTarget.FileSystem(directory)]);
        try
        {
            watcher.Start();
            Assert.Equal(1, watcher.ArmedLocations);

            // Deleting the watched directory is what a real overflow-then-failed-re-arm ends in, and
            // it is the state the count has to reflect. Windows raises Error asynchronously, so the
            // assertion waits for it rather than assuming a delivery deadline.
            Directory.Delete(directory, recursive: true);

            var deadline = DateTime.UtcNow.AddSeconds(10);
            while (watcher.ArmedLocations != 0 && DateTime.UtcNow < deadline)
            {
                Thread.Sleep(50);
            }

            Assert.Equal(0, watcher.ArmedLocations);
            Assert.True(watcher.OverflowCount > 0, "no error was reported for the deleted directory");
        }
        finally
        {
            watcher.Dispose();
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
    }
}
