using WinSight.Core;

using Xunit;

namespace WinSight.Ransomware.Tests;

public sealed class CanarySeedConcurrencyTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ConcurrentFirstUseAgreesOnOneSeed(bool malformed)
    {
        // Two components (the launch sweep and restored protection, or two dashboards) can create the
        // seed at the same moment. Different seeds give different decoy names, and decoys named from
        // the losing seed are no longer recognised as expected paths, so they can never be cleaned.
        for (var iteration = 0; iteration < 20; iteration++)
        {
            var directory = Directory.CreateTempSubdirectory("winsight-seed-race-").FullName;
            try
            {
                var path = Path.Combine(directory, "canary-seed.bin");
                if (malformed)
                {
                    File.WriteAllBytes(path, [1, 2, 3]);
                }
                using var go = new ManualResetEventSlim();
                var tasks = Enumerable.Range(0, 8).Select(_ => Task.Run(() =>
                {
                    go.Wait();
                    return CanaryIdentity.LoadOrCreateSeed(path);
                })).ToArray();
                go.Set();
                var seeds = await Task.WhenAll(tasks);

                Assert.All(seeds, seed => Assert.Equal(seeds[0], seed));
                Assert.Equal(seeds[0], File.ReadAllBytes(path));
            }
            finally
            {
                Directory.Delete(directory, recursive: true);
            }
        }
    }

    [Fact]
    public void ACreatorHoldingTheNewSeedDoesNotMakeAReaderInventADifferentOne()
    {
        var directory = Directory.CreateTempSubdirectory("winsight-seed-held-").FullName;
        try
        {
            var path = Path.Combine(directory, "canary-seed.bin");
            var expected = Enumerable.Range(0, 32).Select(value => (byte)value).ToArray();
            using var creator = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            var delays = new List<int>();
            var seed = CanaryIdentity.LoadOrCreateSeed(path, delay =>
            {
                delays.Add(delay);
                // The first attempt must encounter the real exclusive, empty file. Complete the
                // creator at the retry boundary, not on a timer whose continuation may be starved.
                creator.Write(expected);
                creator.Flush(flushToDisk: true);
                creator.Dispose();
            });

            Assert.Equal([5], delays);
            Assert.Equal(expected, seed);
            Assert.Equal(expected, File.ReadAllBytes(path));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void ASeedPendingDeletionIsRetriedUntilAReplacementCanBePersisted()
    {
        var directory = Directory.CreateTempSubdirectory("winsight-seed-repair-held-").FullName;
        try
        {
            var path = Path.Combine(directory, "canary-seed.bin");
            File.WriteAllBytes(path, [1, 2, 3]);
            using var repairer = AutomaticFileAccess.TryAcquireForDelete(path);
            Assert.NotNull(repairer);
            Assert.True(repairer.TryDelete());
            // A sharing refusal is deliberately reported as non-local by this conservative
            // preflight. It must not bypass the seed operation's bounded contention retries.
            Assert.False(AutomaticFileAccess.IsLocal(path));
            var delays = new List<int>();
            var seed = CanaryIdentity.LoadOrCreateSeed(path, delay =>
            {
                delays.Add(delay);
                repairer.Dispose();
            });
            Assert.Equal([5], delays);
            Assert.Equal(32, seed.Length);
            Assert.Equal(seed, File.ReadAllBytes(path));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void PersistentContentionExhaustsTheExactBoundedRetryScheduleWithoutChangingTheSeed()
    {
        var directory = Directory.CreateTempSubdirectory("winsight-seed-budget-").FullName;
        try
        {
            var path = Path.Combine(directory, "canary-seed.bin");
            var expected = Enumerable.Range(0, 32).Select(value => (byte)value).ToArray();
            var delays = new List<int>();
            using (var creator = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                creator.Write(expected);
                creator.Flush(flushToDisk: true);
                var fallback = CanaryIdentity.LoadOrCreateSeed(path, delays.Add);
                Assert.Equal(32, fallback.Length);
                Assert.Equal(Enumerable.Range(1, 19).Select(attempt => 5 * attempt), delays);
            }
            Assert.Equal(expected, File.ReadAllBytes(path));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void AMalformedSeedIsReplacedOnceAndThenStable()
    {
        var directory = Directory.CreateTempSubdirectory("winsight-seed-malformed-").FullName;
        try
        {
            var path = Path.Combine(directory, "canary-seed.bin");
            File.WriteAllBytes(path, [1, 2, 3]); // a torn write from an older version

            var first = CanaryIdentity.LoadOrCreateSeed(path);
            var second = CanaryIdentity.LoadOrCreateSeed(path);

            Assert.Equal(32, first.Length);
            Assert.Equal(first, second);
            Assert.Equal(first, File.ReadAllBytes(path));
            Assert.Single(Directory.GetFiles(directory));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }
}
