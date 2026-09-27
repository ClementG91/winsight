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
    public async Task ACreatorHoldingTheNewSeedDoesNotMakeAReaderInventADifferentOne()
    {
        var directory = Directory.CreateTempSubdirectory("winsight-seed-held-").FullName;
        try
        {
            var path = Path.Combine(directory, "canary-seed.bin");
            var expected = Enumerable.Range(0, 32).Select(value => (byte)value).ToArray();
            Task<byte[]> reading;
            using (var creator = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                reading = Task.Factory.StartNew(() =>
                {
                    started.SetResult();
                    return CanaryIdentity.LoadOrCreateSeed(path);
                }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
                await started.Task.WaitAsync(TimeSpan.FromSeconds(30));
                // The previous loop exhausted twenty null/false returns immediately: neither safe
                // file helper throws on sharing violations, so its catch-only delay never ran.
                await Task.WhenAny(reading, Task.Delay(TimeSpan.FromMilliseconds(500)));
                creator.Write(expected);
                creator.Flush(flushToDisk: true);
            }

            Assert.Equal(expected, await reading.WaitAsync(TimeSpan.FromSeconds(30)));
            Assert.Equal(expected, File.ReadAllBytes(path));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task ASeedPendingDeletionIsRetriedUntilAReplacementCanBePersisted()
    {
        var directory = Directory.CreateTempSubdirectory("winsight-seed-repair-held-").FullName;
        try
        {
            var path = Path.Combine(directory, "canary-seed.bin");
            File.WriteAllBytes(path, [1, 2, 3]);
            Task<byte[]> reading;
            using (var repairer = AutomaticFileAccess.TryAcquireForDelete(path))
            {
                Assert.NotNull(repairer);
                Assert.True(repairer.TryDelete());
                // A sharing refusal is deliberately reported as non-local by this conservative
                // preflight. It must not bypass the seed operation's bounded contention retries.
                Assert.False(AutomaticFileAccess.IsLocal(path));
                var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                reading = Task.Factory.StartNew(() =>
                {
                    started.SetResult();
                    return CanaryIdentity.LoadOrCreateSeed(path);
                }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
                await started.Task.WaitAsync(TimeSpan.FromSeconds(30));
                await Task.WhenAny(reading, Task.Delay(TimeSpan.FromMilliseconds(500)));
            }
            var seed = await reading.WaitAsync(TimeSpan.FromSeconds(30));
            Assert.Equal(32, seed.Length);
            Assert.Equal(seed, File.ReadAllBytes(path));
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
