using Xunit;

namespace WinSight.Ransomware.Tests;

public sealed class CanarySeedConcurrencyTests
{
    [Fact]
    public async Task ConcurrentFirstUseAgreesOnOneSeed()
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
