using System.Reflection;
using System.Text;

using Xunit;

namespace WinSight.Core.Tests;

public sealed class AtomicPublicationOwnershipTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("winsight-publication-owner-").FullName;
    public void Dispose() => Directory.Delete(_root, recursive: true);
    private delegate bool GenericAtomic(string? path, ReadOnlySpan<byte> bytes, bool createParents, bool replaceExisting);
    private delegate bool BoundedAtomic(string path, ReadOnlySpan<byte> bytes, bool replaceExisting);

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void DestinationAppearingAfterMissingObservationIsNeverReplaced(bool bounded)
    {
        var path = Path.Combine(_root, "observed-missing.json");
        using (var absent = AutomaticFileAccess.TryAcquire(path, out var missing))
        {
            Assert.Null(absent);
            Assert.True(missing);
        }
        var foreign = Encoding.UTF8.GetBytes("actual foreign bytes published after absence");
        Assert.True(AutomaticFileAccess.TryCreateNewFile(path, foreign));
        Assert.False(Publish(path, Encoding.UTF8.GetBytes("losing writer"), bounded));
        Assert.Equal(foreign, File.ReadAllBytes(path));
        Assert.Single(Directory.GetFiles(_root));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void InitialPublicationIsDurableAndItsSecondAttemptCannotReplace(bool bounded)
    {
        var path = Path.Combine(_root, "initial.json");
        var first = Encoding.UTF8.GetBytes("first durable publication");
        Assert.True(Publish(path, first, bounded));
        Assert.False(Publish(path, Encoding.UTF8.GetBytes("second publication"), bounded));
        Assert.Equal(first, File.ReadAllBytes(path));
        Assert.Single(Directory.GetFiles(_root));
    }

    [Fact]
    public async Task ConcurrentNativeInitialPublicationsHaveExactlyOneWinner()
    {
        var path = Path.Combine(_root, "concurrent.json");
        using var barrier = new Barrier(2);
        var writes = Enumerable.Range(0, 2).Select(index => Task.Run(() =>
        {
            var bytes = Encoding.UTF8.GetBytes(new string((char)('a' + index), 8192));
            Assert.True(barrier.SignalAndWait(TimeSpan.FromSeconds(10)));
            return (bytes, success: Publish(path, bytes, bounded: false));
        })).ToArray();
        var results = await Task.WhenAll(writes).WaitAsync(TimeSpan.FromSeconds(30));
        Assert.Equal(Assert.Single(results, result => result.success).bytes, File.ReadAllBytes(path));
        Assert.Single(Directory.GetFiles(_root));
    }

    private static bool Publish(string path, byte[] bytes, bool bounded)
    {
        var method = typeof(AutomaticFileAccess).GetMethods(BindingFlags.Public | BindingFlags.Static)
            .SingleOrDefault(candidate => candidate.Name == (bounded ? "TryWriteAtomicBounded" : "TryWriteAtomic")
                && candidate.GetParameters().Length == (bounded ? 3 : 4));
        Assert.NotNull(method);
        return bounded ? method.CreateDelegate<BoundedAtomic>()(path, bytes, false)
            : method.CreateDelegate<GenericAtomic>()(path, bytes, true, false);
    }
}
