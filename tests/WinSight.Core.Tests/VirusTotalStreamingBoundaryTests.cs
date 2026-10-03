using System.Net;
using System.Text;

using Xunit;

namespace WinSight.Core.Tests;

public sealed class VirusTotalStreamingBoundaryTests
{
    private const int Limit = 1024 * 1024;
    private static readonly string Hash = new('b', 64);
    private static readonly string Key = new('a', 64); // synthetic credentials only

    [Theory]
    [InlineData(null)]
    [InlineData(1L)]
    public void MissingOrFalseLengthCannotBypassByteBudget(long? declared)
    {
        using var body = new VirusTotalStreamingTests.CountingBody(new byte[3 * Limit]);
        using var handler = new VirusTotalStreamingTests.ReplyHandler(body, declared);
        using var http = new HttpClient(handler);
        Assert.Null(new VirusTotalClient(Key, http).Lookup(Hash));
        Assert.Equal(Limit + 1, body.BytesRead);
        Assert.Equal(1, handler.Calls);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(Limit)]
    public void ValidJsonWorksThroughExactBoundary(int size)
    {
        const string json = "{\"data\":{\"attributes\":{\"last_analysis_stats\":{\"malicious\":1,\"suspicious\":2,\"harmless\":3}}}}";
        var payload = Encoding.UTF8.GetBytes(json.PadRight(Math.Max(size, json.Length)));
        using var body = new VirusTotalStreamingTests.CountingBody(payload);
        using var handler = new VirusTotalStreamingTests.ReplyHandler(body);
        using var http = new HttpClient(handler);
        var result = new VirusTotalClient(Key, http).Lookup(Hash);
        Assert.NotNull(result);
        Assert.Equal(1, result.Malicious);
        Assert.Equal(2, result.Suspicious);
        Assert.Equal(6, result.Total);
        Assert.Equal(payload.Length, body.BytesRead);
    }

    [Theory]
    [InlineData(HttpStatusCode.TooManyRequests)]
    [InlineData(HttpStatusCode.Redirect)]
    public void ErrorStatusDoesNotReadOrRetry(HttpStatusCode status)
    {
        using var body = new VirusTotalStreamingTests.CountingBody(new byte[Limit]);
        using var handler = new VirusTotalStreamingTests.ReplyHandler(body, status: status);
        using var http = new HttpClient(handler);
        Assert.Null(new VirusTotalClient(Key, http).Lookup(Hash));
        Assert.Equal(0, body.BytesRead);
        Assert.Equal(1, handler.Calls);
    }

    [Theory]
    [InlineData(100, 20_000)]
    [InlineData(20_000, 100)]
    public async Task BodyDeadlineEndsAStalledRead(int lookupMilliseconds, int httpMilliseconds)
    {
        using var body = new StalledBody();
        using var handler = new VirusTotalStreamingTests.ReplyHandler(body);
        using var http = new HttpClient(handler) { Timeout = TimeSpan.FromMilliseconds(httpMilliseconds) };
        var client = new VirusTotalClient(Key, http, TimeSpan.FromMilliseconds(lookupMilliseconds));
        var lookup = Task.Run(() => client.Lookup(Hash));
        try
        {
            Assert.Null(await lookup.WaitAsync(TimeSpan.FromSeconds(5)));
            Assert.True(body.Cancelled);
        }
        finally
        {
            await FinishLookup(lookup, body);
        }
    }

    [Fact]
    public async Task CallerCancellationIsPreserved()
    {
        using var cancellation = new CancellationTokenSource();
        using var body = new StalledBody(cancellation);
        using var handler = new VirusTotalStreamingTests.ReplyHandler(body);
        using var http = new HttpClient(handler);
        var client = new VirusTotalClient(Key, http);
        var lookup = Task.Run(() => client.Lookup(Hash, cancellation.Token));
        try
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => lookup.WaitAsync(TimeSpan.FromSeconds(5)));
            Assert.True(body.Cancelled);
        }
        finally
        {
            await FinishLookup(lookup, body);
        }
    }

    [Fact]
    public void InvalidUtf8IsRejected()
    {
        using var body = new VirusTotalStreamingTests.CountingBody([0xff, 0xfe]);
        using var handler = new VirusTotalStreamingTests.ReplyHandler(body);
        using var http = new HttpClient(handler);
        Assert.Null(new VirusTotalClient(Key, http).Lookup(Hash));
    }

    private static async Task FinishLookup(Task lookup, StalledBody body)
    {
        // Release only after the assertions or a failing watchdog, never as their cancellation oracle.
        body.Release();
        try
        {
            await lookup.WaitAsync(TimeSpan.FromSeconds(5));
        }
        catch (OperationCanceledException)
        {
            // Cancellation is already observed/asserted in the test; this is only worker cleanup.
        }
    }

    private sealed class StalledBody(CancellationTokenSource? caller = null) : Stream
    {
        private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal bool Cancelled { get; private set; }
        internal void Release() => _release.TrySetResult();
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            caller?.Cancel();
            try
            {
                await _release.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
                return 0;
            }
            catch (OperationCanceledException)
            {
                Cancelled = true;
                throw;
            }
        }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
