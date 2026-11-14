using System.Net;

using Xunit;

namespace WinSight.Core.Tests;

public sealed class VirusTotalStreamingTests
{
    [Fact]
    public void DeclaredOversizedBodyIsRejectedWithoutReading()
    {
        using var body = new CountingBody(new byte[3 * 1024 * 1024]);
        using var handler = new ReplyHandler(body, 3 * 1024 * 1024);
        using var http = new HttpClient(handler);
        var client = new VirusTotalClient(new string('a', 64), http); // synthetic key, no network
        Assert.Null(client.Lookup(new string('b', 64)));
        Assert.Equal(0, body.BytesRead);
        Assert.Equal(1, handler.Calls);
    }

    internal sealed class ReplyHandler(Stream body, long? declaredLength = null,
        HttpStatusCode status = HttpStatusCode.OK) : HttpMessageHandler
    {
        internal int Calls { get; private set; }
        protected override HttpResponseMessage Send(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            var response = new HttpResponseMessage(status) { Content = new StreamContent(body) };
            response.Content.Headers.ContentLength = declaredLength;
            return response;
        }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken) => Task.FromResult(Send(request, cancellationToken));
    }

    internal sealed class CountingBody(byte[] payload) : Stream
    {
        private int _position;
        internal int BytesRead => _position;
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => _position; set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));
        public override int Read(Span<byte> buffer)
        {
            var count = Math.Min(buffer.Length, payload.Length - _position);
            payload.AsSpan(_position, count).CopyTo(buffer);
            _position += count;
            return count;
        }
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(Read(buffer.Span));
        }
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
