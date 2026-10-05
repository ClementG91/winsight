using System.Text;
using System.Text.Json;

namespace WinSight.Core;

/// <summary>A VirusTotal file-reputation verdict.</summary>
/// <param name="Malicious">Engines flagging the file as malicious.</param>
/// <param name="Suspicious">Engines flagging it as suspicious.</param>
/// <param name="Total">Total engines that analysed it.</param>
/// <param name="Permalink">Human URL to the VT report.</param>
public sealed record VtVerdict(int Malicious, int Suspicious, int Total, string Permalink);

/// <summary>
/// Optional VirusTotal file-reputation lookup by SHA-256. STRICTLY opt-in: it only
/// runs when the user supplies their own API key, and is the ONLY thing in WinSight
/// that touches the network, the tool is local-only by default. Failures (no result,
/// rate limit, offline) return null; a reputation lookup never blocks a scan and is
/// never automatically retried. Cross-process quota enforcement lives in the shared
/// application adapter so every scanner uses the same accounting policy.
/// </summary>
public sealed class VirusTotalClient
{
    private const int MaximumResponseBytes = 1024 * 1024;
    private static readonly Encoding StrictUtf8 = new UTF8Encoding(false, true);
    private static readonly HttpClient Shared = new(new HttpClientHandler
    {
        // A custom x-apikey header is not guaranteed to be stripped on a cross-origin redirect.
        // The endpoint is fixed; any redirect is therefore refused instead of forwarding a secret.
        AllowAutoRedirect = false,
    })
    {
        Timeout = TimeSpan.FromSeconds(20),
    };
    private readonly HttpClient _http;
    private readonly string _apiKey;
    private readonly TimeSpan _lookupTimeout;

    /// <param name="apiKey">The user's own VirusTotal API key.</param>
    /// <param name="http">Optional HttpClient (tests / custom pipeline); defaults to a shared instance.</param>
    public VirusTotalClient(string apiKey, HttpClient? http = null)
        : this(apiKey, http, TimeSpan.FromSeconds(20))
    {
    }

    internal VirusTotalClient(string apiKey, HttpClient? http, TimeSpan lookupTimeout)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(lookupTimeout, TimeSpan.Zero);
        if (!VirusTotalConfiguration.IsPlausibleApiKey(apiKey))
        {
            throw new ArgumentException("The VirusTotal API key format is invalid.", nameof(apiKey));
        }
        _apiKey = apiKey;
        _http = http ?? Shared;
        _lookupTimeout = lookupTimeout;
    }

    /// <summary>
    /// True when the input is a well-formed SHA-256 (64 hex chars). Lookup refuses
    /// anything else so no attacker-influenced string can ever alter the request URL.
    /// </summary>
    public static bool IsSha256(string? value) =>
        value is { Length: 64 } && value.All(Uri.IsHexDigit);

    public VtVerdict? Lookup(string sha256, CancellationToken cancellationToken = default)
    {
        if (!IsSha256(sha256))
        {
            return null;
        }
        try
        {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            var timeout = _http.Timeout == Timeout.InfiniteTimeSpan
                ? _lookupTimeout : TimeSpan.FromTicks(Math.Min(_lookupTimeout.Ticks, _http.Timeout.Ticks));
            deadline.CancelAfter(timeout);
            using var request = new HttpRequestMessage(
                HttpMethod.Get, $"https://www.virustotal.com/api/v3/files/{sha256}");
            request.Headers.Add("x-apikey", _apiKey);
            using var response = _http.Send(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token);
            if (!response.IsSuccessStatusCode)
            {
                return null;
            }
            if (response.Content.Headers.ContentLength is > MaximumResponseBytes)
            {
                return null;
            }
            using var stream = response.Content.ReadAsStreamAsync(deadline.Token).GetAwaiter().GetResult();
            return ReadLimitedAsync(stream, deadline.Token).GetAwaiter().GetResult() is { } json
                ? ParseStats(json, sha256) : null;
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException or JsonException
                                     or InvalidOperationException or DecoderFallbackException ||
                                     ex is OperationCanceledException && !cancellationToken.IsCancellationRequested)
        {
            return null;
        }
    }

    /// <summary>
    /// Parses a VT v3 file response into a verdict. Pure and unit-tested; malformed or
    /// unexpected JSON yields null.
    /// </summary>
    public static VtVerdict? ParseStats(string json, string sha256)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var stats = doc.RootElement
                .GetProperty("data").GetProperty("attributes").GetProperty("last_analysis_stats");
            var malicious = stats.GetProperty("malicious").GetInt32();
            var suspicious = stats.GetProperty("suspicious").GetInt32();
            if (malicious < 0 || suspicious < 0)
            {
                return null;
            }
            var total = 0;
            foreach (var entry in stats.EnumerateObject())
            {
                var value = entry.Value.GetInt32();
                if (value < 0)
                {
                    return null;
                }
                total = checked(total + value);
            }
            return new VtVerdict(malicious, suspicious, total,
                $"https://www.virustotal.com/gui/file/{sha256}");
        }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException
                                     or InvalidOperationException or FormatException or OverflowException)
        {
            return null;
        }
    }

    private static async Task<string?> ReadLimitedAsync(Stream stream, CancellationToken cancellationToken)
    {
        var buffer = new byte[8192];
        using var result = new MemoryStream();
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            // Read one extra byte to distinguish an exact-sized body from an oversized one.
            var allowed = (int)Math.Min(buffer.Length, MaximumResponseBytes - result.Length + 1);
            var read = await stream.ReadAsync(buffer.AsMemory(0, allowed), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return StrictUtf8.GetString(result.GetBuffer().AsSpan(0, (int)result.Length));
            }
            if (result.Length + read > MaximumResponseBytes)
            {
                return null;
            }
            result.Write(buffer, 0, read);
        }
    }
}
