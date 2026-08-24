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
    private const int MaximumResponseCharacters = 1024 * 1024;
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

    /// <param name="apiKey">The user's own VirusTotal API key.</param>
    /// <param name="http">Optional HttpClient (tests / custom pipeline); defaults to a shared instance.</param>
    public VirusTotalClient(string apiKey, HttpClient? http = null)
    {
        if (!VirusTotalConfiguration.IsPlausibleApiKey(apiKey))
        {
            throw new ArgumentException("The VirusTotal API key format is invalid.", nameof(apiKey));
        }
        _apiKey = apiKey;
        _http = http ?? Shared;
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
            using var request = new HttpRequestMessage(
                HttpMethod.Get, $"https://www.virustotal.com/api/v3/files/{sha256}");
            request.Headers.Add("x-apikey", _apiKey);
            using var response = _http.Send(request, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                return null;
            }
            if (response.Content.Headers.ContentLength is > MaximumResponseCharacters)
            {
                return null;
            }
            using var reader = new StreamReader(response.Content.ReadAsStream(cancellationToken));
            return ReadLimited(reader) is { } json ? ParseStats(json, sha256) : null;
        }
        catch (Exception ex) when (ex is HttpRequestException or JsonException or InvalidOperationException ||
                                     ex is TaskCanceledException && !cancellationToken.IsCancellationRequested)
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

    private static string? ReadLimited(StreamReader reader)
    {
        var buffer = new char[8192];
        var result = new System.Text.StringBuilder();
        while (true)
        {
            var read = reader.Read(buffer, 0, buffer.Length);
            if (read == 0)
            {
                return result.ToString();
            }
            if (result.Length + read > MaximumResponseCharacters)
            {
                return null;
            }
            result.Append(buffer, 0, read);
        }
    }
}
