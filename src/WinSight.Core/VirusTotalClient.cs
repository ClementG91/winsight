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
/// that touches the network — the tool is local-only by default. Failures (no result,
/// rate limit, offline) return null; a reputation lookup never blocks a scan.
/// </summary>
public sealed class VirusTotalClient
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(20) };
    private readonly string _apiKey;

    public VirusTotalClient(string apiKey) => _apiKey = apiKey;

    public VtVerdict? Lookup(string sha256)
    {
        try
        {
            using var request = new HttpRequestMessage(
                HttpMethod.Get, $"https://www.virustotal.com/api/v3/files/{sha256}");
            request.Headers.Add("x-apikey", _apiKey);
            using var response = Http.Send(request);
            if (!response.IsSuccessStatusCode)
            {
                return null;
            }
            using var reader = new StreamReader(response.Content.ReadAsStream());
            return ParseStats(reader.ReadToEnd(), sha256);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException
                                     or JsonException or InvalidOperationException)
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
            var total = 0;
            foreach (var entry in stats.EnumerateObject())
            {
                total += entry.Value.GetInt32();
            }
            return new VtVerdict(malicious, suspicious, total,
                $"https://www.virustotal.com/gui/file/{sha256}");
        }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException
                                     or InvalidOperationException or FormatException)
        {
            return null;
        }
    }
}
