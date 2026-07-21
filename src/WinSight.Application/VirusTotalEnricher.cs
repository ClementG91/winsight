using WinSight.Core;

namespace WinSight.Application;

/// <summary>
/// Optional, quota-controlled reputation enrichment. Keeping this policy outside
/// scanner adapters prevents network concerns from leaking into detection logic.
/// </summary>
internal static class VirusTotalEnricher
{
    public static IReadOnlyDictionary<string, VtVerdict> Lookup(
        IEnumerable<string> imagePaths,
        bool allowNetworkLookups,
        CancellationToken cancellationToken) =>
        Lookup(imagePaths, allowNetworkLookups, lookup: null, cancellationToken);

    /// <param name="lookup">Stands in for the live VirusTotal client; production passes null.</param>
    /// <remarks>
    /// This is the only code in WinSight that can send anything off the machine, so its guards are
    /// worth proving rather than inferring. An empty result is not proof: a request that simply
    /// failed returns empty too, so a test asserting "nothing came back" would keep passing even if
    /// a guard were deleted. Injecting the call lets a test assert the lookup was never *reached*.
    /// The real client is constructed only once every guard has passed and there is something to
    /// ask about, so no HttpClient is created for a scan that will not use it.
    /// </remarks>
    internal static IReadOnlyDictionary<string, VtVerdict> Lookup(
        IEnumerable<string> imagePaths,
        bool allowNetworkLookups,
        Func<string, CancellationToken, VtVerdict?>? lookup,
        CancellationToken cancellationToken)
    {
        var results = new Dictionary<string, VtVerdict>(StringComparer.OrdinalIgnoreCase);
        if (!allowNetworkLookups)
        {
            return results;
        }
        var apiKey = Environment.GetEnvironmentVariable("WINSIGHT_VT_KEY");
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            return results;
        }

        // A per-scan cap bounds latency even for premium keys. The persistent,
        // cross-process limiter additionally protects Community minute/day/month
        // allowances and fails closed when accounting cannot be persisted.
        const int cap = 4;
        var candidates = new List<(string Path, string Sha256)>();
        foreach (var path in imagePaths.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (HashUtil.Sha256File(path) is { } hash)
            {
                candidates.Add((path, hash));
            }
        }

        if (candidates.Count == 0)
        {
            return results;
        }

        var resolve = lookup ?? new VirusTotalClient(apiKey).Lookup;
        foreach (var candidateGroup in candidates
                     .GroupBy(candidate => candidate.Sha256, StringComparer.OrdinalIgnoreCase)
                     .Take(cap))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!VirusTotalQuotaLimiter.Default.TryAcquire(out _))
            {
                break;
            }
            if (resolve(candidateGroup.Key, cancellationToken) is not { } verdict)
            {
                continue;
            }
            foreach (var candidate in candidateGroup)
            {
                results[candidate.Path] = verdict;
            }
        }
        return results;
    }
}
