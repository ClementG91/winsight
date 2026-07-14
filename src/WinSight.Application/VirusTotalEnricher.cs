using WinSight.Core;

namespace WinSight.Application;

/// <summary>
/// Optional, quota-controlled reputation enrichment. Keeping this policy outside
/// scanner adapters prevents network concerns from leaking into detection logic.
/// </summary>
internal static class VirusTotalEnricher
{
    public static Dictionary<string, VtVerdict> Lookup(
        IEnumerable<string> imagePaths,
        bool allowNetworkLookups,
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

        var client = new VirusTotalClient(apiKey);
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

        foreach (var candidateGroup in candidates
                     .GroupBy(candidate => candidate.Sha256, StringComparer.OrdinalIgnoreCase)
                     .Take(cap))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!VirusTotalQuotaLimiter.Default.TryAcquire(out _))
            {
                break;
            }
            if (client.Lookup(candidateGroup.Key, cancellationToken) is not { } verdict)
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
