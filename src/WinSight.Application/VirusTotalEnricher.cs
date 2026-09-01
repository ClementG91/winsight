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
    /// <param name="tryAcquire">
    /// Stands in for the persistent quota limiter; production passes null. Injected for the same
    /// reason the lookup is: the real limiter is cross-process and fails closed, so a test that
    /// wanted to exercise anything past the guards could never reach it - which is why the budget
    /// behaviour below had no tests at all until it was found to be wrong.
    /// </param>
    internal static IReadOnlyDictionary<string, VtVerdict> Lookup(
        IEnumerable<string> imagePaths,
        bool allowNetworkLookups,
        Func<string, CancellationToken, VtVerdict?>? lookup,
        CancellationToken cancellationToken,
        Func<bool>? tryAcquire = null)
    {
        var results = new Dictionary<string, VtVerdict>(StringComparer.OrdinalIgnoreCase);
        if (!allowNetworkLookups)
        {
            return results;
        }
        cancellationToken.ThrowIfCancellationRequested();
        var apiKey = VirusTotalConfiguration.CurrentApiKey;
        if (apiKey is null)
        {
            return results;
        }

        // A per-scan cap bounds latency even for premium keys. The persistent,
        // cross-process limiter additionally protects Community minute/day/month
        // allowances and fails closed when accounting cannot be persisted.
        const int cap = 4;

        // Hashing is lazy and stops at the cap.
        //
        // It used to SHA-256 every candidate and then take four groups. On a persistence scan that
        // meant reading every flagged executable end to end - a several-hundred-megabyte installer
        // among them - to use four of the digests and throw the rest away. The work was done before
        // anything could decide it was unnecessary.
        //
        // A path whose content matches one already accepted still joins that group, so the verdict
        // still fans out across duplicates. What stops is starting a fifth group: a fifth distinct
        // file was never going to be looked up, and hashing it answered no question.
        //
        // This makes the caller's ordering matter, which is the point. The callers pass their most
        // adverse entries first, so the four lookups go to the findings that most warrant them
        // rather than to whatever the enumerator happened to reach first.
        var resolve = lookup ?? new VirusTotalClient(apiKey).Lookup;
        var groups = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        var order = new List<string>(cap);
        foreach (var path in imagePaths.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (HashUtil.Sha256File(path) is not { } hash)
            {
                continue;
            }
            if (groups.TryGetValue(hash, out var sharing))
            {
                sharing.Add(path);
                continue;
            }
            if (order.Count >= cap)
            {
                break;
            }
            groups[hash] = [path];
            order.Add(hash);
        }

        foreach (var hash in order)
        {
            cancellationToken.ThrowIfCancellationRequested();

            // A verdict already established in this process is reused rather than asked for again.
            // The dashboard runs the same scan repeatedly, and a file's reputation does not change
            // between two scans a minute apart - but the quota it costs is spent every time, and on
            // a Community key that quota is four lookups a minute. Re-asking meant a scheduled
            // dashboard could consume the whole allowance re-establishing what it already knew, and
            // then have nothing left for a file it had never seen.
            if (VirusTotalVerdictCache.TryGet(hash, out var cached))
            {
                Attach(results, groups[hash], cached);
                continue;
            }
            if (!(tryAcquire ?? DefaultAcquire)())
            {
                break;
            }
            if (resolve(hash, cancellationToken) is not { } verdict)
            {
                continue;
            }
            VirusTotalVerdictCache.Set(hash, verdict);
            Attach(results, groups[hash], verdict);
        }
        return results;
    }

    private static bool DefaultAcquire() => VirusTotalQuotaLimiter.Default.TryAcquire(out _);

    private static void Attach(
        Dictionary<string, VtVerdict> results, List<string> paths, VtVerdict verdict)
    {
        foreach (var path in paths)
        {
            results[path] = verdict;
        }
    }
}
