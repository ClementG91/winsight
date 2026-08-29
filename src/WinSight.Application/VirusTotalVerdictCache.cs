using System.Collections.Concurrent;

using WinSight.Core;

namespace WinSight.Application;

/// <summary>
/// Reputation verdicts already established in this process, keyed by file content hash.
/// </summary>
/// <remarks>
/// <b>What this protects.</b> A Community VirusTotal key allows four lookups a minute. The dashboard
/// re-runs the same scan on a timer and the CLI is recommended for a scheduled task, so the same
/// handful of files were looked up again and again - spending the whole allowance re-establishing a
/// verdict the process already had, and then having nothing left for a file it had never seen. The
/// per-scan cap bounded latency; nothing bounded repetition across scans.
///
/// <b>Why keying on the hash is the right unit.</b> The verdict is about content, not about a path.
/// Two paths with the same hash share one answer, and a file replaced at the same path hashes
/// differently and is therefore asked about again - which is exactly the case where a stale answer
/// would matter.
///
/// <b>Why it expires.</b> A reputation is a claim about the world at a moment, and the world moves:
/// a file that was clean this morning can be detected this afternoon, and that transition is the one
/// an operator most needs to see. <see cref="Lifetime"/> is short enough that a scan an hour later
/// asks again, and long enough that a dashboard refreshing every few minutes does not.
///
/// <b>Why in memory only.</b> Persisting it would put third-party reputation claims about this
/// machine's files on disk, which is a privacy question this tool has not asked its user. The cache
/// dies with the process.
/// </remarks>
internal static class VirusTotalVerdictCache
{
    /// <summary>How long a verdict is reused before it is asked for again.</summary>
    internal static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(30);

    /// <summary>
    /// A bound, so a long-lived dashboard cannot grow this without limit. Reaching it means the
    /// process has seen more than this many distinct interesting files in half an hour, at which
    /// point the oldest answers are the ones worth losing.
    /// </summary>
    internal const int MaxEntries = 512;

    private static readonly ConcurrentDictionary<string, (VtVerdict Verdict, DateTimeOffset At)> Entries =
        new(StringComparer.OrdinalIgnoreCase);

    private static Func<DateTimeOffset> _clock = () => DateTimeOffset.UtcNow;

    /// <summary>The verdict for <paramref name="sha256"/> if one is still current.</summary>
    internal static bool TryGet(string sha256, out VtVerdict verdict)
    {
        verdict = default!;
        if (!Entries.TryGetValue(sha256, out var entry))
        {
            return false;
        }
        if (_clock() - entry.At > Lifetime)
        {
            Entries.TryRemove(sha256, out _);
            return false;
        }
        verdict = entry.Verdict;
        return true;
    }

    /// <summary>Remembers <paramref name="verdict"/> for <paramref name="sha256"/>.</summary>
    internal static void Set(string sha256, VtVerdict verdict)
    {
        if (Entries.Count >= MaxEntries)
        {
            Evict();
        }
        Entries[sha256] = (verdict, _clock());
    }

    /// <summary>Drops expired entries, then the oldest, until the cache is under its bound.</summary>
    private static void Evict()
    {
        var now = _clock();
        foreach (var pair in Entries)
        {
            if (now - pair.Value.At > Lifetime)
            {
                Entries.TryRemove(pair.Key, out _);
            }
        }
        // Still full: the process really is seeing this many distinct files, so make room by age.
        foreach (var pair in Entries.OrderBy(entry => entry.Value.At).Take(MaxEntries / 4))
        {
            if (Entries.Count < MaxEntries)
            {
                break;
            }
            Entries.TryRemove(pair.Key, out _);
        }
    }

    /// <summary>Test seam: drives expiry without waiting for it.</summary>
    internal static IDisposable UseClock(Func<DateTimeOffset> clock)
    {
        var previous = _clock;
        _clock = clock;
        Entries.Clear();
        return new Restore(() =>
        {
            _clock = previous;
            Entries.Clear();
        });
    }

    /// <summary>Test seam: an empty cache, so one test cannot answer another's lookup.</summary>
    internal static void Clear() => Entries.Clear();

    private sealed class Restore(Action onDispose) : IDisposable
    {
        public void Dispose() => onDispose();
    }
}
