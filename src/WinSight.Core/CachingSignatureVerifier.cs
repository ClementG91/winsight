using System.Diagnostics;

namespace WinSight.Core;

/// <summary>
/// A caching decorator over any <see cref="ISignatureVerifier"/>. A file's verdict is
/// cached by path and file metadata, so unchanged binaries are verified once when
/// several tools inspect them. Entries expire and the least-recently-used entry is
/// evicted at a fixed bound: a long-running dashboard cannot grow this cache without
/// limit or treat an old verdict as an authorization decision.
/// </summary>
public sealed class CachingSignatureVerifier : ISignatureVerifier
{
    private readonly ISignatureVerifier _inner;
    private readonly int _maxEntries;
    private readonly TimeSpan _maxAge;
    private readonly object _sync = new();
    private readonly LinkedList<string> _lru = new();
    private readonly Dictionary<string, CacheEntry> _cache =
        new(StringComparer.OrdinalIgnoreCase);

    public CachingSignatureVerifier(
        ISignatureVerifier inner,
        int maxEntries = 4096,
        TimeSpan? maxAge = null)
    {
        ArgumentNullException.ThrowIfNull(inner);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxEntries);
        if (maxAge is { } configuredAge && configuredAge <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(maxAge));
        }
        _inner = inner;
        _maxEntries = maxEntries;
        _maxAge = maxAge ?? TimeSpan.FromMinutes(5);
    }

    public SignatureVerdict Verify(string path, CancellationToken cancellationToken = default) =>
        VerifyMany([path], cancellationToken).TryGetValue(path, out var v) ? v : SignatureVerdict.Missing;

    public IReadOnlyDictionary<string, SignatureVerdict> VerifyMany(
        IReadOnlyCollection<string> paths, CancellationToken cancellationToken = default)
    {
        var results = new Dictionary<string, SignatureVerdict>(StringComparer.OrdinalIgnoreCase);
        var misses = new List<string>();

        foreach (var path in paths)
        {
            if (TryGetCached(path, out var verdict))
            {
                results[path] = verdict;
            }
            else
            {
                misses.Add(path);
            }
        }

        if (misses.Count > 0)
        {
            var fresh = _inner.VerifyMany(misses, cancellationToken);
            foreach (var path in misses)
            {
                var verdict = fresh.TryGetValue(path, out var v) ? v : SignatureVerdict.Missing;
                results[path] = verdict;
                Store(path, verdict);
            }
        }
        return results;
    }

    private bool TryGetCached(string path, out SignatureVerdict verdict)
    {
        verdict = default;
        var fingerprint = Fingerprint(path);
        if (fingerprint is null)
        {
            return false;
        }

        lock (_sync)
        {
            if (!_cache.TryGetValue(path, out var entry) ||
                entry.Fingerprint != fingerprint ||
                Stopwatch.GetElapsedTime(entry.CachedAtTimestamp) > _maxAge)
            {
                Remove(path, entry);
                return false;
            }

            _lru.Remove(entry.Node);
            _lru.AddLast(entry.Node);
            verdict = entry.Verdict;
            return true;
        }
    }

    private void Store(string path, SignatureVerdict verdict)
    {
        if (Fingerprint(path) is not { } fingerprint)
        {
            return;
        }

        lock (_sync)
        {
            if (_cache.TryGetValue(path, out var existing))
            {
                _lru.Remove(existing.Node);
                _cache.Remove(path);
            }
            while (_cache.Count >= _maxEntries && _lru.First is { } oldest)
            {
                _cache.Remove(oldest.Value);
                _lru.RemoveFirst();
            }

            var node = _lru.AddLast(path);
            _cache[path] = new CacheEntry(fingerprint, verdict, Stopwatch.GetTimestamp(), node);
        }
    }

    private void Remove(string path, CacheEntry? entry)
    {
        if (entry is null)
        {
            return;
        }
        _cache.Remove(path);
        _lru.Remove(entry.Node);
    }

    private static FileFingerprint? Fingerprint(string path)
    {
        try
        {
            if (!File.Exists(path))
            {
                return null;
            }
            var file = new FileInfo(path);
            return new FileFingerprint(file.Length, file.CreationTimeUtc, file.LastWriteTimeUtc);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private sealed record CacheEntry(
        FileFingerprint Fingerprint,
        SignatureVerdict Verdict,
        long CachedAtTimestamp,
        LinkedListNode<string> Node);

    private sealed record FileFingerprint(long Length, DateTime CreationTimeUtc, DateTime LastWriteTimeUtc);
}
