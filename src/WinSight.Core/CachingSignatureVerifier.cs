using System.Diagnostics;

namespace WinSight.Core;

/// <summary>
/// A caching decorator over any <see cref="ISignatureVerifier"/>. A file's verdict is
/// cached by path and file identity, so unchanged binaries are verified once when
/// several tools inspect them. Entries expire and the least-recently-used entry is
/// evicted at a fixed bound: a long-running dashboard cannot grow this cache without
/// limit or treat an old verdict as an authorization decision.
/// </summary>
/// <remarks>
/// <b>What "unchanged" means, exactly.</b> In the optional metadata-only mode a file is considered
/// unchanged when its length and both timestamps match. All three are attacker-controlled: timestomping
/// (MITRE T1070.006) is a single API call, so an attacker who replaces a signed binary with an
/// unsigned one of the same length and restores the timestamps is served the cached <i>trusted</i>
/// verdict until the entry expires. That window was undocumented, which was the real defect — a
/// trust core must state the bound it offers.
///
/// <b>Why metadata-only remains an explicit option.</b> Measured on this
/// machine over 300 System32 DLLs: an Authenticode verification costs 19.25 ms/file, a SHA-256 of
/// the content 1.64 ms/file, and the metadata fingerprint 0.052 ms/file. A single <c>modules</c> run
/// performs ~14 000 lookups over a few thousand distinct files, so hashing every lookup would add
/// roughly 23 s to a 57 s scan for a staleness window that closes when the process exits seconds
/// later. A long-lived host is the opposite case: it makes few lookups, and its verdicts sit on
/// screen next to security findings for as long as it runs.
///
/// Secure-by-default wins here: SHA-256 content identity is the default. A measured, short-lived
/// caller may explicitly pass <paramref name="verifyContent"/> <c>false</c> when the metadata-only
/// staleness window is acceptable. WinSight's own long-lived hosts never opt out.
/// </remarks>
public sealed class CachingSignatureVerifier : ISignatureVerifier
{
    private readonly ISignatureVerifier _inner;
    private readonly int _maxEntries;
    private readonly TimeSpan _maxAge;
    private readonly bool _verifyContent;
    private readonly object _sync = new();
    private readonly LinkedList<string> _lru = new();
    private readonly Dictionary<string, CacheEntry> _cache =
        new(StringComparer.OrdinalIgnoreCase);

    /// <param name="verifyContent">
    /// When true the cached verdict is bound to a SHA-256 of the file's content, so a replaced
    /// binary is never served a stale verdict however its timestamps are forged. Costs about
    /// 1.6 ms per lookup; use it in any process that outlives a single scan.
    /// </param>
    public CachingSignatureVerifier(
        ISignatureVerifier inner,
        int maxEntries = 4096,
        TimeSpan? maxAge = null,
        bool verifyContent = true)
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
        _verifyContent = verifyContent;
    }

    public SignatureVerdict Verify(string path, CancellationToken cancellationToken = default) =>
        VerifyMany([path], cancellationToken).TryGetValue(path, out var v) ? v : SignatureVerdict.Missing;

    public IReadOnlyDictionary<string, SignatureVerdict> VerifyMany(
        IReadOnlyCollection<string> paths, CancellationToken cancellationToken = default)
    {
        var results = new Dictionary<string, SignatureVerdict>(StringComparer.OrdinalIgnoreCase);
        var misses = new List<string>();
        var preVerificationFingerprints = new Dictionary<string, FileFingerprint?>(
            StringComparer.OrdinalIgnoreCase);

        foreach (var path in paths)
        {
            if (TryGetCached(path, out var verdict, out var observedFingerprint))
            {
                results[path] = verdict;
            }
            else
            {
                misses.Add(path);
                preVerificationFingerprints[path] = observedFingerprint;
            }
        }

        if (misses.Count > 0)
        {
            var fresh = _inner.VerifyMany(misses, cancellationToken);
            foreach (var path in misses)
            {
                var verdict = fresh.TryGetValue(path, out var v) ? v : SignatureVerdict.Missing;
                results[path] = verdict;
                StoreIfUnchanged(path, verdict, preVerificationFingerprints[path]);
            }
        }
        return results;
    }

    private bool TryGetCached(
        string path,
        out SignatureVerdict verdict,
        out FileFingerprint? observedFingerprint)
    {
        verdict = default;
        observedFingerprint = Fingerprint(path);
        if (observedFingerprint is null)
        {
            return false;
        }

        lock (_sync)
        {
            if (!_cache.TryGetValue(path, out var entry) ||
                entry.Fingerprint != observedFingerprint ||
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

    private void StoreIfUnchanged(
        string path,
        SignatureVerdict verdict,
        FileFingerprint? preVerificationFingerprint)
    {
        var postVerificationFingerprint = Fingerprint(path);
        // The verifier works on a path, so the file can be replaced after WinVerifyTrust returns
        // but before this cache entry is written. Never bind that old verdict to the replacement.
        // Metadata mode deliberately cannot detect a same-metadata swap; content mode can.
        if (preVerificationFingerprint is null ||
            postVerificationFingerprint is null ||
            preVerificationFingerprint != postVerificationFingerprint)
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
            _cache[path] = new CacheEntry(
                postVerificationFingerprint,
                verdict,
                Stopwatch.GetTimestamp(),
                node);
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

    private FileFingerprint? Fingerprint(string path)
    {
        try
        {
            if (!File.Exists(path))
            {
                return null;
            }
            var file = new FileInfo(path);
            // A null hash in content mode means the file could not be read: treat that as no
            // fingerprint at all rather than silently falling back to forgeable metadata, which
            // would reopen the exact window this mode exists to close.
            if (!_verifyContent)
            {
                return new FileFingerprint(file.Length, file.CreationTimeUtc, file.LastWriteTimeUtc, null);
            }
            return HashUtil.Sha256File(path) is { } hash
                ? new FileFingerprint(file.Length, file.CreationTimeUtc, file.LastWriteTimeUtc, hash)
                : null;
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

    /// <param name="ContentSha256">
    /// Null in metadata mode. When present it is what actually decides identity, so a same-length
    /// timestomped replacement no longer matches.
    /// </param>
    private sealed record FileFingerprint(
        long Length,
        DateTime CreationTimeUtc,
        DateTime LastWriteTimeUtc,
        string? ContentSha256);
}
