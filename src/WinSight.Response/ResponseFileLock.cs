using System.Diagnostics;

using WinSight.Core;

namespace WinSight.Response;

/// <summary>Persistent per-user file coordination, independent of named kernel object namespaces.</summary>
internal sealed class ResponseFileLock : IDisposable
{
    private readonly AutomaticFileAccess.LocalFileLock? _lock;
    private readonly AutomaticFileAccess.LocalPathLease? _legacy;
    private readonly string? _legacyPath;

    private ResponseFileLock(AutomaticFileAccess.LocalFileLock? gate,
        AutomaticFileAccess.LocalPathLease? legacy = null, string? legacyPath = null)
    {
        _lock = gate;
        _legacy = legacy;
        _legacyPath = legacyPath;
    }

    internal static string PathFor(string path) => Path.GetFullPath(path) + ".lock";

    internal static ResponseFileLock AcquireWriter(string path, TimeSpan wait)
    {
        var lockPath = PathFor(path);
        var timer = Stopwatch.StartNew();
        while (true)
        {
            var gate = AutomaticFileAccess.TryAcquireExclusiveLockFile(lockPath, out var status);
            if (gate is not null)
            {
                return new(gate);
            }
            WaitOrThrow(status, timer, wait);
        }
    }

    internal static ResponseFileLock AcquireReader(string path, TimeSpan wait)
    {
        var lockPath = PathFor(path);
        var timer = Stopwatch.StartNew();
        while (true)
        {
            var gate = AutomaticFileAccess.TryAcquireExistingLockFile(lockPath, out var status);
            if (gate is not null)
            {
                if (status == LocalFileLockStatus.Missing)
                {
                    return AcquireLegacyRead(path, lockPath, gate);
                }
                return new(gate);
            }
            if (status == LocalFileLockStatus.Missing)
            {
                return AcquireLegacyRead(path, lockPath, null);
            }
            WaitOrThrow(status, timer, wait);
        }
    }

    private static ResponseFileLock AcquireLegacyRead(string path, string lockPath,
        AutomaticFileAccess.LocalFileLock? gate)
    {
        var legacy = AutomaticFileAccess.TryAcquireStableRead(path, out var missing);
        if (legacy is not { IsDirectory: false, DataIsLocal: true } && !missing)
        {
            legacy?.Dispose();
            gate?.Dispose();
            // The DATA path, rather than its coordination sidecar, is unavailable.
            throw new IOException("Legacy response state could not be read safely.");
        }
        if (SidecarMissing(lockPath))
        {
            return new(gate, legacy, lockPath);
        }
        legacy?.Dispose();
        gate?.Dispose();
        throw new ResponseFileLockException(LocalFileLockStatus.Unavailable);
    }

    private static void WaitOrThrow(LocalFileLockStatus status, Stopwatch timer, TimeSpan wait)
    {
        if (status != LocalFileLockStatus.Busy || timer.Elapsed >= wait)
        {
            throw new ResponseFileLockException(status);
        }
        Thread.Sleep(TimeSpan.FromMilliseconds(Math.Max(1, Math.Min(10, (wait - timer.Elapsed).TotalMilliseconds))));
    }

    // Existing parents are held by the bootstrap gate. For an absent parent the final absence
    // check also detects a first writer arriving during a missing-state read.
    internal bool IsCurrent => _legacyPath is null
        || SidecarMissing(_legacyPath) && (_legacy is null || _legacy.IsCurrent());

    private static bool SidecarMissing(string path)
    {
        using var lease = AutomaticFileAccess.TryAcquire(path, out var missing);
        return lease is null && missing;
    }

    public void Dispose()
    {
        _legacy?.Dispose();
        _lock?.Dispose();
    }
}

internal sealed class ResponseFileLockException(LocalFileLockStatus status) : IOException
{
    internal LocalFileLockStatus Status { get; } = status;
}
