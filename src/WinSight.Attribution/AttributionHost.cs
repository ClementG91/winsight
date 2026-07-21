using System.Security.Principal;

namespace WinSight.Attribution;

/// <summary>What the watcher has managed to see, so its blind spots are readable.</summary>
/// <remarks>
/// The two unresolved counters are kept apart on purpose. They look identical from the outside —
/// both are a write nobody could name — but they have different causes and different fixes: an
/// unannounced key handle is a gap in the kernel's own bookkeeping replay, while an untranslatable
/// path is a gap in WinSight's namespace mapping. Merged into one number, neither can be
/// investigated; the first live run of this host reported 114 unresolved against 2 attributed, and
/// that number was useless until it could be split.
/// </remarks>
/// <param name="Running">Whether a watch is currently active.</param>
/// <param name="Attributed">Writes seen and pinned on a process.</param>
/// <param name="UnknownProcess">Writes seen whose writer was not in the process index.</param>
/// <param name="UnannouncedKey">
/// Writes on a key handle the kernel never announced — typically a key already open when the
/// session started.
/// </param>
/// <param name="UntranslatablePath">
/// Writes whose key resolved to a kernel path WinSight could not translate into a form an operator
/// would recognise.
/// </param>
/// <param name="Refused">
/// True when the watch could not start because the process is not elevated. Distinct from "running
/// and seeing nothing", which is the confusion this whole type exists to prevent.
/// </param>
public sealed record AttributionHealth(
    bool Running,
    long Attributed,
    long UnknownProcess,
    long UnannouncedKey,
    long UntranslatablePath,
    bool Refused)
{
    /// <summary>Every write seen but not attributed, for a one-line "how blind am I?" answer.</summary>
    public long Unattributed => UnknownProcess + UnannouncedKey + UntranslatablePath;
}

/// <summary>
/// Joins the watcher to the correlation index: runs the trace session for as long as it is wanted,
/// records what it sees, and answers "who wrote this?" when a detection asks.
/// </summary>
/// <remarks>
/// The two halves were built and tested separately — a pure index that remembers writes, and a
/// session that observes them — and this is the seam between them. Keeping it small and explicit
/// means the correlation rules stay unit-testable while the privileged part stays a thin edge.
///
/// <b>It reports its own health on purpose.</b> Attribution can be unavailable (not elevated),
/// running and blind (a key handle the kernel never announced), or working. Those are three very
/// different things to tell an operator, and collapsing them into "no answer" is how a monitor
/// gets trusted when it should not be.
/// </remarks>
public sealed class AttributionHost : IDisposable
{
    /// <summary>How long <see cref="Dispose"/> waits for the watch to unwind before giving up.</summary>
    private static readonly TimeSpan StopTimeout = TimeSpan.FromSeconds(5);

    private readonly IWriteWatcher _watcher;
    private readonly WriteAttributionIndex _index;
    private readonly Lock _gate = new();
    private CancellationTokenSource? _cancellation;
    private Task? _worker;
    private bool _disposed;
    private long _attributed;
    private long _unknownProcess;
    private long _unannouncedKey;
    private long _untranslatablePath;
    private bool _refused;
    private bool _running;

    public AttributionHost(IWriteWatcher? watcher = null, WriteAttributionIndex? index = null)
    {
        _watcher = watcher ?? new WriteAttributionWatcher();
        _index = index ?? new WriteAttributionIndex();
    }

    /// <summary>Whether this process could open a kernel trace session at all.</summary>
    public static bool IsElevated()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    public AttributionHealth Health
    {
        get
        {
            lock (_gate)
            {
                return new AttributionHealth(
                    _running,
                    Interlocked.Read(ref _attributed),
                    Interlocked.Read(ref _unknownProcess),
                    Interlocked.Read(ref _unannouncedKey),
                    Interlocked.Read(ref _untranslatablePath),
                    _refused);
            }
        }
    }

    /// <summary>Begins watching. Safe to call twice; the second call does nothing.</summary>
    public void Start()
    {
        CancellationToken token;
        lock (_gate)
        {
            if (_disposed || _cancellation is not null)
            {
                return;
            }
            _cancellation = new CancellationTokenSource();
            _running = true;
            _refused = false;
            token = _cancellation.Token;
        }

        // The session blocks its thread until stopped, so it cannot run on the caller's.
        var worker = Task.Run(
            () =>
            {
                var refused = false;
                try
                {
                    _watcher.Watch(OnWrite, OnUnattributed, token);
                }
                catch (OperationCanceledException)
                {
                    // Normal shutdown.
                }
                catch (UnauthorizedAccessException)
                {
                    // Not elevated. Recorded as a refusal rather than silence, so a caller can say
                    // "attribution is unavailable" instead of "nothing was written".
                    refused = true;
                }
                finally
                {
                    // Both under one lock: a reader that sees the refusal must never also see a
                    // watch still claiming to run.
                    lock (_gate)
                    {
                        _refused = refused;
                        _running = false;
                    }
                }
            },
            CancellationToken.None);

        lock (_gate)
        {
            _worker = worker;
        }
    }

    /// <summary>
    /// The write that best explains a detection on <paramref name="target"/>, or null when nothing
    /// observed accounts for it. Null is a normal answer — see <see cref="Health"/> for whether it
    /// means "nothing wrote this" or "attribution was not watching".
    /// </summary>
    public WriteObservation? Attribute(string? target, DateTimeOffset detectedAtUtc) =>
        _index.Attribute(target, detectedAtUtc);

    /// <summary>
    /// Stops the watch and waits for it to unwind, so the trace session is closed by the time this
    /// returns rather than at some later garbage-collection.
    /// </summary>
    public void Dispose()
    {
        CancellationTokenSource? cancellation;
        Task? worker;
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }
            _disposed = true;
            cancellation = _cancellation;
            worker = _worker;
            _cancellation = null;
            _worker = null;
        }

        if (cancellation is null)
        {
            return;
        }

        cancellation.Cancel();
        // Waiting before disposing the source matters: the watch is blocked on this token's wait
        // handle, and disposing it out from under that thread is how a clean shutdown turns into an
        // ObjectDisposedException on a background thread nobody is watching.
        worker?.Wait(StopTimeout);
        cancellation.Dispose();
    }

    private void OnWrite(WriteObservation observation)
    {
        Interlocked.Increment(ref _attributed);
        _index.Record(observation);
        // Pruning here rather than on a timer keeps the index bounded by the same traffic that
        // fills it, with no extra thread to own.
        _index.Prune(observation.WhenUtc);
    }

    private void OnUnattributed(UnattributedWrite miss)
    {
        if (miss.Reason == UnattributedReason.UnknownProcess)
        {
            Interlocked.Increment(ref _unknownProcess);
        }
        // The watcher already draws the distinction the counters need, in the only way it can: it
        // carries the kernel's own spelling through when a key resolved but would not translate, and
        // nothing at all when the handle was never announced in the first place.
        else if (miss.Target is null)
        {
            Interlocked.Increment(ref _unannouncedKey);
        }
        else
        {
            Interlocked.Increment(ref _untranslatablePath);
        }
    }
}
