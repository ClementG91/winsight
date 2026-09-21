using System.Runtime.InteropServices;

namespace WinSight.Dashboard;

/// <summary>
/// Decides whether an exception that reached the UI thread unhandled may be absorbed, so the process
/// - and the real-time monitors it hosts - keeps running.
/// </summary>
/// <remarks>
/// <b>Why absorb anything.</b> The dashboard is also where Guardian, ransomware protection and the
/// camera/microphone monitor run. Letting WPF terminate on every unhandled UI exception meant a bug
/// in one button handler switched all real-time protection off without a word: no alert, and the
/// tray icon simply gone.
///
/// <b>What is never absorbed.</b> Anything before the dashboard finished starting, since a half-built
/// window is not worth keeping. Exceptions meaning the process itself cannot be trusted to continue -
/// memory or stack exhaustion, corrupted state, a type that failed to initialise, a broken
/// deployment. And a crash loop: past <c>maxRecoveries</c> in one <c>window</c> the fault is not
/// transient, and terminating with a report is more honest than a window failing on every repaint.
/// </remarks>
internal sealed class DispatcherRecoveryPolicy(
    int maxRecoveries = 3,
    TimeSpan? window = null,
    Func<DateTimeOffset>? clock = null)
{
    private const int MaxInnerDepth = 8;

    private readonly TimeSpan _window = window ?? TimeSpan.FromMinutes(1);
    private readonly Func<DateTimeOffset> _clock = clock ?? (() => DateTimeOffset.UtcNow);
    private readonly Queue<DateTimeOffset> _recent = new();
    private readonly Lock _gate = new();
    private bool _armed;

    /// <summary>Allows recovery from now on. Called once the dashboard has finished starting.</summary>
    public void Arm()
    {
        lock (_gate)
        {
            _armed = true;
        }
    }

    /// <summary>
    /// Whether <paramref name="exception"/> may be absorbed. A true answer is counted against the
    /// recovery budget; the caller must then actually absorb it.
    /// </summary>
    public bool ShouldRecover(Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);
        lock (_gate)
        {
            if (!_armed || IsUnrecoverable(exception))
            {
                return false;
            }
            var now = _clock();
            while (_recent.Count > 0 && now - _recent.Peek() >= _window)
            {
                _recent.Dequeue();
            }
            if (_recent.Count >= maxRecoveries)
            {
                return false;
            }
            _recent.Enqueue(now);
            return true;
        }
    }

    /// <summary>
    /// True when the exception, or any exception wrapped inside it, means the process cannot be
    /// trusted to continue.
    /// </summary>
    internal static bool IsUnrecoverable(Exception exception) =>
        Flatten(exception, 0).Any(inner => inner
            is OutOfMemoryException
            or InsufficientExecutionStackException
            or StackOverflowException
            or AccessViolationException
            or SEHException
            or InvalidProgramException
            or BadImageFormatException
            or TypeLoadException
            or TypeInitializationException
            or MissingMemberException
            or DllNotFoundException
            or EntryPointNotFoundException);

    private static IEnumerable<Exception> Flatten(Exception exception, int depth)
    {
        yield return exception;
        if (depth >= MaxInnerDepth)
        {
            yield break;
        }
        IReadOnlyCollection<Exception> inner = exception switch
        {
            AggregateException aggregate => aggregate.InnerExceptions,
            { InnerException: { } wrapped } => [wrapped],
            _ => [],
        };
        foreach (var child in inner)
        {
            foreach (var nested in Flatten(child, depth + 1))
            {
                yield return nested;
            }
        }
    }
}
