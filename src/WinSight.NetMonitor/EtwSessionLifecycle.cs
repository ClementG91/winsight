using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security;

using Microsoft.Diagnostics.Tracing.Session;

namespace WinSight.NetMonitor;

/// <summary>The three private ETW session families owned by WinSight.</summary>
internal enum EtwSessionProfile
{
    Attribution,
    Outbound,
    Dns,
}

/// <summary>
/// A stable, redacted reason why an observational ETW feature is unavailable.
/// </summary>
public enum EtwFailureCode
{
    None,
    AccessDenied,
    ResourceExhausted,
    SessionCollision,
    PlatformUnavailable,
    Unexpected,
}

/// <summary>Classifies ETW boundary failures without exposing native diagnostics.</summary>
public static class EtwFailure
{
    private const int ErrorNotEnoughMemory = 8;
    private const int ErrorOutOfMemory = 14;
    private const int ErrorAccessDenied = 5;
    private const int ErrorAlreadyExists = 183;
    private const int ErrorNoSystemResources = 1450;
    private const int ErrorNotEnoughQuota = 1816;

    /// <summary>
    /// Failures that must not be converted into an observational-feature status.
    /// </summary>
    public static bool IsCatastrophic(Exception exception) =>
        exception is OutOfMemoryException or StackOverflowException or AccessViolationException;

    /// <summary>Maps an exception to a bounded diagnostic classification.</summary>
    public static EtwFailureCode Classify(Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);

        return exception switch
        {
            UnauthorizedAccessException or SecurityException => EtwFailureCode.AccessDenied,
            COMException com when IsWin32(com.HResult, ErrorAccessDenied) =>
                EtwFailureCode.AccessDenied,
            Win32Exception win32 when win32.NativeErrorCode == ErrorAccessDenied =>
                EtwFailureCode.AccessDenied,
            PlatformNotSupportedException or NotSupportedException or DllNotFoundException
                or EntryPointNotFoundException => EtwFailureCode.PlatformUnavailable,
            COMException com when IsWin32(com.HResult, ErrorNoSystemResources)
                || IsWin32(com.HResult, ErrorNotEnoughMemory)
                || IsWin32(com.HResult, ErrorOutOfMemory)
                || IsWin32(com.HResult, ErrorNotEnoughQuota) => EtwFailureCode.ResourceExhausted,
            Win32Exception win32 when win32.NativeErrorCode is ErrorNoSystemResources
                or ErrorNotEnoughMemory or ErrorOutOfMemory or ErrorNotEnoughQuota =>
                EtwFailureCode.ResourceExhausted,
            COMException com when IsWin32(com.HResult, ErrorAlreadyExists) =>
                EtwFailureCode.SessionCollision,
            Win32Exception win32 when win32.NativeErrorCode == ErrorAlreadyExists =>
                EtwFailureCode.SessionCollision,
            _ => EtwFailureCode.Unexpected,
        };
    }

    /// <summary>A stable token suitable for CLI and service diagnostics.</summary>
    public static string Token(EtwFailureCode failure) => failure switch
    {
        EtwFailureCode.AccessDenied => "ETW_ACCESS_DENIED",
        EtwFailureCode.ResourceExhausted => "ETW_RESOURCE_EXHAUSTED",
        EtwFailureCode.SessionCollision => "ETW_SESSION_COLLISION",
        EtwFailureCode.PlatformUnavailable => "ETW_PLATFORM_UNAVAILABLE",
        EtwFailureCode.Unexpected => "ETW_UNEXPECTED_FAILURE",
        _ => "ETW_NONE",
    };

    private static bool IsWin32(int hresult, int error) =>
        hresult == unchecked((int)(0x80070000u | (uint)error));
}

/// <summary>Definitive or indeterminate ownership evidence for one PID.</summary>
internal enum EtwOwnerState
{
    Absent,
    Matches,
    Mismatch,
    Indeterminate,
}

/// <summary>Process identity operations isolated for deterministic lifecycle tests.</summary>
internal interface IEtwProcessIdentity
{
    int CurrentProcessId { get; }

    string CurrentStartIdentity { get; }

    EtwOwnerState Probe(int processId, string? expectedStartIdentity);
}

/// <summary>A minimal ETW session handle used by cleanup and creation.</summary>
internal interface IEtwSessionHandle : IDisposable
{
    TraceEventSession? NativeSession { get; }

    void Stop(bool noThrow);
}

/// <summary>Machine-wide ETW operations isolated for deterministic lifecycle tests.</summary>
internal interface IEtwSessionRuntime
{
    IReadOnlyCollection<string> GetActiveSessionNames();

    IEtwSessionHandle? Attach(string sessionName);

    IEtwSessionHandle Create(string sessionName, TraceEventSessionOptions options);
}

/// <summary>Observable result of an explicit orphan-stop attempt.</summary>
internal sealed record EtwCleanupResult(string SessionName, bool Disappeared);

/// <summary>
/// Conservatively reclaims proven WinSight orphans and creates one collision-safe private session.
/// </summary>
/// <remarks>
/// The profile is a closed enum rather than a caller-controlled prefix. A WinSight-looking name is
/// not cleanup authority: the grammar, PID and process-start identity all have to agree, twice,
/// around attachment. Cleanup is best effort because observation must not become a service or
/// dashboard availability dependency.
/// </remarks>
internal sealed class EtwSessionLifecycle
{
    private const string AttributionPrefix = "WinSight-Attribution-";
    private const string OutboundPrefix = "WinSight-Outbound-";
    private const string DnsPrefix = "WinSight-DNS-";
    private const string VersionMarker = "v2-";

    private static readonly EtwSessionLifecycle Shared =
        new(new TraceEventSessionRuntime(), new WindowsEtwProcessIdentity());

    private readonly IEtwSessionRuntime _runtime;
    private readonly IEtwProcessIdentity _processes;

    internal EtwSessionLifecycle(IEtwSessionRuntime runtime, IEtwProcessIdentity processes)
    {
        _runtime = runtime ?? throw new ArgumentNullException(nameof(runtime));
        _processes = processes ?? throw new ArgumentNullException(nameof(processes));
    }

    /// <summary>Opens the profile's native session after best-effort conservative cleanup.</summary>
    internal static TraceEventSession OpenNative(EtwSessionProfile profile)
    {
        var handle = Shared.Open(profile);
        return handle.NativeSession
            ?? throw new InvalidOperationException("The native ETW runtime returned no session.");
    }

    /// <summary>
    /// Opens a session handle. Internal and injectable so ordinary tests never touch the real ETW
    /// namespace.
    /// </summary>
    internal IEtwSessionHandle Open(EtwSessionProfile profile)
    {
        _ = ReclaimProvenOrphans(profile);
        var name = BuildCurrentName(profile);
        return _runtime.Create(
            name,
            TraceEventSessionOptions.Create | TraceEventSessionOptions.NoRestartOnCreate);
    }

    internal string BuildCurrentName(EtwSessionProfile profile) =>
        string.Create(
            CultureInfo.InvariantCulture,
            $"{Prefix(profile)}{VersionMarker}{_processes.CurrentProcessId}-{_processes.CurrentStartIdentity}");

    internal IReadOnlyList<EtwCleanupResult> ReclaimProvenOrphans(EtwSessionProfile profile)
    {
        var results = new List<EtwCleanupResult>();
        IReadOnlyCollection<string> active;
        try
        {
            active = _runtime.GetActiveSessionNames();
        }
        catch (Exception ex) when (!EtwFailure.IsCatastrophic(ex))
        {
            return results;
        }

        foreach (var name in active)
        {
            if (!TryParse(profile, name, out var owner))
            {
                continue;
            }
            if ((owner.IsLegacy && owner.ProcessId == _processes.CurrentProcessId)
                || (!owner.IsLegacy
                    && owner.ProcessId == _processes.CurrentProcessId
                    && string.Equals(
                        owner.StartIdentity,
                        _processes.CurrentStartIdentity,
                        StringComparison.Ordinal))
                || !IsDefiniteOrphan(owner))
            {
                continue;
            }

            IEtwSessionHandle? attached;
            try
            {
                attached = _runtime.Attach(name);
            }
            catch (Exception ex) when (!EtwFailure.IsCatastrophic(ex))
            {
                continue;
            }
            if (attached is null)
            {
                continue;
            }

            using (attached)
            {
                if (!IsDefiniteOrphan(owner))
                {
                    continue;
                }
                try
                {
                    attached.Stop(noThrow: true);
                    // Disposal of an attached TraceEventSession is not stop evidence. Force a
                    // second machine-wide enumeration so disappearance is actually observed.
                    var disappeared =
                        !_runtime.GetActiveSessionNames().Contains(name, StringComparer.Ordinal);
                    results.Add(new EtwCleanupResult(name, disappeared));
                }
                catch (Exception ex) when (!EtwFailure.IsCatastrophic(ex))
                {
                    // A cleanup race or access failure preserves availability. No broader session
                    // is ever targeted as a fallback.
                    results.Add(new EtwCleanupResult(name, Disappeared: false));
                }
            }
        }

        return results;
    }

    private bool IsDefiniteOrphan(ParsedOwner owner)
    {
        var state = _processes.Probe(owner.ProcessId, owner.StartIdentity);
        return owner.IsLegacy
            ? state == EtwOwnerState.Absent
            : state is EtwOwnerState.Absent or EtwOwnerState.Mismatch;
    }

    private static bool TryParse(EtwSessionProfile profile, string? name, out ParsedOwner owner)
    {
        owner = default;
        if (name is null)
        {
            return false;
        }

        var prefix = Prefix(profile);
        if (!name.StartsWith(prefix, StringComparison.Ordinal))
        {
            return false;
        }

        var suffix = name[prefix.Length..];
        if (TryParsePositivePid(suffix, out var legacyPid))
        {
            owner = new ParsedOwner(legacyPid, null, IsLegacy: true);
            return true;
        }
        if (!suffix.StartsWith(VersionMarker, StringComparison.Ordinal))
        {
            return false;
        }

        var identity = suffix[VersionMarker.Length..];
        var separator = identity.IndexOf('-');
        if (separator <= 0 || separator == identity.Length - 1
            || identity.IndexOf('-', separator + 1) >= 0
            || !TryParsePositivePid(identity[..separator], out var pid)
            || !IsStartIdentity(identity[(separator + 1)..]))
        {
            return false;
        }

        owner = new ParsedOwner(pid, identity[(separator + 1)..], IsLegacy: false);
        return true;
    }

    private static bool TryParsePositivePid(string value, out int processId)
    {
        processId = 0;
        return value.Length > 0
            && value.All(static character => character is >= '0' and <= '9')
            && int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out processId)
            && processId > 0;
    }

    private static bool IsStartIdentity(string value) =>
        value.Length == 16 && value.All(static character =>
            character is >= '0' and <= '9'
            or >= 'A' and <= 'F');

    private static string Prefix(EtwSessionProfile profile) => profile switch
    {
        EtwSessionProfile.Attribution => AttributionPrefix,
        EtwSessionProfile.Outbound => OutboundPrefix,
        EtwSessionProfile.Dns => DnsPrefix,
        _ => throw new ArgumentOutOfRangeException(nameof(profile)),
    };

    private readonly record struct ParsedOwner(int ProcessId, string? StartIdentity, bool IsLegacy);
}

internal sealed class WindowsEtwProcessIdentity : IEtwProcessIdentity
{
    public int CurrentProcessId => Environment.ProcessId;

    public string CurrentStartIdentity
    {
        get
        {
            using var current = Process.GetCurrentProcess();
            return FormatStartIdentity(current.StartTime);
        }
    }

    public EtwOwnerState Probe(int processId, string? expectedStartIdentity)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            if (process.HasExited)
            {
                return EtwOwnerState.Absent;
            }
            if (expectedStartIdentity is null)
            {
                return EtwOwnerState.Matches;
            }

            var actual = FormatStartIdentity(process.StartTime);
            return string.Equals(actual, expectedStartIdentity, StringComparison.Ordinal)
                ? EtwOwnerState.Matches
                : EtwOwnerState.Mismatch;
        }
        catch (ArgumentException)
        {
            return EtwOwnerState.Absent;
        }
        catch (Exception ex) when (ex is InvalidOperationException or Win32Exception
                                   or NotSupportedException or PlatformNotSupportedException)
        {
            return EtwOwnerState.Indeterminate;
        }
    }

    private static string FormatStartIdentity(DateTime startTime) =>
        startTime.ToUniversalTime().Ticks.ToString("X16", CultureInfo.InvariantCulture);
}

internal sealed class TraceEventSessionRuntime : IEtwSessionRuntime
{
    public IReadOnlyCollection<string> GetActiveSessionNames() =>
        TraceEventSession.GetActiveSessionNames();

    public IEtwSessionHandle? Attach(string sessionName)
    {
        var session = TraceEventSession.GetActiveSession(sessionName);
        return session is null ? null : new TraceEventSessionHandle(session);
    }

    public IEtwSessionHandle Create(string sessionName, TraceEventSessionOptions options) =>
        new TraceEventSessionHandle(new TraceEventSession(sessionName, options));
}

internal sealed class TraceEventSessionHandle(TraceEventSession session) : IEtwSessionHandle
{
    private readonly TraceEventSession _session =
        session ?? throw new ArgumentNullException(nameof(session));

    public TraceEventSession NativeSession => _session;

    public void Stop(bool noThrow) => _session.Stop(noThrow);

    public void Dispose() => _session.Dispose();
}
