using System.Management;
using System.Runtime.InteropServices;

namespace WinSight.Ransomware;

/// <summary>Reads the local Defender CFA posture without changing Defender configuration.</summary>
public sealed class ControlledFolderAccessReader
{
    /// <summary>The Windows Security page where an operator can review CFA themselves.</summary>
    public const string SettingsDeepLink = "windowsdefender://RansomwareProtection";

    private readonly IControlledFolderAccessDataSource _dataSource;

    public ControlledFolderAccessReader()
        : this(new WmiControlledFolderAccessDataSource())
    {
    }

    /// <summary>Internal composition seam for deterministic tests and host-independent callers.</summary>
    internal ControlledFolderAccessReader(IControlledFolderAccessDataSource dataSource)
    {
        _dataSource = dataSource ?? throw new ArgumentNullException(nameof(dataSource));
    }

    /// <summary>
    /// Reads the configured CFA mode and its Defender runtime evidence. Provider failures degrade to
    /// a notable unavailable posture; caller-requested cancellation always propagates.
    /// </summary>
    public ControlledFolderAccessPosture Read(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            var snapshot = _dataSource.Read(cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            return ToPosture(snapshot);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            return Unavailable();
        }
        catch (Exception ex) when (ex is ManagementException
                                     or UnauthorizedAccessException
                                     or COMException
                                     or TimeoutException
                                     or InvalidOperationException
                                     or ArgumentException)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Unavailable();
        }
    }

    internal static ControlledFolderAccessPosture ToPosture(ControlledFolderAccessWmiSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        if (snapshot.Preference is null || snapshot.Runtime is null
            || ToInt(snapshot.Preference.EnableControlledFolderAccess) is not { } rawState
            || ToRuntimeEvidence(snapshot.Runtime) is not
            {
                IsComplete: true,
                IsRecognizedRunningMode: true,
            } runtimeEvidence)
        {
            return Unavailable();
        }

        var state = ControlledFolderAccessTriage.StateFromValue(rawState);
        if (state == ControlledFolderAccessState.Unavailable)
        {
            return Unavailable(rawState);
        }

        if (!TryToStrings(snapshot.Preference.ProtectedFolders, out var protectedFolders))
        {
            return Unavailable(rawState);
        }
        if (protectedFolders.Any(entry => !LooksLikeApplicationPath(entry)))
        {
            return Unavailable(rawState);
        }
        var allowedApplications = ToAllowedApplications(snapshot.Preference.AllowedApplications);
        if (allowedApplications.Visibility == AllowedApplicationsVisibility.Unavailable)
        {
            return Unavailable(rawState);
        }
        var concern = ControlledFolderAccessTriage.Concern(state, runtimeEvidence);
        return new ControlledFolderAccessPosture(
            state,
            runtimeEvidence,
            protectedFolders,
            allowedApplications,
            concern)
        {
            RawStateValue = rawState,
        };
    }

    private static ControlledFolderAccessPosture Unavailable(int? rawStateValue = null) => new(
        ControlledFolderAccessState.Unavailable,
        new DefenderRuntimeEvidence(null, null, null),
        [],
        AllowedApplications.Unavailable,
        ControlledFolderAccessConcern.Unavailable)
    {
        RawStateValue = rawStateValue,
    };

    private static DefenderRuntimeEvidence ToRuntimeEvidence(ControlledFolderAccessRawRuntime runtime) => new(
        runtime.AMRunningMode as string,
        ToBool(runtime.AntivirusEnabled),
        ToBool(runtime.RealTimeProtectionEnabled));

    private static int? ToInt(object? value) => value switch
    {
        byte number => number,
        sbyte number => number,
        short number => number,
        ushort number => number,
        int number => number,
        uint number when number <= int.MaxValue => (int)number,
        long number when number is >= int.MinValue and <= int.MaxValue => (int)number,
        ulong number when number <= int.MaxValue => (int)number,
        _ => null,
    };

    private static bool? ToBool(object? value) => value is bool result ? result : null;

    private static bool TryToStrings(object? value, out string[] items)
    {
        switch (value)
        {
            case string[] many:
                if (many.Any(string.IsNullOrWhiteSpace))
                {
                    items = [];
                    return false;
                }
                items = many;
                return true;
            case string one when !string.IsNullOrWhiteSpace(one):
                items = [one];
                return true;
            case null:
                items = [];
                return true;
            default:
                items = [];
                return false;
        }
    }

    private static AllowedApplications ToAllowedApplications(object? value)
    {
        const string elevationSentinel = "N/A: Must be an administrator to view exclusions";
        string[] items;
        switch (value)
        {
            case null:
                return AllowedApplications.None;
            case string[] many:
                items = many;
                break;
            case string one:
                items = [one];
                break;
            default:
                return AllowedApplications.Unavailable;
        }
        if (items.Any(string.IsNullOrWhiteSpace))
        {
            return AllowedApplications.Unavailable;
        }
        if (items.Length == 1
            && string.Equals(items[0], elevationSentinel, StringComparison.OrdinalIgnoreCase))
        {
            return new AllowedApplications(AllowedApplicationsVisibility.RequiresElevation, []);
        }
        if (items.Any(entry => !LooksLikeApplicationPath(entry)))
        {
            return AllowedApplications.Unavailable;
        }
        return items.Length == 0
            ? AllowedApplications.None
            : new AllowedApplications(AllowedApplicationsVisibility.Visible, items);
    }

    private static bool LooksLikeApplicationPath(string value) =>
        Path.IsPathFullyQualified(value)
        || (value.StartsWith('%') && value.IndexOf('%', 1) >= 0);
}

/// <summary>Internal, injectable raw WMI acquisition seam.</summary>
internal interface IControlledFolderAccessDataSource
{
    ControlledFolderAccessWmiSnapshot Read(CancellationToken cancellationToken);
}

/// <summary>Raw, un-interpreted rows from the two Defender WMI classes.</summary>
internal sealed record ControlledFolderAccessWmiSnapshot(
    ControlledFolderAccessRawPreference? Preference,
    ControlledFolderAccessRawRuntime? Runtime);

internal sealed record ControlledFolderAccessRawPreference(
    object? EnableControlledFolderAccess,
    object? ProtectedFolders,
    object? AllowedApplications);

internal sealed record ControlledFolderAccessRawRuntime(
    object? AMRunningMode,
    object? AntivirusEnabled,
    object? RealTimeProtectionEnabled);

internal sealed class WmiControlledFolderAccessDataSource : IControlledFolderAccessDataSource
{
    private const string DefenderScope = @"\\.\root\Microsoft\Windows\Defender";
    private static readonly TimeSpan QueryTimeout = TimeSpan.FromSeconds(5);

    public ControlledFolderAccessWmiSnapshot Read(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var scope = new ManagementScope(DefenderScope);
        var preference = ReadPreference(scope, cancellationToken);
        var runtime = ReadRuntime(scope, cancellationToken);
        return new ControlledFolderAccessWmiSnapshot(preference, runtime);
    }

    private static ControlledFolderAccessRawPreference? ReadPreference(
        ManagementScope scope, CancellationToken cancellationToken)
    {
        using var searcher = CreateSearcher(
            scope,
            "SELECT EnableControlledFolderAccess, ControlledFolderAccessProtectedFolders, "
            + "ControlledFolderAccessAllowedApplications FROM MSFT_MpPreference");
        foreach (ManagementBaseObject row in searcher.Get())
        {
            using (row)
            {
                cancellationToken.ThrowIfCancellationRequested();
                return new ControlledFolderAccessRawPreference(
                    row["EnableControlledFolderAccess"],
                    row["ControlledFolderAccessProtectedFolders"],
                    row["ControlledFolderAccessAllowedApplications"]);
            }
        }
        return null;
    }

    private static ControlledFolderAccessRawRuntime? ReadRuntime(
        ManagementScope scope, CancellationToken cancellationToken)
    {
        using var searcher = CreateSearcher(
            scope,
            "SELECT AMRunningMode, AntivirusEnabled, RealTimeProtectionEnabled FROM MSFT_MpComputerStatus");
        foreach (ManagementBaseObject row in searcher.Get())
        {
            using (row)
            {
                cancellationToken.ThrowIfCancellationRequested();
                return new ControlledFolderAccessRawRuntime(
                    row["AMRunningMode"],
                    row["AntivirusEnabled"],
                    row["RealTimeProtectionEnabled"]);
            }
        }
        return null;
    }

    private static ManagementObjectSearcher CreateSearcher(ManagementScope scope, string query) => new(
        scope,
        new ObjectQuery(query),
        new System.Management.EnumerationOptions
        {
            Timeout = QueryTimeout,
            ReturnImmediately = false,
            Rewindable = false,
        });
}
