using System.Globalization;
using System.IO;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Threading;
using WinSight.Core;

namespace WinSight.Dashboard;

/// <summary>
/// Captures unhandled exceptions to a local file so a crash leaves evidence instead of vanishing.
/// Without this the dashboard dies silently: no message, no log, and nothing reliable in the Windows
/// event log either — which makes a user's "it crashed" impossible to act on.
/// </summary>
/// <remarks>
/// Local-only, like everything else here: reports are written to
/// <c>%LocalAppData%\WinSight\crashes</c> and never sent anywhere. They contain the exception, its
/// stack and the app version. Exception messages can contain local paths or the operation that
/// failed, so reports remain local; the optional VirusTotal credential is explicitly redacted.
/// </remarks>
public static class CrashReporter
{
    /// <summary>Keep the folder small; a crash loop must not fill the disk.</summary>
    internal const int MaxReports = 20;
    internal const int MaxReportCharacters = 256 * 1024;

    /// <summary>Where reports are written.</summary>
    public static string LogDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "WinSight",
        "crashes");

    /// <summary>Whether a UI-thread exception may be absorbed. See <see cref="DispatcherRecoveryPolicy"/>.</summary>
    internal static DispatcherRecoveryPolicy Recovery { get; } = new();

    /// <summary>
    /// Raised on the UI thread after an exception was absorbed, with the path of its report (null
    /// when the report could not be written), so the dashboard can say that it recovered.
    /// </summary>
    public static event Action<string?>? Recovered;

    /// <summary>
    /// Allows UI-thread exceptions to be absorbed from now on. The dashboard calls this once it has
    /// finished starting and its monitors are running; before that, and in the signature window and
    /// smoke test, an exception still terminates the process.
    /// </summary>
    public static void EnableRecovery() => Recovery.Arm();

    /// <summary>Hooks every channel an unhandled exception can arrive on.</summary>
    public static void Install(System.Windows.Application application)
    {
        ArgumentNullException.ThrowIfNull(application);

        // UI thread. Evidence is always captured. Once the dashboard is running, an exception that
        // does not compromise the process is absorbed so Guardian, ransomware protection and the
        // camera/microphone monitor keep running; otherwise WPF terminates it as before. The
        // independently installed firewall service keeps enforcement either way.
        application.DispatcherUnhandledException += OnDispatcherUnhandledException;

        // Background thread: the runtime is already tearing the process down, so this is the last
        // chance to write anything at all.
        AppDomain.CurrentDomain.UnhandledException += OnAppDomainUnhandledException;

        // A faulted Task nobody awaited — the usual way a background scan failure disappears.
        TaskScheduler.UnobservedTaskException += OnUnobservedTaskException;
    }

    private static void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        var recover = Recovery.ShouldRecover(e.Exception);
        var report = TryCapture(e.Exception, recover ? "Dispatcher (recovered)" : "Dispatcher");
        e.Handled = recover;
        if (!recover)
        {
            return;
        }
        try
        {
            Recovered?.Invoke(report);
        }
        catch (Exception ex) when (!DispatcherRecoveryPolicy.IsUnrecoverable(ex))
        {
            // Telling the operator is secondary to staying up; a failing notice must not undo the
            // recovery it announces.
        }
    }

    private static void OnAppDomainUnhandledException(object sender, UnhandledExceptionEventArgs e)
    {
        if (e.ExceptionObject is Exception exception)
        {
            TryCapture(exception, "AppDomain");
        }
    }

    private static void OnUnobservedTaskException(object? sender, UnobservedTaskExceptionEventArgs e)
    {
        TryCapture(e.Exception, "UnobservedTask");
        e.SetObserved();
    }

    /// <summary>
    /// Writes a report and returns its path, swallowing any failure (null) — reporting must never
    /// itself crash.
    /// </summary>
    internal static string? TryCapture(Exception exception, string source) =>
        TryCapture(exception, source, LogDirectory);

    /// <summary>
    /// Overload taking the target directory so tests never write into the real
    /// <see cref="LogDirectory"/> — a test must not leave files in the user's own application data.
    /// </summary>
    internal static string? TryCapture(Exception exception, string source, string directory)
    {
        try
        {
            var path = Write(directory, Format(exception, source, DateTimeOffset.Now));
            try
            {
                Prune(directory);
            }
            catch (Exception ex) when (IsReportingFailure(ex))
            {
                // The report is written; failing to tidy older ones must not lose its path.
            }
            return path;
        }
        catch (Exception ex) when (IsReportingFailure(ex))
        {
            return null;
        }
    }

    /// <summary>
    /// Deliberately broad: reporting runs while the app is already failing, so an invalid path or an
    /// unsupported target must not turn a recoverable crash into a second one. ArgumentException and
    /// NotSupportedException matter — a malformed directory raises those, not IOException.
    /// </summary>
    private static bool IsReportingFailure(Exception exception) =>
        exception is IOException
            or UnauthorizedAccessException
            or System.Security.SecurityException
            or ArgumentException
            or NotSupportedException;

    /// <summary>The report body. Pure, so its shape is unit-tested.</summary>
    internal static string Format(Exception exception, string source, DateTimeOffset when)
    {
        ArgumentNullException.ThrowIfNull(exception);
        var version = Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "unknown";
        var builder = new StringBuilder()
            .Append("WinSight crash report").AppendLine()
            .Append("time    : ").Append(when.ToString("O", CultureInfo.InvariantCulture)).AppendLine()
            .Append("version : ").Append(version).AppendLine()
            .Append("os      : ").Append(Environment.OSVersion.VersionString).AppendLine()
            .Append("source  : ").Append(source).AppendLine()
            .AppendLine()
            .Append(exception.ToString()).AppendLine();
        var report = builder.ToString();
        foreach (var secret in new[]
                 {
                     Environment.GetEnvironmentVariable(VirusTotalConfiguration.EnvironmentVariable),
                     VirusTotalConfiguration.CurrentApiKey,
                 }.Where(secret => !string.IsNullOrEmpty(secret)).Distinct(StringComparer.Ordinal))
        {
            report = report.Replace(secret!, "[REDACTED]", StringComparison.Ordinal);
        }
        return report.Length <= MaxReportCharacters
            ? report
            : report[..(MaxReportCharacters - 24)] + Environment.NewLine + "[report truncated]";
    }

    /// <summary>Writes one report and returns its path.</summary>
    internal static string Write(string directory, string content)
    {
        var path = Path.Combine(
            directory,
            $"crash-{DateTime.Now:yyyyMMdd-HHmmss}-{Guid.NewGuid():N}.log");
        if (!AutomaticFileAccess.TryCreateNewFile(
                path,
                Encoding.UTF8.GetBytes(content),
                createParentDirectories: true))
        {
            throw new IOException("The crash report could not be written safely.");
        }
        return path;
    }

    /// <summary>Keeps only the newest <see cref="MaxReports"/> reports.</summary>
    internal static void Prune(string directory)
    {
        if (!Directory.Exists(directory))
        {
            return;
        }
        var stale = Directory.GetFiles(directory, "crash-*.log")
            .OrderByDescending(File.GetLastWriteTimeUtc)
            .Skip(MaxReports);
        foreach (var file in stale)
        {
            try
            {
                _ = AutomaticFileAccess.TryDeleteFile(file);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
            }
        }
    }
}
