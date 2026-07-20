using System.Globalization;
using System.IO;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Threading;

namespace WinSight.Dashboard;

/// <summary>
/// Captures unhandled exceptions to a local file so a crash leaves evidence instead of vanishing.
/// Without this the dashboard dies silently: no message, no log, and nothing reliable in the Windows
/// event log either — which makes a user's "it crashed" impossible to act on.
/// </summary>
/// <remarks>
/// Local-only, like everything else here: reports are written to
/// <c>%LocalAppData%\WinSight\crashes</c> and never sent anywhere. They contain the exception, its
/// stack and the app version — no scan results, no file inventory, nothing about what was found.
/// </remarks>
public static class CrashReporter
{
    /// <summary>Keep the folder small; a crash loop must not fill the disk.</summary>
    internal const int MaxReports = 20;

    /// <summary>Where reports are written.</summary>
    public static string LogDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "WinSight",
        "crashes");

    /// <summary>Hooks every channel an unhandled exception can arrive on.</summary>
    public static void Install(System.Windows.Application application)
    {
        ArgumentNullException.ThrowIfNull(application);

        // UI thread. The app is still coherent enough to keep running, and for a monitoring tool
        // staying alive preserves protection — so the exception is recorded and swallowed rather
        // than taking the process (and Guardian with it) down.
        application.DispatcherUnhandledException += OnDispatcherUnhandledException;

        // Background thread: the runtime is already tearing the process down, so this is the last
        // chance to write anything at all.
        AppDomain.CurrentDomain.UnhandledException += OnAppDomainUnhandledException;

        // A faulted Task nobody awaited — the usual way a background scan failure disappears.
        TaskScheduler.UnobservedTaskException += OnUnobservedTaskException;
    }

    private static void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        TryCapture(e.Exception, "Dispatcher");
        e.Handled = true;
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

    /// <summary>Writes a report, swallowing any failure — reporting must never itself crash.</summary>
    internal static void TryCapture(Exception exception, string source) =>
        TryCapture(exception, source, LogDirectory);

    /// <summary>
    /// Overload taking the target directory so tests never write into the real
    /// <see cref="LogDirectory"/> — a test must not leave files in the user's own application data.
    /// </summary>
    internal static void TryCapture(Exception exception, string source, string directory)
    {
        try
        {
            Write(directory, Format(exception, source, DateTimeOffset.Now));
            Prune(directory);
        }
        // Deliberately broad: this runs while the app is already failing, so an invalid path or an
        // unsupported target must not turn a recoverable crash into a second one. ArgumentException
        // and NotSupportedException matter — a malformed directory raises those, not IOException.
        catch (Exception ex) when (ex is IOException
                                     or UnauthorizedAccessException
                                     or System.Security.SecurityException
                                     or ArgumentException
                                     or NotSupportedException)
        {
        }
    }

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
        return builder.ToString();
    }

    /// <summary>Writes one report and returns its path.</summary>
    internal static string Write(string directory, string content)
    {
        Directory.CreateDirectory(directory);
        var path = Path.Combine(
            directory,
            $"crash-{DateTime.Now:yyyyMMdd-HHmmss}-{Guid.NewGuid():N}.log");
        File.WriteAllText(path, content, Encoding.UTF8);
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
                File.Delete(file);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
            }
        }
    }
}
