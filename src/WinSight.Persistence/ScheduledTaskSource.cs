using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;

namespace WinSight.Persistence;

/// <summary>One registered scheduled task: its full path and its definition XML.</summary>
/// <param name="Path">The task's full name, e.g. <c>\Microsoft\Windows\UpdateOrchestrator\Foo</c>.</param>
/// <param name="Xml">The task definition, in the same schema as the files under \System32\Tasks.</param>
public readonly record struct ScheduledTaskDefinition(string Path, string Xml);

/// <summary>Where registered scheduled tasks are read from.</summary>
/// <remarks>
/// A seam, so the enumerator above it is testable without COM and without the machine's real task
/// set — the same reasoning as the capture-device reader and the write watcher.
/// </remarks>
public interface IScheduledTaskSource
{
    /// <summary>Every task the caller is allowed to see. Never throws; an unreachable source
    /// yields nothing and says so through <see cref="Unreadable"/>.</summary>
    IEnumerable<ScheduledTaskDefinition> Enumerate();

    /// <summary>True when the source could not be read at all, so an empty result is not "no tasks".</summary>
    bool Unreadable { get; }
}

/// <summary>
/// Reads scheduled tasks through the Task Scheduler service itself.
/// </summary>
/// <remarks>
/// <b>Why this replaced reading the files.</b> The previous source parsed the XML files under
/// <c>%SystemRoot%\System32\Tasks</c>, chosen to avoid a COM dependency. That directory is
/// readable only by administrators, and <see cref="Directory.GetFiles(string, string, SearchOption)"/>
/// does not skip what it cannot enumerate — it throws for the whole tree. The failure was caught and
/// turned into an empty list, so unelevated WinSight reported **zero scheduled tasks** while listing
/// the surface as covered. Measured on a real desktop: 0 unelevated, 104 elevated. A top-tier
/// persistence vector was entirely blind in the default mode, silently.
///
/// The service answers the same question without elevation, and answers it better: 195 tasks
/// visible on the same machine, because it lists what is registered rather than what happens to
/// have a readable file. It also hands back the identical XML, so the parsing that was already
/// tested is reused unchanged.
///
/// Late binding is used deliberately. Task Scheduler's interfaces would otherwise need an interop
/// assembly or a hand-written set of COM declarations — a large amount of unverifiable P/Invoke
/// surface in a security tool, to call four methods.
/// </remarks>
public sealed class ComScheduledTaskSource : IScheduledTaskSource
{
    /// <summary>Include hidden tasks: a task that hides itself is more interesting, not less.</summary>
    private const int IncludeHidden = 1;

    private bool _unreadable;

    public bool Unreadable => _unreadable;

    public IEnumerable<ScheduledTaskDefinition> Enumerate()
    {
        _unreadable = false;
        object? service = null;
        try
        {
            var type = Type.GetTypeFromProgID("Schedule.Service");
            service = type is null ? null : Activator.CreateInstance(type);
            if (service is null)
            {
                _unreadable = true;
                return [];
            }
            Invoke(service, "Connect", Type.Missing, Type.Missing, Type.Missing, Type.Missing);
            var root = Invoke(service, "GetFolder", @"\");
            if (root is null)
            {
                _unreadable = true;
                return [];
            }
            var collected = new List<ScheduledTaskDefinition>();
            try
            {
                Collect(root, collected, depth: 0);
            }
            finally
            {
                Release(root);
            }
            return collected;
        }
        catch (Exception ex) when (IsRecoverable(ex))
        {
            // The Task Scheduler service can be stopped or restricted. An empty list is then not a
            // finding about the machine, and saying so is the whole point of this flag.
            _unreadable = true;
            return [];
        }
        finally
        {
            Release(service);
        }
    }

    /// <summary>
    /// Whether a failure means "this source could not be read" rather than a defect in WinSight.
    /// </summary>
    /// <remarks>
    /// <b>Why this is a named predicate and not an inline <c>when</c> clause.</b> The set was wrong,
    /// and nothing could see that it was wrong. Late binding raises COM failures through
    /// <see cref="Type.InvokeMember(string, BindingFlags, Binder, object, object[], System.Globalization.CultureInfo)"/>,
    /// which wraps whatever the member threw in a <see cref="TargetInvocationException"/> — measured
    /// on this machine, asking the live service for a folder that does not exist surfaced
    /// <c>TargetInvocationException</c> (0x80131604), not <see cref="COMException"/>. The previous
    /// filter listed only unwrapped types, so <b>no</b> COM failure matched it: a stopped Task
    /// Scheduler service threw straight through <see cref="Enumerate"/> and took the whole
    /// persistence scan with it, while <see cref="Unreadable"/> — the flag whose entire purpose is
    /// to say "an empty list is not a fact about this machine" — could never become true.
    ///
    /// That is the same class of defect this component was written to fix, one layer down: the
    /// health signal was structurally incapable of reporting the blind spot it guards.
    ///
    /// The inner exception is what gets classified, because the CLR maps well-known HRESULTs to
    /// specific types before wrapping: <c>ERROR_FILE_NOT_FOUND</c> arrives as
    /// <see cref="FileNotFoundException"/>, <c>E_ACCESSDENIED</c> as
    /// <see cref="UnauthorizedAccessException"/>, and only the rest as <see cref="COMException"/>.
    /// Keeping this a predicate means it is tested directly, with the exception shapes the runtime
    /// actually produces, rather than asserted through a stub that can never fail the way COM does.
    /// </remarks>
    internal static bool IsRecoverable(Exception exception) => Unwrap(exception) is
        COMException or UnauthorizedAccessException or InvalidOperationException or
        MissingMethodException or NotSupportedException or IOException or ArgumentException;

    /// <summary>The exception a late-bound member actually threw, past the reflection wrapper.</summary>
    private static Exception Unwrap(Exception exception) =>
        exception is TargetInvocationException { InnerException: { } inner } ? inner : exception;

    /// <summary>Folders nest, and a cycle or a pathological tree must not become a stack overflow.</summary>
    private const int MaxDepth = 32;

    private static void Collect(object folder, List<ScheduledTaskDefinition> into, int depth)
    {
        if (depth > MaxDepth)
        {
            return;
        }

        var tasks = Invoke(folder, "GetTasks", IncludeHidden);
        try
        {
            if (tasks is System.Collections.IEnumerable taskList)
            {
                foreach (var task in taskList)
                {
                    try
                    {
                        var path = Get(task, "Path") as string;
                        var xml = Get(task, "Xml") as string;
                        if (!string.IsNullOrWhiteSpace(path) && !string.IsNullOrWhiteSpace(xml))
                        {
                            into.Add(new ScheduledTaskDefinition(path, xml));
                        }
                    }
                    catch (Exception ex) when (IsRecoverable(ex))
                    {
                        // One unreadable task must not cost the other 194.
                    }
                    finally
                    {
                        Release(task);
                    }
                }
            }
        }
        finally
        {
            Release(tasks);
        }

        var folders = Invoke(folder, "GetFolders", 0);
        try
        {
            if (folders is System.Collections.IEnumerable folderList)
            {
                foreach (var child in folderList)
                {
                    try
                    {
                        Collect(child, into, depth + 1);
                    }
                    catch (Exception ex) when (IsRecoverable(ex))
                    {
                        // Likewise: a folder we cannot open is not a reason to abandon the rest.
                    }
                    finally
                    {
                        Release(child);
                    }
                }
            }
        }
        finally
        {
            Release(folders);
        }
    }

    private static object? Invoke(object target, string method, params object?[] args) =>
        target.GetType().InvokeMember(
            method,
            System.Reflection.BindingFlags.InvokeMethod,
            binder: null,
            target,
            args,
            System.Globalization.CultureInfo.InvariantCulture);

    private static object? Get(object target, string property) =>
        target.GetType().InvokeMember(
            property,
            System.Reflection.BindingFlags.GetProperty,
            binder: null,
            target,
            args: null,
            System.Globalization.CultureInfo.InvariantCulture);

    private static void Release(object? comObject)
    {
        if (comObject is not null && Marshal.IsComObject(comObject))
        {
            Marshal.FinalReleaseComObject(comObject);
        }
    }
}
