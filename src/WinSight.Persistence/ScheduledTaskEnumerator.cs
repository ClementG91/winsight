using System.Xml;
using System.Xml.Linq;
using Microsoft.Win32;

namespace WinSight.Persistence;

/// <summary>
/// Scheduled Tasks, read from the Task Scheduler service. Each task's Exec action Command is an
/// autostart command. A favourite modern persistence spot.
/// </summary>
/// <remarks>
/// This used to parse the XML files under <c>%SystemRoot%\System32\Tasks</c> directly, to avoid a
/// COM dependency. That directory is administrators-only and <c>Directory.GetFiles</c> throws for
/// the whole tree rather than skipping what it cannot read, so unelevated WinSight reported
/// <b>zero</b> scheduled tasks while still listing the surface as covered — measured, 0 unelevated
/// against 104 elevated. The service answers without elevation and answers better (195 on the same
/// machine, because it lists what is registered rather than what has a readable file), and it hands
/// back the same XML, so the parsing below is unchanged. See <see cref="ComScheduledTaskSource"/>.
/// </remarks>
public sealed class ScheduledTaskEnumerator(IScheduledTaskSource? source = null) : IAutostartEnumerator
{
    public bool CanConfirmAbsence => true;

    private static readonly string TasksRoot =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "Tasks");

    private readonly IScheduledTaskSource _source = source ?? new ComScheduledTaskSource();
    private int _unreadable;

    public string Surface => "Scheduled Tasks";

    // A scheduled task is still a file under \System32\Tasks even when read through the service, so
    // the live watcher keeps watching the tree — directory change notifications do not require the
    // read access that opening the files does.
    public IReadOnlyList<PersistenceWatchTarget> WatchTargets { get; } = new[]
    {
        PersistenceWatchTarget.FileSystem(TasksRoot, includeSubdirectories: true),
    };

    /// <inheritdoc />
    /// <remarks>
    /// Reported as one unreadable location, not a count: when the service cannot be reached the
    /// number of tasks behind it is exactly what is unknown.
    /// </remarks>
    public int UnreadableLocations => _unreadable;

    private List<string>? _unreadableScopes = [];

    /// <inheritdoc />
    public IReadOnlyCollection<string>? UnreadableScopes => _unreadableScopes;

    public IEnumerable<RawAutostart> Enumerate()
    {
        var tasks = _source.Enumerate().ToList();
        _unreadable = _source.Unreadable ? 1 : 0;
        // Folders the service refused are scopes; a source that cannot name its gap is unattributed.
        _unreadableScopes = !_source.Unreadable
            ? []
            : _source.UnreadableFolders is { } folders
                ? [.. folders.Select(folder => Path.Combine(TasksRoot, folder.Trim('\\')))]
                : null;
        var scannerSid = UserHiveEnumerator.CurrentSid();
        var loaders = new Dictionary<string, LoaderContext>(StringComparer.OrdinalIgnoreCase);
        foreach (var task in tasks)
        {
            var location = Path.Combine(TasksRoot, task.Path.TrimStart('\\'));
            if (!TryParseTaskCommands(task.Xml, out var commands, out var unresolvedComHandlers))
            {
                _unreadable++;
                _unreadableScopes?.Add(location);
                continue;
            }
            // A COM handler this scan could not resolve to a file is a task whose code it never
            // looked at. Counted rather than guessed at.
            _unreadable += unresolvedComHandlers;
            if (unresolvedComHandlers > 0)
            {
                _unreadableScopes?.Add(location);
            }
            // The action's variables expand in the environment of the account the task runs as.
            var loader = ScheduledTaskPrincipal.Loader(ScheduledTaskPrincipal.Sid(task.Xml), scannerSid, loaders);
            foreach (var command in commands)
            {
                yield return new RawAutostart(
                    AutostartVector.ScheduledTask,
                    task.Path.TrimStart('\\'),
                    Path.Combine(TasksRoot, task.Path.TrimStart('\\')),
                    command,
                    Loader: loader);
            }
        }
    }

    /// <summary>
    /// Extracts the Exec-action command lines from a Task Scheduler XML definition. The
    /// schema uses a default namespace, so matching is by local element name. Invalid
    /// XML yields nothing (isolated, never throws).
    /// </summary>
    /// <remarks>
    /// <b>The arguments are the payload, and they used to be discarded.</b> An Exec action stores
    /// the interpreter in <c>&lt;Command&gt;</c> and what it is told to run in
    /// <c>&lt;Arguments&gt;</c>, so reading only the first reduces
    /// <c>rundll32.exe C:\Users\…\AppData\Roaming\evil.dll,Start</c> to <c>rundll32.exe</c> — a
    /// Microsoft-signed binary with a valid signature, and no trace anywhere in the report of the
    /// DLL it loads. Measured on a real desktop: <b>12 of the 15</b> autostart entries resolving to
    /// an interpreter were scheduled tasks, and every one of them carried an empty command line.
    /// The surface most used for modern persistence was the one reporting the least evidence.
    ///
    /// Pairing is done through each <c>Command</c> element's own parent rather than by matching
    /// <c>Exec</c> elements, so the flat descendant search that made this robust against unexpected
    /// nesting is preserved: a <c>Command</c> the schema puts somewhere unforeseen still yields its
    /// command, simply without arguments, instead of disappearing from the scan.
    ///
    /// The two are joined with a space into one command line because that is the string
    /// <see cref="CommandLine.ResolveExecutable"/> already parses — it takes the longest leading
    /// prefix that exists on disk, so a spaced or quoted program path still resolves and the
    /// arguments become inert trailing text rather than a second parsing rule to keep correct.
    /// </remarks>
    public static IReadOnlyList<string> ParseTaskCommands(string xml) =>
        TryParseTaskCommands(xml, out var commands) ? commands : [];

    internal static bool TryParseTaskCommands(string xml, out IReadOnlyList<string> commands) =>
        TryParseTaskCommands(xml, out commands, out _);

    internal static bool TryParseTaskCommands(
        string xml, out IReadOnlyList<string> commands, out int unresolvedComHandlers)
    {
        unresolvedComHandlers = 0;
        XDocument doc;
        try
        {
            doc = XDocument.Parse(xml);
        }
        catch (XmlException)
        {
            commands = [];
            return false;
        }
        var found = doc.Descendants()
            .Where(e => e.Name.LocalName == "Command")
            .Select(e => Join(e.Value.Trim(), SiblingArguments(e)))
            .Where(c => c.Length > 0)
            .ToList();

        // A ComHandler action runs code just as an Exec action does - it instantiates a CLSID and
        // calls into it - and reading only Exec meant such a task left the report entirely, without
        // even incrementing the unreadable count.
        //
        // Only a handler whose CLSID resolves to a file is emitted, because every entry in this
        // report is graded by the image model and a bare GUID has nothing to resolve. Windows ships
        // ComHandler tasks whose classes are not registered where a CLSID lookup can reach them, so
        // reporting the GUID itself would flag eight stock tasks as "no resolvable image" on every
        // machine. The unresolvable ones are counted instead - which is exactly the gap: they used
        // to vanish from the report without incrementing anything.
        unresolvedComHandlers = 0;
        foreach (var handler in doc.Descendants().Where(e => e.Name.LocalName == "ComHandler"))
        {
            var target = ComHandlerTarget(handler);
            if (target.Length > 0)
            {
                found.Add(target);
            }
            else
            {
                unresolvedComHandlers++;
            }
        }

        commands = found;
        return true;
    }

    /// <summary>
    /// The binary a <c>ComHandler</c> action loads, or empty when its CLSID names no file.
    /// </summary>
    private static string ComHandlerTarget(XElement handler)
    {
        var clsid = handler.Elements()
            .FirstOrDefault(child => child.Name.LocalName == "ClassId")?
            .Value
            .Trim();
        if (string.IsNullOrEmpty(clsid))
        {
            return string.Empty;
        }
        // A denied class registration is an unresolved handler (counted by the caller), not a
        // reason to abandon every task after it in the enumeration.
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            if (!ClsidResolver.TryResolveInprocServer(clsid, view, out var path))
            {
                return string.Empty;
            }
            if (path is not null)
            {
                return path;
            }
        }
        return string.Empty;
    }

    /// <summary>The <c>Arguments</c> value beside a given <c>Command</c>, or null when it has none.</summary>
    private static string? SiblingArguments(XElement command) =>
        command.Parent?
            .Elements()
            .FirstOrDefault(sibling => sibling.Name.LocalName == "Arguments")?
            .Value
            .Trim();

    private static string Join(string command, string? arguments) =>
        command.Length == 0 || string.IsNullOrEmpty(arguments)
            ? command
            : $"{command} {arguments}";

}
