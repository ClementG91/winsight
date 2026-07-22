using System.Collections.Immutable;

namespace WinSight.Application;

/// <summary>
/// Decides which file writes attribution records, so a detection can name the program behind it.
/// </summary>
/// <remarks>
/// <b>Why file writes are filtered at all.</b> A busy machine performs thousands of file writes a
/// second, and the correlation index is deliberately small and time-bounded. Recording everything
/// would evict every useful observation within seconds — the index would be full and useless at the
/// exact moment a detection asked it a question. Registry writes need no such filter: they are
/// orders of magnitude rarer.
///
/// <b>Why only these two sets.</b> Both are small, precisely known, and sit under exactly the two
/// detections that need an author: the startup folders behind Guardian's file-based persistence, and
/// the ransomware decoys. The protected *directories* — Documents, Desktop, Pictures — are
/// deliberately <i>not</i> watched wholesale: they are among the busiest paths on a desktop, and
/// admitting them would reintroduce the flooding this filter exists to prevent. The consequence is
/// stated plainly rather than hidden: a rename/delete burst is alerted without an author, while a
/// touched decoy — the high-confidence signal — is alerted with one.
///
/// <b>Why matching ignores the volume root.</b> This filter runs on the path as the kernel spells it,
/// before any normalisation, because normalising thousands of events a second is the cost the filter
/// exists to avoid. The kernel writes <c>\Device\HarddiskVolume3\Users\…</c> where an operator writes
/// <c>C:\Users\…</c>, so a match against the full DOS path cannot succeed against the kernel form.
/// Comparing the root-relative tail is correct under either spelling, which matters because which one
/// arrives depends on the trace plumbing and is not something this code should be betting on.
///
/// The cost of that choice is a path with the same tail on another volume also matching. That is
/// harmless: the filter only decides what is worth <i>recording</i>, and the recorded target is
/// normalised properly afterwards. Recording a few extra writes costs an index slot; missing all of
/// them costs the entire feature.
/// </remarks>
public sealed class AttributionScope
{
    private readonly ImmutableArray<string> _startupTails;
    // Written by the UI thread when protection is toggled, read by the trace thread on every file
    // event. Immutable snapshots swapped atomically, so the reader never sees a half-built set.
    private volatile ImmutableHashSet<string> _canaryTails = ImmutableHashSet.Create<string>(StringComparer.OrdinalIgnoreCase);

    public AttributionScope(IReadOnlyList<string>? startupFolders = null)
    {
        var folders = startupFolders ?? DefaultStartupFolders();
        _startupTails = folders
            .Select(RootRelative)
            .Where(tail => tail.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToImmutableArray();
    }

    /// <summary>The per-user and machine-wide Startup folders, where file-based persistence lands.</summary>
    public static IReadOnlyList<string> DefaultStartupFolders() =>
        new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
        }
        .Where(folder => !string.IsNullOrWhiteSpace(folder))
        .ToArray();

    /// <summary>
    /// Begins recording writes to these decoys. Called when ransomware protection is switched on,
    /// because the decoy paths do not exist until they are planted.
    /// </summary>
    public void WatchCanaries(IEnumerable<string>? canaries) =>
        _canaryTails = (canaries ?? [])
            .Select(RootRelative)
            .Where(tail => tail.Length > 0)
            .ToImmutableHashSet(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Stops recording decoy writes. Called when protection is switched off, so the index is not
    /// held open on paths that no longer exist.
    /// </summary>
    public void ForgetCanaries() => WatchCanaries([]);

    /// <summary>Whether a write to <paramref name="path"/> is worth remembering.</summary>
    public bool ShouldRecord(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }
        var tail = RootRelative(path);
        if (tail.Length == 0)
        {
            return false;
        }
        // A decoy is matched exactly: it is one named file, and anything else under the same folder
        // is ordinary user activity this must not admit.
        if (_canaryTails.Contains(tail))
        {
            return true;
        }
        foreach (var startup in _startupTails)
        {
            if (tail.Contains(startup, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }

    /// <summary>
    /// A path with its volume root removed, so <c>C:\Users\…</c> and
    /// <c>\Device\HarddiskVolume3\Users\…</c> compare equal.
    /// </summary>
    internal static string RootRelative(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return string.Empty;
        }
        var value = path.Trim().Replace('/', '\\');

        // \Device\HarddiskVolumeN\rest  ->  \rest
        const string device = @"\Device\";
        if (value.StartsWith(device, StringComparison.OrdinalIgnoreCase))
        {
            var afterVolume = value.IndexOf('\\', device.Length);
            return afterVolume < 0 ? string.Empty : value[afterVolume..];
        }

        // \??\C:\rest and \\?\C:\rest are the same path wearing a prefix.
        if (value.StartsWith(@"\??\", StringComparison.Ordinal) || value.StartsWith(@"\\?\", StringComparison.Ordinal))
        {
            value = value[4..];
        }

        // C:\rest -> \rest
        if (value.Length >= 2 && value[1] == ':')
        {
            return value.Length == 2 ? string.Empty : value[2..];
        }

        return value.StartsWith('\\') ? value : "\\" + value;
    }
}
