namespace WinSight.Attribution;

/// <summary>
/// Rebuilds the full registry path of a write from the kernel's key-handle bookkeeping.
/// </summary>
/// <remarks>
/// <b>Why this is needed at all.</b> Kernel registry events do not carry the key you would
/// recognise. A write reports a <i>key control block</i> handle plus, at most, a name relative to
/// it — the full path is announced once, separately, when the kernel opens the key. Without joining
/// the two, a live <c>SetValue</c> arrives as a bare handle and a value name, resolves to nothing,
/// and is dropped.
///
/// That is not a theoretical worry: the first version of this watcher did exactly that. It printed
/// a healthy-looking burst of fully-qualified keys at start-up — which were only the rundown of
/// keys already open — and then silently recorded nothing at all, while every live write went past
/// unattributed. It looked like it was working.
///
/// Bounded on purpose: a machine opens and closes registry keys constantly, and a map that only
/// ever grows would be a slow leak in a process meant to run all day. When the ceiling is reached
/// the map is cleared rather than trimmed — losing resolution for a moment is recoverable, because
/// the kernel re-announces a key the next time it is opened, whereas unbounded memory is not.
/// </remarks>
public sealed class RegistryKeyResolver
{
    /// <summary>A ceiling on tracked key handles, so a busy machine cannot grow this without limit.</summary>
    public const int MaxTracked = 65536;

    private readonly Dictionary<ulong, string> _byHandle = [];
    private readonly Lock _gate = new();

    public int Count
    {
        get { lock (_gate) { return _byHandle.Count; } }
    }

    /// <summary>Records the full path the kernel announced for a key handle.</summary>
    public void Track(ulong handle, string? fullKeyName)
    {
        if (handle == 0 || string.IsNullOrWhiteSpace(fullKeyName))
        {
            return;
        }
        lock (_gate)
        {
            if (_byHandle.Count >= MaxTracked)
            {
                _byHandle.Clear();
            }
            _byHandle[handle] = fullKeyName.TrimEnd('\\');
        }
    }

    /// <summary>Forgets a handle the kernel has closed.</summary>
    public void Forget(ulong handle)
    {
        lock (_gate)
        {
            _byHandle.Remove(handle);
        }
    }

    /// <summary>
    /// The full key path for an event, or null when the handle was never announced.
    /// </summary>
    /// <param name="handle">The key control block the event refers to.</param>
    /// <param name="relativeName">
    /// What the event carried: empty for the key itself, a sub-path or value name otherwise, and
    /// occasionally an already-absolute path — which is returned unchanged rather than appended to
    /// anything.
    /// </param>
    public string? Resolve(ulong handle, string? relativeName)
    {
        var raw = relativeName?.Trim();

        // Some events carry the whole path already. Joining that onto a base would produce a key
        // that does not exist, which is worse than not resolving it. Tested before any separator
        // is trimmed: a leading backslash is exactly what marks the path absolute, so stripping it
        // first would disguise every absolute name as a relative one.
        if (!string.IsNullOrEmpty(raw) && IsAbsolute(raw))
        {
            return raw;
        }
        var relative = raw?.Trim('\\');

        string? baseKey;
        lock (_gate)
        {
            if (!_byHandle.TryGetValue(handle, out baseKey))
            {
                // Never announced: the key was opened before this session started and has not been
                // reopened since. Null is the honest answer.
                return null;
            }
        }
        return string.IsNullOrEmpty(relative) ? baseKey : $"{baseKey}\\{relative}";
    }

    private static bool IsAbsolute(string name) =>
        name.StartsWith(@"\REGISTRY\", StringComparison.OrdinalIgnoreCase)
        || name.StartsWith("HK", StringComparison.OrdinalIgnoreCase);
}
