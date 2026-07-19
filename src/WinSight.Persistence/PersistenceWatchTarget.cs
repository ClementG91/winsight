using Microsoft.Win32;

namespace WinSight.Persistence;

/// <summary>The kind of location a <see cref="PersistenceWatchTarget"/> points at.</summary>
public enum PersistenceWatchKind
{
    Registry,
    FileSystem,
}

/// <summary>
/// A location worth watching to learn that a surface may have changed, for real-time monitoring.
/// It is only a trigger hint: the enumerator, not the target, stays the source of truth for what
/// actually changed. A registry target names a hive/view/subkey (optionally watching the whole
/// subtree); a filesystem target names a directory (optionally including subdirectories).
/// </summary>
public sealed record PersistenceWatchTarget
{
    private PersistenceWatchTarget()
    {
    }

    public PersistenceWatchKind Kind { get; private init; }

    /// <summary>Registry hive (Registry targets only).</summary>
    public RegistryHive Hive { get; private init; }

    /// <summary>Registry view — 64- vs 32-bit (Registry targets only).</summary>
    public RegistryView View { get; private init; }

    /// <summary>The registry subkey path, or the filesystem directory, depending on <see cref="Kind"/>.</summary>
    public string Path { get; private init; } = string.Empty;

    /// <summary>Watch the registry subtree / include subdirectories.</summary>
    public bool Recursive { get; private init; }

    public static PersistenceWatchTarget Registry(
        RegistryHive hive, RegistryView view, string subKey, bool watchSubtree = false) =>
        new()
        {
            Kind = PersistenceWatchKind.Registry,
            Hive = hive,
            View = view,
            Path = subKey ?? string.Empty,
            Recursive = watchSubtree,
        };

    public static PersistenceWatchTarget FileSystem(string directory, bool includeSubdirectories = false) =>
        new()
        {
            Kind = PersistenceWatchKind.FileSystem,
            Path = directory ?? string.Empty,
            Recursive = includeSubdirectories,
        };
}
