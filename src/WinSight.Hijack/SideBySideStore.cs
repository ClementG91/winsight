using System.Diagnostics;

using WinSight.Core;

namespace WinSight.Hijack;

/// <summary>Whether a DLL is present in the side-by-side assembly store.</summary>
public interface ISideBySideStore
{
    /// <summary>
    /// True when the store holds <paramref name="dll"/>, false when it definitely does not, and
    /// null when the question could not be answered.
    /// </summary>
    bool? Contains(string dll);

    /// <summary>Names no verdict was reached about, so the caller can report coverage.</summary>
    int UnansweredLookups { get; }

    /// <summary>
    /// Whether the loader can serve <paramref name="dll"/> out of the store to an image of the given
    /// bitness whose manifest binds <paramref name="bound"/> (null when that manifest could not be
    /// read): true when a bound assembly holds it, false when nothing the image can reach does, null
    /// when that cannot be established.
    /// </summary>
    /// <remarks>
    /// Presence alone answers null here, never true (RA-04): a file of the same name in some other
    /// assembly is not the one the loader would load. An implementation that knows no more than
    /// presence therefore reports the import as unknown, not as resolved.
    /// </remarks>
    bool? Resolves(string dll, bool? is64Bit, IReadOnlyList<SideBySideAssembly>? bound) =>
        Contains(dll) switch
        {
            true => null,
            var answer => answer,
        };
}

/// <summary>
/// The real store, under <c>%WINDIR%\WinSxS</c>.
/// </summary>
/// <remarks>
/// <b>The accusation this prevents.</b> A binary whose manifest binds a side-by-side assembly - the
/// Visual C++ redistributables, MFC, ATL - has those imports resolved by the loader out of the
/// WinSxS store through an activation context. That store appears in no DLL search path, so "no
/// directory in the search order holds this file" was reported as a phantom import for every such
/// binary. On a machine with the usual redistributables that is a confident, repeated accusation
/// against ordinary software, including SYSTEM services.
///
/// <b>Bound to the image's manifest (RA-04).</b> This used to stop at "is a file of that name
/// anywhere in the store": the loader reaches WinSxS only through an activation context, built from
/// the assemblies the image's manifest names, so a same-named file in another architecture's copy, in
/// a feature staged but not installed, or in an unrelated component served nothing - and hid a
/// genuine phantom import. The index now records which component each file belongs to, and
/// <see cref="Resolves"/> answers true only when an assembly the image binds holds the file, or one
/// from the same non-Windows publisher (MFC depends on the CRT beside it). Where it cannot tell - an
/// unread manifest, a bound assembly whose own dependencies are not modelled - it answers unknown and
/// the scan reports coverage, never "resolved".
///
/// <b>One walk, not one per name.</b> The first version searched the tree per lookup, and the
/// hijack test suite went from 70 ms to 75 seconds - the fix for a false positive turning into a
/// scan nobody would wait for. The store's DLL names are indexed once and every later question is
/// answered from memory.
///
/// <b>It gives up rather than guessing.</b> The walk stops at a time budget and an entry cap. If it
/// did not finish, the index cannot prove a name is absent, so every lookup answers null and the
/// caller reports coverage instead of a finding - the same rule the rest of this codebase follows.
///
/// <b>Only what the loader can load from is walked (WS-51).</b> Walking every folder of WinSxS did
/// not fit the budget: on the audit machine it took 9.75 s warm and longer cold, across 124 584
/// directories, so the index was usually partial and every phantom-import question came back
/// "unknown". Most of those directories are the store's bookkeeping - pending deletions and
/// in-flight installs, backups, manifests, catalogs - and the forward/reverse/null differentials
/// inside each component, which are deltas against another version of a file the component already
/// names. None of them is a load source. Skipping them walks 27 039 directories in 2.1 s and finds
/// the same 5 828 names, less five <c>hermes.dll</c> files waiting in <c>Temp\PendingDeletes</c>.
/// The rule is a denylist on purpose: <c>Fusion</c>, where Windows 11 keeps MSI-installed Win32
/// assemblies such as the VC80 MFC and OpenMP ones, is walked, and so is any folder a later Windows
/// adds.
///
/// <b>One instance per scan, on one thread.</b> The index is built lazily on first use and the
/// unanswered-lookup count is a plain increment, neither of which is synchronised: this is a
/// per-scan object, created inside <c>HijackScanner.ScanWithCoverage</c> and used by the single
/// loop that walks the services. Sharing one across threads would race the index against its own
/// completeness flag, and a lookup could then read a finished index as a partial one - answering
/// "unknown" where it knows the answer, which silently turns findings into coverage. If this ever
/// needs to be shared, that is the thing to fix first.
/// </remarks>
public sealed class SideBySideStore : ISideBySideStore
{
    /// <summary>Wall-clock spent indexing the store before the walk is abandoned.</summary>
    public static readonly TimeSpan Budget = TimeSpan.FromSeconds(8);

    /// <summary>Entries indexed before the walk is abandoned.</summary>
    public const int MaxEntries = 400_000;

    // Top-level folders that are the store's bookkeeping, never a load source.
    private static readonly string[] BookkeepingFolders = ["Temp", "InstallTemp", "Backup", "Manifests", "Catalogs", "FileMaps"];

    // Differentials inside a component directory: deltas against another version of the same file.
    private static readonly string[] DeltaFolders = ["f", "r", "n"];

    private static readonly string[] NoFolders = [];

    private readonly string _root;
    private readonly TimeSpan _budget;
    private readonly int _maxEntries;
    // Each DLL name, with the components holding a file of that name.
    private Dictionary<string, List<SideBySideComponent>>? _names;
    private bool _complete;

    public SideBySideStore(string? windowsDirectory = null)
        : this(windowsDirectory, Budget, MaxEntries)
    {
    }

    /// <summary>
    /// The same store with the limits made explicit, so the give-up behaviour can be exercised.
    /// </summary>
    /// <remarks>
    /// The interesting property of this class is what it does when the walk does <i>not</i> finish:
    /// every later lookup has to answer "unknown" rather than "absent", because an absence it never
    /// looked for would be reported as a phantom import - the false positive the whole class exists
    /// to remove. Reaching that path against the real store means building a tree of four hundred
    /// thousand files or waiting eight seconds, so the limits are injectable and a test sets them
    /// to something it can actually reach.
    /// </remarks>
    internal SideBySideStore(string? windowsDirectory, TimeSpan budget, int maxEntries)
    {
        _root = Path.Combine(
            windowsDirectory ?? Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "WinSxS");
        _budget = budget;
        _maxEntries = maxEntries;
    }

    /// <inheritdoc />
    public int UnansweredLookups { get; private set; }

    /// <inheritdoc />
    public bool? Contains(string dll)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dll);

        Index();
        if (_names is null)
        {
            UnansweredLookups++;
            return null;
        }
        if (_names.ContainsKey(dll))
        {
            return true;
        }
        // Absent from a complete index is proof; absent from a partial one is not.
        if (_complete)
        {
            return false;
        }
        UnansweredLookups++;
        return null;
    }

    /// <inheritdoc />
    public bool? Resolves(string dll, bool? is64Bit, IReadOnlyList<SideBySideAssembly>? bound)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dll);

        Index();
        if (_names is null)
        {
            UnansweredLookups++;
            return null;
        }
        var holders = _names.TryGetValue(dll, out var found)
            ? found.Where(component => component.Fits(is64Bit)).ToList()
            : [];
        if (bound is not null && holders.Any(component => bound.Any(component.IsReachedThrough)))
        {
            return true;
        }
        // Everything below reasons from the whole store; a partial index proves nothing absent.
        if (!_complete)
        {
            UnansweredLookups++;
            return null;
        }
        // No copy of this architecture anywhere, or none an image binding nothing could reach.
        if (holders.Count == 0 || bound is { Count: 0 })
        {
            return false;
        }
        // Copies exist only where the image's manifest does not lead. Final only when the manifest
        // was read and everything it binds is an assembly with no dependencies of its own.
        if (bound is not null && bound.All(SideBySideComponent.IsLeaf))
        {
            return false;
        }
        UnansweredLookups++;
        return null;
    }

    private void Index()
    {
        if (_names is not null)
        {
            return;
        }
        using var rootLease = AutomaticFileAccess.TryAcquire(_root);
        if (rootLease is null)
        {
            // IsLocal performs the same non-reparse lookup but also distinguishes a genuinely
            // missing local path from a refused one. Only the former proves the store is empty.
            if (AutomaticFileAccess.IsLocal(_root))
            {
                _names = new Dictionary<string, List<SideBySideComponent>>(StringComparer.OrdinalIgnoreCase);
                _complete = true;
            }
            else
            {
                _names = null;
                _complete = false;
            }
            return;
        }
        if (!rootLease.IsDirectory)
        {
            _names = null;
            _complete = false;
            return;
        }

        var names = new Dictionary<string, List<SideBySideComponent>>(StringComparer.OrdinalIgnoreCase);
        var indexed = 0;
        var spent = Stopwatch.StartNew();
        try
        {
            // Walked depth first, one directory at a time, rather than with RecurseSubdirectories.
            // The recursive enumerator opens every subdirectory as it meets it and queues the open
            // handle; WinSxS has tens of thousands of component directories, so one index held about
            // 46 000 directory handles at once - every one a kernel object and a file-system filter
            // callback - before letting them go. A stack of names holds one handle at a time.
            var options = new EnumerationOptions
            {
                RecurseSubdirectories = false,
                // A reparse point in the store would take the walk somewhere else entirely.
                AttributesToSkip = FileAttributes.ReparsePoint,
                IgnoreInaccessible = true,
            };
            var pending = new Stack<(string Path, int Depth, SideBySideComponent Component)>();
            pending.Push((_root, 0, SideBySideComponent.Unattributed));
            while (pending.Count > 0)
            {
                if (spent.Elapsed > _budget)
                {
                    _names = names;
                    _complete = false;
                    return;
                }
                var (directory, depth, component) = pending.Pop();
                // Only a DLL's name is materialised; every other file is filtered before a string exists.
                var entries = new System.IO.Enumeration.FileSystemEnumerable<(string Value, bool IsDirectory)>(
                    directory,
                    (ref System.IO.Enumeration.FileSystemEntry entry) => entry.IsDirectory
                        ? (entry.ToFullPath(), true)
                        : (entry.FileName.ToString(), false),
                    options)
                {
                    ShouldIncludePredicate = (ref System.IO.Enumeration.FileSystemEntry entry) => entry.IsDirectory
                        ? !IsNamed(entry.FileName, depth switch { 0 => BookkeepingFolders, 1 => DeltaFolders, _ => NoFolders })
                        : entry.FileName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase),
                };
                foreach (var (value, isDirectory) in entries)
                {
                    if (isDirectory)
                    {
                        pending.Push((value, depth + 1, SideBySideComponent.ForDirectory(value, depth + 1, directory, component)));
                        continue;
                    }
                    if (!names.TryGetValue(value, out var holders))
                    {
                        holders = [];
                        names[value] = holders;
                    }
                    if (!holders.Contains(component))
                    {
                        holders.Add(component);
                    }
                    if (++indexed >= _maxEntries || spent.Elapsed > _budget)
                    {
                        _names = names;
                        _complete = false;
                        return;
                    }
                }
            }
            _names = names;
            _complete = rootLease.IsCurrent();
        }
        catch (Exception ex) when (ex is IOException
                                     or UnauthorizedAccessException
                                     or System.Security.SecurityException)
        {
            // A refusal is a gap in the observation, not evidence any file is absent.
            _names = names;
            _complete = false;
        }
    }

    private static bool IsNamed(ReadOnlySpan<char> name, string[] candidates)
    {
        foreach (var candidate in candidates)
        {
            if (name.Equals(candidate, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }
}
