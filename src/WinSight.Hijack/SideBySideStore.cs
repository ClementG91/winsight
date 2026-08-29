using System.Diagnostics;

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
/// <b>Why a file lookup rather than manifest parsing.</b> Reading the RT_MANIFEST resource and
/// resolving the declared assembly to its files is the complete model, and it is a great deal of
/// parsing of attacker-reachable structures for the same answer. If the DLL is physically in the
/// store, the loader can reach it and the import is not phantom - which is the question being asked.
///
/// <b>One walk, not one per name.</b> The first version searched the tree per lookup, and the
/// hijack test suite went from 70 ms to 75 seconds - the fix for a false positive turning into a
/// scan nobody would wait for. The store's DLL names are indexed once and every later question is
/// answered from memory.
///
/// <b>It gives up rather than guessing.</b> The walk stops at a time budget and an entry cap. If it
/// did not finish, the index cannot prove a name is absent, so every lookup answers null and the
/// caller reports coverage instead of a finding - the same rule the rest of this codebase follows.
/// </remarks>
public sealed class SideBySideStore : ISideBySideStore
{
    /// <summary>Wall-clock spent indexing the store before the walk is abandoned.</summary>
    public static readonly TimeSpan Budget = TimeSpan.FromSeconds(8);

    /// <summary>Entries indexed before the walk is abandoned.</summary>
    public const int MaxEntries = 400_000;

    private readonly string _root;
    private readonly TimeSpan _budget;
    private readonly int _maxEntries;
    private HashSet<string>? _names;
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
        if (_names.Contains(dll))
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

    private void Index()
    {
        if (_names is not null)
        {
            return;
        }
        if (!Directory.Exists(_root))
        {
            // No store on this machine: nothing resolves through it, which is a complete answer.
            _names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _complete = true;
            return;
        }

        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var spent = Stopwatch.StartNew();
        try
        {
            var options = new EnumerationOptions
            {
                RecurseSubdirectories = true,
                // A reparse point in the store would take the walk somewhere else entirely.
                AttributesToSkip = FileAttributes.ReparsePoint,
                IgnoreInaccessible = true,
            };
            foreach (var file in Directory.EnumerateFiles(_root, "*.dll", options))
            {
                names.Add(Path.GetFileName(file));
                if (names.Count >= _maxEntries || spent.Elapsed > _budget)
                {
                    _names = names;
                    _complete = false;
                    return;
                }
            }
            _names = names;
            _complete = true;
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
}
