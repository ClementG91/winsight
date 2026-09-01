using Microsoft.Win32;
using WinSight.Core;

namespace WinSight.Hijack;

/// <summary>An import no file on this machine answers.</summary>
/// <param name="Dll">The module name the binary declares.</param>
/// <param name="DelayLoaded">
/// True when it is fetched on first use rather than at load. Both are plantable; a delay-loaded one
/// is quieter, because nothing fails until the feature that needs it runs.
/// </param>
/// <param name="PlantableAt">
/// The first directory in the search order the current user could write the missing file into, or
/// null when none of them is writable. Null is still worth reporting: it is one permission change
/// away, and an installer that widens a directory turns every phantom under it into a live vector.
/// </param>
public sealed record PhantomImport(string Dll, bool DelayLoaded, string? PlantableAt);

/// <summary>
/// The directories Windows searches for a DLL a program imports by name, in order.
/// </summary>
/// <remarks>
/// This is the default, <b>safe</b> search order — the one in force since
/// <c>SafeDllSearchMode</c> became the default. The unsafe order puts the current working directory
/// second instead of near the end; it is deliberately not modelled, because assuming the weaker
/// order would manufacture findings on machines that are not configured that way.
///
/// The application's own directory comes first, which is why a writable program directory is
/// already a finding of its own: it pre-empts every import, present or missing.
/// </remarks>
public static class DllSearchOrder
{
    /// <summary>
    /// The directory a process of this bitness actually reaches when it searches "the system
    /// directory".
    /// </summary>
    /// <remarks>
    /// <b>The redirector is not optional.</b> A 32-bit process on 64-bit Windows that opens
    /// <c>%WINDIR%\System32\x.dll</c> is silently served <c>%WINDIR%\SysWOW64\x.dll</c>. The scan
    /// searched System32 for every binary regardless of its bitness, so a 32-bit service importing
    /// a DLL that ships only in SysWOW64 - which is the ordinary case for the 32-bit half of
    /// anything - had that import declared phantom. The bitness was read during the PE parse and
    /// thrown away.
    ///
    /// On 32-bit Windows there is no SysWOW64 and <paramref name="systemDirectory"/> is already
    /// right, so the substitution only happens where the redirector exists.
    /// </remarks>
    public static string SystemDirectoryFor(
        bool is64Bit, string systemDirectory, string windowsDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(systemDirectory);
        ArgumentException.ThrowIfNullOrWhiteSpace(windowsDirectory);

        if (is64Bit)
        {
            return systemDirectory;
        }
        var wow = Path.Combine(windowsDirectory, "SysWOW64");
        return Directory.Exists(wow) ? wow : systemDirectory;
    }

    public static IReadOnlyList<string> For(
        string applicationDirectory,
        string systemDirectory,
        string windowsDirectory,
        IReadOnlyList<string> machinePath)
    {
        var order = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void Add(string? directory)
        {
            if (!string.IsNullOrWhiteSpace(directory) && seen.Add(directory.TrimEnd('\\')))
            {
                order.Add(directory.TrimEnd('\\'));
            }
        }

        Add(applicationDirectory);
        Add(systemDirectory);
        // The 16-bit system directory is still searched, and still exists on 64-bit Windows.
        Add(Path.Combine(windowsDirectory, "System"));
        Add(windowsDirectory);
        foreach (var entry in machinePath)
        {
            Add(entry);
        }
        return order;
    }
}

/// <summary>
/// Decides which of a binary's imports are phantom: declared, and answered by no file in the
/// search order.
/// </summary>
/// <remarks>
/// <b>Why this is the highest-signal half of DLL hijacking.</b> A phantom import is not a
/// misconfiguration an attacker has to race — it is a permanent, unoccupied slot. Whoever can write
/// the name into any searched directory has their code loaded by that program, at its privilege,
/// every time it runs. Windows ships several of these itself, which is exactly why they are worth
/// enumerating on the machine in front of you rather than from a published list.
///
/// <b>Two exclusions carry the entire signal-to-noise ratio.</b>
///
/// <i>API sets</i> (<c>api-ms-win-…</c>, <c>ext-ms-win-…</c>) are not files. They are redirected by
/// the loader through a schema in the kernel, and no file of that name exists anywhere on a healthy
/// machine. Measured on this desktop, they are the majority of every binary's import table —
/// <c>notepad.exe</c> declares 50 imports of which most are api-sets — so failing to exclude them
/// would report every program on the machine as riddled with phantoms and bury the real ones.
///
/// <i>KnownDLLs</i> are mapped from a pre-loaded section object, never resolved through the search
/// order at all, so planting one earlier in the order achieves nothing. Reading the list from the
/// registry rather than hardcoding it matters: it is machine state, and a machine whose KnownDLLs
/// were tampered with is one this scan should reflect rather than paper over.
/// </remarks>
public static class PhantomDllRule
{
    /// <summary>True for a name the loader answers itself, with no file anywhere.</summary>
    /// <remarks>
    /// The prefixes are <c>api-ms-</c> and <c>ext-ms-</c>, not <c>api-ms-win-</c> and
    /// <c>ext-ms-win-</c>. Narrowing them to <c>-win-</c> looks harmless and is not: measured
    /// against the live machine, the first two findings this rule ever produced were
    /// <c>ext-ms-win32-subsystem-query-l1-1-0.dll</c> in the print spooler and
    /// <c>ext-ms-onecore-appmodel-staterepository-internal-l1-1-3.dll</c> in the search indexer —
    /// both api-sets, neither matching <c>ext-ms-win-</c>, both reported as phantom imports of a
    /// SYSTEM service. Two confident false accusations against Windows itself, from four characters.
    /// </remarks>
    public static bool IsLoaderResolved(string dll) =>
        dll.StartsWith("api-ms-", StringComparison.OrdinalIgnoreCase)
        || dll.StartsWith("ext-ms-", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// The imports of <paramref name="imports"/> that no directory in
    /// <paramref name="searchOrder"/> can satisfy.
    /// </summary>
    /// <param name="fileExists">
    /// Asked for a full candidate path. A seam so the rule is testable against a machine that does
    /// not exist, which is the only way to prove it fires at all.
    /// </param>
    /// <param name="canPlantIn">
    /// Asked for a directory in the search order. Null means writability is not assessed, and every
    /// finding is reported with no plant location rather than a guessed one.
    /// </param>
    /// <param name="resolvedElsewhere">
    /// Asked for an import no directory in the search order answered, before it is called phantom.
    /// True means the loader can still find it by a route this rule does not model - side-by-side
    /// redirection through an activation context, which is how the Visual C++ and MFC/ATL
    /// redistributables are resolved.
    /// </param>
    /// <remarks>
    /// <b>Why the extra question exists.</b> "No file answers this name in the search order" is not
    /// the same statement as "the loader cannot find it". A binary whose manifest binds a
    /// side-by-side assembly resolves those imports out of the WinSxS store, which appears in no
    /// search path. Without this the scan reported every VC-redistributable-linked service as
    /// carrying phantom imports - a confident accusation, at scale, against ordinary software.
    /// </remarks>
    public static IReadOnlyList<PhantomImport> Find(
        PeImportSet imports,
        IReadOnlyList<string> searchOrder,
        IReadOnlySet<string> knownDlls,
        Func<string, bool> fileExists,
        Func<string, bool>? canPlantIn = null,
        Func<string, bool>? resolvedElsewhere = null)
    {
        ArgumentNullException.ThrowIfNull(imports);
        ArgumentNullException.ThrowIfNull(searchOrder);
        ArgumentNullException.ThrowIfNull(knownDlls);
        ArgumentNullException.ThrowIfNull(fileExists);

        var findings = new List<PhantomImport>();
        var reported = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        // Writability is asked once per directory, not once per import: a service with 130 imports
        // would otherwise probe the same folder 130 times.
        var plantable = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);

        foreach (var (dll, delayLoaded) in imports.Imports.Select(d => (d, false))
                     .Concat(imports.DelayImports.Select(d => (d, true))))
        {
            if (IsLoaderResolved(dll) || knownDlls.Contains(TrimExtension(dll)) || !reported.Add(dll))
            {
                continue;
            }
            if (searchOrder.Any(directory => fileExists(Path.Combine(directory, dll))))
            {
                continue;
            }
            // Asked only for names the search order could not answer, so the cost is proportional
            // to the findings rather than to the imports - which on a service with 130 imports is
            // the difference between a few lookups and a hundred and thirty.
            if (resolvedElsewhere is not null && resolvedElsewhere(dll))
            {
                continue;
            }
            findings.Add(new PhantomImport(dll, delayLoaded, FirstPlantable()));
        }
        return findings;

        string? FirstPlantable()
        {
            if (canPlantIn is null)
            {
                return null;
            }
            foreach (var directory in searchOrder)
            {
                if (!plantable.TryGetValue(directory, out var writable))
                {
                    writable = canPlantIn(directory);
                    plantable[directory] = writable;
                }
                if (writable)
                {
                    return directory;
                }
            }
            return null;
        }
    }

    /// <summary>KnownDLLs are registered without the extension in some entries and with it in others.</summary>
    private static string TrimExtension(string dll) =>
        dll.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ? dll[..^4] : dll;
}

/// <summary>Reads the machine's KnownDLLs set. A seam, so the rule above never needs the registry.</summary>
public interface IKnownDllSource
{
    IReadOnlySet<string> Read();

    AcquisitionSnapshot<string> ReadWithCoverage() => new(Read().ToList());
}

/// <summary>
/// Reads <c>HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs</c>. World-readable, so
/// this needs no elevation — the same reason the rest of the hijack scan ships in the default mode.
/// </summary>
public sealed class RegistryKnownDllSource : IKnownDllSource
{
    private const string KnownDllsKey = @"SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs";

    public IReadOnlySet<string> Read() =>
        ReadWithCoverage().Items.ToHashSet(StringComparer.OrdinalIgnoreCase);

    public AcquisitionSnapshot<string> ReadWithCoverage()
    {
        var known = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var key = baseKey.OpenSubKey(KnownDllsKey);
            if (key is null)
            {
                return new AcquisitionSnapshot<string>([], unreadableSources: 1);
            }
            foreach (var name in key.GetValueNames())
            {
                // DllDirectory and DllDirectory32 name folders, not modules.
                if (name.StartsWith("DllDirectory", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }
                if (key.GetValue(name) is string value && !string.IsNullOrWhiteSpace(value))
                {
                    known.Add(value.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ? value[..^4] : value);
                }
            }
        }
        catch (Exception ex) when (ex is System.Security.SecurityException
                                     or UnauthorizedAccessException
                                     or IOException)
        {
            return new AcquisitionSnapshot<string>([], unreadableSources: 1);
        }
        return new AcquisitionSnapshot<string>(known.ToList());
    }
}
