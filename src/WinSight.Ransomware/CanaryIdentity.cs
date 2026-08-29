using System.Security.Cryptography;
using System.Text;

using WinSight.Core;

namespace WinSight.Ransomware;

/// <summary>
/// Names decoy files so an adversary cannot recognise them, and remembers where they were planted so
/// they can still be cleaned up.
/// </summary>
/// <remarks>
/// <b>The defect this replaces.</b> Every decoy was called
/// <c>WinSightGuard_&lt;guid&gt;.xlsx</c> — a constant in a public GPL repository, with only the GUID
/// varying. Evading the entire ransomware feature was one line in the attacker's directory walk:
/// <c>if (name.StartsWith("WinSightGuard_")) continue;</c>. A decoy whose name announces that it is
/// a decoy is not a decoy.
///
/// <b>Machine-local variation, not a public constant.</b> Names are derived by HMAC-SHA256 from a
/// 32-byte seed generated on this machine and never transmitted. Reading the source alone no longer
/// reveals the names. The seed lives beside the other per-user WinSight state, so a reinstall keeps
/// recognising decoys planted by a previous run. This is not a trust boundary: code already running
/// as the same user can read the seed or enumerate the visible files. It prevents source-only and
/// fleet-wide static recognition, not targeted evasion by a local compromise.
///
/// <b>Recognisability had a purpose, so it is replaced rather than removed.</b> The old prefix was
/// how orphans from a crashed run were swept up. That job moves to an explicit manifest of planted
/// paths, which is strictly better: it finds decoys whatever they are called, including the ones a
/// future naming change produces. The legacy glob is still swept so files left by earlier versions
/// are not stranded in the operator's folders.
///
/// <b>Plausible names on purpose.</b> Ransomware prioritises what looks like a user document.
/// A decoy named like a real spreadsheet is picked up early; a random hex string may be skipped by
/// families that filter for document-shaped names.
/// </remarks>
public static class CanaryIdentity
{
    /// <summary>Decoys planted per directory. Several, at different points of an alphabetical walk.</summary>
    public const int PerDirectory = 3;

    /// <summary>The pattern earlier versions used. Swept up, never produced.</summary>
    internal const string LegacyGlob = "WinSightGuard_*.xlsx";

    /// <summary>The exact payload written by the legacy implementation.</summary>
    internal const string LegacyContent =
        "WinSight ransomware canary. This hidden decoy exists to detect ransomware; do not modify or delete it.\n";

    // Ordinary-looking document stems, in three pools chosen so the decoys land at the start, the
    // middle and the end of an alphabetical directory walk. A decoy is only worth the point of the
    // walk at which it is reached: one that always sorts last is touched after the documents it was
    // protecting have already been encrypted, which is what made a single decoy per directory worth
    // less than it looked.
    //
    // The pools being public reveals nothing. The seed picks the stem, the year and the
    // discriminator, so a name cannot be recognised without it - which is the property the old
    // published "WinSightGuard_" prefix did not have.
    private static readonly string[] EarlyStems =
    [
        "Budget", "Accounts", "Audit", "Bank_statement", "Balance_sheet", "Contracts",
    ];

    private static readonly string[] MiddleStems =
    [
        "Invoice", "Inventory", "Payroll", "Notes", "Ledger", "Insurance", "Payments", "Orders",
    ];

    private static readonly string[] LateStems =
    [
        "Taxes", "Timesheet", "Vendors", "Wages", "Year_end", "Utilities", "Suppliers", "Salaries",
    ];

    private static readonly string[] Extensions = [".xlsx", ".docx", ".xlsx"];

    /// <summary>
    /// The file name for decoy <paramref name="index"/> in <paramref name="directory"/>, derived
    /// from <paramref name="seed"/>. Pure and deterministic, so the same run recognises its own
    /// decoys and a later run can recompute them.
    /// </summary>
    public static string FileName(byte[] seed, string directory, int index)
    {
        ArgumentNullException.ThrowIfNull(seed);
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        ArgumentOutOfRangeException.ThrowIfNegative(index);

        var material = HMACSHA256.HashData(
            seed,
            Encoding.Unicode.GetBytes($"{directory.ToLowerInvariant()}|{index}"));

        var year = 2019 + (material[1] % 8);
        // A short discriminator so two decoys never collide, and so a name is not guessable even
        // by someone who knows the stem pools.
        var discriminator = Convert.ToHexString(material, 2, 4).ToLowerInvariant();
        var extension = Extensions[index % Extensions.Length];

        // The sort position is carried by the first character of the finished name, not by a marker
        // bolted on, so each decoy still reads as an ordinary document.
        var lead = (index % 3) switch
        {
            // A leading year sorts ahead of every letter, so this decoy is met first.
            0 => $"{year}_{EarlyStems[material[0] % EarlyStems.Length]}",
            1 => $"{MiddleStems[material[0] % MiddleStems.Length]}_{year}",
            _ => $"{LateStems[material[0] % LateStems.Length]}_{year}",
        };
        return $"{lead}_{discriminator}{extension}";
    }

    /// <summary>
    /// The machine-local seed, created on first use. Returns a process-lifetime random seed when it
    /// cannot be persisted, so decoys are still unguessable even if the state directory is
    /// unwritable — only cross-run orphan recovery is lost, and the manifest covers that.
    /// </summary>
    public static byte[] LoadOrCreateSeed(string? statePath = null)
    {
        var path = statePath ?? SeedPath;
        if (!AutomaticFileAccess.IsLocal(path))
        {
            return RandomNumberGenerator.GetBytes(32);
        }
        try
        {
            if (File.Exists(path))
            {
                var existing = File.ReadAllBytes(path);
                if (existing.Length == 32)
                {
                    return existing;
                }
            }
        }
        catch (Exception ex) when (ex is IOException
                                     or UnauthorizedAccessException
                                     or System.Security.SecurityException)
        {
            return RandomNumberGenerator.GetBytes(32);
        }

        var seed = RandomNumberGenerator.GetBytes(32);
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllBytes(path, seed);
        }
        catch (Exception ex) when (ex is IOException
                                     or UnauthorizedAccessException
                                     or System.Security.SecurityException)
        {
            // Unpersisted is still unguessable for this run.
        }
        return seed;
    }

    /// <summary>Where the decoy seed is kept, beside WinSight's other per-user state.</summary>
    public static string SeedPath => Path.Combine(StateDirectory, "canary-seed.bin");

    /// <summary>
    /// The record of what was planted, so a run that ended without disposing can still be cleaned up
    /// even though the names carry no recognisable marker.
    /// </summary>
    public static string ManifestPath => Path.Combine(StateDirectory, "canary-manifest.txt");

    private static string StateDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "WinSight");
}
