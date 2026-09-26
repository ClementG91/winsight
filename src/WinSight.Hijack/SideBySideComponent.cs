using System.Text.RegularExpressions;

namespace WinSight.Hijack;

/// <summary>
/// The assembly a folder of the WinSxS store holds, read from the folder's name: architecture,
/// assembly name and publisher key.
/// </summary>
/// <remarks>
/// A component folder is <c>amd64_microsoft.vc90.crt_1fc8b3b9a1e18e3b_9.0.30729.9635_none_08e2c157a83ed5da</c>:
/// architecture, name, key, version, culture, hash. Under <c>Fusion</c> the version is a subfolder
/// instead. Names contain underscores (<c>aspnet_compiler</c>) and long ones are shortened around
/// <c>..</c>, so the name is what lies between the architecture and the fixed fields read from the
/// right. Measured on Windows 11 26200: 25 766 of 25 775 top-level folders parse; the nine others are
/// the store's own bookkeeping.
/// </remarks>
internal sealed partial record SideBySideComponent(string Architecture, string Name, string PublicKeyToken)
{
    /// <summary>A file in no component folder: counted as present, never as bound.</summary>
    public static readonly SideBySideComponent Unattributed = new(string.Empty, string.Empty, string.Empty);

    /// <summary>Publisher keys shared by every Windows component: a shared key says nothing about dependencies.</summary>
    private static readonly HashSet<string> WindowsKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "31bf3856ad364e35", "6595b64144ccf1df", "b03f5f7f11d50a3a", "b77a5c561934e089",
    };

    /// <summary>
    /// The folder's component: parsed from its own name at the top level and directly under
    /// <c>Fusion</c>, inherited from its parent below that.
    /// </summary>
    public static SideBySideComponent ForDirectory(string path, int depth, string parent, SideBySideComponent parentComponent)
    {
        var name = Path.GetFileName(path);
        if (depth == 1)
        {
            return Parse(name, versioned: true) ?? Unattributed;
        }
        if (depth == 2 && Path.GetFileName(parent).Equals("Fusion", StringComparison.OrdinalIgnoreCase))
        {
            return Parse(name, versioned: false) ?? Unattributed;
        }
        return parentComponent;
    }

    /// <summary>The component a folder name describes, or null when it is not one.</summary>
    internal static SideBySideComponent? Parse(string folder, bool versioned)
    {
        var parts = folder.Split('_');
        // Key, then version (top level only), culture and hash.
        var fixedFields = versioned ? 4 : 3;
        if (parts.Length < fixedFields + 2)
        {
            return null;
        }
        var key = parts[^fixedFields];
        if (!KeyPattern().IsMatch(key))
        {
            return null;
        }
        return new SideBySideComponent(
            parts[0].ToLowerInvariant(),
            string.Join('_', parts[1..^fixedFields]).ToLowerInvariant(),
            key.ToLowerInvariant());
    }

    /// <summary>
    /// Whether a process of this bitness can load from this component. Unknown bitness, managed
    /// (<c>msil</c>) and unattributed copies fit either way, which only ever widens the "unknown".
    /// </summary>
    public bool Fits(bool? is64Bit) => is64Bit switch
    {
        null => true,
        _ when Architecture is "" or "msil" => true,
        true => Architecture is "amd64" or "arm64",
        false => Architecture is "x86" or "wow64" or "arm",
    };

    /// <summary>
    /// Whether an image binding <paramref name="assembly"/> reaches this component: it is that
    /// assembly (any version, since publisher policy may redirect), or the C runtime of the same
    /// Visual C++ version that a Visual C++ library (MFC, ATL, OpenMP) brings with it.
    /// </summary>
    /// <remarks>
    /// A shared publisher key alone is not enough. The manifest is read from the scanned image, so
    /// its names are whatever the file says: an image declaring a made-up assembly under the Visual
    /// C++ key reached every Visual C++ component on the machine, and an import answered by any of
    /// them read as resolved. The one dependency modelled is the one every Visual C++ library
    /// declares; anything else reached through a bound assembly stays unknown.
    /// </remarks>
    public bool IsReachedThrough(SideBySideAssembly assembly)
    {
        if (ReferenceEquals(this, Unattributed) || assembly.PublicKeyToken is not { } key
            || !key.Equals(PublicKeyToken, StringComparison.OrdinalIgnoreCase)
            || !ArchitectureMatches(assembly.ProcessorArchitecture))
        {
            return false;
        }
        return NameMatches(assembly.Name) || (!WindowsKeys.Contains(key) && IsRuntimeOf(assembly.Name));
    }

    /// <summary>True when this component is the CRT of the Visual C++ version <paramref name="library"/> belongs to.</summary>
    private bool IsRuntimeOf(string library)
    {
        var match = VisualCppLibraryPattern().Match(library);
        if (!match.Success)
        {
            return false;
        }
        var family = $"microsoft.{match.Groups["version"].Value.ToLowerInvariant()}.";
        return Name == family + "crt" || Name == family + "debugcrt";
    }

    /// <summary>
    /// Assemblies that declare no dependencies of their own, so binding only these proves nothing
    /// else in the store is reachable.
    /// </summary>
    public static bool IsLeaf(SideBySideAssembly assembly) =>
        assembly.Name.Equals("Microsoft.Windows.Common-Controls", StringComparison.OrdinalIgnoreCase)
        || assembly.Name.Equals("Microsoft.Windows.GdiPlus", StringComparison.OrdinalIgnoreCase)
        || CrtPattern().IsMatch(assembly.Name);

    private bool NameMatches(string assemblyName)
    {
        var wanted = assemblyName.ToLowerInvariant();
        var cut = Name.IndexOf("..", StringComparison.Ordinal);
        if (cut < 0)
        {
            return wanted == Name;
        }
        var prefix = Name[..cut];
        var suffix = Name[(cut + 2)..];
        return wanted.Length >= prefix.Length + suffix.Length && wanted.StartsWith(prefix, StringComparison.Ordinal)
            && wanted.EndsWith(suffix, StringComparison.Ordinal);
    }

    private bool ArchitectureMatches(string? wanted) =>
        wanted is null or "*"
        || wanted.Equals(Architecture, StringComparison.OrdinalIgnoreCase)
        || (wanted.Equals("x86", StringComparison.OrdinalIgnoreCase) && Architecture == "wow64");

    [GeneratedRegex("^([0-9a-fA-F]{16}|none)$")]
    private static partial Regex KeyPattern();

    [GeneratedRegex(@"^Microsoft\.VC\d+\.(Debug)?CRT$", RegexOptions.IgnoreCase)]
    private static partial Regex CrtPattern();

    [GeneratedRegex(@"^Microsoft\.(?<version>VC\d+)\.(Debug)?(MFC|MFCLOC|ATL|OpenMP)$", RegexOptions.IgnoreCase)]
    private static partial Regex VisualCppLibraryPattern();
}
