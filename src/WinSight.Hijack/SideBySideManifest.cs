using System.Xml;

namespace WinSight.Hijack;

/// <summary>A side-by-side assembly an image's manifest depends on.</summary>
/// <param name="Name">The assembly name, <c>Microsoft.VC90.CRT</c>.</param>
/// <param name="PublicKeyToken">Its publisher key; null for a private assembly, which the store never holds.</param>
/// <param name="ProcessorArchitecture">As written: <c>amd64</c>, <c>x86</c>, <c>*</c>, or null.</param>
public sealed record SideBySideAssembly(string Name, string? PublicKeyToken, string? ProcessorArchitecture);

/// <summary>
/// Reads the dependencies an image's embedded manifest (<c>RT_MANIFEST</c>) declares.
/// </summary>
/// <remarks>
/// <b>Why it is read at all (RA-04).</b> The loader resolves an import out of WinSxS only through an
/// activation context, and an executable's context is built from the assemblies its own manifest
/// names. A file of the same name elsewhere in the store - another architecture, a feature staged
/// but not installed, an unrelated component - serves nothing, yet was taken as proof the import
/// resolved.
///
/// <b>Hostile input, parsed defensively.</b> No DTD, no external resolution, a character cap, a
/// dependency cap. A manifest that does not parse yields null - "cannot tell" - never an empty list,
/// which would mean "binds nothing" and could turn an unreadable manifest into a finding.
/// </remarks>
public static class SideBySideManifest
{
    /// <summary>Manifests are a few kilobytes; a larger resource is refused, not parsed.</summary>
    public const int MaximumBytes = 256 * 1024;

    private const int MaxDependencies = 64;

    /// <summary>
    /// The dependencies declared by <paramref name="manifest"/>, empty when it declares none, null
    /// when it cannot be parsed.
    /// </summary>
    public static IReadOnlyList<SideBySideAssembly>? ReadDependencies(ReadOnlySpan<byte> manifest)
    {
        // Resource compilers pad a manifest with NULs or spaces to an alignment boundary. A UTF-16
        // one is trimmed a whole character at a time, or the high byte of its last '>' would go.
        var utf16 = manifest.Length >= 2 && manifest[0] == 0xFF && manifest[1] == 0xFE;
        var end = manifest.Length;
        if (utf16)
        {
            end -= end % 2;
            while (end > 2 && manifest[end - 1] == 0 && manifest[end - 2] is 0 or (byte)' ' or (byte)'\r' or (byte)'\n' or (byte)'\t')
            {
                end -= 2;
            }
        }
        else
        {
            while (end > 0 && manifest[end - 1] is 0 or (byte)' ' or (byte)'\r' or (byte)'\n' or (byte)'\t')
            {
                end--;
            }
        }
        if (end == 0 || end > MaximumBytes)
        {
            return null;
        }

        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersInDocument = MaximumBytes,
            MaxCharactersFromEntities = 0,
            IgnoreComments = true,
            IgnoreProcessingInstructions = true,
            IgnoreWhitespace = true,
        };
        var dependencies = new List<SideBySideAssembly>();
        try
        {
            using var stream = new MemoryStream(manifest[..end].ToArray(), writable: false);
            using var reader = XmlReader.Create(stream, settings);
            // Depth of the dependentAssembly element being read, or -1 outside one.
            var dependentDepth = -1;
            var identified = false;
            while (reader.Read())
            {
                if (reader.NodeType == XmlNodeType.EndElement && reader.Depth == dependentDepth)
                {
                    dependentDepth = -1;
                    continue;
                }
                if (reader.NodeType != XmlNodeType.Element)
                {
                    continue;
                }
                if (reader.LocalName == "dependentAssembly" && dependentDepth < 0)
                {
                    if (!reader.IsEmptyElement)
                    {
                        dependentDepth = reader.Depth;
                        identified = false;
                    }
                    continue;
                }
                // The identity that names the dependency is the first one inside it.
                if (dependentDepth >= 0 && !identified && reader.LocalName == "assemblyIdentity")
                {
                    identified = true;
                    if (reader.GetAttribute("name") is { Length: > 0 } name)
                    {
                        if (dependencies.Count == MaxDependencies)
                        {
                            return null;
                        }
                        dependencies.Add(new SideBySideAssembly(
                            name,
                            NullIfEmpty(reader.GetAttribute("publicKeyToken")),
                            NullIfEmpty(reader.GetAttribute("processorArchitecture"))));
                    }
                }
            }
        }
        catch (XmlException)
        {
            return null;
        }
        return dependencies;
    }

    private static string? NullIfEmpty(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
