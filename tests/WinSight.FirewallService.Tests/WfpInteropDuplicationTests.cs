using System.Text.RegularExpressions;

using Xunit;

namespace WinSight.FirewallService.Tests;

/// <summary>
/// The six WFP declarations that exist twice in this assembly must stay identical.
/// </summary>
/// <remarks>
/// <b>Why they exist twice at all.</b> <c>WfpSelfTest</c> is a read-only probe and repeats six of
/// <c>WfpProvisioning</c>'s <c>LibraryImport</c> declarations verbatim. Merging them looks obvious
/// and is not free: <c>WfpProvisioning.NativeMethods</c> is private, and widening it forces every
/// struct in its signatures — <c>FWPM_FILTER0</c>, <c>FWPM_PROVIDER0</c>, <c>FWPM_SUBLAYER0</c> and
/// what they contain — to widen with it. That is a large change to the most safety-critical interop
/// in the product, for a tidiness gain.
///
/// <b>Why the duplication still needs a guard.</b> Two declarations of one native function is an
/// invitation to fix a marshalling bug in whichever copy somebody happens to open, and interop is
/// exactly where that stays silent: a wrong signature is a wrong error code, or a filter that
/// installs and never matches, not a crash. This makes the drift impossible to ship instead of
/// pretending the copies are not there.
/// </remarks>
public sealed class WfpInteropDuplicationTests
{
    private static readonly string RepositoryRoot = Path.GetFullPath(Path.Combine(
        AppContext.BaseDirectory, "..", "..", "..", "..", ".."));

    /// <summary>Every <c>LibraryImport</c> declaration in a file, keyed by native function name.</summary>
    private static Dictionary<string, string> Declarations(string fileName)
    {
        var source = File.ReadAllText(
            Path.Combine(RepositoryRoot, "src", "WinSight.FirewallService", fileName));

        var matches = Regex.Matches(
            source,
            @"\[LibraryImport\((?<attribute>[^\)]*)\)\]\s*internal\s+static\s+partial\s+(?<return>\w+)\s+(?<name>\w+)\((?<parameters>[^;]*?)\);",
            RegexOptions.Singleline);

        return matches.ToDictionary(
            match => match.Groups["name"].Value,
            match => Normalise(
                $"{match.Groups["attribute"].Value}|{match.Groups["return"].Value}|{match.Groups["parameters"].Value}"),
            StringComparer.Ordinal);
    }

    /// <summary>Line breaks and indentation differ between the two files; the contract does not.</summary>
    private static string Normalise(string declaration) =>
        Regex.Replace(declaration, @"\s+", " ").Trim();

    [Fact]
    public void TheProbeRepeatsOnlyDeclarationsProvisioningAlreadyHas()
    {
        var probe = Declarations("WfpSelfTest.cs");
        var provisioning = Declarations("WfpProvisioning.cs");

        // A declaration in the probe that provisioning does not have would be a third home for WFP
        // interop, which is the thing this guard exists to prevent growing.
        var unique = probe.Keys.Where(name => !provisioning.ContainsKey(name)).Order(StringComparer.Ordinal);

        Assert.Empty(unique);
    }

    [Fact]
    public void EveryDuplicatedDeclarationIsCharacterForCharacterTheSame()
    {
        var probe = Declarations("WfpSelfTest.cs");
        var provisioning = Declarations("WfpProvisioning.cs");

        var drifted = probe
            .Where(entry => provisioning.TryGetValue(entry.Key, out var other) && other != entry.Value)
            .Select(entry =>
                $"{entry.Key}\n  WfpSelfTest.cs:     {entry.Value}\n  WfpProvisioning.cs: {provisioning[entry.Key]}")
            .ToArray();

        Assert.True(
            drifted.Length == 0,
            "These native declarations exist in both files and no longer agree. Interop that differs "
            + "between two copies fails silently — a wrong error code, or a filter that installs and "
            + "never matches:\n" + string.Join("\n", drifted));
    }

    /// <summary>
    /// Guards the guard: a regex that matched nothing would make both tests above vacuous.
    /// </summary>
    [Fact]
    public void TheDeclarationsAreActuallyBeingFound()
    {
        var probe = Declarations("WfpSelfTest.cs");
        var provisioning = Declarations("WfpProvisioning.cs");

        Assert.Equal(6, probe.Count);
        Assert.True(provisioning.Count >= probe.Count, "provisioning should hold at least the probe's set");
        Assert.Contains("FwpmEngineOpen0", probe.Keys);
        Assert.Contains("FwpmFilterEnum0", probe.Keys);
    }
}
