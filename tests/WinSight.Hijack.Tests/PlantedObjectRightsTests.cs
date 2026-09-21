using System.Security.AccessControl;

using WinSight.Hijack;

using Xunit;

namespace WinSight.Hijack.Tests;

/// <summary>
/// Creating a file and creating a subdirectory are separate rights, and an inherit-only entry grants
/// neither on the directory that carries it.
/// </summary>
/// <remarks>
/// <b>The two defects.</b> The system drive root's default ACL grants Authenticated Users
/// <c>(AD)</c> - create subdirectories - and <c>(OI)(CI)(IO)(M)</c> - Modify, but only for what is
/// created beneath it. The elevated check read both as "can plant a file in C:\", so every unquoted
/// service path graded Exploitable through <c>C:\Program.exe</c>, a file no standard user can
/// create. The unelevated check made the opposite mistake for PATH: it asked whether a file could be
/// created in the parent of an absent PATH directory, and a standard user cannot create a file in
/// C:\ - so a stale entry such as <c>C:\Python27</c>, which any user can recreate and fill, was
/// reported as safe.
/// </remarks>
public sealed class PlantedObjectRightsTests
{
    /// <summary>The stock system-drive-root DACL, reduced to the two entries that matter here.</summary>
    private const string SystemDriveRootLike =
        "D:(A;OICIIO;0x1301bf;;;AU)(A;;0x4;;;AU)(A;OICI;0x1200a9;;;BU)";

    [Fact]
    public void TheSystemDriveRootGrantsFoldersNotFilesToAStandardUser()
    {
        var security = FromSddl(SystemDriveRootLike);

        Assert.False(UnprivilegedWriteAccess.IsGrantedBy(security, PlantedObject.File));
        Assert.True(UnprivilegedWriteAccess.IsGrantedBy(security, PlantedObject.Directory));
    }

    [Fact]
    public void AnInheritOnlyGrantGivesNothingOnTheDirectoryItself()
    {
        var security = FromSddl("D:(A;OICIIO;FA;;;BU)");

        Assert.False(UnprivilegedWriteAccess.IsGrantedBy(security, PlantedObject.File));
        Assert.False(UnprivilegedWriteAccess.IsGrantedBy(security, PlantedObject.Directory));
    }

    [Fact]
    public void AnInheritOnlyDenyDoesNotTakeBackAGrantOnTheDirectoryItself()
    {
        var security = FromSddl("D:(D;OICIIO;FA;;;BU)(A;;FA;;;BU)");

        Assert.True(UnprivilegedWriteAccess.IsGrantedBy(security, PlantedObject.File));
    }

    /// <summary>
    /// The real system drive root, whatever the session: no standard user can create a file there,
    /// so <c>C:\Program.exe</c> is never plantable. True under both evaluation methods - the filtered
    /// token lacks the right, and the well-known-group model ignores the inherit-only grant.
    /// </summary>
    [Fact]
    public void AFileInTheRealSystemDriveRootIsNotPlantable()
    {
        var root = Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.System))!;
        var candidate = Path.Combine(root, $"winsight-probe-{Guid.NewGuid():N}.exe");

        Assert.False(new WritabilityProbe().CanCreate(candidate));
    }

    /// <summary>
    /// The well-known-group fallback reads the binary descriptor exactly as the SDDL model does.
    /// </summary>
    [Fact]
    public void TheFallbackReadsABinaryDescriptorLikeTheSddlModel()
    {
        var descriptor = new RawSecurityDescriptor("O:SYG:SY" + SystemDriveRootLike);
        var bytes = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(bytes, 0);

        Assert.False(UnprivilegedWriteAccess.IsGrantedByDescriptor(bytes, PlantedObject.File));
        Assert.True(UnprivilegedWriteAccess.IsGrantedByDescriptor(bytes, PlantedObject.Directory));
    }

    /// <summary>
    /// The scanner and its triage ask the same probe, so every unanswerable question reaches the
    /// coverage count the report is built from.
    /// </summary>
    [Fact]
    public void TheScannerAndItsTriageShareOneProbe()
    {
        var scanner = new HijackScanner();
        const System.Reflection.BindingFlags Instance =
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic;

        var scannerProbe = typeof(HijackScanner).GetField("_probe", Instance)!.GetValue(scanner);
        var triage = typeof(HijackScanner).GetField("_triage", Instance)!.GetValue(scanner)!;
        var triageProbe = typeof(HijackTriage).GetField("_probe", Instance)!.GetValue(triage);

        Assert.NotNull(scannerProbe);
        Assert.Same(scannerProbe, triageProbe);
    }

    [Fact]
    public void AnAbsentPathEntryWhoseParentAllowsNewFoldersIsExploitable()
    {
        var parent = Path.GetTempPath().TrimEnd('\\');
        var absent = Path.Combine(parent, $"missing-{Guid.NewGuid():N}");
        var probe = new FoldersOnly(parent);

        var finding = new HijackTriage(probe).AssessPathEntry(absent);

        Assert.Equal(HijackExposure.Exploitable, finding?.Exposure);
        Assert.Equal([absent], probe.AskedForDirectories);
    }

    [Fact]
    public void ANestedAbsentPathEntryIsAskedAboutItsFirstMissingFolder()
    {
        var parent = Path.GetTempPath().TrimEnd('\\');
        var firstMissing = Path.Combine(parent, $"missing-{Guid.NewGuid():N}");
        var absent = Path.Combine(firstMissing, "bin");
        var probe = new FoldersOnly(parent);

        var finding = new HijackTriage(probe).AssessPathEntry(absent);

        Assert.Equal(HijackExposure.Exploitable, finding?.Exposure);
        Assert.Equal(absent, finding?.ActionablePath);
        Assert.Equal([firstMissing], probe.AskedForDirectories);
    }

    [Fact]
    public void AnAbsentPathEntryWhereNoFolderCanBeCreatedStaysQuiet()
    {
        var absent = Path.Combine(Path.GetTempPath(), $"missing-{Guid.NewGuid():N}", "bin");

        Assert.Null(new HijackTriage(new FoldersOnly()).AssessPathEntry(absent));
    }

    [Fact]
    public void TheRealDirectoryProbeAnswersAndLeavesNothingBehind()
    {
        var parent = Path.Combine(Path.GetTempPath(), $"winsight-probe-{Guid.NewGuid():N}");
        Directory.CreateDirectory(parent);
        try
        {
            var answer = new WritabilityProbe().CanCreateDirectory(Path.Combine(parent, "absent"));

            Assert.Empty(Directory.EnumerateFileSystemEntries(parent));
            Assert.True(UnprivilegedWriteAccess.TryIsGrantedIn(
                parent, PlantedObject.Directory, out var granted, out var evaluation));
            Assert.Equal(granted, answer);
            // The test user's own directory: yes with the effective token; the well-known-group
            // model does not see a grant to one named user and consistently says no.
            Assert.Equal(evaluation == WriteAccessEvaluation.EffectiveAccess, answer);
        }
        finally
        {
            Directory.Delete(parent, recursive: true);
        }
    }

    [Fact]
    public void AnExistingDirectoryIsNeverReportedAsCreatable()
    {
        var existing = Path.Combine(Path.GetTempPath(), $"winsight-probe-{Guid.NewGuid():N}");
        Directory.CreateDirectory(existing);
        try
        {
            Assert.False(new WritabilityProbe(elevated: false).CanCreateDirectory(existing));
            Assert.False(new WritabilityProbe(elevated: true).CanCreateDirectory(existing));
        }
        finally
        {
            Directory.Delete(existing);
        }
    }

    private static DirectorySecurity FromSddl(string sddl)
    {
        var security = new DirectorySecurity();
        security.SetSecurityDescriptorSddlForm("O:SYG:SY" + sddl);
        return security;
    }

    /// <summary>Lets folders, never files, be created in the given parents, and records what it
    /// was asked about.</summary>
    private sealed class FoldersOnly(params string[] parents) : IWritabilityProbe
    {
        public List<string> AskedForDirectories { get; } = [];

        public bool CanCreate(string path) => false;

        public bool CanCreateDirectory(string path)
        {
            AskedForDirectories.Add(path);
            return Path.GetDirectoryName(path) is { } parent
                   && parents.Any(p => string.Equals(p.TrimEnd('\\'), parent.TrimEnd('\\'),
                       StringComparison.OrdinalIgnoreCase));
        }
    }
}
