using System.Security.AccessControl;
using WinSight.FirewallService;
using Xunit;

namespace WinSight.FirewallService.Tests;

public sealed class ServicePathRightsTests
{
    // Regression for the composite-mask defect: Modify/FullControl share the Read/Execute bits, so a
    // bitwise-AND-non-zero probe against them mis-classified a plain Read&Execute grant as writable.
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Map_ReadAndExecute_IsNotDangerous(bool isDirectory) =>
        Assert.Equal(DangerousPathAccess.None,
            ServicePathRights.Map(FileSystemRights.ReadAndExecute, isDirectory));

    [Theory]
    [InlineData(FileSystemRights.Read)]
    [InlineData(FileSystemRights.ReadAndExecute)]
    [InlineData(FileSystemRights.ListDirectory | FileSystemRights.Traverse | FileSystemRights.ReadAttributes)]
    public void Map_ReadOnlyRights_AreNeverDangerous(FileSystemRights rights)
    {
        Assert.Equal(DangerousPathAccess.None, ServicePathRights.Map(rights, isDirectory: true));
        Assert.Equal(DangerousPathAccess.None, ServicePathRights.Map(rights, isDirectory: false));
    }

    // A genuine Modify/FullControl grant must still be detected via the atomic bits it contains.
    [Fact]
    public void Map_Modify_OnFile_FlagsWriteData() =>
        Assert.True(ServicePathRights.Map(FileSystemRights.Modify, isDirectory: false)
            .HasFlag(DangerousPathAccess.WriteData));

    [Fact]
    public void Map_FullControl_OnFile_FlagsWriteAndDeleteAndOwnership()
    {
        var mapped = ServicePathRights.Map(FileSystemRights.FullControl, isDirectory: false);
        Assert.True(mapped.HasFlag(DangerousPathAccess.WriteData));
        Assert.True(mapped.HasFlag(DangerousPathAccess.Delete));
        Assert.True(mapped.HasFlag(DangerousPathAccess.ChangePermissions));
        Assert.True(mapped.HasFlag(DangerousPathAccess.TakeOwnership));
    }

    // CreateDirectories == AppendData (0x4): benign on a directory (adding a sub-directory cannot
    // tamper with an existing protected child) but dangerous on a file (appending grows the binary).
    [Fact]
    public void Map_CreateDirectories_OnDirectory_IsBenign() =>
        Assert.Equal(DangerousPathAccess.None,
            ServicePathRights.Map(FileSystemRights.CreateDirectories, isDirectory: true));

    [Fact]
    public void Map_AppendData_OnFile_IsDangerous() =>
        Assert.Equal(DangerousPathAccess.AppendData,
            ServicePathRights.Map(FileSystemRights.AppendData, isDirectory: false));

    // CreateFiles == WriteData (0x2): planting a file in a directory enables DLL side-loading.
    [Fact]
    public void Map_CreateFiles_OnDirectory_IsDangerous() =>
        Assert.Equal(DangerousPathAccess.CreateFiles,
            ServicePathRights.Map(FileSystemRights.CreateFiles, isDirectory: true));

    [Fact]
    public void Map_WriteData_OnFile_IsDangerous() =>
        Assert.Equal(DangerousPathAccess.WriteData,
            ServicePathRights.Map(FileSystemRights.WriteData, isDirectory: false));

    [Theory]
    [InlineData(FileSystemRights.Delete, DangerousPathAccess.Delete)]
    [InlineData(FileSystemRights.DeleteSubdirectoriesAndFiles, DangerousPathAccess.DeleteChildren)]
    [InlineData(FileSystemRights.ChangePermissions, DangerousPathAccess.ChangePermissions)]
    [InlineData(FileSystemRights.TakeOwnership, DangerousPathAccess.TakeOwnership)]
    public void Map_TamperRights_AreDangerousOnAnyType(FileSystemRights rights, DangerousPathAccess expected)
    {
        Assert.Equal(expected, ServicePathRights.Map(rights, isDirectory: true));
        Assert.Equal(expected, ServicePathRights.Map(rights, isDirectory: false));
    }
}

public sealed class ServicePathTrustPolicyTests
{
    private const string SystemSid = "S-1-5-18";
    private const string AdministratorsSid = "S-1-5-32-544";
    private const string TrustedInstallerSid = "S-1-5-80-956008885";
    private const string UserSid = "S-1-5-21-1000";
    private readonly ServicePathTrustPolicy _policy = new(SystemSid, AdministratorsSid, TrustedInstallerSid);

    [Theory]
    [InlineData(SystemSid, true, false, true)]
    [InlineData(AdministratorsSid, true, true, true)]
    [InlineData(TrustedInstallerSid, false, false, true)]
    [InlineData(TrustedInstallerSid, true, false, false)]
    [InlineData(TrustedInstallerSid, false, true, false)]
    [InlineData(UserSid, false, false, false)]
    public void Evaluate_OwnerMatrix(string owner, bool isLeaf, bool isProductPath, bool trusted)
    {
        var decision = _policy.Evaluate(Component(owner: owner), isLeaf, isProductPath);
        Assert.Equal(trusted, decision.IsTrusted);
        Assert.Equal(trusted ? PathTrustCode.Trusted : PathTrustCode.UntrustedOwner, decision.Code);
    }

    [Theory]
    [InlineData(true, false, DangerousPathAccess.WriteData, PathTrustCode.WritableByUnprivilegedPrincipal)]
    [InlineData(true, true, DangerousPathAccess.DeleteChildren, PathTrustCode.WritableByUnprivilegedPrincipal)]
    [InlineData(false, false, DangerousPathAccess.TakeOwnership, PathTrustCode.Trusted)]
    [InlineData(false, true, DangerousPathAccess.ChangePermissions, PathTrustCode.Trusted)]
    [InlineData(true, false, DangerousPathAccess.None, PathTrustCode.Trusted)]
    public void Evaluate_ConservativeAllowDenyAndInheritanceMatrix(
        bool allow, bool inherited, DangerousPathAccess access, PathTrustCode expected)
    {
        var component = Component(rules: [new(UserSid, allow, inherited, access)]);
        Assert.Equal(expected, _policy.Evaluate(component, isLeaf: true, isProductPath: false).Code);
    }

    [Theory]
    [InlineData(SystemSid)]
    [InlineData(AdministratorsSid)]
    [InlineData(TrustedInstallerSid)]
    public void Evaluate_PrivilegedDangerousAllow_IsTrusted(string principal)
    {
        var component = Component(rules: [new(principal, true, true, DangerousPathAccess.Delete)]);
        Assert.True(_policy.Evaluate(component, isLeaf: true, isProductPath: false).IsTrusted);
    }

    [Fact]
    public void EffectiveRights_EarlierApplicableDenyNeutralizesAllow_ButLaterDenyDoesNot()
    {
        var deny = new PathAccessMetadata(UserSid, false, false, DangerousPathAccess.WriteData);
        var allow = new PathAccessMetadata(UserSid, true, true, DangerousPathAccess.WriteData);

        Assert.True(_policy.Evaluate(Component(rules: [deny, allow]), true, false).IsTrusted);
        Assert.Equal(PathTrustCode.WritableByUnprivilegedPrincipal,
            _policy.Evaluate(Component(rules: [allow, deny]), true, false).Code);
    }

    [Theory]
    [InlineData(PrincipalApplicability.Yes, PathTrustCode.Trusted)]
    [InlineData(PrincipalApplicability.No, PathTrustCode.WritableByUnprivilegedPrincipal)]
    [InlineData(PrincipalApplicability.Indeterminate, PathTrustCode.WritableByUnprivilegedPrincipal)]
    public void EffectiveRights_PrincipalApplicabilityFailsClosed(
        PrincipalApplicability applicability, PathTrustCode expected)
    {
        var policy = new ServicePathTrustPolicy(SystemSid, AdministratorsSid, TrustedInstallerSid,
            new FixedApplicability(applicability));
        var rules = new[]
        {
            new PathAccessMetadata("group", false, true, DangerousPathAccess.Delete),
            new PathAccessMetadata(UserSid, true, false, DangerousPathAccess.Delete),
        };

        Assert.Equal(expected, policy.Evaluate(Component(rules: rules), true, false).Code);
    }

    private sealed class FixedApplicability(PrincipalApplicability result) : IPathPrincipalApplicability
    {
        public PrincipalApplicability Applies(string acePrincipalSid, string targetPrincipalSid) => result;
    }

    private static PathComponentMetadata Component(
        string owner = SystemSid,
        IReadOnlyList<PathAccessMetadata>? rules = null) =>
        new(@"C:\trusted\service.exe", true, false, false, owner, "identity-1", rules ?? []);
}

public sealed class WindowsServicePathTrustInspectorTests
{
    [Fact]
    public void InspectExecutable_NestedReparsePoint_Denies()
    {
        var source = FakeMetadata.Trusted(@"C:\trusted\service.exe");
        source.Components[@"C:\trusted"] = source.Components[@"C:\trusted"] with { IsReparsePoint = true };
        Assert.Equal(PathTrustCode.ReparsePoint,
            new WindowsServicePathTrustInspector(source).InspectExecutable(@"C:\trusted\service.exe").Code);
    }

    [Fact]
    public void InspectExecutable_MetadataReadFailure_DeniesWithStableCode()
    {
        var source = FakeMetadata.Trusted(@"C:\trusted\service.exe");
        source.ThrowOnRead = @"C:\trusted";
        Assert.Equal(PathTrustCode.InspectionFailed,
            new WindowsServicePathTrustInspector(source).InspectExecutable(@"C:\trusted\service.exe").Code);
    }

    [Fact]
    public void InspectExecutable_TrustedInstallerSidResolutionFailure_Denies()
    {
        var source = FakeMetadata.Trusted(@"C:\trusted\service.exe");
        source.FailSidResolution = true;
        Assert.Equal(PathTrustCode.InspectionFailed,
            new WindowsServicePathTrustInspector(source).InspectExecutable(@"C:\trusted\service.exe").Code);
    }

    [Fact]
    public void Evidence_BindsEveryComponentAndRevalidateDetectsIdentityChange()
    {
        var source = FakeMetadata.Trusted(@"C:\trusted\service.exe");
        var inspector = new WindowsServicePathTrustInspector(source);
        var evidence = inspector.InspectExecutableEvidence(@"C:\trusted\service.exe");
        Assert.True(evidence.Decision.IsTrusted);
        Assert.Equal(3, evidence.ComponentIdentities.Count);

        source.Components[@"C:\trusted"] = source.Components[@"C:\trusted"] with { StableIdentity = "changed" };
        Assert.Equal(PathTrustCode.IdentityChanged, inspector.Revalidate(evidence).Code);
    }

    [Theory]
    [InlineData("owner", PathTrustCode.UntrustedOwner)]
    [InlineData("acl", PathTrustCode.WritableByUnprivilegedPrincipal)]
    [InlineData("reparse", PathTrustCode.ReparsePoint)]
    [InlineData("type", PathTrustCode.IdentityChanged)]
    [InlineData("topology", PathTrustCode.IdentityChanged)]
    public void RevalidateTrustMetadata_SameIdentityButTrustMetadataChangeDenies(string mutation, PathTrustCode expected)
    {
        var source = FakeMetadata.Trusted(@"C:\trusted\service.exe");
        var inspector = new WindowsServicePathTrustInspector(source);
        var evidence = inspector.InspectExecutableEvidence(@"C:\trusted\service.exe");
        var current = source.Components[@"C:\trusted"];
        if (mutation == "owner") source.Components[@"C:\trusted"] = current with { OwnerSid = "S-1-5-21-1000" };
        if (mutation == "acl") source.Components[@"C:\trusted"] = current with
        {
            AccessRules = [new("S-1-5-21-1000", true, false, DangerousPathAccess.WriteData)],
        };
        if (mutation == "reparse") source.Components[@"C:\trusted"] = current with { IsReparsePoint = true };
        if (mutation == "type") source.Components[@"C:\trusted"] = current with { IsDirectory = false };
        if (mutation == "topology") source.Components.Remove(@"C:\trusted");

        Assert.Equal(expected, inspector.Revalidate(evidence).Code);
    }

    private sealed class FakeMetadata : IPathMetadataSource
    {
        public Dictionary<string, PathComponentMetadata> Components { get; } =
            new(StringComparer.OrdinalIgnoreCase);
        public string? ThrowOnRead { get; set; }
        public bool FailSidResolution { get; set; }

        public static FakeMetadata Trusted(string leaf)
        {
            var source = new FakeMetadata();
            foreach (var path in new[] { @"C:\", @"C:\trusted", leaf })
                source.Components[path] = new(path, true, path != leaf, false, "S-1-5-18", path, []);
            return source;
        }

        public string Canonicalize(string path) => path;
        public IReadOnlyList<string> ExistingComponents(string canonicalPath) =>
            Components.Keys.Where(path => canonicalPath.StartsWith(path, StringComparison.OrdinalIgnoreCase))
                .OrderBy(path => path.Length).ToArray();
        public PathComponentMetadata Read(string canonicalPath)
        {
            if (string.Equals(ThrowOnRead, canonicalPath, StringComparison.OrdinalIgnoreCase)) throw new IOException("synthetic");
            return Components[canonicalPath];
        }
        public string ResolveTrustedInstallerSid() => FailSidResolution
            ? throw new System.Security.Principal.IdentityNotMappedException("synthetic")
            : "S-1-5-80-956008885";
    }
}
