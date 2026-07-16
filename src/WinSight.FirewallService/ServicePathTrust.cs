using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace WinSight.FirewallService;

public enum PathTrustCode
{
    Trusted, InvalidPath, OutsideProgramData, MissingComponent, ReparsePoint,
    UntrustedOwner, WritableByUnprivilegedPrincipal, IdentityChanged, InspectionFailed,
}

[Flags]
public enum DangerousPathAccess
{
    None = 0, WriteData = 1, AppendData = 2, CreateFiles = 4, CreateDirectories = 8,
    Delete = 16, DeleteChildren = 32, ChangePermissions = 64, TakeOwnership = 128,
}

public static class ServicePathRights
{
    /// <summary>
    /// Translates a raw <see cref="FileSystemRights"/> mask into the dangerous-access flags that would
    /// let an unprivileged principal tamper with a trusted path component.
    /// </summary>
    /// <remarks>
    /// The composite rights <see cref="FileSystemRights.Modify"/> and <see cref="FileSystemRights.FullControl"/>
    /// MUST NOT be probed with a bitwise-AND-non-zero test: they include the Read/Execute/Synchronize
    /// bits, so such a probe reports a harmless Read&amp;Execute grant as writable. Only the atomic
    /// write/delete/ownership bits are inspected; because Modify and FullControl are supersets that
    /// contain those atomic bits, a genuine Modify/FullControl grant is still detected.
    ///
    /// Windows overloads the write (0x2) and append (0x4) bits by object type. On a file they are
    /// WriteData/AppendData — overwriting or growing the binary, both dangerous. On a directory they are
    /// CreateFiles/CreateDirectories. Planting a new file (CreateFiles) enables DLL side-loading, so it
    /// stays dangerous; but creating a new sub-directory (CreateDirectories) cannot modify, replace, or
    /// delete an existing protected child — that needs Delete/DeleteChildren, which remain flagged — so
    /// it is not dangerous. Without this distinction no path under C:\ could ever be trusted, because the
    /// default C:\ ACL lets authenticated users create sub-directories (how "mkdir C:\foo" works).
    /// </remarks>
    public static DangerousPathAccess Map(FileSystemRights rights, bool isDirectory)
    {
        var result = DangerousPathAccess.None;
        // 0x2 — WriteData (file: overwrite) / CreateFiles (directory: plant → DLL side-load). Both dangerous.
        if ((rights & FileSystemRights.WriteData) != 0)
            result |= isDirectory ? DangerousPathAccess.CreateFiles : DangerousPathAccess.WriteData;
        // 0x4 — AppendData (file: grow the binary → dangerous) / CreateDirectories (directory: benign).
        if ((rights & FileSystemRights.AppendData) != 0 && !isDirectory)
            result |= DangerousPathAccess.AppendData;
        if ((rights & FileSystemRights.Delete) != 0) result |= DangerousPathAccess.Delete;
        if ((rights & FileSystemRights.DeleteSubdirectoriesAndFiles) != 0) result |= DangerousPathAccess.DeleteChildren;
        if ((rights & FileSystemRights.ChangePermissions) != 0) result |= DangerousPathAccess.ChangePermissions;
        if ((rights & FileSystemRights.TakeOwnership) != 0) result |= DangerousPathAccess.TakeOwnership;
        return result;
    }
}

public sealed record PathAccessMetadata(
    string PrincipalSid,
    bool IsAllow,
    bool IsInherited,
    DangerousPathAccess DangerousAccess);

public sealed record PathComponentMetadata(
    string CanonicalPath,
    bool Exists,
    bool IsDirectory,
    bool IsReparsePoint,
    string? OwnerSid,
    string StableIdentity,
    IReadOnlyList<PathAccessMetadata> AccessRules);

public enum PrincipalApplicability { No, Yes, Indeterminate }

public interface IPathPrincipalApplicability
{
    PrincipalApplicability Applies(string acePrincipalSid, string targetPrincipalSid);
}

public interface IPathMetadataSource
{
    string Canonicalize(string path);
    IReadOnlyList<string> ExistingComponents(string canonicalPath);
    PathComponentMetadata Read(string canonicalPath);
    string ResolveTrustedInstallerSid();
}

public sealed record PathTrustDecision(bool IsTrusted, PathTrustCode Code, string Message)
{
    public static PathTrustDecision Allow() => new(true, PathTrustCode.Trusted, "The path trust policy was satisfied.");
    public static PathTrustDecision Deny(PathTrustCode code) => new(false, code, code switch
    {
        PathTrustCode.InvalidPath => "The path is invalid.",
        PathTrustCode.OutsideProgramData => "The policy path is outside the trusted machine-data root.",
        PathTrustCode.MissingComponent => "A required path component is missing.",
        PathTrustCode.ReparsePoint => "A path component is a reparse point.",
        PathTrustCode.UntrustedOwner => "A path component has an untrusted owner.",
        PathTrustCode.WritableByUnprivilegedPrincipal => "A path component is writable by an unprivileged principal.",
        PathTrustCode.IdentityChanged => "A path component changed after inspection.",
        _ => "The path trust inspection could not be completed.",
    });
}

public sealed record PathTrustEvidence(
    PathTrustDecision Decision,
    string CanonicalPath,
    IReadOnlyDictionary<string, string> ComponentIdentities,
    IReadOnlyDictionary<string, PathComponentMetadata>? Components = null,
    string? ProductRoot = null);

public interface IServicePathTrustInspector
{
    PathTrustDecision InspectExecutable(string path);
    PathTrustDecision InspectPolicyStorage(string directory, string policyFile);

    PathTrustEvidence InspectExecutableEvidence(string path) =>
        new(InspectExecutable(path), path, new Dictionary<string, string>());

    PathTrustEvidence InspectPolicyStorageEvidence(string directory, string policyFile) =>
        new(InspectPolicyStorage(directory, policyFile), policyFile, new Dictionary<string, string>());

    PathTrustDecision Revalidate(PathTrustEvidence evidence) =>
        evidence.Decision.IsTrusted ? PathTrustDecision.Deny(PathTrustCode.InspectionFailed) : evidence.Decision;
}

/// <summary>
/// Deterministic owner/ACL policy. Ordered applicable Deny ACEs neutralize matching rights
/// before a later Allow is evaluated. Unknown group membership is never used to neutralize
/// an Allow, so indeterminate applicability remains fail-closed.
/// </summary>
public sealed class ServicePathTrustPolicy
{
    private readonly string _systemSid;
    private readonly string _administratorsSid;
    private readonly string _trustedInstallerSid;
    private readonly IPathPrincipalApplicability _applicability;

    public ServicePathTrustPolicy(
        string systemSid,
        string administratorsSid,
        string trustedInstallerSid,
        IPathPrincipalApplicability? applicability = null)
    {
        _systemSid = systemSid;
        _administratorsSid = administratorsSid;
        _trustedInstallerSid = trustedInstallerSid;
        _applicability = applicability ?? new ConservativePrincipalApplicability();
    }

    public PathTrustDecision Evaluate(PathComponentMetadata component, bool isLeaf, bool isProductPath)
    {
        if (!component.Exists) return PathTrustDecision.Deny(PathTrustCode.MissingComponent);
        if (component.IsReparsePoint) return PathTrustDecision.Deny(PathTrustCode.ReparsePoint);
        if (string.IsNullOrWhiteSpace(component.OwnerSid)) return PathTrustDecision.Deny(PathTrustCode.InspectionFailed);
        var trustedOwner = SidEquals(component.OwnerSid, _systemSid) || SidEquals(component.OwnerSid, _administratorsSid) ||
            (SidEquals(component.OwnerSid, _trustedInstallerSid) && !isLeaf && !isProductPath);
        if (!trustedOwner) return PathTrustDecision.Deny(PathTrustCode.UntrustedOwner);
        if (component.AccessRules is null) return PathTrustDecision.Deny(PathTrustCode.InspectionFailed);
        for (var allowIndex = 0; allowIndex < component.AccessRules.Count; allowIndex++)
        {
            var rule = component.AccessRules[allowIndex];
            if (string.IsNullOrWhiteSpace(rule.PrincipalSid)) return PathTrustDecision.Deny(PathTrustCode.InspectionFailed);
            if (!rule.IsAllow || rule.DangerousAccess == DangerousPathAccess.None || IsPrivileged(rule.PrincipalSid))
                continue;
            var effective = rule.DangerousAccess;
            // Windows evaluates the ordered DACL. Only an earlier applicable deny can
            // neutralize an allow; a later deny cannot revoke already granted rights.
            for (var denyIndex = 0; denyIndex < allowIndex && effective != DangerousPathAccess.None; denyIndex++)
            {
                var deny = component.AccessRules[denyIndex];
                if (!deny.IsAllow &&
                    _applicability.Applies(deny.PrincipalSid, rule.PrincipalSid) == PrincipalApplicability.Yes)
                    effective &= ~deny.DangerousAccess;
            }
            if (effective != DangerousPathAccess.None)
                return PathTrustDecision.Deny(PathTrustCode.WritableByUnprivilegedPrincipal);
        }
        return PathTrustDecision.Allow();
    }

    private bool IsPrivileged(string sid) => SidEquals(sid, _systemSid) || SidEquals(sid, _administratorsSid) ||
        SidEquals(sid, _trustedInstallerSid);
    private static bool SidEquals(string left, string right) =>
        string.Equals(left, right, StringComparison.OrdinalIgnoreCase);

    private sealed class ConservativePrincipalApplicability : IPathPrincipalApplicability
    {
        public PrincipalApplicability Applies(string acePrincipalSid, string targetPrincipalSid)
        {
            if (SidEquals(acePrincipalSid, targetPrincipalSid) ||
                acePrincipalSid is "S-1-1-0" or "S-1-5-11" or "S-1-5-32-545")
                return PrincipalApplicability.Yes;
            // Unknown group expansion is never used to turn a dangerous Allow into trust.
            return PrincipalApplicability.Indeterminate;
        }
    }
}

public sealed class WindowsServicePathTrustInspector : IServicePathTrustInspector
{
    private readonly IPathMetadataSource _metadata;

    public WindowsServicePathTrustInspector() : this(new WindowsPathMetadataSource()) { }
    public WindowsServicePathTrustInspector(IPathMetadataSource metadata) =>
        _metadata = metadata ?? throw new ArgumentNullException(nameof(metadata));

    public PathTrustDecision InspectExecutable(string path) => InspectExecutableEvidence(path).Decision;
    public PathTrustDecision InspectPolicyStorage(string directory, string policyFile) =>
        InspectPolicyStorageEvidence(directory, policyFile).Decision;

    public PathTrustEvidence InspectExecutableEvidence(string path) => Inspect(path, null);

    public PathTrustEvidence InspectPolicyStorageEvidence(string directory, string policyFile)
    {
        try
        {
            var root = _metadata.Canonicalize(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
            var canonicalDirectory = _metadata.Canonicalize(directory);
            var canonicalFile = _metadata.Canonicalize(policyFile);
            if (!IsContained(root, canonicalDirectory) || !IsContained(canonicalDirectory, canonicalFile))
                return Denied(canonicalFile, PathTrustCode.OutsideProgramData);
            var directoryEvidence = Inspect(canonicalDirectory, root);
            if (!directoryEvidence.Decision.IsTrusted) return directoryEvidence;
            var components = _metadata.ExistingComponents(canonicalFile);
            if (!components.Contains(canonicalFile, StringComparer.OrdinalIgnoreCase)) return directoryEvidence;
            return Inspect(canonicalFile, root);
        }
        catch (ArgumentException) { return Denied(string.Empty, PathTrustCode.InvalidPath); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SystemException)
        { return Denied(string.Empty, PathTrustCode.InspectionFailed); }
    }

    public PathTrustDecision Revalidate(PathTrustEvidence evidence)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        if (!evidence.Decision.IsTrusted) return evidence.Decision;
        try
        {
            if (evidence.Components is null) return PathTrustDecision.Deny(PathTrustCode.InspectionFailed);
            var currentPaths = _metadata.ExistingComponents(evidence.CanonicalPath);
            if (!currentPaths.ToHashSet(StringComparer.OrdinalIgnoreCase)
                .SetEquals(evidence.Components.Keys))
                return PathTrustDecision.Deny(PathTrustCode.IdentityChanged);
            var policy = new ServicePathTrustPolicy(
                new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null).Value,
                new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null).Value,
                _metadata.ResolveTrustedInstallerSid());
            foreach (var pair in evidence.Components)
            {
                var fresh = _metadata.Read(pair.Key);
                if (!string.Equals(fresh.StableIdentity, pair.Value.StableIdentity, StringComparison.Ordinal))
                    return PathTrustDecision.Deny(PathTrustCode.IdentityChanged);
                if (fresh.IsDirectory != pair.Value.IsDirectory)
                    return PathTrustDecision.Deny(PathTrustCode.IdentityChanged);
                var decision = policy.Evaluate(fresh,
                    pair.Key.Equals(evidence.CanonicalPath, StringComparison.OrdinalIgnoreCase),
                    evidence.ProductRoot is not null && IsContained(evidence.ProductRoot, pair.Key));
                if (!decision.IsTrusted) return decision;
            }
            return PathTrustDecision.Allow();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SystemException)
        { return PathTrustDecision.Deny(PathTrustCode.InspectionFailed); }
    }

    private PathTrustEvidence Inspect(string path, string? productRoot)
    {
        try
        {
            var canonical = _metadata.Canonicalize(path);
            var components = _metadata.ExistingComponents(canonical);
            if (!components.Contains(canonical, StringComparer.OrdinalIgnoreCase))
                return Denied(canonical, PathTrustCode.MissingComponent);
            var policy = new ServicePathTrustPolicy(
                new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null).Value,
                new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null).Value,
                _metadata.ResolveTrustedInstallerSid());
            var identities = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var metadata = new Dictionary<string, PathComponentMetadata>(StringComparer.OrdinalIgnoreCase);
            foreach (var componentPath in components)
            {
                var component = _metadata.Read(componentPath);
                var decision = policy.Evaluate(component,
                    componentPath.Equals(canonical, StringComparison.OrdinalIgnoreCase),
                    productRoot is not null && IsContained(productRoot, componentPath));
                if (!decision.IsTrusted) return new(decision, canonical, identities, metadata, productRoot);
                if (string.IsNullOrWhiteSpace(component.StableIdentity)) return Denied(canonical, PathTrustCode.InspectionFailed);
                identities.Add(componentPath, component.StableIdentity);
                metadata.Add(componentPath, component);
            }
            return new(PathTrustDecision.Allow(), canonical, identities, metadata, productRoot);
        }
        catch (ArgumentException) { return Denied(string.Empty, PathTrustCode.InvalidPath); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SystemException)
        { return Denied(string.Empty, PathTrustCode.InspectionFailed); }
    }

    private static PathTrustEvidence Denied(string path, PathTrustCode code) =>
        new(PathTrustDecision.Deny(code), path, new Dictionary<string, string>());
    private static bool IsContained(string root, string path) => path.Equals(root, StringComparison.OrdinalIgnoreCase) ||
        path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
}

public sealed partial class WindowsPathMetadataSource : IPathMetadataSource
{
    public string Canonicalize(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (!Path.IsPathFullyQualified(path)) throw new ArgumentException("Path must be absolute.", nameof(path));
        return Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
    }

    public IReadOnlyList<string> ExistingComponents(string canonicalPath)
    {
        var stack = new Stack<string>();
        for (var current = canonicalPath; !string.IsNullOrEmpty(current); current = Path.GetDirectoryName(current))
        {
            if (File.Exists(current) || Directory.Exists(current)) stack.Push(current);
            if (string.Equals(current, Path.GetPathRoot(current), StringComparison.OrdinalIgnoreCase)) break;
        }
        return stack.ToArray();
    }

    public PathComponentMetadata Read(string canonicalPath)
    {
        var attributes = File.GetAttributes(canonicalPath);
        var directory = (attributes & FileAttributes.Directory) != 0;
        var identityBefore = ReadStableIdentity(canonicalPath, directory);
        var security = directory ? (FileSystemSecurity)new DirectoryInfo(canonicalPath).GetAccessControl() :
            new FileInfo(canonicalPath).GetAccessControl();
        var rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>()
            // Inherit-only ACEs (PropagationFlags.InheritOnly) are templates that Windows applies to
            // child objects only; they grant no access to this component itself, so evaluating them
            // against it would flag phantom rights. Windows' own access check ignores them here too.
            .Where(rule => (rule.PropagationFlags & PropagationFlags.InheritOnly) == 0)
            .Select(rule => new PathAccessMetadata(rule.IdentityReference.Value,
                rule.AccessControlType == AccessControlType.Allow, rule.IsInherited,
                ServicePathRights.Map(rule.FileSystemRights, directory))).ToArray();
        var identityAfter = ReadStableIdentity(canonicalPath, directory);
        if (!string.Equals(identityBefore, identityAfter, StringComparison.Ordinal))
            throw new IOException("Path identity changed during metadata inspection.");
        return new(canonicalPath, true, directory, (attributes & FileAttributes.ReparsePoint) != 0,
            (security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier)?.Value,
            identityAfter, rules);
    }

    public string ResolveTrustedInstallerSid() =>
        ((SecurityIdentifier)new NTAccount("NT SERVICE", "TrustedInstaller")
            .Translate(typeof(SecurityIdentifier))).Value;

    private static string ReadStableIdentity(string path, bool directory)
    {
        using var handle = CreateFileW(path, 0x80, 0x7, IntPtr.Zero, 3,
            0x00200000u | (directory ? 0x02000000u : 0), IntPtr.Zero);
        if (handle.IsInvalid || !GetFileInformationByHandle(handle, out var info))
            throw new IOException("Stable path identity inspection failed.");
        return $"{info.VolumeSerialNumber:X8}:{info.FileIndexHigh:X8}{info.FileIndexLow:X8}";
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes; public long CreationTime; public long LastAccessTime; public long LastWriteTime;
        public uint VolumeSerialNumber; public uint FileSizeHigh; public uint FileSizeLow; public uint NumberOfLinks;
        public uint FileIndexHigh; public uint FileIndexLow;
    }

    [LibraryImport("kernel32.dll", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    private static partial SafeFileHandle CreateFileW(string fileName, uint desiredAccess, uint shareMode,
        IntPtr securityAttributes, uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);
    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetFileInformationByHandle(SafeFileHandle file, out ByHandleFileInformation information);
}
