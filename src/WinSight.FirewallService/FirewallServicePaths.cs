using System.Security.AccessControl;
using System.Security.Principal;

namespace WinSight.FirewallService;

/// <summary>
/// Resolves and provisions the service-owned, ACL-protected directory that holds the
/// outbound-firewall policy file. Only SYSTEM and the local Administrators group may
/// read or write it, and inheritance is removed so a permissive parent ACL cannot widen
/// access. The unprivileged dashboard never touches this directory; it goes through the
/// authenticated pipe.
/// </summary>
public static class FirewallServicePaths
{
    /// <summary>Machine-wide data root that Windows owns and under which the product's own directories live.</summary>
    private static string ProductRoot { get; } = Path.TrimEndingDirectorySeparator(
        Path.GetFullPath(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)));

    /// <summary>Service-owned policy directory under the machine's ProgramData.</summary>
    public static string DefaultDirectory { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "WinSight",
        "firewall");

    /// <summary>The durable policy file inside <see cref="DefaultDirectory"/>.</summary>
    public static string DefaultPolicyFile => Path.Combine(DefaultDirectory, "policies.json");

    /// <summary>
    /// Creates <paramref name="directory"/> if missing and applies the hardened ACL to every
    /// component the product owns beneath ProgramData. Returns the directory path so callers can
    /// compose the policy file path.
    /// </summary>
    public static string ProvisionDirectory(string directory) =>
        ProvisionDirectory(directory, ProductRoot, claimOwnership: true);

    /// <summary>
    /// Creates <paramref name="directory"/> and hardens every component strictly below
    /// <paramref name="root"/>, outermost first. <paramref name="root"/> itself and everything
    /// above it are left untouched. Components below <paramref name="root"/> are also owned by the
    /// Administrators group when <paramref name="claimOwnership"/> is set.
    /// </summary>
    /// <remarks>
    /// Hardening only the leaf left the intermediate directory that Directory.CreateDirectory
    /// creates implicitly (ProgramData\WinSight) carrying ProgramData's inherited ACL: it grants
    /// Users write and materializes CREATOR OWNER into a FullControl entry for whoever created it.
    /// That principal could delete and recreate the hardened leaf with its own ACL and plant a
    /// policy the SYSTEM service reads, so the trust inspector refused the whole chain and the
    /// service could not start. Existing components are re-hardened too, which repairs a chain a
    /// previous version left permissive. Stopping at <paramref name="root"/> is what keeps the walk
    /// from re-ACLing ProgramData and the drive root, which belong to Windows.
    /// </remarks>
    public static string ProvisionDirectory(string directory, string root, bool claimOwnership)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        ArgumentException.ThrowIfNullOrWhiteSpace(root);
        var full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(directory));
        var canonicalRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));

        // Create the chain before tightening anything: hardening a parent first strips the calling
        // process's own access to it, leaving it unable to create the child underneath.
        var provisioned = Directory.CreateDirectory(full);

        // Harden innermost first, so each directory is still reachable when its turn comes. Any
        // window this leaves is closed by the trust inspection callers run afterwards, which
        // refuses a chain that is not fully hardened.
        var chain = ProvisionedComponents(full, canonicalRoot);
        for (var index = chain.Length - 1; index >= 0; index--)
        {
            new DirectoryInfo(chain[index]).SetAccessControl(CreateHardenedDirectorySecurity(
                claimOwnership: claimOwnership && IsUnder(canonicalRoot, chain[index])));
        }
        return provisioned.FullName;
    }

    /// <summary>
    /// The components <see cref="ProvisionDirectory(string, string, bool)"/> hardens, outermost
    /// first: every directory strictly below <paramref name="root"/> down to
    /// <paramref name="directory"/>, or just <paramref name="directory"/> when it sits outside
    /// <paramref name="root"/>. <paramref name="root"/> itself is never included.
    /// </summary>
    public static string[] ProvisionedComponents(string directory, string root)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        ArgumentException.ThrowIfNullOrWhiteSpace(root);
        var full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(directory));
        var canonicalRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        if (!IsUnder(canonicalRoot, full)) return [full];

        // Walking up pushes the leaf first, so popping yields the components outermost first.
        var chain = new Stack<string>();
        for (var current = full;
             !string.IsNullOrEmpty(current) &&
             !string.Equals(current, canonicalRoot, StringComparison.OrdinalIgnoreCase);
             current = Path.GetDirectoryName(current))
        {
            chain.Push(current);
        }
        return [.. chain];
    }

    private static bool IsUnder(string root, string path) =>
        path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);

    public static string ProvisionDefaultDirectory()
    {
        var directory = ProvisionDirectory(DefaultDirectory);
        var trust = InspectDefaultStorage();
        if (!trust.IsTrusted)
        {
            throw new InvalidOperationException($"Policy storage rejected [{trust.Code}]: {trust.Message}");
        }
        return directory;
    }

    public static PathTrustDecision InspectDefaultStorage() =>
        new WindowsServicePathTrustInspector().InspectPolicyStorage(DefaultDirectory, DefaultPolicyFile);

    /// <summary>
    /// Full control for SYSTEM and Administrators only, with inheritance disabled and
    /// no inherited rules preserved. When <paramref name="claimOwnership"/> is set, the
    /// Administrators group is also made the owner.
    /// </summary>
    /// <remarks>
    /// Whoever creates a directory stays its owner, and an owner keeps implicit control of the
    /// DACL. An elevated admin console leaves the directory owned by the individual user, which the
    /// trust inspector refuses, so which context provisioned first would decide whether the service
    /// can start. Only directories the product owns claim ownership; an arbitrary directory passed
    /// in from outside ProgramData keeps its owner and receives the hardened ACL alone.
    /// </remarks>
    public static DirectorySecurity CreateHardenedDirectorySecurity(bool claimOwnership = false)
    {
        var security = new DirectorySecurity();

        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);

        if (claimOwnership) security.SetOwner(administrators);

        const InheritanceFlags inheritance = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        security.AddAccessRule(new FileSystemAccessRule(
            system, FileSystemRights.FullControl, inheritance, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            administrators, FileSystemRights.FullControl, inheritance, PropagationFlags.None, AccessControlType.Allow));

        // Remove inheritance and do not copy the parent's inherited rules, so only the
        // two explicit trusted principals above can reach the policy file.
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        return security;
    }
}
