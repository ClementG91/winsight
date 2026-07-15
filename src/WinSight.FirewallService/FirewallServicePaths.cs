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
    /// <summary>Service-owned policy directory under the machine's ProgramData.</summary>
    public static string DefaultDirectory { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "WinSight",
        "firewall");

    /// <summary>The durable policy file inside <see cref="DefaultDirectory"/>.</summary>
    public static string DefaultPolicyFile => Path.Combine(DefaultDirectory, "policies.json");

    /// <summary>
    /// Creates <paramref name="directory"/> if missing and applies the hardened ACL.
    /// Returns the directory path so callers can compose the policy file path.
    /// </summary>
    public static string ProvisionDirectory(string directory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        var info = Directory.CreateDirectory(directory);
        info.SetAccessControl(CreateHardenedDirectorySecurity());
        return info.FullName;
    }

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
    /// no inherited rules preserved.
    /// </summary>
    public static DirectorySecurity CreateHardenedDirectorySecurity()
    {
        var security = new DirectorySecurity();

        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);

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
