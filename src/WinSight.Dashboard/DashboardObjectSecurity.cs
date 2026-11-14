using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

using Microsoft.Win32.SafeHandles;

namespace WinSight.Dashboard;

/// <summary>Exact-handle trust for the Dashboard's private, per-session lifetime and activation objects.</summary>
internal static class DashboardObjectSecurity
{
    private const int MaximumDescriptorBytes = 4096;
    private const uint OwnerAndDacl = 0x00000005;
    private static readonly SecurityIdentifier SystemSid = new(WellKnownSidType.LocalSystemSid, null);

    internal static MutexSecurity MutexDescriptor(SecurityIdentifier user)
    {
        var security = new MutexSecurity();
        security.SetOwner(user);
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new MutexAccessRule(user, MutexRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new MutexAccessRule(SystemSid, MutexRights.FullControl, AccessControlType.Allow));
        return security;
    }

    internal static EventWaitHandleSecurity EventDescriptor(SecurityIdentifier user)
    {
        var security = new EventWaitHandleSecurity();
        security.SetOwner(user);
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new EventWaitHandleAccessRule(user, EventWaitHandleRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new EventWaitHandleAccessRule(SystemSid, EventWaitHandleRights.FullControl, AccessControlType.Allow));
        return security;
    }

    internal static bool IsTrusted(SafeWaitHandle handle, SecurityIdentifier user, int fullControl)
    {
        if (handle.IsClosed || handle.IsInvalid) { return false; }
        var bytes = new byte[MaximumDescriptorBytes];
        if (!GetKernelObjectSecurity(handle, OwnerAndDacl, bytes, (uint)bytes.Length, out var needed)
            || needed == 0 || needed > bytes.Length)
        {
            return false;
        }
        // One bounded query only. Never grow a buffer or request SACL privileges to establish trust.
        return IsTrustedDescriptor(bytes.AsSpan(0, (int)needed).ToArray(), user, fullControl);
    }

    internal static bool IsTrustedDescriptor(byte[]? bytes, SecurityIdentifier? user, int fullControl)
    {
        if (bytes is null || bytes.Length == 0 || bytes.Length > MaximumDescriptorBytes || user is null
            || (fullControl != (int)MutexRights.FullControl && fullControl != (int)EventWaitHandleRights.FullControl))
        {
            return false;
        }
        RawSecurityDescriptor descriptor;
        try { descriptor = new RawSecurityDescriptor(bytes, 0); }
        catch (ArgumentException) { return false; }
        const ControlFlags required = ControlFlags.SelfRelative | ControlFlags.DiscretionaryAclPresent
            | ControlFlags.DiscretionaryAclProtected;
        if (descriptor.Owner != user || (descriptor.ControlFlags & required) != required
            || descriptor.DiscretionaryAcl is not { } dacl || dacl.Revision != GenericAcl.AclRevision
            || dacl.Count != (user == SystemSid ? 1 : 2))
        {
            return false;
        }
        var userGrant = false;
        var systemGrant = false;
        foreach (GenericAce entry in dacl)
        {
            if (entry is not CommonAce
                {
                    IsCallback: false, AceFlags: AceFlags.None,
                    AceQualifier: AceQualifier.AccessAllowed
                } ace || ace.AccessMask != fullControl)
            {
                return false;
            }
            if (ace.SecurityIdentifier == user && !userGrant)
            {
                userGrant = true;
                if (user == SystemSid) { systemGrant = true; }
            }
            else if (ace.SecurityIdentifier == SystemSid && !systemGrant)
            {
                systemGrant = true;
            }
            else { return false; }
        }
        return userGrant && systemGrant;
    }

    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetKernelObjectSecurity(
        SafeWaitHandle handle, uint securityInformation, [Out] byte[] securityDescriptor,
        uint length, out uint lengthNeeded);
}
