using System.Security.AccessControl;
using System.Security.Principal;

using WinSight.Hijack;
using Xunit;

namespace WinSight.Hijack.Tests;

/// <summary>
/// The elevated half of the writability question, which the real-attempt probe cannot answer.
/// </summary>
/// <remarks>
/// <b>The defect.</b> <c>IWritabilityProbe</c> asks whether an <i>unprivileged</i> user could plant
/// a file, and the probe answered by creating one with the current token. Run as administrator -
/// the mode WinSight recommends for attribution and scheduled tasks - that succeeds in C:\, in
/// Program Files, in System32 and in every machine PATH entry, so every unquoted service path graded
/// Exploitable, every service directory writable and every PATH entry was reported. A tool that
/// declares the whole machine vulnerable the moment you give it more privilege is finished in one
/// run, and the measurement the design cites ("18 PATH entries and 88 services, none writable") was
/// only ever taken unelevated.
/// </remarks>
public sealed class UnprivilegedWriteAccessTests
{
    private static DirectorySecurity Descriptor(
        params (WellKnownSidType Sid, FileSystemRights Rights, AccessControlType Type)[] rules)
    {
        var security = new DirectorySecurity();
        // Ownership must be set before rules can be added to a detached descriptor.
        security.SetOwner(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null));
        foreach (var (sid, rights, type) in rules)
        {
            security.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(sid, null), rights, type));
        }
        return security;
    }

    [Theory]
    [InlineData(WellKnownSidType.BuiltinUsersSid)]
    [InlineData(WellKnownSidType.AuthenticatedUserSid)]
    [InlineData(WellKnownSidType.WorldSid)]
    [InlineData(WellKnownSidType.InteractiveSid)]
    public void AGrantToAnyUnprivilegedPrincipalIsAGrant(WellKnownSidType sid) =>
        Assert.True(UnprivilegedWriteAccess.IsGrantedBy(
            Descriptor((sid, FileSystemRights.CreateFiles, AccessControlType.Allow))));

    /// <summary>
    /// Administrators and SYSTEM are supposed to be able to write here. Counting them would
    /// reproduce exactly the false positive this replaces.
    /// </summary>
    [Theory]
    [InlineData(WellKnownSidType.BuiltinAdministratorsSid)]
    [InlineData(WellKnownSidType.LocalSystemSid)]
    [InlineData(WellKnownSidType.CreatorOwnerSid)]
    public void AGrantToAPrivilegedPrincipalIsNot(WellKnownSidType sid) =>
        Assert.False(UnprivilegedWriteAccess.IsGrantedBy(
            Descriptor((sid, FileSystemRights.FullControl, AccessControlType.Allow))));

    [Fact]
    public void ReadAndExecuteAreNotPlantingRights() =>
        Assert.False(UnprivilegedWriteAccess.IsGrantedBy(Descriptor(
            (WellKnownSidType.BuiltinUsersSid, FileSystemRights.ReadAndExecute, AccessControlType.Allow))));

    [Fact]
    public void ADenyDefeatsAnAllow() =>
        Assert.False(UnprivilegedWriteAccess.IsGrantedBy(Descriptor(
            (WellKnownSidType.BuiltinUsersSid, FileSystemRights.CreateFiles, AccessControlType.Allow),
            (WellKnownSidType.BuiltinUsersSid, FileSystemRights.CreateFiles, AccessControlType.Deny))));

    [Fact]
    public void AnEmptyDaclGrantsNothing() =>
        Assert.False(UnprivilegedWriteAccess.IsGrantedBy(Descriptor()));

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(@"C:\this\directory\does\not\exist")]
    public void AnUnreadableDirectoryIsNotEvidence(string directory) =>
        Assert.False(UnprivilegedWriteAccess.IsGrantedIn(directory));

    /// <summary>
    /// The regression that mattered: elevated or not, the machine's own protected directories must
    /// never grade as plantable by a standard user.
    /// </summary>
    [Theory]
    [InlineData(Environment.SpecialFolder.Windows)]
    [InlineData(Environment.SpecialFolder.System)]
    [InlineData(Environment.SpecialFolder.ProgramFiles)]
    public void WindowsOwnDirectoriesAreNotPlantableByAStandardUser(Environment.SpecialFolder folder)
    {
        var directory = Environment.GetFolderPath(folder);
        var probe = new WritabilityProbe(elevated: true);

        Assert.False(probe.CanCreate(Path.Combine(directory, "winsight-probe.dll")));
    }

    /// <summary>
    /// And the counterpart: a directory a standard user really can write must still read as
    /// writable, or the elevated path would trade a flood of false positives for silence.
    /// </summary>
    [Fact]
    public void AUserWritableDirectoryIsStillReported()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"winsight-acl-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            var security = new DirectoryInfo(directory).GetAccessControl();
            security.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
                FileSystemRights.Modify,
                InheritanceFlags.None,
                PropagationFlags.None,
                AccessControlType.Allow));
            new DirectoryInfo(directory).SetAccessControl(security);

            var probe = new WritabilityProbe(elevated: true);

            Assert.True(probe.CanCreate(Path.Combine(directory, "winsight-probe.dll")));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>
    /// A grant to the user's own SID is seen when Windows can evaluate the non-elevated token, and
    /// is the documented blind spot of the well-known-group model used when it cannot.
    /// </summary>
    /// <remarks>
    /// Which method runs depends on the account running the tests: a split (UAC) token is evaluated
    /// by <c>AccessCheck</c>; SYSTEM or an administrator with UAC disabled - a common CI runner shape -
    /// has no non-elevated token and falls back to the well-known groups. Both outcomes are asserted,
    /// each against the method that actually answered.
    /// </remarks>
    [Fact]
    public void AGrantToTheActualUserSidIsSeenExactlyWhenTheEffectiveTokenIsAvailable()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"winsight-user-acl-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            var user = WindowsIdentity.GetCurrent().User;
            Assert.NotNull(user);
            ReplaceDacl(directory, user, Allow(user, FileSystemRights.FullControl));

            Assert.True(UnprivilegedWriteAccess.TryIsGrantedIn(
                directory, PlantedObject.File, out var granted, out var evaluation));
            Assert.Equal(evaluation == WriteAccessEvaluation.EffectiveAccess, granted);
            Assert.Equal(granted, new WritabilityProbe().CanCreate(Path.Combine(directory, "winsight-probe.dll")));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>
    /// A directory the user owns is one they can plant in, whatever its DACL grants them today.
    /// </summary>
    /// <remarks>
    /// <b>The hole.</b> The owner of an object holds WRITE_DAC without any entry granting it, and an
    /// explicit Deny does not take that away - only an OWNER RIGHTS entry does (both measured on
    /// Windows 11 26200). A user who owns a directory can therefore give themselves the right to
    /// create a file in it. The check asked Windows about the create right alone, so a folder a
    /// standard user created and an administrator later locked down with <c>icacls</c>, keeping its
    /// owner - a PATH entry, a service's directory - read as not plantable by the very user who can
    /// reopen it. The cleanup below is that step.
    /// </remarks>
    [Fact]
    public void OwningTheDirectoryIsAPlantingRight()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"winsight-owned-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        var user = WindowsIdentity.GetCurrent().User;
        Assert.NotNull(user);
        try
        {
            ReplaceDacl(
                directory,
                user,
                Allow(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl),
                Allow(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), FileSystemRights.FullControl),
                Allow(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null), FileSystemRights.ReadAndExecute));

            Assert.True(UnprivilegedWriteAccess.TryIsGrantedIn(
                directory, PlantedObject.File, out var granted, out var evaluation));
            // The well-known-group model does not see one named user, owner or not.
            Assert.Equal(evaluation == WriteAccessEvaluation.EffectiveAccess, granted);
            Assert.Equal(granted, new WritabilityProbe().CanCreate(Path.Combine(directory, "winsight-probe.dll")));
        }
        finally
        {
            ReplaceDacl(directory, user, Allow(user, FileSystemRights.FullControl));
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>
    /// A right to take ownership is a right to plant: the new owner holds WRITE_DAC.
    /// </summary>
    /// <remarks>
    /// Built as a descriptor because a standard user cannot give a directory to SYSTEM, and a
    /// directory the user already owns would answer through ownership instead. Windows is asked
    /// about the descriptor as it would read after the user took it.
    /// </remarks>
    [Fact]
    public void ARightToTakeOwnershipIsSeenWithTheEffectiveToken()
    {
        var user = WindowsIdentity.GetCurrent().User;
        Assert.NotNull(user);

        Assert.True(UnprivilegedWriteAccess.TryIsGrantedByDescriptor(
            Binary($"O:SYG:SYD:(A;;FA;;;SY)(A;;0x1200a9;;;BU)(A;;WO;;;{user.Value})"),
            PlantedObject.File,
            out var granted,
            out var evaluation));
        Assert.Equal(evaluation == WriteAccessEvaluation.EffectiveAccess, granted);
    }

    /// <summary>
    /// Taking ownership gives nothing more when an OWNER RIGHTS entry says what the owner holds.
    /// </summary>
    [Fact]
    public void AnOwnerRightsEntryLimitsWhatTakingOwnershipGives()
    {
        var user = WindowsIdentity.GetCurrent().User;
        Assert.NotNull(user);

        Assert.True(UnprivilegedWriteAccess.TryIsGrantedByDescriptor(
            Binary($"O:SYG:SYD:(A;;FA;;;SY)(A;;0x1200a9;;;OW)(A;;0x1200a9;;;BU)(A;;WO;;;{user.Value})"),
            PlantedObject.File,
            out var granted,
            out _));
        Assert.False(granted);
    }

    /// <summary>
    /// The well-known-group model: a group allowed to rewrite the DACL, or to take the directory and
    /// then rewrite it, can plant.
    /// </summary>
    [Theory]
    [InlineData("WD")]
    [InlineData("WO")]
    public void ARightToRewriteTheDaclIsAPlantingRight(string right) =>
        Assert.True(UnprivilegedWriteAccess.IsGrantedBy(FromSddl(right)));

    /// <summary>A group denied the create right but allowed to rewrite the DACL removes the Deny.</summary>
    [Fact]
    public void ADeniedCreateRightDoesNotStopAGroupThatCanRewriteTheDacl() =>
        Assert.True(UnprivilegedWriteAccess.IsGrantedBy(Sddl("O:SYG:SYD:(D;;0x2;;;BU)(A;;WD;;;BU)")));

    /// <summary>
    /// Every member of a group that owns the directory holds WRITE_DAC on it, and a Deny does not
    /// take that away.
    /// </summary>
    [Theory]
    [InlineData("O:BUG:SYD:(A;;0x1200a9;;;BU)")]
    [InlineData("O:AUG:SYD:(D;;WD;;;AU)(A;;0x1200a9;;;BU)")]
    public void OwnershipByAnUnprivilegedGroupIsAPlantingRight(string sddl)
    {
        Assert.True(UnprivilegedWriteAccess.IsGrantedBy(Sddl(sddl)));
        Assert.True(UnprivilegedWriteAccess.IsGrantedByDescriptor(Binary(sddl), PlantedObject.File));
    }

    /// <summary>
    /// An OWNER RIGHTS entry replaces the owner's implicit rights, so ownership then gives exactly
    /// what that entry grants - the create right, or nothing that plants.
    /// </summary>
    [Theory]
    [InlineData("O:BUG:SYD:(A;;0x1200a9;;;OW)(A;;0x1200a9;;;BU)", false)]
    [InlineData("O:SYG:SYD:(A;;0x1200a9;;;OW)(A;;WO;;;BU)", false)]
    [InlineData("O:BUG:SYD:(A;;0x1200ab;;;OW)", true)]
    public void AnOwnerRightsEntryDecidesWhatOwnershipGives(string sddl, bool plantable) =>
        Assert.Equal(plantable, UnprivilegedWriteAccess.IsGrantedBy(Sddl(sddl)));

    /// <summary>
    /// The probe answers without creating anything, and its answer is the evaluator's.
    /// </summary>
    /// <remarks>
    /// It used to answer unelevated by creating and deleting a real file. The directory here is the
    /// test user's own, so with the effective token the answer must be yes; the well-known-group
    /// fallback (no split token, e.g. a CI runner with UAC off) does not see a grant to one named
    /// user and must say so consistently rather than guess.
    /// </remarks>
    [Fact]
    public void TheProbeAnswersWithoutWritingAnything()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"winsight-probe-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            var answer = new WritabilityProbe().CanCreate(Path.Combine(directory, "anything.dll"));

            Assert.Empty(Directory.EnumerateFileSystemEntries(directory));
            Assert.True(UnprivilegedWriteAccess.TryIsGrantedIn(
                directory, PlantedObject.File, out var granted, out var evaluation));
            Assert.Equal(granted, answer);
            if (evaluation == WriteAccessEvaluation.EffectiveAccess)
            {
                Assert.True(answer);
            }
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>An existing file is never overwritten, and never reported as plantable.</summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void AnExistingCandidateIsNeverTouched(bool elevated)
    {
        var directory = Path.Combine(Path.GetTempPath(), $"winsight-probe-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        var existing = Path.Combine(directory, "already-here.dll");
        File.WriteAllText(existing, "the real file");
        try
        {
            Assert.False(new WritabilityProbe(elevated).CanCreate(existing));
            Assert.Equal("the real file", File.ReadAllText(existing));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>
    /// A grant spelled with the generic bits is still a grant.
    /// </summary>
    /// <remarks>
    /// <b>The hole.</b> This check tested specific rights against a mask read straight out of the
    /// DACL, and .NET returns that mask exactly as stored - it does not apply the object's generic
    /// mapping. <c>GENERIC_WRITE</c> is <c>0x40000000</c> and shares no bit with
    /// <c>FileSystemRights.Write</c>, so a directory granting Users <c>(GW)</c> read as granting no
    /// planting right, and a real DLL side-loading point was reported as safe.
    ///
    /// It is not an exotic spelling: <c>icacls /grant Users:(GW)</c>, an SDDL <c>GW</c> or
    /// <c>GA</c>, and any installer calling <c>SetNamedSecurityInfo</c> with the generic mapping all
    /// produce it. An attacker who can set an ACL can choose the spelling the checker does not read.
    ///
    /// <b>Why these build the descriptor from SDDL.</b> <see cref="FileSystemAccessRule"/>'s
    /// constructor rejects a generic mask outright, so an ACL carrying one cannot be assembled
    /// through the managed API at all - which is precisely why this gap was easy to miss. Windows
    /// stores the raw ACE mask regardless, and the read path hands it back unmapped. SDDL builds the
    /// descriptor in a shape a real one can actually have.
    /// </remarks>
    [Theory]
    [InlineData("GW")]
    [InlineData("GA")]
    public void AGenericGrantIsStillAPlantingRight(string right) =>
        Assert.True(UnprivilegedWriteAccess.IsGrantedBy(FromSddl(right)));

    /// <summary>
    /// Expansion must not invent access: a generic read or execute grant confers no planting right,
    /// or every readable directory on the machine becomes a finding.
    /// </summary>
    [Theory]
    [InlineData("GR")]
    [InlineData("GX")]
    public void AGenericReadOrExecuteGrantIsNot(string right) =>
        Assert.False(UnprivilegedWriteAccess.IsGrantedBy(FromSddl(right)));

    /// <summary>An allow ACE granting BUILTIN\Users the named right and nothing else.</summary>
    private static DirectorySecurity FromSddl(string right) => Sddl($"O:SYG:SYD:(A;;{right};;;BU)");

    private static DirectorySecurity Sddl(string sddl)
    {
        var security = new DirectorySecurity();
        security.SetSecurityDescriptorSddlForm(sddl);
        return security;
    }

    /// <summary>The self-relative form Windows returns for a directory handle.</summary>
    private static byte[] Binary(string sddl)
    {
        var descriptor = new RawSecurityDescriptor(sddl);
        var bytes = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(bytes, 0);
        return bytes;
    }

    private static FileSystemAccessRule Allow(SecurityIdentifier sid, FileSystemRights rights) =>
        new(sid, rights, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Allow);

    /// <summary>
    /// Replaces the DACL of a directory this test created with <paramref name="rules"/> alone, and
    /// makes <paramref name="user"/> its owner.
    /// </summary>
    /// <remarks>
    /// The owner is written only when it is not already the user. Writing it needs WRITE_OWNER even
    /// when the value does not change, and the creator of a directory holds that right only where an
    /// inherited entry grants it: under the user profile (Full Control), not under a data volume's
    /// default root ACL (Authenticated Users: Modify), where this failed with TEMP on D:. An elevated
    /// run creates the directory owned by Administrators, and does hold the right.
    /// </remarks>
    private static void ReplaceDacl(string directory, SecurityIdentifier user, params FileSystemAccessRule[] rules)
    {
        var info = new DirectoryInfo(directory);
        var security = new DirectorySecurity();
        if (!user.Equals(info.GetAccessControl(AccessControlSections.Owner).GetOwner(typeof(SecurityIdentifier))))
        {
            security.SetOwner(user);
        }
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (var rule in rules)
        {
            security.AddAccessRule(rule);
        }
        info.SetAccessControl(security);
    }
}
