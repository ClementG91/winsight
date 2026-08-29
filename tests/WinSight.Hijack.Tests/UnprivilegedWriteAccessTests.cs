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
    /// The unelevated path is unchanged and still answers by really trying, which remains the best
    /// method when the current token already is the unprivileged one.
    /// </summary>
    [Fact]
    public void TheUnelevatedPathStillAnswersByAttempt()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"winsight-probe-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            var probe = new WritabilityProbe(elevated: false);

            Assert.True(probe.CanCreate(Path.Combine(directory, "anything.dll")));
            Assert.Empty(Directory.GetFiles(directory)); // and it leaves no litter behind
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
    private static DirectorySecurity FromSddl(string right)
    {
        var security = new DirectorySecurity();
        security.SetSecurityDescriptorSddlForm($"O:SYG:SYD:(A;;{right};;;BU)");
        return security;
    }
}
