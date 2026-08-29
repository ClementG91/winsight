using System.Diagnostics;

using WinSight.NetMonitor;
using Xunit;

namespace WinSight.NetMonitor.Tests;

/// <summary>
/// The real answer to "does the process that owns this ETW session still exist, and is it the same
/// process?".
/// </summary>
/// <remarks>
/// <b>What was covered and what was not.</b> The lifecycle's orphan-recovery decisions were tested
/// exhaustively against a fake identity - correctly, because a unit test must never enumerate or
/// stop the machine-global ETW namespace. But the fake answers by construction, so the adapter that
/// produces the real answer had never run.
///
/// The consequence of getting it wrong is specific and bad in both directions. Report a live owner
/// as absent and WinSight stops another instance's session out from under it. Report a recycled pid
/// as still owning the session and the orphan is never reclaimed, so the feature stays dead until
/// reboot. The start-identity comparison is what separates those two, and it was the untested part.
///
/// Nothing here touches ETW: it probes processes only.
/// </remarks>
public sealed class WindowsEtwProcessIdentityTests
{
    private static readonly WindowsEtwProcessIdentity Identity = new();

    [Fact]
    public void TheCurrentProcessIsItsOwnPid() =>
        Assert.Equal(Environment.ProcessId, Identity.CurrentProcessId);

    /// <summary>
    /// The identity is the start time as a fixed-width hex tick count, which is what the session
    /// name embeds. A different width or casing would make every session this build creates
    /// unrecognisable to the next one.
    /// </summary>
    [Fact]
    public void TheStartIdentityIsSixteenUppercaseHexDigits()
    {
        var identity = Identity.CurrentStartIdentity;

        Assert.Equal(16, identity.Length);
        Assert.All(identity, character =>
            Assert.True(character is >= '0' and <= '9' or >= 'A' and <= 'F', $"'{character}'"));
    }

    [Fact]
    public void TheStartIdentityIsStableAcrossReads() =>
        Assert.Equal(Identity.CurrentStartIdentity, Identity.CurrentStartIdentity);

    [Fact]
    public void ALiveProcessWithItsOwnStartIdentityMatches() =>
        Assert.Equal(
            EtwOwnerState.Matches,
            Identity.Probe(Environment.ProcessId, Identity.CurrentStartIdentity));

    /// <summary>
    /// A session name from before a pid was recycled carries the old start time. Treating that as
    /// the owner would leave the orphan forever; it must read as a mismatch.
    /// </summary>
    [Fact]
    public void ALiveProcessWithSomebodyElsesStartIdentityIsAMismatch() =>
        Assert.Equal(
            EtwOwnerState.Mismatch, Identity.Probe(Environment.ProcessId, "0000000000000001"));

    /// <summary>
    /// A legacy session name carries no start identity. It cannot be checked, so a live pid is
    /// accepted as the owner - the conservative direction, which risks leaving a session rather
    /// than stopping somebody else's.
    /// </summary>
    [Fact]
    public void ALiveProcessWithNoExpectedIdentityMatches() =>
        Assert.Equal(EtwOwnerState.Matches, Identity.Probe(Environment.ProcessId, null));

    /// <summary>
    /// A pid that no longer exists is definitively absent, which is what makes reclaiming its
    /// session safe.
    /// </summary>
    [Fact]
    public void AProcessThatHasExitedIsAbsent()
    {
        using var process = Process.Start(new ProcessStartInfo(
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe"),
            "/c exit")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
        })!;
        var pid = process.Id;
        process.WaitForExit();

        Assert.Equal(EtwOwnerState.Absent, Identity.Probe(pid, null));
    }

    /// <summary>
    /// A pid Windows will never assign is absent rather than indeterminate: nothing failed, there
    /// simply is no such process.
    /// </summary>
    [Fact]
    public void AnImpossiblePidIsAbsentRatherThanIndeterminate() =>
        Assert.Equal(EtwOwnerState.Absent, Identity.Probe(-1, null));

    /// <summary>
    /// The idle process cannot be opened for its start time. That is a gap in the observation, not
    /// evidence the owner is gone, so it must never read as Absent - which is the reading that
    /// authorises stopping a session.
    /// </summary>
    [Fact]
    public void AProcessWhoseStartTimeCannotBeReadIsNeverReportedAsAbsent()
    {
        var state = Identity.Probe(0, "0000000000000001");

        Assert.NotEqual(EtwOwnerState.Absent, state);
    }
}
