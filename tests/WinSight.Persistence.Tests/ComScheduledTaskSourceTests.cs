using System.Globalization;
using System.Reflection;
using System.Runtime.InteropServices;

using WinSight.Persistence;

using Xunit;

namespace WinSight.Persistence.Tests;

/// <summary>
/// The shipping scheduled-task source, as opposed to the scripted stub the enumerator tests drive.
/// </summary>
/// <remarks>
/// <b>Why these exist.</b> <c>ScheduledTaskEnumeratorTests</c> proves the enumerator propagates
/// <see cref="IScheduledTaskSource.Unreadable"/> — but it proves it against a stub that simply
/// returns <c>true</c>. Nothing covered whether <see cref="ComScheduledTaskSource"/>, the only
/// implementation that ships, can ever <i>set</i> that flag. It could not: late binding raises
/// every COM failure wrapped in a <see cref="TargetInvocationException"/>, which matched none of
/// the types the catch filter listed, so a stopped Task Scheduler service threw straight through
/// and took the whole persistence scan with it while <c>Unreadable</c> stayed <c>false</c>.
///
/// A green regression test guarding the seam instead of the component is the failure mode these
/// tests close: they drive the real classification with the exception shapes the runtime actually
/// produces, and they hold the real source to its own "never throws" contract.
/// </remarks>
public sealed class ComScheduledTaskSourceTests
{
    /// <summary>A managed stand-in for a COM member that fails: the wrapper is what matters here.</summary>
    /// <remarks>
    /// CA2201 is suppressed deliberately and narrowly. The rule exists to stop production code
    /// raising runtime-reserved types; here the whole point is to reproduce the exact shape COM
    /// interop hands back, and substituting a friendlier type would test something the runtime
    /// never produces.
    /// </remarks>
    public sealed class Thrower
    {
#pragma warning disable CA2201
        public void FailLikeCom() => throw new COMException("RPC server unavailable.", unchecked((int)0x800706BA));
#pragma warning restore CA2201

        public void FailLikeMissingFile() => throw new FileNotFoundException("No such folder.");

        // Not reserved, and genuinely how a late-binding defect in WinSight itself would surface.
        public void FailLikeABug() => throw new InvalidCastException("Unexpected member shape.");
    }

    private static Exception RaiseThroughLateBinding(string member) =>
        Assert.ThrowsAny<Exception>(() => typeof(Thrower).InvokeMember(
            member,
            BindingFlags.InvokeMethod,
            binder: null,
            new Thrower(),
            args: null,
            CultureInfo.InvariantCulture));

    // The bug, stated as a test: the runtime wraps, and the filter has to see past the wrapper.
    [Theory]
    [InlineData(nameof(Thrower.FailLikeCom))]
    [InlineData(nameof(Thrower.FailLikeMissingFile))]
    public void AFailureRaisedThroughLateBindingIsClassifiedAsRecoverable(string member)
    {
        var raised = RaiseThroughLateBinding(member);

        // Guard the premise: if reflection ever stopped wrapping, this test would still be honest
        // rather than silently asserting something easier than the real condition.
        Assert.IsType<TargetInvocationException>(raised);

        Assert.True(
            ComScheduledTaskSource.IsRecoverable(raised),
            $"{member} arrived as {raised.GetType().Name}/{raised.InnerException?.GetType().Name} " +
            "and must be read as 'could not look', not thrown at the caller.");
    }

    // Without this, a predicate that just returned true would pass everything above.
    [Fact]
    public void ADefectInWinSightIsNotDisguisedAsAnUnreadableSource()
    {
        var raised = RaiseThroughLateBinding(nameof(Thrower.FailLikeABug));

        Assert.False(ComScheduledTaskSource.IsRecoverable(raised));
    }

    [Fact]
    public void AnUnwrappedFailureIsStillClassified()
    {
        // Activator.CreateInstance and the CLR's own HRESULT mapping can both surface these
        // directly, so unwrapping must not become the only path that works.
#pragma warning disable CA2201
        Assert.True(ComScheduledTaskSource.IsRecoverable(new COMException()));
#pragma warning restore CA2201
        Assert.True(ComScheduledTaskSource.IsRecoverable(new UnauthorizedAccessException()));
        Assert.False(ComScheduledTaskSource.IsRecoverable(new InvalidCastException()));
    }

    /// <summary>
    /// The contract on <see cref="IScheduledTaskSource.Enumerate"/> is "never throws". This holds the
    /// shipping implementation to it against the live machine, whatever state its service is in.
    /// </summary>
    [Fact]
    public void TheRealSourceEitherSeesTasksOrSaysItCouldNotLook()
    {
        var source = new ComScheduledTaskSource();

        var tasks = source.Enumerate().ToList();

        // Never "empty and fine": an empty list is only ever allowed alongside an explicit
        // admission that the source was unreadable.
        Assert.True(
            tasks.Count > 0 || source.Unreadable,
            "The source returned no tasks without reporting itself unreadable, which is the exact "
            + "blind spot this component exists to remove.");
    }
}
