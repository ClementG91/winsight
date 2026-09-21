using WinSight.Dashboard;

using Xunit;

namespace WinSight.Dashboard.Tests;

/// <summary>
/// One interactive dashboard per user and session: a second launch raises the first and ends.
/// </summary>
/// <remarks>
/// Each test uses its own random scope, so a real dashboard running on the machine is never touched
/// and the tests cannot collide with one another.
/// </remarks>
public sealed class DashboardSingleInstanceTests
{
    private static string Scope() => $"test-{Guid.NewGuid():N}";

    [Fact]
    public void ASecondLaunchIsNotPrimaryAndRaisesTheFirst()
    {
        var scope = Scope();
        using var first = DashboardSingleInstance.Acquire(scope);
        using var raised = new ManualResetEventSlim();
        first.OnActivationRequested(raised.Set);

        using var second = DashboardSingleInstance.Acquire(scope);

        Assert.True(first.IsPrimary);
        Assert.False(second.IsPrimary);
        Assert.True(raised.Wait(TimeSpan.FromSeconds(10)), "the first dashboard was not asked to show itself");
    }

    [Fact]
    public void TheInstanceIsFreeAgainOnceTheFirstDashboardExits()
    {
        var scope = Scope();
        DashboardSingleInstance.Acquire(scope).Dispose();

        using var next = DashboardSingleInstance.Acquire(scope);

        Assert.True(next.IsPrimary);
    }

    [Fact]
    public void AnotherScopeKeepsItsOwnInstance()
    {
        using var mine = DashboardSingleInstance.Acquire(Scope());
        using var theirs = DashboardSingleInstance.Acquire(Scope());

        Assert.True(mine.IsPrimary);
        Assert.True(theirs.IsPrimary);
    }

    [Fact]
    public void RepeatedLaunchesRaiseTheFirstEachTime()
    {
        var scope = Scope();
        using var first = DashboardSingleInstance.Acquire(scope);
        var raised = 0;
        first.OnActivationRequested(() => Interlocked.Increment(ref raised));

        for (var launch = 0; launch < 3; launch++)
        {
            using var again = DashboardSingleInstance.Acquire(scope);
            Assert.False(again.IsPrimary);
            var expected = launch + 1;
            Assert.True(SpinWait.SpinUntil(() => Volatile.Read(ref raised) >= expected, TimeSpan.FromSeconds(10)));
        }
    }

    [Theory]
    [InlineData("--smoke-test")]
    [InlineData("--signature")]
    public void ModesThatStartNoMonitorsAreNotSubjectToTheSingleInstance(string argument)
    {
        // App only claims the instance when monitors start; these two modes never start them.
        Assert.False(DashboardStartupPolicy.FromArguments([argument]).StartMonitors);
    }
}
