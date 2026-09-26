using System.Reflection;
using System.Runtime.InteropServices;

using Xunit;

namespace WinSight.Dashboard.Tests;

/// <summary>
/// When a UI-thread exception may be absorbed. The dashboard hosts Guardian, ransomware protection
/// and the camera/microphone monitor, so letting every UI exception terminate it switched all of
/// that off; absorbing everything would keep a process running that cannot be trusted.
/// </summary>
public sealed class DispatcherRecoveryPolicyTests
{
    private static readonly DateTimeOffset Start = new(2026, 9, 22, 8, 0, 0, TimeSpan.Zero);

    /// <summary>Built through the activator: constructing a runtime-reserved exception directly is CA2201.</summary>
    private static OutOfMemoryException OutOfMemory() =>
        Activator.CreateInstance<OutOfMemoryException>();

    private static DispatcherRecoveryPolicy Armed(Func<DateTimeOffset>? clock = null)
    {
        var policy = new DispatcherRecoveryPolicy(maxRecoveries: 3, window: TimeSpan.FromMinutes(1), clock: clock ?? (() => Start));
        policy.Arm();
        return policy;
    }

    [Fact]
    public void NothingIsAbsorbedBeforeTheDashboardHasStarted() =>
        Assert.False(new DispatcherRecoveryPolicy().ShouldRecover(new InvalidOperationException()));

    [Theory]
    [InlineData(typeof(InvalidOperationException))]
    [InlineData(typeof(NullReferenceException))]
    [InlineData(typeof(ArgumentException))]
    [InlineData(typeof(IOException))]
    [InlineData(typeof(FormatException))]
    public void AnOrdinaryHandlerFailureIsAbsorbedOnceRunning(Type type) =>
        Assert.True(Armed().ShouldRecover((Exception)Activator.CreateInstance(type)!));

    [Theory]
    [InlineData(typeof(OutOfMemoryException))]
    [InlineData(typeof(InsufficientExecutionStackException))]
    [InlineData(typeof(AccessViolationException))]
    [InlineData(typeof(SEHException))]
    [InlineData(typeof(InvalidProgramException))]
    [InlineData(typeof(BadImageFormatException))]
    [InlineData(typeof(TypeLoadException))]
    [InlineData(typeof(MissingMethodException))]
    [InlineData(typeof(DllNotFoundException))]
    [InlineData(typeof(EntryPointNotFoundException))]
    public void AnExceptionThatCompromisesTheProcessIsNeverAbsorbed(Type type) =>
        Assert.False(Armed().ShouldRecover((Exception)Activator.CreateInstance(type)!));

    /// <summary>A fatal exception is still fatal when a wrapper arrives first.</summary>
    [Fact]
    public void AWrappedFatalExceptionIsNeverAbsorbed()
    {
        var policy = Armed();

        Assert.False(policy.ShouldRecover(new TargetInvocationException(OutOfMemory())));
        Assert.False(policy.ShouldRecover(new AggregateException(
            new InvalidOperationException(), new InvalidOperationException("x", new DllNotFoundException()))));
        Assert.False(policy.ShouldRecover(new TypeInitializationException("Some.Type", new InvalidOperationException())));
    }

    /// <summary>
    /// Past the budget the fault is not transient: a window failing on every repaint is not worth
    /// keeping, and the process terminates with its report as before.
    /// </summary>
    [Fact]
    public void ACrashLoopIsNotAbsorbed()
    {
        var now = Start;
        var policy = Armed(() => now);

        Assert.True(policy.ShouldRecover(new InvalidOperationException()));
        now += TimeSpan.FromSeconds(10);
        Assert.True(policy.ShouldRecover(new InvalidOperationException()));
        now += TimeSpan.FromSeconds(10);
        Assert.True(policy.ShouldRecover(new InvalidOperationException()));
        now += TimeSpan.FromSeconds(10);
        Assert.False(policy.ShouldRecover(new InvalidOperationException()));
    }

    [Fact]
    public void TheBudgetRefillsOnceTheWindowHasPassed()
    {
        var now = Start;
        var policy = Armed(() => now);
        for (var i = 0; i < 3; i++)
        {
            Assert.True(policy.ShouldRecover(new InvalidOperationException()));
        }

        now += TimeSpan.FromMinutes(1);

        Assert.True(policy.ShouldRecover(new InvalidOperationException()));
    }

    /// <summary>A refused fatal exception must not consume the budget of later ordinary ones.</summary>
    [Fact]
    public void ARefusedExceptionDoesNotCountAgainstTheBudget()
    {
        var policy = Armed();
        for (var i = 0; i < 5; i++)
        {
            Assert.False(policy.ShouldRecover(OutOfMemory()));
        }

        Assert.True(policy.ShouldRecover(new InvalidOperationException()));
    }
}
