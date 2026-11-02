using System.Reflection;
using System.Security.AccessControl;
using System.Security.Principal;

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

    [Fact]
    public void APermissiveMutexCannotSuppressTheDashboard()
    {
        var scope = Scope();
        var user = User();
        using var incidental = MutexAcl.Create(false, DashboardSingleInstance.MutexName(scope),
            out var created, MutexDescriptor(user, permissive: true));
        Assert.True(created);
        AssertNativeDescriptor(incidental.GetAccessControl(), user, permissive: true);

        using var dashboard = DashboardSingleInstance.Acquire(scope);

        Assert.True(dashboard.IsPrimary);
    }

    [Fact]
    public void ASecondaryDoesNotSignalAPermissiveActivationEvent()
    {
        var scope = Scope();
        var user = User();
        using var owner = MutexAcl.Create(false, DashboardSingleInstance.MutexName(scope),
            out var mutexCreated, MutexDescriptor(user));
        using var activation = EventWaitHandleAcl.Create(false, EventResetMode.AutoReset,
            DashboardSingleInstance.ActivationName(scope), out var eventCreated, EventDescriptor(user, permissive: true));
        Assert.True(mutexCreated);
        Assert.True(eventCreated);
        AssertNativeDescriptor(owner.GetAccessControl(), user, permissive: false);
        AssertNativeDescriptor(activation.GetAccessControl(), user, permissive: true);
        Assert.False(activation.WaitOne(0));

        using var secondary = DashboardSingleInstance.Acquire(scope);

        Assert.False(secondary.IsPrimary);
        Assert.False(activation.WaitOne(0)); // Acquire's activation request is synchronous.
    }

    [Fact]
    public async Task APrimaryDoesNotRegisterAPermissiveActivationEvent()
    {
        var scope = Scope();
        var user = User();
        using var activation = EventWaitHandleAcl.Create(false, EventResetMode.AutoReset,
            DashboardSingleInstance.ActivationName(scope), out var created, EventDescriptor(user, permissive: true));
        Assert.True(created);
        AssertNativeDescriptor(activation.GetAccessControl(), user, permissive: true);
        using var primary = DashboardSingleInstance.Acquire(scope);
        Assert.True(primary.IsPrimary);
        // A TCS stays safe if an already-queued callback returns after disposal. This is a bounded
        // negative observation, not a callback-quiescence or native-wait scheduling proof.
        var raised = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        primary.OnActivationRequested(() => raised.TrySetResult());

        activation.Set();

        var observation = Task.Delay(TimeSpan.FromMilliseconds(200));
        var first = await Task.WhenAny(raised.Task, observation);
        await observation;
        Assert.Same(observation, first);
    }

    [Fact]
    public void NewObjectsHaveExplicitUserOwnerAndProtectedPrivateDacls()
    {
        var scope = Scope();
        using var primary = DashboardSingleInstance.Acquire(scope);
        Assert.True(primary.IsPrimary);
        var user = User();
        using var mutex = Mutex.OpenExisting(DashboardSingleInstance.MutexName(scope));
        using var activation = EventWaitHandle.OpenExisting(DashboardSingleInstance.ActivationName(scope));

        AssertNativeDescriptor(mutex.GetAccessControl(), user, permissive: false);
        AssertNativeDescriptor(activation.GetAccessControl(), user, permissive: false);
    }

    [Fact]
    public void AnActivationTypeCollisionKeepsThePrimaryMutex()
    {
        var scope = Scope();
        using var incidental = new Mutex(false, DashboardSingleInstance.ActivationName(scope));

        using var first = DashboardSingleInstance.Acquire(scope);
        using var second = DashboardSingleInstance.Acquire(scope);

        Assert.True(first.IsPrimary);
        Assert.False(second.IsPrimary);
    }

    [Fact]
    public void AnInstanceTypeCollisionCannotPreventAnIndependentPrimary()
    {
        var scope = Scope();
        using var incidental = new EventWaitHandle(false, EventResetMode.AutoReset,
            DashboardSingleInstance.MutexName(scope));

        using var dashboard = DashboardSingleInstance.Acquire(scope);

        Assert.True(dashboard.IsPrimary);
    }

    [Fact]
    public void ASecondaryNeverCreatesAnActivationEvent()
    {
        var scope = Scope();
        using var owner = MutexAcl.Create(false, DashboardSingleInstance.MutexName(scope),
            out var created, MutexDescriptor(User()));
        Assert.True(created);

        using var secondary = DashboardSingleInstance.Acquire(scope);

        Assert.False(secondary.IsPrimary);
        var opened = EventWaitHandle.TryOpenExisting(DashboardSingleInstance.ActivationName(scope), out var activation);
        using (activation) { Assert.False(opened); }
    }

    // These future-helper controls are managed descriptor data only. No native object with a null
    // DACL is created. Missing helper failures on the old implementation are NOT qualifying RED.
    [Theory]
    [InlineData("trusted", true)]
    [InlineData("system-user", true)]
    [InlineData("owner", false)]
    [InlineData("null-dacl", false)]
    [InlineData("empty", false)]
    [InlineData("unprotected", false)]
    [InlineData("absent-dacl", false)]
    [InlineData("foreign", false)]
    [InlineData("generic", false)]
    [InlineData("inherited", false)]
    [InlineData("callback", false)]
    [InlineData("deny", false)]
    [InlineData("duplicate", false)]
    [InlineData("wrong-rights", false)]
    [InlineData("malformed", false)]
    [InlineData("truncated", false)]
    [InlineData("over-budget", false)]
    public void DescriptorPolicyIsStrictAndBounded(string scenario, bool expected)
    {
        var user = scenario == "system-user" ? SystemSid() : User();
        var mask = (int)MutexRights.FullControl;
        var flags = ControlFlags.SelfRelative | ControlFlags.DiscretionaryAclPresent | ControlFlags.DiscretionaryAclProtected;
        var acl = new RawAcl(GenericAcl.AclRevision, 3);
        var aceFlags = scenario == "inherited" ? AceFlags.Inherited : AceFlags.None;
        acl.InsertAce(0, new CommonAce(aceFlags,
            scenario == "deny" ? AceQualifier.AccessDenied : AceQualifier.AccessAllowed,
            scenario == "generic" ? 0x10000000 : scenario == "wrong-rights" ? (int)EventWaitHandleRights.FullControl : mask,
            user, isCallback: scenario == "callback", opaque: null));
        if (user != SystemSid())
        {
            acl.InsertAce(acl.Count, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed,
                mask, SystemSid(), isCallback: false, opaque: null));
        }
        if (scenario is "foreign" or "duplicate")
        {
            acl.InsertAce(acl.Count, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed,
                mask, scenario == "foreign" ? WorldSid() : user, isCallback: false, opaque: null));
        }
        if (scenario == "unprotected") { flags &= ~ControlFlags.DiscretionaryAclProtected; }
        if (scenario == "absent-dacl") { flags &= ~ControlFlags.DiscretionaryAclPresent; }
        var descriptor = new RawSecurityDescriptor(flags, scenario == "owner" ? WorldSid() : user,
            group: null, systemAcl: null,
            discretionaryAcl: scenario == "null-dacl" ? null : scenario == "empty" ? new RawAcl(GenericAcl.AclRevision, 0) : acl);
        var bytes = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(bytes, 0);
        if (scenario == "malformed") { bytes = [1, 2, 3]; }
        if (scenario == "truncated") { bytes = bytes[..^1]; }
        if (scenario == "over-budget") { bytes = new byte[4097]; }

        var helper = typeof(DashboardSingleInstance).Assembly.GetType("WinSight.Dashboard.DashboardObjectSecurity")
            ?.GetMethod("IsTrustedDescriptor", BindingFlags.Static | BindingFlags.NonPublic);
        Assert.NotNull(helper);
        Assert.Equal(expected, Assert.IsType<bool>(helper.Invoke(null, [bytes, user, mask])));
    }

    private static SecurityIdentifier User()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return Assert.IsType<SecurityIdentifier>(identity.User);
    }

    private static SecurityIdentifier SystemSid() => new(WellKnownSidType.LocalSystemSid, null);
    private static SecurityIdentifier WorldSid() => new(WellKnownSidType.WorldSid, null);

    private static MutexSecurity MutexDescriptor(SecurityIdentifier user, bool permissive = false)
    {
        var security = new MutexSecurity();
        security.SetOwner(user);
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new MutexAccessRule(user, MutexRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new MutexAccessRule(SystemSid(), MutexRights.FullControl, AccessControlType.Allow));
        if (permissive)
        {
            security.AddAccessRule(new MutexAccessRule(WorldSid(), MutexRights.Modify | MutexRights.Synchronize, AccessControlType.Allow));
        }
        return security;
    }

    private static EventWaitHandleSecurity EventDescriptor(SecurityIdentifier user, bool permissive = false)
    {
        var security = new EventWaitHandleSecurity();
        security.SetOwner(user);
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new EventWaitHandleAccessRule(user, EventWaitHandleRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new EventWaitHandleAccessRule(SystemSid(), EventWaitHandleRights.FullControl, AccessControlType.Allow));
        if (permissive)
        {
            security.AddAccessRule(new EventWaitHandleAccessRule(WorldSid(), EventWaitHandleRights.Modify, AccessControlType.Allow));
        }
        return security;
    }

    private static void AssertNativeDescriptor(ObjectSecurity actual, SecurityIdentifier user, bool permissive)
    {
        var raw = new RawSecurityDescriptor(actual.GetSecurityDescriptorBinaryForm(), 0);
        Assert.Equal(user, raw.Owner);
        Assert.True(actual.AreAccessRulesProtected);
        Assert.NotNull(raw.DiscretionaryAcl);
        var rules = raw.DiscretionaryAcl.Cast<GenericAce>().ToArray();
        Assert.All(rules, rule => Assert.IsType<CommonAce>(rule));
        Assert.All(rules, rule => Assert.Equal(AceQualifier.AccessAllowed, ((CommonAce)rule).AceQualifier));
        Assert.Equal(permissive, rules.Any(rule => ((CommonAce)rule).SecurityIdentifier == WorldSid()));
        if (!permissive)
        {
            Assert.All(rules, rule => Assert.True(((CommonAce)rule).SecurityIdentifier == user
                || ((CommonAce)rule).SecurityIdentifier == SystemSid()));
        }
    }
}
