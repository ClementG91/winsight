using System.ComponentModel;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using WinSight.Firewall;
using WinSight.FirewallService;
using Xunit;

namespace WinSight.FirewallService.Tests;

public sealed class FirewallServiceWorkerTests
{
    [Fact]
    public async Task Worker_RunsListenerUntilStopped()
    {
        var listener = new BlockingListener();
        using var worker = new FirewallServiceWorker(listener, NullLogger<FirewallServiceWorker>.Instance);

        await worker.StartAsync(CancellationToken.None);
        await listener.Started.WaitAsync(TimeSpan.FromSeconds(5));

        // The listener is still running until the host stops the worker.
        Assert.False(listener.Completed);

        await worker.StopAsync(CancellationToken.None);
        Assert.True(listener.WasCancelled);
    }

    [Fact]
    public async Task Worker_StopsCleanly_WhenListenerCompletesOnItsOwn()
    {
        var listener = new SignalingListener();
        using var worker = new FirewallServiceWorker(listener, NullLogger<FirewallServiceWorker>.Instance);

        await worker.StartAsync(CancellationToken.None);
        // Await the signal rather than a plain field, so completion is observed
        // deterministically regardless of which thread ran ExecuteAsync.
        await listener.Ran.WaitAsync(TimeSpan.FromSeconds(5));
        await worker.StopAsync(CancellationToken.None);
    }

    private sealed class BlockingListener : IFirewallServiceListener
    {
        private readonly TaskCompletionSource _started =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task Started => _started.Task;

        public bool Completed { get; private set; }

        public bool WasCancelled { get; private set; }

        public async Task RunAsync(CancellationToken cancellationToken)
        {
            _started.TrySetResult();
            try
            {
                await Task.Delay(Timeout.Infinite, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                WasCancelled = true;
                throw;
            }
            finally
            {
                Completed = true;
            }
        }
    }

    private sealed class SignalingListener : IFirewallServiceListener
    {
        private readonly TaskCompletionSource _ran =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task Ran => _ran.Task;

        public Task RunAsync(CancellationToken cancellationToken)
        {
            _ran.TrySetResult();
            return Task.CompletedTask;
        }
    }
}

public sealed class FirewallServiceDiagnosticTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), $"winsight-diag-{Guid.NewGuid():N}");

    [Fact]
    public async Task StartupNestedNativeFailure_LogsOnlyInvariantAllowlistedDiagnostic()
    {
        var store = new FirewallPolicyStore(Path.Combine(_directory, "policies.json"), allowEnforcement: true);
        await store.SaveAsync(new OutboundFirewallConfiguration(OutboundFirewallMode.Enforcement,
            [new AppFirewallPolicy(@"C:\attacker\secret.exe", OutboundAction.Block)]));
        var coordinator = TestEnforcementCoordinator.Create(store, new NativeFailureEngine());
        var logger = new CapturingLogger<EnforcementStartupService>();
        var service = new EnforcementStartupService(coordinator, logger);

        await service.StartAsync(CancellationToken.None);

        AssertInvariantEntries(logger.Entries,
        [
            "[FW_STARTUP_APPLY_BEGIN] Applying stored block policies.",
            "[FW_STARTUP_APPLY_FAILED] Stored block policy application failed; the service continues in a degraded state.",
        ]);
    }

    [Fact]
    public async Task WorkerFailureSink_LogsInvariantTemplatesWithoutExceptionAndRequestsCleanStop()
    {
        var logger = new CapturingLogger<FirewallServiceWorker>();
        var lifetime = new RecordingLifetime();
        using var worker = new FirewallServiceWorker(new NativeFailingListener(), logger, lifetime);

        await worker.StartAsync(CancellationToken.None);
        await lifetime.Stopping.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await worker.StopAsync(CancellationToken.None);

        AssertInvariantEntries(logger.Entries,
        [
            "[FW_PIPE_LISTENER_FAILED] The firewall listener stopped unexpectedly.",
            "[FW_SERVICE_STOPPED] WinSight firewall service stopped.",
        ]);
        Assert.Equal(1, lifetime.StopCalls);
    }

    [Fact]
    public async Task Worker_LogsListeningOnlyAfterEndpointReadiness()
    {
        var logger = new CapturingLogger<FirewallServiceWorker>();
        var listener = new DelayedReadyListener();
        using var worker = new FirewallServiceWorker(listener, logger);

        await worker.StartAsync(CancellationToken.None);
        await listener.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Empty(logger.Entries);

        listener.MarkReady();
        await logger.Logged.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(
            "[FW_PIPE_LISTENING] WinSight firewall service listening.",
            Assert.Single(logger.Entries).Message);

        await worker.StopAsync(CancellationToken.None);
    }

    [Fact]
    public async Task ListenerFaultBeforeReadiness_NeverClaimsListeningAndUsesFixedRedactedLog()
    {
        var logger = new CapturingLogger<FirewallServiceWorker>();
        var lifetime = new RecordingLifetime();
        using var worker = new FirewallServiceWorker(new ReadinessFailingListener(), logger, lifetime);

        await worker.StartAsync(CancellationToken.None);
        await lifetime.Stopping.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await worker.StopAsync(CancellationToken.None);

        Assert.Equal(
        [
            "[FW_PIPE_LISTENER_FAILED] The firewall listener stopped unexpectedly.",
            "[FW_SERVICE_STOPPED] WinSight firewall service stopped.",
        ], logger.Entries.Select(entry => entry.Message));
        Assert.DoesNotContain(logger.Entries, entry => entry.Message.Contains("LISTENING", StringComparison.Ordinal));
        Assert.All(logger.Entries, entry =>
        {
            Assert.Null(entry.Exception);
            Assert.False(ContainsSecret(entry.Message));
            Assert.False(ContainsSecret(entry.StableState));
        });
    }

    private static void AssertInvariantEntries(IReadOnlyList<CapturedLogEntry> entries, string[] expectedTemplates)
    {
        Assert.Equal(expectedTemplates, entries.Select(entry => entry.Message));
        Assert.Equal(expectedTemplates, entries.Select(entry => entry.OriginalFormat));
        Assert.All(entries, entry =>
        {
            Assert.Null(entry.Exception);
            Assert.Equal(["{OriginalFormat}"], entry.State.Keys);
            Assert.Equal(entry.Message, entry.State["{OriginalFormat}"]);
            Assert.False(string.IsNullOrWhiteSpace(entry.StableState));
            Assert.False(ContainsSecret(entry.Message));
            Assert.False(ContainsSecret(entry.OriginalFormat));
            Assert.False(ContainsSecret(entry.StableState));
            Assert.All(entry.State, pair =>
            {
                Assert.Equal("{OriginalFormat}", pair.Key);
                Assert.False(ContainsSecret(pair.Value));
            });
        });
    }

    // The reason this type exists: a refusal used to go to stderr, which a Windows service does
    // not have. The operator saw SCM error 1053 and an empty event log, and nothing said why.
    [Theory]
    [InlineData(PathTrustCode.UntrustedOwner)]
    [InlineData(PathTrustCode.WritableByUnprivilegedPrincipal)]
    [InlineData(PathTrustCode.OutsideProgramData)]
    [InlineData(PathTrustCode.ReparsePoint)]
    [InlineData(PathTrustCode.IdentityChanged)]
    public void ServiceStartupLog_StorageProvisioningRefused_NamesTheRuleThatRefused(PathTrustCode code)
    {
        var logger = new CapturingLogger<ServiceStartupLog>();

        new ServiceStartupLog(logger).StorageProvisioningRefused(code);

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Critical, entry.Level);
        Assert.Contains("[FW_STORAGE_PROVISIONING_FAILED]", entry.Message, StringComparison.Ordinal);
        Assert.Contains(code.ToString(), entry.Message, StringComparison.Ordinal);
        Assert.Null(entry.Exception);
    }

    [Fact]
    public void ServiceStartupLog_CarriesStableMarkers()
    {
        var logger = new CapturingLogger<ServiceStartupLog>();
        var log = new ServiceStartupLog(logger);

        log.StorageProvisioningFailed();
        log.StorageUntrusted();
        log.HostReady(OutboundFirewallMode.AuditOnly);

        Assert.Collection(logger.Entries,
            entry => Assert.Contains("[FW_STORAGE_PROVISIONING_FAILED]", entry.Message, StringComparison.Ordinal),
            entry => Assert.Contains("[FW_STORAGE_UNTRUSTED]", entry.Message, StringComparison.Ordinal),
            entry =>
            {
                Assert.Contains("[FW_HOST_READY]", entry.Message, StringComparison.Ordinal);
                Assert.Contains("AuditOnly", entry.Message, StringComparison.Ordinal);
            });
        Assert.All(logger.Entries, entry => Assert.Null(entry.Exception));
    }

    // A PathTrustCode names which rule refused; it must never become a way to disclose which path
    // or which principal tripped it. The VM protocol checks the event log for exactly that.
    [Fact]
    public void ServiceStartupLog_RefusalDisclosesNoPathOrPrincipal()
    {
        var logger = new CapturingLogger<ServiceStartupLog>();

        new ServiceStartupLog(logger).StorageProvisioningRefused(PathTrustCode.UntrustedOwner);

        var entry = Assert.Single(logger.Entries);
        Assert.False(ContainsSecret(entry.Message));
        Assert.False(ContainsSecret(entry.StableState));
        Assert.All(entry.State, pair => Assert.False(ContainsSecret(pair.Value)));
    }

    // The exception carries the code as data precisely so the code can be logged without the
    // message, which for a native failure carries paths and SIDs.
    [Fact]
    public void PolicyStorageTrustException_CarriesTheCodeAsData_AndStaysCatchableAsInvalidOperation()
    {
        var refusal = new PolicyStorageTrustException(PathTrustCode.WritableByUnprivilegedPrincipal);

        Assert.Equal(PathTrustCode.WritableByUnprivilegedPrincipal, refusal.Code);
        Assert.IsAssignableFrom<InvalidOperationException>(refusal);
    }

    [Fact]
    public void FirewallServiceLoggerMessages_StaticContractHasNoExceptionParameters()
    {
        foreach (var type in new[] { typeof(EnforcementStartupService), typeof(FirewallServiceWorker) })
        {
            var logMethods = type.GetMethods(System.Reflection.BindingFlags.Instance |
                System.Reflection.BindingFlags.NonPublic).Where(method => method.Name.StartsWith("Log", StringComparison.Ordinal));
            Assert.NotEmpty(logMethods);
            Assert.All(logMethods, method =>
                Assert.DoesNotContain(method.GetParameters(), parameter => typeof(Exception).IsAssignableFrom(parameter.ParameterType)));
        }
    }

    // Handing an exception to the logger is how a path or a SID reaches the event log: native
    // failures carry both in their text. This holds the whole startup surface to that rule, so a
    // later message cannot quietly reintroduce the leak by taking an Exception parameter.
    [Fact]
    public void ServiceStartupLog_ContractTakesNoExceptionParameter()
    {
        var logMethods = typeof(ServiceStartupLog)
            .GetMethods(System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Public)
            .Where(method => method.DeclaringType == typeof(ServiceStartupLog));

        Assert.NotEmpty(logMethods);
        Assert.All(logMethods, method =>
            Assert.DoesNotContain(method.GetParameters(),
                parameter => typeof(Exception).IsAssignableFrom(parameter.ParameterType)));
    }

    private static bool ContainsSecret(string text) =>
        text.Contains("attacker", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("secret.exe", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("S-1-5-21-666", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("native detail", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("D:(A;;FA", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("schemaVersion", StringComparison.OrdinalIgnoreCase);

    public void Dispose()
    {
        if (Directory.Exists(_directory)) Directory.Delete(_directory, recursive: true);
    }

    private sealed class NativeFailureEngine : IOutboundFirewallEngine
    {
        public bool IsSupported => true;
        public Task ApplyAsync(AppFirewallPolicy policy, CancellationToken cancellationToken = default) =>
            throw new Win32Exception(5, @"native detail C:\attacker\secret.exe S-1-5-21-666");
        public Task RemoveAsync(string executablePath, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }

    private sealed class NativeFailingListener : IFirewallServiceListener
    {
        public Task RunAsync(CancellationToken cancellationToken) =>
            throw new Win32Exception(5, @"native detail C:\attacker\secret.exe S-1-5-21-666");
    }

    private sealed class ReadinessFailingListener : IFirewallServiceListener, IFirewallServiceReadiness
    {
        private readonly TaskCompletionSource _ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Task Ready => _ready.Task;
        public Task RunAsync(CancellationToken cancellationToken) =>
            throw new Win32Exception(5, @"native detail C:\attacker\secret.exe S-1-5-21-666");
    }

    private sealed class DelayedReadyListener : IFirewallServiceListener, IFirewallServiceReadiness
    {
        private readonly TaskCompletionSource _ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Task Ready => _ready.Task;
        public void MarkReady() => _ready.TrySetResult();
        public async Task RunAsync(CancellationToken cancellationToken)
        {
            Started.TrySetResult();
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
        }
    }

    private sealed class RecordingLifetime : IHostApplicationLifetime
    {
        public TaskCompletionSource Stopping { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public int StopCalls { get; private set; }
        public CancellationToken ApplicationStarted => CancellationToken.None;
        public CancellationToken ApplicationStopping => CancellationToken.None;
        public CancellationToken ApplicationStopped => CancellationToken.None;
        public void StopApplication() { StopCalls++; Stopping.TrySetResult(); }
    }

    private sealed class CapturingLogger<T> : ILogger<T>
    {
        public List<CapturedLogEntry> Entries { get; } = [];
        public TaskCompletionSource Logged { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            var structured = state is IEnumerable<KeyValuePair<string, object?>> values
                ? values.ToDictionary(pair => pair.Key, pair => Convert.ToString(pair.Value,
                    System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty, StringComparer.Ordinal)
                : new Dictionary<string, string>(StringComparer.Ordinal);
            var stableState = structured.Count > 0
                ? string.Join(";", structured.OrderBy(pair => pair.Key, StringComparer.Ordinal)
                    .Select(pair => $"{pair.Key}={pair.Value}"))
                : Convert.ToString(state, System.Globalization.CultureInfo.InvariantCulture) ?? state?.GetType().FullName ?? "<null>";
            structured.TryGetValue("{OriginalFormat}", out var originalFormat);
            Entries.Add(new(logLevel, formatter(state, exception), exception, structured,
                originalFormat ?? stableState, stableState));
            Logged.TrySetResult();
        }
    }

    private sealed record CapturedLogEntry(
        LogLevel Level,
        string Message,
        Exception? Exception,
        IReadOnlyDictionary<string, string> State,
        string OriginalFormat,
        string StableState);
}

public sealed class FirewallServicePathsTests : IDisposable
{
    private readonly string _directory = Path.Combine(
        Path.GetTempPath(),
        $"winsight-fw-svc-paths-{Guid.NewGuid():N}");

    [Fact]
    public void CreateHardenedDirectorySecurity_GrantsOnlyTrustedPrincipals_AndIsProtected()
    {
        var security = FirewallServicePaths.CreateHardenedDirectorySecurity();

        Assert.True(security.AreAccessRulesProtected);
        var rules = security
            .GetAccessRules(includeExplicit: true, includeInherited: false, typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>()
            .ToList();

        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);

        Assert.Contains(rules, r => r.IdentityReference.Equals(system)
            && r.FileSystemRights.HasFlag(FileSystemRights.FullControl)
            && r.AccessControlType == AccessControlType.Allow);
        Assert.Contains(rules, r => r.IdentityReference.Equals(administrators)
            && r.AccessControlType == AccessControlType.Allow);
        Assert.DoesNotContain(rules, r => r.IdentityReference.Equals(everyone));
    }

    [Fact]
    public void ProvisionDirectory_CreatesDirectory_WithProtectedAcl()
    {
        var provisioned = FirewallServicePaths.ProvisionDirectory(_directory);

        Assert.True(Directory.Exists(provisioned));
        var security = new DirectoryInfo(provisioned).GetAccessControl();
        Assert.True(security.AreAccessRulesProtected);
    }

    // A directory outside ProgramData is not ours to re-own: claiming it would also demand
    // elevation the caller may not have. It still receives the hardened ACL.
    [Fact]
    public void CreateHardenedDirectorySecurity_WithoutOwnershipClaim_LeavesOwnerUnset() =>
        Assert.Null(FirewallServicePaths.CreateHardenedDirectorySecurity()
            .GetOwner(typeof(SecurityIdentifier)));

    // Regression: an elevated admin console left the directory owned by the individual user, which
    // the path-trust inspector refuses, so the service could not start (sc start reported 1053).
    [Fact]
    public void CreateHardenedDirectorySecurity_WithOwnershipClaim_OwnerIsAdministrators() =>
        Assert.Equal(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            FirewallServicePaths.CreateHardenedDirectorySecurity(claimOwnership: true)
                .GetOwner(typeof(SecurityIdentifier)));

    // Regression: only the leaf used to be provisioned, so the intermediate directory that
    // CreateDirectory makes implicitly (ProgramData\WinSight) kept its parent's inherited,
    // user-writable ACL and stayed owned by whoever created it. The path-trust inspector rightly
    // refused the whole chain, and the service could not start (sc start reported 1053).
    [Fact]
    public void ProvisionedComponents_CoversEveryComponentBelowTheRoot_OutermostFirst() =>
        Assert.Equal(
            [Path.Combine(_directory, "WinSight"), Path.Combine(_directory, "WinSight", "firewall")],
            FirewallServicePaths.ProvisionedComponents(
                Path.Combine(_directory, "WinSight", "firewall"), _directory));

    // The root belongs to Windows (ProgramData in production): re-ACLing it, or walking past it up
    // to the drive root, would be catastrophic.
    [Fact]
    public void ProvisionedComponents_NeverIncludesTheRootOrAnythingAboveIt()
    {
        var components = FirewallServicePaths.ProvisionedComponents(
            Path.Combine(_directory, "WinSight", "firewall"), _directory);

        Assert.DoesNotContain(Path.TrimEndingDirectorySeparator(_directory), components);
        Assert.All(components, component =>
            Assert.StartsWith(_directory + Path.DirectorySeparatorChar, component, StringComparison.OrdinalIgnoreCase));
    }

    // A directory outside the root is not ours to walk up from: provisioning stops at it.
    [Fact]
    public void ProvisionedComponents_OutsideTheRoot_IsThatDirectoryAlone() =>
        Assert.Equal(
            [Path.TrimEndingDirectorySeparator(_directory)],
            FirewallServicePaths.ProvisionedComponents(
                _directory, Path.Combine(Path.GetTempPath(), $"unrelated-{Guid.NewGuid():N}")));

    [Fact]
    public void ProvisionedComponents_DefaultPolicyDirectory_IncludesTheProductRootFolder()
    {
        var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);

        var components = FirewallServicePaths.ProvisionedComponents(
            FirewallServicePaths.DefaultDirectory, programData);

        Assert.Equal(
            [Path.Combine(programData, "WinSight"), Path.Combine(programData, "WinSight", "firewall")],
            components);
    }

    [Fact]
    public void DefaultPolicyFile_IsUnderProgramData()
    {
        var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        Assert.StartsWith(programData, FirewallServicePaths.DefaultPolicyFile, StringComparison.OrdinalIgnoreCase);
        Assert.EndsWith("policies.json", FirewallServicePaths.DefaultPolicyFile, StringComparison.OrdinalIgnoreCase);
    }

    public void Dispose()
    {
        if (!Directory.Exists(_directory))
        {
            return;
        }

        // The hardened ACL locks out the (non-admin) test user, but the creator remains
        // the owner and can always rewrite the DACL. Restore access before cleaning up.
        try
        {
            var info = new DirectoryInfo(_directory);
            var security = info.GetAccessControl();
            security.SetAccessRuleProtection(isProtected: false, preserveInheritance: false);
            using var current = WindowsIdentity.GetCurrent();
            security.AddAccessRule(new FileSystemAccessRule(
                current.User!, FileSystemRights.FullControl, InheritanceFlags.None, PropagationFlags.None, AccessControlType.Allow));
            info.SetAccessControl(security);
            Directory.Delete(_directory, recursive: true);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            // Best-effort cleanup of a temp directory; leave it to the OS otherwise.
        }
    }
}
