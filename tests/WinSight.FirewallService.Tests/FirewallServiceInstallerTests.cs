using System.ComponentModel;
using WinSight.Firewall;
using WinSight.FirewallService;
using Xunit;

namespace WinSight.FirewallService.Tests;

public sealed class FirewallServiceCommandLineTests
{
    [Theory]
    [InlineData("run", FirewallServiceVerb.Run)]
    [InlineData("install", FirewallServiceVerb.Install)]
    [InlineData("INSTALL", FirewallServiceVerb.Install)]
    [InlineData("uninstall", FirewallServiceVerb.Uninstall)]
    [InlineData("remove", FirewallServiceVerb.Uninstall)]
    [InlineData("status", FirewallServiceVerb.Status)]
    [InlineData("wfp-selftest", FirewallServiceVerb.WfpSelfTest)]
    [InlineData("wfp-provision", FirewallServiceVerb.WfpProvision)]
    [InlineData("wfp-deprovision", FirewallServiceVerb.WfpDeprovision)]
    [InlineData("wfp-status", FirewallServiceVerb.WfpStatus)]
    [InlineData("wfp-filter-add", FirewallServiceVerb.WfpFilterAdd)]
    [InlineData("wfp-filter-remove", FirewallServiceVerb.WfpFilterRemove)]
    [InlineData("wfp-block-add", FirewallServiceVerb.WfpBlockAdd)]
    [InlineData("wfp-block-remove", FirewallServiceVerb.WfpBlockRemove)]
    [InlineData("wfp-block-status", FirewallServiceVerb.WfpBlockStatus)]
    [InlineData("enforce-status", FirewallServiceVerb.EnforceStatus)]
    [InlineData("enforce-enable", FirewallServiceVerb.EnforceEnable)]
    [InlineData("enforce-disable", FirewallServiceVerb.EnforceDisable)]
    [InlineData("block-app", FirewallServiceVerb.BlockApp)]
    [InlineData("allow-app", FirewallServiceVerb.AllowApp)]
    [InlineData("bogus", FirewallServiceVerb.Unknown)]
    public void Parse_MapsFirstArgumentToVerb(string arg, FirewallServiceVerb expected) =>
        Assert.Equal(expected, FirewallServiceCommandLine.Parse([arg]));

    [Fact]
    public void Parse_NoArguments_DefaultsToRun()
    {
        Assert.Equal(FirewallServiceVerb.Run, FirewallServiceCommandLine.Parse(null));
        Assert.Equal(FirewallServiceVerb.Run, FirewallServiceCommandLine.Parse([]));
    }

    [Fact]
    public void CliDiagnosticSink_StaticContractUsesInvariantCodesWithoutInterpolation()
    {
        var programPath = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory,
            "..", "..", "..", "..", "..", "src", "WinSight.FirewallService", "Program.cs"));
        var source = File.ReadAllText(programPath);

        Assert.DoesNotContain("Console.Error.WriteLine($", source, StringComparison.Ordinal);
        foreach (var code in new[]
        {
            "[FW_INSTALL_FAILED]", "[FW_UNINSTALL_FAILED]", "[FW_SERVICE_STATUS_UNAVAILABLE]",
            "[FW_STORAGE_PROVISIONING_FAILED]", "[FW_STORAGE_UNTRUSTED]",
            "[FW_ENFORCEMENT_STATUS_UNAVAILABLE]",
        })
        {
            Assert.Contains($"Console.Error.WriteLine(\"{code}\")", source, StringComparison.Ordinal);
        }
    }
}

public sealed class FirewallServiceInstallerTests
{
    [Fact]
    public void BuildBinaryPath_QuotesTheExecutable_AndAppendsRunVerb()
    {
        var binary = FirewallServiceInstaller.BuildBinaryPath(@"C:\Program Files\WinSight\winsight-firewall-service.exe");

        Assert.Equal(@"""C:\Program Files\WinSight\winsight-firewall-service.exe"" run", binary);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void BuildBinaryPath_RejectsEmptyPath(string path) =>
        Assert.Throws<ArgumentException>(() => FirewallServiceInstaller.BuildBinaryPath(path));

    [Fact]
    public void ServiceName_HasNoWhitespace_ForScmCompatibility() =>
        Assert.DoesNotContain(FirewallServiceInstaller.ServiceName, character => char.IsWhiteSpace(character));

    [Fact]
    public void Description_TruthfullyDescribesOptInEnforcement()
    {
        Assert.Contains("opt-in", FirewallServiceInstaller.Description, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("effective runtime state", FirewallServiceInstaller.Description, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("audit-only", FirewallServiceInstaller.Description, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("does not install", FirewallServiceInstaller.Description, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("does not apply", FirewallServiceInstaller.Description, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("no filter", FirewallServiceInstaller.Description, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void SetDescription_NativeFalse_ThrowsWin32ExceptionWithCapturedError()
    {
        const int nativeError = 1234;
        FirewallServiceInstaller.ChangeServiceDescription change =
            (IntPtr _, uint _, ref FirewallServiceInstaller.ServiceDescription _) => false;

        var exception = Assert.Throws<Win32Exception>(() => FirewallServiceInstaller.SetDescription(
            new IntPtr(42),
            "description",
            change,
            () => nativeError));

        Assert.Equal(nativeError, exception.NativeErrorCode);
    }

    [Fact]
    public void SetDescription_NativeTrue_DoesNotReadLastErrorOrThrow()
    {
        var lastErrorReads = 0;
        FirewallServiceInstaller.ChangeServiceDescription change =
            (IntPtr _, uint _, ref FirewallServiceInstaller.ServiceDescription _) => true;

        FirewallServiceInstaller.SetDescription(
            new IntPtr(42),
            "description",
            change,
            () =>
            {
                lastErrorReads++;
                return 5;
            });

        Assert.Equal(0, lastErrorReads);
    }

    [Theory]
    [InlineData(1060, false)]
    [InlineData(5, true)]
    [InlineData(87, true)]
    public void InterpretServiceQueryResult_Only1060MeansAbsent(int error, bool throws)
    {
        if (throws)
        {
            var exception = Assert.Throws<Win32Exception>(() =>
                FirewallServiceInstaller.InterpretServiceQueryResult(IntPtr.Zero, error));
            Assert.Equal(error, exception.NativeErrorCode);
            return;
        }

        Assert.False(FirewallServiceInstaller.InterpretServiceQueryResult(IntPtr.Zero, error));
    }

    [Fact]
    public void InterpretServiceQueryResult_NonZeroHandleMeansInstalledRegardlessOfStaleError() =>
        Assert.True(FirewallServiceInstaller.InterpretServiceQueryResult(new IntPtr(42), 5));

    [Fact]
    public void StatusCommand_StaticContractReportsScmFailureWithStableCodeAndNonZeroExit()
    {
        var programPath = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory,
            "..", "..", "..", "..", "..", "src", "WinSight.FirewallService", "Program.cs"));
        var source = File.ReadAllText(programPath);
        const string expectedCatch = "catch (Win32Exception)\r\n    {\r\n        Console.Error.WriteLine(\"[FW_SERVICE_STATUS_UNAVAILABLE]\");\r\n        return 1;\r\n    }";

        Assert.Contains(expectedCatch, source.Replace("\n", "\r\n").Replace("\r\r\n", "\r\n"), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(PathTrustCode.InvalidPath)]
    [InlineData(PathTrustCode.MissingComponent)]
    [InlineData(PathTrustCode.ReparsePoint)]
    [InlineData(PathTrustCode.UntrustedOwner)]
    [InlineData(PathTrustCode.WritableByUnprivilegedPrincipal)]
    [InlineData(PathTrustCode.InspectionFailed)]
    public void Install_TrustDenial_FailsBeforeScm(PathTrustCode code)
    {
        var exception = Assert.Throws<InvalidOperationException>(() =>
            FirewallServiceInstaller.Install(@"C:\untrusted\service.exe", new DenyingInspector(code)));

        Assert.Contains($"[{code}]", exception.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(@"C:\untrusted\service.exe", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(PathTrustCode.InvalidPath, "The path is invalid.")]
    [InlineData(PathTrustCode.ReparsePoint, "A path component is a reparse point.")]
    [InlineData(PathTrustCode.UntrustedOwner, "A path component has an untrusted owner.")]
    [InlineData(PathTrustCode.WritableByUnprivilegedPrincipal, "A path component is writable by an unprivileged principal.")]
    [InlineData(PathTrustCode.InspectionFailed, "The path trust inspection could not be completed.")]
    public void PathTrustDecision_DenialIsStructuredAndStable(PathTrustCode code, string message)
    {
        var decision = PathTrustDecision.Deny(code);

        Assert.False(decision.IsTrusted);
        Assert.Equal(code, decision.Code);
        Assert.Equal(message, decision.Message);
    }

    [Fact]
    public void CanonicalScmPath_UsesInspectedCanonicalPathExactly()
    {
        var inspector = new ScriptedInspector(@"C:\canonical\service.exe", PathTrustDecision.Allow(), PathTrustDecision.Allow());
        var scm = new RecordingScm(deleteResult: true);

        FirewallServiceInstaller.Install(@"C:\syntactic\..\service.exe", inspector, scm);

        Assert.Equal("\"C:\\canonical\\service.exe\" run", scm.BinaryPath);
    }

    [Theory]
    [InlineData(true, ServiceInstallTrustCode.PathChangedRolledBack)]
    [InlineData(false, ServiceInstallTrustCode.RollbackFailed)]
    public void DeleteServiceRollback_PostCreateTrustDenialHasStableOutcome(
        bool deleteResult, ServiceInstallTrustCode expected)
    {
        var inspector = new ScriptedInspector(@"C:\canonical\service.exe",
            PathTrustDecision.Allow(), PathTrustDecision.Deny(PathTrustCode.IdentityChanged));
        var scm = new RecordingScm(deleteResult);

        var exception = Assert.Throws<ServiceInstallTrustException>(() =>
            FirewallServiceInstaller.Install(@"C:\input.exe", inspector, scm));

        Assert.Equal(expected, exception.Code);
        Assert.Equal(1, scm.Registration.DeleteCalls);
        Assert.DoesNotContain(@"C:\input.exe", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(false, false, ServiceInstallTrustCode.PostCreateOperationRolledBack)]
    [InlineData(false, true, ServiceInstallTrustCode.RollbackFailed)]
    [InlineData(true, false, ServiceInstallTrustCode.RollbackFailed)]
    public void SetDescriptionFailure_CheckedRollbackHasStableCodeAndCanonicalPath(
        bool deleteThrows, bool deleteReturnsFalse, ServiceInstallTrustCode expected)
    {
        var inspector = new ScriptedInspector(@"C:\canonical\service.exe",
            PathTrustDecision.Allow(), PathTrustDecision.Allow());
        var scm = new RecordingScm(!deleteReturnsFalse, descriptionThrows: true, deleteThrows: deleteThrows);

        var exception = Assert.Throws<ServiceInstallTrustException>(() =>
            FirewallServiceInstaller.Install(@"C:\syntactic\service.exe", inspector, scm));

        Assert.Equal(expected, exception.Code);
        Assert.Equal("\"C:\\canonical\\service.exe\" run", scm.BinaryPath);
        Assert.Equal(1, scm.Registration.DeleteCalls);
        Assert.DoesNotContain(@"C:\syntactic\service.exe", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Install_SetDescriptionFailure_DeletesExactlyOnceAndUsesStableRollbackCode()
    {
        var inspector = new ScriptedInspector(@"C:\canonical\service.exe",
            PathTrustDecision.Allow(), PathTrustDecision.Allow());
        var scm = new RecordingScm(deleteResult: true, descriptionThrows: true);

        var exception = Assert.Throws<ServiceInstallTrustException>(() =>
            FirewallServiceInstaller.Install(@"C:\input\service.exe", inspector, scm));

        Assert.Equal(ServiceInstallTrustCode.PostCreateOperationRolledBack, exception.Code);
        Assert.Equal(1, scm.Registration.DeleteCalls);
        Assert.DoesNotContain(@"C:\input\service.exe", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    private sealed class DenyingInspector(PathTrustCode code) : IServicePathTrustInspector
    {
        public PathTrustDecision InspectExecutable(string path) => PathTrustDecision.Deny(code);

        public PathTrustDecision InspectPolicyStorage(string directory, string policyFile) =>
            throw new NotSupportedException();
    }

    private sealed class ScriptedInspector(
        string canonicalPath,
        PathTrustDecision preUse,
        PathTrustDecision postUse) : IServicePathTrustInspector
    {
        private int _revalidations;
        public PathTrustDecision InspectExecutable(string path) => PathTrustDecision.Allow();
        public PathTrustDecision InspectPolicyStorage(string directory, string policyFile) => PathTrustDecision.Allow();
        public PathTrustEvidence InspectExecutableEvidence(string path) =>
            new(PathTrustDecision.Allow(), canonicalPath, new Dictionary<string, string>());
        public PathTrustDecision Revalidate(PathTrustEvidence evidence) =>
            Interlocked.Increment(ref _revalidations) == 1 ? preUse : postUse;
    }

    private sealed class RecordingScm(
        bool deleteResult,
        bool descriptionThrows = false,
        bool deleteThrows = false) : IServiceControlManager
    {
        public string? BinaryPath { get; private set; }
        public RecordingRegistration Registration { get; } = new(deleteResult, descriptionThrows, deleteThrows);
        public IServiceRegistration Create(string binaryPath)
        {
            BinaryPath = binaryPath;
            return Registration;
        }
    }

    private sealed class RecordingRegistration(
        bool deleteResult,
        bool descriptionThrows,
        bool deleteThrows) : IServiceRegistration
    {
        public int DeleteCalls { get; private set; }
        public void SetDescription(string description)
        { if (descriptionThrows) throw new Win32Exception(5); }
        public bool Delete()
        {
            DeleteCalls++;
            if (deleteThrows) throw new Win32Exception(5);
            return deleteResult;
        }
        public void Dispose() { }
    }
}

public sealed class WfpProvisioningTests
{
    [Fact]
    public void WfpObjectKeys_AreStableAndDistinct()
    {
        var keys = new[]
        {
            WfpProvisioning.ProviderKey, WfpProvisioning.SublayerKey,
            WfpProvisioning.PermitFilterKeyV4, WfpProvisioning.PermitFilterKeyV6,
        };
        Assert.DoesNotContain(Guid.Empty, keys);
        Assert.Equal(keys.Length, keys.Distinct().Count());
    }

    [Fact]
    public void BlockFilterKeys_AreStablePerPath_DistinctPerLayer_AndDifferBetweenApps()
    {
        var a1 = WfpProvisioning.BlockFilterKeys(@"C:\apps\a.exe");
        var a2 = WfpProvisioning.BlockFilterKeys(@"C:\apps\a.exe");
        var b = WfpProvisioning.BlockFilterKeys(@"C:\apps\b.exe");

        Assert.Equal(a1, a2);                    // stable across calls
        Assert.NotEqual(a1.V4, a1.V6);           // IPv4 and IPv6 keys differ
        Assert.NotEqual(a1.V4, b.V4);            // different apps get different keys
        Assert.NotEqual(Guid.Empty, a1.V4);
    }

    [Fact]
    public void BlockFilterKeys_AreCaseInsensitiveOnPath()
    {
        Assert.Equal(
            WfpProvisioning.BlockFilterKeys(@"C:\Apps\A.exe"),
            WfpProvisioning.BlockFilterKeys(@"c:\apps\a.exe"));
    }

    [Fact]
    public void BlockFilterKeys_CanonicalizeQuotedAndRelativeSegments_SameAsClean()
    {
        // Quoted and dot-segmented forms must derive the same key as the clean canonical
        // path, or a block installed via one form is orphaned when re-applied via another.
        var clean = WfpProvisioning.BlockFilterKeys(@"C:\apps\a.exe");
        Assert.Equal(clean, WfpProvisioning.BlockFilterKeys("\"C:\\apps\\a.exe\""));
        Assert.Equal(clean, WfpProvisioning.BlockFilterKeys(@"C:\apps\.\a.exe"));
    }

    [Fact]
    public void BlockFilterKeys_RejectsRelativePath() =>
        Assert.Throws<ArgumentException>(() => WfpProvisioning.BlockFilterKeys(@"a.exe"));
}

public sealed class WfpOutboundFirewallEngineTests
{
    [Fact]
    public void Engine_ReportsSupported() =>
        Assert.True(new WfpOutboundFirewallEngine().IsSupported);

    [Fact]
    public async Task ApplyAsync_HonoursCancellation()
    {
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        var engine = new WfpOutboundFirewallEngine();

        await Assert.ThrowsAsync<OperationCanceledException>(
            () => engine.ApplyAsync(new WinSight.Firewall.AppFirewallPolicy(@"C:\a.exe", WinSight.Firewall.OutboundAction.Block), cts.Token));
    }
}

public sealed class EnforcementCoordinatorTests : IDisposable
{
    private readonly string _directory = Path.Combine(
        Path.GetTempPath(), $"winsight-enforce-{Guid.NewGuid():N}");

    private FirewallPolicyStore Store() =>
        new(Path.Combine(_directory, "policies.json"), allowEnforcement: true);

    [Fact]
    public async Task SetPolicy_Block_PersistsWithoutApplyingInAuditOnly()
    {
        var store = Store();
        var engine = new RecordingEngine();
        var coordinator = TestEnforcementCoordinator.Create(store, engine);

        await coordinator.SetPolicyAsync(@"C:\apps\a.exe", OutboundAction.Block);

        var stored = Assert.Single((await store.LoadAsync()).Policies);
        Assert.Equal(OutboundAction.Block, stored.Action);
        Assert.Empty(engine.Applied);
        Assert.Empty(engine.Removed);
    }

    [Fact]
    public async Task SetPolicy_CanonicalizesPath_SoStoreAndEngineAgree()
    {
        var store = Store();
        var engine = new RecordingEngine();
        var coordinator = TestEnforcementCoordinator.Create(store, engine);

        await coordinator.SetPolicyAsync("\"C:\\apps\\a.exe\"", OutboundAction.Block);

        var stored = Assert.Single((await store.LoadAsync()).Policies);
        Assert.Equal(@"C:\apps\a.exe", stored.ExecutablePath);
        Assert.Empty(engine.Applied);
        Assert.Empty(engine.Removed);
    }

    [Fact]
    public async Task Enable_PersistsEnforcement_AndAppliesOnlyBlockPolicies()
    {
        var store = Store();
        await store.SaveAsync(new OutboundFirewallConfiguration(OutboundFirewallMode.AuditOnly,
        [
            new AppFirewallPolicy(@"C:\apps\block.exe", OutboundAction.Block),
            new AppFirewallPolicy(@"C:\apps\allow.exe", OutboundAction.Allow),
        ]));
        var engine = new RecordingEngine();
        var coordinator = TestEnforcementCoordinator.Create(store, engine);

        await coordinator.EnableAsync();

        Assert.Equal(OutboundFirewallMode.Enforcement, await coordinator.GetModeAsync());
        var applied = Assert.Single(engine.Applied);
        Assert.EndsWith("block.exe", applied.ExecutablePath, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(FirewallEnforcementState.Active, coordinator.EffectiveState);
    }

    [Fact]
    public async Task Disable_LiftsEveryFilter_ThenPersistsAuditOnly()
    {
        var store = Store();
        await store.SaveAsync(new OutboundFirewallConfiguration(OutboundFirewallMode.Enforcement,
            [new AppFirewallPolicy(@"C:\apps\block.exe", OutboundAction.Block)]));
        var engine = new RecordingEngine();
        var coordinator = TestEnforcementCoordinator.Create(store, engine);

        await coordinator.DisableAsync();

        Assert.Contains(engine.Removed, path => path.EndsWith("block.exe", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(OutboundFirewallMode.AuditOnly, await coordinator.GetModeAsync());
        Assert.Equal(FirewallEnforcementState.AuditOnly, coordinator.EffectiveState);
    }

    [Fact]
    public async Task ApplyBlocks_AuditOnly_DoesNotCallEngine()
    {
        var store = Store();
        await store.SaveAsync(new OutboundFirewallConfiguration(OutboundFirewallMode.AuditOnly,
            [new AppFirewallPolicy(@"C:\apps\block.exe", OutboundAction.Block)]));
        var engine = new RecordingEngine();
        var coordinator = TestEnforcementCoordinator.Create(store, engine);

        await coordinator.ApplyBlocksAsync();

        Assert.Empty(engine.Applied);
        Assert.Empty(engine.Removed);
        Assert.Equal(FirewallEnforcementState.AuditOnly, coordinator.EffectiveState);
    }

    [Fact]
    public async Task Enable_PersistsEnforcementBeforeApplyingFilters()
    {
        var store = Store();
        await store.SaveAsync(new OutboundFirewallConfiguration(OutboundFirewallMode.AuditOnly,
            [new AppFirewallPolicy(@"C:\apps\block.exe", OutboundAction.Block)]));
        var observedMode = OutboundFirewallMode.AuditOnly;
        var engine = new CallbackEngine(onApply: async () => observedMode = (await store.LoadAsync()).Mode);
        var coordinator = TestEnforcementCoordinator.Create(store, engine);

        await coordinator.EnableAsync();

        Assert.Equal(OutboundFirewallMode.Enforcement, observedMode);
    }

    [Fact]
    public async Task Disable_RemovesFiltersBeforePersistingAuditOnly()
    {
        var store = Store();
        await store.SaveAsync(new OutboundFirewallConfiguration(OutboundFirewallMode.Enforcement,
            [new AppFirewallPolicy(@"C:\apps\block.exe", OutboundAction.Block)]));
        var observedMode = OutboundFirewallMode.AuditOnly;
        var engine = new CallbackEngine(onRemove: async () => observedMode = (await store.LoadAsync()).Mode);
        var coordinator = TestEnforcementCoordinator.Create(store, engine);

        await coordinator.DisableAsync();

        Assert.Equal(OutboundFirewallMode.Enforcement, observedMode);
        Assert.Equal(OutboundFirewallMode.AuditOnly, (await store.LoadAsync()).Mode);
    }

    [Fact]
    public async Task UntrustedStorage_DeniesBeforeEngineUse()
    {
        var store = new FirewallPolicyStore(Path.Combine(_directory, "policies.json"), allowEnforcement: true,
            storageTrust: () => (false, "StorageInspectionFailed"));
        var engine = new RecordingEngine();
        var coordinator = TestEnforcementCoordinator.Create(store, engine);

        var exception = await Assert.ThrowsAsync<FirewallStorageTrustException>(() => coordinator.ApplyBlocksAsync());

        Assert.Equal("StorageInspectionFailed", exception.Code);
        Assert.Empty(engine.Applied);
        Assert.Empty(engine.Removed);
    }

    [Fact]
    public async Task UntrustedStorage_DoesNotConstructBackend()
    {
        var store = new FirewallPolicyStore(Path.Combine(_directory, "policies.json"), allowEnforcement: true,
            storageTrust: () => (false, "StorageInspectionFailed"));
        var constructions = 0;
        var coordinator = TestEnforcementCoordinator.Create(store, () =>
        {
            constructions++;
            return new RecordingEngine();
        });

        await Assert.ThrowsAsync<FirewallStorageTrustException>(() => coordinator.EnableAsync());

        Assert.Equal(0, constructions);
    }

    [Fact]
    public async Task EmergencyDisable_UsesOwnedCleanupCapabilityOnly()
    {
        var store = Store();
        var policies = new[] { new AppFirewallPolicy(@"C:\apps\owned.exe", OutboundAction.Block) };
        await store.SaveAsync(new OutboundFirewallConfiguration(OutboundFirewallMode.Enforcement, policies));
        var engine = new CleanupEngine();
        var coordinator = TestEnforcementCoordinator.Create(store, engine);

        await coordinator.EmergencyDisableAsync();

        Assert.Equal(policies, engine.CleanupPolicies);
        Assert.Empty(engine.Applied);
        Assert.Empty(engine.Removed);
        Assert.Equal(OutboundFirewallMode.AuditOnly, (await store.LoadAsync()).Mode);
    }

    [Fact]
    public async Task ConcurrentEnableAndEmergencyDisable_AreSerializedInOrder()
    {
        var store = Store();
        await store.SaveAsync(new OutboundFirewallConfiguration(OutboundFirewallMode.AuditOnly,
            [new AppFirewallPolicy(@"C:\apps\owned.exe", OutboundAction.Block)]));
        var engine = new BlockingCleanupEngine();
        var coordinator = TestEnforcementCoordinator.Create(store, engine);

        var enable = coordinator.EnableAsync();
        await engine.ApplyStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var emergency = coordinator.EmergencyDisableAsync();
        Assert.False(emergency.IsCompleted);

        engine.ReleaseApply.TrySetResult();
        await Task.WhenAll(enable, emergency);

        Assert.Equal(["apply", "cleanup"], engine.Events);
        Assert.Equal(OutboundFirewallMode.AuditOnly, (await store.LoadAsync()).Mode);
    }

    [Theory]
    [InlineData(true, "UpsertPersistenceFailed")]
    [InlineData(false, "UpsertRollbackFailed")]
    public async Task SaveFailureCompensation_UpsertRestoresLiveStateOrReportsRollback(bool rollbackSucceeds, string code)
    {
        var seed = Store();
        await seed.SaveAsync(new OutboundFirewallConfiguration(OutboundFirewallMode.Enforcement, []));
        var store = new FirewallPolicyStore(Path.Combine(_directory, "policies.json"), allowEnforcement: true,
            storageTrustGuard: new FailSecondInspectGuard());
        var engine = new ScriptedEngine(failRemove: !rollbackSucceeds);
        var coordinator = TestEnforcementCoordinator.Create(store, engine);

        var exception = await Assert.ThrowsAsync<FirewallTransitionException>(() =>
            coordinator.UpsertPolicyAsync(new AppFirewallPolicy(@"C:\apps\new.exe", OutboundAction.Block)));

        Assert.Equal(code, exception.Code);
        Assert.Equal(["apply:new.exe", "remove:new.exe"], engine.Events);
        Assert.Empty((await seed.LoadAsync()).Policies);
        Assert.Equal(FirewallEnforcementState.Degraded, coordinator.EffectiveState);
    }

    [Theory]
    [InlineData(true, "RemovePersistenceFailed")]
    [InlineData(false, "RemoveRollbackFailed")]
    public async Task SaveFailureCompensation_RemoveRestoresLiveStateOrReportsRollback(bool rollbackSucceeds, string code)
    {
        var seed = Store();
        await seed.SaveAsync(new OutboundFirewallConfiguration(OutboundFirewallMode.Enforcement,
            [new AppFirewallPolicy(@"C:\apps\old.exe", OutboundAction.Block)]));
        var store = new FirewallPolicyStore(Path.Combine(_directory, "policies.json"), allowEnforcement: true,
            storageTrustGuard: new FailSecondInspectGuard());
        var engine = new ScriptedEngine(failApply: !rollbackSucceeds);
        var coordinator = TestEnforcementCoordinator.Create(store, engine);

        var exception = await Assert.ThrowsAsync<FirewallTransitionException>(() =>
            coordinator.RemovePolicyAsync(@"C:\apps\old.exe"));

        Assert.Equal(code, exception.Code);
        Assert.Equal(["remove:old.exe", "apply:old.exe"], engine.Events);
        Assert.Single((await seed.LoadAsync()).Policies);
        Assert.Equal(FirewallEnforcementState.Degraded, coordinator.EffectiveState);
    }

    [Theory]
    [InlineData(false, "EnableApplyFailed")]
    [InlineData(true, "EnableRollbackFailed")]
    public async Task PartialApplyRollback_EnableRemovesOwnedPartialFilters(bool rollbackFails, string code)
    {
        var store = Store();
        await store.SaveAsync(new OutboundFirewallConfiguration(OutboundFirewallMode.AuditOnly,
        [
            new AppFirewallPolicy(@"C:\apps\one.exe", OutboundAction.Block),
            new AppFirewallPolicy(@"C:\apps\two.exe", OutboundAction.Block),
        ]));
        var engine = new PartialApplyEngine(rollbackFails);
        var coordinator = TestEnforcementCoordinator.Create(store, engine);

        var exception = await Assert.ThrowsAsync<FirewallTransitionException>(() => coordinator.EnableAsync());

        Assert.Equal(code, exception.Code);
        Assert.Equal(["apply:one.exe", "apply:two.exe", "remove:two.exe"], engine.Events.Take(3));
        Assert.DoesNotContain(engine.Events, item => item.Contains("foreign", StringComparison.Ordinal));
        Assert.Equal(OutboundFirewallMode.AuditOnly, (await store.LoadAsync()).Mode);
        Assert.Equal(FirewallEnforcementState.Degraded, coordinator.EffectiveState);
    }

    [Theory]
    [InlineData(false, "StartupApplyFailed")]
    [InlineData(true, "StartupApplyRollbackFailed")]
    public async Task PartialApplyRollback_StartupRemovesOnlyAttemptedOwnedFilters(bool rollbackFails, string code)
    {
        var store = Store();
        await store.SaveAsync(new OutboundFirewallConfiguration(OutboundFirewallMode.Enforcement,
        [
            new AppFirewallPolicy(@"C:\apps\one.exe", OutboundAction.Block),
            new AppFirewallPolicy(@"C:\apps\two.exe", OutboundAction.Block),
        ]));
        var engine = new PartialApplyEngine(rollbackFails);
        var coordinator = TestEnforcementCoordinator.Create(store, engine);

        var exception = await Assert.ThrowsAsync<FirewallTransitionException>(() => coordinator.ApplyBlocksAsync());

        Assert.Equal(code, exception.Code);
        Assert.All(engine.Events, item => Assert.DoesNotContain("foreign", item, StringComparison.Ordinal));
        Assert.StartsWith("remove:two.exe", engine.Events[2], StringComparison.Ordinal);
        Assert.Equal(FirewallEnforcementState.Degraded, coordinator.EffectiveState);
    }

    [Theory]
    [InlineData(false, "EmergencyCleanupFailed")]
    [InlineData(true, "EmergencyCleanupRollbackFailed")]
    public async Task EmergencyCleanupFailure_RestoresEnforcementOrReportsCompensationFailure(
        bool restoreFails, string code)
    {
        var store = Store();
        await store.SaveAsync(new OutboundFirewallConfiguration(OutboundFirewallMode.Enforcement,
            [new AppFirewallPolicy(@"C:\apps\owned.exe", OutboundAction.Block)]));
        var engine = new FailingCleanupEngine(restoreFails);
        var coordinator = TestEnforcementCoordinator.Create(store, engine);

        var exception = await Assert.ThrowsAsync<FirewallTransitionException>(() => coordinator.EmergencyDisableAsync());

        Assert.Equal(code, exception.Code);
        Assert.Equal(["cleanup:owned.exe", "apply:owned.exe"], engine.Events);
        Assert.DoesNotContain(engine.Events, item => item.Contains("foreign", StringComparison.Ordinal));
        Assert.Equal(OutboundFirewallMode.Enforcement, (await store.LoadAsync()).Mode);
        Assert.Equal(FirewallEnforcementState.Degraded, coordinator.EffectiveState);
    }

    [Fact]
    public async Task EmergencySaveFailure_ReappliesOwnedEnforcementWithoutGenericCleanup()
    {
        var seed = Store();
        await seed.SaveAsync(new OutboundFirewallConfiguration(OutboundFirewallMode.Enforcement,
            [new AppFirewallPolicy(@"C:\apps\owned.exe", OutboundAction.Block)]));
        var store = new FirewallPolicyStore(Path.Combine(_directory, "policies.json"), allowEnforcement: true,
            storageTrustGuard: new FailSecondInspectGuard());
        var engine = new CleanupThenRecordEngine();
        var coordinator = TestEnforcementCoordinator.Create(store, engine);

        var exception = await Assert.ThrowsAsync<FirewallTransitionException>(() => coordinator.EmergencyDisableAsync());

        Assert.Equal("EmergencyPersistenceFailed", exception.Code);
        Assert.Equal(["cleanup:owned.exe", "apply:owned.exe"], engine.Events);
        Assert.Empty(engine.Removed);
        Assert.Equal(OutboundFirewallMode.Enforcement, (await seed.LoadAsync()).Mode);
        Assert.Equal(FirewallEnforcementState.Degraded, coordinator.EffectiveState);
    }

    // Persisted intent is not a runtime attestation. Startup failure is rolled back to the
    // fail-safe durable mode even when filter cleanup itself also fails.
    [Fact]
    public async Task StartupRollbackFailure_WithPersistedEnforcement_RemainsDegraded()
    {
        var store = Store();
        await store.SaveAsync(new OutboundFirewallConfiguration(OutboundFirewallMode.Enforcement,
        [
            new AppFirewallPolicy(@"C:\apps\one.exe", OutboundAction.Block),
            new AppFirewallPolicy(@"C:\apps\two.exe", OutboundAction.Block),
        ]));
        var coordinator = TestEnforcementCoordinator.Create(store, new PartialApplyEngine(rollbackFails: true));

        await Assert.ThrowsAsync<FirewallTransitionException>(() => coordinator.ApplyBlocksAsync());

        Assert.Equal(OutboundFirewallMode.AuditOnly, (await store.LoadAsync()).Mode);
        Assert.Equal(FirewallEnforcementState.Degraded, coordinator.EffectiveState);
    }

    [Fact]
    public async Task EnableAfterFailure_RecoversEffectiveStateOnlyAfterACompleteApply()
    {
        var store = Store();
        await store.SaveAsync(new OutboundFirewallConfiguration(OutboundFirewallMode.AuditOnly,
            [new AppFirewallPolicy(@"C:\apps\block.exe", OutboundAction.Block)]));
        var coordinator = TestEnforcementCoordinator.Create(store, new FailOnceApplyEngine());

        await Assert.ThrowsAsync<FirewallTransitionException>(() => coordinator.EnableEnforcementAsync());
        Assert.Equal(FirewallEnforcementState.Degraded, coordinator.EffectiveState);

        await coordinator.EnableEnforcementAsync();

        Assert.Equal(OutboundFirewallMode.Enforcement, (await store.LoadAsync()).Mode);
        Assert.Equal(FirewallEnforcementState.Active, coordinator.EffectiveState);
    }

    [Theory]
    [InlineData("upsert", false, "UpsertApplyFailed")]
    [InlineData("upsert", true, "UpsertApplyRollbackFailed")]
    [InlineData("remove", false, "RemoveApplyFailed")]
    [InlineData("remove", true, "RemoveApplyRollbackFailed")]
    public async Task Win32PrimaryAndCompensation_UpsertRemoveHaveStableCodesAndOwnedEffects(
        string operation, bool compensationFails, string code)
    {
        var store = Store();
        var policies = operation == "remove"
            ? new[] { new AppFirewallPolicy(@"C:\apps\owned.exe", OutboundAction.Block) }
            : [];
        await store.SaveAsync(new OutboundFirewallConfiguration(OutboundFirewallMode.Enforcement, policies));
        var engine = new Win32MutationEngine(operation, compensationFails);
        var coordinator = TestEnforcementCoordinator.Create(store, engine);

        var exception = await Assert.ThrowsAsync<FirewallTransitionException>(() => operation == "upsert"
            ? coordinator.UpsertPolicyAsync(new AppFirewallPolicy(@"C:\apps\owned.exe", OutboundAction.Block))
            : coordinator.RemovePolicyAsync(@"C:\apps\owned.exe"));

        Assert.Equal(code, exception.Code);
        Assert.All(engine.Events, item => Assert.Contains("owned.exe", item, StringComparison.Ordinal));
        Assert.DoesNotContain(engine.Events, item => item.Contains("foreign", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(false, false, "EnableApplyFailed")]
    [InlineData(false, true, "EnableRollbackFailed")]
    [InlineData(true, false, "StartupApplyFailed")]
    [InlineData(true, true, "StartupApplyRollbackFailed")]
    public async Task Win32PartialApply_EnableAndStartupRollbackHaveStableCodes(
        bool startup, bool rollbackFails, string code)
    {
        var store = Store();
        await store.SaveAsync(new OutboundFirewallConfiguration(
            startup ? OutboundFirewallMode.Enforcement : OutboundFirewallMode.AuditOnly,
        [
            new AppFirewallPolicy(@"C:\apps\one.exe", OutboundAction.Block),
            new AppFirewallPolicy(@"C:\apps\two.exe", OutboundAction.Block),
        ]));
        var engine = new Win32PartialEngine(rollbackFails);
        var coordinator = TestEnforcementCoordinator.Create(store, engine);

        var exception = await Assert.ThrowsAsync<FirewallTransitionException>(() =>
            startup ? coordinator.ApplyBlocksAsync() : coordinator.EnableAsync());

        Assert.Equal(code, exception.Code);
        Assert.All(engine.Events, item => Assert.DoesNotContain("foreign", item, StringComparison.Ordinal));
        Assert.Contains("remove:two.exe", engine.Events);
    }

    [Theory]
    [InlineData(false, "EmergencyCleanupFailed")]
    [InlineData(true, "EmergencyCleanupRollbackFailed")]
    public async Task Win32EmergencyCleanupAndRestoreHaveStableCodes(bool restoreFails, string code)
    {
        var store = Store();
        await store.SaveAsync(new OutboundFirewallConfiguration(OutboundFirewallMode.Enforcement,
            [new AppFirewallPolicy(@"C:\apps\owned.exe", OutboundAction.Block)]));
        var engine = new Win32CleanupEngine(restoreFails);
        var coordinator = TestEnforcementCoordinator.Create(store, engine);

        var exception = await Assert.ThrowsAsync<FirewallTransitionException>(() => coordinator.EmergencyDisableAsync());

        Assert.Equal(code, exception.Code);
        Assert.Equal(["cleanup:owned.exe", "apply:owned.exe"], engine.Events);
    }

    [Fact]
    public async Task DisposeRace_DrainsActiveAndQueuedWorkThenRejectsNewTransitions()
    {
        var store = Store();
        await store.SaveAsync(new OutboundFirewallConfiguration(OutboundFirewallMode.Enforcement,
            [new AppFirewallPolicy(@"C:\apps\one.exe", OutboundAction.Block)]));
        var engine = new BlockingCleanupEngine();
        var coordinator = TestEnforcementCoordinator.Create(store, engine);
        var active = coordinator.ApplyBlocksAsync();
        await engine.ApplyStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var queued = coordinator.GetModeAsync();
        var disposing = coordinator.DisposeAsync().AsTask();

        await Assert.ThrowsAsync<ObjectDisposedException>(() => coordinator.GetModeAsync());
        Assert.False(disposing.IsCompleted);
        engine.ReleaseApply.TrySetResult();
        await Task.WhenAll(active, queued, disposing);
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }

    private sealed class RecordingEngine : IOutboundFirewallEngine
    {
        public List<AppFirewallPolicy> Applied { get; } = [];

        public List<string> Removed { get; } = [];

        public bool IsSupported => true;

        public Task ApplyAsync(AppFirewallPolicy policy, CancellationToken cancellationToken = default)
        {
            Applied.Add(policy);
            return Task.CompletedTask;
        }

        public Task RemoveAsync(string executablePath, CancellationToken cancellationToken = default)
        {
            Removed.Add(executablePath);
            return Task.CompletedTask;
        }
    }

    private sealed class CallbackEngine(
        Func<Task>? onApply = null,
        Func<Task>? onRemove = null) : IOutboundFirewallEngine
    {
        public bool IsSupported => true;

        public async Task ApplyAsync(AppFirewallPolicy policy, CancellationToken cancellationToken = default)
        {
            if (onApply is not null) await onApply();
        }

        public async Task RemoveAsync(string executablePath, CancellationToken cancellationToken = default)
        {
            if (onRemove is not null) await onRemove();
        }
    }

    private class CleanupEngine : IOutboundFirewallEngine, ITestWinSightFirewallCleanup
    {
        public List<AppFirewallPolicy> Applied { get; } = [];
        public List<string> Removed { get; } = [];
        public IReadOnlyList<AppFirewallPolicy> CleanupPolicies { get; private set; } = [];
        public bool IsSupported => true;
        public virtual Task ApplyAsync(AppFirewallPolicy policy, CancellationToken cancellationToken = default)
        { Applied.Add(policy); return Task.CompletedTask; }
        public Task RemoveAsync(string executablePath, CancellationToken cancellationToken = default)
        { Removed.Add(executablePath); return Task.CompletedTask; }
        public virtual Task CleanupWinSightAsync(IReadOnlyList<AppFirewallPolicy> knownPolicies,
            CancellationToken cancellationToken = default)
        { CleanupPolicies = knownPolicies; return Task.CompletedTask; }
    }

    private sealed class BlockingCleanupEngine : CleanupEngine
    {
        public TaskCompletionSource ApplyStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource ReleaseApply { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public List<string> Events { get; } = [];
        public override async Task ApplyAsync(AppFirewallPolicy policy, CancellationToken cancellationToken = default)
        {
            Events.Add("apply");
            ApplyStarted.TrySetResult();
            await ReleaseApply.Task.WaitAsync(cancellationToken);
        }
        public override Task CleanupWinSightAsync(IReadOnlyList<AppFirewallPolicy> knownPolicies,
            CancellationToken cancellationToken = default)
        { Events.Add("cleanup"); return base.CleanupWinSightAsync(knownPolicies, cancellationToken); }
    }

    private sealed class FailSecondInspectGuard : IFirewallStorageTrustGuard
    {
        private int _inspects;
        public FirewallStorageTrustLease Inspect() => Interlocked.Increment(ref _inspects) == 1
            ? new(true, "Trusted", new object())
            : new(false, "SyntheticSaveFailure");
        public FirewallStorageTrustLease Revalidate(FirewallStorageTrustLease lease) => lease;
    }

    private sealed class ScriptedEngine(bool failApply = false, bool failRemove = false) : IOutboundFirewallEngine
    {
        private int _applyCalls;
        private int _removeCalls;
        public List<string> Events { get; } = [];
        public bool IsSupported => true;
        public Task ApplyAsync(AppFirewallPolicy policy, CancellationToken cancellationToken = default)
        {
            Events.Add($"apply:{Path.GetFileName(policy.ExecutablePath)}");
            if (failApply && Interlocked.Increment(ref _applyCalls) >= 1) throw new IOException("synthetic apply");
            return Task.CompletedTask;
        }
        public Task RemoveAsync(string executablePath, CancellationToken cancellationToken = default)
        {
            Events.Add($"remove:{Path.GetFileName(executablePath)}");
            if (failRemove && Interlocked.Increment(ref _removeCalls) >= 1) throw new IOException("synthetic remove");
            return Task.CompletedTask;
        }
    }

    private sealed class PartialApplyEngine(bool rollbackFails) : IOutboundFirewallEngine
    {
        private int _applies;
        public List<string> Events { get; } = [];
        public bool IsSupported => true;
        public Task ApplyAsync(AppFirewallPolicy policy, CancellationToken cancellationToken = default)
        {
            Events.Add($"apply:{Path.GetFileName(policy.ExecutablePath)}");
            if (Interlocked.Increment(ref _applies) == 2) throw new IOException("synthetic second apply");
            return Task.CompletedTask;
        }
        public Task RemoveAsync(string executablePath, CancellationToken cancellationToken = default)
        {
            Events.Add($"remove:{Path.GetFileName(executablePath)}");
            if (rollbackFails) throw new IOException("synthetic rollback");
            return Task.CompletedTask;
        }
    }

    private sealed class FailOnceApplyEngine : IOutboundFirewallEngine
    {
        private bool _failed;
        public bool IsSupported => true;
        public Task ApplyAsync(AppFirewallPolicy policy, CancellationToken cancellationToken = default)
        {
            if (!_failed)
            {
                _failed = true;
                throw new IOException("synthetic first apply");
            }
            return Task.CompletedTask;
        }
        public Task RemoveAsync(string executablePath, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }

    private sealed class FailingCleanupEngine(bool restoreFails) : IOutboundFirewallEngine, ITestWinSightFirewallCleanup
    {
        public List<string> Events { get; } = [];
        public bool IsSupported => true;
        public Task CleanupWinSightAsync(IReadOnlyList<AppFirewallPolicy> knownPolicies, CancellationToken cancellationToken = default)
        { Events.Add($"cleanup:{Path.GetFileName(Assert.Single(knownPolicies).ExecutablePath)}"); throw new IOException("cleanup"); }
        public Task ApplyAsync(AppFirewallPolicy policy, CancellationToken cancellationToken = default)
        { Events.Add($"apply:{Path.GetFileName(policy.ExecutablePath)}"); return restoreFails ? throw new IOException("restore") : Task.CompletedTask; }
        public Task RemoveAsync(string executablePath, CancellationToken cancellationToken = default) =>
            throw new Xunit.Sdk.XunitException("Generic cleanup must not be used.");
    }

    private sealed class CleanupThenRecordEngine : CleanupEngine
    {
        public List<string> Events { get; } = [];
        public override Task CleanupWinSightAsync(IReadOnlyList<AppFirewallPolicy> knownPolicies,
            CancellationToken cancellationToken = default)
        { Events.Add($"cleanup:{Path.GetFileName(Assert.Single(knownPolicies).ExecutablePath)}"); return Task.CompletedTask; }
        public override Task ApplyAsync(AppFirewallPolicy policy, CancellationToken cancellationToken = default)
        { Events.Add($"apply:{Path.GetFileName(policy.ExecutablePath)}"); return Task.CompletedTask; }
    }

    private sealed class Win32MutationEngine(string operation, bool compensationFails) : IOutboundFirewallEngine
    {
        private int _apply;
        private int _remove;
        public List<string> Events { get; } = [];
        public bool IsSupported => true;
        public Task ApplyAsync(AppFirewallPolicy policy, CancellationToken cancellationToken = default)
        {
            Events.Add($"apply:{Path.GetFileName(policy.ExecutablePath)}");
            if (operation == "upsert" || (operation == "remove" && compensationFails && ++_apply > 0))
                throw new Win32Exception(5);
            return Task.CompletedTask;
        }
        public Task RemoveAsync(string executablePath, CancellationToken cancellationToken = default)
        {
            Events.Add($"remove:{Path.GetFileName(executablePath)}");
            if (operation == "remove" || (operation == "upsert" && compensationFails && ++_remove > 0))
                throw new Win32Exception(5);
            return Task.CompletedTask;
        }
    }

    private sealed class Win32PartialEngine(bool rollbackFails) : IOutboundFirewallEngine
    {
        private int _apply;
        public List<string> Events { get; } = [];
        public bool IsSupported => true;
        public Task ApplyAsync(AppFirewallPolicy policy, CancellationToken cancellationToken = default)
        {
            Events.Add($"apply:{Path.GetFileName(policy.ExecutablePath)}");
            if (++_apply == 2) throw new Win32Exception(5);
            return Task.CompletedTask;
        }
        public Task RemoveAsync(string executablePath, CancellationToken cancellationToken = default)
        {
            Events.Add($"remove:{Path.GetFileName(executablePath)}");
            if (rollbackFails) throw new Win32Exception(5);
            return Task.CompletedTask;
        }
    }

    private sealed class Win32CleanupEngine(bool restoreFails) : IOutboundFirewallEngine, ITestWinSightFirewallCleanup
    {
        public List<string> Events { get; } = [];
        public bool IsSupported => true;
        public Task CleanupWinSightAsync(IReadOnlyList<AppFirewallPolicy> knownPolicies, CancellationToken cancellationToken = default)
        { Events.Add($"cleanup:{Path.GetFileName(Assert.Single(knownPolicies).ExecutablePath)}"); throw new Win32Exception(5); }
        public Task ApplyAsync(AppFirewallPolicy policy, CancellationToken cancellationToken = default)
        { Events.Add($"apply:{Path.GetFileName(policy.ExecutablePath)}"); return restoreFails ? throw new Win32Exception(5) : Task.CompletedTask; }
        public Task RemoveAsync(string executablePath, CancellationToken cancellationToken = default) =>
            throw new Xunit.Sdk.XunitException("Generic cleanup must not run.");
    }
}
