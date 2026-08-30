using System.ComponentModel;
using WinSight.Firewall;
using WinSight.FirewallService;
using Xunit;

namespace WinSight.FirewallService.Tests;

public sealed class FirewallServiceInstallerTests
{
    /// <summary>
    /// These cases exercise the SCM contract, not policy storage. Installation provisions
    /// C:\ProgramData\WinSight for real - deliberately, because a standard user who pre-creates it
    /// makes the service unable to start on every boot - and a unit test must not need elevation to
    /// assert a rollback code.
    /// </summary>
    private static readonly Action NoStorageProvisioning = static () => { };

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
        var exception = Assert.Throws<ServicePathTrustException>(() =>
            FirewallServiceInstaller.Install(@"C:\untrusted\service.exe", new DenyingInspector(code)));

        Assert.Equal(code, exception.Code);
        Assert.DoesNotContain(@"C:\untrusted\service.exe", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(PathTrustCode.InvalidPath)]
    [InlineData(PathTrustCode.OutsideProgramData)]
    [InlineData(PathTrustCode.MissingComponent)]
    [InlineData(PathTrustCode.ReparsePoint)]
    [InlineData(PathTrustCode.UntrustedOwner)]
    [InlineData(PathTrustCode.WritableByUnprivilegedPrincipal)]
    [InlineData(PathTrustCode.IdentityChanged)]
    [InlineData(PathTrustCode.InspectionFailed)]
    public void Install_TrustDenial_NeverCallsInjectedScm(PathTrustCode code)
    {
        var scm = new RecordingScm(deleteResult: true);

        Assert.Throws<ServicePathTrustException>(() => FirewallServiceInstaller.Install(
            @"C:\untrusted\service.exe",
            new DenyingInspector(code),
            scm));

        Assert.Equal(0, scm.CreateCalls);
        Assert.Null(scm.BinaryPath);
    }

    [Fact]
    public void InspectAndRevalidateExecutable_UsesOnlyInspectorAndReturnsCanonicalEvidence()
    {
        var inspector = new ScriptedInspector(
            @"C:\canonical\service.exe",
            PathTrustDecision.Allow(),
            PathTrustDecision.Allow());

        var evidence = FirewallServiceInstaller.InspectAndRevalidateExecutable(
            @"C:\syntactic\..\service.exe",
            inspector);

        Assert.Equal(@"C:\canonical\service.exe", evidence.CanonicalPath);
        Assert.Equal(1, inspector.InspectEvidenceCalls);
        Assert.Equal(1, inspector.RevalidationCalls);
    }

    [Theory]
    [InlineData(PathTrustCode.InvalidPath, ServicePathTrustDiagnosticCodes.InvalidPath)]
    [InlineData(PathTrustCode.OutsideProgramData, ServicePathTrustDiagnosticCodes.OutsideMachineData)]
    [InlineData(PathTrustCode.MissingComponent, ServicePathTrustDiagnosticCodes.MissingComponent)]
    [InlineData(PathTrustCode.ReparsePoint, ServicePathTrustDiagnosticCodes.ReparsePoint)]
    [InlineData(PathTrustCode.UntrustedOwner, ServicePathTrustDiagnosticCodes.UntrustedOwner)]
    [InlineData(PathTrustCode.WritableByUnprivilegedPrincipal, ServicePathTrustDiagnosticCodes.WritableByUnprivileged)]
    [InlineData(PathTrustCode.IdentityChanged, ServicePathTrustDiagnosticCodes.IdentityChanged)]
    [InlineData(PathTrustCode.InspectionFailed, ServicePathTrustDiagnosticCodes.InspectionFailed)]
    [InlineData(PathTrustCode.Trusted, ServicePathTrustDiagnosticCodes.InspectionFailed)]
    public void InstallTrustDiagnosticCodes_AreClosedAndAllowlisted(PathTrustCode code, string expected) =>
        Assert.Equal(expected, ServicePathTrustDiagnosticCodes.ForInstallDenial(code));

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

        FirewallServiceInstaller.Install(@"C:\syntactic\..\service.exe", inspector, scm, NoStorageProvisioning);

        Assert.Equal("\"C:\\canonical\\service.exe\" run", scm.BinaryPath);
        Assert.Equal(1, scm.Registration.ConfigureSecurityProfileCalls);
    }

    [Fact]
    public void RequiredPrivilegeProfile_IsMinimalAndDoubleNullTerminated()
    {
        var privileges = FirewallServiceInstaller.RequiredPrivilegesMultiString();

        Assert.Equal(
            "SeChangeNotifyPrivilege\0SeImpersonatePrivilege\0SeSystemProfilePrivilege\0\0",
            privileges);
        Assert.DoesNotContain("SeDebugPrivilege", privileges, StringComparison.Ordinal);
        Assert.EndsWith("\0\0", privileges, StringComparison.Ordinal);
    }

    [Fact]
    public void RecoveryProfile_RetriesIndefinitelyWithoutDayLongFailureMemory()
    {
        var actions = FirewallServiceInstaller.RecoveryActions();

        Assert.Equal(3_600U, FirewallServiceInstaller.RecoveryResetPeriodSeconds);
        Assert.Collection(
            actions,
            action =>
            {
                Assert.Equal(1, action.Type);
                Assert.Equal(5_000U, action.DelayMilliseconds);
            },
            action =>
            {
                Assert.Equal(1, action.Type);
                Assert.Equal(30_000U, action.DelayMilliseconds);
            },
            action =>
            {
                Assert.Equal(1, action.Type);
                Assert.Equal(60_000U, action.DelayMilliseconds);
            });
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
            FirewallServiceInstaller.Install(@"C:\input.exe", inspector, scm, NoStorageProvisioning));

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
            FirewallServiceInstaller.Install(@"C:\syntactic\service.exe", inspector, scm, NoStorageProvisioning));

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
            FirewallServiceInstaller.Install(@"C:\input\service.exe", inspector, scm, NoStorageProvisioning));

        Assert.Equal(ServiceInstallTrustCode.PostCreateOperationRolledBack, exception.Code);
        Assert.Equal(1, scm.Registration.DeleteCalls);
        Assert.DoesNotContain(@"C:\input\service.exe", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Install_SecurityProfileFailure_RollsBackRegistration()
    {
        var inspector = new ScriptedInspector(@"C:\canonical\service.exe",
            PathTrustDecision.Allow(), PathTrustDecision.Allow());
        var scm = new RecordingScm(deleteResult: true, securityProfileThrows: true);

        var exception = Assert.Throws<ServiceInstallTrustException>(() =>
            FirewallServiceInstaller.Install(@"C:\input\service.exe", inspector, scm, NoStorageProvisioning));

        Assert.Equal(ServiceInstallTrustCode.PostCreateOperationRolledBack, exception.Code);
        Assert.Equal(1, scm.Registration.ConfigureSecurityProfileCalls);
        Assert.Equal(1, scm.Registration.DeleteCalls);
    }

    [Fact]
    public void Uninstall_StopsThenCleansWfpBeforeDeletingRegistration()
    {
        var scm = new RecordingRemovalScm();

        FirewallServiceInstaller.Uninstall(scm, () => scm.Events.Add("cleanup-wfp"));

        Assert.Equal(["open", "stop", "cleanup-wfp", "delete", "dispose"], scm.Events);
    }

    [Fact]
    public void Uninstall_WfpCleanupFailure_PreservesServiceRegistration()
    {
        var scm = new RecordingRemovalScm();

        Assert.Throws<IOException>(() => FirewallServiceInstaller.Uninstall(
            scm,
            () =>
            {
                scm.Events.Add("cleanup-wfp");
                throw new IOException("WFP unavailable");
            }));

        Assert.Equal(["open", "stop", "cleanup-wfp", "dispose"], scm.Events);
    }

    [Fact]
    public void Uninstall_StopFailure_NeverTouchesWfpOrDeletesRegistration()
    {
        var scm = new RecordingRemovalScm { StopFailure = new TimeoutException() };

        Assert.Throws<TimeoutException>(() => FirewallServiceInstaller.Uninstall(
            scm, () => scm.Events.Add("cleanup-wfp")));

        Assert.Equal(["open", "stop", "dispose"], scm.Events);
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
        public int InspectEvidenceCalls { get; private set; }
        public int RevalidationCalls => _revalidations;
        public PathTrustDecision InspectExecutable(string path) => PathTrustDecision.Allow();
        public PathTrustDecision InspectPolicyStorage(string directory, string policyFile) => PathTrustDecision.Allow();
        public PathTrustEvidence InspectExecutableEvidence(string path)
        {
            InspectEvidenceCalls++;
            return new(PathTrustDecision.Allow(), canonicalPath, new Dictionary<string, string>());
        }
        public PathTrustDecision Revalidate(PathTrustEvidence evidence) =>
            Interlocked.Increment(ref _revalidations) == 1 ? preUse : postUse;
    }

    private sealed class RecordingScm(
        bool deleteResult,
        bool descriptionThrows = false,
        bool deleteThrows = false,
        bool securityProfileThrows = false) : IServiceControlManager
    {
        public string? BinaryPath { get; private set; }
        public int CreateCalls { get; private set; }
        public RecordingRegistration Registration { get; } =
            new(deleteResult, descriptionThrows, deleteThrows, securityProfileThrows);
        public IServiceRegistration Create(string binaryPath)
        {
            CreateCalls++;
            BinaryPath = binaryPath;
            return Registration;
        }

        public IServiceRegistration OpenForRemoval() => Registration;
    }

    private sealed class RecordingRegistration(
        bool deleteResult,
        bool descriptionThrows,
        bool deleteThrows,
        bool securityProfileThrows) : IServiceRegistration
    {
        public int DeleteCalls { get; private set; }
        public int ConfigureSecurityProfileCalls { get; private set; }
        public void SetDescription(string description)
        { if (descriptionThrows) throw new Win32Exception(5); }
        public void ConfigureSecurityProfile()
        {
            ConfigureSecurityProfileCalls++;
            if (securityProfileThrows) throw new Win32Exception(5);
        }
        public void StopAndWait(TimeSpan timeout) { }
        public bool Delete()
        {
            DeleteCalls++;
            if (deleteThrows) throw new Win32Exception(5);
            return deleteResult;
        }
        public void Dispose() { }
    }

    private sealed class RecordingRemovalScm : IServiceControlManager
    {
        public List<string> Events { get; } = [];
        public Exception? StopFailure { get; init; }

        public IServiceRegistration Create(string binaryPath) => throw new NotSupportedException();

        public IServiceRegistration OpenForRemoval()
        {
            Events.Add("open");
            return new RecordingRemovalRegistration(this);
        }

        private sealed class RecordingRemovalRegistration(RecordingRemovalScm owner) : IServiceRegistration
        {
            public void SetDescription(string description) => throw new NotSupportedException();
            public void ConfigureSecurityProfile() => throw new NotSupportedException();

            public void StopAndWait(TimeSpan timeout)
            {
                owner.Events.Add("stop");
                if (owner.StopFailure is not null)
                {
                    throw owner.StopFailure;
                }
            }

            public bool Delete()
            {
                owner.Events.Add("delete");
                return true;
            }

            public void Dispose() => owner.Events.Add("dispose");
        }
    }
}
