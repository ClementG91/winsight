using System.ComponentModel;
using WinSight.Firewall;
using WinSight.FirewallService;
using Xunit;

namespace WinSight.FirewallService.Tests;

public sealed class FirewallServiceCommandHostTests
{
    private const string ProbePath = @"C:\Users\standard\sentinel.exe";

    [Fact]
    public void Execute_TrustedProbe_UsesInspectionOnlyAndReturnsExactStdout()
    {
        var capability = new RecordingInstallCapability();
        var inspector = new RecordingPathTrustInspector();
        var execution = Execute(capability, inspector, ["install-path-trust-check", ProbePath]);

        Assert.Equal(FirewallServiceVerb.InstallPathTrustCheck, execution.Dispatch.Verb);
        Assert.True(execution.Dispatch.Handled);
        Assert.Equal(0, execution.Dispatch.ExitCode);
        Assert.Equal(ServicePathTrustDiagnosticCodes.Trusted + Environment.NewLine, execution.StandardOutput);
        Assert.Empty(execution.StandardError);
        Assert.Equal(ProbePath, Assert.Single(inspector.InspectedPaths));
        Assert.Equal(1, inspector.RevalidationCount);
        AssertNoInstallCapabilityCalls(capability);
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
    public void Execute_AllProbeDenialsReturnExactStderrAndNeverReachInstall(
        PathTrustCode code,
        string expectedDiagnostic)
    {
        var capability = new RecordingInstallCapability();
        var inspector = new RecordingPathTrustInspector
        {
            InspectResult = PathTrustDecision.Deny(code),
        };
        var execution = Execute(capability, inspector, ["install-path-trust-check", ProbePath]);

        Assert.Equal(FirewallServiceVerb.InstallPathTrustCheck, execution.Dispatch.Verb);
        Assert.True(execution.Dispatch.Handled);
        Assert.Equal(1, execution.Dispatch.ExitCode);
        Assert.Empty(execution.StandardOutput);
        Assert.Equal(expectedDiagnostic + Environment.NewLine, execution.StandardError);
        Assert.DoesNotContain(ProbePath, execution.StandardError, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(ProbePath, Assert.Single(inspector.InspectedPaths));
        Assert.Equal(0, inspector.RevalidationCount);
        AssertNoInstallCapabilityCalls(capability);
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
    public void Execute_AllProbeRevalidationDenialsReturnExactStderrAndNeverReachInstall(
        PathTrustCode code,
        string expectedDiagnostic)
    {
        var capability = new RecordingInstallCapability();
        var inspector = new RecordingPathTrustInspector
        {
            RevalidateResult = PathTrustDecision.Deny(code),
        };
        var execution = Execute(capability, inspector, ["install-path-trust-check", ProbePath]);

        Assert.Equal(1, execution.Dispatch.ExitCode);
        Assert.Empty(execution.StandardOutput);
        Assert.Equal(expectedDiagnostic + Environment.NewLine, execution.StandardError);
        Assert.Equal(ProbePath, Assert.Single(inspector.InspectedPaths));
        Assert.Equal(1, inspector.RevalidationCount);
        AssertNoInstallCapabilityCalls(capability);
    }

    [Fact]
    public void Execute_InvalidProbeArityNeverInvokesInspectorOrInstallAndFailsClosed()
    {
        IReadOnlyList<string>[] invalidArguments =
        [
            ["install-path-trust-check"],
            ["install-path-trust-check", "   "],
            ["install-path-trust-check", ProbePath, "extra"],
        ];

        foreach (var arguments in invalidArguments)
        {
            var capability = new RecordingInstallCapability();
            var inspector = new RecordingPathTrustInspector();
            var execution = Execute(capability, inspector, arguments);

            Assert.Equal(FirewallServiceVerb.InstallPathTrustCheck, execution.Dispatch.Verb);
            Assert.True(execution.Dispatch.Handled);
            Assert.Equal(1, execution.Dispatch.ExitCode);
            Assert.Empty(execution.StandardOutput);
            Assert.Equal(
                ServicePathTrustDiagnosticCodes.InspectionFailed + Environment.NewLine,
                execution.StandardError);
            Assert.Empty(inspector.InspectedPaths);
            Assert.Equal(0, inspector.RevalidationCount);
            AssertNoInstallCapabilityCalls(capability);
        }
    }

    [Fact]
    public void Execute_UnexpectedProbeFailureIsRedactedAndNeverReachesInstall()
    {
        var capability = new RecordingInstallCapability();
        var inspector = new RecordingPathTrustInspector
        {
            InspectException = new IOException($"native details for {ProbePath}"),
        };
        var execution = Execute(capability, inspector, ["install-path-trust-check", ProbePath]);

        Assert.Equal(1, execution.Dispatch.ExitCode);
        Assert.Empty(execution.StandardOutput);
        Assert.Equal(
            ServicePathTrustDiagnosticCodes.InspectionFailed + Environment.NewLine,
            execution.StandardError);
        Assert.DoesNotContain(ProbePath, execution.StandardError, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("native", execution.StandardError, StringComparison.OrdinalIgnoreCase);
        AssertNoInstallCapabilityCalls(capability);
    }

    [Fact]
    public void Execute_InstallRoutesOnlyToInstallCapability()
    {
        var capability = new RecordingInstallCapability
        {
            Elevated = true,
            ProcessPath = ProbePath,
        };
        var inspector = new RecordingPathTrustInspector
        {
            InspectException = new Xunit.Sdk.XunitException("install must not inspect"),
        };
        var execution = Execute(capability, inspector, ["install"]);

        Assert.Equal(FirewallServiceVerb.Install, execution.Dispatch.Verb);
        Assert.True(execution.Dispatch.Handled);
        Assert.Equal(0, execution.Dispatch.ExitCode);
        Assert.Equal(
            $"Installed '{FirewallServiceInstaller.DisplayName}' (demand-start; enforcement is opt-in and runtime state is reported separately).{Environment.NewLine}" +
            $"Start it with:  sc start {FirewallServiceInstaller.ServiceName}{Environment.NewLine}",
            execution.StandardOutput);
        Assert.Empty(execution.StandardError);
        Assert.Equal(1, capability.ElevationCalls);
        Assert.Equal(1, capability.ProcessPathCalls);
        Assert.Equal(ProbePath, Assert.Single(capability.InstalledPaths));
        Assert.Empty(inspector.InspectedPaths);
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
    public void Execute_InstallPathDenialsPreserveTypedCodeWithoutInspectorOrPathLeak(
        PathTrustCode code,
        string expectedDiagnostic)
    {
        var capability = new RecordingInstallCapability
        {
            Elevated = true,
            ProcessPath = ProbePath,
            InstallException = new ServicePathTrustException(code),
        };
        var inspector = new RecordingPathTrustInspector();
        var execution = Execute(capability, inspector, ["install"]);

        Assert.Equal(1, execution.Dispatch.ExitCode);
        Assert.Empty(execution.StandardOutput);
        Assert.Equal(expectedDiagnostic + Environment.NewLine, execution.StandardError);
        Assert.DoesNotContain(ProbePath, execution.StandardError, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(inspector.InspectedPaths);
    }

    [Fact]
    public void Execute_ExpectedInstallFailuresAreClosedAndRedacted()
    {
        var notElevatedCapability = new RecordingInstallCapability();
        var notElevated = Execute(
            notElevatedCapability,
            new RecordingPathTrustInspector(),
            ["install"]);
        Assert.Equal(1, notElevated.Dispatch.ExitCode);
        Assert.Empty(notElevated.StandardOutput);
        Assert.Equal(
            "Installing the WinSight firewall service requires an elevated (Administrator) console." +
            Environment.NewLine,
            notElevated.StandardError);
        Assert.Equal(1, notElevatedCapability.ElevationCalls);
        Assert.Equal(0, notElevatedCapability.ProcessPathCalls);
        Assert.Empty(notElevatedCapability.InstalledPaths);

        var noPathCapability = new RecordingInstallCapability { Elevated = true };
        var noProcessPath = Execute(
            noPathCapability,
            new RecordingPathTrustInspector(),
            ["install"]);
        Assert.Equal(1, noProcessPath.Dispatch.ExitCode);
        Assert.Empty(noProcessPath.StandardOutput);
        Assert.Equal(
            "Could not resolve the service executable path." + Environment.NewLine,
            noProcessPath.StandardError);
        Assert.Empty(noPathCapability.InstalledPaths);

        foreach (var exception in new Exception[]
        {
            new InvalidOperationException($"generic failure at {ProbePath}"),
            new Win32Exception(5, $"native failure at {ProbePath}"),
        })
        {
            var capability = new RecordingInstallCapability
            {
                Elevated = true,
                ProcessPath = ProbePath,
                InstallException = exception,
            };
            var generic = Execute(capability, new RecordingPathTrustInspector(), ["install"]);
            Assert.Equal(1, generic.Dispatch.ExitCode);
            Assert.Empty(generic.StandardOutput);
            Assert.Equal("[FW_INSTALL_FAILED]" + Environment.NewLine, generic.StandardError);
            Assert.DoesNotContain(ProbePath, generic.StandardError, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("native", generic.StandardError, StringComparison.OrdinalIgnoreCase);
        }
    }

    // The probe already redacts any exception type. The install route used to filter on
    // InvalidOperationException and Win32Exception only, so a future call path throwing anything
    // else would escape the handler and let the CLR print the type, message and stack trace -
    // including the executable path - straight to stderr. Nothing today throws these, which is
    // exactly why nothing would have noticed the day something did.
    [Theory]
    [MemberData(nameof(UnexpectedInstallFailures))]
    public void Execute_UnexpectedInstallFailureIsRedactedLikeAnyOther(Exception exception)
    {
        var capability = new RecordingInstallCapability
        {
            Elevated = true,
            ProcessPath = ProbePath,
            InstallException = exception,
        };

        var execution = Execute(capability, new RecordingPathTrustInspector(), ["install"]);

        Assert.Equal(1, execution.Dispatch.ExitCode);
        Assert.Empty(execution.StandardOutput);
        Assert.Equal("[FW_INSTALL_FAILED]" + Environment.NewLine, execution.StandardError);
        Assert.DoesNotContain(ProbePath, execution.StandardError, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("secret", execution.StandardError, StringComparison.OrdinalIgnoreCase);
    }

    public static TheoryData<Exception> UnexpectedInstallFailures()
    {
        var failures = new TheoryData<Exception>();
        failures.Add(new IOException($"secret detail at {ProbePath}"));
        failures.Add(new UnauthorizedAccessException($"secret detail at {ProbePath}"));
        failures.Add(new ArgumentException($"secret detail at {ProbePath}"));
        failures.Add(new InvalidCastException($"secret detail at {ProbePath}"));
        failures.Add(new TimeoutException($"secret detail at {ProbePath}"));
        return failures;
    }

    [Fact]
    public void Execute_UnhandledVerbWritesNothingAndTouchesNoCapability()
    {
        var capability = new RecordingInstallCapability();
        var inspector = new RecordingPathTrustInspector();
        var execution = Execute(capability, inspector, ["status"]);

        Assert.Equal(new(FirewallServiceVerb.Status, Handled: false, ExitCode: 0), execution.Dispatch);
        Assert.Empty(execution.StandardOutput);
        Assert.Empty(execution.StandardError);
        AssertNoInstallCapabilityCalls(capability);
        Assert.Empty(inspector.InspectedPaths);
    }

    [Fact(Timeout = 30000)]
    public async Task Program_InvalidProbeAritySmokeUsesPublicRouteWithoutInspection()
    {
        var outputDirectory = new DirectoryInfo(AppContext.BaseDirectory);
        var targetFramework = outputDirectory.Name;
        var configuration = outputDirectory.Parent!.Name;
        var repositoryRoot = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..", ".."));
        var executable = Path.Combine(
            repositoryRoot,
            "src",
            "WinSight.FirewallService",
            "bin",
            configuration,
            targetFramework,
            "winsight-firewall-service.exe");
        Assert.True(File.Exists(executable), $"Missing built service apphost: {executable}");

        var start = new System.Diagnostics.ProcessStartInfo(
            executable,
            "install-path-trust-check")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        using var process = System.Diagnostics.Process.Start(start) ??
            throw new InvalidOperationException("Unable to start service apphost.");
        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(20));

        Assert.Equal(1, process.ExitCode);
        Assert.Empty(await stdoutTask);
        Assert.Equal(
            ServicePathTrustDiagnosticCodes.InspectionFailed + Environment.NewLine,
            await stderrTask);
    }

    private static HostExecution Execute(
        RecordingInstallCapability capability,
        RecordingPathTrustInspector inspector,
        IReadOnlyList<string>? arguments)
    {
        using var standardOutput = new StringWriter();
        using var standardError = new StringWriter();
        var dispatch = new FirewallServiceCommandHost(capability, inspector)
            .Execute(arguments, standardOutput, standardError);
        return new(dispatch, standardOutput.ToString(), standardError.ToString());
    }

    private static void AssertNoInstallCapabilityCalls(RecordingInstallCapability capability)
    {
        Assert.Equal(0, capability.ElevationCalls);
        Assert.Equal(0, capability.ProcessPathCalls);
        Assert.Empty(capability.InstalledPaths);
    }

    private sealed record HostExecution(
        FirewallServiceCommandDispatch Dispatch,
        string StandardOutput,
        string StandardError);

    private sealed class RecordingInstallCapability : IFirewallServiceInstallCapability
    {
        public bool Elevated { get; init; }
        public string? ProcessPath { get; init; }
        public Exception? InstallException { get; init; }
        public int ElevationCalls { get; private set; }
        public int ProcessPathCalls { get; private set; }
        public List<string> InstalledPaths { get; } = [];

        public bool IsElevated()
        {
            ElevationCalls++;
            return Elevated;
        }

        public string? GetProcessPath()
        {
            ProcessPathCalls++;
            return ProcessPath;
        }

        public void Install(string executablePath)
        {
            InstalledPaths.Add(executablePath);
            if (InstallException is not null) throw InstallException;
        }
    }

    private sealed class RecordingPathTrustInspector : IServicePathTrustInspector
    {
        public PathTrustDecision InspectResult { get; init; } = PathTrustDecision.Allow();
        public PathTrustDecision RevalidateResult { get; init; } = PathTrustDecision.Allow();
        public Exception? InspectException { get; init; }
        public List<string> InspectedPaths { get; } = [];
        public int RevalidationCount { get; private set; }

        public PathTrustDecision InspectExecutable(string path) =>
            InspectExecutableEvidence(path).Decision;

        public PathTrustEvidence InspectExecutableEvidence(string path)
        {
            InspectedPaths.Add(path);
            if (InspectException is not null) throw InspectException;
            return new(
                InspectResult,
                path,
                new Dictionary<string, string>(StringComparer.Ordinal));
        }

        public PathTrustDecision InspectPolicyStorage(string directory, string policyFile) =>
            throw new Xunit.Sdk.XunitException("Probe host must not inspect policy storage.");

        public PathTrustDecision Revalidate(PathTrustEvidence evidence)
        {
            RevalidationCount++;
            return RevalidateResult;
        }
    }
}
