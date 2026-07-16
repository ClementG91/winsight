using System.Text;
using WinSight.Firewall;
using Xunit;

namespace WinSight.Firewall.Tests;

public sealed class PolicyStoreTests : IDisposable
{
    private readonly string _directory = Path.Combine(
        Path.GetTempPath(),
        $"winsight-policy-tests-{Guid.NewGuid():N}");

    private string PolicyPath => Path.Combine(_directory, "policies.json");

    [Fact]
    public async Task LoadAsync_MissingFile_ReturnsAuditOnlyEmptyConfiguration()
    {
        var store = new FirewallPolicyStore(PolicyPath);

        var configuration = await store.LoadAsync();

        Assert.Equal(OutboundFirewallMode.AuditOnly, configuration.Mode);
        Assert.Empty(configuration.Policies);
    }

    [Fact]
    public async Task SaveAndLoadAsync_RoundTripsCanonicalPoliciesAtomically()
    {
        var store = new FirewallPolicyStore(PolicyPath);
        var path = @"C:\Program Files\WinSight\..\WinSight\agent.exe";

        await store.SaveAsync(new OutboundFirewallConfiguration(
            OutboundFirewallMode.AuditOnly,
            [new AppFirewallPolicy(path, OutboundAction.Block)]));
        var configuration = await store.LoadAsync();

        Assert.Equal(OutboundFirewallMode.AuditOnly, configuration.Mode);
        var policy = Assert.Single(configuration.Policies);
        Assert.Equal(Path.GetFullPath(path), policy.ExecutablePath);
        Assert.Equal(OutboundAction.Block, policy.Action);
        Assert.Empty(Directory.GetFiles(_directory, "*.tmp"));
    }

    [Fact]
    public async Task SaveAsync_InvalidReplacement_PreservesPreviousFile()
    {
        var store = new FirewallPolicyStore(PolicyPath);
        await store.SaveAsync(new OutboundFirewallConfiguration(
            OutboundFirewallMode.AuditOnly,
            [new AppFirewallPolicy(@"C:\safe.exe", OutboundAction.Allow)]));

        await Assert.ThrowsAsync<InvalidDataException>(() => store.SaveAsync(
            new OutboundFirewallConfiguration(
                OutboundFirewallMode.AuditOnly,
                [
                    new AppFirewallPolicy(@"C:\duplicate.exe", OutboundAction.Allow),
                    new AppFirewallPolicy(@"c:\DUPLICATE.exe", OutboundAction.Block),
                ])));

        var configuration = await store.LoadAsync();
        Assert.Equal(@"C:\safe.exe", Assert.Single(configuration.Policies).ExecutablePath);
    }

    [Fact]
    public async Task LoadAsync_RejectsUnknownPropertyAndKeepsFailOpenBoundary()
    {
        Directory.CreateDirectory(_directory);
        await File.WriteAllTextAsync(
            PolicyPath,
            """
            {
              "schemaVersion": 1,
              "mode": "AuditOnly",
              "policies": [],
              "enableEverything": true
            }
            """);

        var exception = await Assert.ThrowsAsync<InvalidDataException>(
            () => new FirewallPolicyStore(PolicyPath).LoadAsync());

        Assert.Contains("strict JSON", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task LoadOrAuditAsync_CorruptFileRecoversToEmptyAuditOnly()
    {
        Directory.CreateDirectory(_directory);
        await File.WriteAllTextAsync(PolicyPath, "{ definitely-not-json }");

        var result = await new FirewallPolicyStore(PolicyPath).LoadOrAuditAsync();

        Assert.True(result.RecoveredToAuditOnly);
        Assert.Equal(OutboundFirewallMode.AuditOnly, result.Configuration.Mode);
        Assert.Empty(result.Configuration.Policies);
        Assert.False(string.IsNullOrWhiteSpace(result.Diagnostic));
    }

    [Fact]
    public async Task LoadAsync_RejectsFutureSchema()
    {
        Directory.CreateDirectory(_directory);
        await File.WriteAllTextAsync(
            PolicyPath,
            """
            { "schemaVersion": 2, "mode": "AuditOnly", "policies": [] }
            """);

        var exception = await Assert.ThrowsAsync<InvalidDataException>(
            () => new FirewallPolicyStore(PolicyPath).LoadAsync());

        Assert.Contains("Unsupported", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Enforcement_RequiresExplicitServiceGateForSaveAndLoad()
    {
        var gatedStore = new FirewallPolicyStore(PolicyPath, allowEnforcement: true);
        await gatedStore.SaveAsync(new OutboundFirewallConfiguration(
            OutboundFirewallMode.Enforcement,
            []));

        await Assert.ThrowsAsync<InvalidDataException>(
            () => new FirewallPolicyStore(PolicyPath).LoadAsync());
        var configuration = await gatedStore.LoadAsync();
        Assert.Equal(OutboundFirewallMode.Enforcement, configuration.Mode);
    }

    [Fact]
    public async Task LoadAsync_RejectsOversizedFileBeforeParsing()
    {
        Directory.CreateDirectory(_directory);
        await File.WriteAllBytesAsync(
            PolicyPath,
            new byte[FirewallPolicyStore.MaxFileBytes + 1]);

        var exception = await Assert.ThrowsAsync<InvalidDataException>(
            () => new FirewallPolicyStore(PolicyPath).LoadAsync());

        Assert.Contains("size", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SaveAsync_RejectsCumulativePathBudgetBeforeWriting()
    {
        var policies = Enumerable.Range(0, FirewallPolicyStore.MaxPolicyCount)
            .Select(index => new AppFirewallPolicy(
                $@"C:\policy-{index:D4}-{new string('a', 60)}.exe",
                OutboundAction.Ask))
            .ToArray();

        var exception = await Assert.ThrowsAsync<InvalidDataException>(() =>
            new FirewallPolicyStore(PolicyPath).SaveAsync(
                new OutboundFirewallConfiguration(OutboundFirewallMode.AuditOnly, policies)));

        Assert.Contains("budget", exception.Message, StringComparison.Ordinal);
        Assert.False(File.Exists(PolicyPath));
    }

    [Fact]
    public void Constructor_RejectsRelativeStoragePath()
    {
        Assert.Throws<ArgumentException>(() => new FirewallPolicyStore("policies.json"));
    }

    [Fact]
    public async Task LoadOrAuditAsync_UntrustedStorage_HasStableRedactedDiagnostic()
    {
        var store = new FirewallPolicyStore(
            PolicyPath,
            storageTrust: () => (false, "StorageInspectionFailed"));

        var result = await store.LoadOrAuditAsync();

        Assert.False(result.StorageTrusted);
        Assert.True(result.RecoveredToAuditOnly);
        Assert.Equal("StorageInspectionFailed", result.Diagnostic);
        Assert.DoesNotContain(PolicyPath, result.Diagnostic, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task SaveAsync_TrustIsCheckedBeforeCreatingStorage()
    {
        var store = new FirewallPolicyStore(PolicyPath, storageTrust: () => (false, "StorageAclUntrusted"));

        var exception = await Assert.ThrowsAsync<FirewallStorageTrustException>(() =>
            store.SaveAsync(OutboundFirewallConfiguration.Empty));

        Assert.Equal("StorageAclUntrusted", exception.Code);
        Assert.False(Directory.Exists(_directory));
        Assert.DoesNotContain(PolicyPath, exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task LoadAsync_RevalidatesLeaseAfterOpeningStorage()
    {
        Directory.CreateDirectory(_directory);
        await File.WriteAllTextAsync(PolicyPath, """{"schemaVersion":1,"mode":"AuditOnly","policies":[]}""");
        var guard = new ScriptedTrustGuard(revalidateTrusted: false);
        var store = new FirewallPolicyStore(PolicyPath, storageTrustGuard: guard);

        var exception = await Assert.ThrowsAsync<FirewallStorageTrustException>(() => store.LoadAsync());

        Assert.Equal("StorageIdentityChanged", exception.Code);
        Assert.Equal(["inspect", "revalidate"], guard.Calls);
    }

    [Fact]
    public async Task SaveAsync_ValidatesBeforeIoBeforeReplaceAndAfterReplace()
    {
        var guard = new ScriptedTrustGuard(revalidateTrusted: true);
        var store = new FirewallPolicyStore(PolicyPath, storageTrustGuard: guard);

        await store.SaveAsync(OutboundFirewallConfiguration.Empty);

        Assert.Equal(["inspect", "revalidate", "inspect"], guard.Calls);
        Assert.True(File.Exists(PolicyPath));
    }

    private sealed class ScriptedTrustGuard(bool revalidateTrusted) : IFirewallStorageTrustGuard
    {
        public List<string> Calls { get; } = [];
        public FirewallStorageTrustLease Inspect()
        {
            Calls.Add("inspect");
            return new(true, "Trusted", new object());
        }
        public FirewallStorageTrustLease Revalidate(FirewallStorageTrustLease lease)
        {
            Calls.Add("revalidate");
            return new(revalidateTrusted, revalidateTrusted ? "Trusted" : "StorageIdentityChanged", lease.Evidence);
        }
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }
}

public sealed class FirewallProtocolTests
{
    [Fact]
    public async Task Request_RoundTripsThroughLengthPrefixedStrictFrame()
    {
        var request = new FirewallCommandRequest(
            FirewallProtocolCodec.CurrentVersion,
            Guid.NewGuid(),
            FirewallCommand.UpsertPolicy,
            new AppFirewallPolicy(@"C:\Program Files\Browser\browser.exe", OutboundAction.Block));
        await using var stream = new MemoryStream();

        await FirewallProtocolCodec.WriteRequestAsync(stream, request);
        stream.Position = 0;
        var decoded = await FirewallProtocolCodec.ReadRequestAsync(stream);

        Assert.Equal(request, decoded);
    }

    [Fact]
    public async Task Response_RoundTripsStatusAndPolicies()
    {
        var response = new FirewallCommandResponse(
            FirewallProtocolCodec.CurrentVersion,
            Guid.NewGuid(),
            Success: true,
            Status: new FirewallServiceStatus(
                OutboundFirewallMode.AuditOnly,
                EngineSupported: true,
                EnforcementEnabled: false),
            Policies: [new AppFirewallPolicy(@"C:\app.exe", OutboundAction.Ask)]);
        await using var stream = new MemoryStream();

        await FirewallProtocolCodec.WriteResponseAsync(stream, response);
        stream.Position = 0;
        var decoded = await FirewallProtocolCodec.ReadResponseAsync(stream);

        Assert.Equal(response.RequestId, decoded.RequestId);
        Assert.Equal(response.Status, decoded.Status);
        Assert.Equal(response.Policies, decoded.Policies);
    }

    [Fact]
    public async Task ReadRequestAsync_RejectsOversizedLengthBeforeAllocation()
    {
        await using var stream = new MemoryStream(
            BitConverter.GetBytes(FirewallProtocolCodec.MaxMessageBytes + 1));

        var exception = await Assert.ThrowsAsync<FirewallProtocolException>(
            () => FirewallProtocolCodec.ReadRequestAsync(stream));

        Assert.Equal(FirewallProtocolError.InvalidRequest, exception.Error);
    }

    [Fact]
    public async Task ReadRequestAsync_RejectsTruncatedPayload()
    {
        var frame = new byte[6];
        BitConverter.GetBytes(10).CopyTo(frame, 0);
        await using var stream = new MemoryStream(frame);

        var exception = await Assert.ThrowsAsync<FirewallProtocolException>(
            () => FirewallProtocolCodec.ReadRequestAsync(stream));

        Assert.Contains("truncated", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ReadRequestAsync_RejectsUnknownJsonMember()
    {
        var json = $$"""
            {
              "protocolVersion": {{FirewallProtocolCodec.CurrentVersion}},
              "requestId": "{{Guid.NewGuid()}}",
              "command": "GetStatus",
              "bypassAuthorization": true
            }
            """;
        await using var stream = Frame(json);

        var exception = await Assert.ThrowsAsync<FirewallProtocolException>(
            () => FirewallProtocolCodec.ReadRequestAsync(stream));

        Assert.Contains("strict JSON", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ReadRequestAsync_RejectsDuplicateSecuritySensitiveMember()
    {
        var json = $$"""
            {
              "protocolVersion": {{FirewallProtocolCodec.CurrentVersion}},
              "requestId": "{{Guid.NewGuid()}}",
              "command": "GetStatus",
              "command": "EmergencyDisable"
            }
            """;
        await using var stream = Frame(json);

        var exception = await Assert.ThrowsAsync<FirewallProtocolException>(
            () => FirewallProtocolCodec.ReadRequestAsync(stream));

        Assert.Contains("strict JSON", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task WriteRequestAsync_RejectsUnsupportedVersion()
    {
        var request = new FirewallCommandRequest(
            FirewallProtocolCodec.CurrentVersion + 1,
            Guid.NewGuid(),
            FirewallCommand.GetStatus);
        await using var stream = new MemoryStream();

        var exception = await Assert.ThrowsAsync<FirewallProtocolException>(
            () => FirewallProtocolCodec.WriteRequestAsync(stream, request));

        Assert.Equal(FirewallProtocolError.UnsupportedVersion, exception.Error);
        Assert.Empty(stream.ToArray());
    }

    [Fact]
    public async Task ListPolicies_RequiresBoundedPagination()
    {
        var invalid = new FirewallCommandRequest(
            FirewallProtocolCodec.CurrentVersion,
            Guid.NewGuid(),
            FirewallCommand.ListPolicies);
        var valid = invalid with { Offset = 0, Limit = FirewallProtocolCodec.MaxPoliciesPerMessage };

        await using var invalidStream = new MemoryStream();
        await Assert.ThrowsAsync<FirewallProtocolException>(
            () => FirewallProtocolCodec.WriteRequestAsync(invalidStream, invalid));
        await using var validStream = new MemoryStream();
        await FirewallProtocolCodec.WriteRequestAsync(validStream, valid);
        Assert.NotEmpty(validStream.ToArray());
    }

    [Theory]
    [InlineData("app.exe")]
    [InlineData(".\\app.exe")]
    public async Task WriteRequestAsync_RejectsRelativeRemovalPath(string path)
    {
        var request = new FirewallCommandRequest(
            FirewallProtocolCodec.CurrentVersion,
            Guid.NewGuid(),
            FirewallCommand.RemovePolicy,
            ExecutablePath: path);
        await using var stream = new MemoryStream();

        await Assert.ThrowsAsync<FirewallProtocolException>(
            () => FirewallProtocolCodec.WriteRequestAsync(stream, request));
    }

    [Fact]
    public async Task WriteResponseAsync_RejectsAuditOnlyEnforcementContradiction()
    {
        var response = new FirewallCommandResponse(
            FirewallProtocolCodec.CurrentVersion,
            Guid.NewGuid(),
            Success: true,
            Status: new FirewallServiceStatus(
                OutboundFirewallMode.AuditOnly,
                EngineSupported: true,
                EnforcementEnabled: true));
        await using var stream = new MemoryStream();

        await Assert.ThrowsAsync<FirewallProtocolException>(
            () => FirewallProtocolCodec.WriteResponseAsync(stream, response));
    }

    [Fact]
    public async Task WriteResponseAsync_RejectsDuplicatePolicyIdentity()
    {
        var response = new FirewallCommandResponse(
            FirewallProtocolCodec.CurrentVersion,
            Guid.NewGuid(),
            Success: true,
            Policies:
            [
                new AppFirewallPolicy(@"C:\same.exe", OutboundAction.Allow),
                new AppFirewallPolicy(@"c:\SAME.exe", OutboundAction.Block),
            ]);
        await using var stream = new MemoryStream();

        await Assert.ThrowsAsync<FirewallProtocolException>(
            () => FirewallProtocolCodec.WriteResponseAsync(stream, response));
    }

    [Fact]
    public async Task WriteResponseAsync_RejectsPayloadOnFailure()
    {
        var response = new FirewallCommandResponse(
            FirewallProtocolCodec.CurrentVersion,
            Guid.NewGuid(),
            Success: false,
            Error: FirewallProtocolError.Unauthorized,
            Policies: []);
        await using var stream = new MemoryStream();

        await Assert.ThrowsAsync<FirewallProtocolException>(
            () => FirewallProtocolCodec.WriteResponseAsync(stream, response));
    }

    [Fact]
    public async Task WriteResponseAsync_RejectsUnboundedPolicyPage()
    {
        var policies = Enumerable.Range(0, FirewallProtocolCodec.MaxPoliciesPerMessage + 1)
            .Select(index => new AppFirewallPolicy($@"C:\app-{index}.exe", OutboundAction.Ask))
            .ToArray();
        var response = new FirewallCommandResponse(
            FirewallProtocolCodec.CurrentVersion,
            Guid.NewGuid(),
            Success: true,
            Policies: policies);
        await using var stream = new MemoryStream();

        await Assert.ThrowsAsync<FirewallProtocolException>(
            () => FirewallProtocolCodec.WriteResponseAsync(stream, response));
    }

    private static MemoryStream Frame(string json)
    {
        var payload = Encoding.UTF8.GetBytes(json);
        var stream = new MemoryStream();
        stream.Write(BitConverter.GetBytes(payload.Length));
        stream.Write(payload);
        stream.Position = 0;
        return stream;
    }
}
