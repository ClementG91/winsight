using WinSight.Core;

using Xunit;

namespace WinSight.Application.Tests;

/// <summary>
/// These tests set the process-wide VirusTotal key variable, so they must not run alongside
/// anything else that reads it.
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class VirusTotalEnvironmentCollection
{
    public const string Name = "virustotal-environment";
}

/// <summary>
/// Guards the only code in WinSight that can send anything off the machine. It had no tests at
/// all, which left the product's central promise — nothing leaves this PC unless the operator
/// turns reputation lookups on *and* supplies a key — resting on unverified code.
///
/// Each test asserts the lookup was never reached, not merely that the result was empty: an empty
/// result also comes back from a request that failed, so asserting on it alone would keep passing
/// if a guard were deleted. None of these tests touch the network, and none reach the quota
/// limiter, so they never consume the operator's real VirusTotal allowance.
/// </summary>
[Collection(VirusTotalEnvironmentCollection.Name)]
public sealed class VirusTotalEnricherTests
{
    private const string KeyVariable = "WINSIGHT_VT_KEY";

    // Deliberately not a real key shape: were any of this to ever reach the network, the request
    // would fail rather than authenticate as somebody.
    private const string UnusableKey = "key-that-must-never-be-used";

    private static readonly string[] SamplePath = [@"C:\Windows\System32\notepad.exe"];

    [Fact]
    public void Lookup_WithNetworkDisabled_NeverReachesTheService_EvenWhenAKeyIsConfigured()
    {
        // The default for every scan. A configured key must not be enough on its own: the operator
        // has to have asked for lookups too, so this is the branch that must never regress.
        using var key = new TemporaryEnvironmentVariable(KeyVariable, UnusableKey);
        var probe = new LookupProbe();

        var result = VirusTotalEnricher.Lookup(
            SamplePath, allowNetworkLookups: false, probe.Lookup, CancellationToken.None);

        Assert.Equal(0, probe.Calls);
        Assert.Empty(result);
    }

    [Fact]
    public void Lookup_WithoutAConfiguredKey_FailsClosed()
    {
        // Asking for lookups is not enough either. With no key there is nothing to authenticate
        // with, and the enricher must give up rather than attempt an anonymous request.
        using var key = new TemporaryEnvironmentVariable(KeyVariable, null);
        var probe = new LookupProbe();

        var result = VirusTotalEnricher.Lookup(
            SamplePath, allowNetworkLookups: true, probe.Lookup, CancellationToken.None);

        Assert.Equal(0, probe.Calls);
        Assert.Empty(result);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Lookup_TreatsABlankKeyAsNoKey(string configured)
    {
        // A key variable that exists but holds whitespace is a misconfiguration, not consent.
        using var key = new TemporaryEnvironmentVariable(KeyVariable, configured);
        var probe = new LookupProbe();

        var result = VirusTotalEnricher.Lookup(
            SamplePath, allowNetworkLookups: true, probe.Lookup, CancellationToken.None);

        Assert.Equal(0, probe.Calls);
        Assert.Empty(result);
    }

    [Fact]
    public void Lookup_HonoursCancellationBeforeItReadsOrSendsAnything()
    {
        // Cancellation is checked before the first file is even hashed. Pinning that ordering keeps
        // a cancelled scan from leaking a request the operator already asked to stop.
        using var key = new TemporaryEnvironmentVariable(KeyVariable, UnusableKey);
        using var cancellation = new CancellationTokenSource();
        var probe = new LookupProbe();
        cancellation.Cancel();

        Assert.ThrowsAny<OperationCanceledException>(() => VirusTotalEnricher.Lookup(
            SamplePath, allowNetworkLookups: true, probe.Lookup, cancellation.Token));
        Assert.Equal(0, probe.Calls);
    }

    [Fact]
    public void Lookup_WithNothingToEnrich_StaysOffTheNetwork()
    {
        // An empty candidate set must short-circuit rather than open a client and ask for nothing.
        using var key = new TemporaryEnvironmentVariable(KeyVariable, UnusableKey);
        var probe = new LookupProbe();

        var result = VirusTotalEnricher.Lookup(
            [], allowNetworkLookups: true, probe.Lookup, CancellationToken.None);

        Assert.Equal(0, probe.Calls);
        Assert.Empty(result);
    }

    [Fact]
    public void Lookup_WithOnlyUnreadableFiles_StaysOffTheNetwork()
    {
        // Nothing hashable means nothing to ask about. A path that cannot be read must not become
        // a request built from an empty or garbage digest.
        using var key = new TemporaryEnvironmentVariable(KeyVariable, UnusableKey);
        var probe = new LookupProbe();

        var result = VirusTotalEnricher.Lookup(
            [Path.Combine(Path.GetTempPath(), $"winsight-missing-{Guid.NewGuid():N}.exe")],
            allowNetworkLookups: true,
            probe.Lookup,
            CancellationToken.None);

        Assert.Equal(0, probe.Calls);
        Assert.Empty(result);
    }

    private sealed class LookupProbe
    {
        public int Calls { get; private set; }

        public VtVerdict? Lookup(string sha256, CancellationToken cancellationToken)
        {
            Calls++;
            return null;
        }
    }

    private sealed class TemporaryEnvironmentVariable : IDisposable
    {
        private readonly string _name;
        private readonly string? _original;

        public TemporaryEnvironmentVariable(string name, string? value)
        {
            _name = name;
            _original = Environment.GetEnvironmentVariable(name);
            Environment.SetEnvironmentVariable(name, value);
        }

        public void Dispose() => Environment.SetEnvironmentVariable(_name, _original);
    }
}
