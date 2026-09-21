using WinSight.Core;

using Xunit;

namespace WinSight.Modules.Tests;

/// <summary>
/// Which loaded modules the scan names. User-mode loading enforces no signature, so a DLL whose
/// chain validates only through a root the user could have installed is how an injected module
/// reads as validly signed; only the persistence scan used to say so.
/// </summary>
public sealed class LoadedModuleTests
{
    private static LoadedModule Module(SignatureVerdict signature, string? path = @"C:\Users\me\AppData\Local\x.dll") =>
        new(1234, "host.exe", "x.dll", path, signature);

    [Theory]
    [InlineData(SignatureState.Unsigned)]
    [InlineData(SignatureState.SignedUntrusted)]
    public void AnUnsignedOrUntrustedModuleIsFlagged(SignatureState state)
    {
        var module = Module(new SignatureVerdict(state, null));

        Assert.True(module.Unsigned);
        Assert.True(module.Flagged);
    }

    [Fact]
    public void AModuleTrustedOnlyThroughAUserInstalledRootIsFlaggedWithoutBeingCalledUnsigned()
    {
        var module = Module(new SignatureVerdict(
            SignatureState.SignedTrusted, "CN=Microsoft Windows", SignatureTrustAnchor.UserInstalledRoot));

        Assert.False(module.Unsigned);
        Assert.True(module.TrustedOnlyThroughUserRoot);
        Assert.True(module.Flagged);
    }

    [Theory]
    [InlineData(SignatureTrustAnchor.MachineRoot)]
    [InlineData(SignatureTrustAnchor.Unspecified)]
    public void AModuleTrustedThroughTheMachineIsNotFlagged(SignatureTrustAnchor anchor)
    {
        var module = Module(new SignatureVerdict(SignatureState.SignedTrusted, "CN=Vendor", anchor));

        Assert.False(module.Flagged);
    }

    [Fact]
    public void AModuleWithNoResolvablePathIsNeverFlagged()
    {
        var module = Module(
            new SignatureVerdict(SignatureState.SignedTrusted, "CN=x", SignatureTrustAnchor.UserInstalledRoot),
            path: null);

        Assert.False(module.Flagged);
    }
}
