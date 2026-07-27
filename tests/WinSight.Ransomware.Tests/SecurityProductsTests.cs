using WinSight.Ransomware;

using Xunit;

namespace WinSight.Ransomware.Tests;

public sealed class SecurityProductTriageTests
{
    /// <summary>
    /// The live value this decoding was verified against before it was relied on: Windows Defender,
    /// actively scanning with current definitions, reports 0x061100 — scanner byte 0x11, signature
    /// byte 0x00.
    /// </summary>
    [Fact]
    public void Decode_TheObservedLiveDefenderValue_IsEnabledAndUpToDate()
    {
        var (state, signatures) = SecurityProductTriage.Decode(0x061100);

        Assert.Equal(SecurityProductState.Enabled, state);
        Assert.Equal(SecurityProductSignatures.UpToDate, signatures);
    }

    [Theory]
    [InlineData(0x011000, SecurityProductState.Enabled)]
    [InlineData(0x011100, SecurityProductState.Enabled)]
    [InlineData(0x010000, SecurityProductState.Disabled)]
    [InlineData(0x010100, SecurityProductState.Disabled)]
    public void Decode_KnownScannerBytes_AreDecoded(int productState, SecurityProductState expected) =>
        Assert.Equal(expected, SecurityProductTriage.Decode(productState).State);

    [Theory]
    [InlineData(0x011000, SecurityProductSignatures.UpToDate)]
    [InlineData(0x011010, SecurityProductSignatures.OutOfDate)]
    public void Decode_KnownSignatureBytes_AreDecoded(int productState, SecurityProductSignatures expected) =>
        Assert.Equal(expected, SecurityProductTriage.Decode(productState).Signatures);

    /// <summary>
    /// The encoding is undocumented, so a byte this reader does not know must not be rounded to the
    /// nearest guess. Guessing "probably enabled" would invent protection that was never observed.
    /// </summary>
    [Theory]
    [InlineData(0x01AB00)]
    [InlineData(0x017F00)]
    [InlineData(0x012000)]
    public void Decode_UnrecognisedScannerByte_IsUnknown_NotGuessedAsEnabled(int productState)
    {
        var (state, _) = SecurityProductTriage.Decode(productState);

        Assert.Equal(SecurityProductState.Unknown, state);
        Assert.NotEqual(SecurityProductState.Enabled, state);
    }

    [Theory]
    [InlineData(0x0110AB)]
    [InlineData(0x011099)]
    public void Decode_UnrecognisedSignatureByte_IsUnknown(int productState) =>
        Assert.Equal(SecurityProductSignatures.Unknown, SecurityProductTriage.Decode(productState).Signatures);

    [Fact]
    public void Concern_UnreadableSecurityCenter_IsUnavailable_NotAnAbsenceOfAntivirus() =>
        Assert.Equal(
            AntiVirusConcern.Unavailable,
            SecurityProductTriage.Concern(SecurityProductInventory.Unavailable));

    [Fact]
    public void Concern_SecurityCenterAnsweredWithNothingRegistered_IsDistinctFromUnreadable()
    {
        var inventory = new SecurityProductInventory(SecurityCenterReading.Available, []);

        Assert.Equal(AntiVirusConcern.NoAntiVirusRegistered, SecurityProductTriage.Concern(inventory));
    }

    [Fact]
    public void Concern_AThirdPartyAntivirusActivelyScanning_IsProtected()
    {
        var inventory = Inventory(Product("Bitdefender Antivirus", SecurityProductState.Enabled));

        Assert.Equal(AntiVirusConcern.Protected, SecurityProductTriage.Concern(inventory));
        Assert.True(inventory.HasActiveNonMicrosoftAntiVirus);
    }

    [Fact]
    public void Concern_EveryRegisteredAntivirusDisabled_IsNoActiveAntivirus()
    {
        var inventory = Inventory(
            Product("Windows Defender", SecurityProductState.Disabled),
            Product("Norton 360", SecurityProductState.Disabled));

        Assert.Equal(AntiVirusConcern.NoActiveAntiVirus, SecurityProductTriage.Concern(inventory));
    }

    /// <summary>
    /// An undecodable state must never count as protection: it is the difference between "something is
    /// scanning" and "we could not tell whether anything is scanning".
    /// </summary>
    [Fact]
    public void Concern_OnlyUndecodableProducts_DoNotEstablishProtection()
    {
        var inventory = Inventory(Product("Mystery Suite", SecurityProductState.Unknown));

        Assert.Empty(inventory.ActiveAntiVirusProducts);
        Assert.Equal(AntiVirusConcern.NoActiveAntiVirus, SecurityProductTriage.Concern(inventory));
        Assert.False(inventory.HasActiveNonMicrosoftAntiVirus);
    }

    [Fact]
    public void Concern_ActiveButEverySignatureStale_IsReportedAsOutOfDate()
    {
        var inventory = Inventory(
            Product("Norton 360", SecurityProductState.Enabled, SecurityProductSignatures.OutOfDate));

        Assert.Equal(AntiVirusConcern.SignaturesOutOfDate, SecurityProductTriage.Concern(inventory));
    }

    [Fact]
    public void Concern_OneCurrentProductAmongStaleOnes_IsEnoughToEstablishProtection()
    {
        var inventory = Inventory(
            Product("Norton 360", SecurityProductState.Enabled, SecurityProductSignatures.OutOfDate),
            Product("Windows Defender", SecurityProductState.Enabled));

        Assert.Equal(AntiVirusConcern.Protected, SecurityProductTriage.Concern(inventory));
    }

    [Theory]
    [InlineData(AntiVirusConcern.Protected, false)]
    [InlineData(AntiVirusConcern.SignaturesOutOfDate, true)]
    [InlineData(AntiVirusConcern.NoActiveAntiVirus, true)]
    [InlineData(AntiVirusConcern.NoAntiVirusRegistered, true)]
    [InlineData(AntiVirusConcern.Unavailable, true)]
    public void IsNotable_OnlyProtectedIsQuiet(AntiVirusConcern concern, bool expected) =>
        Assert.Equal(expected, SecurityProductTriage.IsNotable(concern));

    [Theory]
    [InlineData("Windows Defender", true)]
    [InlineData("Microsoft Defender Antivirus", true)]
    [InlineData("microsoft defender", true)]
    [InlineData("Bitdefender Antivirus Free", false)]
    [InlineData("Norton 360", false)]
    public void IsMicrosoftDefender_MatchesOnlyMicrosoftsOwnNames(string displayName, bool expected) =>
        Assert.Equal(expected, Product(displayName, SecurityProductState.Enabled).IsMicrosoftDefender);

    /// <summary>
    /// "Bitdefender" contains "defender". A naive substring match would call a third-party antivirus
    /// Microsoft's own, and the Controlled Folder Access finding would then be cross-referenced against
    /// the wrong product.
    /// </summary>
    [Fact]
    public void IsMicrosoftDefender_IsNotFooledByBitdefender()
    {
        var inventory = Inventory(Product("Bitdefender Total Security", SecurityProductState.Enabled));

        Assert.True(inventory.HasActiveNonMicrosoftAntiVirus);
    }

    private static SecurityProductInventory Inventory(params SecurityProduct[] products) =>
        new(SecurityCenterReading.Available, products);

    private static SecurityProduct Product(
        string displayName,
        SecurityProductState state,
        SecurityProductSignatures signatures = SecurityProductSignatures.UpToDate) =>
        new(SecurityProductKind.AntiVirus, displayName, state, signatures, RawProductState: 0);
}

public sealed class SecurityCenterReaderTests
{
    [Fact]
    public void Read_ProviderFailure_DegradesToUnavailable_RatherThanThrowing()
    {
        var reader = new SecurityCenterReader(new ThrowingDataSource());

        var inventory = reader.Read();

        Assert.Equal(SecurityCenterReading.Unavailable, inventory.Reading);
        Assert.Empty(inventory.Products);
        Assert.Equal(AntiVirusConcern.Unavailable, SecurityProductTriage.Concern(inventory));
    }

    [Fact]
    public void Read_CallerCancellation_Propagates_RatherThanLookingLikeAnEmptyMachine()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var reader = new SecurityCenterReader(new ThrowingDataSource());

        Assert.Throws<OperationCanceledException>(() => reader.Read(cancellation.Token));
    }

    [Fact]
    public void ToInventory_MapsEveryCategoryAndDecodesState()
    {
        var inventory = SecurityCenterReader.ToInventory(
        [
            new SecurityCenterRow(SecurityProductKind.AntiVirus, "Windows Defender", 0x061100),
            new SecurityCenterRow(SecurityProductKind.Firewall, "Norton Smart Firewall", 0x011000),
        ]);

        Assert.Equal(SecurityCenterReading.Available, inventory.Reading);
        Assert.Equal(2, inventory.Products.Count);
        var antivirus = Assert.Single(inventory.AntiVirusProducts);
        Assert.Equal("Windows Defender", antivirus.DisplayName);
        Assert.Equal(SecurityProductState.Enabled, antivirus.State);
        Assert.Equal(0x061100, antivirus.RawProductState);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ToInventory_RowWithNoUsableName_IsDropped_RatherThanShownBlank(string? displayName)
    {
        var inventory = SecurityCenterReader.ToInventory(
            [new SecurityCenterRow(SecurityProductKind.AntiVirus, displayName, 0x061100)]);

        Assert.Empty(inventory.Products);
        Assert.Equal(SecurityCenterReading.Available, inventory.Reading);
    }

    /// <summary>
    /// A product whose state word is missing is still a registered product. Dropping it would under-
    /// report what is installed; claiming it is enabled would over-report what is running.
    /// </summary>
    [Fact]
    public void ToInventory_RowWithNoStateWord_IsKeptAsUnknown()
    {
        var inventory = SecurityCenterReader.ToInventory(
            [new SecurityCenterRow(SecurityProductKind.AntiVirus, "Mystery Suite", null)]);

        var product = Assert.Single(inventory.Products);
        Assert.Equal(SecurityProductState.Unknown, product.State);
        Assert.Equal(SecurityProductSignatures.Unknown, product.Signatures);
    }

    [Fact]
    public void ToInventory_TrimsTheRegisteredName()
    {
        var inventory = SecurityCenterReader.ToInventory(
            [new SecurityCenterRow(SecurityProductKind.AntiVirus, "  Norton 360  ", 0x011000)]);

        Assert.Equal("Norton 360", Assert.Single(inventory.Products).DisplayName);
    }

    /// <summary>Zero rows is a valid answer meaning "none registered", never a failure.</summary>
    [Fact]
    public void ToInventory_NoRows_IsAvailableAndEmpty_NotUnavailable()
    {
        var inventory = SecurityCenterReader.ToInventory([]);

        Assert.Equal(SecurityCenterReading.Available, inventory.Reading);
        Assert.Equal(AntiVirusConcern.NoAntiVirusRegistered, SecurityProductTriage.Concern(inventory));
    }

    private sealed class ThrowingDataSource : ISecurityCenterDataSource
    {
        public IReadOnlyList<SecurityCenterRow> Read(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            throw new System.Management.ManagementException("namespace not found");
        }
    }
}
