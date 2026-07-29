using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using WinSight.Ransomware;

using Xunit;

namespace WinSight.Ransomware.Tests;

public sealed class SecurityProductTriageTests
{
    [Fact]
    public void AntiVirusConcern_LegacyNumericValuesRemainStable()
    {
        Assert.Equal(0, (int)AntiVirusConcern.Protected);
        Assert.Equal(1, (int)AntiVirusConcern.SignaturesOutOfDate);
        Assert.Equal(2, (int)AntiVirusConcern.NoActiveAntiVirus);
        Assert.Equal(3, (int)AntiVirusConcern.NoAntiVirusRegistered);
        Assert.Equal(4, (int)AntiVirusConcern.Unavailable);
        Assert.Equal(5, (int)AntiVirusConcern.SignatureStatusUnknown);
        Assert.Equal(6, (int)AntiVirusConcern.ActivityStatusUnknown);
    }

    [Theory]
    [InlineData(0, SecurityProductState.Enabled)]
    [InlineData(1, SecurityProductState.Disabled)]
    [InlineData(2, SecurityProductState.Snoozed)]
    [InlineData(3, SecurityProductState.Expired)]
    [InlineData(-1, SecurityProductState.Unknown)]
    [InlineData(4, SecurityProductState.Unknown)]
    [InlineData(0x061100, SecurityProductState.Unknown)]
    [InlineData(int.MaxValue, SecurityProductState.Unknown)]
    public void MapProductState_MapsOnlyDocumentedComValues(
        int rawState,
        SecurityProductState expected) =>
        Assert.Equal(expected, SecurityProductTriage.MapProductState(rawState));

    [Theory]
    [InlineData(0, SecurityProductSignatures.OutOfDate)]
    [InlineData(1, SecurityProductSignatures.UpToDate)]
    [InlineData(-1, SecurityProductSignatures.Unknown)]
    [InlineData(2, SecurityProductSignatures.Unknown)]
    [InlineData(0x10, SecurityProductSignatures.Unknown)]
    [InlineData(int.MaxValue, SecurityProductSignatures.Unknown)]
    public void MapSignatureStatus_MapsOnlyDocumentedComValues(
        int rawStatus,
        SecurityProductSignatures expected) =>
        Assert.Equal(expected, SecurityProductTriage.MapSignatureStatus(rawStatus));

    [Fact]
    public void Decode_RemainsLegacyOnly_AndDoesNotDefineComMappings()
    {
        var (legacyState, legacySignatures) = SecurityProductTriage.Decode(0x061100);

        Assert.Equal(SecurityProductState.Enabled, legacyState);
        Assert.Equal(SecurityProductSignatures.UpToDate, legacySignatures);
        Assert.Equal(
            SecurityProductState.Unknown,
            SecurityProductTriage.MapProductState(0x061100));
    }

    [Fact]
    public void Concern_UnreadableSecurityCenter_IsUnavailable_NotAnAbsenceOfAntivirus() =>
        Assert.Equal(
            AntiVirusConcern.Unavailable,
            SecurityProductTriage.Concern(SecurityProductInventory.Unavailable));

    [Fact]
    public void Concern_SecurityCenterAnsweredWithNothingRegistered_IsDistinctFromUnreadable()
    {
        var inventory = Inventory();

        Assert.Equal(AntiVirusConcern.NoAntiVirusRegistered, SecurityProductTriage.Concern(inventory));
    }

    [Fact]
    public void Concern_EnabledAndCurrent_EstablishesProtection()
    {
        var inventory = Inventory(Product(
            "Bitdefender Antivirus",
            SecurityProductState.Enabled,
            SecurityProductSignatures.UpToDate));

        Assert.Equal(AntiVirusConcern.Protected, SecurityProductTriage.Concern(inventory));
        Assert.True(inventory.HasActiveNonMicrosoftAntiVirus);
    }

    [Fact]
    public void Concern_UnknownOnly_IsActivityStatusUnknown_NotNoActiveAntivirus()
    {
        var inventory = Inventory(Product(
            "Mystery Suite",
            SecurityProductState.Unknown,
            SecurityProductSignatures.UpToDate));

        Assert.Empty(inventory.ActiveAntiVirusProducts);
        Assert.Equal(AntiVirusConcern.ActivityStatusUnknown, SecurityProductTriage.Concern(inventory));
        Assert.False(inventory.HasActiveNonMicrosoftAntiVirus);
    }

    [Fact]
    public void Concern_DisabledPlusUnknown_IsActivityStatusUnknown()
    {
        var inventory = Inventory(
            Product(
                "Known Off",
                SecurityProductState.Disabled,
                SecurityProductSignatures.UpToDate),
            Product(
                "Future Product",
                SecurityProductState.Unknown,
                SecurityProductSignatures.UpToDate));

        Assert.Equal(AntiVirusConcern.ActivityStatusUnknown, SecurityProductTriage.Concern(inventory));
    }

    [Fact]
    public void Concern_UnknownActivityWithExplicitlyStaleSignature_IsActivityStatusUnknown()
    {
        var inventory = Inventory(Product(
            "Future Product",
            SecurityProductState.Unknown,
            SecurityProductSignatures.OutOfDate));

        Assert.Equal(AntiVirusConcern.ActivityStatusUnknown, SecurityProductTriage.Concern(inventory));
    }

    [Theory]
    [InlineData(SecurityProductSignatures.OutOfDate)]
    [InlineData(SecurityProductSignatures.Unknown)]
    public void Concern_UnknownActivityOutranksAnotherOnProductWithoutCurrentSignatures(
        SecurityProductSignatures onProductSignatures)
    {
        var inventory = Inventory(
            Product(
                "Future Activity",
                SecurityProductState.Unknown,
                SecurityProductSignatures.OutOfDate),
            Product(
                "On Product",
                SecurityProductState.Enabled,
                onProductSignatures));

        Assert.Equal(AntiVirusConcern.ActivityStatusUnknown, SecurityProductTriage.Concern(inventory));
    }

    [Fact]
    public void Concern_SnoozedAndExpiredOnly_AreExplicitlyInactive()
    {
        var inventory = Inventory(
            Product(
                "Snoozed Product",
                SecurityProductState.Snoozed,
                SecurityProductSignatures.UpToDate),
            Product(
                "Expired Product",
                SecurityProductState.Expired,
                SecurityProductSignatures.OutOfDate));

        Assert.Equal(AntiVirusConcern.NoActiveAntiVirus, SecurityProductTriage.Concern(inventory));
    }

    [Fact]
    public void Concern_EnabledWithUnknownSignature_IsSignatureStatusUnknown()
    {
        var inventory = Inventory(Product(
            "Mystery Signatures",
            SecurityProductState.Enabled,
            SecurityProductSignatures.Unknown));

        Assert.Equal(AntiVirusConcern.SignatureStatusUnknown, SecurityProductTriage.Concern(inventory));
    }

    [Fact]
    public void Concern_StalePlusUnknownActive_IsSignatureStatusUnknown()
    {
        var inventory = Inventory(
            Product(
                "Known Stale",
                SecurityProductState.Enabled,
                SecurityProductSignatures.OutOfDate),
            Product(
                "Unknown Currency",
                SecurityProductState.Enabled,
                SecurityProductSignatures.Unknown));

        Assert.Equal(AntiVirusConcern.SignatureStatusUnknown, SecurityProductTriage.Concern(inventory));
    }

    [Fact]
    public void Concern_CurrentPlusUnknownActive_IsProtected()
    {
        var inventory = Inventory(
            Product(
                "Known Current",
                SecurityProductState.Enabled,
                SecurityProductSignatures.UpToDate),
            Product(
                "Unknown Currency",
                SecurityProductState.Enabled,
                SecurityProductSignatures.Unknown));

        Assert.Equal(AntiVirusConcern.Protected, SecurityProductTriage.Concern(inventory));
    }

    [Fact]
    public void Concern_EnabledCurrentProductProtectsEvenWhenAnotherActivityStateIsUnknown()
    {
        var inventory = Inventory(
            Product(
                "Known Current",
                SecurityProductState.Enabled,
                SecurityProductSignatures.UpToDate),
            Product(
                "Future Activity",
                SecurityProductState.Unknown,
                SecurityProductSignatures.OutOfDate));

        Assert.Equal(AntiVirusConcern.Protected, SecurityProductTriage.Concern(inventory));
    }

    [Fact]
    public void Concern_AllEnabledProductsExplicitlyStale_IsOutOfDate()
    {
        var inventory = Inventory(
            Product(
                "Known Stale",
                SecurityProductState.Enabled,
                SecurityProductSignatures.OutOfDate),
            Product(
                "Also Stale",
                SecurityProductState.Enabled,
                SecurityProductSignatures.OutOfDate));

        Assert.Equal(AntiVirusConcern.SignaturesOutOfDate, SecurityProductTriage.Concern(inventory));
    }

    [Fact]
    public void Concern_EveryRegisteredAntivirusExplicitlyOff_IsNoActiveAntivirus()
    {
        var inventory = Inventory(
            Product(
                "Windows Defender",
                SecurityProductState.Disabled,
                SecurityProductSignatures.UpToDate),
            Product(
                "Norton 360",
                SecurityProductState.Disabled,
                SecurityProductSignatures.UpToDate));

        Assert.Equal(AntiVirusConcern.NoActiveAntiVirus, SecurityProductTriage.Concern(inventory));
    }

    [Theory]
    [InlineData(AntiVirusConcern.Protected, false)]
    [InlineData(AntiVirusConcern.SignaturesOutOfDate, true)]
    [InlineData(AntiVirusConcern.SignatureStatusUnknown, true)]
    [InlineData(AntiVirusConcern.ActivityStatusUnknown, true)]
    [InlineData(AntiVirusConcern.NoActiveAntiVirus, true)]
    [InlineData(AntiVirusConcern.NoAntiVirusRegistered, true)]
    [InlineData(AntiVirusConcern.Unavailable, true)]
    public void IsNotable_OnlyProtectedIsQuiet(AntiVirusConcern concern, bool expected) =>
        Assert.Equal(expected, SecurityProductTriage.IsNotable(concern));

    /// <summary>
    /// <b>This heuristic reads a localized string, and that is new.</b> The WMI inventory it replaced
    /// returned the invariant English "Windows Defender"; <c>IWscProduct::get_ProductName</c> returns
    /// the display name in the machine's own language — a French host returns
    /// "Antivirus Microsoft Defender", observed live on 2026-07-29. The brand tokens survive
    /// localization, which is why the match works, but the coupling did not exist before and is
    /// pinned here so a locale that breaks it fails a test rather than a user's verdict.
    ///
    /// The adjacency requirement is the load-bearing part. Relaxing it to "contains Defender AND
    /// contains Microsoft or Windows" — which reads like a locale-robustness improvement — makes
    /// "Bitdefender Antivirus for Windows" match, turning a competitor into Microsoft's own product
    /// on the one path that decides whether the operator is told they are protected. That case is
    /// listed below precisely so the next person to have that idea sees it fail.
    /// </summary>
    [Theory]
    [InlineData("Windows Defender", true)]
    [InlineData("Microsoft Defender Antivirus", true)]
    [InlineData("microsoft defender", true)]
    // Observed live on a French Windows host through the COM inventory.
    [InlineData("Antivirus Microsoft Defender", true)]
    // Spanish and Japanese shipping forms: the brand stays Latin and adjacent.
    [InlineData("Antivirus de Microsoft Defender", true)]
    [InlineData("Microsoft Defender ウイルス対策", true)]
    [InlineData("Bitdefender Antivirus Free", false)]
    // The trap a token-based "improvement" falls into.
    [InlineData("Bitdefender Antivirus for Windows", false)]
    [InlineData("Norton 360", false)]
    public void IsMicrosoftDefender_MatchesOnlyMicrosoftsOwnNames(string displayName, bool expected) =>
        Assert.Equal(
            expected,
            Product(
                displayName,
                SecurityProductState.Enabled,
                SecurityProductSignatures.UpToDate).IsMicrosoftDefender);

    [Fact]
    public void IsMicrosoftDefender_IsNotFooledByBitdefender()
    {
        var inventory = Inventory(Product(
            "Bitdefender Total Security",
            SecurityProductState.Enabled,
            SecurityProductSignatures.UpToDate));

        Assert.True(inventory.HasActiveNonMicrosoftAntiVirus);
    }

    private static SecurityProductInventory Inventory(params SecurityProduct[] products) =>
        new(SecurityCenterReading.Available, products);

    private static SecurityProduct Product(
        string displayName,
        SecurityProductState state,
        SecurityProductSignatures signatures) =>
        new(SecurityProductKind.AntiVirus, displayName, state, signatures, RawProductState: 0)
        {
            RawSignatureStatus = 1,
        };
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
    public void Read_ProviderCancellationWithoutCallerCancellation_DegradesToUnavailable()
    {
        var reader = new SecurityCenterReader(new CancelingDataSource());

        var inventory = reader.Read();

        Assert.Equal(SecurityCenterReading.Unavailable, inventory.Reading);
        Assert.Empty(inventory.Products);
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
    public void ToInventory_MapsOfficialComStateAndSignatureValues()
    {
        var inventory = SecurityCenterReader.ToInventory(
        [
            new SecurityCenterRow(SecurityProductKind.AntiVirus, "On Stale", 0, 0),
            new SecurityCenterRow(SecurityProductKind.AntiVirus, "Off Current", 1, 1),
            new SecurityCenterRow(SecurityProductKind.AntiVirus, "Snoozed", 2, 1),
            new SecurityCenterRow(SecurityProductKind.AntiVirus, "Expired", 3, 0),
            new SecurityCenterRow(SecurityProductKind.AntiVirus, "Future", 17, 23),
        ]);

        Assert.Collection(
            inventory.Products,
            product =>
            {
                Assert.Equal(SecurityProductState.Enabled, product.State);
                Assert.Equal(SecurityProductSignatures.OutOfDate, product.Signatures);
            },
            product =>
            {
                Assert.Equal(SecurityProductState.Disabled, product.State);
                Assert.Equal(SecurityProductSignatures.UpToDate, product.Signatures);
            },
            product => Assert.Equal(SecurityProductState.Snoozed, product.State),
            product => Assert.Equal(SecurityProductState.Expired, product.State),
            product =>
            {
                Assert.Equal(SecurityProductState.Unknown, product.State);
                Assert.Equal(SecurityProductSignatures.Unknown, product.Signatures);
            });
    }

    [Fact]
    public void ToInventory_DoesNotDecodeLegacyWmiProductStateWord()
    {
        var inventory = SecurityCenterReader.ToInventory(
            [new SecurityCenterRow(SecurityProductKind.AntiVirus, "Legacy-looking", 0x061100, 1)]);

        var product = Assert.Single(inventory.Products);
        Assert.Equal(SecurityProductState.Unknown, product.State);
        Assert.NotEqual(SecurityProductState.Enabled, product.State);
        Assert.Equal(0, product.RawProductState);
        Assert.Equal(0x061100, product.RawActivityState);
    }

    [Fact]
    public void ToInventory_PreservesSeparateRawActivityAndSignatureValues()
    {
        var inventory = SecurityCenterReader.ToInventory(
            [new SecurityCenterRow(SecurityProductKind.AntiVirus, "Future", 173, 271)]);

        var product = Assert.Single(inventory.Products);
        Assert.Equal(0, product.RawProductState);
        Assert.Equal(173, product.RawActivityState);
        Assert.Equal(271, product.RawSignatureStatus);
        Assert.Equal(SecurityProductState.Unknown, product.State);
        Assert.Equal(SecurityProductSignatures.Unknown, product.Signatures);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\t\r\n\0")]
    public void ToInventory_BlankOrControlOnlyName_RemainsAnUnnamedRegistration(string? displayName)
    {
        var inventory = SecurityCenterReader.ToInventory(
            [new SecurityCenterRow(SecurityProductKind.AntiVirus, displayName, 1, 1)]);

        var product = Assert.Single(inventory.Products);
        Assert.Equal("(unnamed antivirus)", product.DisplayName);
        Assert.Equal(AntiVirusConcern.NoActiveAntiVirus, SecurityProductTriage.Concern(inventory));
    }

    [Fact]
    public void ToInventory_NeutralizesControlsAndNewlinesInProductName()
    {
        var inventory = SecurityCenterReader.ToInventory(
            [new SecurityCenterRow(
                SecurityProductKind.AntiVirus,
                "  Vendor\r\n\tProduct\0  Suite  ",
                0,
                1)]);

        Assert.Equal("Vendor Product Suite", Assert.Single(inventory.Products).DisplayName);
    }

    [Fact]
    public void ToInventory_IgnoresUnpairedSurrogatesInProductName()
    {
        var inventory = SecurityCenterReader.ToInventory(
            [new SecurityCenterRow(SecurityProductKind.AntiVirus, "\uD800Vendor\uDC00", 0, 1)]);

        Assert.Equal("Vendor", Assert.Single(inventory.Products).DisplayName);
    }

    [Fact]
    public void ToInventory_RemovesUnicodeBidiAndOtherFormatCharacters()
    {
        var inventory = SecurityCenterReader.ToInventory(
            [new SecurityCenterRow(
                SecurityProductKind.AntiVirus,
                "Vendor\u202Eevil\u2066\u200D AV",
                0,
                1)]);

        Assert.Equal("Vendorevil AV", Assert.Single(inventory.Products).DisplayName);
    }

    [Fact]
    public void ToInventory_InspectsAtMost1024Utf16CodeUnits()
    {
        var inventory = SecurityCenterReader.ToInventory(
            [new SecurityCenterRow(
                SecurityProductKind.AntiVirus,
                new string('\u202E', 1024) + "InvisibleTailMustNotBeInspected",
                0,
                1)]);

        Assert.Equal("(unnamed antivirus)", Assert.Single(inventory.Products).DisplayName);
    }

    [Fact]
    public void ToInventory_BoundsProductNameAt256Utf16CodeUnits()
    {
        var inventory = SecurityCenterReader.ToInventory(
            [new SecurityCenterRow(SecurityProductKind.AntiVirus, new string('a', 300), 0, 1)]);

        var displayName = Assert.Single(inventory.Products).DisplayName;
        Assert.Equal(256, displayName.Length);
        Assert.Equal(new string('a', 256), displayName);
    }

    [Fact]
    public void ToInventory_MissingRawValues_AreUnknownAndRemainObservable()
    {
        var inventory = SecurityCenterReader.ToInventory(
            [new SecurityCenterRow(SecurityProductKind.AntiVirus, "Mystery Suite", null, null)]);

        var product = Assert.Single(inventory.Products);
        Assert.Equal(SecurityProductState.Unknown, product.State);
        Assert.Equal(SecurityProductSignatures.Unknown, product.Signatures);
        Assert.Equal(0, product.RawProductState);
        Assert.Null(product.RawActivityState);
        Assert.Null(product.RawSignatureStatus);
    }

    [Fact]
    public void ToInventory_NoRows_IsAvailableAndEmpty_NotUnavailable()
    {
        var inventory = SecurityCenterReader.ToInventory([]);

        Assert.Equal(SecurityCenterReading.Available, inventory.Reading);
        Assert.Empty(inventory.Products);
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

    private sealed class CancelingDataSource : ISecurityCenterDataSource
    {
        public IReadOnlyList<SecurityCenterRow> Read(CancellationToken cancellationToken) =>
            throw new OperationCanceledException();
    }
}

public sealed class ComSecurityCenterDataSourceTests
{
    [Fact]
    public void Read_UsesDocumentedCallOrderAndDisposesEachOwnedWrapper()
    {
        using var cancellation = new CancellationTokenSource();
        var factory = new FakeProductListFactory(cancellation, count: 2);
        var reader = Reader(factory);

        var inventory = reader.Read(cancellation.Token);

        Assert.Equal(SecurityCenterReading.Available, inventory.Reading);
        Assert.Equal(2, inventory.Products.Count);
        Assert.Equal(
        [
            "Create",
            "Initialize:4",
            "Count",
            "Item:0",
            "Name:0",
            "State:0",
            "Signature:0",
            "DisposeProduct:0",
            "Item:1",
            "Name:1",
            "State:1",
            "Signature:1",
            "DisposeProduct:1",
            "DisposeList",
        ],
            factory.Events);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(65)]
    public void Read_InvalidProductCount_IsUnavailableAndDisposesList(int count)
    {
        using var cancellation = new CancellationTokenSource();
        var factory = new FakeProductListFactory(cancellation, count);

        var inventory = Reader(factory).Read(cancellation.Token);

        Assert.Equal(SecurityCenterReading.Unavailable, inventory.Reading);
        Assert.Equal(
            ["Create", "Initialize:4", "Count", "DisposeList"],
            factory.Events);
    }

    [Theory]
    [InlineData(Effect.Create)]
    [InlineData(Effect.Initialize)]
    [InlineData(Effect.Count)]
    [InlineData(Effect.Item)]
    [InlineData(Effect.Name)]
    [InlineData(Effect.State)]
    [InlineData(Effect.Signature)]
    public void Read_ManagedSeamFailure_IsUnavailableAndReleasesAcquiredWrappers(Effect failure)
    {
        using var cancellation = new CancellationTokenSource();
        var factory = new FakeProductListFactory(cancellation, count: 1, failure: failure);

        var inventory = Reader(factory).Read(cancellation.Token);

        Assert.Equal(SecurityCenterReading.Unavailable, inventory.Reading);
        Assert.Equal(ExpectedEventsThrough(failure, canceled: false), factory.Events);
    }

    [Theory]
    [InlineData(Effect.Create)]
    [InlineData(Effect.Initialize)]
    [InlineData(Effect.Count)]
    [InlineData(Effect.Item)]
    [InlineData(Effect.Name)]
    [InlineData(Effect.State)]
    [InlineData(Effect.Signature)]
    public void Read_ComFailureAtEveryNativeEffect_IsUnavailableAndReleasesAcquiredWrappers(
        Effect failure)
    {
        using var cancellation = new CancellationTokenSource();
        var factory = new FakeProductListFactory(
            cancellation,
            count: 1,
            failure: failure,
            useComException: true);

        var inventory = Reader(factory).Read(cancellation.Token);

        Assert.Equal(SecurityCenterReading.Unavailable, inventory.Reading);
        Assert.Equal(ExpectedEventsThrough(failure, canceled: false), factory.Events);
    }

    [Theory]
    [InlineData(Effect.Create)]
    [InlineData(Effect.Initialize)]
    [InlineData(Effect.Count)]
    [InlineData(Effect.Item)]
    [InlineData(Effect.Name)]
    [InlineData(Effect.State)]
    [InlineData(Effect.Signature)]
    public void Read_CallerCancellationBetweenNativeEffects_PropagatesAndReleasesWrappers(
        Effect cancellationEffect)
    {
        using var cancellation = new CancellationTokenSource();
        var factory = new FakeProductListFactory(
            cancellation,
            count: 1,
            cancellationEffect: cancellationEffect);

        Assert.Throws<OperationCanceledException>(() => Reader(factory).Read(cancellation.Token));
        Assert.Equal(ExpectedEventsThrough(cancellationEffect, canceled: true), factory.Events);
    }

    [Fact]
    public void DefaultComposition_UsesTheRealManagedComSourceAndFactory()
    {
        var reader = new SecurityCenterReader();

        var source = Assert.IsType<ComSecurityCenterDataSource>(reader.DataSource);
        var factory = Assert.IsType<ComSecurityCenterProductListFactory>(source.ProductListFactory);
        Assert.IsType<RuntimeComClassActivator>(factory.Activator);
        Assert.IsType<MarshalComReferenceReleaser>(factory.Releaser);
        Assert.Equal(0x4u, ComSecurityCenterDataSource.AntiVirusProvider);
        Assert.Equal(64, ComSecurityCenterDataSource.MaximumProducts);
        Assert.Equal(
            new Guid("17072F7B-9ABE-4A74-A261-1EB76B55107A"),
            ComSecurityCenterProductListFactory.ProductListClassId);
    }

    [Fact]
    public void ProductListFactory_ActivationFailureDoesNotReleaseAnUnacquiredReference()
    {
        var releaser = new CountingComReferenceReleaser();
        var factory = new ComSecurityCenterProductListFactory(
            new FakeComClassActivator(() => throw new InvalidOperationException("activation failed")),
            releaser);

        Assert.Throws<InvalidOperationException>(() => factory.Create());
        Assert.Empty(releaser.Released);
    }

    [Fact]
    public void ProductListFactory_NonProductListObjectIsReleasedExactlyOnce()
    {
        var activated = new object();
        var releaser = new CountingComReferenceReleaser();
        var factory = new ComSecurityCenterProductListFactory(
            new FakeComClassActivator(() => activated),
            releaser);

        Assert.Throws<InvalidCastException>(() => factory.Create());
        Assert.Equal([activated], releaser.Released);
    }

    [Fact]
    public void ComOwnedReference_ClearsValueBeforeExactlyOneReleaseCallback()
    {
        var ownedObject = new object();
        ComOwnedReference? owner = null;
        var releaser = new CountingComReferenceReleaser(() =>
            Assert.Throws<ObjectDisposedException>(() => owner!.Value));
        owner = new ComOwnedReference(ownedObject, releaser);

        Assert.Same(ownedObject, owner.Value);
        owner.Dispose();
        owner.Dispose();

        Assert.Equal([ownedObject], releaser.Released);
        Assert.Throws<ObjectDisposedException>(() => owner.Value);
    }

    [Fact]
    public void ConcreteComWrappers_DisposeThroughComOwnedReference()
    {
        AssertDisposeCallsOwnership(typeof(ComSecurityCenterProductList));
        AssertDisposeCallsOwnership(typeof(ComSecurityCenterProduct));
    }

    [Fact]
    public void MarshalComReferenceReleaser_InvokesExactlyMarshalReleaseComObject()
    {
        var release = typeof(MarshalComReferenceReleaser).GetMethod(
            nameof(IComReferenceReleaser.Release),
            BindingFlags.Instance | BindingFlags.Public)!;
        var expected = typeof(Marshal).GetMethod(
            nameof(Marshal.ReleaseComObject),
            BindingFlags.Static | BindingFlags.Public,
            binder: null,
            types: [typeof(object)],
            modifiers: null)!;

        var actual = Assert.IsAssignableFrom<MethodInfo>(Assert.Single(
            CalledMethods(release),
            method => method.DeclaringType == typeof(Marshal)));

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void ProductListComAbi_MatchesTheWindowsSdkContract()
    {
        var type = typeof(IWscProductList);

        Assert.True(type.IsImport);
        Assert.Equal(new Guid("722A338C-6E8E-4E72-AC27-1417FB0C81C2"), type.GUID);
        Assert.Equal(
            ComInterfaceType.InterfaceIsDual,
            type.GetCustomAttribute<InterfaceTypeAttribute>()?.Value);

        var methods = type.GetMethods().OrderBy(method => method.MetadataToken).ToArray();
        Assert.Equal(["Initialize", "GetCount", "GetItem"], methods.Select(method => method.Name));
        Assert.Equal(typeof(void), methods[0].ReturnType);
        Assert.Equal([typeof(uint)], methods[0].GetParameters().Select(parameter => parameter.ParameterType));
        Assert.Empty(methods[1].GetParameters());
        Assert.Equal(typeof(int), methods[1].ReturnType);
        Assert.Equal([typeof(uint)], methods[2].GetParameters().Select(parameter => parameter.ParameterType));
        Assert.Equal(typeof(IWscProduct), methods[2].ReturnType);
        Assert.Equal(
            UnmanagedType.Interface,
            methods[2].ReturnParameter.GetCustomAttribute<MarshalAsAttribute>()?.Value);
    }

    [Fact]
    public void ProductComAbi_MatchesTheWindowsSdkContract()
    {
        var type = typeof(IWscProduct);

        Assert.True(type.IsImport);
        Assert.Equal(new Guid("8C38232E-3A45-4A27-92B0-1A16A975F669"), type.GUID);
        Assert.Equal(
            ComInterfaceType.InterfaceIsDual,
            type.GetCustomAttribute<InterfaceTypeAttribute>()?.Value);

        var methods = type.GetMethods().OrderBy(method => method.MetadataToken).ToArray();
        Assert.Equal(
            ["GetProductName", "GetProductState", "GetSignatureStatus"],
            methods.Select(method => method.Name));
        Assert.All(methods, method => Assert.Empty(method.GetParameters()));
        Assert.Equal(typeof(string), methods[0].ReturnType);
        Assert.Equal(
            UnmanagedType.BStr,
            methods[0].ReturnParameter.GetCustomAttribute<MarshalAsAttribute>()?.Value);
        Assert.Equal(typeof(int), methods[1].ReturnType);
        Assert.Equal(typeof(int), methods[2].ReturnType);
    }

    private static SecurityCenterReader Reader(FakeProductListFactory factory) =>
        new(new ComSecurityCenterDataSource(factory));

    /// <summary>
    /// The imported SDK interfaces cannot be implemented by a managed fake without manufacturing a
    /// real RCW. The managed source seam proves operational disposal order; this narrow IL assertion
    /// additionally binds each concrete RCW wrapper's Dispose method to ComOwnedReference.Dispose.
    /// Removing either ownership call therefore fails without activating mutable host COM state.
    /// </summary>
    private static void AssertDisposeCallsOwnership(Type wrapperType)
    {
        var wrapperDispose = wrapperType.GetMethod(
            nameof(IDisposable.Dispose),
            BindingFlags.Instance | BindingFlags.Public)!;
        var ownershipDispose = typeof(ComOwnedReference).GetMethod(
            nameof(IDisposable.Dispose),
            BindingFlags.Instance | BindingFlags.Public)!;
        var ownershipCalls = CalledMethods(wrapperDispose)
            .Where(method => method == ownershipDispose)
            .ToArray();

        Assert.Single(ownershipCalls);
    }

    private static List<MethodBase> CalledMethods(MethodInfo containingMethod)
    {
        var il = containingMethod.GetMethodBody()?.GetILAsByteArray();
        Assert.NotNull(il);
        var calls = new List<MethodBase>();
        var offset = 0;
        while (offset < il.Length)
        {
            var firstByte = il[offset++];
            var opcodeValue = firstByte == 0xFE
                ? (ushort)(0xFE00 | il[offset++])
                : firstByte;
            Assert.True(OpCodesByValue.TryGetValue(opcodeValue, out var opcode));

            if (opcode.OperandType == OperandType.InlineMethod)
            {
                var token = BitConverter.ToInt32(il, offset);
                if (opcode == OpCodes.Call || opcode == OpCodes.Callvirt)
                {
                    calls.Add(containingMethod.Module.ResolveMethod(
                        token,
                        containingMethod.DeclaringType?.GetGenericArguments(),
                        containingMethod.IsGenericMethod
                            ? containingMethod.GetGenericArguments()
                            : null)!);
                }
            }
            offset += OperandSize(opcode.OperandType, il, offset);
        }
        return calls;
    }

    private static int OperandSize(OperandType operandType, byte[] il, int operandOffset) =>
        operandType switch
        {
            OperandType.InlineNone => 0,
            OperandType.ShortInlineBrTarget
                or OperandType.ShortInlineI
                or OperandType.ShortInlineVar => 1,
            OperandType.InlineVar => 2,
            OperandType.InlineBrTarget
                or OperandType.InlineField
                or OperandType.InlineI
                or OperandType.InlineMethod
                or OperandType.InlineSig
                or OperandType.InlineString
                or OperandType.InlineTok
                or OperandType.ShortInlineR => 4,
            OperandType.InlineI8
                or OperandType.InlineR => 8,
            OperandType.InlineSwitch => 4 + (4 * BitConverter.ToInt32(il, operandOffset)),
            _ => throw new InvalidOperationException($"Unsupported IL operand type {operandType}."),
        };

    private static readonly Dictionary<ushort, OpCode> OpCodesByValue =
        typeof(OpCodes)
            .GetFields(BindingFlags.Public | BindingFlags.Static)
            .Where(field => field.FieldType == typeof(OpCode))
            .Select(field => (OpCode)field.GetValue(null)!)
            .ToDictionary(opcode => unchecked((ushort)opcode.Value));

    private static string[] ExpectedEventsThrough(Effect effect, bool canceled)
    {
        var events = new List<string> { "Create" };
        if (effect >= Effect.Initialize)
        {
            events.Add("Initialize:4");
        }
        if (effect >= Effect.Count)
        {
            events.Add("Count");
        }
        if (effect >= Effect.Item)
        {
            events.Add("Item:0");
        }
        if (effect >= Effect.Name)
        {
            events.Add("Name:0");
        }
        if (effect >= Effect.State)
        {
            events.Add("State:0");
        }
        if (effect >= Effect.Signature)
        {
            events.Add("Signature:0");
        }
        if (effect >= Effect.Name || canceled && effect == Effect.Item)
        {
            events.Add("DisposeProduct:0");
        }
        if (effect != Effect.Create || canceled)
        {
            events.Add("DisposeList");
        }
        return [.. events];
    }

    public enum Effect
    {
        Create,
        Initialize,
        Count,
        Item,
        Name,
        State,
        Signature,
    }

    private sealed class FakeProductListFactory(
        CancellationTokenSource cancellation,
        int count,
        Effect? failure = null,
        Effect? cancellationEffect = null,
        bool useComException = false) : ISecurityCenterProductListFactory
    {
        public List<string> Events { get; } = [];

        public ISecurityCenterProductList Create()
        {
            Events.Add("Create");
            After(Effect.Create);
            return new FakeProductList(this, count);
        }

        public void After(Effect effect)
        {
            if (cancellationEffect == effect)
            {
                cancellation.Cancel();
            }
            if (failure == effect)
            {
                if (useComException)
                {
                    var comFailure = Marshal.GetExceptionForHR(unchecked((int)0x80004005));
                    Assert.IsType<COMException>(comFailure);
                    ExceptionDispatchInfo.Capture(comFailure).Throw();
                }
                throw new InvalidOperationException($"Injected {effect} failure.");
            }
        }
    }

    private sealed class FakeProductList(FakeProductListFactory owner, int count)
        : ISecurityCenterProductList
    {
        public void Initialize(uint provider)
        {
            owner.Events.Add($"Initialize:{provider}");
            owner.After(Effect.Initialize);
        }

        public int GetCount()
        {
            owner.Events.Add("Count");
            owner.After(Effect.Count);
            return count;
        }

        public ISecurityCenterProduct GetItem(uint index)
        {
            owner.Events.Add($"Item:{index}");
            owner.After(Effect.Item);
            return new FakeProduct(owner, index);
        }

        public void Dispose() => owner.Events.Add("DisposeList");
    }

    private sealed class FakeProduct(FakeProductListFactory owner, uint index)
        : ISecurityCenterProduct
    {
        public string GetProductName()
        {
            owner.Events.Add($"Name:{index}");
            owner.After(Effect.Name);
            return $"Product {index}";
        }

        public int GetProductState()
        {
            owner.Events.Add($"State:{index}");
            owner.After(Effect.State);
            return 0;
        }

        public int GetSignatureStatus()
        {
            owner.Events.Add($"Signature:{index}");
            owner.After(Effect.Signature);
            return 1;
        }

        public void Dispose() => owner.Events.Add($"DisposeProduct:{index}");
    }

    private sealed class FakeComClassActivator(Func<object> activate) : IComClassActivator
    {
        public object Activate(Guid classId)
        {
            Assert.Equal(ComSecurityCenterProductListFactory.ProductListClassId, classId);
            return activate();
        }
    }

    private sealed class CountingComReferenceReleaser(Action? onRelease = null)
        : IComReferenceReleaser
    {
        public List<object> Released { get; } = [];

        public void Release(object instance)
        {
            onRelease?.Invoke();
            Released.Add(instance);
        }
    }
}
