namespace WinSight.Ransomware;

/// <summary>Which Windows Security Center category a registered product was registered under.</summary>
public enum SecurityProductKind
{
    AntiVirus,
    AntiSpyware,
    Firewall,
}

/// <summary>The activity state reported by Windows Security Center.</summary>
public enum SecurityProductState
{
    /// <summary>The product state is not understood. Never treated as either on or off.</summary>
    Unknown,

    /// <summary>Windows Security Center reports <c>WSC_SECURITY_PRODUCT_STATE_ON</c>.</summary>
    Enabled,

    /// <summary>Windows Security Center reports <c>WSC_SECURITY_PRODUCT_STATE_OFF</c>.</summary>
    Disabled,

    /// <summary>Windows Security Center reports <c>WSC_SECURITY_PRODUCT_STATE_SNOOZED</c>.</summary>
    Snoozed,

    /// <summary>Windows Security Center reports <c>WSC_SECURITY_PRODUCT_STATE_EXPIRED</c>.</summary>
    Expired,
}

/// <summary>Whether a registered product reports its definitions as current.</summary>
public enum SecurityProductSignatures
{
    Unknown,
    UpToDate,
    OutOfDate,
}

/// <summary>One product registered with Windows Security Center.</summary>
/// <param name="Kind">The category it registered under.</param>
/// <param name="DisplayName">The vendor's own name for it, as registered.</param>
/// <param name="State">Whether it reports itself as actively scanning.</param>
/// <param name="Signatures">Whether it reports its definitions as current.</param>
/// <param name="RawProductState">
/// The legacy undecoded WMI <c>productState</c> word. Production COM inventory leaves this at the
/// historical sentinel; consumers must use <see cref="RawActivityState"/> for the documented COM enum.
/// </param>
public sealed record SecurityProduct(
    SecurityProductKind Kind,
    string DisplayName,
    SecurityProductState State,
    SecurityProductSignatures Signatures,
    int RawProductState)
{
    /// <summary>
    /// The raw documented <c>WSC_SECURITY_PRODUCT_STATE</c> value. Production COM inventory sets
    /// this property and leaves <see cref="RawProductState"/> at its legacy WMI sentinel.
    /// </summary>
    public int? RawActivityState { get; init; }

    /// <summary>
    /// The raw documented <c>WSC_SECURITY_SIGNATURE_STATUS</c> value. This is nullable only for
    /// compatibility with inventories constructed before signature evidence was carried separately.
    /// </summary>
    public int? RawSignatureStatus { get; init; }

    /// <summary>
    /// Whether this is Microsoft's own antivirus, matched on the registered display name.
    /// </summary>
    /// <remarks>
    /// Name matching is a heuristic and is treated as one: it is used only to relate this inventory to
    /// the Controlled Folder Access finding, never to decide whether the machine is protected. A
    /// mismatch costs a cross-reference, not a wrong verdict.
    ///
    /// <b>The string it reads is localized.</b> The WMI inventory this replaced returned the invariant
    /// English name; <c>IWscProduct::get_ProductName</c> returns the machine's display language — a
    /// French host reports "Antivirus Microsoft Defender". Microsoft keeps the brand tokens Latin and
    /// adjacent across the shipping locales, which is why matching on the adjacent pair still works.
    ///
    /// <b>The adjacency is load-bearing, not incidental.</b> Matching "Defender" and "Microsoft" or
    /// "Windows" as independent tokens looks like a locale-robustness improvement and is a regression:
    /// it makes "Bitdefender Antivirus for Windows" read as Microsoft's own product, on the one path
    /// that decides whether the operator is told a third-party antivirus is protecting them. The test
    /// matrix carries that exact name so the idea fails a test rather than a user.
    /// </remarks>
    public bool IsMicrosoftDefender =>
        DisplayName.Contains("Windows Defender", StringComparison.OrdinalIgnoreCase)
        || DisplayName.Contains("Microsoft Defender", StringComparison.OrdinalIgnoreCase);
}

/// <summary>Whether Windows Security Center could be enumerated at all.</summary>
public enum SecurityCenterReading
{
    /// <summary>The provider answered. Zero products is a valid answer and means none are registered.</summary>
    Available,

    /// <summary>
    /// The provider could not be read — unsupported (including Windows Server), unavailable, or the
    /// COM call failed. Explicitly not the same as "no antivirus is installed".
    /// </summary>
    Unavailable,
}

/// <summary>What Windows Security Center reports is protecting this machine.</summary>
public sealed record SecurityProductInventory(
    SecurityCenterReading Reading,
    IReadOnlyList<SecurityProduct> Products)
{
    public static SecurityProductInventory Unavailable { get; } = new(SecurityCenterReading.Unavailable, []);

    public IReadOnlyList<SecurityProduct> AntiVirusProducts =>
        [.. Products.Where(product => product.Kind == SecurityProductKind.AntiVirus)];

    /// <summary>
    /// The registered antivirus products for which Windows Security Center reports <c>On</c>. An
    /// unknown state is deliberately excluded: "we could not tell" must not be counted as protection.
    /// </summary>
    public IReadOnlyList<SecurityProduct> ActiveAntiVirusProducts =>
        [.. AntiVirusProducts.Where(product => product.State == SecurityProductState.Enabled)];

    /// <summary>
    /// Whether Windows Security Center reports <c>On</c> for an antivirus other than Microsoft's —
    /// the ordinary reason Defender steps aside and Controlled Folder Access is not protecting.
    /// </summary>
    public bool HasActiveNonMicrosoftAntiVirus =>
        ActiveAntiVirusProducts.Any(product => !product.IsMicrosoftDefender);
}

/// <summary>What the observed inventory establishes about this machine's antivirus protection.</summary>
public enum AntiVirusConcern
{
    /// <summary>At least one antivirus is actively scanning and reports current definitions.</summary>
    Protected = 0,

    /// <summary>An antivirus is actively scanning but reports its definitions as out of date.</summary>
    SignaturesOutOfDate = 1,

    /// <summary>Products are registered, but none of them reports itself as actively scanning.</summary>
    NoActiveAntiVirus = 2,

    /// <summary>Security Center answered and no antivirus is registered at all.</summary>
    NoAntiVirusRegistered = 3,

    /// <summary>Security Center could not be read, so nothing is established either way.</summary>
    Unavailable = 4,

    /// <summary>An antivirus reports On, but signature currency could not be established.</summary>
    SignatureStatusUnknown = 5,

    /// <summary>Products are registered, but at least one activity state is not understood.</summary>
    ActivityStatusUnknown = 6,
}

/// <summary>
/// Pure interpretation of what Windows Security Center reports. Split from the COM reader so the
/// mapping is tested exhaustively without depending on whatever happens to be installed on the
/// machine running the tests.
/// </summary>
public static class SecurityProductTriage
{
    /// <summary>Maps the documented Windows Security Center product state without guessing.</summary>
    public static SecurityProductState MapProductState(int rawState) => rawState switch
    {
        0 => SecurityProductState.Enabled,
        1 => SecurityProductState.Disabled,
        2 => SecurityProductState.Snoozed,
        3 => SecurityProductState.Expired,
        _ => SecurityProductState.Unknown,
    };

    /// <summary>Maps the documented Windows Security Center signature status without guessing.</summary>
    public static SecurityProductSignatures MapSignatureStatus(int rawStatus) => rawStatus switch
    {
        0 => SecurityProductSignatures.OutOfDate,
        1 => SecurityProductSignatures.UpToDate,
        _ => SecurityProductSignatures.Unknown,
    };

    /// <summary>
    /// Decodes the legacy WMI <c>productState</c> word. Production acquisition does not use this
    /// undocumented encoding; the method remains only for source compatibility.
    /// </summary>
    /// <remarks>
    /// <b>This encoding is not documented by Microsoft.</b> It is the widely-used community decoding,
    /// and it was verified against a live machine before being relied on here: Windows Defender,
    /// active with current definitions, reports <c>0x061100</c> — scanner byte <c>0x11</c>, signature
    /// byte <c>0x00</c>.
    ///
    /// Because the encoding is undocumented, anything outside the values known to this reader decodes
    /// to <see cref="SecurityProductState.Unknown"/> rather than being rounded to the nearest guess. A
    /// security tool that guesses "probably enabled" from a byte it does not recognise is inventing
    /// protection, which is the one failure this whole file exists to avoid.
    /// </remarks>
    public static (SecurityProductState State, SecurityProductSignatures Signatures) Decode(int productState)
    {
        var scanner = (productState >> 8) & 0xFF;
        var signature = productState & 0xFF;
        return (
            scanner switch
            {
                0x10 or 0x11 => SecurityProductState.Enabled,
                0x00 or 0x01 => SecurityProductState.Disabled,
                _ => SecurityProductState.Unknown,
            },
            signature switch
            {
                0x00 => SecurityProductSignatures.UpToDate,
                0x10 => SecurityProductSignatures.OutOfDate,
                _ => SecurityProductSignatures.Unknown,
            });
    }

    /// <summary>Determines what the inventory establishes, without guessing past what was read.</summary>
    public static AntiVirusConcern Concern(SecurityProductInventory inventory)
    {
        ArgumentNullException.ThrowIfNull(inventory);

        if (inventory.Reading == SecurityCenterReading.Unavailable)
        {
            return AntiVirusConcern.Unavailable;
        }
        if (inventory.AntiVirusProducts.Count == 0)
        {
            return AntiVirusConcern.NoAntiVirusRegistered;
        }

        var active = inventory.ActiveAntiVirusProducts;
        if (active.Any(product => product.Signatures == SecurityProductSignatures.UpToDate))
        {
            return AntiVirusConcern.Protected;
        }
        if (inventory.AntiVirusProducts.Any(product =>
                product.State is not SecurityProductState.Enabled
                    and not SecurityProductState.Disabled
                    and not SecurityProductState.Snoozed
                    and not SecurityProductState.Expired))
        {
            return AntiVirusConcern.ActivityStatusUnknown;
        }
        if (active.Any(product =>
                product.Signatures is not SecurityProductSignatures.UpToDate
                    and not SecurityProductSignatures.OutOfDate))
        {
            return AntiVirusConcern.SignatureStatusUnknown;
        }
        return active.Count > 0
            ? AntiVirusConcern.SignaturesOutOfDate
            : AntiVirusConcern.NoActiveAntiVirus;
    }

    /// <summary>Whether a concern must stay visible in a flagged-only report.</summary>
    public static bool IsNotable(AntiVirusConcern concern) => concern != AntiVirusConcern.Protected;
}
