namespace WinSight.Ransomware;

/// <summary>Which Windows Security Center category a registered product was registered under.</summary>
public enum SecurityProductKind
{
    AntiVirus,
    AntiSpyware,
    Firewall,
}

/// <summary>Whether a registered product reports itself as actively scanning.</summary>
public enum SecurityProductState
{
    /// <summary>The product state could not be decoded. Never treated as either on or off.</summary>
    Unknown,
    Enabled,
    Disabled,
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
/// The undecoded <c>productState</c> word, kept so a reader is never lied to about what Windows
/// actually said — particularly when this reader could not decode it.
/// </param>
public sealed record SecurityProduct(
    SecurityProductKind Kind,
    string DisplayName,
    SecurityProductState State,
    SecurityProductSignatures Signatures,
    int RawProductState)
{
    /// <summary>
    /// Whether this is Microsoft's own antivirus, matched on the registered display name.
    /// </summary>
    /// <remarks>
    /// Name matching is a heuristic and is treated as one: it is used only to relate this inventory to
    /// the Controlled Folder Access finding, never to decide whether the machine is protected. A
    /// mismatch costs a cross-reference, not a wrong verdict.
    /// </remarks>
    public bool IsMicrosoftDefender =>
        DisplayName.Contains("Windows Defender", StringComparison.OrdinalIgnoreCase)
        || DisplayName.Contains("Microsoft Defender", StringComparison.OrdinalIgnoreCase);
}

/// <summary>Whether Windows Security Center could be enumerated at all.</summary>
public enum SecurityCenterReading
{
    /// <summary>The namespace answered. Zero products is a valid answer and means none are registered.</summary>
    Available,

    /// <summary>
    /// The namespace could not be read — absent (Windows Server does not ship it), the service is
    /// stopped, or the query failed. Explicitly not the same as "no antivirus is installed".
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
    /// The registered antivirus products that report themselves as actively scanning. An undecodable
    /// state is deliberately excluded: "we could not tell" must not be counted as protection.
    /// </summary>
    public IReadOnlyList<SecurityProduct> ActiveAntiVirusProducts =>
        [.. AntiVirusProducts.Where(product => product.State == SecurityProductState.Enabled)];

    /// <summary>
    /// Whether an antivirus other than Microsoft's is actively scanning — the ordinary reason Defender
    /// steps aside, and therefore the reason Controlled Folder Access is not protecting.
    /// </summary>
    public bool HasActiveNonMicrosoftAntiVirus =>
        ActiveAntiVirusProducts.Any(product => !product.IsMicrosoftDefender);
}

/// <summary>What the observed inventory establishes about this machine's antivirus protection.</summary>
public enum AntiVirusConcern
{
    /// <summary>At least one antivirus is actively scanning and reports current definitions.</summary>
    Protected,

    /// <summary>An antivirus is actively scanning but reports its definitions as out of date.</summary>
    SignaturesOutOfDate,

    /// <summary>Products are registered, but none of them reports itself as actively scanning.</summary>
    NoActiveAntiVirus,

    /// <summary>Security Center answered and no antivirus is registered at all.</summary>
    NoAntiVirusRegistered,

    /// <summary>Security Center could not be read, so nothing is established either way.</summary>
    Unavailable,
}

/// <summary>
/// Pure interpretation of what Windows Security Center reports. Split from the WMI reader so the
/// decoding is tested exhaustively without depending on whatever happens to be installed on the
/// machine running the tests.
/// </summary>
public static class SecurityProductTriage
{
    /// <summary>
    /// Decodes the <c>productState</c> word into a scanning state and a definition state.
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
        if (active.Count == 0)
        {
            return AntiVirusConcern.NoActiveAntiVirus;
        }

        // Out-of-date definitions on every active product is a real gap; one current product is enough
        // to establish protection, so this only fires when none of them reports current definitions.
        return active.Any(product => product.Signatures == SecurityProductSignatures.UpToDate)
            ? AntiVirusConcern.Protected
            : AntiVirusConcern.SignaturesOutOfDate;
    }

    /// <summary>Whether a concern must stay visible in a flagged-only report.</summary>
    public static bool IsNotable(AntiVirusConcern concern) => concern != AntiVirusConcern.Protected;
}
