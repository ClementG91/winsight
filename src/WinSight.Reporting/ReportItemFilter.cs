namespace WinSight.Reporting;

/// <summary>A signature view filter over report items, the KnockKnock/TaskExplorer-style triage tokens.</summary>
public enum ReportFilterToken
{
    /// <summary>Items whose file carries no valid trusted signature (unsigned or untrusted).</summary>
    Unsigned,

    /// <summary>Items not proven to carry Microsoft's own trusted signature.</summary>
    NonMicrosoft,
}

/// <summary>
/// Filters a tool's report items by signature triage tokens (#unsigned, #nonMicrosoft), so a long list
/// can be cut to what matters. Pure and reusable: it reads only structured fields the adapters emit
/// (<c>signature</c> = the Authenticode state, <c>microsoftSigned</c> = Microsoft's own trusted
/// signature, established from the whole verdict).
/// </summary>
/// <remarks>
/// Tokens combine with AND: <c>#unsigned #nonMicrosoft</c> keeps items that are both. Severity is not a
/// token here: <c>--flagged</c> already filters on it, and two ways to express one filter would drift.
/// "Unsigned" deliberately excludes an <em>Unknown</em> verdict - a check that could not run is not the
/// same as a file that is unsigned, the same distinction the severity model draws elsewhere.
/// </remarks>
public static class ReportItemFilter
{
    /// <summary>Whether one item matches one token.</summary>
    public static bool Matches(ReportItem item, ReportFilterToken token)
    {
        ArgumentNullException.ThrowIfNull(item);
        return token switch
        {
            ReportFilterToken.Unsigned => IsUnsigned(item),
            ReportFilterToken.NonMicrosoft => IsNonMicrosoft(item),
            _ => false,
        };
    }

    /// <summary>The items matching every token (AND). An empty token set returns the items unchanged.</summary>
    public static IReadOnlyList<ReportItem> Apply(
        IReadOnlyList<ReportItem> items, IReadOnlyCollection<ReportFilterToken> tokens)
    {
        ArgumentNullException.ThrowIfNull(items);
        ArgumentNullException.ThrowIfNull(tokens);
        if (tokens.Count == 0)
        {
            return items;
        }
        return items.Where(item => tokens.All(token => Matches(item, token))).ToList();
    }

    private static bool IsUnsigned(ReportItem item) =>
        item.Fields.TryGetValue("signature", out var state) && state is not null
        && !state.Equals("SignedTrusted", StringComparison.OrdinalIgnoreCase)
        && !state.Equals("Unknown", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Anything not proven to be Microsoft's own signature. The proof is the <c>microsoftSigned</c>
    /// field, which the adapters set from the whole verdict: an exact Microsoft signing identity on a
    /// chain the machine trusts. Reading "Microsoft" out of the signer text instead hid a self-signed
    /// "CN=Microsoft ..." certificate - or one minted under a user-installed root - from exactly the
    /// view meant to surface it. An item that does not carry the field is kept, so a tool that never
    /// established the fact cannot have its rows filtered away by it.
    /// </summary>
    private static bool IsNonMicrosoft(ReportItem item) =>
        !(item.Fields.TryGetValue("microsoftSigned", out var microsoft)
          && string.Equals(microsoft, "true", StringComparison.Ordinal));
}
