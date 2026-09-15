namespace WinSight.Reporting;

/// <summary>A signature view filter over report items, the KnockKnock/TaskExplorer-style triage tokens.</summary>
public enum ReportFilterToken
{
    /// <summary>Items whose file carries no valid trusted signature (unsigned or untrusted).</summary>
    Unsigned,

    /// <summary>Items not signed by Microsoft (a different or absent signer).</summary>
    NonMicrosoft,
}

/// <summary>
/// Filters a tool's report items by signature triage tokens (#unsigned, #nonMicrosoft), so a long list
/// can be cut to what matters. Pure and reusable: it reads only the structured fields every adapter
/// already emits (<c>signature</c> = the Authenticode state, <c>signer</c> = the certificate subject).
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

    private static bool IsNonMicrosoft(ReportItem item) =>
        !(item.Fields.TryGetValue("signer", out var signer) && signer is not null
          && signer.Contains("Microsoft", StringComparison.OrdinalIgnoreCase));
}
