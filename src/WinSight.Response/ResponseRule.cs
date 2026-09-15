namespace WinSight.Response;

/// <summary>What an operator decided about a class of detection, so WinSight need not ask again.</summary>
public enum RuleDecision
{
    /// <summary>Do not alert on, or act against, matching detections.</summary>
    Allow,

    /// <summary>Act automatically where the monitor supports it (currently network only).</summary>
    Block,
}

/// <summary>How long a rule stays in effect.</summary>
public enum RuleDuration
{
    /// <summary>Applies to the current decision only; not stored.</summary>
    Once,

    /// <summary>Until the machine restarts.</summary>
    UntilReboot,

    /// <summary>Until the identified process exits (network rules).</summary>
    UntilProcessExit,

    /// <summary>Until a fixed expiry time.</summary>
    Timed,

    /// <summary>Until the operator removes it.</summary>
    Permanent,
}

/// <summary>The surface a rule belongs to, so one store can serve every monitor without ambiguity.</summary>
public enum RuleScopeKind
{
    Persistence,
    Ransomware,
    CameraMicrophone,
}

/// <summary>
/// A stored operator decision. Matching is by the fields present: a rule with only a signer publisher
/// matches any image from that publisher; one with an image hash matches exactly that binary.
/// </summary>
/// <param name="Id">Stable id, used to remove the rule and to correlate it in the action journal.</param>
/// <param name="Scope">The monitor this rule governs.</param>
/// <param name="Decision">Allow or block.</param>
/// <param name="Duration">How long it lasts.</param>
/// <param name="CreatedUtc">When it was created.</param>
/// <param name="ExpiresUtc">The expiry for a <see cref="RuleDuration.Timed"/> rule, else null.</param>
/// <param name="Item">An opaque item key (e.g. a persistence identity), or null.</param>
/// <param name="ImagePath">The image path a rule is keyed to, or null.</param>
/// <param name="ImageSha256">The image hash a rule is keyed to, or null.</param>
/// <param name="Publisher">The certificate subject a rule is keyed to, or null.</param>
public sealed record ResponseRule(
    Guid Id,
    RuleScopeKind Scope,
    RuleDecision Decision,
    RuleDuration Duration,
    DateTimeOffset CreatedUtc,
    DateTimeOffset? ExpiresUtc = null,
    string? Item = null,
    string? ImagePath = null,
    string? ImageSha256 = null,
    string? Publisher = null)
{
    /// <summary>Whether the rule has any key at all; a rule matching everything is rejected on save.</summary>
    public bool HasKey =>
        !string.IsNullOrEmpty(Item) || !string.IsNullOrEmpty(ImagePath)
        || !string.IsNullOrEmpty(ImageSha256) || !string.IsNullOrEmpty(Publisher);

    /// <summary>Whether this rule is still in force at <paramref name="nowUtc"/>.</summary>
    public bool IsActive(DateTimeOffset nowUtc) =>
        Duration != RuleDuration.Timed || (ExpiresUtc is { } expiry && expiry > nowUtc);

    /// <summary>
    /// Whether this rule covers a candidate described by these keys. Every non-null key on the rule
    /// must match; the candidate may carry more keys than the rule constrains.
    /// </summary>
    public bool Matches(
        RuleScopeKind scope, string? item, string? imagePath, string? imageSha256, string? publisher)
    {
        if (scope != Scope)
        {
            return false;
        }
        if (!Constrains(Item, item) || !Constrains(ImagePath, imagePath)
            || !Constrains(ImageSha256, imageSha256) || !Constrains(Publisher, publisher))
        {
            return false;
        }
        return HasKey;
    }

    private static bool Constrains(string? ruleKey, string? candidate) =>
        string.IsNullOrEmpty(ruleKey)
        || string.Equals(ruleKey, candidate, StringComparison.OrdinalIgnoreCase);
}
