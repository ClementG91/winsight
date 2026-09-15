namespace WinSight.InputHooks;

/// <summary>One keyboard/mouse class filter, identified by where it sits and its service name.</summary>
public sealed record InputFilterRef(InputStack Stack, FilterPosition Position, string Name);

/// <summary>Whether a filter appeared or disappeared between two observations.</summary>
public enum InputFilterChangeKind
{
    Added,
    Removed,
}

/// <summary>A single change to the set of installed input-stack filters.</summary>
public sealed record InputFilterAlert(InputFilterChangeKind Kind, InputFilterRef Filter);

/// <summary>
/// The pure diff behind the real-time input-filter alert (ReiKey parity): what changed between two
/// snapshots of the keyboard/mouse class filters. A newly added filter is the signal that matters -
/// a keylogger installing a tap - but removals are reported too, so the operator sees the whole change.
/// </summary>
public static class InputFilterDiff
{
    /// <summary>The filters added and removed going from <paramref name="before"/> to <paramref name="after"/>.</summary>
    public static IReadOnlyList<InputFilterAlert> Between(
        IReadOnlyCollection<InputFilterRef> before, IReadOnlyCollection<InputFilterRef> after)
    {
        ArgumentNullException.ThrowIfNull(before);
        ArgumentNullException.ThrowIfNull(after);
        var beforeSet = new HashSet<InputFilterRef>(before);
        var afterSet = new HashSet<InputFilterRef>(after);

        var alerts = new List<InputFilterAlert>();
        foreach (var added in afterSet.Where(f => !beforeSet.Contains(f)))
        {
            alerts.Add(new InputFilterAlert(InputFilterChangeKind.Added, added));
        }
        foreach (var removed in beforeSet.Where(f => !afterSet.Contains(f)))
        {
            alerts.Add(new InputFilterAlert(InputFilterChangeKind.Removed, removed));
        }
        return alerts;
    }
}
