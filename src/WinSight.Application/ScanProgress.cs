namespace WinSight.Application;

/// <summary>Progress reported between independent overview scanners.</summary>
public sealed record ScanProgress(int Completed, int Total, string Command)
{
    public int Percent => Total <= 0
        ? 0
        : Math.Clamp((int)Math.Round(Completed * 100d / Total), 0, 100);
}
