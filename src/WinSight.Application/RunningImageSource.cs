using System.Diagnostics;

using WinSight.Response;

namespace WinSight.Application;

/// <summary>
/// The production <see cref="IRunningImageSource"/>: enumerates running processes and reads each
/// image path with the same minimum-rights inspector the response layer uses, so it works for the
/// current user's own processes without elevation and simply skips those it cannot open.
/// </summary>
public sealed class RunningImageSource : IRunningImageSource
{
    private readonly IProcessInspector _inspector;

    public RunningImageSource(IProcessInspector? inspector = null) =>
        _inspector = inspector ?? new Win32ProcessInspector();

    public IReadOnlyList<RunningImage> All()
    {
        var images = new List<RunningImage>();
        foreach (var process in Process.GetProcesses())
        {
            try
            {
                var identity = _inspector.Capture(process.Id);
                if (identity is not null && !string.IsNullOrEmpty(identity.ImagePath))
                {
                    images.Add(new RunningImage(process.Id, identity.ImagePath));
                }
            }
            catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
            {
                // The process exited between enumeration and read; skip it.
            }
            finally
            {
                process.Dispose();
            }
        }
        return images;
    }
}
