using WinSight.Core;

namespace WinSight.Drivers;

/// <summary>What kind of kernel-mode code the registration describes.</summary>
public enum DriverKind
{
    /// <summary>A device driver (service <c>Type</c> 1).</summary>
    Kernel,

    /// <summary>A file-system or file-system filter driver (service <c>Type</c> 2).</summary>
    FileSystem,
}

/// <summary>
/// When Windows loads the driver. This is how far it reaches, not merely when: a
/// boot-start driver is running before anything that could inspect it.
/// </summary>
public enum DriverStart
{
    /// <summary>Loaded by the boot loader, ahead of the kernel. (<c>Start</c> 0)</summary>
    Boot,

    /// <summary>Loaded during kernel initialisation. (<c>Start</c> 1)</summary>
    System,

    /// <summary>Loaded by the service control manager at startup. (<c>Start</c> 2)</summary>
    Automatic,

    /// <summary>Loaded on demand, so it may or may not be resident right now. (<c>Start</c> 3)</summary>
    Manual,

    /// <summary>Registered, but Windows will not load it. (<c>Start</c> 4)</summary>
    Disabled,

    /// <summary>The registration carries no usable <c>Start</c> value.</summary>
    Unknown,
}

/// <summary>
/// A kernel-mode driver registered on this machine, with the Authenticode standing of
/// the image it points at.
/// </summary>
/// <param name="Name">The service name, which is what Windows loads the driver by.</param>
/// <param name="Kind">Device driver or file-system driver.</param>
/// <param name="Start">When Windows loads it.</param>
/// <param name="ImagePath">The resolved driver file, or null when it is not on disk.</param>
/// <param name="ExpectedImagePath">
/// Where the registration says the image should be. Kept separate from
/// <paramref name="ImagePath"/> so an orphaned registration can name the file that is
/// missing instead of collapsing into "no image".
/// </param>
/// <param name="Signature">The Authenticode standing of that file.</param>
/// <param name="IsWindowsProvided">True when Windows itself ships the image.</param>
public sealed record KernelDriver(
    string Name,
    DriverKind Kind,
    DriverStart Start,
    string? ImagePath,
    string? ExpectedImagePath,
    SignatureVerdict Signature,
    bool IsWindowsProvided);
