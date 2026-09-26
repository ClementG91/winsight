using WinSight.Core;

namespace WinSight.InputHooks;

/// <summary>Which input device stack a filter driver sits in.</summary>
public enum InputStack
{
    Keyboard,
    Mouse,
}

/// <summary>Where in the stack the filter sits relative to the class driver.</summary>
public enum FilterPosition
{
    /// <summary>Above the class driver: sees input on its way up to applications.</summary>
    Upper,

    /// <summary>Below the class driver, nearer the hardware.</summary>
    Lower,
}

/// <summary>
/// A kernel driver positioned to see every keystroke or mouse movement on this machine.
/// </summary>
/// <param name="Stack">Keyboard or mouse.</param>
/// <param name="Position">Upper or lower filter.</param>
/// <param name="Name">The service name as the class key lists it, e.g. <c>kbdclass</c>.</param>
/// <param name="ImagePath">The resolved driver file, or null when it could not be located.</param>
/// <param name="Signature">The Authenticode standing of that file.</param>
/// <param name="IsWindowsClassDriver">
/// True for the class driver Windows itself installs: its name, and an image of that name that
/// Windows signed inside System32. See <see cref="InputFilterTriage.IsWindowsClassDriver"/>.
/// </param>
/// <param name="ImageSource">
/// Whether the image came from the service's registered <c>ImagePath</c>, from the default Windows
/// uses when there is none, or could not be located at all.
/// </param>
/// <param name="RegisteredImagePath">The service's <c>ImagePath</c> as registered, or null when absent.</param>
public sealed record InputFilter(
    InputStack Stack,
    FilterPosition Position,
    string Name,
    string? ImagePath,
    SignatureVerdict Signature,
    bool IsWindowsClassDriver,
    DriverImageSource ImageSource = DriverImageSource.Registered,
    string? RegisteredImagePath = null);
