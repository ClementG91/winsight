using WinSight.Core;

namespace WinSight.InputHooks;

/// <summary>How much attention a filter on the input path deserves.</summary>
public enum InputFilterConcern
{
    /// <summary>The class driver Windows installs itself. Expected on every machine.</summary>
    Expected,

    /// <summary>A third-party driver in the input path, properly signed. Worth knowing about.</summary>
    ThirdParty,

    /// <summary>A driver in the input path that is unsigned or whose chain did not validate.</summary>
    Untrusted,

    /// <summary>The class key names a filter whose driver file could not be found.</summary>
    Missing,
}

/// <summary>
/// Decides what a filter on the keyboard or mouse stack means. Pure, so the judgement can be
/// argued with in tests rather than only observed on a live machine.
/// </summary>
/// <remarks>
/// <b>Why this is the Windows answer to ReiKey.</b> macOS lets you enumerate event taps outright;
/// Windows has no documented way to list <c>SetWindowsHookEx</c> hooks. What Windows *does* expose,
/// and what a serious keylogger actually installs, is a filter driver on the keyboard or mouse
/// device stack: it sits in the kernel and sees every keystroke before any application does. Those
/// are plainly readable from the class keys, which makes this both the highest-signal and the most
/// honestly detectable form of input interception on this platform.
///
/// <b>Why there is no vendor allowlist.</b> Touchpad and remote-desktop drivers legitimately sit
/// here, and it is tempting to hard-code their names as benign. That would be security theatre:
/// nothing stops a keylogger calling itself <c>SynTP</c>. Only the class driver Windows itself
/// installs is treated as expected; everything else is reported with its signature standing, and
/// the operator decides. Listing a real touchpad driver costs a moment's reading. Hiding a
/// keylogger because it borrowed a familiar name costs everything.
/// </remarks>
public static class InputFilterTriage
{
    /// <summary>The class drivers Windows itself provides, keyed by stack.</summary>
    public static string ClassDriverFor(InputStack stack) =>
        stack == InputStack.Keyboard ? "kbdclass" : "mouclass";

    /// <summary>Whether <paramref name="name"/> is the Windows-provided class driver for its stack.</summary>
    public static bool IsWindowsClassDriver(InputStack stack, string? name) =>
        !string.IsNullOrWhiteSpace(name)
        && name.Trim().Equals(ClassDriverFor(stack), StringComparison.OrdinalIgnoreCase);

    /// <summary>What the filter means for the operator.</summary>
    public static InputFilterConcern Concern(InputFilter filter)
    {
        ArgumentNullException.ThrowIfNull(filter);

        if (filter.IsWindowsClassDriver)
        {
            return InputFilterConcern.Expected;
        }
        return filter.Signature.State switch
        {
            SignatureState.Missing => InputFilterConcern.Missing,
            SignatureState.Unsigned or SignatureState.SignedUntrusted => InputFilterConcern.Untrusted,
            // Unknown means verification could not run, which is not evidence of anything. Treating
            // it as suspicious would cry wolf on files WinSight simply failed to check.
            _ => InputFilterConcern.ThirdParty,
        };
    }

    /// <summary>
    /// Whether a finding should be surfaced by the flagged-only filter.
    /// </summary>
    /// <remarks>
    /// Any third-party driver in the input path is worth surfacing, not just an unsigned one. A
    /// signed kernel keylogger is still a kernel keylogger, and on most machines this list is one
    /// or two lines long — so showing them costs the operator almost nothing and hiding them
    /// would defeat the point of the check.
    /// </remarks>
    public static bool IsNotable(InputFilterConcern concern) => concern != InputFilterConcern.Expected;
}
