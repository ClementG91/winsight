using WinSight.Attribution;

namespace WinSight.Application;

/// <summary>
/// Why a detection carries no author, in the words an operator reads.
/// </summary>
/// <remarks>
/// <b>The problem this closes.</b> A journalled detection with no author is ambiguous in three
/// different ways, and they call for three different responses: attribution was never running
/// (nothing to fix but the setting), it could not run because the process is unelevated (restart as
/// Administrator and you will get names), or it was running and simply saw nothing that explains this
/// write (the answer really is "unknown"). Collapsing them into a silent absence is how a monitor
/// gets trusted when it should not be — someone reads a nameless alert and concludes attribution is
/// working and had nothing to say.
///
/// <see cref="AttributionHealth"/> was built to draw exactly these distinctions and its own summary
/// says so. Nothing read it: every consumer took the author or the absence of one, and the health
/// record went to no operator, no journal and no MCP client. This is that missing consumer.
///
/// <b>Why the note rides on the alert instead of a separate health endpoint.</b> The journal already
/// crosses the process boundary — the dashboard writes it, the MCP server reads it — so the caveat
/// reaches an LLM or a returning operator with no new file, no new tool and, more importantly, no
/// staleness problem: a health file written by a dashboard that has since exited would describe a
/// world that no longer exists, while a note written beside the detection describes the state at the
/// moment that detection fired, which is the only state that can explain it.
///
/// Each line repeats the caveat rather than stating it once at the top. A journal line is read out of
/// context, often one line at a time, and a self-contained record is worth more than a terse one.
/// </remarks>
public static class AttributionNote
{
    /// <summary>
    /// The parenthetical explaining an absent author, or null when the caller knows nothing about
    /// attribution's state and should therefore claim nothing about it.
    /// </summary>
    /// <param name="health">
    /// The watcher's own account of itself, or null when no attribution host exists at all — which
    /// is itself an answer, not missing information.
    /// </param>
    public static string WhyNoAuthor(AttributionHealth? health) => health switch
    {
        // No host was ever created. On an unelevated machine this is the normal state, and the
        // dashboard deliberately does not open a privileged session just to have it refused.
        null => "attribution not running",
        // A session was attempted and the kernel refused it.
        { Refused: true } => "attribution needs Administrator",
        // Started, then stopped or faulted. Distinct from never having started: something went wrong.
        { Running: false } => "attribution stopped",
        // The honest "unknown": watching, and nothing observed accounts for this target. The writer
        // may have acted before the session opened, or through a path the filter does not record.
        _ => "attribution watching, no matching write seen",
    };

    /// <summary>
    /// Appends the author to a detection line, or an explained absence when there is none.
    /// </summary>
    /// <remarks>
    /// Shared by the persistence and ransomware presenters so the sentence an operator reads is
    /// identical whichever monitor fired. Two hand-written versions of this drifted apart once
    /// already, and a security record whose wording depends on which code path reached it is a
    /// record you have to read twice.
    /// </remarks>
    public static string Describe(string line, WriteObservation? author, AttributionHealth? health)
    {
        if (author is null)
        {
            return $"{line} — author unknown ({WhyNoAuthor(health)})";
        }
        // A bare-name launch is named, never dressed up as a located file: "powershell.exe" and
        // "C:\Windows\...\powershell.exe" mean different things to someone deciding what to do next,
        // and living-off-the-land attacks are exactly the case that produces the former.
        var by = author.PathIsExact
            ? $"{author.ExecutablePath} (pid {author.ProcessId})"
            : $"{author.ExecutablePath} (pid {author.ProcessId}, full path unknown)";
        return $"{line} — written by {by}";
    }
}
