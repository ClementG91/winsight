namespace WinSight.Persistence;

/// <summary>
/// Why an autostart command line is worth a second look even though its executable is fine.
/// </summary>
public enum InterpreterAbuse
{
    /// <summary>Nothing in the command line contradicts the executable's verdict.</summary>
    None,

    /// <summary>A system interpreter is pointed at a URL or a network share.</summary>
    RemotePayload,

    /// <summary>A system interpreter is pointed at a file in a per-user or temporary location.</summary>
    PerUserPayload,

    /// <summary>The command line carries an encoded, inline or downloaded script body.</summary>
    EncodedCommand,

    /// <summary>The command line uses a scriptlet/COM registration trick to run code.</summary>
    ScriptletCom,
}

/// <summary>
/// Reads the <i>command line</i> of an autostart entry, for the case the signature model cannot
/// reach: a Windows-signed interpreter told to run somebody else's code.
/// </summary>
/// <remarks>
/// <b>Why this exists.</b> Every other persistence verdict is a fact about a file — is it there, is
/// it signed, does the signature stand. That model is blind by construction to the dominant modern
/// Windows technique, because the file it inspects is genuinely Microsoft's and genuinely signed.
/// A Run key holding
/// <c>rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";eval(…)</c> resolves to
/// <c>C:\Windows\System32\rundll32.exe</c>, verifies as <c>SignatureValid</c>, and is reported as
/// routine. The payload is in the arguments, and nothing was reading them.
///
/// <b>The gate is the interpreter, not the pattern.</b> Flagging every autostart entry whose
/// arguments mention a user path would bury the operator: ordinary software passes profile paths on
/// its command line all day. What is not ordinary is <i>a program whose whole purpose is to execute
/// what it is handed</i> being handed something from a place anyone can write, from the network, or
/// encoded. Both halves must hold, which is what keeps this quiet.
///
/// <b>Measured before it was written.</b> On the desktop this was developed against: 4 351 autostart
/// items, of which <b>15</b> resolve to one of the interpreters below — 13 <c>rundll32.exe</c>, one
/// <c>cmd.exe</c>, one <c>explorer.exe</c> — and <b>none</b> of the 15 carries a payload matching any
/// rule here. Zero findings is the intended shape on a healthy machine, and it is exactly why the
/// tests below make the rule fire against synthetic entries: a silent detector and a broken one look
/// identical from outside.
///
/// <b>It performs no I/O and reads no registry.</b> This runs inside
/// <see cref="AutostartEntry.IsSuspicious"/>, which is evaluated repeatedly while a report is built,
/// so it stays a pure function over two strings — it can neither block a scan nor throw into one.
/// The consequence is deliberate: the per-user claim is made about the <i>shape</i> of the path, so
/// this says "runs from a per-user location", never "that directory is writable", which would
/// require asking the filesystem.
///
/// <b>What it does not catch, stated rather than implied.</b> Hidden-window and no-profile switches
/// (<c>-w hidden</c>, <c>-nop</c>) are left out: legitimate deployment tooling uses them constantly,
/// and a rule that fires on them trades this check's precision for nothing. An interpreter handed a
/// payload that is neither remote, nor per-user, nor encoded — a planted DLL under
/// <c>Program Files</c>, say — is invisible here and belongs to the writability analysis the
/// <c>hijack</c> scanner already performs.
/// </remarks>
public static class InterpreterAbuseTriage
{
    /// <summary>
    /// Programs whose purpose is to execute what they are given. A signature on one of these says
    /// the interpreter is authentic and says nothing at all about what it was told to run.
    /// </summary>
    /// <remarks>
    /// <c>explorer.exe</c> is deliberately absent even though it appeared in the measurement: the
    /// default <c>Winlogon\Shell</c> is <c>explorer.exe</c>, and the classic abuse of that value —
    /// appending a second command — is already split into its own entry by
    /// <c>WinlogonEnumerator.SplitCommands</c> and judged on its own executable.
    /// </remarks>
    private static readonly HashSet<string> Interpreters = new(StringComparer.OrdinalIgnoreCase)
    {
        "rundll32.exe", "mshta.exe", "regsvr32.exe", "wscript.exe", "cscript.exe",
        "powershell.exe", "pwsh.exe", "cmd.exe", "msbuild.exe", "installutil.exe",
        "regasm.exe", "regsvcs.exe", "wmic.exe", "certutil.exe", "bitsadmin.exe",
        "curl.exe", "msiexec.exe", "forfiles.exe", "pcalua.exe", "odbcconf.exe",
        "mavinject.exe", "scriptrunner.exe", "cmstp.exe", "ieexec.exe",
        "presentationhost.exe", "hh.exe", "xwizard.exe", "conhost.exe", "schtasks.exe",
    };

    /// <summary>Script bodies and download primitives carried inline on a command line.</summary>
    private static readonly string[] EncodedMarkers =
    [
        "-enc", "-encodedcommand", "/enc", "frombase64string", "invoke-expression",
        "iex(", "iex ", "downloadstring", "downloadfile", "invoke-webrequest",
        "javascript:", "vbscript:", "runhtmlapplication",
    ];

    /// <summary>The scriptlet and COM-registration routes to running code from a signed host.</summary>
    private static readonly string[] ScriptletMarkers = ["scrobj.dll", ".sct", "/i:http", "-i:http"];

    /// <summary>
    /// Per-user and temporary roots, in both their literal and environment-variable spellings.
    /// </summary>
    /// <remarks>
    /// <c>\temp\</c> also matches the machine-wide <c>C:\Windows\Temp</c>, which is not a user
    /// profile. It is kept because an interpreter launched from an autostart entry and pointed at a
    /// scratch directory is worth the same look either way — and the wording in
    /// <see cref="Describe"/> says "per-user or temporary location" rather than claiming a profile,
    /// so the sentence stays true of every path that reaches it.
    /// </remarks>
    private static readonly string[] PerUserMarkers =
    [
        @"\appdata\", "%appdata%", "%localappdata%", @"\users\",
        "%temp%", "%tmp%", @"\temp\", "%userprofile%", "%public%",
    ];

    /// <summary>Remote sources a payload may be fetched from.</summary>
    private static readonly string[] RemoteMarkers = ["http://", "https://", "ftp://", "\\\\"];

    private static readonly char[] PathSeparators = ['\\', '/'];

    /// <summary>
    /// Classifies one entry's command line. Returns <see cref="InterpreterAbuse.None"/> unless the
    /// entry both runs a known interpreter and hands it a payload worth naming.
    /// </summary>
    public static InterpreterAbuse Classify(AutostartEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        return Classify(ImageName(entry), entry.Command);
    }

    /// <summary>
    /// The rule itself, over the two values it actually depends on, so it can be tested without
    /// constructing a resolved entry and a signature verdict for every case.
    /// </summary>
    /// <param name="imageName">File name of the resolved executable, e.g. <c>rundll32.exe</c>.</param>
    /// <param name="commandLine">The entry's raw command line, arguments included.</param>
    public static InterpreterAbuse Classify(string? imageName, string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(imageName)
            || string.IsNullOrWhiteSpace(commandLine)
            || !Interpreters.Contains(imageName))
        {
            return InterpreterAbuse.None;
        }

        // Every comparison below is case-insensitive against the original string rather than
        // against a lower-cased copy. A report holds ~4 300 autostart items and each is classified
        // several times while it is built, so lower-casing here would allocate thousands of strings
        // to answer a question that needs none.
        //
        // The tests are ordered by how specific the evidence is, so a command line matching several
        // is named by the most concrete one rather than by whichever rule ran first.
        if (ContainsRemoteSource(commandLine))
        {
            return InterpreterAbuse.RemotePayload;
        }
        if (ContainsAny(commandLine, ScriptletMarkers))
        {
            return InterpreterAbuse.ScriptletCom;
        }
        if (ContainsAny(commandLine, EncodedMarkers))
        {
            return InterpreterAbuse.EncodedCommand;
        }
        if (ContainsAny(commandLine, PerUserMarkers))
        {
            return InterpreterAbuse.PerUserPayload;
        }
        return InterpreterAbuse.None;
    }

    /// <summary>
    /// True for a URL or a UNC share, and false for the two local forms that also begin with two
    /// backslashes. <c>\\?\</c> and <c>\\.\</c> are Win32 escapes for long and device paths; reading
    /// either as "fetched from another machine" would be a confident false accusation.
    /// </summary>
    private static bool ContainsRemoteSource(string command)
    {
        foreach (var marker in RemoteMarkers)
        {
            var index = command.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
            while (index >= 0)
            {
                if (marker != "\\\\" || !IsLocalDevicePrefix(command, index))
                {
                    return true;
                }
                index = command.IndexOf(marker, index + 1, StringComparison.OrdinalIgnoreCase);
            }
        }
        return false;
    }

    private static bool IsLocalDevicePrefix(string command, int index)
    {
        var next = index + 2;
        return next < command.Length && (command[next] == '?' || command[next] == '.');
    }

    private static bool ContainsAny(string command, string[] markers)
    {
        foreach (var marker in markers)
        {
            if (command.Contains(marker, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }

    /// <summary>
    /// The executable's file name, preferring what was resolved on disk over what was written.
    /// </summary>
    /// <remarks>
    /// Falls back to the command's leading token so an entry whose image could not be resolved is
    /// still classified. The fallback is a plain split rather than
    /// <see cref="CommandLine.ExtractExecutable"/>, which probes the filesystem: this method is on
    /// the <see cref="AutostartEntry.IsSuspicious"/> path and must not perform I/O.
    ///
    /// <b>The extension is supplied when the command line omits it.</b> <c>CreateProcess</c>
    /// appends <c>.exe</c> to an extension-less token, so <c>powershell -enc …</c> runs exactly
    /// what <c>powershell.exe -enc …</c> runs. The table below is keyed by file name including the
    /// extension — the form the loader ends up with — so a raw token had to be normalised the same
    /// way or the rule missed every entry that simply left <c>.exe</c> off. That was a four-
    /// character bypass of this whole check.
    /// </remarks>
    private static string? ImageName(AutostartEntry entry)
    {
        var path = entry.ImagePath ?? entry.ExpectedImagePath;
        if (!string.IsNullOrWhiteSpace(path))
        {
            return NormalizeExtension(SafeFileName(path));
        }
        var command = entry.Command?.Trim();
        if (string.IsNullOrEmpty(command))
        {
            return null;
        }
        var token = command.StartsWith('"')
            ? command[1..(command.IndexOf('"', 1) is var end && end > 0 ? end : command.Length)]
            : command.Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? command;
        return NormalizeExtension(SafeFileName(token));
    }

    /// <summary>
    /// Appends the extension <c>CreateProcess</c> would, so an extension-less token is matched
    /// against the interpreter table in the form the loader actually resolves.
    /// </summary>
    /// <remarks>
    /// Only a name carrying no extension at all is touched. A name that already ends in something
    /// — <c>msv1_0.dll</c>, <c>x.sys</c> — is left exactly as written, so a module that is not an
    /// executable is never renamed into one.
    /// </remarks>
    internal static string? NormalizeExtension(string? name)
    {
        if (string.IsNullOrEmpty(name))
        {
            return name;
        }
        // A trailing dot is a legal-but-degenerate spelling; treat it as no extension rather than
        // producing "name..exe".
        var trimmed = name.TrimEnd('.');
        return trimmed.Length != 0 && trimmed.LastIndexOf('.') < 0 ? trimmed + ".exe" : name;
    }

    /// <summary>
    /// <see cref="Path.GetFileName(string)"/> without its exceptions. The value may come from a
    /// registry key an attacker controls, so an invalid path yields no name rather than ending a scan.
    /// </summary>
    private static string? SafeFileName(string path)
    {
        var separator = path.LastIndexOfAny(PathSeparators);
        var name = separator >= 0 ? path[(separator + 1)..] : path;
        return name.Length == 0 ? null : name;
    }

    /// <summary>Plain-language reason, or null when there is nothing to say.</summary>
    public static string? Describe(InterpreterAbuse abuse) => abuse switch
    {
        InterpreterAbuse.RemotePayload =>
            "a signed Windows interpreter is pointed at a remote location, so what actually runs is not on this machine and is not covered by the signature above",
        InterpreterAbuse.ScriptletCom =>
            "a signed Windows interpreter is used to register a scriptlet, a documented way to run code through a trusted host",
        InterpreterAbuse.EncodedCommand =>
            "a signed Windows interpreter carries an encoded or inline script body, so the signature verifies the interpreter and says nothing about the script",
        InterpreterAbuse.PerUserPayload =>
            "a signed Windows interpreter is pointed at a file in a per-user or temporary location, where the signature above covers the interpreter and not the payload",
        _ => null,
    };
}
