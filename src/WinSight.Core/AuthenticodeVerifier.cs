using System.ComponentModel;
using System.Diagnostics;
using System.Text.Json;

namespace WinSight.Core;

/// <summary>
/// Catalog-aware Authenticode verification via a single batched
/// <c>Get-AuthenticodeSignature</c> PowerShell call. Unlike the managed
/// <see cref="SignatureVerifier"/>, this correctly resolves CATALOG-signed binaries
/// (most of Windows) and detects tampering (a signed-then-modified file reports
/// HashMismatch), which is what a security tool needs. One process per batch keeps it
/// practical; a native WTGetSignatureInfo implementation is the future optimization.
///
/// Robustness: anything the batch cannot resolve (PowerShell missing, a path dropped
/// from the output, a parse error) falls back to the managed verifier, so a verdict
/// is never worse than the managed baseline and never throws.
/// </summary>
public sealed class AuthenticodeVerifier : ISignatureVerifier
{
    private readonly SignatureVerifier _fallback = new();

    // The script is passed via -EncodedCommand (base64 UTF-16LE), which caps the
    // command line at ~32K chars. Paths vary wildly in length (System32 vs long
    // WindowsApps paths), so chunks are sized by cumulative script length, not count:
    // keep each chunk's raw script under this budget so its base64 stays well under
    // the OS limit. Smaller chunks also finish faster (each Get-AuthenticodeSignature
    // call ~15-20ms/file), so a chunk is far less likely to hit the timeout under load.
    private const int ScriptCharBudget = 3500;

    public SignatureVerdict Verify(string path) =>
        VerifyMany([path]).TryGetValue(path, out var v) ? v : _fallback.Verify(path);

    public IReadOnlyDictionary<string, SignatureVerdict> VerifyMany(IReadOnlyCollection<string> paths)
    {
        // PowerShell verdicts are keyed by NORMALISED full path, because the Path it
        // echoes may differ in form from the input string. Inputs are matched back the
        // same way, so casing/relative differences never cause a spurious fallback.
        var byFullPath = new Dictionary<string, SignatureVerdict>(StringComparer.OrdinalIgnoreCase);

        var existing = paths
            .Where(p => !string.IsNullOrWhiteSpace(p) && File.Exists(p))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        foreach (var chunk in Chunk(existing))
        {
            VerifyChunkWithRetry(chunk, byFullPath);
        }

        var results = new Dictionary<string, SignatureVerdict>(StringComparer.OrdinalIgnoreCase);
        foreach (var path in paths)
        {
            results[path] = TryFull(path) is { } full && byFullPath.TryGetValue(full, out var v)
                ? v
                : _fallback.Verify(path);
        }
        return results;
    }

    // Runs one chunk, retrying until every path in it has a catalog verdict. A
    // PowerShell spawn can transiently fail or return truncated output under load (a
    // slow cold start hitting the timeout, a partial pipe) — without a retry, the
    // uncovered paths silently fall to the catalog-blind managed verifier and read as
    // "Unsigned", so a scan run twice could show 4 flagged then 130. Get-Authenticode-
    // Signature returns exactly one object per input path, so ANY missing path means
    // an incomplete run and is retried with a fresh spawn (verdicts are keyed by full
    // path, so an already-resolved path is never destructively re-fetched).
    private void VerifyChunkWithRetry(IReadOnlyList<string> chunk, Dictionary<string, SignatureVerdict> byFullPath)
    {
        const int maxAttempts = 3;
        var expected = chunk.Select(p => TryFull(p) ?? p).ToList();

        for (var attempt = 1; attempt < maxAttempts; attempt++)
        {
            try
            {
                ParseInto(RunPowerShell(chunk), byFullPath);
            }
            catch (Exception ex) when (ex is Win32Exception or InvalidOperationException
                                         or IOException or JsonException)
            {
                // Fall through to the retry.
            }

            if (expected.All(byFullPath.ContainsKey))
            {
                return; // fully covered — no need to respawn
            }
        }

        // Last attempt: take whatever it yields; any still-missing path uses the
        // per-path managed fallback in VerifyMany.
        try
        {
            ParseInto(RunPowerShell(chunk), byFullPath);
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException
                                     or IOException or JsonException)
        {
            // The managed fallback in VerifyMany covers this chunk's paths.
        }
    }

    // Groups paths into chunks whose combined single-quoted length stays under the
    // script budget, so the -EncodedCommand argument never overflows the OS limit.
    private static IEnumerable<IReadOnlyList<string>> Chunk(IReadOnlyList<string> paths)
    {
        var current = new List<string>();
        var length = 0;
        foreach (var path in paths)
        {
            var cost = path.Length + 4; // quotes + comma + doubling headroom
            if (current.Count > 0 && length + cost > ScriptCharBudget)
            {
                yield return current;
                current = new List<string>();
                length = 0;
            }
            current.Add(path);
            length += cost;
        }
        if (current.Count > 0)
        {
            yield return current;
        }
    }

    private static string? TryFull(string path)
    {
        try
        {
            return File.Exists(path) ? Path.GetFullPath(path) : null;
        }
        catch (Exception ex) when (ex is ArgumentException or PathTooLongException or NotSupportedException)
        {
            return null;
        }
    }

    /// <summary>
    /// Maps a PowerShell SignatureStatus (+ signer subject) to a WinSight verdict.
    /// Pure and unit-tested; the process/parse plumbing around it is not.
    /// </summary>
    public static SignatureVerdict MapStatus(string? status, string? signer) => status switch
    {
        "Valid" => new SignatureVerdict(SignatureState.SignedTrusted, signer),
        "NotSigned" => SignatureVerdict.Unsigned,
        "HashMismatch" => new SignatureVerdict(SignatureState.SignedUntrusted, signer), // tampered
        "NotTrusted" => new SignatureVerdict(SignatureState.SignedUntrusted, signer),
        null or "" => SignatureVerdict.Unsigned,
        // UnknownError / NotSupportedFileFormat / Incompatible / ...: if a signer was
        // extracted treat as signed-but-untrusted, else unsigned. Never fabricate trust.
        _ => signer is null ? SignatureVerdict.Unsigned : new SignatureVerdict(SignatureState.SignedUntrusted, signer),
    };

    private static string RunPowerShell(IReadOnlyList<string> paths)
    {
        // Paths go inside a PowerShell array literal, single-quoted with ' doubled.
        var literals = string.Join(",", paths.Select(p => "'" + p.Replace("'", "''") + "'"));
        var script =
            "$ErrorActionPreference='SilentlyContinue';" +
            // Silence the progress stream too — otherwise PowerShell writes CLIXML
            // progress records to stderr that leak onto the user's terminal mid-scan.
            "$ProgressPreference='SilentlyContinue';" +
            "@(" + literals + ") | Get-AuthenticodeSignature | " +
            "Select-Object Path," +
            "@{n='Status';e={$_.Status.ToString()}}," +
            "@{n='Signer';e={if($_.SignerCertificate){$_.SignerCertificate.Subject}}} | " +
            "ConvertTo-Json -Depth 3";

        // The script is passed as a base64 (UTF-16LE) -EncodedCommand argument rather
        // than piped on stdin: `powershell -Command -` reading a script from a
        // redirected stdin proved unreliable from a non-interactive child process
        // (it silently produced NO output, so every catalog-signed binary read as
        // Unsigned). -EncodedCommand also sidesteps all quoting/escaping issues.
        // Callers chunk by script length so the encoded argument stays under the OS
        // command-line limit.
        var encoded = Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes(script));

        // Absolute System32 path: a security tool must never resolve a child binary
        // through the search path (binary-planting / PATH-hijack resistance).
        var exe = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            "WindowsPowerShell", "v1.0", "powershell.exe");

        using var p = Process.Start(new ProcessStartInfo(exe, $"-NoProfile -NonInteractive -EncodedCommand {encoded}")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        }) ?? throw new InvalidOperationException("powershell did not start");

        // Read asynchronously so a hung PowerShell can't block ReadToEnd forever;
        // on timeout the process tree is killed (no zombie), which also completes
        // the read by closing the pipe. stderr is drained (not just redirected) so it
        // neither leaks to the user's terminal nor deadlocks on a full pipe buffer.
        var output = p.StandardOutput.ReadToEndAsync();
        var drainErr = p.StandardError.ReadToEndAsync();
        if (!p.WaitForExit(30_000))
        {
            TryKill(p);
        }
        _ = drainErr.GetAwaiter().GetResult();
        return output.GetAwaiter().GetResult();
    }

    private static void TryKill(Process p)
    {
        try
        {
            p.Kill(entireProcessTree: true);
            p.WaitForExit(5_000);
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException or NotSupportedException)
        {
            // Already exited or cannot be killed — the stream read completes either way.
        }
    }

    private static void ParseInto(string json, Dictionary<string, SignatureVerdict> results)
    {
        json = json.Trim();
        if (json.Length == 0)
        {
            return;
        }
        using var doc = JsonDocument.Parse(json);
        // Get-AuthenticodeSignature returns one object for a single file, an array for many.
        if (doc.RootElement.ValueKind == JsonValueKind.Array)
        {
            foreach (var element in doc.RootElement.EnumerateArray())
            {
                AddOne(element, results);
            }
        }
        else if (doc.RootElement.ValueKind == JsonValueKind.Object)
        {
            AddOne(doc.RootElement, results);
        }
    }

    private static void AddOne(JsonElement element, Dictionary<string, SignatureVerdict> byFullPath)
    {
        if (!element.TryGetProperty("Path", out var pathEl) || pathEl.GetString() is not { } path)
        {
            return;
        }
        var status = element.TryGetProperty("Status", out var s) ? s.GetString() : null;
        var signer = element.TryGetProperty("Signer", out var g) && g.ValueKind == JsonValueKind.String
            ? g.GetString()
            : null;
        byFullPath[TryFull(path) ?? path] = MapStatus(status, signer);
    }
}
