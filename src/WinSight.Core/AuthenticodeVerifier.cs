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

    public SignatureVerdict Verify(string path) =>
        VerifyMany([path]).TryGetValue(path, out var v) ? v : _fallback.Verify(path);

    public IReadOnlyDictionary<string, SignatureVerdict> VerifyMany(IReadOnlyCollection<string> paths)
    {
        var results = new Dictionary<string, SignatureVerdict>(StringComparer.OrdinalIgnoreCase);

        var existing = paths
            .Where(p => !string.IsNullOrWhiteSpace(p) && File.Exists(p))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (existing.Count > 0)
        {
            try
            {
                ParseInto(RunPowerShell(existing), results);
            }
            catch (Exception ex) when (ex is Win32Exception or InvalidOperationException
                                         or IOException or JsonException)
            {
                // Fall through — missing paths get the managed fallback below.
            }
        }

        foreach (var path in paths)
        {
            if (!results.ContainsKey(path))
            {
                results[path] = _fallback.Verify(path);
            }
        }
        return results;
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
        // Paths are passed inside a PowerShell array literal, single-quoted with '
        // doubled. The script is fed on stdin (-Command -) to avoid arg-length limits.
        var literals = string.Join(",", paths.Select(p => "'" + p.Replace("'", "''") + "'"));
        var script =
            "$ErrorActionPreference='SilentlyContinue';" +
            "@(" + literals + ") | Get-AuthenticodeSignature | " +
            "Select-Object Path," +
            "@{n='Status';e={$_.Status.ToString()}}," +
            "@{n='Signer';e={if($_.SignerCertificate){$_.SignerCertificate.Subject}}} | " +
            "ConvertTo-Json -Depth 3";

        using var p = Process.Start(new ProcessStartInfo("powershell", "-NoProfile -NonInteractive -Command -")
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        }) ?? throw new InvalidOperationException("powershell did not start");

        p.StandardInput.WriteLine(script);
        p.StandardInput.Close();
        var output = p.StandardOutput.ReadToEnd();
        p.WaitForExit(30_000);
        return output;
    }

    private void ParseInto(string json, Dictionary<string, SignatureVerdict> results)
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

    private static void AddOne(JsonElement element, Dictionary<string, SignatureVerdict> results)
    {
        if (!element.TryGetProperty("Path", out var pathEl) || pathEl.GetString() is not { } path)
        {
            return;
        }
        var status = element.TryGetProperty("Status", out var s) ? s.GetString() : null;
        var signer = element.TryGetProperty("Signer", out var g) && g.ValueKind == JsonValueKind.String
            ? g.GetString()
            : null;
        results[path] = MapStatus(status, signer);
    }
}
