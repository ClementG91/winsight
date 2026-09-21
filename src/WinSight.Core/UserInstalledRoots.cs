using System.Collections.Frozen;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace WinSight.Core;

/// <summary>
/// Distinguishes roots trusted only by the current user from roots trusted machine-wide.
/// Each verification batch reads a fresh, immutable snapshot. A long-running dashboard must
/// notice root-store changes even when the signed file itself has not changed.
/// </summary>
public static class UserInstalledRoots
{
    /// <summary>SHA-1 thumbprints of roots trusted for this user but not machine-wide.</summary>
    public static IReadOnlySet<string> Thumbprints => ReadSnapshot().UserThumbprints;

    /// <summary>True when the current snapshot contains a user-installed trusted root.</summary>
    public static bool Any => Thumbprints.Count > 0;

    /// <summary>Whether the file's Authenticode chain reaches a user-installed root.</summary>
    public static bool TrustsAUserInstalledRoot(string path) =>
        TrustAnchorFor(path, ReadSnapshot()) == SignatureTrustAnchor.UserInstalledRoot;

    internal sealed record RootSnapshot(
        IReadOnlySet<string> MachineThumbprints,
        IReadOnlySet<string> UserThumbprints,
        bool IsComplete,
        string Version);

    internal static RootSnapshot ReadSnapshot() => ReadSnapshot(ReadThumbprints);

    // Injection is scoped to one call: tests never mutate a global provider or the real stores.
    internal static RootSnapshot ReadSnapshot(Func<StoreLocation, IReadOnlySet<string>?> read)
    {
        var machine = read(StoreLocation.LocalMachine);
        var user = read(StoreLocation.CurrentUser);
        var machineSet = (machine ?? FrozenSet<string>.Empty).ToFrozenSet(StringComparer.OrdinalIgnoreCase);
        var userSet = (user ?? FrozenSet<string>.Empty).ToFrozenSet(StringComparer.OrdinalIgnoreCase);
        var complete = machine is not null && user is not null;
        var userOnly = complete
            ? userSet.Except(machineSet, StringComparer.OrdinalIgnoreCase).ToFrozenSet(StringComparer.OrdinalIgnoreCase)
            : Array.Empty<string>().ToFrozenSet(StringComparer.OrdinalIgnoreCase);

        // Include BOTH stores and failures. Removing a machine root also invalidates signature
        // verdicts, even if the difference between the stores remains empty. Stable ordering
        // prevents needless invalidation when the store enumerates the same roots differently.
        var identity = $"machine:{machine is not null}\n"
            + string.Join('\n', machineSet.Select(value => value.ToUpperInvariant()).Order(StringComparer.Ordinal))
            + $"\nuser:{user is not null}\n"
            + string.Join('\n', userSet.Select(value => value.ToUpperInvariant()).Order(StringComparer.Ordinal));
        var version = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(identity)));
        return new RootSnapshot(machineSet, userOnly, complete, version);
    }

    internal static SignatureTrustAnchor TrustAnchorFor(
        string path, RootSnapshot snapshot, Func<string, string?>? readRoot = null)
    {
        if (!snapshot.IsComplete || string.IsNullOrWhiteSpace(path))
        {
            return SignatureTrustAnchor.Unspecified;
        }

        var root = (readRoot ?? ReadChainRoot)(path);
        if (root is null)
        {
            return SignatureTrustAnchor.Unspecified;
        }
        if (snapshot.UserThumbprints.Contains(root))
        {
            return SignatureTrustAnchor.UserInstalledRoot;
        }
        // A parse failure or a root installed after the snapshot must not implicitly claim a
        // machine anchor. Only an observed root in the machine snapshot establishes that fact.
        return snapshot.MachineThumbprints.Contains(root)
            ? SignatureTrustAnchor.MachineRoot
            : SignatureTrustAnchor.Unspecified;
    }

    /// <summary>
    /// Classifies the trust anchor from a signer certificate extracted from already acquired bytes,
    /// avoiding a second path resolution after WinVerifyTrust evaluated the file handle.
    /// </summary>
    internal static SignatureTrustAnchor TrustAnchorFor(
        X509Certificate2 signer, RootSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(signer);
        if (!snapshot.IsComplete || ReadChainRoot(signer) is not { } root)
        {
            return SignatureTrustAnchor.Unspecified;
        }
        if (snapshot.UserThumbprints.Contains(root))
        {
            return SignatureTrustAnchor.UserInstalledRoot;
        }
        return snapshot.MachineThumbprints.Contains(root)
            ? SignatureTrustAnchor.MachineRoot
            : SignatureTrustAnchor.Unspecified;
    }

    private static string? ReadChainRoot(string path)
    {
        try
        {
#pragma warning disable SYSLIB0057 // CreateFromSignedFile is the Authenticode leaf reader.
            using var leaf = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
            return ReadChainRoot(leaf);
        }
        catch (Exception ex) when (ex is CryptographicException
                                     or IOException
                                     or UnauthorizedAccessException
                                     or System.Security.SecurityException)
        {
            return null;
        }
    }

    private static string? ReadChainRoot(X509Certificate2 leaf)
    {
        try
        {
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.DisableCertificateDownloads = true;
            // WinVerifyTrust establishes validity. Here only the root identity is needed,
            // including for a timestamped signature whose leaf has since expired.
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid
                | X509VerificationFlags.IgnoreCtlNotTimeValid
                | X509VerificationFlags.IgnoreCtlSignerRevocationUnknown
                | X509VerificationFlags.IgnoreEndRevocationUnknown
                | X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown
                | X509VerificationFlags.IgnoreRootRevocationUnknown;
            _ = chain.Build(leaf);
            return chain.ChainElements.Count > 0
                ? chain.ChainElements[^1].Certificate.Thumbprint
                : null;
        }
        catch (Exception ex) when (ex is CryptographicException
                                     or UnauthorizedAccessException
                                     or System.Security.SecurityException)
        {
            return null;
        }
    }

    private static IReadOnlySet<string>? ReadThumbprints(StoreLocation location)
    {
        var thumbprints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var store = new X509Store(StoreName.Root, location);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            foreach (var certificate in store.Certificates)
            {
                using (certificate)
                {
                    if (certificate.Thumbprint is { Length: > 0 } thumbprint)
                    {
                        thumbprints.Add(thumbprint);
                    }
                }
            }
            return thumbprints;
        }
        catch (Exception ex) when (ex is CryptographicException
                                     or UnauthorizedAccessException
                                     or System.Security.SecurityException)
        {
            // An unreadable store is different from a successfully read empty store. In
            // particular it cannot establish that every visible user root is user-installed.
            return null;
        }
    }
}
