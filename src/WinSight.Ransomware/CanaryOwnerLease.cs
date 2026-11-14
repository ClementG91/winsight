using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using WinSight.Core;

namespace WinSight.Ransomware;

internal sealed record CanaryOwnerProof(int Slot, string Nonce, CanaryFileIdentity Identity);

/// <summary>
/// A cooperative owner in all Windows sessions. The exclusive marker holds no ancestor handles.
/// Its absence is never a death proof: only acquiring and verifying the recorded object is one.
/// </summary>
internal sealed class CanaryOwnerLease : IDisposable
{
    private readonly AutomaticFileAccess.LocalPathLease _lease;
    internal CanaryOwnerProof Proof { get; }

    private CanaryOwnerLease(AutomaticFileAccess.LocalPathLease lease, CanaryOwnerProof proof)
    {
        _lease = lease;
        Proof = proof;
    }

    internal bool Matches(CanaryOwnerProof proof) => Proof == proof
        && CanaryFile.Identity(_lease) == proof.Identity && _lease.IsCurrent();

    internal void DeleteUnreferenced() { if (Matches(Proof)) { _ = _lease.TryDelete(); } }
    public void Dispose() => _lease.Dispose();

    internal sealed class Store
    {
        private const int Slots = 128;
        private const int MaximumMarkerBytes = 4096;
        private readonly string _parent;
        private readonly string _root;
        private readonly string _key;

        internal Store(string manifest)
        {
            _parent = Path.GetDirectoryName(manifest) ?? throw new IOException("Missing canary state parent.");
            _key = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(manifest.ToUpperInvariant())));
            _root = Path.Combine(_parent, ".canary-owners-" + _key);
        }

        internal CanaryOwnerLease Create()
        {
            if (!VerifyRoot(create: true)) { throw new IOException("The canary owner store is unavailable."); }
            var nonce = Guid.NewGuid().ToString("N");
            var bytes = Marker(nonce);
            for (var slot = 0; slot < Slots; slot++)
            {
                var lease = AutomaticFileAccess.TryCreateNewFileLease(MarkerPath(slot), bytes, false);
                if (lease is null) { continue; } // Never evict an occupied or inaccessible slot.
                var identity = CanaryFile.Identity(lease);
                if (identity is not null)
                {
                    // This write-only share0 handle cannot OpenRead. Known created bytes and the
                    // identity captured here remain the owner's authority until it closes.
                    return new CanaryOwnerLease(lease, new CanaryOwnerProof(slot, nonce, identity));
                }
                _ = lease.TryDelete();
                lease.Dispose();
                throw new IOException("The canary owner marker has no supported full identity.");
            }
            throw new IOException("No safe canary owner slot is available; manual recovery may be required.");
        }

        internal CanaryOwnerLease? TryAcquireDead(CanaryOwnerProof proof)
        {
            if (!IsValid(proof)) { return null; }
            try
            {
                if (!VerifyRoot(create: false)) { return null; }
                var lease = AutomaticFileAccess.TryAcquireForDelete(MarkerPath(proof.Slot));
                if (lease is null) { return null; } // Missing, denied and sharing conflicts prove nothing.
                try
                {
                    if (CanaryFile.Identity(lease) != proof.Identity
                        || !ReadBounded(lease, MaximumMarkerBytes).AsSpan().SequenceEqual(Marker(proof.Nonce)))
                    {
                        return null;
                    }
                    var result = new CanaryOwnerLease(lease, proof);
                    lease = null;
                    return result;
                }
                finally { lease?.Dispose(); }
            }
            catch (Exception ex) when (IsExpectedFailure(ex)) { return null; }
        }

        internal static bool IsValid(CanaryOwnerProof? proof) => proof is { Slot: >= 0 and < Slots, Identity: not null }
            && Guid.TryParseExact(proof.Nonce, "N", out var nonce)
            && nonce.ToString("N").Equals(proof.Nonce, StringComparison.Ordinal)
            && proof.Identity.CreationTime > 0
            && (proof.Identity.FileIdLow != 0 || proof.Identity.FileIdHigh != 0);

        private string MarkerPath(int slot) => Path.Combine(_root, $"o{slot:D3}.owner");
        private byte[] Marker(string nonce) => Encoding.ASCII.GetBytes($"v1\n{_key}\n{nonce}\n");

        private bool VerifyRoot(bool create)
        {
            using var token = WindowsIdentity.GetCurrent();
            var user = token.User;
            if (user is null || !DirectoryIsPrivate(_parent, user, requireProtected: false)) { return false; }
            var created = false;
            using (var existing = AutomaticFileAccess.TryAcquire(_root, out var missing))
            {
                if (existing is null)
                {
                    if (!missing || !create) { return false; }
                    // Cooperative provisioning under the manifest gate and an already private
                    // parent. EnsureDirectory is NOT an atomic createdNew result. Hostile same-SID
                    // or admin races are outside this contract; never repair an observed old root.
                    if (!AutomaticFileAccess.TryEnsureDirectory(_root)
                        || !AutomaticFileAccess.TryApplyProtectedDirectoryDacl(_root, PrivateDacl(user)))
                    {
                        return false;
                    }
                    created = true;
                }
                else if (!existing.IsDirectory || !existing.IsCurrent()) { return false; }
            }
            if (!DirectoryIsPrivate(_root, user, requireProtected: true)) { return false; }
            var binding = Path.Combine(_root, ".binding");
            var bytes = Encoding.ASCII.GetBytes($"v1\n{_key}\n");
            if (created && !AutomaticFileAccess.TryCreateNewFile(binding, bytes, false)) { return false; }
            using var lease = AutomaticFileAccess.TryAcquire(binding);
            return lease is { IsDirectory: false }
                && ReadBounded(lease, MaximumMarkerBytes).AsSpan().SequenceEqual(bytes);
        }

        private static byte[] PrivateDacl(SecurityIdentifier user)
        {
            var security = new DirectorySecurity();
            security.SetAccessRuleProtection(true, false);
            foreach (var sid in Trusted(user))
            {
                security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None, AccessControlType.Allow));
            }
            return security.GetSecurityDescriptorBinaryForm(); // DACL only; do not change TOKEN_OWNER.
        }

        private static SecurityIdentifier[] Trusted(SecurityIdentifier user) => [.. new[]
        {
            user,
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
        }.Distinct()];

        private static bool DirectoryIsPrivate(string path, SecurityIdentifier user, bool requireProtected)
        {
            var bytes = AutomaticFileAccess.TryReadDirectorySecurityDescriptor(path);
            if (bytes is null) { return false; }
            var descriptor = new RawSecurityDescriptor(bytes, 0);
            var trusted = Trusted(user);
            if (descriptor.Owner is null || !trusted.Contains(descriptor.Owner)
                || !descriptor.ControlFlags.HasFlag(ControlFlags.DiscretionaryAclPresent)
                || (requireProtected && !descriptor.ControlFlags.HasFlag(ControlFlags.DiscretionaryAclProtected))
                || descriptor.DiscretionaryAcl is not { Count: > 0 } dacl
                || dacl.Revision != GenericAcl.AclRevision)
            {
                return false;
            }
            const int mutations = 0x000D0156; // write/append/EA/attributes/delete-child/delete/DACL/owner
            foreach (GenericAce item in dacl)
            {
                if (item is not CommonAce { IsCallback: false, AceQualifier: AceQualifier.AccessAllowed } ace
                    || (ace.AccessMask & unchecked((int)0xF0000000)) != 0
                    || (ace.AceFlags & ~(AceFlags.ObjectInherit | AceFlags.ContainerInherit
                        | AceFlags.NoPropagateInherit | AceFlags.InheritOnly | AceFlags.Inherited)) != 0)
                {
                    return false;
                }
                // Inherit-only grants matter BEFORE root creation: a hostile write handle obtained
                // through an inherited grant would survive a later DACL change.
                if (!trusted.Contains(ace.SecurityIdentifier) && (ace.AccessMask & mutations) != 0) { return false; }
            }
            return true;
        }
    }

    internal static byte[] ReadBounded(AutomaticFileAccess.LocalPathLease lease, int maximum)
    {
        if (lease.IsDirectory || !lease.DataIsLocal) { throw new IOException("Unsupported canary metadata file."); }
        using var stream = lease.OpenRead();
        if (stream.Length > maximum) { throw new IOException("Canary metadata exceeds its physical byte budget."); }
        var buffer = new byte[maximum + 1];
        var count = 0;
        while (count < buffer.Length)
        {
            var read = stream.Read(buffer.AsSpan(count));
            if (read == 0) { break; }
            count += read;
        }
        if (count > maximum || !lease.IsCurrent()) { throw new IOException("Canary metadata changed or exceeds its byte budget."); }
        return buffer.AsSpan(0, count).ToArray();
    }

    internal static bool IsExpectedFailure(Exception ex) => ex is IOException or UnauthorizedAccessException
        or System.Security.SecurityException or ArgumentException;
}
