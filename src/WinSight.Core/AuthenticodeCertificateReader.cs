using System.Buffers.Binary;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace WinSight.Core;

/// <summary>
/// Extracts the Authenticode signer certificate from the exact PE bytes already acquired by the
/// caller. It never resolves a pathname, so signer metadata cannot be substituted after trust was
/// evaluated through the same file handle.
/// </summary>
internal static class AuthenticodeCertificateReader
{
    private const ushort WinCertificatePkcsSignedData = 0x0002;
    private const int WinCertificateHeaderSize = 8;
    private const int MaxCertificateTableBytes = 16 * 1024 * 1024;

    internal static X509Certificate2? ReadSigner(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (!stream.CanRead || !stream.CanSeek)
        {
            return null;
        }

        var originalPosition = stream.Position;
        try
        {
            stream.Position = 0;
            using var pe = new PEReader(stream, PEStreamOptions.LeaveOpen);
            var directory = pe.PEHeaders.PEHeader?.CertificateTableDirectory ?? default;
            var tableOffset = directory.RelativeVirtualAddress;
            var tableSize = directory.Size;
            if (tableOffset <= 0
                || tableSize < WinCertificateHeaderSize
                || tableSize > MaxCertificateTableBytes
                || (long)tableOffset + tableSize > stream.Length)
            {
                return null;
            }

            var consumed = 0;
            Span<byte> header = stackalloc byte[WinCertificateHeaderSize];
            while (tableSize - consumed >= WinCertificateHeaderSize)
            {
                stream.Position = tableOffset + consumed;
                stream.ReadExactly(header);
                var entryLength = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(header));
                var certificateType = BinaryPrimitives.ReadUInt16LittleEndian(header[6..]);
                if (entryLength < WinCertificateHeaderSize || entryLength > tableSize - consumed)
                {
                    return null;
                }

                if (certificateType == WinCertificatePkcsSignedData)
                {
                    var encoded = new byte[entryLength - WinCertificateHeaderSize];
                    stream.ReadExactly(encoded);
                    var cms = new SignedCms();
                    cms.Decode(encoded);
                    if (cms.SignerInfos.Count > 0
                        && cms.SignerInfos[0].Certificate is { } certificate)
                    {
                        return X509CertificateLoader.LoadCertificate(certificate.RawData);
                    }
                }

                var alignedLength = checked((entryLength + 7) & ~7);
                if (alignedLength <= 0 || alignedLength > tableSize - consumed)
                {
                    return null;
                }
                consumed += alignedLength;
            }
            return null;
        }
        catch (Exception ex) when (ex is BadImageFormatException
                                     or CryptographicException
                                     or IOException
                                     or ArgumentException
                                     or OverflowException)
        {
            return null;
        }
        finally
        {
            stream.Position = originalPosition;
        }
    }
}
