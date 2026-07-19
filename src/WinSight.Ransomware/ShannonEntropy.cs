namespace WinSight.Ransomware;

/// <summary>
/// Shannon entropy of a byte buffer, in bits per byte (0..8). Encrypted or compressed data sits
/// near 8; plain text and structured formats sit well below. A high value on a freshly written file
/// is one signal — never a verdict on its own — that a process may be encrypting user data.
/// </summary>
public static class ShannonEntropy
{
    /// <summary>The conventional "looks encrypted/compressed" threshold, in bits per byte.</summary>
    public const double EncryptedThreshold = 7.5;

    /// <summary>
    /// The minimum sample size for <see cref="LooksEncrypted"/>. Small buffers are noisy — a few
    /// random-looking bytes routinely hit high entropy — so a verdict needs a real sample.
    /// </summary>
    public const int MinimumSampleBytes = 256;

    /// <summary>Entropy of <paramref name="data"/> in bits/byte. Empty input is 0.</summary>
    public static double BitsPerByte(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
        {
            return 0.0;
        }

        Span<int> counts = stackalloc int[256];
        foreach (var b in data)
        {
            counts[b]++;
        }

        var entropy = 0.0;
        double length = data.Length;
        foreach (var count in counts)
        {
            if (count == 0)
            {
                continue;
            }
            var p = count / length;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }

    /// <summary>
    /// True when <paramref name="data"/> is large enough to judge and its entropy is at or above
    /// <see cref="EncryptedThreshold"/> — i.e. it looks encrypted or compressed.
    /// </summary>
    public static bool LooksEncrypted(ReadOnlySpan<byte> data) =>
        data.Length >= MinimumSampleBytes && BitsPerByte(data) >= EncryptedThreshold;
}
