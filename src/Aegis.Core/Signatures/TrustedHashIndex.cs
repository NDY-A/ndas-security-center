using System.Buffers.Binary;
using System.IO;

namespace Aegis.Core.Signatures;

/// <summary>
/// Sorted SHA-256 digest set. File layout: "NTH1" | u32 version(1) | u32 count | count × 32-byte digests (ascending).
/// </summary>
public sealed class TrustedHashIndex
{
    public const string RelativePath = "trusted/trusted-sha256.bin";
    private const int DigestSize = 32;
    private const uint Magic = 0x3148544E; // "NTH1" little-endian
    private const uint FormatVersion = 1;

    private readonly byte[] _digests;

    public static TrustedHashIndex Empty { get; } = new(Array.Empty<byte>());

    private TrustedHashIndex(byte[] digests)
    {
        _digests = digests;
        Count = digests.Length / DigestSize;
    }

    public int Count { get; }

    public static async Task<TrustedHashIndex> LoadAsync(string path, CancellationToken cancellationToken = default)
    {
        var bytes = await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
        return Parse(bytes);
    }

    public static TrustedHashIndex Parse(ReadOnlySpan<byte> fileBytes)
    {
        if (fileBytes.Length < 12 ||
            BinaryPrimitives.ReadUInt32LittleEndian(fileBytes) != Magic ||
            BinaryPrimitives.ReadUInt32LittleEndian(fileBytes[4..]) != FormatVersion)
        {
            throw new InvalidDataException("可信哈希库文件头无效。");
        }

        var count = BinaryPrimitives.ReadUInt32LittleEndian(fileBytes[8..]);
        if (fileBytes.Length != 12L + (long)count * DigestSize)
        {
            throw new InvalidDataException("可信哈希库文件长度与条目数不一致。");
        }

        var digests = fileBytes[12..].ToArray();
        for (var i = 1; i < count; i++)
        {
            if (digests.AsSpan((i - 1) * DigestSize, DigestSize)
                    .SequenceCompareTo(digests.AsSpan(i * DigestSize, DigestSize)) >= 0)
            {
                throw new InvalidDataException("可信哈希库未按 SHA-256 严格升序排列。");
            }
        }

        return count == 0 ? Empty : new TrustedHashIndex(digests);
    }

    public bool Contains(ReadOnlySpan<byte> digest)
    {
        if (digest.Length != DigestSize)
        {
            return false;
        }

        var low = 0;
        var high = Count - 1;
        while (low <= high)
        {
            var middle = low + ((high - low) >> 1);
            var comparison = digest.SequenceCompareTo(_digests.AsSpan(middle * DigestSize, DigestSize));
            if (comparison == 0)
            {
                return true;
            }

            if (comparison < 0)
            {
                high = middle - 1;
            }
            else
            {
                low = middle + 1;
            }
        }

        return false;
    }

    public bool ContainsHex(string sha256Hex)
    {
        if (sha256Hex.Length != DigestSize * 2)
        {
            return false;
        }

        Span<byte> digest = stackalloc byte[DigestSize];
        for (var i = 0; i < DigestSize; i++)
        {
            var high = HexValue(sha256Hex[i * 2]);
            var low = HexValue(sha256Hex[(i * 2) + 1]);
            if (high < 0 || low < 0)
            {
                return false;
            }

            digest[i] = (byte)((high << 4) | low);
        }

        return Contains(digest);
    }

    private static int HexValue(char character) => character switch
    {
        >= '0' and <= '9' => character - '0',
        >= 'a' and <= 'f' => character - 'a' + 10,
        >= 'A' and <= 'F' => character - 'A' + 10,
        _ => -1
    };
}
