using Aegis.Core.Yara;

namespace Aegis.Core.Signatures;

public sealed class SignatureSnapshot
{
    public required string Version { get; init; }
    public required string Source { get; init; }
    public required DateTimeOffset FetchedAt { get; init; }
    public required bool IsSeed { get; init; }
    public required string SourceDirectory { get; init; }
    public required IReadOnlyDictionary<string, HashSignature> Hashes { get; init; }
    public required IReadOnlyList<HashSignature> Entries { get; init; }
    public required DomainMatcher Domains { get; init; }
    public required IpMatcher IpAddresses { get; init; }
    public required YaraRuleSet Yara { get; init; }
    public required SpecialPathMatcher SpecialPaths { get; init; }
    public TrustedHashIndex TrustedHashes { get; init; } = TrustedHashIndex.Empty;
    public bool ExtendedRuleEngineIIEnabled { get; init; }
    public int ExtendedRulePackSkippedFiles { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }

    public int HashCount => Entries.Count;
    public int DomainCount => Domains.Count;
    public int IpCount => IpAddresses.Count;
    public int YaraRuleCount => Yara.RuleCount;
    public int SpecialPathCount => SpecialPaths.Count;
    public int TrustedHashCount => TrustedHashes.Count;

    private readonly object _indexLock = new();
    private IReadOnlyDictionary<string, HashSignature>? _md5Index;
    private IReadOnlyDictionary<string, HashSignature>? _sha1Index;

    public bool TryMatchHash(string sha256, out HashSignature? signature)
    {
        if (Hashes.TryGetValue(sha256, out var found))
        {
            signature = found;
            return true;
        }

        signature = null;
        return false;
    }

    public bool TryMatchHash(string sha256, string? md5, out HashSignature? signature)
    {
        return TryMatchHash(sha256, md5, null, out signature, out _);
    }

    public bool TryMatchHash(string sha256, string? md5, string? sha1, out HashSignature? signature,
        out string matchedAlgorithm)
    {
        if (TryMatchHash(sha256, out signature))
        {
            matchedAlgorithm = "SHA-256";
            return true;
        }

        if (!string.IsNullOrWhiteSpace(md5) && TryMatchMd5(md5, out signature) && signature is not null)
        {
            matchedAlgorithm = "MD5";
            return true;
        }

        if (!string.IsNullOrWhiteSpace(sha1) && TryMatchSha1(sha1, out signature) && signature is not null)
        {
            matchedAlgorithm = "SHA-1";
            return true;
        }

        matchedAlgorithm = string.Empty;
        return false;
    }

    public bool TryMatchMd5(string md5, out HashSignature? signature)
    {
        EnsureIndexes();
        return _md5Index!.TryGetValue(md5, out signature);
    }

    public bool TryMatchSha1(string sha1, out HashSignature? signature)
    {
        EnsureIndexes();
        return _sha1Index!.TryGetValue(sha1, out signature);
    }

    private void EnsureIndexes()
    {
        if (_md5Index is not null && _sha1Index is not null)
        {
            return;
        }

        lock (_indexLock)
        {
            if (_md5Index is null)
            {
                var md5Index = new Dictionary<string, HashSignature>(StringComparer.OrdinalIgnoreCase);
                foreach (var entry in Entries)
                {
                    if (!string.IsNullOrWhiteSpace(entry.Md5))
                    {
                        md5Index.TryAdd(entry.Md5, entry);
                    }
                }

                _md5Index = md5Index;
            }

            if (_sha1Index is null)
            {
                var sha1Index = new Dictionary<string, HashSignature>(StringComparer.OrdinalIgnoreCase);
                foreach (var entry in Entries)
                {
                    if (!string.IsNullOrWhiteSpace(entry.Sha1))
                    {
                        sha1Index.TryAdd(entry.Sha1, entry);
                    }
                }

                _sha1Index = sha1Index;
            }
        }
    }
}
