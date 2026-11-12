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
    public required DomainMatcher Domains { get; init; }
    public required IpMatcher IpAddresses { get; init; }
    public required YaraRuleSet Yara { get; init; }
    public required SpecialPathMatcher SpecialPaths { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }

    public int HashCount => Hashes.Count;
    public int DomainCount => Domains.Count;
    public int IpCount => IpAddresses.Count;
    public int YaraRuleCount => Yara.RuleCount;
    public int SpecialPathCount => SpecialPaths.Count;

    private readonly object _md5IndexLock = new();
    private IReadOnlyDictionary<string, HashSignature>? _md5Index;

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
        if (TryMatchHash(sha256, out signature))
        {
            return true;
        }

        return !string.IsNullOrWhiteSpace(md5) && TryMatchMd5(md5, out signature);
    }

    public bool TryMatchMd5(string md5, out HashSignature? signature)
    {
        var index = _md5Index;
        if (index is null)
        {
            lock (_md5IndexLock)
            {
                index = _md5Index;
                if (index is null)
                {
                    var built = new Dictionary<string, HashSignature>(StringComparer.OrdinalIgnoreCase);
                    foreach (var entry in Hashes.Values)
                    {
                        if (!string.IsNullOrWhiteSpace(entry.Md5))
                        {
                            built.TryAdd(entry.Md5, entry);
                        }
                    }

                    index = built;
                    _md5Index = index;
                }
            }
        }

        return index.TryGetValue(md5, out signature);
    }
}
