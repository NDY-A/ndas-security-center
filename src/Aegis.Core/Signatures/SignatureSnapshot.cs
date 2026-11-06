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
}
