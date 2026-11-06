using System.Text.RegularExpressions;

namespace Aegis.Core.Yara;

public enum YaraStringKind
{
    Text,
    Hex,
    Regex
}

public sealed class YaraStringDef
{
    public required string Identifier { get; init; }
    public required int Index { get; init; }
    public required YaraStringKind Kind { get; init; }
    public string? Text { get; init; }
    public bool Ascii { get; init; } = true;
    public bool Wide { get; init; }
    public bool Nocase { get; init; }
    public bool Fullword { get; init; }
    public Regex? CompiledRegex { get; init; }
    public byte[]? Literal { get; init; }
}

public sealed class YaraRule
{
    public required string Identifier { get; init; }
    public required IReadOnlyList<string> Tags { get; init; }
    public required IReadOnlyDictionary<string, string> Meta { get; init; }
    public required IReadOnlyList<YaraStringDef> Strings { get; init; }
    public required YaraExpression Condition { get; init; }
    public required string Source { get; init; }

    public int Score
    {
        get
        {
            foreach (var key in Meta.Keys)
            {
                if (key.Equals("score", StringComparison.OrdinalIgnoreCase) &&
                    int.TryParse(Meta[key], out var value))
                {
                    return Math.Clamp(value, 1, 100);
                }
            }

            return 90;
        }
    }

    public string DisplayName => MetaValue("threat_name") ?? MetaValue("description") ?? Identifier;

    public string Description => MetaValue("description") ?? MetaValue("threat_name") ?? Identifier;

    public string? Reference => MetaValue("reference") ?? MetaValue("reference_url");

    private string? MetaValue(string key)
    {
        return Meta.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value) ? value.Trim() : null;
    }
}

public sealed record YaraRuleMatch(YaraRule Rule, IReadOnlyList<string> MatchedStrings);

public sealed class YaraScanResult
{
    public static YaraScanResult Empty { get; } = new(Array.Empty<YaraRuleMatch>(), 0, 0, 0);

    public YaraScanResult(
        IReadOnlyList<YaraRuleMatch> matches,
        int rulesEvaluated,
        int candidateRules,
        int regexEvaluations,
        long acMilliseconds = 0,
        long ruleLoopMilliseconds = 0)
    {
        Matches = matches;
        RulesEvaluated = rulesEvaluated;
        CandidateRules = candidateRules;
        RegexEvaluations = regexEvaluations;
        AcMilliseconds = acMilliseconds;
        RuleLoopMilliseconds = ruleLoopMilliseconds;
    }

    public IReadOnlyList<YaraRuleMatch> Matches { get; }

    public int RulesEvaluated { get; }

    public int CandidateRules { get; }

    public int RegexEvaluations { get; }

    public long AcMilliseconds { get; }

    public long RuleLoopMilliseconds { get; }
}
