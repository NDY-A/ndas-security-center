using System.Text.RegularExpressions;

namespace Aegis.Core.Signatures;

public sealed record HashSignature
{
    public required string Sha256 { get; init; }
    public string? Md5 { get; init; }
    public string? Sha1 { get; init; }
    public required string Label { get; init; }
    public string? Notes { get; init; }
    public string? ThreatName { get; init; }

    public string DisplayLabel
    {
        get
        {
            var value = string.IsNullOrWhiteSpace(Label) ? "未命名样本" : Label.Trim();
            return value.Length <= 180 ? value : value[..180] + "…";
        }
    }

    private static readonly Regex ThreatNamePattern = new(
        @"(?i)\b(?:Trojan|Ransom|Backdoor|Worm|Virus|PUA|HackTool|Behavior|Exploit|Dropper|Downloader|RAT|Adware|Spyware|Rootkit|Keylogger|Banker|Miner|CoinMiner)[:：][A-Za-z0-9._/\-!]+",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    public static string? ExtractThreatName(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        var match = ThreatNamePattern.Match(text);
        return match.Success ? match.Value : null;
    }
}
