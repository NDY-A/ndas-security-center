using System.Net;
using System.Text.RegularExpressions;
using Aegis.Core.Models;

namespace Aegis.Core.Signatures;

public sealed class DomainMatcher
{
    private readonly HashSet<string> _domains;

    public DomainMatcher(IEnumerable<string> domains)
    {
        _domains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var domain in domains)
        {
            if (DomainName.TryNormalize(domain, out var normalized))
            {
                _domains.Add(normalized);
            }
        }
    }

    public int Count => _domains.Count;

    public string? Match(string host)
    {
        if (!DomainName.TryNormalize(host, out var candidate))
        {
            return null;
        }

        while (true)
        {
            if (_domains.Contains(candidate))
            {
                return candidate;
            }

            var dot = candidate.IndexOf('.');
            if (dot < 0 || dot == candidate.Length - 1)
            {
                return null;
            }

            candidate = candidate[(dot + 1)..];
        }
    }
}

public sealed class IpMatcher
{
    private readonly HashSet<IPAddress> _addresses;

    public IpMatcher(IEnumerable<string> addresses)
    {
        _addresses = new HashSet<IPAddress>();
        foreach (var value in addresses)
        {
            if (IPAddress.TryParse(value, out var address) && address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                _addresses.Add(address);
            }
        }
    }

    public int Count => _addresses.Count;

    public bool Contains(IPAddress address) => _addresses.Contains(address);
}

public static partial class NetworkIndicatorExtractor
{
    private const int MaxMatches = 24;

    [GeneratedRegex(@"(?<![a-z0-9\-])(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}(?![a-z0-9\-])", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex DomainRegex();

    [GeneratedRegex(@"(?<![0-9.])(?<ip>(?:[0-9]{1,3}\.){3}[0-9]{1,3})(?![0-9.])", RegexOptions.CultureInvariant)]
    private static partial Regex Ipv4Regex();

    public static IReadOnlyList<NetworkIndicator> Extract(string text, DomainMatcher domains, IpMatcher addresses)
    {
        if (string.IsNullOrEmpty(text) || (domains.Count == 0 && addresses.Count == 0))
        {
            return Array.Empty<NetworkIndicator>();
        }

        var results = new List<NetworkIndicator>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (Match match in DomainRegex().Matches(text))
        {
            if (results.Count >= MaxMatches)
            {
                break;
            }

            var known = domains.Match(match.Value);
            if (known is not null && seen.Add("d:" + known))
            {
                results.Add(new NetworkIndicator
                {
                    Kind = IndicatorKind.Domain,
                    Value = known.ToLowerInvariant(),
                    MatchedValue = match.Value.ToLowerInvariant(),
                    Comment = "命中 NDY-A malware-egress-blocklist 域名"
                });
            }
        }

        foreach (Match match in Ipv4Regex().Matches(text))
        {
            if (results.Count >= MaxMatches)
            {
                break;
            }

            if (!IPAddress.TryParse(match.Groups["ip"].Value, out var address) ||
                address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            {
                continue;
            }

            if (addresses.Contains(address) && seen.Add("i:" + address))
            {
                results.Add(new NetworkIndicator
                {
                    Kind = IndicatorKind.IpAddress,
                    Value = address.ToString(),
                    MatchedValue = address.ToString(),
                    Comment = "命中 NDY-A malware-egress-blocklist IP"
                });
            }
        }

        return results;
    }
}

public static class DomainName
{
    public static bool TryNormalize(string? input, out string normalized)
    {
        normalized = string.Empty;
        if (string.IsNullOrWhiteSpace(input))
        {
            return false;
        }

        var value = input.Trim().TrimEnd('.');
        if (value.Length is 0 or > 253 || value.Contains('/') || value.Contains('\\') || value.Contains(' '))
        {
            return false;
        }

        if (Uri.TryCreate(value.Contains("://", StringComparison.Ordinal) ? value : "http://" + value, UriKind.Absolute, out var uri))
        {
            value = uri.Host.TrimEnd('.');
        }

        if (value.Length is 0 or > 253)
        {
            return false;
        }

        var labels = value.Split('.');
        if (labels.Length < 2)
        {
            return false;
        }

        foreach (var label in labels)
        {
            if (label.Length is 0 or > 63 || label[0] == '-' || label[^1] == '-')
            {
                return false;
            }

            foreach (var character in label)
            {
                if (!(char.IsAsciiLetterOrDigit(character) || character == '-'))
                {
                    return false;
                }
            }
        }

        normalized = value.ToLowerInvariant();
        return true;
    }
}
