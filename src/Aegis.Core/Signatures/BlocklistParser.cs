using System.Net;
using System.Text;
using Aegis.Core.Models;

namespace Aegis.Core.Signatures;

public sealed record HashParseResult(
    IReadOnlyDictionary<string, HashSignature> Hashes,
    IReadOnlyList<string> Warnings);

public sealed record IndicatorParseResult(
    IReadOnlyDictionary<string, string?> Values,
    IReadOnlyList<string> Warnings);

public static class BlocklistParser
{
    public const string HashFileName = "hashes.csv";
    public const string DomainFileName = "domains.txt";
    public const string IpFileName = "ips-blocked.txt";

    public static async Task<HashParseResult> ParseHashesAsync(Stream stream, CancellationToken cancellationToken = default)
    {
        var hashes = new Dictionary<string, HashSignature>(StringComparer.OrdinalIgnoreCase);
        var warnings = new List<string>();
        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, leaveOpen: true);

        var header = await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false);
        if (header is null || !header.TrimStart('\uFEFF').StartsWith("sha256", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("hashes.csv 缺少 sha256 表头。");
        }

        var lineNumber = 1;
        while (await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false) is { } line)
        {
            lineNumber++;
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            List<string> fields;
            try
            {
                fields = ParseCsvLine(line);
            }
            catch (FormatException) when (warnings.Count < 40)
            {
                warnings.Add($"hashes.csv 第 {lineNumber} 行 CSV 格式无效，已跳过。");
                continue;
            }

            if (fields.Count < 4)
            {
                if (warnings.Count < 40)
                {
                    warnings.Add($"hashes.csv 第 {lineNumber} 行字段不足，已跳过。");
                }

                continue;
            }

            var sha256 = fields[0].Trim().ToLowerInvariant();
            if (!IsHexDigest(sha256, 64))
            {
                if (warnings.Count < 40)
                {
                    warnings.Add($"hashes.csv 第 {lineNumber} 行 SHA-256 无效，已跳过。");
                }

                continue;
            }

            var md5 = NormalizeOptionalDigest(fields[1], 32);
            var sha1 = NormalizeOptionalDigest(fields[2], 40);
            var label = fields[3].Trim();
            var notes = fields.Count > 4 ? fields[4].Trim() : string.Empty;
            if (string.IsNullOrWhiteSpace(label))
            {
                label = "未命名样本";
            }

            if (!hashes.TryAdd(sha256, new HashSignature
                {
                    Sha256 = sha256,
                    Md5 = md5,
                    Sha1 = sha1,
                    Label = label,
                    Notes = string.IsNullOrWhiteSpace(notes) ? null : notes,
                    ThreatName = HashSignature.ExtractThreatName(label) ?? HashSignature.ExtractThreatName(notes)
                }) && warnings.Count < 40)
            {
                warnings.Add($"hashes.csv 第 {lineNumber} 行与已有 SHA-256 重复，已忽略。");
            }
        }

        return new HashParseResult(hashes, warnings);
    }

    public static async Task<IndicatorParseResult> ParseDomainsAsync(Stream stream, CancellationToken cancellationToken = default)
    {
        var values = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        var warnings = new List<string>();
        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, leaveOpen: true);
        var lineNumber = 0;

        while (await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false) is { } line)
        {
            lineNumber++;
            var value = StripComment(line);
            if (value.Length == 0)
            {
                continue;
            }

            if (!DomainName.TryNormalize(value, out var normalized))
            {
                if (warnings.Count < 40)
                {
                    warnings.Add($"domains.txt 第 {lineNumber} 行域名无效，已跳过。");
                }

                continue;
            }

            var comment = ExtractComment(line);
            values.TryAdd(normalized, comment);
        }

        return new IndicatorParseResult(values, warnings);
    }

    public static async Task<IndicatorParseResult> ParseIpsAsync(Stream stream, CancellationToken cancellationToken = default)
    {
        var values = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        var warnings = new List<string>();
        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, leaveOpen: true);
        var lineNumber = 0;

        while (await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false) is { } line)
        {
            lineNumber++;
            var value = StripComment(line);
            if (value.Length == 0)
            {
                continue;
            }

            if (value.Contains('/') || !IPAddress.TryParse(value, out var address) ||
                address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            {
                if (warnings.Count < 40)
                {
                    warnings.Add($"ips-blocked.txt 第 {lineNumber} 行不是受支持的 IPv4 地址，已跳过。");
                }

                continue;
            }

            values.TryAdd(address.ToString(), ExtractComment(line));
        }

        return new IndicatorParseResult(values, warnings);
    }

    public static bool IsHexDigest(string value, int length)
    {
        if (value.Length != length)
        {
            return false;
        }

        foreach (var character in value)
        {
            if (!Uri.IsHexDigit(character))
            {
                return false;
            }
        }

        return true;
    }

    private static string? NormalizeOptionalDigest(string value, int expectedLength)
    {
        var digest = value.Trim();
        return IsHexDigest(digest, expectedLength) ? digest.ToLowerInvariant() : null;
    }

    private static string StripComment(string line)
    {
        var hashIndex = line.IndexOf('#');
        var value = hashIndex >= 0 ? line[..hashIndex] : line;
        return value.Trim();
    }

    private static string? ExtractComment(string line)
    {
        var hashIndex = line.IndexOf('#');
        if (hashIndex < 0)
        {
            return null;
        }

        var comment = line[(hashIndex + 1)..].Trim();
        return comment.Length == 0 ? null : (comment.Length > 300 ? comment[..300] : comment);
    }

    private static List<string> ParseCsvLine(string line)
    {
        var fields = new List<string>();
        var field = new StringBuilder();
        var inQuotes = false;

        for (var index = 0; index < line.Length; index++)
        {
            var character = line[index];
            if (inQuotes)
            {
                if (character == '"')
                {
                    if (index + 1 < line.Length && line[index + 1] == '"')
                    {
                        field.Append('"');
                        index++;
                    }
                    else
                    {
                        inQuotes = false;
                    }
                }
                else
                {
                    field.Append(character);
                }

                continue;
            }

            switch (character)
            {
                case '"':
                    if (field.Length != 0)
                    {
                        throw new FormatException("CSV 引号位置无效。");
                    }

                    inQuotes = true;
                    break;
                case ',':
                    fields.Add(field.ToString());
                    field.Clear();
                    break;
                default:
                    field.Append(character);
                    break;
            }
        }

        if (inQuotes)
        {
            throw new FormatException("CSV 引号未闭合。");
        }

        fields.Add(field.ToString());
        return fields;
    }
}
