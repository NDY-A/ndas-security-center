using System.Text;
using System.Text.RegularExpressions;
using Aegis.Core.Models;
using Aegis.Core.Signatures;
using Aegis.Core.Yara;

namespace Aegis.Core.Heuristics;

public sealed record HeuristicAnalysis(
    FileKind Kind,
    IReadOnlyList<Detection> Detections,
    IReadOnlyList<NetworkIndicator> NetworkIndicators,
    PeFileInfo? PeInfo,
    IReadOnlyList<string> Notes)
{
    public int Score => Math.Min(100, Detections.Sum(detection => detection.Score));

    public ThreatSeverity Severity => Detections.Count == 0
        ? ThreatSeverity.Informational
        : Detections.Max(detection => detection.Severity);
}

public sealed class HeuristicEngine
{
    private const int MaxTextChars = 400_000;
    private const int MaxFindings = 18;
    private readonly SignatureSnapshot _signatures;

    public HeuristicEngine(SignatureSnapshot signatures)
    {
        _signatures = signatures;
    }

    public async Task<HeuristicAnalysis> AnalyzeAsync(string path, FileKind kind, CancellationToken cancellationToken = default)
    {
        var findings = new List<Detection>();
        var notes = new List<string>();
        IReadOnlyList<NetworkIndicator> indicators = Array.Empty<NetworkIndicator>();
        PeFileInfo? peInfo = null;

        var sample = await ReadSampleAsync(path, kind == FileKind.Script ? 4 * 1024 * 1024 : 8 * 1024 * 1024, cancellationToken).ConfigureAwait(false);
        if (sample.Bytes.Length == 0)
        {
            notes.Add("文件为空或无法读取内容。");
            return new HeuristicAnalysis(kind, findings, indicators, null, notes);
        }

        if (sample.Truncated)
        {
            notes.Add("文件较大，内容启发式只分析了文件首尾的样本。");
        }

        if (ContainsEicar(sample.Bytes))
        {
            findings.Add(new Detection
            {
                RuleId = "Test.Eicar",
                Name = "Test/EICAR",
                Description = "这是 EICAR 标准反病毒测试文件，不是恶意软件；用于验证扫描链路。",
                Score = 100,
                Severity = ThreatSeverity.Critical,
                Source = DetectionSource.BuiltInTest,
                Evidence = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
            });
            return new HeuristicAnalysis(kind, findings, indicators, null, notes);
        }

        if (kind == FileKind.PortableExecutable)
        {
            var pe = PortableExecutableAnalyzer.Analyze(path);
            peInfo = pe.Info;
            findings.AddRange(pe.Findings);
            notes.AddRange(pe.Notes);
        }

        AddYaraFindings(sample.Bytes, kind, peInfo, findings, notes);

        if (kind == FileKind.Archive)
        {
            notes.Add("归档/MSI/镜像文件当前只做文件哈希与 YARA 匹配，尚未递归解包。");
            return new HeuristicAnalysis(kind, findings, indicators, peInfo, notes);
        }

        if (!FileKindDetector.SupportsContentHeuristics(kind))
        {
            return new HeuristicAnalysis(kind, findings, indicators, peInfo, notes);
        }

        var text = BuildSearchableText(sample.Bytes, kind);
        if (string.IsNullOrWhiteSpace(text))
        {
            notes.Add("未提取到可供规则匹配的可打印内容。");
            return new HeuristicAnalysis(kind, findings, indicators, peInfo, notes);
        }

        foreach (var rule in TextIndicatorRules.All)
        {
            if (findings.Count >= MaxFindings)
            {
                break;
            }

            if (rule.Kinds is not null && !rule.Kinds.Contains(kind))
            {
                continue;
            }

            Match match;
            try
            {
                match = rule.Pattern.Match(text);
            }
            catch (RegexMatchTimeoutException)
            {
                notes.Add($"规则 {rule.Id} 匹配超时，已跳过。");
                continue;
            }

            if (!match.Success)
            {
                continue;
            }

            findings.Add(new Detection
            {
                RuleId = rule.Id,
                Name = rule.Name,
                Description = rule.Description,
                Score = rule.Score,
                Severity = rule.Severity,
                Source = DetectionSource.Heuristic,
                Evidence = SanitizeEvidence(match.Value)
            });
        }

        indicators = NetworkIndicatorExtractor.Extract(text, _signatures.Domains, _signatures.IpAddresses);
        if (indicators.Count > 0)
        {
            var domainCount = indicators.Count(x => x.Kind == IndicatorKind.Domain);
            var ipCount = indicators.Count - domainCount;
            var networkScore = Math.Min(60, domainCount * 25 + ipCount * 20);
            findings.Add(new Detection
            {
                RuleId = "Heur.Network.KnownC2",
                Name = "IOC:Win32/Blocklist",
                Description = "文件内容包含恶意出站阻断清单中的域名或 IP，常见于下载器、RAT 或钓鱼落地页。",
                Score = networkScore,
                Severity = networkScore >= 25 ? ThreatSeverity.High : ThreatSeverity.Medium,
                Source = DetectionSource.Heuristic,
                Evidence = string.Join(", ", indicators.Select(x => x.Value).Distinct().Take(5))
            });
        }

        return new HeuristicAnalysis(kind, findings, indicators, peInfo, notes);
    }

    private void AddYaraFindings(byte[] data, FileKind kind, PeFileInfo? peInfo, List<Detection> findings, List<string> notes)
    {
        var ruleSet = _signatures.Yara;
        if (ruleSet.RuleCount == 0 || data.Length == 0)
        {
            return;
        }

        if (kind is not (FileKind.PortableExecutable or FileKind.Script or FileKind.MacroDocument or
            FileKind.Archive or FileKind.Shortcut))
        {
            return;
        }

        YaraScanResult result;
        try
        {
            result = ruleSet.Scan(TruncateYaraSample(data), peInfo);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            notes.Add("YARA 扫描失败：" + exception.GetType().Name);
            return;
        }

        if (result.Matches.Count == 0)
        {
            return;
        }

        foreach (var match in result.Matches.OrderByDescending(match => match.Rule.Score).Take(6))
        {
            var rule = match.Rule;
            findings.Add(new Detection
            {
                RuleId = "Yara." + rule.Identifier,
                Name = rule.DisplayName,
                Description = rule.Description + "（YARA 规则 " + rule.Identifier + "，来源 " + rule.Source + "）",
                Score = rule.Score,
                Severity = ScoreToSeverity(rule.Score),
                Source = DetectionSource.Yara,
                Evidence = match.MatchedStrings.Count > 0 ? string.Join(", ", match.MatchedStrings) : null
            });
        }

        notes.Add($"YARA 命中 {result.Matches.Count} 条规则（已加载 {ruleSet.RuleCount} 条）。");
    }

    private static byte[] TruncateYaraSample(byte[] data)
    {
        const int HeadBytes = 1024 * 1024;
        const int TailBytes = 256 * 1024;
        if (data.Length <= HeadBytes + TailBytes)
        {
            return data;
        }

        var slice = new byte[HeadBytes + TailBytes];
        Buffer.BlockCopy(data, 0, slice, 0, HeadBytes);
        Buffer.BlockCopy(data, data.Length - TailBytes, slice, HeadBytes, TailBytes);
        return slice;
    }

    private static ThreatSeverity ScoreToSeverity(int score) => score switch
    {
        >= 90 => ThreatSeverity.Critical,
        >= 70 => ThreatSeverity.High,
        >= 40 => ThreatSeverity.Medium,
        _ => ThreatSeverity.Low
    };

    private static bool ContainsEicar(byte[] bytes)
    {
        var ascii = Encoding.Latin1.GetString(bytes);
        return ascii.Contains(KnownTestFiles.EicarSignature, StringComparison.Ordinal);
    }

    private static string BuildSearchableText(byte[] sample, FileKind kind)
    {
        if (kind is FileKind.Script or FileKind.MacroDocument)
        {
            var decoded = DecodeText(sample);
            if (decoded.Length > MaxTextChars)
            {
                decoded = decoded[..MaxTextChars];
            }

            return decoded;
        }

        var builder = new StringBuilder(Math.Min(MaxTextChars, sample.Length));
        AppendAsciiStrings(sample, builder);
        builder.Append('\n');
        AppendUnicodeStrings(sample, builder);
        return builder.Length <= MaxTextChars ? builder.ToString() : builder.ToString(0, MaxTextChars);
    }

    private static string DecodeText(byte[] bytes)
    {
        if (bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF)
        {
            return new UTF8Encoding(false, false).GetString(bytes, 3, bytes.Length - 3);
        }

        if (bytes.Length >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE)
        {
            return Encoding.Unicode.GetString(bytes, 2, bytes.Length - 2);
        }

        if (bytes.Length >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF)
        {
            return Encoding.BigEndianUnicode.GetString(bytes, 2, bytes.Length - 2);
        }

        try
        {
            return new UTF8Encoding(false, true).GetString(bytes);
        }
        catch (DecoderFallbackException)
        {
            return Encoding.Latin1.GetString(bytes);
        }
    }

    private static void AppendAsciiStrings(byte[] bytes, StringBuilder builder)
    {
        var start = -1;
        for (var index = 0; index < bytes.Length && builder.Length < MaxTextChars; index++)
        {
            var value = bytes[index];
            var printable = value is >= 0x20 and <= 0x7E or (byte)'\t';
            if (printable)
            {
                if (start < 0)
                {
                    start = index;
                }
            }
            else if (start >= 0)
            {
                if (index - start >= 4)
                {
                    builder.Append(Encoding.ASCII.GetString(bytes, start, index - start));
                    builder.Append('\n');
                }

                start = -1;
            }
        }

        if (start >= 0 && bytes.Length - start >= 4 && builder.Length < MaxTextChars)
        {
            builder.Append(Encoding.ASCII.GetString(bytes, start, bytes.Length - start));
            builder.Append('\n');
        }
    }

    private static void AppendUnicodeStrings(byte[] bytes, StringBuilder builder)
    {
        for (var index = 0; index + 7 < bytes.Length && builder.Length < MaxTextChars;)
        {
            if (!IsPrintableAscii(bytes[index]) || bytes[index + 1] != 0)
            {
                index++;
                continue;
            }

            var start = index;
            var end = index;
            while (end + 1 < bytes.Length && bytes[end + 1] == 0 && IsPrintableAscii(bytes[end]))
            {
                end += 2;
            }

            var length = (end - start) / 2;
            if (length >= 4)
            {
                for (var cursor = start; cursor < end; cursor += 2)
                {
                    builder.Append((char)bytes[cursor]);
                }

                builder.Append('\n');
            }

            index = Math.Max(end, index + 2);
        }
    }

    private static bool IsPrintableAscii(byte value) => value is >= 0x20 and <= 0x7E or (byte)'\t';

    private static string SanitizeEvidence(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        var builder = new StringBuilder(Math.Min(value.Length, 180));
        foreach (var character in value)
        {
            if (builder.Length >= 180)
            {
                break;
            }

            builder.Append(char.IsControl(character) ? ' ' : character);
        }

        return builder.ToString().Trim();
    }

    private sealed record SampleResult(byte[] Bytes, bool Truncated);

    private static async Task<SampleResult> ReadSampleAsync(string path, int maxBytes, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete,
            64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);

        if (stream.Length <= maxBytes)
        {
            var all = new byte[(int)stream.Length];
            var total = 0;
            while (total < all.Length)
            {
                var read = await stream.ReadAsync(all.AsMemory(total), cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                total += read;
            }

            return new SampleResult(total == all.Length ? all : all[..total], false);
        }

        var buffer = new byte[maxBytes];
        var headLength = (int)(maxBytes * 0.75);
        var tailLength = maxBytes - headLength;
        var readTotal = 0;
        while (readTotal < headLength)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(readTotal, headLength - readTotal), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            readTotal += read;
        }

        stream.Seek(-tailLength, SeekOrigin.End);
        var tailRead = 0;
        while (tailRead < tailLength)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(headLength + tailRead, tailLength - tailRead), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            tailRead += read;
        }

        return new SampleResult(buffer[..(readTotal + tailRead)], true);
    }
}
