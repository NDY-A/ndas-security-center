using System.Text;

namespace Aegis.Core.Signatures;

public sealed record SpecialPathEntry
{
    public required string Path { get; init; }
    public string? Label { get; init; }
    public string? Comment { get; init; }
}

public sealed record SpecialPathParseResult(
    SpecialPathMatcher Matcher,
    IReadOnlyList<string> Warnings);

public sealed class SpecialPathMatcher
{
    public const string FileName = "special-paths.txt";

    private readonly Dictionary<string, SpecialPathEntry> _entries;

    public static SpecialPathMatcher Empty { get; } = new(Array.Empty<SpecialPathEntry>());

    public SpecialPathMatcher(IEnumerable<SpecialPathEntry> entries)
    {
        _entries = new Dictionary<string, SpecialPathEntry>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in entries)
        {
            var normalized = NormalizePath(entry.Path);
            if (normalized.Length == 0)
            {
                continue;
            }

            _entries[normalized] = entry;
        }
    }

    public int Count => _entries.Count;

    public IReadOnlyList<SpecialPathEntry> Entries => _entries.Values.ToArray();

    public bool TryMatch(string path, out SpecialPathEntry? entry)
    {
        entry = null;
        var normalized = NormalizePath(path);
        return normalized.Length > 0 && _entries.TryGetValue(normalized, out entry);
    }

    public static string NormalizePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return string.Empty;
        }

        try
        {
            var fullPath = Path.GetFullPath(path.Trim());
            return fullPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return string.Empty;
        }
    }
}

public static class SpecialPathParser
{
    private const int MaxWarnings = 40;

    public static async Task<SpecialPathParseResult> ParseAsync(Stream stream, CancellationToken cancellationToken = default)
    {
        var entries = new List<SpecialPathEntry>();
        var warnings = new List<string>();
        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, leaveOpen: true);

        var lineNumber = 0;
        while (await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false) is { } line)
        {
            lineNumber++;
            var trimmed = line.Trim();
            if (trimmed.Length == 0 || trimmed.StartsWith('#'))
            {
                continue;
            }

            var fields = trimmed.Split('|');
            var path = fields[0].Trim();
            if (path.Length == 0)
            {
                AddWarning(warnings, $"special-paths.txt 第 {lineNumber} 行路径为空，已跳过。");
                continue;
            }

            var normalized = SpecialPathMatcher.NormalizePath(path);
            if (normalized.Length == 0)
            {
                AddWarning(warnings, $"special-paths.txt 第 {lineNumber} 行路径无效：{path}");
                continue;
            }

            entries.Add(new SpecialPathEntry
            {
                Path = normalized,
                Label = fields.Length > 1 && fields[1].Trim().Length > 0 ? fields[1].Trim() : null,
                Comment = fields.Length > 2 && fields[2].Trim().Length > 0 ? fields[2].Trim() : null
            });
        }

        return new SpecialPathParseResult(new SpecialPathMatcher(entries), warnings);
    }

    private static void AddWarning(List<string> warnings, string message)
    {
        if (warnings.Count < MaxWarnings)
        {
            warnings.Add(message);
        }
    }
}
