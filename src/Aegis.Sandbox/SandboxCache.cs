using System.Text.Json;
using Aegis.Core.Models;

namespace Aegis.Sandbox;

public sealed class SandboxCache
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    };

    private readonly object _lock = new();
    private readonly string _path;
    private readonly Dictionary<string, CacheEntry> _entries = new(StringComparer.OrdinalIgnoreCase);

    public SandboxCache(string path)
    {
        _path = path;
        Load();
    }

    public int Count
    {
        get
        {
            lock (_lock)
            {
                return _entries.Count;
            }
        }
    }

    public bool TryGet(string sha256, TimeSpan ttl, out SandboxResult? result)
    {
        lock (_lock)
        {
            if (_entries.TryGetValue(sha256, out var entry) &&
                DateTimeOffset.UtcNow - entry.StoredAt <= ttl)
            {
                result = entry.ToResult();
                return true;
            }
        }

        result = null;
        return false;
    }

    public void Store(SandboxResult result)
    {
        lock (_lock)
        {
            _entries[result.Sha256] = CacheEntry.FromResult(result);
            PruneCore(TimeSpan.FromDays(30));
            Save();
        }
    }

    public void Remove(string sha256)
    {
        lock (_lock)
        {
            if (_entries.Remove(sha256))
            {
                Save();
            }
        }
    }

    private void Load()
    {
        try
        {
            if (!File.Exists(_path))
            {
                return;
            }

            var entries = JsonSerializer.Deserialize<List<CacheEntry>>(File.ReadAllText(_path), JsonOptions);
            foreach (var entry in entries ?? new List<CacheEntry>())
            {
                if (!string.IsNullOrWhiteSpace(entry.Sha256))
                {
                    _entries[entry.Sha256] = entry;
                }
            }

            PruneCore(TimeSpan.FromDays(30));
        }
        catch
        {
            // A corrupt cache must not prevent sandbox startup.
        }
    }

    private void PruneCore(TimeSpan maxAge)
    {
        var cutoff = DateTimeOffset.UtcNow - maxAge;
        foreach (var key in _entries.Where(pair => pair.Value.StoredAt < cutoff).Select(pair => pair.Key).ToArray())
        {
            _entries.Remove(key);
        }
    }

    private void Save()
    {
        try
        {
            var directory = Path.GetDirectoryName(_path);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            var temporary = _path + ".tmp";
            File.WriteAllText(temporary, JsonSerializer.Serialize(_entries.Values.ToList(), JsonOptions));
            File.Move(temporary, _path, overwrite: true);
        }
        catch
        {
            // Cache persistence is best-effort.
        }
    }

    private sealed class CacheEntry
    {
        public string Sha256 { get; set; } = string.Empty;
        public string FileName { get; set; } = string.Empty;
        public string Verdict { get; set; } = nameof(ThreatVerdict.Clean);
        public int Score { get; set; }
        public string? ThreatName { get; set; }
        public string Summary { get; set; } = string.Empty;
        public List<SandboxSignal> Signals { get; set; } = new();
        public List<NetworkIndicator> Indicators { get; set; } = new();
        public string Confidence { get; set; } = "Low";
        public string EngineVersion { get; set; } = string.Empty;
        public double DurationSeconds { get; set; }
        public DateTimeOffset CompletedAt { get; set; }
        public DateTimeOffset StoredAt { get; set; }
        public string? Error { get; set; }

        public static CacheEntry FromResult(SandboxResult result) => new()
        {
            Sha256 = result.Sha256,
            FileName = result.FileName,
            Verdict = result.Verdict.ToString(),
            Score = result.Score,
            ThreatName = result.ThreatName,
            Summary = result.Summary,
            Signals = result.Signals.ToList(),
            Indicators = result.Indicators.ToList(),
            Confidence = result.Confidence,
            EngineVersion = result.EngineVersion,
            DurationSeconds = result.Duration.TotalSeconds,
            CompletedAt = result.CompletedAt,
            StoredAt = DateTimeOffset.UtcNow,
            Error = result.Error
        };

        public SandboxResult ToResult() => new()
        {
            Sha256 = Sha256,
            FileName = FileName,
            Verdict = Enum.TryParse<ThreatVerdict>(Verdict, true, out var verdict) ? verdict : ThreatVerdict.Clean,
            Score = Score,
            ThreatName = ThreatName,
            Summary = Summary + "（缓存结果）",
            Signals = Signals,
            Indicators = Indicators,
            Confidence = Confidence,
            EngineVersion = EngineVersion,
            Duration = TimeSpan.FromSeconds(DurationSeconds),
            CompletedAt = CompletedAt,
            Error = Error
        };
    }
}
