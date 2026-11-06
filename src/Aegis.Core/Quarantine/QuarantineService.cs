using System.Text.Json;
using Aegis.Core.Infrastructure;
using Aegis.Core.Models;

namespace Aegis.Core.Quarantine;

public sealed record QuarantineEntry
{
    public required string Id { get; init; }
    public required string OriginalPath { get; init; }
    public required string FileName { get; init; }
    public required string Sha256 { get; init; }
    public required long Size { get; init; }
    public string? ThreatName { get; init; }
    public required ThreatVerdict Verdict { get; init; }
    public required int Score { get; init; }
    public required DateTimeOffset QuarantinedAt { get; init; }
    public string Source { get; init; } = "scan";
}

public sealed class QuarantineService
{
    private readonly string _root;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public QuarantineService(string? root = null)
    {
        _root = Path.GetFullPath(root ?? AppPaths.QuarantineRoot);
    }

    public string Root => _root;

    public async Task<QuarantineEntry> QuarantineAsync(FileScanResult result, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(result);
        var source = Path.GetFullPath(result.FilePath);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ValidateSource(source);
            Directory.CreateDirectory(_root);

            var id = Guid.NewGuid().ToString("N");
            var dataPath = Path.Combine(_root, id + ".bin");
            var metadataPath = Path.Combine(_root, id + ".json");
            MoveFile(source, dataPath);

            var entry = new QuarantineEntry
            {
                Id = id,
                OriginalPath = source,
                FileName = result.FileName,
                Sha256 = result.Sha256,
                Size = result.Size,
                ThreatName = result.ThreatName,
                Verdict = result.Verdict,
                Score = result.Score,
                QuarantinedAt = DateTimeOffset.UtcNow
            };

            try
            {
                await WriteMetadataAsync(metadataPath, entry, cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                TryMoveBack(dataPath, source);
                throw;
            }

            return entry;
        }
        finally
        {
            _gate.Release();
        }
    }

    public IReadOnlyList<QuarantineEntry> GetEntries()
    {
        try
        {
            if (!Directory.Exists(_root))
            {
                return Array.Empty<QuarantineEntry>();
            }

            var entries = new List<QuarantineEntry>();
            foreach (var metadataPath in Directory.EnumerateFiles(_root, "*.json"))
            {
                try
                {
                    var entry = JsonSerializer.Deserialize<QuarantineEntry>(
                        File.ReadAllText(metadataPath), JsonDefaults.Web);
                    if (entry is not null && !string.IsNullOrWhiteSpace(entry.Id))
                    {
                        entries.Add(entry);
                    }
                }
                catch (Exception exception) when (exception is IOException or JsonException or UnauthorizedAccessException)
                {
                    // A damaged record must not hide the rest of the quarantine.
                }
            }

            return entries.OrderByDescending(entry => entry.QuarantinedAt).ToArray();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return Array.Empty<QuarantineEntry>();
        }
    }

    public async Task RestoreAsync(string id, CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var (entry, dataPath, metadataPath) = LoadEntry(id);
            if (!File.Exists(dataPath))
            {
                throw new FileNotFoundException("隔离文件已不存在。", dataPath);
            }

            var target = Path.GetFullPath(entry.OriginalPath);
            var directory = Path.GetDirectoryName(target);
            if (string.IsNullOrWhiteSpace(directory))
            {
                throw new InvalidOperationException("隔离记录中的原始路径无效。");
            }

            Directory.CreateDirectory(directory);
            if (File.Exists(target))
            {
                throw new IOException("原位置已存在同名文件，未还原。");
            }

            MoveFile(dataPath, target);
            TryDelete(metadataPath);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task DeleteAsync(string id, CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var (_, dataPath, metadataPath) = LoadEntry(id);
            TryDelete(dataPath);
            TryDelete(metadataPath);
        }
        finally
        {
            _gate.Release();
        }
    }

    private (QuarantineEntry Entry, string DataPath, string MetadataPath) LoadEntry(string id)
    {
        if (string.IsNullOrWhiteSpace(id) || id.Any(character => !char.IsAsciiLetterOrDigit(character)))
        {
            throw new ArgumentException("隔离记录编号无效。", nameof(id));
        }

        var metadataPath = Path.Combine(_root, id + ".json");
        var dataPath = Path.Combine(_root, id + ".bin");
        if (!File.Exists(metadataPath))
        {
            throw new FileNotFoundException("隔离记录不存在。", metadataPath);
        }

        var entry = JsonSerializer.Deserialize<QuarantineEntry>(File.ReadAllText(metadataPath), JsonDefaults.Web)
                    ?? throw new InvalidDataException("隔离记录损坏。");
        return (entry, dataPath, metadataPath);
    }

    private static async Task WriteMetadataAsync(string path, QuarantineEntry entry, CancellationToken cancellationToken)
    {
        var temporary = path + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            await File.WriteAllTextAsync(
                temporary,
                JsonSerializer.Serialize(entry, JsonDefaults.WebIndented),
                cancellationToken).ConfigureAwait(false);
            File.Move(temporary, path, overwrite: true);
        }
        finally
        {
            TryDelete(temporary);
        }
    }

    private static void ValidateSource(string source)
    {
        if (!File.Exists(source))
        {
            throw new FileNotFoundException("要处置的文件不存在。", source);
        }

        var attributes = File.GetAttributes(source);
        if ((attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidOperationException("拒绝处置重解析点/符号链接。");
        }

        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (windows.Length > 0 && IsUnder(source, windows))
        {
            throw new InvalidOperationException("拒绝处置 Windows 系统目录中的文件。");
        }

        if (IsUnder(source, AppPaths.DataRoot) || IsUnder(source, AppPaths.LegacyDataRoot))
        {
            throw new InvalidOperationException("拒绝处置 NDAS 自身数据目录中的文件。");
        }
    }

    private static void MoveFile(string source, string destination)
    {
        try
        {
            File.Move(source, destination, overwrite: false);
        }
        catch (IOException) when (!File.Exists(destination))
        {
            File.Copy(source, destination, overwrite: false);
            try
            {
                File.Delete(source);
            }
            catch
            {
                TryDelete(destination);
                throw;
            }
        }
    }

    private static void TryMoveBack(string dataPath, string originalPath)
    {
        try
        {
            if (File.Exists(dataPath) && !File.Exists(originalPath))
            {
                var directory = Path.GetDirectoryName(originalPath);
                if (!string.IsNullOrWhiteSpace(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                MoveFile(dataPath, originalPath);
            }
        }
        catch
        {
            // The quarantined copy remains; the metadata write failure is already surfacing.
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // Best-effort cleanup.
        }
    }

    private static bool IsUnder(string path, string directory)
    {
        if (string.IsNullOrWhiteSpace(directory))
        {
            return false;
        }

        var root = directory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) +
                   Path.DirectorySeparatorChar;
        return path.Equals(directory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
                   StringComparison.OrdinalIgnoreCase) ||
               path.StartsWith(root, StringComparison.OrdinalIgnoreCase);
    }
}
