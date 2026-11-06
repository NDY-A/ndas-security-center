using System.Text.Json;
using Aegis.Core.Infrastructure;

namespace Aegis.Core.Signatures;

public sealed class SignatureManifest
{
    public int SchemaVersion { get; set; } = 1;
    public string Version { get; set; } = string.Empty;
    public string Source { get; set; } = string.Empty;
    public DateTimeOffset FetchedAt { get; set; }
    public bool IsSeed { get; set; }
    public Dictionary<string, ManifestFileInfo> Files { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public SignatureCounts Counts { get; set; } = new();

    public static async Task<SignatureManifest> ReadAsync(string path, CancellationToken cancellationToken)
    {
        var info = new FileInfo(path);
        if (!info.Exists)
        {
            throw new FileNotFoundException("病毒库清单不存在。", path);
        }

        if (info.Length is <= 0 or > 1024 * 1024)
        {
            throw new InvalidDataException("病毒库清单大小异常。");
        }

        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 16 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        var manifest = await JsonSerializer.DeserializeAsync<SignatureManifest>(stream, JsonDefaults.Web, cancellationToken).ConfigureAwait(false);
        if (manifest is null)
        {
            throw new InvalidDataException("病毒库清单为空。");
        }

        manifest.Files = new Dictionary<string, ManifestFileInfo>(manifest.Files ?? new Dictionary<string, ManifestFileInfo>(), StringComparer.OrdinalIgnoreCase);
        manifest.Counts ??= new SignatureCounts();
        return manifest;
    }

    public async Task WriteAsync(string path, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, 16 * 1024, FileOptions.Asynchronous | FileOptions.WriteThrough);
        await JsonSerializer.SerializeAsync(stream, this, JsonDefaults.WebIndented, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }
}

public sealed class ManifestFileInfo
{
    public string Sha256 { get; set; } = string.Empty;
    public long Bytes { get; set; }
}

public sealed class SignatureCounts
{
    public int Hashes { get; set; }
    public int Domains { get; set; }
    public int Ips { get; set; }
    public int YaraRules { get; set; }
    public int SpecialPaths { get; set; }
}
