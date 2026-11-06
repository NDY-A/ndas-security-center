using System.Security.Cryptography;
using System.Text.Json;
using Aegis.Core.Infrastructure;

namespace Aegis.Agent.Security;

public sealed class AgentKeyMetadata
{
    public int SchemaVersion { get; set; } = 1;
    public string KeyId { get; set; } = string.Empty;
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset RotatedAt { get; set; }
    public string Hint { get; set; } = string.Empty;
}

public sealed record AgentKeyMaterial(string Secret, AgentKeyMetadata Metadata)
{
    public string MaskedKey => "aeg_agent_••••••••••••" + Metadata.Hint;
}

/// <summary>
/// Generates the local automation credential on first use. The raw key is protected
/// with DPAPI (current user), while the metadata file contains only a four-character hint.
/// </summary>
public sealed class AgentKeyStore
{
    private const string KeyPrefix = "aeg_agent_";
    private const int KeyBytes = 32;
    private readonly SecretFileStore _secretStore;
    private readonly string _metadataPath;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public AgentKeyStore(string secretsDirectory)
    {
        Directory.CreateDirectory(secretsDirectory);
        _secretStore = new SecretFileStore(Path.Combine(secretsDirectory, "agent-api.key"));
        _metadataPath = Path.Combine(secretsDirectory, "agent-api.meta.json");
    }

    public string SecretFilePath => _secretStore.FilePath;

    public async Task<AgentKeyMaterial> GetOrCreateAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_secretStore.Exists && File.Exists(_metadataPath))
            {
                try
                {
                    var secret = await _secretStore.ReadAsync(cancellationToken).ConfigureAwait(false);
                    var metadata = await ReadMetadataAsync(cancellationToken).ConfigureAwait(false);
                    if (!string.IsNullOrWhiteSpace(secret) && metadata is not null && IsPlausible(secret, metadata))
                    {
                        return new AgentKeyMaterial(secret, metadata);
                    }
                }
                catch (Exception exception) when (exception is InvalidDataException or CryptographicException or System.ComponentModel.Win32Exception)
                {
                    await QuarantineCorruptFilesAsync().ConfigureAwait(false);
                }
            }

            var created = await CreateAndPersistAsync(cancellationToken).ConfigureAwait(false);
            return created;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<AgentKeyMetadata?> GetMetadataAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return File.Exists(_metadataPath) ? await ReadMetadataAsync(cancellationToken).ConfigureAwait(false) : null;
        }
        catch (Exception exception) when (exception is IOException or InvalidDataException or JsonException)
        {
            return null;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<string> RevealAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var secret = await _secretStore.ReadAsync(cancellationToken).ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(secret))
            {
                throw new InvalidOperationException("自动化密钥尚未生成。");
            }

            return secret;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<AgentKeyMaterial> RotateAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var previous = File.Exists(_metadataPath) ? await ReadMetadataAsync(cancellationToken).ConfigureAwait(false) : null;
            var created = await CreateAndPersistAsync(cancellationToken, previous?.CreatedAt).ConfigureAwait(false);
            return created;
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task<AgentKeyMaterial> CreateAndPersistAsync(CancellationToken cancellationToken, DateTimeOffset? originalCreatedAt = null)
    {
        var secret = KeyPrefix + Base64Url(RandomNumberGenerator.GetBytes(KeyBytes));
        var now = DateTimeOffset.UtcNow;
        var metadata = new AgentKeyMetadata
        {
            SchemaVersion = 1,
            KeyId = Guid.NewGuid().ToString("N"),
            CreatedAt = originalCreatedAt ?? now,
            RotatedAt = now,
            Hint = secret[^4..]
        };

        await _secretStore.WriteAsync(secret, cancellationToken).ConfigureAwait(false);
        try
        {
            await WriteMetadataAsync(metadata, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            await _secretStore.DeleteAsync(CancellationToken.None).ConfigureAwait(false);
            throw;
        }

        return new AgentKeyMaterial(secret, metadata);
    }

    private async Task<AgentKeyMetadata?> ReadMetadataAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(_metadataPath))
        {
            return null;
        }

        var info = new FileInfo(_metadataPath);
        if (info.Length is <= 0 or > 16 * 1024)
        {
            throw new InvalidDataException("自动化密钥元数据大小异常。");
        }

        await using var stream = new FileStream(_metadataPath, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.Asynchronous);
        var metadata = await JsonSerializer.DeserializeAsync<AgentKeyMetadata>(stream, JsonDefaults.Web, cancellationToken).ConfigureAwait(false);
        if (metadata is null || string.IsNullOrWhiteSpace(metadata.KeyId) || string.IsNullOrWhiteSpace(metadata.Hint))
        {
            throw new InvalidDataException("自动化密钥元数据损坏。");
        }

        return metadata;
    }

    private async Task WriteMetadataAsync(AgentKeyMetadata metadata, CancellationToken cancellationToken)
    {
        var temporary = _metadataPath + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            await using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await JsonSerializer.SerializeAsync(stream, metadata, JsonDefaults.WebIndented, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }

            File.Move(temporary, _metadataPath, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary))
            {
                try
                {
                    File.Delete(temporary);
                }
                catch (IOException)
                {
                    // Best-effort cleanup.
                }
            }
        }
    }

    private async Task QuarantineCorruptFilesAsync()
    {
        var suffix = ".corrupt-" + DateTimeOffset.UtcNow.ToString("yyyyMMddHHmmss");
        try
        {
            if (File.Exists(_secretStore.FilePath))
            {
                File.Move(_secretStore.FilePath, _secretStore.FilePath + suffix, overwrite: false);
            }

            if (File.Exists(_metadataPath))
            {
                File.Move(_metadataPath, _metadataPath + suffix, overwrite: false);
            }
        }
        catch (IOException)
        {
            // If quarantine fails, CreateAndPersist will overwrite with the same DPAPI protection.
        }

        await Task.CompletedTask.ConfigureAwait(false);
    }

    private static bool IsPlausible(string secret, AgentKeyMetadata metadata)
    {
        return secret.StartsWith(KeyPrefix, StringComparison.Ordinal) &&
               secret.Length > KeyPrefix.Length + 16 &&
               secret.Length < 128 &&
               secret.EndsWith(metadata.Hint, StringComparison.Ordinal);
    }

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
