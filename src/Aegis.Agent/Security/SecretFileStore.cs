using System.Security.Cryptography;
using System.Text;

namespace Aegis.Agent.Security;

/// <summary>
/// Stores one DPAPI-protected secret in the current user's profile.
/// The file never contains plaintext and cannot be decrypted by another Windows user.
/// </summary>
public sealed class SecretFileStore
{
    private static readonly byte[] Magic = Encoding.ASCII.GetBytes("AEGIS1");
    private const int MaxFileBytes = 64 * 1024;
    private readonly string _path;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public SecretFileStore(string path)
    {
        _path = path;
    }

    public string FilePath => _path;

    public bool Exists => File.Exists(_path);

    public async Task<string?> ReadAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!File.Exists(_path))
            {
                return null;
            }

            var info = new FileInfo(_path);
            if (info.Length is <= 0 or > MaxFileBytes)
            {
                throw new InvalidDataException("本地凭据文件大小异常。");
            }

            var payload = await File.ReadAllBytesAsync(_path, cancellationToken).ConfigureAwait(false);
            if (payload.Length <= Magic.Length ||
                !payload.AsSpan(0, Magic.Length).SequenceEqual(Magic))
            {
                throw new InvalidDataException("本地凭据文件格式无效。");
            }

            var plaintext = Dpapi.Unprotect(payload.AsSpan(Magic.Length));
            try
            {
                return new UTF8Encoding(false, true).GetString(plaintext);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task WriteAsync(string secret, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(secret);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var directory = Path.GetDirectoryName(_path);
            if (string.IsNullOrWhiteSpace(directory))
            {
                throw new InvalidOperationException("凭据路径无效。");
            }

            Directory.CreateDirectory(directory);
            var plaintext = Encoding.UTF8.GetBytes(secret);
            try
            {
                var protectedBytes = Dpapi.Protect(plaintext);
                var payload = new byte[Magic.Length + protectedBytes.Length];
                Magic.CopyTo(payload, 0);
                protectedBytes.CopyTo(payload, Magic.Length);
                await WriteAtomicAsync(payload, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task DeleteAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (File.Exists(_path))
            {
                File.Delete(_path);
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task WriteAtomicAsync(byte[] payload, CancellationToken cancellationToken)
    {
        var temporary = _path + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            await using (var stream = new FileStream(
                             temporary,
                             FileMode.CreateNew,
                             FileAccess.Write,
                             FileShare.None,
                             4096,
                             FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await stream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }

            File.Move(temporary, _path, overwrite: true);
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
                    // Best-effort cleanup only; the file is DPAPI-protected.
                }
            }
        }
    }
}
